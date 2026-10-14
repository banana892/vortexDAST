"""
VortexDAST – core/requester.py
────────────────────────────────────────────────────────────────────────────
Centralised HTTP session manager for VortexDAST.

Responsibilities
----------------
  • Maintain a persistent `requests.Session` (connection pooling, cookie jar).
  • Inject configurable custom headers on every outbound request.
  • Enforce a global per-second rate limit via a thread-safe token-bucket.
  • Provide safe GET / POST / HEAD wrappers returning ``(response, error)`` tuples.
  • Expose a :meth:`dispatch_concurrent` helper that fans out a batch of
    callables across a ``ThreadPoolExecutor`` while honouring the rate limit
    on *each individual dispatch* (the lock inside ``_apply_rate_limit``
    serialises the slot reservation, so concurrent threads naturally queue up
    rather than all sleeping the same amount).

Concurrency model — non-blocking slot reservation
-------------------------------------------------
``requests.Session`` is **not thread-safe** when headers or cookies are
mutated concurrently, but *reading* shared session state from multiple threads
during ``session.request()`` calls is safe in practice (CPython GIL + urllib3
connection-pool is inherently thread-safe for concurrent requests to the same
host).

The rate-limiter uses a **slot-reservation** model:

1. A thread acquires ``_rate_lock`` (briefly — no I/O inside the lock).
2. It reads ``_last_request_time`` and computes how long *it personally* must
   wait before its slot begins.
3. It advances ``_last_request_time`` by ``_min_interval`` to **reserve the
   next slot**, then releases the lock immediately.
4. It sleeps for its personal wait time *outside* the lock, so other threads
   can simultaneously reserve their own future slots without blocking.

This means N concurrent threads queue up with staggered sleep durations
(slot 0, slot 1*interval, slot 2*interval, …) instead of all reading the same
timestamp, all deciding to sleep 0 s, and all firing simultaneously.

A ``max_slot_wait`` guard (default ``60.0`` s) prevents indefinite queuing:
if the computed sleep time would exceed the guard, the limiter raises
``RuntimeError`` instead of sleeping — a safety valve for runaway concurrency.
"""

from __future__ import annotations

import datetime
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, TypeVar

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Every public method returns (Response | None, error_str | None).
RequestResult = Tuple[Optional[requests.Response], Optional[str]]

T = TypeVar("T")


class Requester:
    """
    Centralised HTTP session wrapper for VortexDAST.

    Parameters
    ----------
    timeout : int
        Per-request timeout in seconds (applies to both connect and read).
    user_agent : str
        User-Agent header value sent with every request.
    rate_limit_rps : float
        Maximum requests per second **globally across all threads**.
        Set to 0 to disable rate-limiting.
    verify_ssl : bool
        Whether to verify TLS certificates.
    proxy : str | None
        Optional HTTP/HTTPS proxy URL (e.g. ``"http://127.0.0.1:8080"``).
    extra_headers : dict | None
        Additional headers merged into every request.
    max_retries : int
        Number of automatic retries on transient connection failures.
    max_workers : int
        Default thread-pool size used by :meth:`dispatch_concurrent`.
        Each scan module can override this per-call.
    max_slot_wait : float
        Safety ceiling on the rate-limiter slot wait (seconds).  If the
        computed per-thread sleep would exceed this value, ``RuntimeError``
        is raised instead of sleeping.  Guards against runaway concurrency
        (e.g. 200 threads × 0.2 s/slot = 40 s queue).  Default: ``60.0``.
    cookies : str | None
        Semicolon-delimited cookie string (e.g. ``"JSESSIONID=xyz; auth=true"``).
        Parsed and injected into ``session.cookies`` at construction time so
        all subsequent requests carry the supplied cookies automatically.
    auth_headers : dict | None
        Additional HTTP headers injected into every request **after**
        ``extra_headers`` (so they can override base headers).  Useful for
        Bearer tokens (``{"Authorization": "Bearer <token>"}``) and API keys.
    http_auth : tuple[str, str] | None
        ``(username, password)`` credentials assigned to ``session.auth``.
        ``requests`` resolves the authentication scheme automatically:
        Basic by default; pass a :class:`requests.auth.HTTPDigestAuth` tuple
        if the target requires Digest authentication.
    """

    _BASE_HEADERS: Dict[str, str] = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "VortexDAST/1.0",
        rate_limit_rps: float = 5.0,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
        max_workers: int = 10,
        max_slot_wait: float = 60.0,
        cookies: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        http_auth: Optional[Tuple[str, str]] = None,
    ) -> None:
        self.timeout = timeout
        self.rate_limit_rps = rate_limit_rps
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers
        self._max_slot_wait = max_slot_wait

        # ── Scope-aware redirect following (set via set_scope_guard) ───────
        #: Optional object exposing ``is_in_scope(url) -> bool``. When set,
        #: redirects are followed manually and any hop leaving scope is
        #: dropped, so a hostile off-scope 30x can never carry a probe (its
        #: params, body, cookies or auth header) to an unintended host.
        self._scope_guard: Optional[Any] = None

        # ── Session-recovery hooks (set via set_session_recovery) ──────────
        #: (response) -> bool: False means the session was lost.
        self._session_validator: Optional[Callable[[Any], bool]] = None
        #: () -> bool: re-authenticate; True on success.
        self._reauth_callback: Optional[Callable[[], bool]] = None
        #: Serialises re-auth and guards against recursion (the login request
        #: itself flows back through _dispatch).
        self._reauth_lock = threading.Lock()
        self._reauthenticating: bool = False

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning(
                "SSL verification is DISABLED. Only use this against local lab "
                "targets with self-signed certificates."
            )

        # ── Session setup ────────────────────────────────────────────────────
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=max_workers + 2,   # one pool per host group
            pool_maxsize=max_workers + 2,        # enough sockets for all workers
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        headers = dict(self._BASE_HEADERS)
        headers["User-Agent"] = user_agent
        if extra_headers:
            headers.update(extra_headers)
        # auth_headers are applied after extra_headers so they take precedence
        # (e.g. a --header flag can override the User-Agent set above).
        if auth_headers:
            headers.update(auth_headers)
        self.session.headers.update(headers)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            logger.info("Proxy configured: %s", proxy)

        # ── Cookie injection ─────────────────────────────────────────────────
        # Cookies are loaded into the session cookie jar so they persist
        # across all requests (crawl + fuzz phases) without re-injection.
        if cookies:
            self.set_cookies(cookies)
            logger.info(
                "Session cookies loaded: %d cookie(s).",
                len(self.session.cookies),
            )

        # ── HTTP authentication ──────────────────────────────────────────────
        # Assigning session.auth causes requests to automatically negotiate
        # Basic (or Digest if wrapped in HTTPDigestAuth) on every request.
        if http_auth:
            self.session.auth = http_auth
            logger.info("HTTP auth configured for user: %r.", http_auth[0])

        # ── Thread-safe rate-limiter ─────────────────────────────────────────
        # Slot-reservation model: the lock is held only during the timestamp
        # read+write so that multiple threads can reserve their personal future
        # slots in rapid succession.  Each thread then sleeps *outside* the
        # lock for its individual wait duration.
        self._rate_lock = threading.Lock()
        self._last_request_time: float = 0.0
        self._min_interval: float = (
            1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        )

        # ── Adaptive throttling ──────────────────────────────────────────────
        self._base_interval: float = self._min_interval
        self._ok_streak: int = 0
        self.throttle_events: int = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Cookie and authentication helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_cookie_string(raw: str) -> Dict[str, str]:
        """
        Parse a semicolon-delimited ``Cookie:`` header value into a dict.

        Handles the common ``"K=V; K2=V2"`` format used by browsers and tools
        like ``curl -b``.  Malformed pairs (no ``=`` sign, empty name) are
        silently skipped.

        Parameters
        ----------
        raw : str
            Raw cookie string, e.g. ``"JSESSIONID=abc123; auth=true; _ga=GA1.2"``.

        Returns
        -------
        dict[str, str]
            Mapping of cookie name → cookie value.  Values may be empty strings.

        Examples
        --------
        >>> Requester.parse_cookie_string("a=1; b=2; c=")
        {'a': '1', 'b': '2', 'c': ''}
        >>> Requester.parse_cookie_string("bad_pair; x=ok")
        {'x': 'ok'}
        """
        result: Dict[str, str] = {}
        for pair in raw.split(";"):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                logger.debug(
                    "parse_cookie_string: Skipping malformed pair (no '='): %r", pair
                )
                continue
            name, _, value = pair.partition("=")
            name = name.strip()
            if not name:
                logger.debug(
                    "parse_cookie_string: Skipping pair with empty name: %r", pair
                )
                continue
            result[name] = value.strip()
        return result

    def set_cookies(self, raw_cookie_str: str) -> None:
        """
        Parse ``raw_cookie_str`` and load all cookies into the session jar.

        Cookies set this way persist across all requests made by this
        :class:`Requester` instance (crawl phase, fuzz phase, etc.) without
        any per-request re-injection.

        Parameters
        ----------
        raw_cookie_str : str
            Semicolon-delimited cookie string, e.g.
            ``"JSESSIONID=abc; token=xyz"``.
        """
        parsed = self.parse_cookie_string(raw_cookie_str)
        for name, value in parsed.items():
            self.session.cookies.set(name, value)
        logger.debug(
            "set_cookies: Loaded %d cookie(s) into session jar.", len(parsed)
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _apply_rate_limit(self) -> None:
        """
        Thread-safe, non-blocking slot-reservation rate limiter.

        Algorithm
        ---------
        1. Acquire ``_rate_lock`` (no I/O, minimal hold time).
        2. Read ``_last_request_time`` and compute the personal sleep duration.
        3. Advance ``_last_request_time`` by ``_min_interval`` to atomically
           reserve the next time slot.
        4. Release ``_rate_lock`` immediately — other threads can reserve their
           own slots in parallel.
        5. Sleep for the personal wait duration (may be 0) **outside** the lock.

        This prevents thread serialisation: under a 5 RPS limit with 10 threads,
        all 10 threads can reserve their staggered slots (t=0.2, 0.4, … 2.0 s)
        in one rapid pass through the lock, then each sleeps independently.

        Raises
        ------
        RuntimeError
            If the computed sleep time exceeds ``max_slot_wait``, indicating
            runaway concurrency (e.g. far more threads than the rate limit can
            sustain).  Callers should reduce ``--concurrency`` or raise
            ``--rate-limit`` before retrying.
        """
        if self._min_interval == 0:
            return

        with self._rate_lock:
            now = time.monotonic()
            # How long until the next available slot?
            sleep_for = self._last_request_time - now
            # Reserve this slot by advancing the shared timestamp.
            # The next caller will see the updated value and schedule after us.
            self._last_request_time = max(now, self._last_request_time) + self._min_interval

        if sleep_for > self._max_slot_wait:
            raise RuntimeError(
                f"Rate-limiter slot wait {sleep_for:.1f}s exceeds max_slot_wait "
                f"{self._max_slot_wait:.1f}s. Reduce --concurrency or raise "
                "--rate-limit."
            )

        if sleep_for > 0:
            logger.debug("Rate-limiter sleeping %.3f s", sleep_for)
            time.sleep(sleep_for)

    #: Interval used when the target throttles while rate limiting is disabled.
    _THROTTLE_FLOOR_INTERVAL = 0.2
    #: Never slow below 0.5 rps — keeps slot waits well under ``max_slot_wait``.
    _THROTTLE_MAX_INTERVAL = 2.0
    #: Consecutive unthrottled responses before halving the interval again.
    _RECOVERY_STREAK = 50

    #: Response headers that identify a CDN/WAF edge (Cloudflare, Vercel, AWS
    #: CloudFront/WAF, Akamai, Sucuri, Imperva/Incapsula, Fastly). A 403 that
    #: carries one of these is almost always an edge block/challenge page
    #: rather than the application's own 403, so it is treated as throttling
    #: too — plain 429-halving alone never catches it.
    _WAF_EDGE_HEADER_NAMES = frozenset({
        "cf-ray", "cf-mitigated",
        "x-sucuri-id", "x-sucuri-cache",
        "x-akamai-transformed",
        "x-amz-cf-id", "x-amz-cf-pop",
        "x-iinfo",
        "x-vercel-id", "x-vercel-mitigated",
        "x-denied-reason",
    })

    #: Cap on an explicit Retry-After-derived wait, so one header can't stall
    #: a whole scan — same spirit as _THROTTLE_MAX_INTERVAL's existing ceiling,
    #: just higher since this one is the server explicitly telling us a number.
    _MAX_RETRY_AFTER_WAIT = 30.0

    @classmethod
    def _is_waf_edge_block(cls, status: int, headers: Any) -> bool:
        """Best-effort fingerprint: a 403 with a recognised CDN/WAF header."""
        if status != 403 or not headers:
            return False
        names = {str(k).lower() for k in headers}
        if names & cls._WAF_EDGE_HEADER_NAMES:
            return True
        server = str(headers.get("Server") or "").lower()
        return "cloudflare" in server or "sucuri" in server

    @classmethod
    def _parse_retry_after(cls, value: Any) -> Optional[float]:
        """
        Parse a ``Retry-After`` header value into seconds from now.

        RFC 7231 §7.1.3 allows either delta-seconds (``"120"``) or an
        HTTP-date (``"Wed, 21 Oct 2015 07:28:00 GMT"``); both forms are
        handled. Returns ``None`` if absent, unparseable, or already in the
        past; otherwise the wait, capped at ``_MAX_RETRY_AFTER_WAIT``.
        """
        if value is None:
            return None
        text = str(value).strip()
        try:
            seconds = float(text)
        except ValueError:
            try:
                when = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError):
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=datetime.timezone.utc)
            seconds = (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        if seconds <= 0:
            return None
        return min(seconds, cls._MAX_RETRY_AFTER_WAIT)

    def _record_status(self, status: int, headers: Any) -> None:
        """Slow the global rate limiter when the target throttles; recover gradually."""
        # urllib3 has already retried 429/503 by this point, so a final one means
        # the target is still pushing back.
        headers = headers or {}
        waf_block = self._is_waf_edge_block(status, headers)
        throttled = status == 429 or (status == 503 and "Retry-After" in headers) or waf_block
        retry_after = self._parse_retry_after(headers.get("Retry-After")) if throttled else None
        message = None
        with self._rate_lock:
            if throttled:
                self.throttle_events += 1
                self._ok_streak = 0
                slower = min(
                    self._THROTTLE_MAX_INTERVAL,
                    max(self._min_interval * 2, self._THROTTLE_FLOOR_INTERVAL),
                )
                # An explicit Retry-After overrides the blind-doubling ceiling —
                # the server told us a real number, so honour it even past
                # _THROTTLE_MAX_INTERVAL (still bounded by _MAX_RETRY_AFTER_WAIT).
                if retry_after is not None:
                    slower = max(slower, retry_after)
                if slower > self._min_interval:
                    self._min_interval = slower
                    reason = "CDN/WAF edge block" if waf_block else f"HTTP {status}"
                    if retry_after is not None:
                        reason += f", Retry-After {retry_after:.1f}s"
                    message = (
                        f"Target is throttling ({reason}) — slowing to "
                        f"{1 / slower:.1f} req/s."
                    )
            elif self._min_interval > self._base_interval:
                self._ok_streak += 1
                if self._ok_streak >= self._RECOVERY_STREAK:
                    self._ok_streak = 0
                    faster = self._min_interval / 2
                    # Below the throttle floor, snap back to the configured rate
                    # (which may be 0 = unlimited).
                    if faster < max(self._base_interval, self._THROTTLE_FLOOR_INTERVAL):
                        faster = self._base_interval
                    self._min_interval = faster
                    logger.debug("Throttling eased — interval now %.3fs", faster)
        if message:
            logger.warning(message)

    # ─────────────────────────────────────────────────────────────────────────
    # Scope-aware redirect following
    # ─────────────────────────────────────────────────────────────────────────

    def set_scope_guard(self, guard: Optional[Any]) -> None:
        """
        Install a scope guard so redirects are followed only while they stay
        in scope.

        ``guard`` must expose ``is_in_scope(url: str) -> bool``. Once set,
        :meth:`_dispatch` stops delegating redirect-following to ``requests``
        (which follows any ``Location`` blindly) and instead walks the redirect
        chain one hop at a time, checking each next URL against the guard. The
        first off-scope hop is logged and **not** followed — the redirect
        response is returned as-is — so a hostile target cannot use a 30x to
        bounce a probe (its parameters, body, cookies or ``Authorization``
        header) onto an unintended host. Pass ``None`` to restore the default
        ``requests`` redirect behaviour.
        """
        self._scope_guard = guard

    def _send_with_scoped_redirects(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> "requests.Response":
        """
        Issue ``method url`` and follow redirects manually, dropping the first
        hop that leaves scope.

        Reuses ``requests``' own redirect machinery via ``response.next`` (the
        pre-built :class:`~requests.PreparedRequest` for the next hop), so
        method/body rewriting on 301/302/303, ``Authorization`` stripping on
        cross-host hops, relative-``Location`` resolution and cookie extraction
        all behave exactly as they would under native redirect following —
        except that each hop's URL is first checked against the scope guard.
        """
        kwargs = dict(kwargs)
        kwargs["allow_redirects"] = False
        # requests populates ``response.next`` with the next PreparedRequest
        # when allow_redirects is False; mirror its own default hop cap.
        max_redirects = self.session.max_redirects
        send_timeout = kwargs.get("timeout", self.timeout)
        send_verify = kwargs.get("verify", self.verify_ssl)

        response = self.session.request(method, url, **kwargs)

        hops = 0
        while response.is_redirect:
            nxt = response.next  # PreparedRequest for the next hop, or None.
            if nxt is None:
                break
            if hops >= max_redirects:
                raise requests.exceptions.TooManyRedirects(
                    f"Exceeded {max_redirects} redirects.", response=response
                )
            if self._scope_guard is not None and not self._scope_guard.is_in_scope(nxt.url):
                logger.warning(
                    "Blocked off-scope redirect: %s %s -> %s (out of scope; not followed)",
                    method, response.url, nxt.url,
                )
                break
            # Count this redirect hop against throttle/status tracking before
            # we send the next one; the final (non-redirect) response is
            # recorded by the caller in :meth:`_dispatch`.
            self._record_status(response.status_code, response.headers)
            response = self.session.send(
                nxt,
                allow_redirects=False,
                timeout=send_timeout,
                verify=send_verify,
            )
            hops += 1

        return response

    # ─────────────────────────────────────────────────────────────────────────
    # Authenticated-session recovery
    # ─────────────────────────────────────────────────────────────────────────

    def set_session_recovery(
        self,
        validator: Callable[[Any], bool],
        reauth: Callable[[], bool],
    ) -> None:
        """
        Enable transparent re-authentication on session loss.

        ``validator(response)`` returns ``False`` when a response shows the
        session has expired; ``reauth()`` re-authenticates (returning success)
        and leaves fresh cookies on this requester's session. Wired here so a
        dropped session is recovered at the single request choke point rather
        than in every module. See :mod:`core.auth`.
        """
        self._session_validator = validator
        self._reauth_callback = reauth

    def _maybe_recover_session(
        self,
        method: str,
        url: str,
        response: "requests.Response",
        kwargs: Dict[str, Any],
    ) -> "requests.Response":
        """
        If a session-loss is detected on ``response``, re-authenticate once and
        replay the original request. Returns the replayed response on success,
        else the original. No-op unless :meth:`set_session_recovery` was used.
        """
        if self._session_validator is None or self._reauth_callback is None:
            return response
        # Never recurse: the login request itself passes through _dispatch.
        if self._reauthenticating:
            return response
        try:
            if self._session_validator(response):
                return response
        except Exception as exc:  # noqa: BLE001 — a bad validator must not crash a scan
            logger.debug("session validator raised: %s", exc)
            return response

        with self._reauth_lock:
            # Another thread may have already recovered the session; re-check
            # by replaying is cheaper than tracking shared state, so proceed.
            self._reauthenticating = True
            try:
                recovered = bool(self._reauth_callback())
            except Exception as exc:  # noqa: BLE001
                logger.error("re-authentication raised: %s", exc)
                recovered = False
            finally:
                self._reauthenticating = False

        if not recovered:
            logger.error("session recovery failed; continuing unauthenticated")
            return response

        # Replay the original request once with the refreshed session.
        try:
            replay = self.session.request(method, url, **kwargs)
            self._record_status(replay.status_code, replay.headers)
            return replay
        except requests.exceptions.RequestException as exc:
            logger.debug("replay after re-auth failed: %s", exc)
            return response

    def _dispatch(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> RequestResult:
        """
        Low-level dispatcher shared by :meth:`get`, :meth:`post`, and
        :meth:`head`.

        Applies the thread-safe rate limiter, calls the session, and catches
        common transport-layer exceptions, returning a structured error tuple
        rather than letting them propagate.
        """
        self._apply_rate_limit()

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)

        try:
            # With a scope guard installed, follow redirects manually so an
            # off-scope 30x can never carry a probe to an unintended host.
            # Honour an explicit allow_redirects=False from the caller (and the
            # no-guard case) by falling back to requests' native handling.
            if self._scope_guard is not None and kwargs.get("allow_redirects", True):
                response = self._send_with_scoped_redirects(method, url, **kwargs)
            else:
                response = self.session.request(method, url, **kwargs)
            logger.debug(
                "%s %s → HTTP %d (%d bytes)",
                method, url, response.status_code, len(response.content),
            )
            self._record_status(response.status_code, response.headers)
            response = self._maybe_recover_session(method, url, response, kwargs)
            return response, None

        except requests.exceptions.SSLError as exc:
            msg = (
                f"SSL error for {url}: {exc}. "
                "Consider setting verify_ssl=False in config for local labs."
            )
            logger.error(msg)
            return None, msg

        except requests.exceptions.ConnectionError as exc:
            msg = f"Connection error for {url}: {exc}"
            logger.error(msg)
            return None, msg

        except requests.exceptions.Timeout as exc:
            msg = f"Request timed out after {self.timeout}s for {url}: {exc}"
            logger.warning(msg)
            return None, msg

        except requests.exceptions.TooManyRedirects as exc:
            msg = f"Too many redirects for {url}: {exc}"
            logger.warning(msg)
            return None, msg

        except requests.exceptions.RequestException as exc:
            msg = f"Unexpected request error for {url}: {exc}"
            logger.error(msg)
            return None, msg

    # ─────────────────────────────────────────────────────────────────────────
    # Public request API
    # ─────────────────────────────────────────────────────────────────────────

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> RequestResult:
        """Issue a safe HTTP GET request."""
        if headers:
            kwargs["headers"] = headers
        return self._dispatch("GET", url, params=params, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> RequestResult:
        """Issue a safe HTTP POST request."""
        if headers:
            kwargs["headers"] = headers
        return self._dispatch("POST", url, data=data, json=json, **kwargs)

    def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> RequestResult:
        """Issue a safe HTTP HEAD request."""
        if headers:
            kwargs["headers"] = headers
        return self._dispatch("HEAD", url, **kwargs)

    # ─────────────────────────────────────────────────────────────────────────
    # Concurrent dispatch
    # ─────────────────────────────────────────────────────────────────────────

    def dispatch_concurrent(
        self,
        tasks: Iterable[Callable[[], T]],
        max_workers: Optional[int] = None,
    ) -> List[T]:
        """
        Execute a collection of zero-argument callables concurrently using a
        ``ThreadPoolExecutor``, collecting and returning their results in
        **completion order** (not submission order).

        The global rate limit is still honoured because each callable
        ultimately calls :meth:`_dispatch`, which invokes ``_apply_rate_limit``
        and reserves a personal slot.  Workers sleep independently for their
        staggered durations rather than all blocking on the same lock.

        Parameters
        ----------
        tasks : iterable of callables
            Zero-argument callables (e.g. ``lambda: self.get(url)``).
            Each should return a value of type ``T``.
        max_workers : int | None
            Override the instance-level ``max_workers`` for this call only.

        Returns
        -------
        list[T]
            Results of all completed tasks.  Exceptions raised inside tasks
            are logged and skipped rather than propagated, so the list may be
            shorter than ``len(tasks)`` if some tasks failed.

        Example
        -------
        ::

            results = requester.dispatch_concurrent([
                lambda: requester.get("https://target.com/a"),
                lambda: requester.get("https://target.com/b"),
                lambda: requester.get("https://target.com/c"),
            ], max_workers=5)
        """
        workers = max_workers if max_workers is not None else self.max_workers
        task_list = list(tasks)  # materialise so we know the count

        if not task_list:
            return []

        # For a single task avoid thread-pool overhead entirely.
        if len(task_list) == 1:
            try:
                return [task_list[0]()]
            except Exception as exc:
                logger.error("dispatch_concurrent single-task error: %s", exc)
                return []

        results: List[T] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vdast-worker") as pool:
            future_to_idx: Dict[Future[T], int] = {
                pool.submit(fn): i for i, fn in enumerate(task_list)
            }
            for future in as_completed(future_to_idx):
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error(
                        "dispatch_concurrent task[%d] raised: %s",
                        future_to_idx[future], exc,
                    )

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release the underlying connection pool and clean up the session."""
        self.session.close()
        logger.debug("Requester session closed.")

    def __enter__(self) -> "Requester":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"Requester(timeout={self.timeout}, "
            f"rate_limit_rps={self.rate_limit_rps}, "
            f"verify_ssl={self.verify_ssl}, "
            f"max_workers={self.max_workers})"
        )
