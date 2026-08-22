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
    on *each individual dispatch* (the lock inside ``_dispatch`` serialises
    the token-bucket, so concurrent threads naturally queue up rather than
    all sleeping the same amount).

Concurrency model
-----------------
``requests.Session`` is **not thread-safe** when headers or cookies are
mutated concurrently, but *reading* shared session state from multiple threads
during ``session.request()`` calls is safe in practice (CPython GIL + urllib3
connection-pool is inherently thread-safe for concurrent requests to the same
host).  We use a ``threading.Lock`` only around the rate-limiter state update
to prevent two threads from both reading ``_last_request_time`` simultaneously
and both deciding to skip the sleep.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
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
    ) -> None:
        self.timeout = timeout
        self.rate_limit_rps = rate_limit_rps
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers

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
        self.session.headers.update(headers)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            logger.info("Proxy configured: %s", proxy)

        # ── Thread-safe rate-limiter ─────────────────────────────────────────
        # All threads share the same lock so the global RPS budget is honoured
        # even when many workers are active simultaneously.
        self._rate_lock = threading.Lock()
        self._last_request_time: float = 0.0
        self._min_interval: float = (
            1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _apply_rate_limit(self) -> None:
        """
        Thread-safe token-bucket sleep.

        The lock is held only during the state *read + update* — the
        ``time.sleep()`` call happens **outside** the lock so that other
        threads are not blocked while this thread is sleeping.
        """
        if self._min_interval == 0:
            return

        with self._rate_lock:
            elapsed = time.monotonic() - self._last_request_time
            sleep_for = self._min_interval - elapsed
            # Reserve this slot immediately by updating the timestamp.
            # Other threads will see the updated time and compute their own
            # sleep relative to it, naturally queuing up.
            self._last_request_time = time.monotonic() + max(sleep_for, 0)

        if sleep_for > 0:
            logger.debug("Rate-limiter sleeping %.3f s", sleep_for)
            time.sleep(sleep_for)

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
            response = self.session.request(method, url, **kwargs)
            logger.debug(
                "%s %s → HTTP %d (%d bytes)",
                method, url, response.status_code, len(response.content),
            )
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
        ultimately calls :meth:`_dispatch`, which acquires ``_rate_lock``
        before sleeping.  Workers queue up naturally at the rate-limiter
        rather than all firing simultaneously.

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
