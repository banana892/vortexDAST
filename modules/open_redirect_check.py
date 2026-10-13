"""
VortexDAST – modules/open_redirect_check.py
────────────────────────────────────────────────────────────────────────────
Open Redirect detection module (OWASP A01:2021 / CWE-601).

Detection Strategy
------------------
1.  **Candidate parameter identification** — filter GET query parameters
    (on the endpoint itself and on every discovered link) whose *name*
    fuzzy-matches a redirect-indicative keyword (``url``, ``next``,
    ``return``, ``redirect_uri``, …), loaded from
    ``payloads/open_redirect_probes.json``. Same name-gating approach as
    ``ssrf_check`` — a canary swap only means something on a parameter that
    plausibly carries a URL.
2.  For each candidate, swap its value for a benign off-site canary URL (an
    RFC 2606 ``.invalid`` domain VortexDAST runs no infrastructure for — the
    canary host is never actually contacted, only looked for in the
    response) and issue the request with ``allow_redirects=False``.
3.  **Confirmed signal** — a 3xx response whose ``Location`` header's host is
    the canary host: the server redirected using attacker-supplied input,
    unconditionally. Reported at ``CERTAIN`` confidence — this is a direct
    observation, not an inference.
4.  **Heuristic fallback** — if no redirect status fired, scan the response
    body for the *exact* canary URL inside a ``<meta http-equiv="refresh">``
    tag or a ``location.href=``/``location.replace(``/``window.location=``
    JS assignment. Reported at ``TENTATIVE`` confidence: the body was pattern
    -matched, never executed, so this is evidence a client-side redirect
    *would* fire, not proof that it did.
5.  One additional probe is built per-endpoint from the endpoint's own host:
    ``https://<endpoint-host>@vortexdast-redirect-canary.invalid/`` — the
    classic userinfo ``@`` bypass, which fools a validator that only checks
    whether the string *starts with* the expected host.

False-Positive Reduction
------------------------
*   Parameter-name gating avoids testing every param.
*   The confirmed signal matches on the ``Location`` header's parsed *host*
    (not a substring of it), so a canary value merely echoed back — never
    actually redirected to — does not fire it.
*   All canary variants resolve to the same literal domain, so the match is
    against one fixed, known host regardless of which bypass encoding the
    server's redirect ends up normalising to.

Safety
------
*   Only GET requests are issued; the canary domain is never actually
    resolved or contacted by VortexDAST — it only inspects what the target
    server itself did with the value.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, urlsplit

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_OPEN_REDIRECT_PATH = os.path.join(_PAYLOADS_DIR, "open_redirect_probes.json")

# Every canary probe (static or per-endpoint userinfo variant) points here.
_CANARY_HOST = "vortexdast-redirect-canary.invalid"

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Confirmed: Location header proves the server redirected off-site using our
# input, unconditionally. Needs the victim to follow the link (UI:R) and
# usually chains into phishing/credential-theft, hence the textbook CVSS
# vector for this class.
# AV:N / AC:L / PR:N / UI:R / S:C / C:L / I:L / A:N → 6.1 (MEDIUM)
_CVSS_VECTOR_CONFIRMED = build_vector(
    AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"
)
_CVSS_SCORE_CONFIRMED: float = cvss_calc(_CVSS_VECTOR_CONFIRMED)

# Heuristic: a JS/meta-refresh redirect pattern-matched in the raw body, but
# never executed — weaker evidence, higher attack complexity to rely on.
# AV:N / AC:H / PR:N / UI:R / S:C / C:L / I:N / A:N
_CVSS_VECTOR_HEURISTIC = build_vector(
    AV="N", AC="H", PR="N", UI="R", S="C", C="L", I="N", A="N"
)
_CVSS_SCORE_HEURISTIC: float = cvss_calc(_CVSS_VECTOR_HEURISTIC)

_JS_REDIRECT_TEMPLATES = (
    r'location\.href\s*=\s*["\']{canary}',
    r'location\.replace\(\s*["\']{canary}',
    r'window\.location\s*=\s*["\']{canary}',
)
_META_REFRESH_TEMPLATE = r'http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=["\']?{canary}'


class OpenRedirectCheckModule(BaseScannerModule):
    """Open Redirect detection via off-site canary-URL injection."""

    name: str = "open_redirect_check"
    description: str = (
        "Detects open redirects by swapping redirect-indicative parameters "
        "for a benign off-site canary URL and checking whether the server's "
        "Location header (or a JS/meta-refresh redirect in the body) sends "
        "the browser there."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _OPEN_REDIRECT_PATH
        self._keyword_set, self._canary_probes = _load_open_redirect_probes(path)

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        if not self._canary_probes:
            logger.warning("open_redirect_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        candidates = self._filter_candidates(endpoint.query_params)
        if candidates:
            findings.extend(self._fuzz_get_params(endpoint.url, endpoint.query_params, candidates))

        for link in endpoint.links:
            link_params = getattr(link, "query_params", None)
            if link_params:
                candidates = self._filter_candidates(link_params)
                if candidates:
                    findings.extend(self._fuzz_get_params(link.url, link_params, candidates))

        return findings

    # ── Candidate identification ──────────────────────────────────────────────

    def _filter_candidates(self, params: Dict[str, List[str]]) -> Set[str]:
        return {name for name in params if self._is_candidate(name)}

    def _is_candidate(self, param_name: str) -> bool:
        lower = param_name.lower()
        if lower in self._keyword_set:
            return True
        return any(keyword in lower for keyword in self._keyword_set)

    def _probes_for(self, url: str) -> List[Dict[str, str]]:
        """Static canary probes plus one built from the endpoint's own host."""
        probes = list(self._canary_probes)
        host = urlsplit(url).hostname
        if host:
            probes.append({
                "id": "or_userinfo_dynamic",
                "value": f"https://{host}@{_CANARY_HOST}/",
                "description": (
                    "Userinfo '@' bypass using the target's own host as bait "
                    "— fools a validator that only checks the string's prefix"
                ),
            })
        return probes

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(
        self, url: str, all_params: Dict[str, List[str]], candidate_names: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in all_params.items() if v}
        probes = self._probes_for(url)

        for target_param in candidate_names:
            for probe in probes:
                fuzzed = dict(base_params)
                fuzzed[target_param] = probe["value"]
                parsed = urlparse(url)
                fuzzed_url = parsed._replace(query=urlencode(fuzzed)).geturl()

                resp, err = self.requester.get(fuzzed_url, allow_redirects=False)
                if err or resp is None:
                    continue

                finding = self._evaluate(resp, fuzzed_url, target_param, probe)
                if finding:
                    findings.append(finding)
                    break  # one hit per parameter is enough

        return findings

    # ── Evaluation ─────────────────────────────────────────────────────────────

    def _evaluate(
        self, resp: Any, fuzzed_url: str, parameter: str, probe: Dict[str, str]
    ) -> Optional[Finding]:
        if resp.status_code in _REDIRECT_STATUSES:
            location = resp.headers.get("Location", "")
            if location and urlsplit(location).hostname == _CANARY_HOST:
                return self._confirmed_finding(fuzzed_url, parameter, probe, location, resp.status_code)
            return None

        if _body_redirects_to(resp.text or "", probe["value"]):
            return self._heuristic_finding(fuzzed_url, parameter, probe)

        return None

    def _confirmed_finding(
        self, url: str, parameter: str, probe: Dict[str, str], location: str, status_code: int
    ) -> Finding:
        logger.info("⚡ Open Redirect (confirmed): %s | param=%s", url, parameter)
        return Finding(
            title="Open Redirect — Confirmed via Location Header",
            severity=Severity.MEDIUM,
            confidence=Confidence.CERTAIN,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=f"HTTP {status_code} with Location: {location}",
            description=(
                f"Setting the '{parameter}' parameter to an off-site URL "
                f"({probe['description']}) made the server issue an HTTP "
                f"{status_code} redirect whose Location header points at that "
                "same off-site host. An attacker can craft a link to this "
                "application that silently redirects victims to an "
                "attacker-controlled site — commonly used in phishing to "
                "borrow the trusted domain's credibility, or to steal "
                "redirect-carried tokens from an OAuth/SSO flow."
            ),
            remediation=(
                "Never redirect to a raw user-supplied URL. Validate against "
                "an allowlist of known-safe paths/hosts (parsed as a URL, not "
                "a string prefix check), or use an indirection token that maps "
                "to a fixed set of server-known destinations."
            ),
            cvss_vector=_CVSS_VECTOR_CONFIRMED,
            cvss_score=_CVSS_SCORE_CONFIRMED,
            extra={
                "probe_id": probe.get("id"),
                "probe_value": probe["value"],
                "status_code": status_code,
                "location": location,
                "module": self.name,
            },
        )

    def _heuristic_finding(self, url: str, parameter: str, probe: Dict[str, str]) -> Finding:
        logger.info("⚡ Open Redirect (JS/meta-refresh pattern): %s | param=%s", url, parameter)
        return Finding(
            title="Potential Open Redirect — Client-Side Redirect Pattern",
            severity=Severity.LOW,
            confidence=Confidence.TENTATIVE,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=(
                f"The off-site canary URL '{probe['value']}' appears inside a "
                "meta-refresh tag or a location/window.location JS assignment "
                "in the response body."
            ),
            description=(
                f"Setting the '{parameter}' parameter to an off-site URL "
                "produced a response whose body contains a client-side "
                "redirect expression pointing at that same URL. The page was "
                "not rendered/executed to confirm the redirect actually "
                "fires — manual confirmation in a browser is recommended."
            ),
            remediation=(
                "Never build a meta-refresh or JS redirect target directly "
                "from user-supplied input. Validate against an allowlist of "
                "known-safe destinations before emitting the redirect."
            ),
            cvss_vector=_CVSS_VECTOR_HEURISTIC,
            cvss_score=_CVSS_SCORE_HEURISTIC,
            extra={"probe_id": probe.get("id"), "probe_value": probe["value"], "module": self.name},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _body_redirects_to(body: str, canary: str) -> bool:
    """True if ``canary`` appears inside a meta-refresh tag or a JS redirect assignment."""
    escaped = re.escape(canary)
    patterns = [_META_REFRESH_TEMPLATE.format(canary=escaped)] + [
        tmpl.format(canary=escaped) for tmpl in _JS_REDIRECT_TEMPLATES
    ]
    return any(re.search(p, body, re.IGNORECASE) for p in patterns)


def _load_open_redirect_probes(path: str) -> Tuple[Set[str], List[Dict[str, str]]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("open_redirect_probes.json not found at %s", path)
        return set(), []
    except json.JSONDecodeError as exc:
        logger.error("open_redirect_probes.json parse error: %s", exc)
        return set(), []

    keyword_set = {kw.lower() for kw in data.get("redirect_parameter_keywords", [])}
    canary_probes: List[Dict[str, str]] = data.get("canary_probes", [])

    logger.debug(
        "open_redirect_check: loaded %d keywords, %d canary probes from %s",
        len(keyword_set), len(canary_probes), path,
    )
    return keyword_set, canary_probes
