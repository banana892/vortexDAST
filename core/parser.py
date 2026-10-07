"""
VortexDAST – core/parser.py
────────────────────────────────────────────────────────────────────────────
HTML attack-surface extraction utility.

Responsibilities:
  • Parse raw HTML with BeautifulSoup and extract:
      – All <form> elements: action URL, HTTP method, and every named input /
        select / textarea field with its default value.
      – All <a href> links present in the document.
      – Query-string parameters from those discovered links.
  • Return structured, typed dataclasses so downstream components (crawler,
    fuzzers) have a consistent contract without relying on raw dicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FormField:
    """Represents a single input vector inside an HTML form."""

    name: str
    """Field ``name`` attribute — the key submitted in the HTTP body/query."""

    field_type: str
    """Normalised field type: ``text``, ``hidden``, ``password``, ``email``,
    ``number``, ``textarea``, ``select``, ``checkbox``, ``radio``, etc."""

    default_value: str = ""
    """The field's ``value`` attribute or pre-selected option (may be empty)."""


@dataclass
class ParsedForm:
    """
    Fully described HTML form with all submission parameters.

    The ``fields`` list contains every named input vector that would be
    included in a real form submission, making it directly usable by fuzzing
    modules without further HTML parsing.
    """

    action_url: str
    """Absolute URL to which the form submits (resolved against the page URL)."""

    method: str
    """Normalised HTTP method: ``"GET"`` or ``"POST"``."""

    fields: List[FormField] = field(default_factory=list)
    """All named input vectors inside this form."""

    enctype: str = "application/x-www-form-urlencoded"
    """Form encoding type — relevant for multipart file-upload detection."""


@dataclass
class ParsedLink:
    """A discovered hyperlink and any query parameters it carries."""

    url: str
    """Absolute resolved URL of the link."""

    query_params: Dict[str, List[str]] = field(default_factory=dict)
    """
    Query-string parameters parsed from the URL.
    Keys are parameter names; values are lists of strings (``parse_qs`` style).
    """


@dataclass
class ParsedPage:
    """
    Complete extraction result for a single HTML response.

    Aggregates all forms, links, and discovered query parameters found on
    one page so that the crawler can process them without touching HTML again.
    """

    page_url: str
    """The canonical URL of the page that was parsed."""

    forms: List[ParsedForm] = field(default_factory=list)
    """All forms discovered on this page."""

    links: List[ParsedLink] = field(default_factory=list)
    """All hyperlinks discovered on this page."""


# ─────────────────────────────────────────────────────────────────────────────
# Parser class
# ─────────────────────────────────────────────────────────────────────────────


class HTMLParser:
    """
    Stateless HTML attack-surface extractor.

    All public methods are pure functions that accept raw HTML text plus the
    page URL (for resolving relative references) and return structured
    dataclasses.  The class holds no per-instance state, so a single instance
    can safely parse multiple pages.

    Example
    -------
    >>> parser = HTMLParser()
    >>> page = parser.parse(html_text, base_url="https://example.com/login")
    >>> for form in page.forms:
    ...     print(form.method, form.action_url, [f.name for f in form.fields])
    """

    # ── Configuration ────────────────────────────────────────────────────────

    # BS4 parser backend: ``lxml`` is faster; falls back to ``html.parser``
    # if lxml is not installed.  The crawler handles the ImportError.
    _PREFERRED_PARSER = "lxml"
    _FALLBACK_PARSER = "html.parser"

    # Input tag names whose ``name`` attribute constitutes a submission field.
    _INPUT_TAGS = {"input", "textarea", "select"}

    # ── Public API ───────────────────────────────────────────────────────────

    def parse(self, html: str, base_url: str) -> ParsedPage:
        """
        Parse a full HTML document and return a :class:`ParsedPage`.

        Parameters
        ----------
        html : str
            Raw HTML response body text.
        base_url : str
            The URL from which this page was fetched (used to resolve relative
            ``href`` and form ``action`` attributes).

        Returns
        -------
        ParsedPage
            Structured extraction result containing all forms and links.
        """
        soup = self._make_soup(html)
        forms = self._extract_forms(soup, base_url)
        links = self._extract_links(soup, base_url)

        logger.debug(
            "Parsed %s – %d form(s), %d link(s)",
            base_url,
            len(forms),
            len(links),
        )
        return ParsedPage(page_url=base_url, forms=forms, links=links)

    def extract_forms(self, html: str, base_url: str) -> List[ParsedForm]:
        """
        Extract only the forms from an HTML document.

        Convenience wrapper for callers that only need form data.
        """
        soup = self._make_soup(html)
        return self._extract_forms(soup, base_url)

    def extract_links(self, html: str, base_url: str) -> List[ParsedLink]:
        """
        Extract only the hyperlinks from an HTML document.

        Convenience wrapper for callers that only need link data.
        """
        soup = self._make_soup(html)
        return self._extract_links(soup, base_url)

    @staticmethod
    def extract_query_params(url: str) -> Dict[str, List[str]]:
        """
        Parse query-string parameters from a URL.

        Parameters
        ----------
        url : str
            Any absolute or relative URL that may contain a ``?`` query string.

        Returns
        -------
        dict
            Mapping of parameter name → list of values, identical to the
            output of ``urllib.parse.parse_qs``.

        Example
        -------
        >>> HTMLParser.extract_query_params("https://site.com/search?q=test&page=1")
        {'q': ['test'], 'page': ['1']}
        """
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _make_soup(self, html: str) -> BeautifulSoup:
        """Instantiate a BeautifulSoup object, preferring the lxml backend."""
        try:
            return BeautifulSoup(html, self._PREFERRED_PARSER)
        except Exception:  # lxml not installed or parse error
            logger.debug("lxml unavailable; falling back to html.parser")
            return BeautifulSoup(html, self._FALLBACK_PARSER)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[ParsedForm]:
        """
        Locate every ``<form>`` tag and convert it to a :class:`ParsedForm`.

        Handles:
          * Missing ``action`` → defaults to the current page URL.
          * Missing ``method`` → defaults to GET.
          * Relative action URLs → resolved against ``base_url``.
          * ``<input>``, ``<textarea>``, and ``<select>`` fields (named only).
        """
        parsed_forms: List[ParsedForm] = []

        for form_tag in soup.find_all("form"):
            if not isinstance(form_tag, Tag):
                continue

            # ── Resolve action URL ────────────────────────────────────────
            raw_action = str(form_tag.get("action", "")).strip()
            action_url = urljoin(base_url, raw_action) if raw_action else base_url

            # ── Normalise HTTP method ─────────────────────────────────────
            raw_method = form_tag.get("method", "GET")
            method = str(raw_method).strip().upper()
            if method not in {"GET", "POST"}:
                method = "GET"  # Treat unsupported methods as GET

            # ── Enctype ───────────────────────────────────────────────────
            enctype = str(
                form_tag.get("enctype", "application/x-www-form-urlencoded")
            ).strip().lower()

            # ── Extract fields ────────────────────────────────────────────
            fields: List[FormField] = []
            for tag in form_tag.find_all(self._INPUT_TAGS):
                if not isinstance(tag, Tag):
                    continue
                field_obj = self._extract_field(tag)
                if field_obj is not None:
                    fields.append(field_obj)

            parsed_form = ParsedForm(
                action_url=action_url,
                method=method,
                fields=fields,
                enctype=enctype,
            )
            parsed_forms.append(parsed_form)
            logger.debug(
                "  Form → method=%s action=%s fields=%d",
                method,
                action_url,
                len(fields),
            )

        return parsed_forms

    @staticmethod
    def _extract_field(tag: Tag) -> Optional[FormField]:
        """
        Convert a single ``<input>``, ``<textarea>``, or ``<select>`` tag into
        a :class:`FormField`.

        Returns ``None`` for unnamed fields or submit/button/image/reset
        inputs that are not injection-relevant for fuzzing purposes.
        """
        tag_name = tag.name.lower()

        # Only process named fields — unnamed fields are never submitted.
        name = str(tag.get("name", "")).strip()
        if not name:
            return None

        if tag_name == "textarea":
            return FormField(
                name=name,
                field_type="textarea",
                default_value=tag.get_text(strip=True),
            )

        if tag_name == "select":
            # Prefer the pre-selected <option> value; fall back to the first.
            selected = tag.find("option", selected=True)
            first = tag.find("option")
            value = ""
            if selected and isinstance(selected, Tag):
                value = str(selected.get("value", selected.get_text(strip=True)))
            elif first and isinstance(first, Tag):
                value = str(first.get("value", first.get_text(strip=True)))
            return FormField(name=name, field_type="select", default_value=value)

        # <input> tag
        input_type = str(tag.get("type", "text")).strip().lower()

        # Skip non-data input types that are not useful injection vectors.
        if input_type in {"submit", "button", "reset", "image", "file"}:
            return None

        value = str(tag.get("value", "")).strip()
        return FormField(name=name, field_type=input_type, default_value=value)

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[ParsedLink]:
        """
        Locate every ``<a href>`` tag and resolve it to an absolute
        :class:`ParsedLink`, including any embedded query parameters.

        Skips fragment-only anchors (``#section``), ``javascript:`` pseudo-
        links, and ``mailto:``/``tel:`` schemes.
        """
        seen: set[str] = set()
        parsed_links: List[ParsedLink] = []

        for anchor in soup.find_all("a", href=True):
            if not isinstance(anchor, Tag):
                continue

            raw_href = str(anchor["href"]).strip()

            # Filter out non-HTTP schemes and fragment-only anchors.
            if raw_href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            absolute_url = urljoin(base_url, raw_href)

            # Normalise by stripping the fragment portion.
            parsed_url = urlparse(absolute_url)
            clean_url = parsed_url._replace(fragment="").geturl()

            if clean_url in seen:
                continue
            seen.add(clean_url)

            query_params = parse_qs(parsed_url.query, keep_blank_values=True)

            parsed_links.append(
                ParsedLink(url=clean_url, query_params=query_params)
            )

        return parsed_links
