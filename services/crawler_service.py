"""
CrawlerService — bounded BFS crawler over a single origin.
Respects scope via the injected HttpClient; never leaves scope.
Extracts links, forms, and HTML comments.
"""
from __future__ import annotations
import re
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse
from models.discovery import (
    DiscoveredForm,
    DiscoveredURL,
    DiscoveryResult,
)
from services.logger import get_logger


_LINK_RE = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_FORM_RE = re.compile(
    r"(<form\b[^>]*>)(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)

_FORM_ACTION_DQ = re.compile(
    r'action="([^"]*)"',
    re.IGNORECASE,
)

_FORM_ACTION_SQ = re.compile(
    r"action='([^']*)'",
    re.IGNORECASE,
)

_FORM_METHOD_RE = re.compile(
    r'method="([^"]*)"',
    re.IGNORECASE,
)

_FORM_METHOD_SQ = re.compile(
    r"method='([^']*)'",
    re.IGNORECASE,
)

_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname="([^"]+)"',
    re.IGNORECASE,
)

_INPUT_SQ = re.compile(
    r"<input\b[^>]*\bname='([^']+)'",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(
    r"<!--(.*?)-->",
    re.DOTALL,
)

_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dmg",
    ".css", ".js",
)


class CrawlerService:
    def __init__(self, http_client, max_pages: int = 30,
                 max_depth: int = 2):
        self.http = http_client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.logger = get_logger("webguard.crawler")

    def _same_origin(self, base: str, url: str) -> bool:
        a = urlparse(base)
        b = urlparse(url)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)

    def _normalize(self, base: str, href: str) -> Optional[str]:
        if not href:
            return None
        skip = ("mailto:", "tel:", "javascript:", "#")
        if href.startswith(skip):
            return None
        url = urljoin(base, href)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        for ext in _SKIP_EXT:
            if parsed.path.lower().endswith(ext):
                return None
        return url.split("#")[0]

    def _extract_action(self, body: str) -> str:
        m = _FORM_ACTION_DQ.search(body)
        if m:
            return m.group(1)
        m = _FORM_ACTION_SQ.search(body)
        return m.group(1) if m else ""

    def _extract_method(self, body: str) -> str:
        m = _FORM_METHOD_RE.search(body)
        if m:
            return m.group(1).upper()
        m = _FORM_METHOD_SQ.search(body)
        return m.group(1).upper() if m else "GET"

    def _extract_inputs(self, body: str) -> list[str]:
        names = _INPUT_RE.findall(body)
        names += _INPUT_SQ.findall(body)
        return names

    def crawl(self, start_url: str) -> DiscoveryResult:
        result = DiscoveryResult()
        seen: set[str] = set()
        queue: deque = deque([(start_url, 0)])
        pages_fetched = 0

        while queue and pages_fetched < self.max_pages:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)

            try:
                response = self.http.get(url)
            except Exception as e:
                self.logger.debug("fetch failed: %s", e)
                continue
            pages_fetched += 1

            ct = response.headers.get(
                "content-type", ""
            ).lower()
            text = getattr(response, "text", "") or ""

            if "html" not in ct and "<html" not in \
                    text[:500].lower():
                result.urls.append(DiscoveredURL(
                    url=url,
                    status=response.status_code,
                    content_type=ct,
                ))
                continue

            result.urls.append(DiscoveredURL(
                url=url,
                status=response.status_code,
                content_type=ct,
            ))

            # links
            for href in _LINK_RE.findall(text):
                nxt = self._normalize(url, href)
                if not nxt:
                    continue
                if not self._same_origin(start_url, nxt):
                    continue
                if nxt in seen:
                    continue
                if depth >= self.max_depth:
                    continue
                queue.append((nxt, depth + 1))

            # forms
            for opening, body in _FORM_RE.findall(text):
                action = self._extract_action(opening)
                method = self._extract_method(opening)
                inputs = self._extract_inputs(body)
                result.forms.append(DiscoveredForm(
                    action=urljoin(url, action or url),
                    method=method,
                    inputs=inputs,
                    source_url=url,
                ))

            # comments
            for c in _COMMENT_RE.findall(text):
                stripped = c.strip()
                if stripped and len(stripped) < 500:
                    result.comments.append(stripped)

        return result
