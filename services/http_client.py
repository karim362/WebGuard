"""HTTP client with ScopeGuard and rate limiting."""
from __future__ import annotations
import time
from typing import Any
from urllib.parse import urljoin, urlparse
from core.scope_guard import ScopeGuard
import config

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None


class HttpClient:
    """Enforces ScopeGuard on requests and redirects."""

    def __init__(
        self,
        scope_guard: ScopeGuard,
        timeout: int | None = None,
        rate_limit: float | None = None,
        max_requests: int | None = None,
        default_headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ):
        self.scope_guard = scope_guard
        self.timeout = timeout or config.DEFAULT_REQUEST_TIMEOUT
        self.rate_limit = (
            config.DEFAULT_RATE_LIMIT
            if rate_limit is None
            else rate_limit
        )
        self.max_requests = (
            config.DEFAULT_MAX_REQUESTS
            if max_requests is None
            else max_requests
        )
        self.default_headers = dict(default_headers or {})
        self.cookies = dict(cookies or {})
        self.follow_redirects = follow_redirects
        self.request_count = 0
        self._last_request_ts = 0.0

    def _throttle(self) -> None:
        if self.max_requests and self.request_count >= self.max_requests:
            raise RuntimeError("Max HTTP request budget reached")
        if self.rate_limit and self.rate_limit > 0:
            interval = 1.0 / self.rate_limit
            now = time.monotonic()
            diff = now - self._last_request_ts
            if diff < interval:
                time.sleep(interval - diff)
        self.request_count += 1
        self._last_request_ts = time.monotonic()

    def _safe_headers_for(
        self, url: str, headers: dict[str, str] | None = None
    ) -> dict[str, str]:
        merged = dict(self.default_headers)
        if headers:
            merged.update(headers)
        if self.cookies and "Cookie" not in merged and "cookie" not in merged:
            merged["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self.cookies.items()
            )
        host = (urlparse(url).hostname or "").lower()
        if not self.scope_guard.is_host_allowed(host):
            for k in list(merged.keys()):
                if k.lower() in ("cookie", "authorization"):
                    merged.pop(k, None)
        return merged

    def _validate_hops(self, response: Any, base_url: str = "") -> None:
        history = getattr(response, "history", None) or []
        for hop in history:
            hop_url = str(getattr(hop, "url", ""))
            if hop_url:
                self.scope_guard.assert_url_allowed(hop_url)
        headers = getattr(response, "headers", None) or {}
        loc = headers.get("location") or headers.get("Location")
        if loc:
            target_loc = urljoin(base_url, loc) if base_url else loc
            self.scope_guard.assert_url_allowed(target_loc)
        final_url = str(getattr(response, "url", ""))
        if final_url:
            self.scope_guard.assert_url_allowed(final_url)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.scope_guard.assert_url_allowed(url)
        self._throttle()
        if httpx is None:
            raise RuntimeError("httpx is not installed")
        timeout_val = kwargs.pop("timeout", self.timeout)
        req_headers = self._safe_headers_for(
            url, kwargs.pop("headers", None)
        )
        req_cookies = kwargs.pop("cookies", None)
        if req_cookies is None and self.cookies:
            req_cookies = self.cookies
        with httpx.Client(
            timeout=timeout_val,
            follow_redirects=self.follow_redirects,
            headers=req_headers,
            cookies=req_cookies,
        ) as client:
            resp = client.request(method.upper(), url, **kwargs)
        self._validate_hops(resp, base_url=url)
        return resp

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)
