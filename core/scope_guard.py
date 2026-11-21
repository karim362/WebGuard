"""
ScopeGuard — closed-by-default scope enforcement.
Uses models.scope.Scope for wildcards and http/https toggles.
"""
from __future__ import annotations
from urllib.parse import urlparse
from models.scope import Scope
from models.target import Target

class ScopeViolation(Exception):
    pass

class ScopeGuard:
    def __init__(self, target: Target):
        if not target.is_valid():
            raise ScopeViolation(
                "Invalid target: missing host, unsupported scheme, "
                "or authorization not confirmed."
            )
        self.target = target
        self.scope = Scope(
            domains=list(target.scope_domains) + [target.host],
            allow_subdomains=target.allow_subdomains,
            allow_http=True, allow_https=True,
        )
        self.scope.normalize()

    def _scheme_allowed(self, scheme: str) -> bool:
        if scheme == "https":
            return self.scope.allow_https
        if scheme == "http":
            return self.scope.allow_http
        return False

    def is_host_allowed(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        for allowed in self.scope.domains:
            if host == allowed:
                return True
            if self.scope.allow_subdomains and host.endswith("." + allowed):
                return True
        return False

    def is_url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if not self._scheme_allowed(parsed.scheme):
            return False
        return self.is_host_allowed(parsed.hostname or "")

    def assert_url_allowed(self, url: str) -> None:
        if not self.is_url_allowed(url):
            raise ScopeViolation(f"URL outside authorized scope: {url}")

    def allowed_domains(self) -> list[str]:
        return list(self.scope.domains)
