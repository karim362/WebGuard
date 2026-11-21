"""Target model — the thing being tested."""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from urllib.parse import urlparse

@dataclass
class Target:
    url: str
    scope_domains: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    authorization_confirmed: bool = False

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme or "https"

    def is_valid(self) -> bool:
        if not self.authorization_confirmed:
            return False
        if self.scheme not in ("http", "https"):
            return False
        host = self.host
        if not host:
            return False
        # Strict hostname validation: letters/digits/hyphen/dot only
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", host):
            return False
        return True
