"""
DnsService — DNS lookups for reconnaissance.
Uses dnspython; falls back gracefully if library missing.
"""
from __future__ import annotations
from typing import Any

try:
    import dns.resolver  # type: ignore
    _DNS_AVAILABLE = True
except Exception:
    _DNS_AVAILABLE = False

class DnsService:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def available(self) -> bool:
        return _DNS_AVAILABLE

    def _query(self, name: str, rdtype: str) -> list[str]:
        if not _DNS_AVAILABLE:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, rdtype, lifetime=self.timeout)
            return [str(r) for r in answers]
        except Exception:
            return []

    def a(self, name: str) -> list[str]:
        return self._query(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._query(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return self._query(name, "MX")

    def ns(self, name: str) -> list[str]:
        return self._query(name, "NS")

    def txt(self, name: str) -> list[str]:
        return self._query(name, "TXT")

    def cname(self, name: str) -> list[str]:
        return self._query(name, "CNAME")

    def all(self, name: str) -> dict[str, list[str]]:
        return {
            "A": self.a(name),
            "AAAA": self.aaaa(name),
            "MX": self.mx(name),
            "NS": self.ns(name),
            "TXT": self.txt(name),
        }

    def resolve_exists(self, name: str) -> bool:
        return bool(self.a(name) or self.aaaa(name) or self.cname(name))
