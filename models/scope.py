"""Scope — authorized target scope with domains and optional wildcards."""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Scope:
    """Authorized scope. Domains may start with '*.' for wildcard subdomains."""
    domains: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    allow_http: bool = True
    allow_https: bool = True

    def normalize(self) -> None:
        cleaned = []
        for d in self.domains:
            d = d.strip().lower().lstrip("*.").strip(".")
            if d and d not in cleaned:
                cleaned.append(d)
        self.domains = cleaned

    def is_empty(self) -> bool:
        return not self.domains
