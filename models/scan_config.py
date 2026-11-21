"""ScanConfig — per-scan settings."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from models.module import ScanMode
from models.scope import Scope

@dataclass
class ScanConfig:
    target_url: str
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = field(default_factory=Scope)
    selected_modules: list[str] = field(default_factory=list)
    selected_categories: list[str] = field(default_factory=list)
    cookies_header: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    authorization_confirmed: bool = False
    max_requests: int = 500
    rate_limit: int = 10
    timeout: int = 15

    # Legacy compat used by engine to build Target
    @property
    def extra_scope(self) -> list[str]:
        return list(self.scope.domains)

    @property
    def allow_subdomains(self) -> bool:
        return self.scope.allow_subdomains
