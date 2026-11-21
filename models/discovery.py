"""Shared data model for discovery modules."""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class DiscoveredURL:
    url: str
    method: str = "GET"
    source: str = "crawler"
    status: int | None = None
    content_type: str = ""

    def key(self) -> tuple[str, str]:
        return (self.url, self.method)

@dataclass
class DiscoveredForm:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)
    source_url: str = ""

@dataclass
class DiscoveryResult:
    urls: list[DiscoveredURL] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    def merge(self, other: "DiscoveryResult") -> None:
        seen = {u.key() for u in self.urls}
        for u in other.urls:
            if u.key() not in seen:
                self.urls.append(u)
                seen.add(u.key())
        self.forms.extend(other.forms)
        self.comments.extend(other.comments)
