"""
ScopeStore — persist/load authorized scope and target metadata.
Files live under data/targets/<slug>.json.
"""
from __future__ import annotations
import json
import re
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse
import config
from models.scope import Scope

def _slug(host: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", host.lower())

class ScopeStore:
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = Path(base_dir or config.TARGETS_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save(self, url: str, scope: Scope, notes: str = "") -> Path:
        host = urlparse(url).hostname or "unknown"
        path = self.base_dir / f"{_slug(host)}.json"
        payload = {"url": url, "scope": asdict(scope), "notes": notes}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def load(self, url: str) -> tuple[Scope, str] | None:
        host = urlparse(url).hostname or "unknown"
        path = self.base_dir / f"{_slug(host)}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        scope_data = data.get("scope", {})
        scope = Scope(
            domains=scope_data.get("domains", []),
            allow_subdomains=scope_data.get("allow_subdomains", True),
            allow_http=scope_data.get("allow_http", True),
            allow_https=scope_data.get("allow_https", True),
        )
        return scope, data.get("notes", "")

    def list_saved(self) -> list[str]:
        return sorted(p.stem for p in self.base_dir.glob("*.json"))
