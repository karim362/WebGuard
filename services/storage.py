"""Minimal storage: persist scan results as JSON under data/results/."""
from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import config

def _default(obj: Any):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)

class Storage:
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = Path(base_dir or config.RESULTS_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def new_scan_id(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"scan_{ts}"

    def save_scan(self, scan_id: str, payload: dict) -> Path:
        path = self.base_dir / f"{scan_id}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=_default, ensure_ascii=False)
        return path

    def load_scan(self, scan_id: str) -> dict:
        path = self.base_dir / f"{scan_id}.json"
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
