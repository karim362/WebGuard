"""
EvidenceCollector — attaches redacted request/response evidence
to findings and persists them under data/evidence/<scan_id>/.
"""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import config
from models.result import Evidence, EvidenceType, Finding
from services.redactor import (
    redact_body,
    redact_headers,
    redact_url,
)


class EvidenceCollector:
    def __init__(self, scan_id: str,
                 base_dir: Optional[Path] = None,
                 max_body_bytes: int = 8000):
        self.scan_id = scan_id
        self.base_dir = Path(base_dir or (config.DATA_DIR / "evidence"))
        self.scan_dir = self.base_dir / scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.max_body_bytes = max_body_bytes
        self._counter = 0

    def _next_filename(self, kind: str) -> Path:
        self._counter += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return self.scan_dir / f"{ts}_{self._counter:04d}_{kind}.txt"

    def _write(self, path: Path, content: str) -> str:
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return digest

    def from_response(self, finding: Finding, response) -> Evidence:
        """Build a redacted HTTP response evidence and persist it."""
        try:
            status = getattr(response, "status_code", "?")
            url = redact_url(str(getattr(response, "url", "")))
            headers = dict(getattr(response, "headers", {}) or {})
            redacted = redact_headers(headers)
            body = ""
            try:
                body = getattr(response, "text", "") or ""
            except Exception:
                body = ""
            body = redact_body(body, self.max_body_bytes)

            lines = [f"HTTP {status}", f"URL: {url}", "--- Headers ---"]
            lines += [f"{k}: {v}" for k, v in redacted.items()]
            lines += ["--- Body (truncated) ---", body]
            content = "\n".join(lines)

            path = self._next_filename("response")
            sha = self._write(path, content)

            return Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                content=content[:4000],
                redacted=True,
                note=f"saved: {path.name} sha256={sha[:16]}...",
            )
        except Exception as e:
            return Evidence(
                type=EvidenceType.LOG,
                content=f"evidence capture failed: {e}",
                redacted=True,
            )

    def from_request(self, finding: Finding, method: str,
                     url: str, headers: dict[str, str],
                     body: str = "") -> Evidence:
        redacted_headers = redact_headers(headers or {})
        content = "\n".join([
            f"{method} {redact_url(url)}",
            "--- Headers ---",
            *[f"{k}: {v}" for k, v in redacted_headers.items()],
            "--- Body (truncated) ---",
            redact_body(body, self.max_body_bytes),
        ])
        path = self._next_filename("request")
        sha = self._write(path, content)
        return Evidence(
            type=EvidenceType.HTTP_REQUEST,
            content=content[:4000],
            redacted=True,
            note=f"saved: {path.name} sha256={sha[:16]}...",
        )

    def attach(self, finding: Finding, response) -> Finding:
        if response is not None:
            finding.evidence.append(self.from_response(finding, response))
        return finding

    def summary(self) -> dict[str, Any]:
        files = list(self.scan_dir.glob("*.txt"))
        total = sum(f.stat().st_size for f in files)
        return {
            "scan_id": self.scan_id,
            "files": len(files),
            "bytes": total,
            "dir": str(self.scan_dir),
        }
