"""Exposure review for exposed sensitive paths."""
from __future__ import annotations
import re
from urllib.parse import urljoin
from core.execution_manager import ModuleContext
from models.module import (
    BaseModule,
    ModuleResult,
    ModuleStatus,
    ScanMode,
)
from models.result import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)

SENSITIVE_PATHS = [
    ("/.git/HEAD", "git", "Git metadata exposed"),
    ("/.env", "env", ".env file exposed"),
    ("/.env.bak", "env", ".env backup exposed"),
    ("/backup.zip", "backup", "Backup archive exposed"),
    ("/config.php.bak", "backup", "PHP backup exposed"),
]



def _first_direct_url(text: str, fallback: str) -> str:
    s = text or ""
    m = re.search(r"https?://[^\s|\"'';<>)]+", s)
    if m:
        return m.group(0)
    pm = re.search(r"(?<![a-zA-Z0-9_.-])(/[a-zA-Z0-9_./-]{1,120})", s)
    if pm and fallback:
        base = re.match(r"^(https?://[^/?#]+)", fallback)
        if base:
            return base.group(1) + pm.group(1)
    return fallback


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class ExposureModule(BaseModule):
    name = "exposure_review"
    version = "0.6.0"
    description = "Detects exposed sensitive files."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        base = context.target.url.rstrip("/") + "/"
        http = context.services["http"]
        found = 0
        for path, kind, desc in SENSITIVE_PATHS:
            url = urljoin(base, path.lstrip("/"))
            try:
                r = http.get(url)
            except Exception as e:
                result.errors.append(f"{path}: {e}")
                continue
            if getattr(r, "status_code", None) != 200:
                continue
            body = (getattr(r, "text", "") or "")[:200]
            if kind == "git" and "ref: " not in body:
                continue
            if kind == "env" and "=" not in body:
                continue
            found += 1
            result.findings.append(Finding(
                title=desc,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="configuration",
                target=context.target.host,
                affected_url=_first_direct_url(str(f"Accessible at {path}"), ""),
                description=f"Accessible at {path}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        if found == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no sensitive files found")
        return result
