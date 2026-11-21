"""Passive file discovery: robots.txt, sitemap.xml, security.txt."""
from __future__ import annotations
import re
from urllib.parse import urljoin
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

PATHS = [
    ("/robots.txt", "Robots.txt"),
    ("/sitemap.xml", "Sitemap"),
    ("/.well-known/security.txt", "Security.txt"),
]

def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class PassiveFilesModule(BaseModule):
    name = "passive_files"
    version = "0.4.0"
    description = "Fetches robots.txt, sitemap.xml, security.txt."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        base = context.target.url

        for path, label in PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = http.get(url)
            except Exception as e:
                result.errors.append(f"{label}: {e}")
                continue
            if r.status_code >= 400:
                continue
            content = r.text[:5000] if hasattr(r, "text") else ""
            result.findings.append(Finding(
                title=f"{label} exposed",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="reconnaissance",
                target=context.target.host,
                affected_url=_first_direct_url(str(f"{label} is publicly accessible."), ""),
                description=f"{label} is publicly accessible.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
                evidence=[Evidence(
                    type=EvidenceType.HTTP_RESPONSE,
                    content=f"HTTP {r.status_code}\n{content[:1000]}",
                )],
            ))

        if not result.findings and not result.errors:
            result.status = ModuleStatus.PARTIAL
        return result
