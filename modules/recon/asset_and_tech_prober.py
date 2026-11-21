"""Probes well-known security/metadata files, service endpoints, and header links."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
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

META_AND_SERVICE_PATHS = (
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/wp-json/",
    "/api/health",
    "/server-info",
    "/metrics",
)

_SOFT_404_RE = re.compile(r"(?i)\b(not found|404|page does not exist|صفحة غير موجودة)\b")


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class AssetAndTechProberModule(BaseModule):
    name = "asset_and_tech_prober"
    version = "1.0.0"
    description = "Probes security metadata, service endpoints, and response header hints."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = context.target.host

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        root_headers = getattr(root_resp, "headers", {}) or {}
        hmap = {str(k).lower(): str(v) for k, v in root_headers.items()}

        if "x-powered-by" in hmap and hmap["x-powered-by"].strip():
            result.findings.append(Finding(
                title=f"X-Powered-By exposed: {hmap['x-powered-by'].strip()}",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="fingerprint",
                target=host,
                affected_url=_first_direct_url(str("Backend framework/runtime header is publicly visible."), base_url),
                description="Backend framework/runtime header is publicly visible.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if "link" in hmap and hmap["link"].strip():
            result.findings.append(Finding(
                title="HTTP Link header exposes external/API resources",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(f"Link header: {hmap['link'][:160]}"), base_url),
                description=f"Link header: {hmap['link'][:160]}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        reachable_hits: list[str] = []
        for p in META_AND_SERVICE_PATHS:
            probe_url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
            if guard is not None and hasattr(guard, "is_allowed") and not guard.is_allowed(probe_url):
                continue
            try:
                resp = http.get(probe_url)
            except Exception:
                continue
            code = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "") or ""
            if code == 200 and body.strip():
                if len(body) < 3500 and _SOFT_404_RE.search(body):
                    continue
                reachable_hits.append(f"{p} (200)")
            elif code in (401, 403):
                reachable_hits.append(f"{p} ({code})")

        if reachable_hits:
            result.findings.append(Finding(
                title=f"Discovered {len(reachable_hits)} metadata/service endpoint(s)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(f"Endpoints: {', '.join(reachable_hits[:8])}"), base_url),
                description=f"Endpoints: {', '.join(reachable_hits[:8])}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no additional metadata/service endpoints or headers found")
        return result
