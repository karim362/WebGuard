"""Discovers common API and GraphQL endpoints."""
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

API_PATHS = [
    "/api",
    "/api/v1",
    "/graphql",
    "/openapi.json",
    "/swagger.json",
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


class ApiDiscoveryModule(BaseModule):
    name = "api_discovery"
    version = "0.7.0"
    description = "Checks common REST and GraphQL paths."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        base = context.target.url.rstrip("/") + "/"
        http = context.services["http"]
        found = 0
        for p in API_PATHS:
            url = urljoin(base, p.lstrip("/"))
            try:
                r = http.get(url)
            except Exception as e:
                result.errors.append(f"{p}: {e}")
                continue
            code = getattr(r, "status_code", 0)
            if code in (200, 401, 403):
                found += 1
                result.findings.append(Finding(
                    title=f"API endpoint present ({code}): {p}",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    category="api_security",
                    target=context.target.host,
                    affected_url=_first_direct_url(str(f"Endpoint responded with HTTP {code}."), ""),
                    description=f"Endpoint responded with HTTP {code}.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.POTENTIAL,
                ))
        if found == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no standard API paths detected")
        return result
