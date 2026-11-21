"""CORS policy review."""
from __future__ import annotations
import re
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


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class CorsReviewModule(BaseModule):
    name = "cors_review"
    version = "0.6.0"
    description = "Checks CORS configuration."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        url = context.target.url
        headers = {"Origin": "https://evil.example"}
        try:
            r = context.services["http"].get(url, headers=headers)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"fetch failed: {e}")
            return result

        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            result.findings.append(Finding(
                title="CORS wildcard with credentials",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="api_security",
                target=context.target.host,
                affected_url=_first_direct_url(str("ACAO=* with ACAC=true allows "
                            "any origin to read responses."), ""),
                description="ACAO=* with ACAC=true allows "
                            "any origin to read responses.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        elif acao == "*":
            result.findings.append(Finding(
                title="CORS wildcard origin",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="api_security",
                target=context.target.host,
                affected_url=_first_direct_url(str("Access-Control-Allow-Origin=* "
                            "permits all origins."), ""),
                description="Access-Control-Allow-Origin=* "
                            "permits all origins.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        elif acao == "https://evil.example":
            result.findings.append(Finding(
                title="CORS reflects arbitrary Origin",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="api_security",
                target=context.target.host,
                affected_url=_first_direct_url(str("Server echoes untrusted origin."), ""),
                description="Server echoes untrusted origin.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.POTENTIAL,
            ))
        else:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no CORS issue detected")
        return result
