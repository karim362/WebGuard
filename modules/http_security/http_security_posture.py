"""HTTP methods and CORS header posture review."""
from __future__ import annotations
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

_RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")


class HttpSecurityPostureModule(BaseModule):
    name = "http_security_posture"
    version = "0.9.0"
    description = "Reviews allowed HTTP methods and CORS headers safely."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        url = context.target.url
        origin = f"https://{context.target.host}"

        try:
            r = http.get(url, headers={"Origin": origin})
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"probe failed: {e}")
            return result

        headers = getattr(r, "headers", {}) or {}
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}

        allow_hdr = hmap.get("allow", "") or hmap.get(
            "access-control-allow-methods", ""
        )
        exposed_risky = [
            m for m in _RISKY_METHODS if m in allow_hdr.upper()
        ]
        if exposed_risky:
            result.findings.append(Finding(
                title=f"Risky HTTP methods advertised: {', '.join(exposed_risky)}",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="configuration",
                target=context.target.host,
                affected_url=str(getattr(r, "url", url)),
                description=f"Advertised methods header: {allow_hdr}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.POTENTIAL,
            ))

        acao = hmap.get("access-control-allow-origin", "").strip()
        acac = hmap.get("access-control-allow-credentials", "").strip().lower()
        if acao == "*" and acac == "true":
            result.findings.append(Finding(
                title="Wildcard CORS origin combined with credentials",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="configuration",
                target=context.target.host,
                affected_url=str(getattr(r, "url", url)),
                description=(
                    "Access-Control-Allow-Origin is '*' while "
                    "Access-Control-Allow-Credentials is 'true'."
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        elif acao == "*":
            result.findings.append(Finding(
                title="Permissive wildcard CORS policy (*)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="configuration",
                target=context.target.host,
                affected_url=str(getattr(r, "url", url)),
                description="Access-Control-Allow-Origin is set to '*'.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no risky HTTP methods or CORS issues observed")
        return result
