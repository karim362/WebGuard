"""
Security Headers module — passive review of HTTP response security headers.
Flags missing/misconfigured headers. Emits one Finding per issue.
"""
from __future__ import annotations
import re
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

# (header_name, expected_check, severity_if_missing, description)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "hsts", Severity.MEDIUM,
     "HSTS header missing — browser may downgrade to HTTP."),
    ("Content-Security-Policy", "csp", Severity.MEDIUM,
     "CSP header missing — XSS mitigation is weakened."),
    ("X-Content-Type-Options", "nosniff", Severity.LOW,
     "X-Content-Type-Options missing — MIME sniffing enabled."),
    ("X-Frame-Options", "frame", Severity.LOW,
     "X-Frame-Options missing — clickjacking possible."),
    ("Referrer-Policy", "referrer", Severity.LOW,
     "Referrer-Policy missing — referrer leakage possible."),
    ("Permissions-Policy", "permissions", Severity.INFO,
     "Permissions-Policy missing — browser features unrestricted."),
]

def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class SecurityHeadersModule(BaseModule):
    name = "security_headers"
    version = "0.2.0"
    description = "Reviews HTTP response security headers."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name, status=ModuleStatus.SUCCESS)
        try:
            response = context.services["http"].get(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"request failed: {e}")
            return result

        h = response.headers
        url = str(response.url)

        for header_name, _key, severity, desc in SECURITY_HEADERS:
            if header_name.lower() not in {k.lower() for k in h.keys()}:
                result.findings.append(Finding(
                    title=f"Missing security header: {header_name}",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category="configuration",
                    target=context.target.host,
                    affected_url=_first_direct_url(str(desc), ""),
                    description=desc,
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_RESPONSE,
                        content=f"HTTP {response.status_code} — headers observed:\n"
                                + "\n".join(f"{k}: {v}" for k, v in h.items()),
                        note="Header missing in response",
                    )],
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                ))

        # Check for leaked Server/X-Powered-By (info disclosure)
        for leak in ("server", "x-powered-by"):
            if leak in {k.lower() for k in h.keys()}:
                val = h.get(leak) or h.get(leak.title())
                if val:
                    result.findings.append(Finding(
                        title=f"Information disclosure via {leak} header",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category="configuration",
                        target=context.target.host,
                        affected_url=_first_direct_url(str(f"The '{leak}' header reveals: {val}"), ""),
                        description=f"The '{leak}' header reveals: {val}",
                        module=self.name,
                        scan_id=context.scan_id,
                        verification_status=VerificationStatus.CONFIRMED,
                    ))

        return result
