"""TLS configuration review."""
from __future__ import annotations
import re
import ssl
import socket
from urllib.parse import urlparse
from core.execution_manager import ModuleContext
from models.module import (
    BaseModule,
    ModuleResult,
    ModuleStatus,
    ScanMode,
)
from models.result import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    VerificationStatus,
)



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


class TlsReviewModule(BaseModule):
    name = "tls_review"
    version = "0.6.0"
    description = "Reviews TLS certificate and protocol."
    required_mode = ScanMode.PASSIVE
    required_capabilities = []
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        parsed = urlparse(context.target.url)
        if parsed.scheme != "https":
            result.status = ModuleStatus.SKIPPED
            result.errors.append("target is not HTTPS")
            return result
        host = parsed.hostname or ""
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (host, port), timeout=10
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    version = ss.version()
                    cipher = ss.cipher()
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"tls probe failed: {e}")
            return result

        info = (
            f"protocol: {version}\n"
            f"cipher: {cipher[0] if cipher else '?'}\n"
            f"subject: {dict(x[0] for x in cert.get('subject', []))}\n"
            f"issuer: {dict(x[0] for x in cert.get('issuer', []))}\n"
            f"notAfter: {cert.get('notAfter', '')}"
        )

        severity = Severity.INFO
        desc = "TLS endpoint reachable and valid."
        if version in ("TLSv1", "TLSv1.1"):
            severity = Severity.HIGH
            desc = f"Outdated TLS version: {version}"

        result.findings.append(Finding(
            title=f"TLS: {version}",
            severity=severity,
            confidence=Confidence.HIGH,
            category="configuration",
            target=host,
            affected_url=_first_direct_url(str(desc), ""),
            description=desc,
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(
                type=EvidenceType.LOG,
                content=info,
            )],
        ))
        return result
