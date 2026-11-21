"""DNS reconnaissance module — records A/AAAA/MX/NS/TXT as informational findings."""
from __future__ import annotations
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

class DnsReconModule(BaseModule):
    name = "dns_recon"
    version = "0.4.0"
    description = "DNS record enumeration (A, AAAA, MX, NS, TXT)."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["dns"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        dns = context.services["dns"]
        host = context.target.host

        if not dns.available():
            result.status = ModuleStatus.SKIPPED
            result.errors.append("dns library not installed")
            return result

        records = dns.all(host)
        flat: dict[str, list[str]] = {k: v for k, v in records.items() if v}

        if not flat:
            result.status = ModuleStatus.PARTIAL
            result.errors.append(f"No DNS records resolved for {host}")
            return result

        body = "\n".join(f"{k}: {', '.join(v)}" for k, v in flat.items())
        result.findings.append(Finding(
            title=f"DNS records for {host}",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="reconnaissance",
            target=host,
            affected_url=f"dns://{host}",
            description="Enumerated DNS records provide attack surface context.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(type=EvidenceType.LOG, content=body)],
        ))

        # Extra check: missing SPF/DMARC hints in TXT
        txt_joined = " ".join(flat.get("TXT", [])).lower()
        if "v=spf1" not in txt_joined:
            result.findings.append(Finding(
                title="No SPF record detected in TXT",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="reconnaissance",
                target=host,
                affected_url=f"dns://{host}",
                description="Missing SPF increases email spoofing risk.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.POTENTIAL,
            ))
        return result
