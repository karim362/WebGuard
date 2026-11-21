"""Endpoint classification from crawler discovery."""
from __future__ import annotations
from urllib.parse import urlparse
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

SENSITIVE_HINTS = ("admin", "login", "logout", "dashboard", "settings",
                   "config", "backup", "debug", "internal", "private",
                   "api", "graphql", "wp-admin", "phpmyadmin", "actuator")

class EndpointsModule(BaseModule):
    name = "endpoints_classify"
    version = "0.5.0"
    description = "Classifies endpoints and flags sensitive paths."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        discovery = context.services.get("discovery")
        if discovery is None:
            result.status = ModuleStatus.SKIPPED
            result.errors.append("crawler discovery not available")
            return result

        sensitive: list[str] = []
        by_ext: dict[str, int] = {}
        for u in discovery.urls:
            parsed = urlparse(u.url)
            path = parsed.path.lower()
            for hint in SENSITIVE_HINTS:
                if hint in path:
                    sensitive.append(u.url)
                    break
            ext = path.rsplit(".", 1)[-1] if "." in path else "(none)"
            by_ext[ext] = by_ext.get(ext, 0) + 1

        summary_lines = [f"{k}: {v}" for k, v in sorted(by_ext.items(),
                                                       key=lambda x: -x[1])]
        result.findings.append(Finding(
            title=f"Endpoint inventory ({len(discovery.urls)} URLs)",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="discovery",
            target=context.target.host,
            affected_url=context.target.url,
            description="Distribution of URL extensions in scope.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(type=EvidenceType.LOG, content="\n".join(summary_lines))],
        ))

        if sensitive:
            unique = sorted(set(sensitive))
            result.findings.append(Finding(
                title=f"Sensitive-looking paths ({len(unique)})",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="discovery",
                target=context.target.host,
                affected_url=context.target.url,
                description="Paths worth manual review for access control.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.POTENTIAL,
                evidence=[Evidence(type=EvidenceType.LOG, content="\n".join(unique[:100]))],
            ))
        return result
