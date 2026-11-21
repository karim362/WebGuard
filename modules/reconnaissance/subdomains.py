"""
Limited subdomain enumeration via DNS brute force with a small wordlist.
Passive-safe: DNS only, no HTTP, rate-limited.
"""
from __future__ import annotations
import re
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

COMMON_SUBDOMAINS = [
    "www", "api", "admin", "dev", "test", "staging", "beta",
    "app", "mail", "portal", "blog", "shop", "docs",
    "static", "cdn", "assets", "media", "support", "help",
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


class SubdomainsModule(BaseModule):
    name = "subdomains_enum"
    version = "0.4.0"
    description = "Small wordlist subdomain enumeration (DNS only)."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["dns"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        dns = context.services["dns"]
        if not dns.available():
            result.status = ModuleStatus.SKIPPED
            result.errors.append("dns library not installed")
            return result

        host = context.target.host
        found: list[str] = []
        for sub in COMMON_SUBDOMAINS:
            candidate = f"{sub}.{host}"
            try:
                if dns.resolve_exists(candidate):
                    found.append(candidate)
            except Exception:
                continue

        if found:
            result.findings.append(Finding(
                title=f"Discovered {len(found)} subdomain(s)",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="reconnaissance",
                target=host,
                affected_url=_first_direct_url(str("Subdomains may host separate attack surfaces."), ""),
                description="Subdomains may host separate attack surfaces.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
                evidence=[Evidence(
                    type=EvidenceType.LOG,
                    content="\n".join(found),
                )],
            ))
        else:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No common subdomains resolved.")
        return result
