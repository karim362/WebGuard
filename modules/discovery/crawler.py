"""Crawler module — BFS crawl, emits discovered URLs as info finding."""
from __future__ import annotations
import re
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)
from services.crawler_service import CrawlerService


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


class CrawlerModule(BaseModule):
    name = "crawler"
    version = "0.5.0"
    description = "BFS crawler to discover pages and forms."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        crawler = CrawlerService(http, max_pages=25, max_depth=2)
        try:
            discovery = crawler.crawl(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"crawl failed: {e}")
            return result

        # Store discovery for later modules (via context.services["discovery"])
        context.services["discovery"] = discovery

        if not discovery.urls:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No URLs discovered.")
            return result

        # Emit informational finding with summary + evidence
        lines = [f"{u.url}  [{u.method} {u.status or '?'}]" for u in discovery.urls]
        result.findings.append(Finding(
            title=f"Crawled {len(discovery.urls)} URL(s)",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="discovery",
            target=context.target.host,
            affected_url=_first_direct_url(str("Crawl summary of discovered URLs."), ""),
            description="Crawl summary of discovered URLs.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(type=EvidenceType.LOG, content="\n".join(lines[:100]))],
        ))

        if discovery.forms:
            form_lines = [f"{f.method} {f.action} inputs={f.inputs}"
                          for f in discovery.forms]
            result.findings.append(Finding(
                title=f"Discovered {len(discovery.forms)} HTML form(s)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="discovery",
                target=context.target.host,
                affected_url=_first_direct_url(str("Forms indicate input points for further review."), ""),
                description="Forms indicate input points for further review.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
                evidence=[Evidence(type=EvidenceType.LOG, content="\n".join(form_lines[:50]))],
            ))
        return result
