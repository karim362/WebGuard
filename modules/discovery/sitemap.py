"""Sitemap module — parses sitemap.xml and records internal URLs."""
from __future__ import annotations
import re
from urllib.parse import urljoin
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

_URL_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


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


class SitemapModule(BaseModule):
    name = "sitemap_parse"
    version = "0.5.0"
    description = "Extracts URLs from sitemap.xml."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        url = urljoin(context.target.url.rstrip("/") + "/", "sitemap.xml")
        try:
            r = http.get(url)
        except Exception as e:
            result.status = ModuleStatus.SKIPPED
            result.errors.append(f"fetch failed: {e}")
            return result
        if r.status_code >= 400:
            result.status = ModuleStatus.PARTIAL
            result.errors.append(f"HTTP {r.status_code}")
            return result

        urls = _URL_RE.findall(r.text or "")
        if not urls:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No <loc> entries found.")
            return result

        result.findings.append(Finding(
            title=f"Sitemap exposes {len(urls)} URL(s)",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="discovery",
            target=context.target.host,
            affected_url=_first_direct_url(str("Sitemap lists paths that may not be linked publicly."), ""),
            description="Sitemap lists paths that may not be linked publicly.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(type=EvidenceType.LOG,
                               content="\n".join(urls[:200]))],
        ))
        return result
