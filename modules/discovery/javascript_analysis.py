"""JavaScript analysis — extract URLs/endpoints from <script src> files."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_URL_IN_JS_RE = re.compile(
    r'["\']((?:https?://|/)[^"\'\s<>]{4,200})["\']', re.IGNORECASE
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


class JsAnalysisModule(BaseModule):
    name = "js_analysis"
    version = "0.5.0"
    description = "Extracts candidate endpoints from JavaScript bundles."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        target_url = context.target.url
        try:
            page = http.get(target_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"page fetch failed: {e}")
            return result

        scripts = []
        for src in _SCRIPT_SRC_RE.findall(page.text or ""):
            absolute = urljoin(target_url, src)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if not context.scope_guard.is_url_allowed(absolute):
                continue
            scripts.append(absolute)

        if not scripts:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No same-scope <script src> found.")
            return result

        endpoints: set[str] = set()
        for js_url in scripts[:10]:
            try:
                r = http.get(js_url)
            except Exception:
                continue
            for candidate in _URL_IN_JS_RE.findall(r.text or ""):
                if candidate.startswith("/"):
                    endpoints.add(urljoin(target_url, candidate))
                elif context.scope_guard.is_url_allowed(candidate):
                    endpoints.add(candidate)

        if not endpoints:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No endpoints found in JS.")
            return result

        result.findings.append(Finding(
            title=f"JS bundles reveal {len(endpoints)} endpoint candidate(s)",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            category="discovery",
            target=context.target.host,
            affected_url=_first_direct_url(str("Candidate endpoints extracted from JavaScript."), ""),
            description="Candidate endpoints extracted from JavaScript.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.POTENTIAL,
            evidence=[Evidence(type=EvidenceType.LOG,
                               content="\n".join(sorted(endpoints)[:200]))],
        ))
        return result
