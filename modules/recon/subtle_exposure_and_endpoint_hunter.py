"""Probes subtle metadata/config/debug paths and extracts additional high-signal parameters."""
from __future__ import annotations
import re
from urllib.parse import parse_qs, urljoin, urlparse
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

SUBTLE_PATHS = (
    "/.well-known/openid-configuration",
    "/actuator",
    "/actuator/env",
    "/debug",
    "/debug/vars",
    "/trace",
    "/.DS_Store",
    "/clientaccesspolicy.xml",
    "/info.php",
)
_LINK_RE = re.compile(r"""\b(?:href|src|action)\s*=\s*["']([^"'#]+(?:\?[^"']*)?)["']""", re.I)
_SUBTLE_PARAMS = {
    "debug", "trace", "test", "role", "admin", "cmd", "exec",
    "callback", "jsonp", "preview", "draft", "export", "download",
}
_SOFT_404_RE = re.compile(r"(?i)\b(404|not found|page not found|صفحة غير موجودة)\b")


class SubtleExposureAndEndpointHunterModule(BaseModule):
    name = "subtle_exposure_and_endpoint_hunter"
    version = "1.0.0"
    description = "Checks subtle config/debug/metadata endpoints and high-signal query parameters."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = context.target.host

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        root_html = getattr(root_resp, "text", "") or ""
        final_url = str(getattr(root_resp, "url", base_url))

        hits: list[str] = []
        high_sev = False
        for p in SUBTLE_PATHS:
            u = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
            if guard is not None and hasattr(guard, "is_allowed") and not guard.is_allowed(u):
                continue
            try:
                r = http.get(u)
            except Exception:
                continue
            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""
            if code == 200 and body.strip():
                if len(body) < 4000 and _SOFT_404_RE.search(body):
                    continue
                hits.append(f"{p} (200)")
                if p in ("/actuator/env", "/debug/vars", "/.DS_Store", "/info.php"):
                    high_sev = True
            elif code in (401, 403):
                hits.append(f"{p} ({code})")

        subtle_param_hits: set[str] = set()
        for m in _LINK_RE.finditer(root_html):
            full_u = urljoin(final_url, m.group(1).strip())
            for qk in parse_qs(urlparse(full_u).query):
                if qk.lower() in _SUBTLE_PARAMS:
                    subtle_param_hits.add(qk.lower())

        if hits:
            result.findings.append(Finding(
                title=f"Subtle endpoints/files observed ({len(hits)})",
                severity=Severity.HIGH if high_sev else Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="exposure",
                target=host,
                affected_url=final_url,
                description=f"Observed: {', '.join(hits[:6])}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if subtle_param_hits:
            result.findings.append(Finding(
                title=f"Subtle high-interest parameters found ({len(subtle_param_hits)})",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="input_security",
                target=host,
                affected_url=final_url,
                description=f"Params: {', '.join(sorted(subtle_param_hits))}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no subtle exposure endpoints or subtle parameters observed")
        return result
