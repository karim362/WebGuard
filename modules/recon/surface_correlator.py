"""Correlates links, forms, and API hints into a prioritized attack-surface summary."""
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

_HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"'#]+(?:\?[^"']*)?)["']""", re.I)
_FORM_RE = re.compile(r"""<form\b[^>]*>""", re.I)
_HIGH_VAL_KEYS = {"id", "user_id", "content", "p", "zones", "q", "file", "path", "next", "url"}


class SurfaceCorrelatorModule(BaseModule):
    name = "surface_correlator"
    version = "1.0.0"
    description = "Correlates parameter-bearing links, forms, and external hosts into high-focus targets."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        base_url = context.target.url
        host = context.target.host

        try:
            resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"fetch failed: {e}")
            return result

        html = getattr(resp, "text", "") or ""
        final_url = str(getattr(resp, "url", base_url))

        correlated_links: list[str] = []
        external_hosts: set[str] = set()
        forms_count = len(_FORM_RE.findall(html))

        for m in _HREF_RE.finditer(html):
            raw = m.group(1).strip()
            full = urljoin(final_url, raw)
            parsed = urlparse(full)
            if parsed.netloc and host.lower() not in parsed.netloc.lower():
                external_hosts.add(parsed.netloc.lower())
            qs = parse_qs(parsed.query)
            hits = [k for k in qs if k.lower() in _HIGH_VAL_KEYS]
            if hits and len(correlated_links) < 6:
                correlated_links.append(f"{parsed.path or '/'} [{','.join(hits)}]")

        if correlated_links or forms_count or external_hosts:
            sev = Severity.MEDIUM if (correlated_links and forms_count) else Severity.INFO
            result.findings.append(Finding(
                title=f"Attack-surface correlation: {len(correlated_links)} param route(s), {forms_count} form(s)",
                severity=sev,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=final_url,
                description=(
                    f"Param routes: {', '.join(correlated_links) or 'none'} | "
                    f"External hosts: {', '.join(sorted(external_hosts)[:5]) or 'none'}"
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        else:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no correlated parameter links, forms, or external hosts on root page")
        return result
