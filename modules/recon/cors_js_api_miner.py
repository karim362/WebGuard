"""CORS reflected-origin check and JavaScript API endpoint extraction."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
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

_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_API_ENDPOINT_RE = re.compile(
    r"""["']((?:/api/|/v[1-9]/|/graphql|/rest/|/auth/|/admin/)[A-Za-z0-9_./:-]{1,90})["']"""
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


class CorsJsApiMinerModule(BaseModule):
    name = "cors_js_api_miner"
    version = "1.0.0"
    description = "Audits CORS origin reflection and extracts API routes from JS assets."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        url = context.target.url
        probe_origin = "https://probe.example"

        try:
            cors_resp = http.get(url, headers={"Origin": probe_origin})
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"cors probe failed: {e}")
            return result

        headers = getattr(cors_resp, "headers", {}) or {}
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}
        acao = hmap.get("access-control-allow-origin", "").strip()
        acac = hmap.get("access-control-allow-credentials", "").strip().lower()

        if acao == probe_origin and acac == "true":
            result.findings.append(Finding(
                title="Reflected CORS origin allowed with credentials",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="configuration",
                target=context.target.host,
                affected_url=_first_direct_url(str((
                    "Server echoed external Origin header with "
                    "Access-Control-Allow-Credentials: true."
                )), ""),
                description=(
                    "Server echoed external Origin header with "
                    "Access-Control-Allow-Credentials: true."
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        elif acao == probe_origin:
            result.findings.append(Finding(
                title="Reflected CORS origin without credentials",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="configuration",
                target=context.target.host,
                affected_url=_first_direct_url(str("Server echoed test Origin header without credential flag."), ""),
                description="Server echoed test Origin header without credential flag.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        body = getattr(cors_resp, "text", "") or ""
        js_urls: list[str] = []
        seen_js: set[str] = set()
        for m in _SCRIPT_SRC_RE.finditer(body):
            full_js = urljoin(url, m.group(1).strip())
            parsed = urlparse(full_js)
            if parsed.scheme in ("http", "https") and full_js not in seen_js:
                if guard is None or not hasattr(guard, "is_allowed") or guard.is_allowed(full_js):
                    seen_js.add(full_js)
                    js_urls.append(full_js)
                    if len(js_urls) >= 6:
                        break

        endpoints: set[str] = set()
        for ju in js_urls:
            try:
                jr = http.get(ju)
                jtxt = getattr(jr, "text", "") or ""
                for ep in _API_ENDPOINT_RE.findall(jtxt[:120000]):
                    endpoints.add(ep)
                    if len(endpoints) >= 25:
                        break
            except Exception:
                continue

        if endpoints:
            sample = ", ".join(sorted(endpoints)[:6])
            result.findings.append(Finding(
                title=f"Mined {len(endpoints)} API/route pattern(s) from JS",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=context.target.host,
                affected_url=_first_direct_url(str(f"Sample routes: {sample}"), ""),
                description=f"Sample routes: {sample}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no CORS reflection or JS API patterns found")
        return result
