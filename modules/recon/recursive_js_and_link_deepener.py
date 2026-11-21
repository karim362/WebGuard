"""Recursively mines JS bundles and internal links to probe discovered endpoints."""
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

_ASSET_RE = re.compile(
    r"""(?:src|href|data-src|data-url)\s*=\s*["']([^"'#]+(?:\?[^"']*)?)["']""",
    re.I,
)
_ENDPOINT_RE = re.compile(
    r"""["']((?:/api/|/v[1-9]/|/ajax/|/auth/|/admin/|/user/|/account/|/search|/upload|/export)[A-Za-z0-9_./:-]{1,90})["']"""
)


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class RecursiveJsAndLinkDeepenerModule(BaseModule):
    name = "recursive_js_and_link_deepener"
    version = "1.0.0"
    description = "Mines internal links and JS files, then probes discovered endpoint candidates."
    required_mode = ScanMode.ADVANCED
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
        js_files: list[str] = []
        internal_pages: list[str] = []
        query_params: set[str] = set()
        seen: set[str] = set()

        def _allowed(u: str) -> bool:
            if guard is None or not hasattr(guard, "is_allowed"):
                return True
            return bool(guard.is_allowed(u))

        for m in _ASSET_RE.finditer(root_html):
            raw = m.group(1).strip()
            full = urljoin(base_url, raw)
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https") or not _allowed(full):
                continue
            for qk in parse_qs(parsed.query):
                query_params.add(qk)
                if len(query_params) >= 25:
                    break
            clean_u = full.split("#", 1)[0]
            if clean_u in seen:
                continue
            seen.add(clean_u)
            if parsed.path.lower().endswith(".js") and len(js_files) < 10:
                js_files.append(clean_u)
            elif not parsed.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".woff", ".woff2", ".mp4")):
                if len(internal_pages) < 8:
                    internal_pages.append(clean_u)

        corpus = [root_html]
        for page_u in internal_pages[:5]:
            try:
                pr = http.get(page_u)
                ptxt = getattr(pr, "text", "") or ""
                if ptxt:
                    corpus.append(ptxt[:120000])
                for m in _ASSET_RE.finditer(ptxt):
                    js_cand = urljoin(page_u, m.group(1).strip()).split("#", 1)[0]
                    if urlparse(js_cand).path.lower().endswith(".js") and _allowed(js_cand) and js_cand not in js_files and len(js_files) < 12:
                        js_files.append(js_cand)
            except Exception:
                continue

        for ju in js_files:
            try:
                jr = http.get(ju)
                jtxt = getattr(jr, "text", "") or ""
                if jtxt:
                    corpus.append(jtxt[:150000])
            except Exception:
                continue

        discovered_routes: list[str] = []
        seen_routes: set[str] = set()
        for blob in corpus:
            for em in _ENDPOINT_RE.findall(blob):
                if em not in seen_routes:
                    seen_routes.add(em)
                    discovered_routes.append(em)
                    if len(discovered_routes) >= 35:
                        break

        live_probes: list[str] = []
        for ep in discovered_routes[:10]:
            probe_u = urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
            if not _allowed(probe_u):
                continue
            try:
                er = http.get(probe_u)
                code = getattr(er, "status_code", 0)
                if code in (200, 201, 204, 301, 302, 401, 403, 405):
                    live_probes.append(f"{ep} [{code}]")
            except Exception:
                continue

        if js_files or discovered_routes:
            result.findings.append(Finding(
                title=f"Deep surface: {len(js_files)} JS file(s), {len(discovered_routes)} route pattern(s)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str((
                    f"Sample routes: {', '.join(discovered_routes[:6]) or 'none'}"
                    + (f" | Params: {', '.join(sorted(query_params)[:6])}" if query_params else "")
                )), base_url),
                description=(
                    f"Sample routes: {', '.join(discovered_routes[:6]) or 'none'}"
                    + (f" | Params: {', '.join(sorted(query_params)[:6])}" if query_params else "")
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if live_probes:
            result.findings.append(Finding(
                title=f"Live probed routes ({len(live_probes)}) responded in scope",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(f"Responses: {', '.join(live_probes[:6])}"), base_url),
                description=f"Responses: {', '.join(live_probes[:6])}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no deep JS/link endpoints or live route responses found")
        return result
