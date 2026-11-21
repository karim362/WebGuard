"""Extracts internal links, JS endpoints, and query/JSON/form parameters in scope."""
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

_LINK_RE = re.compile(r"""\b(?:href|src|action)\s*=\s*["']([^"'#]+(?:\?[^"']*)?)["']""", re.I)
_ROUTE_RE = re.compile(
    r"""["']((?:/api/|/v[1-9]/|/graphql|/rest/|/auth/|/admin/|/user/|/account/|/search|/items|/posts)[A-Za-z0-9_./:-]{1,90})["']"""
)
_JSON_KEY_RE = re.compile(r"""["']([a-zA-Z0-9_]{2,28})["']\s*:""")


class JsLinkDeepMinerModule(BaseModule):
    name = "js_link_deep_miner"
    version = "1.0.0"
    description = "Mines internal pages and JS assets for routes, query parameters, and structured keys."
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
        params: set[str] = set()
        js_assets: list[str] = []
        sub_pages: list[str] = []
        seen: set[str] = set()

        def _ok(u: str) -> bool:
            if guard is None or not hasattr(guard, "is_allowed"):
                return True
            return bool(guard.is_allowed(u))

        for m in _LINK_RE.finditer(root_html):
            full = urljoin(base_url, m.group(1).strip())
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https") or not _ok(full):
                continue
            for qk in parse_qs(parsed.query):
                params.add(qk)
                if len(params) >= 30:
                    break
            clean = full.split("#", 1)[0]
            if clean in seen:
                continue
            seen.add(clean)
            low_p = parsed.path.lower()
            if low_p.endswith(".js") and len(js_assets) < 10:
                js_assets.append(clean)
            elif not low_p.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff2", ".ico")):
                if len(sub_pages) < 5:
                    sub_pages.append(clean)

        corpus = [root_html]
        for sp in sub_pages:
            try:
                sr = http.get(sp)
                stxt = getattr(sr, "text", "") or ""
                if stxt:
                    corpus.append(stxt[:120000])
                for m in _LINK_RE.finditer(stxt):
                    cand = urljoin(sp, m.group(1).strip()).split("#", 1)[0]
                    if urlparse(cand).path.lower().endswith(".js") and _ok(cand) and cand not in js_assets and len(js_assets) < 12:
                        js_assets.append(cand)
            except Exception:
                continue

        for ja in js_assets:
            try:
                jr = http.get(ja)
                jtxt = getattr(jr, "text", "") or ""
                if jtxt:
                    corpus.append(jtxt[:150000])
            except Exception:
                continue

        routes: set[str] = set()
        keys: set[str] = set()
        for blob in corpus:
            for rm in _ROUTE_RE.findall(blob):
                routes.add(rm)
                if len(routes) >= 35:
                    break
            for km in _JSON_KEY_RE.findall(blob):
                if km.lower() not in ("type", "name", "class", "style", "href", "src"):
                    keys.add(km)
                    if len(keys) >= 25:
                        break

        if routes or params or keys:
            result.findings.append(Finding(
                title=f"Deep miner: {len(routes)} route(s), {len(params)} param(s), {len(keys)} key(s)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=base_url,
                description=(
                    f"Routes: {', '.join(sorted(routes)[:5]) or 'none'} | "
                    f"Params: {', '.join(sorted(params)[:6]) or 'none'} | "
                    f"Keys: {', '.join(sorted(keys)[:6]) or 'none'}"
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        else:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no additional routes, parameters, or structured keys extracted")
        return result
