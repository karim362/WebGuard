"""Multi-source domain, subdomain, and origin hunter across HTML, JS bundles, headers, robots/sitemap, and reachability."""
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

_STATIC_EXT_RE = re.compile(
    r"\.(?:css|scss|sass|less|png|jpe?g|gif|webp|svg|ico|bmp|woff2?|ttf|eot|otf|map)(?:\?.*)?$",
    re.I,
)
_URL_ATTR_RE = re.compile(r"""\b(?:href|src|action|data-src)\s*=\s*["']([^"'#\s]+)["']""", re.I)
_JS_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_HOST_TOKEN_RE = re.compile(
    r"""\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b""",
    re.I,
)
_ROBOTS_HOST_RE = re.compile(r"(?im)^(?:host|sitemap)\s*:\s*(\S+)")
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)



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

def _is_static(u: str) -> bool:
    return bool(_STATIC_EXT_RE.search(urlparse(u).path or ""))


def _root_domain(host: str) -> str:
    h = (host or "").strip().lower().split(":", 1)[0]
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def _clean_host(raw: str) -> str:
    h = (raw or "").strip().lower()
    if "://" in h:
        h = urlparse(h).hostname or ""
    h = h.split(":", 1)[0].strip(".")
    return h


class MultiSourceDomainAndOriginHunterModule(BaseModule):
    name = "multi_source_domain_and_origin_hunter"
    version = "1.0.1"
    description = "Discovers and probes domains, subdomains, and external origins from HTML, JS, headers, robots.txt, and sitemap.xml."
    required_mode = ScanMode.ADVANCED
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = _clean_host(context.target.host)
        root_dom = _root_domain(host)

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        html = getattr(root_resp, "text", "") or ""
        headers = getattr(root_resp, "headers", {}) or {}
        final_url = str(getattr(root_resp, "url", base_url))
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}

        def _allowed(u: str) -> bool:
            if not u or _is_static(u):
                return False
            if guard is None or not hasattr(guard, "is_allowed"):
                return True
            return bool(guard.is_allowed(u))

        subdomains: list[str] = []
        external_origins: list[str] = []
        js_targets: list[str] = []

        def _record_host(candidate: str) -> None:
            ch = _clean_host(candidate)
            if not ch or "." not in ch or len(ch) > 120:
                return
            if root_dom and (ch == root_dom or ch.endswith("." + root_dom)):
                if ch != host and ch not in subdomains and len(subdomains) < 25:
                    subdomains.append(ch)
            else:
                if ch not in external_origins and len(external_origins) < 25:
                    external_origins.append(ch)

        # 1. Non-static HTML attributes & JS targets
        for m in _URL_ATTR_RE.finditer(html):
            raw_u = m.group(1).strip()
            full_u = urljoin(final_url, raw_u)
            if _is_static(full_u):
                continue
            parsed = urlparse(full_u)
            if parsed.hostname:
                _record_host(parsed.hostname)
            if parsed.scheme in ("http", "https") and full_u.lower().split("?", 1)[0].endswith(".js"):
                if _allowed(full_u) and full_u not in js_targets and len(js_targets) < 6:
                    js_targets.append(full_u)

        for sm in _JS_SRC_RE.finditer(html):
            ju = urljoin(final_url, sm.group(1).strip())
            if _allowed(ju) and ju not in js_targets and len(js_targets) < 6:
                js_targets.append(ju)

        # 2. JS bundles host/subdomain extraction
        for ju in js_targets:
            try:
                jr = http.get(ju)
                jbody = getattr(jr, "text", "") or ""
                for hm in _HOST_TOKEN_RE.finditer(jbody[:200000]):
                    tok = hm.group(1).lower()
                    if root_dom and (tok == root_dom or tok.endswith("." + root_dom)):
                        _record_host(tok)
            except Exception:
                continue

        # 3. Response headers (CSP, CORS, Location) + robots.txt + sitemap.xml
        for hk in ("content-security-policy", "access-control-allow-origin", "location"):
            hv = hmap.get(hk, "")
            if hv:
                for hm in _HOST_TOKEN_RE.finditer(hv):
                    _record_host(hm.group(1))

        for meta_path in ("/robots.txt", "/sitemap.xml"):
            mu = urljoin(final_url.rstrip("/") + "/", meta_path.lstrip("/"))
            if not _allowed(mu):
                continue
            try:
                mr = http.get(mu)
                if int(getattr(mr, "status_code", 0) or 0) == 200:
                    mbody = getattr(mr, "text", "") or ""
                    for rm in _ROBOTS_HOST_RE.finditer(mbody):
                        val = rm.group(1).strip()
                        if val.startswith("http"):
                            p_val = urlparse(val)
                            if p_val.hostname:
                                _record_host(p_val.hostname)
                        else:
                            _record_host(val)
                    for lm in _SITEMAP_LOC_RE.finditer(mbody):
                        loc_u = lm.group(1).strip()
                        if _is_static(loc_u):
                            continue
                        p_loc = urlparse(loc_u)
                        if p_loc.hostname:
                            _record_host(p_loc.hostname)
            except Exception:
                continue

        # 4. Probe discovered subdomains for reachability & header signals
        active_subs: list[str] = []
        sub_header_notes: list[str] = []
        for sub in subdomains[:8]:
            scheme = urlparse(final_url).scheme or "https"
            sub_url = f"{scheme}://{sub}/"
            if not _allowed(sub_url):
                continue
            try:
                sr = http.get(sub_url)
                scode = int(getattr(sr, "status_code", 0) or 0)
                if scode > 0:
                    active_subs.append(f"{sub} [{scode}]")
                    shdrs = {str(k).lower(): str(v) for k, v in (getattr(sr, "headers", {}) or {}).items()}
                    if scheme == "https" and not shdrs.get("strict-transport-security", "").strip():
                        sub_header_notes.append(f"{sub}: missing HSTS")
            except Exception:
                continue

        if sub_header_notes:
            result.findings.append(Finding(
                title=f"Discovered subdomain transport header gaps ({len(sub_header_notes)})",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="configuration",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(sub_header_notes[:6])), final_url),
                description=" | ".join(sub_header_notes[:6]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if subdomains or external_origins or active_subs:
            parts: list[str] = []
            if subdomains:
                parts.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains[:8])}")
            if active_subs:
                parts.append(f"Probed: {', '.join(active_subs[:6])}")
            if external_origins:
                parts.append(f"External origins ({len(external_origins)}): {', '.join(external_origins[:8])}")
            result.findings.append(Finding(
                title="Multi-source domain, subdomain, and origin inventory",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(" ; ".join(parts)), final_url),
                description=" ; ".join(parts),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no additional subdomains, external origins, or subdomain header gaps observed")
        return result
