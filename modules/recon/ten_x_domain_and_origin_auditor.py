"""Deep multi-source domain, subdomain, subdomain-path, security-gap, and cross-host redirect auditor."""
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
_URL_ATTR_RE = re.compile(r"""\b(?:href|src|action|data-src|content)\s*=\s*["']([^"'#\s]+)["']""", re.I)
_JS_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_HOST_TOKEN_RE = re.compile(
    r"""\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b""",
    re.I,
)
_ROBOTS_LINE_RE = re.compile(r"(?im)^(?:host|sitemap|allow|disallow)\s*:\s*(\S+)")
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_SUB_PATHS = ("/api", "/admin", "/login", "/.env", "/.git/HEAD")
_LEAK_ERR_RE = re.compile(
    r"(?i)\b(?:api_key|secret_key|private_key|access_token|db_password|sql syntax|traceback \(most recent call last\)|fatal error)\b"
)
_SOFT_404_RE = re.compile(r"(?i)\b(?:404 not found|page not found|not found on this server)\b")



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


class TenXDomainAndOriginAuditorModule(BaseModule):
    name = "ten_x_domain_and_origin_auditor"
    version = "1.0.0"
    description = "Deeply audits subdomains, external origins, subdomain sensitive paths, cross-host redirects, and header gaps."
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
                if ch != host and ch not in subdomains and len(subdomains) < 30:
                    subdomains.append(ch)
            else:
                if ch not in external_origins and len(external_origins) < 30:
                    external_origins.append(ch)

        # 1. HTML attributes & JS script targets
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
                for hm in _HOST_TOKEN_RE.finditer(jbody[:220000]):
                    tok = hm.group(1).lower()
                    if root_dom and (tok == root_dom or tok.endswith("." + root_dom)):
                        _record_host(tok)
            except Exception:
                continue

        # 3. Headers + robots.txt + sitemap.xml
        for hk in ("content-security-policy", "access-control-allow-origin", "location", "server"):
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
                    for rm in _ROBOTS_LINE_RE.finditer(mbody):
                        val = rm.group(1).strip()
                        if val.startswith("http"):
                            p_val = urlparse(val)
                            if not _is_static(val) and p_val.hostname:
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

        # 4. Probe subdomains, sensitive paths on subdomains, cross-host redirects, and header gaps
        high_signals: list[str] = []
        med_signals: list[str] = []
        low_gaps: list[str] = []
        active_subs: list[str] = []

        scheme = urlparse(final_url).scheme or "https"
        for sub in subdomains[:8]:
            sub_url = f"{scheme}://{sub}/"
            if not _allowed(sub_url):
                continue
            try:
                sr = http.get(sub_url)
                scode = int(getattr(sr, "status_code", 0) or 0)
                sbody = getattr(sr, "text", "") or ""
                shdrs = {str(k).lower(): str(v) for k, v in (getattr(sr, "headers", {}) or {}).items()}
                if scode > 0:
                    active_subs.append(f"{sub} [{scode}]")
                if _LEAK_ERR_RE.search(sbody):
                    high_signals.append(f"{sub}/: leak/error cue")
                loc = shdrs.get("location", "")
                if loc:
                    loc_host = _clean_host(urljoin(sub_url, loc))
                    if loc_host and loc_host != sub:
                        med_signals.append(f"{sub} -> {loc_host}")
                missing: list[str] = []
                if scheme == "https" and not shdrs.get("strict-transport-security", "").strip():
                    missing.append("HSTS")
                if not shdrs.get("content-security-policy", "").strip():
                    missing.append("CSP")
                if missing:
                    low_gaps.append(f"{sub}: missing {', '.join(missing)}")
            except Exception:
                continue

            for sp in _SUB_PATHS:
                if _is_static(sp):
                    continue
                sp_url = f"{scheme}://{sub}{sp}"
                if not _allowed(sp_url):
                    continue
                try:
                    pr = http.get(sp_url)
                    pcode = int(getattr(pr, "status_code", 0) or 0)
                    pbody = getattr(pr, "text", "") or ""
                    if pcode == 200 and pbody.strip():
                        if len(pbody) < 3500 and _SOFT_404_RE.search(pbody):
                            continue
                        if _LEAK_ERR_RE.search(pbody):
                            high_signals.append(f"{sub}{sp} [200 leak/error]")
                        else:
                            med_signals.append(f"{sub}{sp} [200]")
                    elif pcode in (401, 403):
                        med_signals.append(f"{sub}{sp} [{pcode}]")
                except Exception:
                    continue

        if high_signals:
            result.findings.append(Finding(
                title=f"High-priority leak/error cues across subdomains ({len(high_signals)})",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="exposure",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(high_signals[:6])), final_url),
                description=" | ".join(high_signals[:6]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if med_signals:
            result.findings.append(Finding(
                title=f"Subdomain sensitive paths and cross-host redirects ({len(med_signals)})",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="access_control",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(med_signals[:7])), final_url),
                description=" | ".join(med_signals[:7]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if low_gaps:
            result.findings.append(Finding(
                title=f"Subdomain security header gaps ({len(low_gaps)})",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="configuration",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(low_gaps[:6])), final_url),
                description=" | ".join(low_gaps[:6]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if subdomains or external_origins or active_subs:
            parts: list[str] = []
            if subdomains:
                parts.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains[:8])}")
            if active_subs:
                parts.append(f"Active: {', '.join(active_subs[:6])}")
            if external_origins:
                parts.append(f"External ({len(external_origins)}): {', '.join(external_origins[:8])}")
            result.findings.append(Finding(
                title="10x multi-source domain, subdomain, and origin inventory",
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
            result.errors.append("no subdomain leaks, sensitive paths, cross-host redirects, header gaps, or additional origins observed")
        return result
