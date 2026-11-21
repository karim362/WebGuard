"""Executes targeted exploratory discovery across hidden/admin/API routes, parameter shifts, allowed methods, and leak cues."""
from __future__ import annotations
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
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

_EXPLORATORY_PATHS = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/admin",
    "/panel",
    "/portal",
    "/dashboard",
    "/backup",
    "/old",
    "/test",
    "/dev",
    "/staging",
    "/console",
)

_LEAK_ERR_RE = re.compile(
    r"(?i)\b(?:api_key|secret_key|private_key|access_token|db_password|sql syntax|mysql_|pg_query|sqlite3|traceback \(most recent call last\)|unhandled exception|fatal error)\b"
)
_SOFT_404_RE = re.compile(r"(?i)\b(?:404 not found|page not found|not found on this server)\b")


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback

def _is_static(u: str) -> bool:
    return bool(_STATIC_EXT_RE.search(urlparse(u).path or ""))


def _clean_host(raw: str) -> str:
    h = (raw or "").strip().lower()
    if "://" in h:
        h = urlparse(h).hostname or ""
    return h.split(":", 1)[0].strip(".")


class ReconExploratoryProberModule(BaseModule):
    name = "recon_exploratory_prober"
    version = "1.0.1"
    description = "Executes exploratory discovery across admin/API/dev paths, parameter shifts, allowed methods, and leak cues."
    required_mode = ScanMode.ADVANCED
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = _clean_host(context.target.host)

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        html = getattr(root_resp, "text", "") or ""
        headers = getattr(root_resp, "headers", {}) or {}
        final_url = str(getattr(root_resp, "url", base_url))
        base_code = int(getattr(root_resp, "status_code", 200) or 200)
        base_len = len(html)
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}

        def _allowed(u: str) -> bool:
            if not u or _is_static(u):
                return False
            if guard is None or not hasattr(guard, "is_allowed"):
                return True
            return bool(guard.is_allowed(u))

        high_cues: list[str] = []
        med_cues: list[str] = []
        info_cues: list[str] = []

        open_paths: list[str] = []
        restricted_paths: list[str] = []
        for ep in _EXPLORATORY_PATHS:
            if _is_static(ep):
                continue
            ep_url = urljoin(final_url.rstrip("/") + "/", ep.lstrip("/"))
            if not _allowed(ep_url):
                continue
            try:
                er = http.get(ep_url)
                ecode = int(getattr(er, "status_code", 0) or 0)
                ebody = getattr(er, "text", "") or ""
                if ecode == 200 and ebody.strip():
                    if len(ebody) < 3500 and _SOFT_404_RE.search(ebody):
                        continue
                    open_paths.append(f"{ep} [200]")
                    if _LEAK_ERR_RE.search(ebody):
                        high_cues.append(f"leak/error cue at {ep}")
                elif ecode in (301, 302, 401, 403, 405):
                    restricted_paths.append(f"{ep} [{ecode}]")
            except Exception:
                continue

        parsed_u = urlparse(final_url)
        q_map = parse_qs(parsed_u.query, keep_blank_values=True)
        probe_urls: list[tuple[str, str]] = []
        if q_map:
            for qk in list(q_map.keys())[:3]:
                q_copy = dict(q_map)
                q_copy[qk] = ["wg_exp_1"]
                probe_urls.append((f"q:{qk}", urlunparse(parsed_u._replace(query=urlencode(q_copy, doseq=True)))))
        else:
            sep = "&" if parsed_u.query else "?"
            probe_urls.append(("q:wg_exp", f"{final_url}{sep}wg_exp=1"))

        for lbl, pu in probe_urls:
            if not _allowed(pu):
                continue
            try:
                pr = http.get(pu)
                pcode = int(getattr(pr, "status_code", 0) or 0)
                pbody = getattr(pr, "text", "") or ""
                if _LEAK_ERR_RE.search(pbody):
                    high_cues.append(f"error/leak on {lbl}")
                elif pcode > 0 and pcode != base_code:
                    med_cues.append(f"{lbl}: status {base_code}->{pcode}")
                elif base_len > 0 and abs(len(pbody) - base_len) > max(2000, int(base_len * 0.6)):
                    med_cues.append(f"{lbl}: response size shift")
            except Exception:
                continue

        allow_hdr = hmap.get("allow", "").strip()
        if allow_hdr:
            info_cues.append(f"Allow: {allow_hdr}")
        if _LEAK_ERR_RE.search(html):
            high_cues.append("leak/error pattern in root response body")

        if high_cues:
            result.findings.append(Finding(
                title=f"High-priority leak or error cues during exploratory recon ({len(high_cues)})",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="exposure",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(high_cues[:6])), final_url),
                description=" | ".join(high_cues[:6]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        med_all = med_cues + [f"open:{p}" for p in open_paths]
        if med_all:
            result.findings.append(Finding(
                title=f"Exploratory discovered routes and parameter shifts ({len(med_all)})",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(" | ".join(med_all[:8])), final_url),
                description=" | ".join(med_all[:8]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if restricted_paths or info_cues:
            parts: list[str] = []
            if restricted_paths:
                parts.append(f"Restricted/redirected: {', '.join(restricted_paths[:8])}")
            if info_cues:
                parts.append(" | ".join(info_cues[:4]))
            result.findings.append(Finding(
                title="Exploratory recon route and header summary",
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
            result.errors.append("no exploratory paths, parameter shifts, leak cues, or method headers observed")
        return result
