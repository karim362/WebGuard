"""Discovers subdomains, crawls paths/params, tests path status behavior, and audits headers."""
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

SUB_PREFIXES = (
    "www", "api", "m", "dev", "staging", "stage", "test", "admin",
    "portal", "cdn", "static", "assets", "img", "media", "mail",
    "app", "shop", "blog", "docs", "auth",
)
_ABS_SUB_RE_TMPL = r"https?://([A-Za-z0-9.-]+\.{root})"
_LINK_RE = re.compile(r"""\b(?:href|src|action)\s*=\s*["']([^"'#]+(?:\?[^"']*)?)["']""", re.I)
_ROUTE_RE = re.compile(r"""["']((?:/api/|/v[1-9]/|/admin|/user|/auth|/search|/media|/assets)[A-Za-z0-9_./:-]{1,80})["']""")



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


def _root_domain(host: str) -> str:
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class SubdomainDeepCrawlerModule(BaseModule):
    name = "subdomain_deep_crawler"
    version = "1.1.0"
    description = "Discovers subdomains, crawls paths/params, probes path status changes, and audits headers."
    required_mode = ScanMode.ADVANCED
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = context.target.host.lower()
        root = _root_domain(host)
        scheme = urlparse(base_url).scheme or "https"

        def _allowed(u: str) -> bool:
            if guard is None or not hasattr(guard, "is_allowed"):
                return True
            return bool(guard.is_allowed(u))

        candidate_hosts: list[str] = []
        seen_hosts: set[str] = {host}

        try:
            root_resp = http.get(base_url)
            root_html = getattr(root_resp, "text", "") or ""
            root_hdrs = getattr(root_resp, "headers", {}) or {}
            hdr_blob = " ".join(f"{k}:{v}" for k, v in root_hdrs.items())
            for m in re.finditer(_ABS_SUB_RE_TMPL.format(root=re.escape(root)), f"{root_html} {hdr_blob}", re.I):
                sh = m.group(1).lower().strip(".")
                if sh not in seen_hosts and len(candidate_hosts) < 12:
                    seen_hosts.add(sh)
                    candidate_hosts.append(sh)
        except Exception:
            pass

        for pref in SUB_PREFIXES:
            sh = f"{pref}.{root}"
            if sh not in seen_hosts and len(candidate_hosts) < 20:
                seen_hosts.add(sh)
                candidate_hosts.append(sh)

        active_subs: list[str] = []
        crawled_paths: set[str] = set()
        found_params: set[str] = set()
        mined_routes: set[str] = set()
        weak_sub_notes: list[str] = []
        path_probe_urls: list[str] = []
        seen_probe_urls: set[str] = set()
        sub_home_codes: dict[str, int] = {}
        status_shifts: list[str] = []

        for sh in candidate_hosts:
            sub_home = f"{scheme}://{sh}/"
            if not _allowed(sub_home):
                continue
            try:
                sr = http.get(sub_home)
            except Exception:
                continue

            code = getattr(sr, "status_code", 0)
            if not (100 <= code < 600) or code in (522, 523):
                continue

            active_subs.append(f"{sh} [{code}]")
            sub_home_codes[sh] = code
            if len(active_subs) > 6:
                continue

            sbody = getattr(sr, "text", "") or ""
            shdrs = {str(k).lower(): str(v) for k, v in (getattr(sr, "headers", {}) or {}).items()}

            missing_sec = [h for h in ("content-security-policy", "strict-transport-security") if not shdrs.get(h)]
            if missing_sec:
                weak_sub_notes.append(f"{sh}: missing {','.join(missing_sec)}")

            sub_inner_links: list[str] = []
            for lm in _LINK_RE.finditer(sbody):
                full_l = urljoin(sub_home, lm.group(1).strip())
                pl = urlparse(full_l)
                if pl.netloc.lower() == sh and _allowed(full_l):
                    if pl.path and pl.path != "/":
                        crawled_paths.add(f"{sh}{pl.path}")
                    q_keys = list(parse_qs(pl.query).keys())
                    for qk in q_keys:
                        found_params.add(qk)
                    clean_l = full_l.split("#", 1)[0]
                    if clean_l not in sub_inner_links and len(sub_inner_links) < 4:
                        sub_inner_links.append(clean_l)
                    if (pl.path or q_keys) and full_l not in seen_probe_urls and len(path_probe_urls) < 12:
                        seen_probe_urls.add(full_l)
                        path_probe_urls.append(full_l)

            for rm in _ROUTE_RE.findall(sbody):
                mined_routes.add(rm)
                cand_route_u = urljoin(sub_home, rm.lstrip("/"))
                if _allowed(cand_route_u) and cand_route_u not in seen_probe_urls and len(path_probe_urls) < 12:
                    seen_probe_urls.add(cand_route_u)
                    path_probe_urls.append(cand_route_u)

            for inner_u in sub_inner_links[:3]:
                try:
                    ir = http.get(inner_u)
                    itxt = getattr(ir, "text", "") or ""
                    for rm in _ROUTE_RE.findall(itxt):
                        mined_routes.add(rm)
                    for lm in _LINK_RE.finditer(itxt):
                        full_l2 = urljoin(inner_u, lm.group(1).strip())
                        pl2 = urlparse(full_l2)
                        if pl2.path and pl2.path != "/":
                            crawled_paths.add(f"{pl2.netloc.lower() or sh}{pl2.path}")
                        q_keys2 = list(parse_qs(pl2.query).keys())
                        for qk in q_keys2:
                            found_params.add(qk)
                        if q_keys2 and full_l2 not in seen_probe_urls and len(path_probe_urls) < 12:
                            seen_probe_urls.add(full_l2)
                            path_probe_urls.append(full_l2)
                except Exception:
                    continue

        for pu in path_probe_urls[:10]:
            try:
                pr = http.get(pu)
                pcode = getattr(pr, "status_code", 0)
                parsed_p = urlparse(pu)
                sh_key = parsed_p.netloc.lower()
                base_c = sub_home_codes.get(sh_key)
                q_str = f"?{parsed_p.query}" if parsed_p.query else ""
                label = f"{sh_key}{parsed_p.path}{q_str}"
                if base_c is not None and pcode != base_c and pcode > 0:
                    status_shifts.append(f"{label} [{base_c}->{pcode}]")
                elif pcode in (200, 401, 403, 405) and q_str:
                    status_shifts.append(f"{label} [param:{pcode}]")
            except Exception:
                continue

        if active_subs:
            result.findings.append(Finding(
                title=f"Subdomain deep crawl: {len(active_subs)} active host(s), {len(crawled_paths)} path(s)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str((
                    f"Hosts: {', '.join(active_subs[:5])} | "
                    f"Paths: {', '.join(sorted(crawled_paths)[:5]) or 'none'} | "
                    f"Params: {', '.join(sorted(found_params)[:6]) or 'none'} | "
                    f"Routes: {', '.join(sorted(mined_routes)[:5]) or 'none'}"
                )), base_url),
                description=(
                    f"Hosts: {', '.join(active_subs[:5])} | "
                    f"Paths: {', '.join(sorted(crawled_paths)[:5]) or 'none'} | "
                    f"Params: {', '.join(sorted(found_params)[:6]) or 'none'} | "
                    f"Routes: {', '.join(sorted(mined_routes)[:5]) or 'none'}"
                ),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if status_shifts:
            has_restricted = any(x.endswith(("->401]", "->403]")) for x in status_shifts)
            result.findings.append(Finding(
                title=f"Subdomain path status/param observations ({len(status_shifts)})",
                severity=Severity.MEDIUM if has_restricted else Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=host,
                affected_url=_first_direct_url(str(f"Probed: {', '.join(status_shifts[:6])}"), base_url),
                description=f"Probed: {', '.join(status_shifts[:6])}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if weak_sub_notes:
            result.findings.append(Finding(
                title=f"Subdomain header gaps observed ({len(weak_sub_notes)})",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="configuration",
                target=host,
                affected_url=_first_direct_url(str(f"Details: {' ; '.join(weak_sub_notes[:4])}"), base_url),
                description=f"Details: {' ; '.join(weak_sub_notes[:4])}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no active subdomains or deep subdomain paths discovered")
        return result
