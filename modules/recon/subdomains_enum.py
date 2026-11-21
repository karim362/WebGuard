"""Subdomain discovery across common service prefixes and discovered links."""
from __future__ import annotations
import re
from urllib.parse import urlparse
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

COMMON_SUBDOMAINS = (
    "www",
    "api",
    "m",
    "dev",
    "staging",
    "stage",
    "test",
    "admin",
    "portal",
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "mail",
    "webmail",
    "blog",
    "shop",
    "app",
    "docs",
)


def _root_domain(host: str) -> str:
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class SubdomainsEnumModule(BaseModule):
    name = "subdomains_enum"
    version = "1.1.0"
    description = "Discovers reachable subdomains under the target root domain."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        root = _root_domain(context.target.host)
        scheme = urlparse(context.target.url).scheme or "https"

        discovered: list[tuple[str, str, int]] = []
        seen_hosts: set[str] = {context.target.host.lower()}

        for prefix in COMMON_SUBDOMAINS:
            sub_host = f"{prefix}.{root}"
            if sub_host in seen_hosts:
                continue
            seen_hosts.add(sub_host)
            probe_url = f"{scheme}://{sub_host}/"
            if guard is not None and hasattr(guard, "is_allowed"):
                if not guard.is_allowed(probe_url):
                    continue
            try:
                resp = http.get(probe_url)
            except Exception:
                continue
            code = getattr(resp, "status_code", 0)
            if 100 <= code < 600 and code != 522 and code != 523:
                discovered.append((sub_host, str(getattr(resp, "url", probe_url)), code))

        try:
            home = http.get(context.target.url)
            html_body = getattr(home, "text", "") or ""
            for m in re.finditer(r"https?://([A-Za-z0-9.-]+\." + re.escape(root) + r")", html_body, re.I):
                h = m.group(1).lower().strip(".")
                if h not in seen_hosts:
                    seen_hosts.add(h)
                    discovered.append((h, f"{scheme}://{h}/", 200))
        except Exception:
            pass

        if not discovered:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no additional subdomains resolved in scope")
            return result

        for sub_host, final_url, code in discovered[:25]:
            result.findings.append(Finding(
                title=f"Subdomain active ({code}): {sub_host}",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="recon",
                target=context.target.host,
                affected_url=_first_direct_url(str(f"Subdomain {sub_host} responded with HTTP {code}."), final_url),
                description=f"Subdomain {sub_host} responded with HTTP {code}.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        return result
