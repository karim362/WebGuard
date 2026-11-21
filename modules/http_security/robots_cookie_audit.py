"""Audits robots.txt disallowed paths in scope and cookie SameSite attributes."""
from __future__ import annotations
import re
from urllib.parse import urljoin
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

_DISALLOW_RE = re.compile(r"(?im)^\s*disallow\s*:\s*(\S+)\s*$")


class RobotsCookieAuditModule(BaseModule):
    name = "robots_cookie_audit"
    version = "1.0.0"
    description = "Checks disallowed paths from robots.txt and cookie SameSite flags."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        headers = getattr(root_resp, "headers", {}) or {}
        cookie_lines = [
            str(v) for k, v in headers.items()
            if str(k).lower() == "set-cookie"
        ]
        for c_hdr in cookie_lines:
            parts = [p.strip() for p in c_hdr.split(";")]
            cname = parts[0].split("=", 1)[0].strip() if parts else "cookie"
            low_parts = [p.lower() for p in parts[1:]]
            has_samesite = any(p.startswith("samesite=") for p in low_parts)
            is_none = any(p == "samesite=none" for p in low_parts)
            has_secure = any(p == "secure" for p in low_parts)

            if is_none and not has_secure:
                result.findings.append(Finding(
                    title=f"Cookie '{cname}' uses SameSite=None without Secure",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="session",
                    target=context.target.host,
                    affected_url=base_url,
                    description="SameSite=None requires Secure flag to be accepted by modern browsers.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                ))
            elif not has_samesite:
                result.findings.append(Finding(
                    title=f"Cookie '{cname}' missing SameSite attribute",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="session",
                    target=context.target.host,
                    affected_url=base_url,
                    description="Consider setting SameSite=Lax or Strict on cookies.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                ))

        robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
        if guard is None or not hasattr(guard, "is_allowed") or guard.is_allowed(robots_url):
            try:
                r_resp = http.get(robots_url)
                if getattr(r_resp, "status_code", 0) == 200:
                    r_txt = getattr(r_resp, "text", "") or ""
                    paths = []
                    for m in _DISALLOW_RE.finditer(r_txt):
                        p = m.group(1).strip()
                        if p and p != "/" and "*" not in p and p not in paths:
                            paths.append(p)
                            if len(paths) >= 10:
                                break
                    reachable = []
                    for p in paths:
                        target_p = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
                        if guard is not None and hasattr(guard, "is_allowed") and not guard.is_allowed(target_p):
                            continue
                        try:
                            pr = http.get(target_p)
                            code = getattr(pr, "status_code", 0)
                            if code in (200, 401, 403):
                                reachable.append(f"{p} ({code})")
                        except Exception:
                            continue
                    if reachable:
                        result.findings.append(Finding(
                            title=f"Robots disallowed paths reachable ({len(reachable)})",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            category="recon",
                            target=context.target.host,
                            affected_url=robots_url,
                            description=f"Observed paths: {', '.join(reachable[:6])}",
                            module=self.name,
                            scan_id=context.scan_id,
                            verification_status=VerificationStatus.CONFIRMED,
                        ))
            except Exception:
                pass

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no SameSite issues or reachable robots paths observed")
        return result
