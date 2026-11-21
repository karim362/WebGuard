"""Access control posture review with soft-404 and login-wall filtering."""
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

PROTECTED_PATHS = (
    "/admin",
    "/dashboard",
    "/account",
    "/settings",
    "/api/users",
)

_SOFT_404_MARKERS = (
    "page not found",
    "not found",
    "404",
    "صفحة غير موجودة",
    "غير موجود",
)

_LOGIN_MARKERS = (
    'type="password"',
    "type='password'",
    "sign in",
    "log in",
    "login",
)


def _looks_like_soft_404(body: str) -> bool:
    low = " ".join(body.lower().split())
    if len(low) < 8:
        return True
    return any(m in low for m in _SOFT_404_MARKERS) and len(low) < 2500


def _looks_like_login_page(body: str) -> bool:
    low = body.lower()
    return any(m in low for m in _LOGIN_MARKERS)


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class AccessControlModule(BaseModule):
    name = "access_control"
    version = "0.9.1"
    description = "Checks protected routes while filtering soft-404 responses."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        base = context.target.url.rstrip("/") + "/"
        http = context.services["http"]
        observed = 0

        for p in PROTECTED_PATHS:
            url = urljoin(base, p.lstrip("/"))
            try:
                r = http.get(url)
            except Exception as e:
                result.errors.append(f"{p}: {e}")
                continue

            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""

            if code == 200:
                if _looks_like_soft_404(body):
                    continue
                observed += 1
                if _looks_like_login_page(body):
                    result.findings.append(Finding(
                        title=f"Protected route shows login wall: {p}",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        category="authorization",
                        target=context.target.host,
                        affected_url=_first_direct_url(str("Route presents a login prompt rather than data."), ""),
                        description="Route presents a login prompt rather than data.",
                        module=self.name,
                        scan_id=context.scan_id,
                        verification_status=VerificationStatus.CONFIRMED,
                    ))
                else:
                    result.findings.append(Finding(
                        title=f"Protected route returned 200: {p}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category="authorization",
                        target=context.target.host,
                        affected_url=_first_direct_url(str((
                            "Returned 200 without clear login wall or soft-404; "
                            "verify authorization manually."
                        )), ""),
                        description=(
                            "Returned 200 without clear login wall or soft-404; "
                            "verify authorization manually."
                        ),
                        module=self.name,
                        scan_id=context.scan_id,
                        verification_status=VerificationStatus.NEEDS_REVIEW,
                    ))
            elif code in (401, 403):
                observed += 1
                result.findings.append(Finding(
                    title=f"Protected route enforces auth ({code}): {p}",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    category="authorization",
                    target=context.target.host,
                    affected_url=_first_direct_url(str(f"Returned HTTP {code} on probe."), ""),
                    description=f"Returned HTTP {code} on probe.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                ))

        if observed == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no protected routes observed")
        return result
