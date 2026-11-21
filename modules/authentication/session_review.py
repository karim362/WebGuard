"""Session cookie and auth header posture review."""
from __future__ import annotations
import re
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

SESSION_NAMES = ("session", "sid", "phpsessid", "jsessionid", "auth", "jwt")



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


class SessionReviewModule(BaseModule):
    name = "session_review"
    version = "0.7.0"
    description = "Reviews session cookie flags from response."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        try:
            r = context.services["http"].get(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"fetch failed: {e}")
            return result

        raw = r.headers.get_list("set-cookie") \
            if hasattr(r.headers, "get_list") else []
        if not raw:
            sc = r.headers.get("set-cookie")
            raw = [sc] if sc else []

        flagged = 0
        for line in raw:
            low = line.lower()
            cname = line.split("=", 1)[0].strip().lower()
            if not any(k in cname for k in SESSION_NAMES):
                continue
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "secure" not in low:
                missing.append("Secure")
            if missing:
                flagged += 1
                result.findings.append(Finding(
                    title=f"Weak session cookie: {cname}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="authentication",
                    target=context.target.host,
                    affected_url=_first_direct_url(str("Missing flags: " + ", ".join(missing)), ""),
                    description="Missing flags: " + ", ".join(missing),
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.NEEDS_REVIEW,
                ))
        if flagged == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no weak session cookie observed")
        return result
