"""Session cookie and auth header posture review."""
from __future__ import annotations
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
                    affected_url=str(r.url),
                    description="Missing flags: " + ", ".join(missing),
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.NEEDS_REVIEW,
                ))
        if flagged == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no weak session cookie observed")
        return result
