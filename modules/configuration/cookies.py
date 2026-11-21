"""Cookie attribute review (Secure, HttpOnly, SameSite)."""
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


def _parse_set_cookie(value: str) -> dict[str, str]:
    attrs = {}
    parts = value.split(";")
    if not parts:
        return attrs
    name_value = parts[0].strip()
    if "=" in name_value:
        name = name_value.split("=", 1)[0]
        attrs["name"] = name
    for p in parts[1:]:
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.lower()] = v
        else:
            attrs[p.lower()] = ""
    return attrs


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class CookiesReviewModule(BaseModule):
    name = "cookies_review"
    version = "0.6.0"
    description = "Checks cookie Secure/HttpOnly/SameSite."
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
            if hasattr(r.headers, "get_list") \
            else r.headers.getall("set-cookie", []) \
            if hasattr(r.headers, "getall") else []
        if not raw:
            val = r.headers.get("set-cookie")
            raw = [val] if val else []

        for i, header in enumerate(raw, 1):
            attrs = _parse_set_cookie(header)
            name = attrs.get("name", f"cookie#{i}")
            issues = []
            if "secure" not in attrs:
                issues.append("Missing Secure")
            if "httponly" not in attrs:
                issues.append("Missing HttpOnly")
            if "samesite" not in attrs:
                issues.append("Missing SameSite")
            if not issues:
                continue
            result.findings.append(Finding(
                title=f"Insecure cookie: {name}",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="configuration",
                target=context.target.host,
                affected_url=_first_direct_url(str("; ".join(issues)), ""),
                description="; ".join(issues),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))
        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no cookies or all are secure")
        return result
