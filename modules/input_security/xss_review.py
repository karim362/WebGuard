"""Context-aware non-destructive query parameter reflection review."""
from __future__ import annotations
import re
from urllib.parse import parse_qs, urlparse
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

_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.S | re.I)
_ATTR_REFLECT_RE = re.compile(r"""[A-Za-z0-9_:-]+\s*=\s*["'][^"']*""")


def _classify_context(body: str, val: str) -> tuple[str, Severity]:
    low_body = body.lower()
    for m in _SCRIPT_BLOCK_RE.finditer(body):
        if val in m.group(0):
            return "script", Severity.MEDIUM
    for m in _ATTR_REFLECT_RE.finditer(body):
        if val in m.group(0):
            return "attribute", Severity.LOW
    if val.lower() in low_body:
        return "html_body", Severity.LOW
    return "", Severity.INFO


class XssReviewModule(BaseModule):
    name = "xss_review"
    version = "0.9.0"
    description = "Checks parameter reflection context safely without payloads."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        parsed = urlparse(context.target.url)
        params = parse_qs(parsed.query)
        if not params:
            result.status = ModuleStatus.SKIPPED
            result.errors.append("no query parameters in target URL")
            return result

        try:
            r = context.services["http"].get(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"fetch failed: {e}")
            return result

        body = getattr(r, "text", "") or ""
        if not body:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("empty response body")
            return result

        reflected = 0
        for name, values in params.items():
            for val in values[:3]:
                cleaned = val.strip()
                if len(cleaned) < 2:
                    continue
                ctx_name, sev = _classify_context(body, cleaned)
                if not ctx_name:
                    continue
                reflected += 1
                result.findings.append(Finding(
                    title=f"Param '{name}' reflected in {ctx_name}",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    category="input_security",
                    target=context.target.host,
                    affected_url=str(
                        getattr(r, "url", context.target.url)
                    ),
                    description=(
                        f"Value of '{name}' appears in {ctx_name} context; "
                        "verify output encoding."
                    ),
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.POTENTIAL,
                ))

        if reflected == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no meaningful parameter reflection observed")
        return result
