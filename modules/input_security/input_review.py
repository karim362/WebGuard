"""Identifies query parameters and HTML forms passively."""
from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs
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

_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_INPUT_RE = re.compile(
    r"<(?:input|textarea|select)\b[^>]*name=[\"']?([^\"'\s>]+)",
    re.IGNORECASE,
)


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class InputReviewModule(BaseModule):
    name = "input_review"
    version = "0.7.0"
    description = "Maps query params and form inputs passively."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        parsed = urlparse(context.target.url)
        q_params = list(parse_qs(parsed.query).keys())
        try:
            r = context.services["http"].get(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"fetch failed: {e}")
            return result

        html = getattr(r, "text", "") or ""
        forms = len(_FORM_RE.findall(html))
        fields = sorted(set(_INPUT_RE.findall(html)))

        if not q_params and forms == 0 and not fields:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no query params or forms found")
            return result

        desc = (
            f"Query params: {q_params or 'none'} | "
            f"Forms: {forms} | Inputs: {fields[:15]}"
        )
        result.findings.append(Finding(
            title="Input surface mapped",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="input_security",
            target=context.target.host,
            affected_url=_first_direct_url(str(desc), ""),
            description=desc,
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
        ))
        return result
