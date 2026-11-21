"""Passive JWT token presence and header validation review."""
from __future__ import annotations
import base64
import json
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

_JWT_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"([A-Za-z0-9_-]{6,})\.([A-Za-z0-9_-]{6,})\.([A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
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


def _decode_b64_json_obj(part: str) -> dict | None:
    if not part or len(part) % 4 == 1:
        return None
    padded = part + "=" * (-len(part) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_valid_jwts(text: str) -> list[tuple[str, dict, dict]]:
    found: list[tuple[str, dict, dict]] = []
    seen_tokens: set[str] = set()
    for h_b64, p_b64, sig_b64 in _JWT_CANDIDATE_RE.findall(text):
        token = f"{h_b64}.{p_b64}.{sig_b64}"
        if token in seen_tokens:
            continue
        header = _decode_b64_json_obj(h_b64)
        payload = _decode_b64_json_obj(p_b64)
        if not header or not payload:
            continue
        alg = header.get("alg")
        if not isinstance(alg, str) or not alg.strip():
            continue
        seen_tokens.add(token)
        found.append((token, header, payload))
    return found


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class JwtReviewModule(BaseModule):
    name = "jwt_review"
    version = "0.7.1"
    description = "Validates JWT header/payload JSON before reporting."
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

        parts_text = [getattr(r, "text", "") or ""]
        headers = getattr(r, "headers", None)
        if headers is not None and hasattr(headers, "items"):
            for k, v in headers.items():
                parts_text.append(f"{k}: {v}")
        haystack = "\n".join(parts_text)

        tokens = _extract_valid_jwts(haystack)
        if not tokens:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no valid JWT observed")
            return result

        for _, header, _ in tokens[:5]:
            alg_raw = str(header.get("alg", "")).strip()
            alg_low = alg_raw.lower()
            if alg_low == "none":
                result.findings.append(Finding(
                    title="JWT uses 'none' algorithm",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="authentication",
                    target=context.target.host,
                    affected_url=_first_direct_url(str("JWT header specifies alg='none'."), ""),
                    description="JWT header specifies alg='none'.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.NEEDS_REVIEW,
                ))
            else:
                result.findings.append(Finding(
                    title=f"JWT observed (alg={alg_raw})",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    category="authentication",
                    target=context.target.host,
                    affected_url=_first_direct_url(str("Valid JWT structure detected; verify exp/aud/iss."), ""),
                    description="Valid JWT structure detected; verify exp/aud/iss.",
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                ))
        return result
