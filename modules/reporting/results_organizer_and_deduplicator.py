"""Organizes, deduplicates, and prioritizes security findings across sessions, surfaces, routes, and headers."""
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

_STATIC_EXT_RE = re.compile(
    r"\.(?:css|scss|sass|less|png|jpe?g|gif|webp|svg|ico|bmp|woff2?|ttf|eot|otf|map)(?:\?.*)?$",
    re.I,
)
_HIGH_CUE_RE = re.compile(
    r"(?i)\b(?:leak|secret|api_key|secret_key|access_token|db_password|sql syntax|traceback|fatal error|samesite=none without secure|accepted post without csrf|accepted tampered)\b"
)
_MED_CUE_RE = re.compile(
    r"(?i)\b(?:missing httponly|cache-control lacks|pragma lacks|reflected|size shift|length delta|419|403|401|\.env|\.git|redirect|external)\b"
)


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback

def _is_static(u: str) -> bool:
    return bool(_STATIC_EXT_RE.search(urlparse(u).path or ""))


def _norm_key(text: str) -> str:
    head = re.split(r"\s+[—-]{1,2}\s+", (text or "").strip(), maxsplit=1)[0]
    s = re.sub(r"\s+", " ", head.lower())
    s = re.sub(r"\(\d+\)", "", s).strip()
    return s


class ResultsOrganizerAndDeduplicatorModule(BaseModule):
    name = "results_organizer_and_deduplicator"
    version = "1.0.1"
    description = "Deduplicates overlapping findings and organizes results by severity and domain for cleaner triage."
    required_mode = ScanMode.ADVANCED
    required_capabilities = ["http"]
    requires_auth = False

    def _collect_prior_items(self, context: ModuleContext) -> list[str]:
        items: list[str] = []
        for attr in ("findings", "results", "prior_findings", "collected_findings"):
            val = getattr(context, attr, None)
            if isinstance(val, list):
                for entry in val:
                    if isinstance(entry, dict):
                        t = str(entry.get("title") or "").strip()
                        d = str(entry.get("description") or "").strip()
                        joined = f"{t} — {d}" if (t and d) else (t or d)
                        if joined:
                            items.append(joined)
                    else:
                        t = str(getattr(entry, "title", "") or "").strip()
                        d = str(getattr(entry, "description", "") or "").strip()
                        joined = f"{t} — {d}" if (t and d) else (t or d)
                        if joined:
                            items.append(joined)
        return items

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        base_url = context.target.url
        host = context.target.host

        try:
            resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        html = getattr(resp, "text", "") or ""
        headers = getattr(resp, "headers", {}) or {}
        final_url = str(getattr(resp, "url", base_url))
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}

        raw_candidates: list[str] = self._collect_prior_items(context)

        if not raw_candidates:
            set_cookie = hmap.get("set-cookie", "")
            if set_cookie and "httponly" not in set_cookie.lower():
                raw_candidates.append("Session/token cookie missing HttpOnly")
            cc = hmap.get("cache-control", "")
            if set_cookie and "no-store" not in cc.lower():
                raw_candidates.append(f"Cookie response Cache-Control lacks no-store ({cc or 'none'})")
            if not hmap.get("strict-transport-security", "").strip() and final_url.lower().startswith("https://"):
                raw_candidates.append("Missing Strict-Transport-Security (HSTS) header")
            if not hmap.get("x-content-type-options", "").strip():
                raw_candidates.append("Missing X-Content-Type-Options header")
            if "<form" in html.lower() and "_token" not in html.lower() and "csrf" not in html.lower():
                raw_candidates.append("Form detected without visible CSRF token field")

        seen_keys: set[str] = set()
        high_group: list[str] = []
        med_group: list[str] = []
        info_group: list[str] = []

        for item in raw_candidates:
            clean = re.sub(r"\s+", " ", str(item)).strip()
            if not clean or _is_static(clean):
                continue
            k = _norm_key(clean)
            if not k or k in seen_keys:
                continue
            seen_keys.add(k)

            if _HIGH_CUE_RE.search(clean):
                high_group.append(clean)
            elif _MED_CUE_RE.search(clean):
                med_group.append(clean)
            else:
                info_group.append(clean)

        if high_group:
            result.findings.append(Finding(
                title=f"Organized HIGH priority signals ({len(high_group)} unique)",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="organized_high",
                target=host,
                affected_url=_first_direct_url(str(" || ".join(high_group[:6])), final_url),
                description=" || ".join(high_group[:6]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if med_group:
            result.findings.append(Finding(
                title=f"Organized MEDIUM priority & hardening signals ({len(med_group)} unique)",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="organized_medium",
                target=host,
                affected_url=_first_direct_url(str(" || ".join(med_group[:7])), final_url),
                description=" || ".join(med_group[:7]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if info_group:
            result.findings.append(Finding(
                title=f"Organized INFO & surface notes ({len(info_group)} unique)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="organized_info",
                target=host,
                affected_url=_first_direct_url(str(" || ".join(info_group[:7])), final_url),
                description=" || ".join(info_group[:7]),
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no non-static signals available to organize")
        return result
