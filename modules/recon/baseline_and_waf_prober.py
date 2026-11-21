"""Establishes root and non-existent path baselines to detect soft-404s and WAF/rate-limit cues."""
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

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_WAF_SIGNATURES = (
    ("Cloudflare", ("cf-ray", "__cf_bm", "attention required! | cloudflare")),
    ("Akamai", ("akamai", "x-akamai-transformed")),
    ("Imperva / Incapsula", ("incap_ses", "visid_incap", "x-iinfo")),
    ("AWS WAF", ("x-amzn-waf-action", "awswaf")),
)


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class BaselineAndWafProberModule(BaseModule):
    name = "baseline_and_waf_prober"
    version = "1.0.0"
    description = "Compares root vs missing-path baseline to spot soft-404 behavior and WAF/rate-limit markers."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url
        host = context.target.host

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        root_body = getattr(root_resp, "text", "") or ""
        root_headers = getattr(root_resp, "headers", {}) or {}
        hmap = {str(k).lower(): str(v) for k, v in root_headers.items()}
        combined_hint = f"{root_body[:4000].lower()} {' '.join(f'{k}:{v}' for k, v in hmap.items()).lower()}"

        detected_wafs: list[str] = []
        for waf_name, markers in _WAF_SIGNATURES:
            if any(m in combined_hint for m in markers):
                detected_wafs.append(waf_name)

        if detected_wafs:
            result.findings.append(Finding(
                title=f"Edge / WAF indicators observed: {', '.join(detected_wafs)}",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="fingerprint",
                target=host,
                affected_url=_first_direct_url(str("Protective edge/WAF headers or challenge markers detected; interpret blocked probes carefully."), base_url),
                description="Protective edge/WAF headers or challenge markers detected; interpret blocked probes carefully.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        missing_url = urljoin(base_url.rstrip("/") + "/", "webguard-nonexistent-path-98765")
        if guard is None or not hasattr(guard, "is_allowed") or guard.is_allowed(missing_url):
            try:
                miss_resp = http.get(missing_url)
                m_code = getattr(miss_resp, "status_code", 0)
                m_body = getattr(miss_resp, "text", "") or ""
                if m_code == 200 and len(m_body) > 100:
                    tm = _TITLE_RE.search(m_body)
                    m_title = " ".join(tm.group(1).split())[:60] if tm else "untitled"
                    result.findings.append(Finding(
                        title="Soft-404 behavior detected (HTTP 200 on missing path)",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category="recon",
                        target=host,
                        affected_url=_first_direct_url(str(f"Missing path returned 200 ({len(m_body)}B, title='{m_title}'); verify body content before trusting 200s."), base_url),
                        description=f"Missing path returned 200 ({len(m_body)}B, title='{m_title}'); verify body content before trusting 200s.",
                        module=self.name,
                        scan_id=context.scan_id,
                        verification_status=VerificationStatus.CONFIRMED,
                    ))
            except Exception:
                pass

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no WAF signature or soft-404 anomaly observed")
        return result
