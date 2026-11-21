"""Deterministic triage and remediation helper (offline-safe)."""
from __future__ import annotations
from models.result import Finding, VerificationStatus
from reporting.risk_assessment import prioritize_findings, score_finding

REMEDIATION_HINTS = {
    "configuration": "Harden server headers, TLS, and cookie attributes.",
    "api_security": "Restrict CORS origins and enforce API auth controls.",
    "authentication": "Set HttpOnly, Secure, and SameSite on session cookies.",
    "input_security": "Validate and encode all untrusted input parameters.",
    "reconnaissance": "Minimize unnecessary public metadata exposure.",
}


def triage_findings(findings: list[Finding]) -> list[dict]:
    ordered = prioritize_findings(findings)
    out = []
    for f in ordered:
        needs_manual = f.verification_status != VerificationStatus.CONFIRMED
        hint = REMEDIATION_HINTS.get(
            f.category,
            "Review configuration and apply least-privilege controls.",
        )
        out.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "score": score_finding(f),
            "needs_manual_verification": needs_manual,
            "recommended_action": hint,
        })
    return out
