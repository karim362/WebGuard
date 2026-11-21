"""Risk scoring, finding prioritization, and status updates."""
from __future__ import annotations
from models.result import Finding, Severity, VerificationStatus

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 10,
}

STATUS_MULTIPLIER = {
    VerificationStatus.CONFIRMED: 1.0,
    VerificationStatus.NEEDS_REVIEW: 0.8,
    VerificationStatus.POTENTIAL: 0.6,
    VerificationStatus.DUPLICATE: 0.0,
    VerificationStatus.FALSE_POSITIVE: 0.0,
}


def set_verification_status(
    finding: Finding, status: VerificationStatus
) -> Finding:
    finding.verification_status = status
    return finding


def score_finding(finding: Finding) -> float:
    base = SEVERITY_WEIGHT.get(finding.severity, 10)
    mult = STATUS_MULTIPLIER.get(finding.verification_status, 0.5)
    return round(base * mult, 2)


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    active = [
        f for f in findings
        if f.verification_status not in (
            VerificationStatus.DUPLICATE,
            VerificationStatus.FALSE_POSITIVE,
        )
    ]
    return sorted(active, key=score_finding, reverse=True)


def summarize_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        if f.verification_status in (
            VerificationStatus.DUPLICATE,
            VerificationStatus.FALSE_POSITIVE,
        ):
            continue
        counts[f.severity.value] += 1
    return counts
