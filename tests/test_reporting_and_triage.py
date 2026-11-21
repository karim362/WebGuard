from pathlib import Path
from ai.analyzer import triage_findings
from core.engine import ScanReport
from models.module import ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)
from reporting.report_builder import build_html_report, build_json_report
from reporting.risk_assessment import prioritize_findings, summarize_counts


def _make_finding(title, sev, status=VerificationStatus.CONFIRMED):
    return Finding(
        title=title,
        severity=sev,
        confidence=Confidence.HIGH,
        category="configuration",
        target="example.com",
        affected_url="https://example.com/?token=secret123",
        description="Header missing with cookie=abc",
        module="security_headers",
        verification_status=status,
    )


def test_prioritize_filters_false_positives():
    f1 = _make_finding("Low issue", Severity.LOW)
    f2 = _make_finding("High issue", Severity.HIGH)
    f3 = _make_finding(
        "FP issue", Severity.CRITICAL, VerificationStatus.FALSE_POSITIVE
    )
    ordered = prioritize_findings([f1, f2, f3])
    assert [x.title for x in ordered] == ["High issue", "Low issue"]


def test_summarize_counts():
    items = [
        _make_finding("A", Severity.HIGH),
        _make_finding("B", Severity.HIGH),
        _make_finding("C", Severity.INFO),
    ]
    counts = summarize_counts(items)
    assert counts["high"] == 2
    assert counts["info"] == 1


def test_build_json_and_html_redacts_secrets(tmp_path: Path):
    f = _make_finding("Exposed header", Severity.MEDIUM)
    report = ScanReport(
        scan_id="scan_test_99",
        target_url="https://example.com/?token=secret123",
        mode=ScanMode.PASSIVE,
        results=[ModuleResult(module_name="m", status=ModuleStatus.SUCCESS, findings=[f])],
        total_duration=0.12,
    )
    jpath = build_json_report(report, out_dir=tmp_path)
    hpath = build_html_report(report, out_dir=tmp_path)

    jtxt = jpath.read_text(encoding="utf-8")
    htxt = hpath.read_text(encoding="utf-8")
    assert "secret123" not in jtxt
    assert "secret123" not in htxt
    assert "[REDACTED]" in jtxt
    assert "Exposed header" in htxt


def test_triage_findings():
    f = _make_finding("Potential CORS", Severity.HIGH, VerificationStatus.POTENTIAL)
    triaged = triage_findings([f])
    assert len(triaged) == 1
    assert triaged[0]["needs_manual_verification"] is True
    assert "Harden" in triaged[0]["recommended_action"]


def test_export_html_to_hack_wed(tmp_path: Path):
    from reporting import export_html_to_hack_wed

    f = _make_finding("Missing HSTS", Severity.MEDIUM)
    report = ScanReport(
        scan_id="scan_hw_01",
        target_url="https://example.com",
        mode=ScanMode.PASSIVE,
        results=[
            ModuleResult(
                module_name="security_headers",
                status=ModuleStatus.SUCCESS,
                findings=[f],
            )
        ],
        total_duration=0.05,
    )
    html_file = build_html_report(report, out_dir=tmp_path / "reports")
    dest_dir = tmp_path / "internal" / "hack wed"
    copied = export_html_to_hack_wed(html_file, hack_wed_dir=dest_dir)
    assert copied.exists()
    assert copied.parent.name == "hack wed"
    assert "Missing HSTS" in copied.read_text(encoding="utf-8")
