from pathlib import Path
from models.result import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)
from services.evidence_collector import EvidenceCollector


class _FakeResp:
    def __init__(self):
        self.status_code = 200
        self.url = "https://x.com/a?token=abc"
        self.headers = {
            "Content-Type": "text/html",
            "Set-Cookie": "sid=xyz",
        }
        self.text = "<html>hi</html>"


def _finding():
    return Finding(
        title="t", severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="c", target="x.com",
        affected_url="/", description="d",
        module="m",
        verification_status=VerificationStatus.POTENTIAL,
    )


def test_attach_response(tmp_path: Path):
    c = EvidenceCollector("scan_test", base_dir=tmp_path)
    f = _finding()
    c.attach(f, _FakeResp())
    assert len(f.evidence) == 1
    ev = f.evidence[0]
    assert "Set-Cookie: [REDACTED]" in ev.content
    assert "token=[REDACTED]" in ev.content


def test_attach_none(tmp_path: Path):
    c = EvidenceCollector("scan_test", base_dir=tmp_path)
    f = _finding()
    c.attach(f, None)
    assert len(f.evidence) == 0


def test_from_request(tmp_path: Path):
    c = EvidenceCollector("scan_test", base_dir=tmp_path)
    ev = c.from_request(
        _finding(), "GET", "https://x.com/a",
        {"Authorization": "Bearer abc"},
    )
    assert "Authorization: [REDACTED]" in ev.content


def test_summary(tmp_path: Path):
    c = EvidenceCollector("scan_test", base_dir=tmp_path)
    c.from_request(_finding(), "GET", "https://x.com",
                   {"Cookie": "a=1"})
    s = c.summary()
    assert s["files"] >= 1
