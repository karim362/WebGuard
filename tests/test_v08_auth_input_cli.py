from pathlib import Path
from urllib.parse import urlparse
from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from interface.app import cleanup_old_artifacts
from models.module import ScanMode
from models.result import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)
from models.target import Target
from modules.authorization.access_control import AccessControlModule
from modules.input_security.xss_review import XssReviewModule
from reporting import score_finding, set_verification_status


class _R:
    def __init__(self, code=200, text="", url="https://x.com/"):
        self.status_code = code
        self.text = text
        self.url = url
        self.headers = {}


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url)


def test_access_control_detects_200_admin():
    def _route(u):
        if urlparse(u).path.rstrip("/") == "/admin":
            return _R(200, "Admin Panel", u)
        return _R(404, "", u)

    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(_route)},
        scan_id="s_ac",
        mode=ScanMode.ACTIVE,
        events=EventBus(),
    )
    res = AccessControlModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].verification_status == VerificationStatus.NEEDS_REVIEW


def test_xss_review_detects_reflection():
    t = Target(url="https://x.com/?q=probe123", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(lambda u: _R(200, "Search: probe123"))},
        scan_id="s_xss",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )
    res = XssReviewModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].verification_status == VerificationStatus.POTENTIAL


def test_status_update_and_cleanup(tmp_path: Path):
    f = Finding(
        title="Test",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="configuration",
        target="x.com",
        affected_url="https://x.com/",
        description="d",
        module="m",
        verification_status=VerificationStatus.POTENTIAL,
    )
    assert score_finding(f) == 45.0
    set_verification_status(f, VerificationStatus.CONFIRMED)
    assert score_finding(f) == 75.0

    r_dir = tmp_path / "results"
    p_dir = tmp_path / "reports"
    r_dir.mkdir()
    p_dir.mkdir()
    (r_dir / "a.json").write_text("{}", encoding="utf-8")
    (p_dir / "a.html").write_text("<html/>", encoding="utf-8")
    assert cleanup_old_artifacts(r_dir, p_dir) == 2
