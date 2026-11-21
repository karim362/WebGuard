"""Tests for SecurityHeadersModule using a fake http service."""
from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ModuleStatus, ScanMode
from models.target import Target
from modules.configuration.headers import SecurityHeadersModule

class _FakeResponse:
    def __init__(self, status, headers):
        self.status_code = status
        self.headers = headers
        from urllib.parse import urlparse
        self.url = "https://example.com/"

class _FakeHttp:
    def __init__(self, response): self.response = response
    def get(self, url, **kw): return self.response

def _ctx(http_service):
    t = Target(url="https://example.com", authorization_confirmed=True)
    return ModuleContext(
        target=t, scope_guard=ScopeGuard(t), services={"http": http_service},
        scan_id="scan_test", mode=ScanMode.PASSIVE, events=EventBus(),
    )

def test_missing_headers_flagged():
    resp = _FakeResponse(200, {"Server": "nginx/1.20"})
    m = SecurityHeadersModule()
    result = m.run(_ctx(_FakeHttp(resp)))
    assert result.status == ModuleStatus.SUCCESS
    titles = [f.title for f in result.findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("server header" in t.lower() or "Information disclosure" in t
               for t in titles)

def test_all_headers_present_quiet():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    m = SecurityHeadersModule()
    result = m.run(_ctx(_FakeHttp(_FakeResponse(200, headers))))
    # Only possible finding: none expected
    assert result.status == ModuleStatus.SUCCESS
    assert len(result.findings) == 0

def test_request_failure_marks_failed():
    class _Broken:
        def get(self, url, **kw): raise RuntimeError("boom")
    m = SecurityHeadersModule()
    result = m.run(_ctx(_Broken()))
    assert result.status == ModuleStatus.FAILED
    assert result.errors
