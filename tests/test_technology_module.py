from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.reconnaissance.technology import TechnologyModule

class _FakeResponse:
    def __init__(self, headers, text):
        self.status_code = 200
        self.headers = headers
        self.text = text
        self.url = "https://example.com/"

class _FakeHttp:
    def __init__(self, resp): self.resp = resp
    def get(self, url, **kw): return self.resp

def _ctx(http):
    t = Target(url="https://example.com", authorization_confirmed=True)
    return ModuleContext(
        target=t, scope_guard=ScopeGuard(t),
        services={"http": http}, scan_id="s", mode=ScanMode.PASSIVE,
        events=EventBus(),
    )

def test_detects_nginx_and_wordpress():
    resp = _FakeResponse({"Server": "nginx/1.20"}, "<html>wp-content</html>")
    r = TechnologyModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 1
    ev = r.findings[0].evidence[0].content
    assert "server:nginx" in ev
    assert "framework:wordpress" in ev

def test_no_tech_partial():
    resp = _FakeResponse({}, "<html>hello</html>")
    r = TechnologyModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 0
    assert r.errors
