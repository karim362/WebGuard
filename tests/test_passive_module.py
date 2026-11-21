from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.reconnaissance.passive import PassiveFilesModule

class _R:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text
        self.url = "https://example.com/robots.txt"

class _FakeHttp:
    def __init__(self, mapping): self.mapping = mapping
    def get(self, url, **kw):
        for k, v in self.mapping.items():
            if url.endswith(k):
                return v
        return _R(404)

def _ctx(http):
    t = Target(url="https://example.com", authorization_confirmed=True)
    return ModuleContext(
        target=t, scope_guard=ScopeGuard(t),
        services={"http": http}, scan_id="s", mode=ScanMode.PASSIVE,
        events=EventBus(),
    )

def test_detects_robots_and_sitemap():
    http = _FakeHttp({
        "/robots.txt": _R(200, "User-agent: *"),
        "/sitemap.xml": _R(200, "<urlset/>"),
    })
    r = PassiveFilesModule().run(_ctx(http))
    titles = [f.title for f in r.findings]
    assert any("Robots.txt" in t for t in titles)
    assert any("Sitemap" in t for t in titles)

def test_none_present_partial():
    http = _FakeHttp({})
    r = PassiveFilesModule().run(_ctx(http))
    assert not r.findings
