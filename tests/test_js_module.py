from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.discovery.javascript_analysis import JsAnalysisModule


class _R:
    def __init__(self, url, text="", status=200):
        self.url = url
        self.status_code = status
        self.text = text
        self.headers = {"content-type": "text/html"}


class _FakeHttp:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, **kw):
        return self.pages.get(url, _R(url, "", 404))


def _ctx(http):
    t = Target(
        url="https://example.com/",
        authorization_confirmed=True,
    )
    return ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": http},
        scan_id="s",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )


def test_js_extracts_endpoints():
    home = _R(
        "https://example.com/",
        '<script src="/app.js"></script>',
    )
    js = _R(
        "https://example.com/app.js",
        'fetch("/api/users");',
    )
    http = _FakeHttp({
        "https://example.com/": home,
        "https://example.com/app.js": js,
    })
    r = JsAnalysisModule().run(_ctx(http))
    assert len(r.findings) == 1
    ev = r.findings[0].evidence[0].content
    assert "/api/users" in ev
