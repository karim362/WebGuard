from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.top_surface_hunter import TopSurfaceHunterModule


class _Resp:
    def __init__(self, text="", headers=None, url="https://target.test/"):
        self.status_code = 200
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, r):
        self.r = r

    def get(self, url, **kw):
        return self.r


def test_top_surface_hunter_finds_headers_params_and_routes():
    html = (
        '<a href="/go?next=https://target.test/dash">next</a>'
        '<script src="/static/app.js"></script>'
        '\'const endpoint = "/api/v2/account";\''
    )
    t = Target(url="https://target.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_Resp(html))}, "s_tsh", ScanMode.ACTIVE, EventBus())
    res = TopSurfaceHunterModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("X-Content-Type-Options" in x for x in titles)
    assert any("High-interest parameters" in x for x in titles)
    assert any("route pattern" in x.lower() for x in titles)
