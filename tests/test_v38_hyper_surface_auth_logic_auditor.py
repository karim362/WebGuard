from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.hyper_surface_and_auth_logic_auditor import HyperSurfaceAndAuthLogicAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://hyp.test/view?id=5"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn("GET", url, kw)

    def post(self, url, **kw):
        return self.fn("POST", url, kw)


def test_hyper_surface_and_auth_logic_auditor():
    def _route(method, u, kw):
        if "wg_hyp_check" in u:
            return _Resp(200, "<div>wg_hyp_check</div>", {}, u)
        if u.endswith("/api/v2"):
            return _Resp(200, '{"access_token":"tok_demo_123"}', {}, u)
        if u.endswith("/dashboard"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><a href="/profile?uid=9">Profile</a><form method="post" action="/update"><input name="bio"></form><script src="/theme.css"></script></html>',
            {},
            "https://hyp.test/view?id=5",
        )

    t = Target(url="https://hyp.test/view?id=5", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_hyp1", ScanMode.ADVANCED, EventBus())
    res = HyperSurfaceAndAuthLogicAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Error or secret signals in hyper-surface audit" in titles
    assert "Reflections and response deltas in hyper-surface audit" in titles
    assert "Hyper-surface route and parameter sweep summary" in titles
