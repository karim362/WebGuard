from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.ultra_deep_surface_and_param_auditor import UltraDeepSurfaceAndParamAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://ultradeep.test/search?q=1"):
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


def test_ultra_deep_surface_and_param_auditor():
    def _route(method, u, kw):
        if "wg_ult_ref" in u:
            return _Resp(200, "<span>wg_ult_ref<\"'</span>", {}, u)
        if u.endswith("/api/v1"):
            return _Resp(200, '{"secret_key":"sk_test_9876543210"}', {}, u)
        if u.endswith("/graphql"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><a href="/items?cat=books">Books</a><form method="post" action="/send"><input name="msg"></form><img src="/pic.png"></html>',
            {"X-Powered-By": "PHP/8.2", "Server": "nginx"},
            "https://ultradeep.test/search?q=1",
        )

    t = Target(url="https://ultradeep.test/search?q=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_ult1", ScanMode.ADVANCED, EventBus())
    res = UltraDeepSurfaceAndParamAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Error or secret signals in ultra-deep audit" in titles
    assert "Reflections and response shifts on parameters/forms" in titles
    assert "Ultra-deep route and header inventory" in titles
