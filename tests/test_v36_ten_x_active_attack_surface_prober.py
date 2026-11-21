from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.ten_x_active_attack_surface_prober import TenXActiveAttackSurfaceProberModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://atk10x.test/page?q=1&next=/home"):
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


def test_ten_x_active_attack_surface_prober():
    def _route(method, u, kw):
        if "wg10x_ref_check" in u:
            return _Resp(200, "<div>wg10x_ref_check</div>", {}, u)
        if "=-1" in u or "%2d1" in u:
            return _Resp(500, "SQL syntax error near '-1'", {}, u)
        if "wg10x_url_check" in u:
            return _Resp(302, "", {"Location": "https://example.invalid/wg10x_url_check"}, u)
        if u.endswith("/.env"):
            return _Resp(200, "DB_PASSWORD=secret_val\nSECRET_KEY=abc", {}, u)
        if u.endswith("/admin"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><form method="post" action="/search"><input type="text" name="term"></form><link rel="stylesheet" href="/app.css"></html>',
            {},
            "https://atk10x.test/page?q=1&next=/home",
        )

    t = Target(url="https://atk10x.test/page?q=1&next=/home", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_atk10x", ScanMode.ADVANCED, EventBus())
    res = TenXActiveAttackSurfaceProberModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Error or leak signals observed during active verification" in titles
    assert "Active surface reflections, deltas, and route signals" in titles
    assert "Active verification surface summary" in titles
