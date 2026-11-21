from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.ten_x_vuln_and_surface_hunter import TenXVulnAndSurfaceHunterModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://x10.test/app?item=1"):
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


def test_ten_x_vuln_and_surface_hunter():
    def _route(method, u, kw):
        low_u = u.lower()
        if "wg_10x_ref" in low_u:
            return _Resp(200, '<span>wg_10x_ref<"\'</span>', {}, u)
        if "wg_10x_url" in low_u:
            return _Resp(302, "", {"Location": "https://example.invalid/wg_10x_url"}, u)
        if "=-1" in low_u or "%2d1" in low_u or (kw.get("data") or {}).get("term") == "-1":
            return _Resp(500, "Traceback (most recent call last): ValueError", {}, u)
        if u.endswith("/api/v1"):
            return _Resp(200, '{"api_key":"ak_test_1234567890"}', {}, u)
        if u.endswith("/admin/login"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><form action="/search" method="get"><input name="term"><img src="/logo.png"></form></html>',
            {"Set-Cookie": "session=xyz"},
            "https://x10.test/app?item=1",
        )

    t = Target(url="https://x10.test/app?item=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_x10_1", ScanMode.ADVANCED, EventBus())
    res = TenXVulnAndSurfaceHunterModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Error/stack patterns triggered during 10x probes" in titles
    assert "Raw special chars reflected on target(s):" in titles
    assert "q:item" in titles
    assert "Leak/error signatures on API/config routes" in titles
    assert "External URL probe behavior observed" in titles
    assert "Differential response shifts detected" in titles
    assert "Active API/auth/config routes probed" in titles
    assert "Session/transport/header control gaps" in titles
