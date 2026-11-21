from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.http_security.robots_cookie_audit import RobotsCookieAuditModule
from modules.recon.cors_js_api_miner import CorsJsApiMinerModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://demo.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_cors_and_js_api_miner():
    def _route(u, kw):
        if u.endswith("/app.js"):
            return _Resp(200, 'const ep="/api/v1/users";', u)
        return _Resp(
            200,
            '<script src="/app.js"></script>',
            headers={
                "Access-Control-Allow-Origin": "https://probe.example",
                "Access-Control-Allow-Credentials": "true",
            },
            url=u,
        )

    t = Target(url="https://demo.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_cj", ScanMode.ACTIVE, EventBus())
    res = CorsJsApiMinerModule().run(ctx)
    assert any("Reflected CORS origin allowed with credentials" in f.title for f in res.findings)
    assert any("Mined 1 API/route pattern" in f.title for f in res.findings)


def test_robots_and_cookie_samesite_audit():
    def _route(u, kw):
        if u.endswith("/robots.txt"):
            return _Resp(200, "User-agent: *\nDisallow: /secret-area\n", u)
        if u.endswith("/secret-area"):
            return _Resp(200, "private", u)
        return _Resp(
            200,
            "home",
            headers={"Set-Cookie": "sid=abc123; SameSite=None"},
            url=u,
        )

    t = Target(url="https://demo.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_rc", ScanMode.ACTIVE, EventBus())
    res = RobotsCookieAuditModule().run(ctx)
    assert any("SameSite=None without Secure" in f.title for f in res.findings)
    assert any("Robots disallowed paths reachable" in f.title for f in res.findings)
