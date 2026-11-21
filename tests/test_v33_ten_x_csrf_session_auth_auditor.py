from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.ten_x_csrf_session_and_auth_auditor import TenXCsrfSessionAndAuthAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://auth10x.test/account?session=abc123"):
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


def test_ten_x_csrf_session_and_auth_auditor():
    def _route(method, u, kw):
        if method == "POST":
            hdrs = kw.get("headers") or {}
            if hdrs.get("Origin") == "https://evil.example.invalid":
                return _Resp(200, "cross-origin ok", {}, u)
            data = kw.get("data") or {}
            if "csrf_token" not in data:
                return _Resp(200, "ok", {}, u)
            if data.get("csrf_token") == "wg_tampered_token_99":
                return _Resp(200, "ok", {}, u)
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><head><meta name="csrf-token" content=""></head><body><form method="post" action="/transfer"><input type="hidden" name="csrf_token" value="short"><input type="text" name="amount"></form></body></html>',
            {
                "Set-Cookie": "session_id=tok123; SameSite=None; Domain=.auth10x.test",
                "Cache-Control": "no-cache",
                "Access-Control-Allow-Origin": "https://evil.example.invalid",
                "Access-Control-Allow-Credentials": "true",
            },
            "https://auth10x.test/account?session=abc123",
        )

    t = Target(url="https://auth10x.test/account?session=abc123", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_csrf10x", ScanMode.ADVANCED, EventBus())
    res = TenXCsrfSessionAndAuthAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    high_desc = " ".join(f.description for f in res.findings if f.title.startswith("High-risk"))
    info_desc = " ".join(f.description for f in res.findings if "summary" in f.title.lower())
    assert "Session/token parameter(s) in URLs: session" in titles
    assert "High-risk CSRF/cookie/session weaknesses" in titles
    assert "cross-origin POST returned 200" in high_desc
    assert "cross-origin POST returned 200" in info_desc
