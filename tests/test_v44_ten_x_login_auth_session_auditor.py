from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.ten_x_login_auth_and_session_auditor import TenXLoginAuthAndSessionAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://auth10x.test/admin/login.php"):
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


def test_ten_x_login_auth_and_session_auditor():
    def _route(method, u, kw):
        if method == "POST":
            return _Resp(419, "CSRF token mismatch", {}, u)
        if u.endswith("/2fa"):
            return _Resp(403, "Forbidden", {}, u)
        if u.endswith("/reset-password"):
            return _Resp(200, "<form><input name='email'></form>", {}, u)
        return _Resp(
            200,
            '<html><!-- TODO: check admin login --><form method="post" action="/admin/login.php"><input name="email"><input type="password" name="password"></form><link rel="stylesheet" href="/app.css"></html>',
            {"Set-Cookie": "admin_session=xyz123; Path=/", "Cache-Control": "private"},
            "https://auth10x.test/admin/login.php",
        )

    t = Target(url="https://auth10x.test/admin/login.php", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_auth44", ScanMode.ADVANCED, EventBus())
    res = TenXLoginAuthAndSessionAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    med_desc = " ".join(f.description for f in res.findings if f.title.startswith("Authentication & session"))
    low_desc = " ".join(f.description for f in res.findings if f.title.startswith("Login form"))
    info_desc = " ".join(f.description for f in res.findings if "summary" in f.title.lower())
    assert "Authentication & session hardening gaps" in titles
    assert "Login form & framing hygiene notes" in titles
    assert "10x authentication surface, login forms, and response summary" in titles
    assert "admin_session" in med_desc
    assert "no-store" in med_desc
    assert "autocomplete" in low_desc
    assert "/2fa [403]" in info_desc
    assert "HTTP 419" in info_desc
