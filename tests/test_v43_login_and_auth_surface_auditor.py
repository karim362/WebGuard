from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.login_and_auth_surface_auditor import LoginAndAuthSurfaceAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://authlab.test/admin/login.php"):
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


def test_login_and_auth_surface_auditor():
    def _route(method, u, kw):
        if method == "POST":
            return _Resp(419, "Page Expired", {}, u)
        if u.endswith("/api/login"):
            return _Resp(405, "Method Not Allowed", {}, u)
        if u.endswith("/forgot-password"):
            return _Resp(200, "<form><input name='email'></form>", {}, u)
        return _Resp(
            200,
            '<html><body><form method="post" action="/admin/login.php"><input type="text" name="email"><input type="password" name="password"></form><link rel="stylesheet" href="/login.css"></body></html>',
            {},
            "https://authlab.test/admin/login.php",
        )

    t = Target(url="https://authlab.test/admin/login.php", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_auth43", ScanMode.ADVANCED, EventBus())
    res = LoginAndAuthSurfaceAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    med_desc = " ".join(f.description for f in res.findings if f.title.startswith("Authentication surface"))
    info_desc = " ".join(f.description for f in res.findings if "summary" in f.title.lower())
    assert "Authentication surface & login form weaknesses" in titles
    assert "Login forms, credential fields, and auth endpoint summary" in titles
    assert "lacks CSRF field" in med_desc
    assert "/api/login [405]" in info_desc
    assert "password" in info_desc
