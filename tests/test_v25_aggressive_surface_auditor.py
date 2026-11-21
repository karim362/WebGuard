from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.aggressive_surface_and_vuln_auditor import AggressiveSurfaceAndVulnAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://agg.test/login?next=/home&q=1"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_aggressive_surface_and_vuln_auditor():
    def _route(u, kw):
        if "wg_redir_check" in u:
            return _Resp(302, "", {"Location": "https://example.invalid/wg_redir_check"}, u)
        if "wg_x_99" in u:
            return _Resp(200, '<div>val: wg_x_99<"test\'></div>', {}, u)
        if u.endswith("/.env"):
            return _Resp(200, "APP_ENV=staging\nDB_HOST=127.0.0.1", {}, u)
        if u.endswith("/api/v1"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<form method="post" action="http://agg.test/auth"><input type="text" name="user"><input type="password" name="pass"></form>',
            {},
            "https://agg.test/login?next=/home&q=1",
        )

    t = Target(url="https://agg.test/login?next=/home&q=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_agg1", ScanMode.ACTIVE, EventBus())
    res = AggressiveSurfaceAndVulnAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Redirect/forwarding parameter behavior observed" in titles
    assert "Unencoded special characters reflected on param(s):" in titles
    assert "q" in titles
    assert "Potentially exposed sensitive paths" in titles
    assert "Restricted sensitive/API paths detected" in titles
    assert "Authentication surface hardening gaps" in titles
