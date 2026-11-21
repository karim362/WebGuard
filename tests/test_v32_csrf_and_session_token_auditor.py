from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.csrf_and_session_token_auditor import CsrfAndSessionTokenAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://csrf.test/account"):
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


def test_csrf_and_session_token_auditor():
    def _route(method, u, kw):
        if method == "POST":
            return _Resp(419, "Page Expired", {}, u)
        return _Resp(
            200,
            '<html><form method="post" action="/update-profile"><input type="text" name="email"></form></html>',
            {"Set-Cookie": "PHPSESSID=abc123; path=/"},
            "https://csrf.test/account",
        )

    t = Target(url="https://csrf.test/account", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_csrf1", ScanMode.ADVANCED, EventBus())
    res = CsrfAndSessionTokenAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "POST form(s) without visible CSRF token" in titles
    assert "Session/token cookie attribute gaps" in titles
    assert "CSRF/token posture and missing-token probe observation" in titles
