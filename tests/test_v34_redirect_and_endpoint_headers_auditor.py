from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.redirect_and_endpoint_headers_auditor import RedirectAndEndpointHeadersAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://redir.test/start?next=https://partner.example.invalid/cb"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_redirect_and_endpoint_headers_auditor():
    def _route(u, kw):
        if "/start" in u:
            return _Resp(302, "", {"Location": "https://partner.example.invalid/cb"}, u)
        if "/dash" in u:
            return _Resp(200, "<html>Dashboard</html>", {"X-Content-Type-Options": "nosniff"}, u)
        return _Resp(
            200,
            '<html><a href="/start?next=https://partner.example.invalid/cb">Go</a><a href="/dash">Dash</a><link rel="stylesheet" href="/style.css"></html>',
            {},
            "https://redir.test/app",
        )

    t = Target(url="https://redir.test/app", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_redir1", ScanMode.ADVANCED, EventBus())
    res = RedirectAndEndpointHeadersAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Sensitive/external redirect chain behavior" in titles
    assert "Redirect chains observed on discovered endpoints" in titles
    assert "Security header gaps across discovered endpoints" in titles
