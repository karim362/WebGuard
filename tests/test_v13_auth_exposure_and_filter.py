from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.auth_and_exposure_audit import AuthAndExposureAuditModule


class _Resp:
    def __init__(self, text="", url="https://x.com/"):
        self.status_code = 200
        self.text = text
        self.url = url
        self.headers = {}


class _Http:
    def __init__(self, r):
        self.r = r

    def get(self, url, **kw):
        return self.r


def test_auth_and_exposure_audit_detects_comments_and_http_login():
    page = (
        "<!-- TODO: remove temporary admin debug key -->"
        "<form action='http://x.com/login' method='post'>"
        "<input type='password' name='pass'>"
        "</form>"
    )
    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_Resp(page))}, "s_ae", ScanMode.PASSIVE, EventBus())
    res = AuthAndExposureAuditModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("Password input" in x for x in titles)
    assert any("HTML comments" in x for x in titles)
