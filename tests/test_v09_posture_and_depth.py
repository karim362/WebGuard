from urllib.parse import urlparse
from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.authorization.access_control import AccessControlModule
from modules.http_security.http_security_posture import HttpSecurityPostureModule
from modules.input_security.xss_review import XssReviewModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://x.com/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_xss_review_detects_script_context():
    html_body = "<html><body><script>var q = 'probe_val';</script></body></html>"
    t = Target(url="https://x.com/?q=probe_val", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(lambda u, kw: _Resp(200, html_body))},
        scan_id="s_xss2",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )
    res = XssReviewModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].severity.value == "medium"


def test_access_control_skips_soft_404_page():
    soft_404 = "Page Not Found - " + ("x" * 200)

    def _fn(u, kw):
        if urlparse(u).path.rstrip("/") == "/admin":
            return _Resp(200, soft_404, url=u)
        return _Resp(404, "", url=u)

    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(_fn)},
        scan_id="s_ac2",
        mode=ScanMode.ACTIVE,
        events=EventBus(),
    )
    res = AccessControlModule().run(ctx)
    assert len(res.findings) == 0


def test_http_security_posture_detects_wildcard_cors_with_creds():
    hdrs = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(lambda u, kw: _Resp(200, "", headers=hdrs))},
        scan_id="s_cors",
        mode=ScanMode.ACTIVE,
        events=EventBus(),
    )
    res = HttpSecurityPostureModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].severity.value == "high"
