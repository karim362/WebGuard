from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.content_signal_verifier import ContentSignalVerifierModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://sig.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_content_signal_verifier_filters_generic_html_and_keeps_json():
    root_html = "<html><body>" + ("x" * 1200) + "</body></html>"

    def _route(u, kw):
        if u.endswith("/openapi.json"):
            return _Resp(200, '{"openapi":"3.0.0","paths":{}}', {"Content-Type": "application/json"}, u)
        if u.endswith("/api"):
            return _Resp(200, root_html, {"Content-Type": "text/html"}, u)
        return _Resp(200, root_html, {"Content-Type": "text/html"}, u)

    t = Target(url="https://sig.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_sig1", ScanMode.ACTIVE, EventBus())
    res = ContentSignalVerifierModule().run(ctx)
    assert len(res.findings) == 1
    assert "/openapi.json [structured payload]" in res.findings[0].description
    assert "/api" not in res.findings[0].description
