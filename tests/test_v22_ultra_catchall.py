from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.subtle_exposure_and_endpoint_hunter import SubtleExposureAndEndpointHunterModule
from modules.vulnerability.code_sink_and_leak_inspector import CodeSinkAndLeakInspectorModule
from modules.vulnerability.missing_security_controls_audit import MissingSecurityControlsAuditModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://ultra.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_ultra_catchall_modules():
    def _route(u, kw):
        if u.endswith("/app.js"):
            return _Resp(
                200,
                'el.innerHTML = x; window.addEventListener("message", fn); const db="127.0.0.1"; const hook="https://hooks.slack.com/services/T123/B456/secretval1234";',
                {},
                u,
            )
        if u.endswith("/.well-known/openid-configuration"):
            return _Resp(200, '{"issuer":"https://ultra.test"}', {"Content-Type": "application/json"}, u)
        return _Resp(
            200,
            '<script src="/app.js"></script><form method="post"><input name="email"></form><a href="/file?download=1&debug=true">f</a>',
            {"Set-Cookie": "auth_tok=v1; Path=/"},
            u,
        )

    t = Target(url="https://ultra.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_u22", ScanMode.ADVANCED, EventBus())

    r_code = CodeSinkAndLeakInspectorModule().run(ctx)
    r_ctrl = MissingSecurityControlsAuditModule().run(ctx)
    r_sub = SubtleExposureAndEndpointHunterModule().run(ctx)

    assert any("Subtle leak indicators" in f.title for f in r_code.findings)
    assert any("Static client-side sink patterns" in f.title for f in r_code.findings)
    assert any("Missing security control headers" in f.title for f in r_ctrl.findings)
    assert any("without visible CSRF token field" in f.title for f in r_ctrl.findings)
    assert any("Subtle endpoints/files observed" in f.title for f in r_sub.findings)
    assert any("Subtle high-interest parameters found" in f.title for f in r_sub.findings)
