from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.baseline_and_waf_prober import BaselineAndWafProberModule
from modules.recon.js_link_deep_miner import JsLinkDeepMinerModule
from modules.recon.surface_correlator import SurfaceCorrelatorModule
from modules.vulnerability.api_session_depth_audit import ApiSessionDepthAuditModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://up.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_full_upgrade_modules():
    def _route(u, kw):
        if "webguard-nonexistent-path" in u:
            return _Resp(200, "<html><title>Not Found</title>" + ("z" * 200) + "</html>", {}, u)
        if u.endswith("/app.js"):
            return _Resp(200, 'fetch("/api/v1/items"); const obj = {"user_id": 1, "role": "guest"};', {}, u)
        if u.endswith("/api/v1/items"):
            return _Resp(200, '{"items":[]}', {"Content-Type": "application/json"}, u)
        return _Resp(
            200,
            '<form><input name="q"></form><a href="/view?id=7&content=1">v</a><script src="/app.js"></script>',
            {"Set-Cookie": "sid=abc123; Path=/", "CF-Ray": "999-IST"},
            u,
        )

    t = Target(url="https://up.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_v20", ScanMode.ADVANCED, EventBus())

    r1 = BaselineAndWafProberModule().run(ctx)
    r2 = JsLinkDeepMinerModule().run(ctx)
    r3 = ApiSessionDepthAuditModule().run(ctx)
    r4 = SurfaceCorrelatorModule().run(ctx)

    assert any("Cloudflare" in f.title for f in r1.findings)
    assert any("Soft-404" in f.title for f in r1.findings)
    assert any("Deep miner:" in f.title for f in r2.findings)
    assert any("Cookie 'sid'" in f.title for f in r3.findings)
    assert any("Attack-surface correlation:" in f.title for f in r4.findings)
