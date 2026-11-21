from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.deep_endpoint_and_config_auditor import DeepEndpointAndConfigAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://deep.test/page?id=1"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_deep_endpoint_and_config_auditor():
    def _route(u, kw):
        if u.endswith("/config.json"):
            return _Resp(200, '{"api_key":"demo_key_value_12345"}', {}, u)
        if u.endswith("/admin"):
            return _Resp(403, "forbidden", {}, u)
        if "wg_probe_1" in u:
            return _Resp(500, "SQL syntax error near 'wg_probe_1'", {}, u)
        return _Resp(
            200,
            '<html><body><a href="/admin">admin</a><script>const c="/config.json";</script></body></html>',
            {},
            "https://deep.test/page?id=1",
        )

    t = Target(url="https://deep.test/page?id=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_deca1", ScanMode.ADVANCED, EventBus())
    res = DeepEndpointAndConfigAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Endpoint content leak/error signals" in titles
    assert "Discovered endpoints probed" in titles
    assert "Parameter response anomalies observed" in titles
    assert "Missing transport/isolation controls" in titles
