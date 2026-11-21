from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.diverse_high_impact_surface_auditor import DiverseHighImpactSurfaceAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://div10x.test/item?id=2"):
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


def test_diverse_high_impact_auditor():
    def _route(method, u, kw):
        hdrs = kw.get("headers") or {}
        if hdrs.get("X-Forwarded-Host") == "wg-host-check.example.invalid":
            return _Resp(200, "https://wg-host-check.example.invalid/reset", {}, u)
        if hdrs.get("X-HTTP-Method-Override") == "PUT":
            return _Resp(200, "updated", {}, u)
        if "wg_expr_9x9" in u or (kw.get("data") or {}).get("note") == 'wg_expr_9x9<"\'':
            return _Resp(500, "Twig_Error_Syntax: unexpected tag", {}, u)
        if u.endswith("/.git/config"):
            return _Resp(200, '[core]\nrepositoryformatversion = 0\nurl = https://secret_key@git.local', {}, u)
        if u.endswith("/web.config"):
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><form method="post" action="/save"><input name="note"></form><link rel="stylesheet" href="/base.css"></html>',
            {},
            "https://div10x.test/item?id=2",
        )

    t = Target(url="https://div10x.test/item?id=2", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_div1", ScanMode.ADVANCED, EventBus())
    res = DiverseHighImpactSurfaceAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "High-priority signals in diverse surface audit" in titles
    assert "Diverse probe shifts, host/override cues, and artifacts" in titles
