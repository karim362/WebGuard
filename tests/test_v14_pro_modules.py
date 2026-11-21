from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.asset_and_tech_prober import AssetAndTechProberModule
from modules.vulnerability.misconfig_and_headers_pro import MisconfigAndHeadersProModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://pro.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_asset_and_tech_prober_detects_security_txt_and_powered_by():
    def _route(u, kw):
        if u.endswith("/.well-known/security.txt"):
            return _Resp(200, "Contact: mailto:sec@pro.test\n", {}, u)
        return _Resp(
            200,
            "<html>ok</html>",
            {"X-Powered-By": "PHP/8.3.0", "Link": '<https://pro.test/wp-json/>; rel="https://api.w.org/"'},
            u,
        )

    t = Target(url="https://pro.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_pro1", ScanMode.ACTIVE, EventBus())
    res = AssetAndTechProberModule().run(ctx)
    titles = [f.title for f in res.findings]
    combined = " ".join(f"{f.title} {f.description}" for f in res.findings)
    assert any("X-Powered-By" in x for x in titles)
    assert "/.well-known/security.txt (200)" in combined


def test_misconfig_and_headers_pro_detects_coop_cache_and_version():
    hdrs = {
        "Server": "nginx/1.24.0",
        "Set-Cookie": "sessionid=xyz; Path=/",
        "Cache-Control": "public, max-age=300",
    }
    t = Target(url="https://pro.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(lambda u, kw: _Resp(200, "", hdrs, u))}, "s_pro2", ScanMode.PASSIVE, EventBus())
    res = MisconfigAndHeadersProModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("COOP" in x for x in titles)
    assert any("Cache-Control" in x for x in titles)
    assert any("nginx/1.24.0" in x for x in titles)
