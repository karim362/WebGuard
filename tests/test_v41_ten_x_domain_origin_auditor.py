from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.ten_x_domain_and_origin_auditor import TenXDomainAndOriginAuditorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://corp10x.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_ten_x_domain_and_origin_auditor():
    def _route(u, kw):
        if u.endswith("/main.js"):
            return _Resp(200, 'var host="gw.corp10x.test"; var ext="partner.example.invalid";', {}, u)
        if "gw.corp10x.test/.env" in u:
            return _Resp(200, "API_KEY=demo_secret_key_999", {}, u)
        if "gw.corp10x.test/admin" in u:
            return _Resp(403, "forbidden", {}, u)
        if "gw.corp10x.test/" and u.endswith("gw.corp10x.test/"):
            return _Resp(200, "<html>GW</html>", {"Location": "https://sso.corp10x.test/auth"}, u)
        return _Resp(
            200,
            '<html><script src="/main.js"></script><a href="https://gw.corp10x.test/app">GW</a><img src="https://cdn.img.invalid/pic.png"></html>',
            {"Content-Security-Policy": "default-src 'self' https://cdn.corp10x.test"},
            "https://corp10x.test/",
        )

    t = Target(url="https://corp10x.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_dom41", ScanMode.ADVANCED, EventBus())
    res = TenXDomainAndOriginAuditorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    inv_desc = " ".join(f.description for f in res.findings if "inventory" in f.title.lower())
    assert "High-priority leak/error cues across subdomains" in titles
    assert "Subdomain sensitive paths and cross-host redirects" in titles
    assert "Subdomain security header gaps" in titles
    assert "10x multi-source domain, subdomain, and origin inventory" in titles
    assert "gw.corp10x.test" in inv_desc
    assert "cdn.img.invalid" not in inv_desc
