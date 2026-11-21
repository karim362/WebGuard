from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.multi_source_domain_and_origin_hunter import MultiSourceDomainAndOriginHunterModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://targetcorp.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_multi_source_domain_and_origin_hunter():
    def _route(u, kw):
        if u.endswith("/app.js"):
            return _Resp(200, 'const apiHost = "api.targetcorp.test"; const cdn = "cdn.partner.invalid";', {}, u)
        if u.endswith("/robots.txt"):
            return _Resp(200, "Sitemap: https://staging.targetcorp.test/sitemap.xml\n", {}, u)
        if u.endswith("/sitemap.xml"):
            return _Resp(200, "<urlset><url><loc>https://portal.targetcorp.test/home</loc></url></urlset>", {}, u)
        if "api.targetcorp.test" in u:
            return _Resp(200, '{"ok":true}', {}, u)
        if "staging.targetcorp.test" in u:
            return _Resp(403, "forbidden", {}, u)
        return _Resp(
            200,
            '<html><script src="/app.js"></script><a href="https://docs.targetcorp.test">Docs</a><link rel="stylesheet" href="https://static.other.invalid/a.css"></html>',
            {"Content-Security-Policy": "default-src 'self' https://auth.targetcorp.test"},
            "https://targetcorp.test/",
        )

    t = Target(url="https://targetcorp.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_dom40", ScanMode.ADVANCED, EventBus())
    res = MultiSourceDomainAndOriginHunterModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    inv_desc = " ".join(f.description for f in res.findings if "inventory" in f.title.lower())
    assert "Discovered subdomain transport header gaps" in titles
    assert "Multi-source domain, subdomain, and origin inventory" in titles
    assert "api.targetcorp.test" in inv_desc
    assert "staging.targetcorp.test" in inv_desc
    assert "portal.targetcorp.test" in inv_desc
    assert "auth.targetcorp.test" in inv_desc
    assert "static.other.invalid" not in inv_desc
