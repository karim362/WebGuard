from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.recursive_js_and_link_deepener import RecursiveJsAndLinkDeepenerModule
from modules.vulnerability.deep_leaks_and_misconfig_hunter import DeepLeaksAndMisconfigHunterModule


class _Resp:
    def __init__(self, code=200, text="", url="https://deep.test/"):
        self.status_code = code
        self.text = text
        self.url = url
        self.headers = {}


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_recursive_js_and_link_deepener():
    def _route(u, kw):
        if u.endswith("/bundle.js"):
            return _Resp(200, 'fetch("/api/v1/sessions");', u)
        if u.endswith("/api/v1/sessions"):
            return _Resp(401, "unauthorized", u)
        return _Resp(200, '<script src="/bundle.js"></script><a href="/item?id=5">i</a>', u)

    t = Target(url="https://deep.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_r1", ScanMode.ADVANCED, EventBus())
    res = RecursiveJsAndLinkDeepenerModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("Deep surface:" in x for x in titles)
    assert any("Live probed routes" in x for x in titles)


def test_deep_leaks_and_misconfig_hunter():
    def _route(u, kw):
        if u.endswith("/main.js"):
            return _Resp(200, 'const bucket="https://my-assets.s3.amazonaws.com";', u)
        return _Resp(200, '<script src="/main.js"></script><a href="/reset?token=abc123456">r</a>', u)

    t = Target(url="https://deep.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_l1", ScanMode.ADVANCED, EventBus())
    res = DeepLeaksAndMisconfigHunterModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("Sensitive parameters in links" in x for x in titles)
    assert any("High-signal token/bucket indicators" in x for x in titles)
