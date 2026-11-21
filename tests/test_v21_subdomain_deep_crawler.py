from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.subdomain_deep_crawler import SubdomainDeepCrawlerModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://sub.test/"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_subdomain_deep_crawler_discovers_crawls_and_probes_paths():
    def _route(u, kw):
        if "api.sub.test/v1/items" in u:
            return _Resp(403, "forbidden", {}, u)
        if "api.sub.test/" in u and u.endswith("/"):
            return _Resp(200, '<a href="/v1/items?id=9">items</a><script>const x="/api/v1/profile";</script>', {}, u)
        return _Resp(200, '<a href="https://api.sub.test/">api</a>', {}, u)

    t = Target(url="https://sub.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_sdc2", ScanMode.ADVANCED, EventBus())
    res = SubdomainDeepCrawlerModule().run(ctx)
    titles = [f.title for f in res.findings]
    combined = " ".join(f"{f.title} {f.description}" for f in res.findings)
    assert any("Subdomain deep crawl:" in x for x in titles)
    assert any("Subdomain path status/param observations" in x for x in titles)
    assert "api.sub.test/v1/items?id=9 [200->403]" in combined
    assert "/api/v1/profile" in combined
