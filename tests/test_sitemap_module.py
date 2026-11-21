from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.discovery.sitemap import SitemapModule


class _R:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": "application/xml"}
        self.url = "https://example.com/sitemap.xml"


class _FakeHttp:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, **kw):
        return self.resp


def _ctx(http):
    t = Target(
        url="https://example.com/",
        authorization_confirmed=True,
    )
    return ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": http},
        scan_id="s",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )


def test_sitemap_parses_locs():
    xml = (
        "<urlset>"
        "<url><loc>https://example.com/a</loc></url>"
        "<url><loc>https://example.com/b</loc></url>"
        "</urlset>"
    )
    resp = _R(200, xml)
    http = _FakeHttp(resp)
    r = SitemapModule().run(_ctx(http))
    assert len(r.findings) == 1
    assert "2 URL" in r.findings[0].title


def test_sitemap_404_partial():
    resp = _R(404)
    http = _FakeHttp(resp)
    r = SitemapModule().run(_ctx(http))
    assert not r.findings
