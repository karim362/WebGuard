from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.discovery.crawler import CrawlerModule


class _R:
    def __init__(self, url, status=200, text=""):
        self.url = url
        self.status_code = status
        self.headers = {"content-type": "text/html"}
        self.text = text


class _FakeHttp:
    def get(self, url, **kw):
        if url.endswith("/"):
            body = '<a href="/x">x</a><form action="/y"></form>'
            return _R(url, 200, body)
        return _R(url, 200, "<html>leaf</html>")


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


def test_crawler_module_produces_findings():
    r = CrawlerModule().run(_ctx(_FakeHttp()))
    assert len(r.findings) >= 1
    titles = [f.title for f in r.findings]
    assert any("Crawled" in t for t in titles)
    assert any("form" in t.lower() for t in titles)
