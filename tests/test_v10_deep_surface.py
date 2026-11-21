from urllib.parse import urlparse
from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.deep_surface_and_leaks import DeepSurfaceAndLeaksModule


class _Resp:
    def __init__(self, code=200, text="", url="https://x.com/"):
        self.status_code = code
        self.text = text
        self.url = url
        self.headers = {}


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url)


def test_deep_surface_detects_git_head_and_emails():
    def _route(u):
        path = urlparse(u).path
        if path == "/.git/HEAD":
            return _Resp(200, "ref: refs/heads/main\n", u)
        if path == "/app.js":
            return _Resp(200, 'fetch("/api/v1/profile"); const team="ops@x.com";', u)
        return _Resp(
            200,
            '<html><script src="/app.js"></script><a href="/api/v1/items">api</a></html>',
            u,
        )

    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(_route)},
        scan_id="s_deep",
        mode=ScanMode.ADVANCED,
        events=EventBus(),
    )
    res = DeepSurfaceAndLeaksModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any(".git/HEAD" in title for title in titles)
    assert any("email" in title.lower() for title in titles)
    assert any("route" in title.lower() for title in titles)
