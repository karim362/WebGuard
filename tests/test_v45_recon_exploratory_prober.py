from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.recon.recon_exploratory_prober import ReconExploratoryProberModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://exp45.test/app"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_recon_exploratory_prober():
    def _route(u, kw):
        if u.endswith("/api/v1"):
            return _Resp(200, '{"api_key":"demo_key_123"}', {}, u)
        if u.endswith("/panel"):
            return _Resp(200, "<html>Admin Panel</html>", {}, u)
        if u.endswith("/backup"):
            return _Resp(403, "Forbidden", {}, u)
        if "wg_exp=1" in u:
            return _Resp(302, "", {"Location": "https://exp45.test/login"}, u)
        return _Resp(
            200,
            '<html><body>Home<link rel="stylesheet" href="/site.css"></body></html>',
            {"Allow": "GET, HEAD, POST"},
            "https://exp45.test/app",
        )

    t = Target(url="https://exp45.test/app", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_exp45", ScanMode.ADVANCED, EventBus())
    res = ReconExploratoryProberModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    med_desc = " ".join(f.description for f in res.findings if f.title.startswith("Exploratory discovered"))
    info_desc = " ".join(f.description for f in res.findings if "summary" in f.title.lower())
    assert "High-priority leak or error cues during exploratory recon" in titles
    assert "Exploratory discovered routes and parameter shifts" in titles
    assert "Exploratory recon route and header summary" in titles
    assert "/panel [200]" in med_desc
    assert "302" in med_desc
    assert "/backup [403]" in info_desc
    assert "Allow: GET, HEAD, POST" in info_desc
