from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.triple_strength_vuln_and_surface_engine import TripleStrengthVulnAndSurfaceEngineModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://t3x.test/app?file=doc.txt&url=/home&q=1"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)

    def options(self, url, **kw):
        return _Resp(200, "", {"Allow": "GET, POST, OPTIONS, TRACE"}, url)


def test_triple_strength_vuln_and_surface_engine():
    def _route(u, kw):
        if "etc/passwd" in u or "etc%2Fpasswd" in u:
            return _Resp(200, "root:x:0:0:root:/root:/bin/bash", {}, u)
        if "wg_3x_probe" in u:
            return _Resp(302, "", {"Location": "https://example.invalid/wg_3x_probe"}, u)
        if "wg_3x_841" in u:
            return _Resp(200, '<script>var x = "wg_3x_841";</script>', {}, u)
        if u.endswith("/js/app.js"):
            return _Resp(200, 'const api_key = "ak_live_999888777"; const ep = "/api/v1/users";', {}, u)
        return _Resp(
            200,
            '<html><script src="/js/app.js"></script><a href="/api/v1/profile">p</a></html>',
            {"Set-Cookie": "sid=abc123"},
            "https://t3x.test/app?file=doc.txt&url=/home&q=1",
        )

    t = Target(url="https://t3x.test/app?file=doc.txt&url=/home&q=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_t3x1", ScanMode.ADVANCED, EventBus())
    res = TripleStrengthVulnAndSurfaceEngineModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Path/file parameter disclosure signal" in titles
    assert "URL/redirect/SSRF parameter signal" in titles
    assert "Script/attribute/quote reflection cue on param(s):" in titles
    assert "q" in titles
    assert "Token/key/credential cues in page or JS" in titles
    assert "API/app routes extracted from surface" in titles
    assert "Set-Cookie hardening gaps" in titles
    assert "Potentially risky HTTP methods advertised" in titles
