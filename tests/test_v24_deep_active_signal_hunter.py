from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.deep_active_signal_hunter import DeepActiveSignalHunterModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://sig.test/search?q=hi"):
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
        return _Resp(200, "", {"Allow": "GET, HEAD, OPTIONS"}, url)


def test_deep_active_signal_hunter_detects_reflection_and_cues():
    def _route(u, kw):
        if "wg_ref_9341" in u:
            return _Resp(200, '<a href="https://sig.test/?x=wg_ref_9341">link</a>', {}, u)
        return _Resp(
            200,
            '<form><input name="q"></form><script>const api_key = "ak_live_9876543210";</script>',
            {},
            "https://sig.test/search?q=hi",
        )

    t = Target(url="https://sig.test/search?q=hi", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_dash1", ScanMode.ACTIVE, EventBus())
    res = DeepActiveSignalHunterModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "High-context reflection observed on param(s): q" in titles
    assert "HTTP method/allowed-verb behavior observed" in titles
    assert "Sensitive token/config assignment cues" in titles
