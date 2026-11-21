from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.param_surface_analyzer import ParamSurfaceAnalyzerModule


class _Resp:
    def __init__(self, text="", code=200, url="https://p.test/"):
        self.text = text
        self.status_code = code
        self.url = url
        self.headers = {}


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_param_surface_analyzer_detects_priority_params_and_delta():
    def _route(u, kw):
        if "id=2" in u:
            return _Resp("B" * 900, 200, u)
        if "id=1" in u:
            return _Resp("A" * 120, 200, u)
        return _Resp('<a href="/watch?id=1&zones=us&p=1">w</a><form><input name="q"></form>', 200, u)

    t = Target(url="https://p.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_p19", ScanMode.ACTIVE, EventBus())
    res = ParamSurfaceAnalyzerModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("Priority parameters show response variation" in x for x in titles)
    assert any("Mapped 4 priority parameter(s)" in x for x in titles)
