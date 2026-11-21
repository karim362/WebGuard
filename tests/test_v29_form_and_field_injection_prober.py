from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.form_and_field_injection_prober import FormAndFieldInjectionProberModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://fld.test/search?q=test"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn("GET", url, kw)

    def post(self, url, **kw):
        return self.fn("POST", url, kw)


def test_form_and_field_injection_prober():
    def _route(method, u, kw):
        if method == "POST" and u.endswith("/submit"):
            return _Resp(500, "SQL syntax error near 'wg_fld_519'", {}, u)
        if "wg_fld_519" in u:
            return _Resp(200, '<div>Result: wg_fld_519<"\'</div>', {}, u)
        return _Resp(
            200,
            '<form method="post" action="/submit"><input type="text" name="username"><input type="hidden" name="csrf"></form>',
            {},
            "https://fld.test/search?q=test",
        )

    t = Target(url="https://fld.test/search?q=test", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_fld1", ScanMode.ACTIVE, EventBus())
    res = FormAndFieldInjectionProberModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Probed 2 input field(s)/parameter(s) and observed responses" in titles
    assert "Error/database signals triggered by field probes" in titles
    assert "Unencoded probe reflection on field(s): query:q" in titles
    assert "Response status/size shifts during field probing" in titles
