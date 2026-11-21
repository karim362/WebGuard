from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.configuration.cookies import (
    CookiesReviewModule,
    _parse_set_cookie,
)


class _Headers:
    def __init__(self, mapping, lists):
        self._m = mapping
        self._l = lists

    def get(self, k, d=None):
        return self._m.get(k, d)

    def get_list(self, k):
        return self._l.get(k, [])

    def items(self):
        return self._m.items()


class _Resp:
    def __init__(self, cookies):
        self.status_code = 200
        self.url = "https://x.com/"
        self.headers = _Headers(
            {"content-type": "text/html"},
            {"set-cookie": cookies},
        )


class _FakeHttp:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, **kw):
        return self.resp


def _ctx(http):
    t = Target(
        url="https://x.com/",
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


def test_parse_set_cookie():
    a = _parse_set_cookie("sid=abc; Secure; HttpOnly; SameSite=Lax")
    assert a["name"] == "sid"
    assert "secure" in a
    assert "httponly" in a
    assert "samesite" in a


def test_insecure_cookie_flagged():
    resp = _Resp(["sid=abc; Path=/"])
    r = CookiesReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) >= 1
    assert "Insecure cookie" in r.findings[0].title


def test_secure_cookie_no_finding():
    resp = _Resp(["sid=abc; Secure; HttpOnly; SameSite=Lax"])
    r = CookiesReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 0
