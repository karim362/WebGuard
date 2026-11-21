from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.authentication.session_review import SessionReviewModule
from modules.api_security.api_discovery import ApiDiscoveryModule
from modules.input_security.input_review import InputReviewModule


class _H:
    def __init__(self, m, l=None):
        self._m = m
        self._l = l or {}

    def get(self, k, d=None):
        return self._m.get(k, d)

    def get_list(self, k):
        return self._l.get(k, [])


class _R:
    def __init__(self, code=200, text="", headers=None, lists=None):
        self.status_code = code
        self.text = text
        self.url = "https://x.com/"
        self.headers = _H(headers or {}, lists)


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url)


def _ctx(fn, mode=ScanMode.PASSIVE):
    t = Target(url="https://x.com/?id=1", authorization_confirmed=True)
    return ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http(fn)},
        scan_id="s1",
        mode=mode,
        events=EventBus(),
    )


def test_session_cookie_missing_flags():
    r = SessionReviewModule().run(_ctx(
        lambda u: _R(lists={"set-cookie": ["PHPSESSID=abc; Path=/"]})
    ))
    assert len(r.findings) == 1
    assert r.findings[0].severity.value == "medium"


def test_api_discovery_finds_graphql():
    r = ApiDiscoveryModule().run(_ctx(
        lambda u: _R(200 if u.endswith("/graphql") else 404),
        mode=ScanMode.ACTIVE,
    ))
    assert len(r.findings) == 1
    assert "/graphql" in r.findings[0].title


def test_input_review_maps_params_and_forms():
    html = '<form action="/login"><input name="username"></form>'
    r = InputReviewModule().run(_ctx(lambda u: _R(200, html)))
    assert len(r.findings) == 1
    assert "username" in r.findings[0].description
