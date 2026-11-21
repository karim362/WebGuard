from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.api_security.cors import CorsReviewModule


class _Resp:
    def __init__(self, headers):
        self.status_code = 200
        self.url = "https://x.com/"
        self.headers = headers
        self.text = ""


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


def test_wildcard_with_creds_high():
    resp = _Resp({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    r = CorsReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 1
    assert r.findings[0].severity.value == "high"


def test_wildcard_only_medium():
    resp = _Resp({"access-control-allow-origin": "*"})
    r = CorsReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 1
    assert r.findings[0].severity.value == "medium"


def test_reflects_evil_origin():
    resp = _Resp({"access-control-allow-origin": "https://evil.example"})
    r = CorsReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 1


def test_no_cors_partial():
    resp = _Resp({})
    r = CorsReviewModule().run(_ctx(_FakeHttp(resp)))
    assert len(r.findings) == 0
