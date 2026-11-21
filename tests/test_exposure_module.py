from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.configuration.exposure import ExposureModule


class _Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": "text/plain"}
        self.url = "https://x.com/"


class _FakeHttp:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url, **kw):
        for k, v in self.mapping.items():
            if url.endswith(k):
                return v
        return _Resp(404)


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
        mode=ScanMode.ACTIVE,
        events=EventBus(),
    )


def test_git_exposed():
    mapping = {"/.git/HEAD": _Resp(200, "ref: refs/heads/main\n")}
    r = ExposureModule().run(_ctx(_FakeHttp(mapping)))
    assert len(r.findings) == 1
    assert "Git" in r.findings[0].title


def test_env_exposed():
    mapping = {"/.env": _Resp(200, "DB_PASS=x\nAPI_KEY=y")}
    r = ExposureModule().run(_ctx(_FakeHttp(mapping)))
    assert len(r.findings) == 1
    assert ".env" in r.findings[0].title


def test_none_found():
    r = ExposureModule().run(_ctx(_FakeHttp({})))
    assert len(r.findings) == 0
