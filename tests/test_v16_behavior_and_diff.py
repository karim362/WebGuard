from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.response_behavior_analyzer import ResponseBehaviorAnalyzerModule
from reporting.scan_diff import compare_scan_reports


class _Resp:
    def __init__(self, text="", headers=None, url="https://beh.test/"):
        self.status_code = 200
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, r):
        self.r = r

    def get(self, url, **kw):
        return self.r


def test_response_behavior_analyzer_detects_hidden_fields_and_missing_ctype():
    html = '<form><input type="hidden" name="role" value="user"><input type="hidden" name="user_id" value="10"></form>'
    t = Target(url="https://beh.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_Resp(html, {}, "https://beh.test/"))}, "s_b1", ScanMode.PASSIVE, EventBus())
    res = ResponseBehaviorAnalyzerModule().run(ctx)
    titles = [f.title for f in res.findings]
    assert any("Missing Content-Type" in x for x in titles)
    assert any("Sensitive hidden form fields" in x for x in titles)


def test_compare_scan_reports_highlights_new_and_resolved():
    prev = [{"module": "m1", "severity": "LOW", "title": "Old issue"}]
    curr = [
        {"module": "m1", "severity": "LOW", "title": "Old issue"},
        {"module": "m2", "severity": "HIGH", "title": "New critical check"},
    ]
    diff = compare_scan_reports(prev, curr)
    assert len(diff["new"]) == 1
    assert diff["new"][0]["title"] == "New critical check"
    assert len(diff["resolved"]) == 0
