from pathlib import Path
import config
from core.engine import Engine
from core.event_bus import EventBus
from core.module_manager import ModuleManager
from interface.web_ui import execute_web_scan, render_hackrwed_html
from main import main


def test_render_hackrwed_html_contains_brand(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "HACK_WED_DIR", tmp_path / "hack wed")
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path / "results")
    (tmp_path / "reports").mkdir()
    (tmp_path / "hack wed").mkdir()
    (tmp_path / "results").mkdir()

    html_out = render_hackrwed_html()
    assert "hackrwed" in html_out
    assert "Launch Security Scan" in html_out


def test_execute_web_scan_runs_and_exports(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "HACK_WED_DIR", tmp_path / "hack wed")
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path / "results")

    mgr = ModuleManager("modules")
    mgr.discover()
    eng = Engine(module_manager=mgr, services={}, events=EventBus())

    res = execute_web_scan(
        eng,
        target_url="https://example.com",
        mode_str="passive",
        extra_scope_str="",
    )
    assert res["scan_id"].startswith("scan_")
    assert Path(res["hack_wed_path"]).exists()
    assert Path(res["json_path"]).exists()


def test_main_web_flag_invokes_server(monkeypatch):
    called = {}

    def _fake_serve(host="127.0.0.1", port=8765):
        called["host"] = host
        called["port"] = port

    monkeypatch.setattr("main.serve_hackrwed", _fake_serve)
    rc = main(["--web", "--port", "9090"])
    assert rc == 0
    assert called == {"host": "127.0.0.1", "port": 9090}
