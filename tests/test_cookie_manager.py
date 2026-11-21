import json
from pathlib import Path
from services.cookie_manager import (
    CookieError, load_cookies, parse_header, parse_json_file, parse_netscape_file,
)

def test_parse_header():
    assert parse_header("a=1; b=2;") == {"a": "1", "b": "2"}

def test_load_from_string():
    assert load_cookies("session=abc; csrf=xyz")["session"] == "abc"

def test_json_dict(tmp_path: Path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"sid": "abc"}))
    assert parse_json_file(p)["sid"] == "abc"

def test_json_list(tmp_path: Path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps([{"name": "sid", "value": "abc"}]))
    assert parse_json_file(p)["sid"] == "abc"

def test_netscape(tmp_path: Path):
    p = tmp_path / "c.txt"
    p.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tFALSE\t0\tsid\tabc\n"
    )
    assert parse_netscape_file(p)["sid"] == "abc"

def test_unsupported_extension(tmp_path: Path):
    p = tmp_path / "c.xls"
    p.write_text("x")
    try:
        load_cookies(str(p))
    except CookieError:
        pass
    else:
        raise AssertionError("Expected CookieError")
