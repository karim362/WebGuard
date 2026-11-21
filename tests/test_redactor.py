from services.redactor import (
    redact_headers,
    redact_url,
    redact_body,
    redact_cookie_header,
)


def test_redact_headers_authorization():
    h = {"Authorization": "Bearer xyz", "Accept": "*/*"}
    out = redact_headers(h)
    assert out["Authorization"] == "[REDACTED]"
    assert out["Accept"] == "*/*"


def test_redact_headers_cookie():
    h = {"Cookie": "sid=abc", "Server": "nginx"}
    out = redact_headers(h)
    assert out["Cookie"] == "[REDACTED]"
    assert out["Server"] == "nginx"


def test_redact_url_token():
    url = "https://x.com/a?token=abc&id=5"
    out = redact_url(url)
    assert "token=[REDACTED]" in out
    assert "id=5" in out


def test_redact_url_no_query():
    assert redact_url("https://x.com/a") == "https://x.com/a"


def test_redact_body_password():
    body = '{"user":"a","password":"secret123"}'
    out = redact_body(body)
    assert "secret123" not in out
    assert "[REDACTED]" in out


def test_redact_body_truncate():
    big = "a" * 5000
    out = redact_body(big, max_len=100)
    assert "truncated" in out
    assert len(out) < 200


def test_cookie_header():
    out = redact_cookie_header("a=1; b=2; c=3")
    assert "a=[REDACTED]" in out
    assert "1" not in out


def test_cookie_header_empty():
    assert redact_cookie_header("") == ""
