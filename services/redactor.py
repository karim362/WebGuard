"""
Central redactor — strips secrets from headers/text before storage.
Used by evidence_collector and logger. Never logs matched values.
"""
from __future__ import annotations
import re

_SENSITIVE_HEADERS = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
)

_SENSITIVE_QUERY_KEYS = (
    "token",
    "api_key",
    "apikey",
    "access_token",
    "password",
    "passwd",
    "secret",
    "session",
    "sid",
)

_REDACTED = "[REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADERS:
            out[k] = _REDACTED
        else:
            out[k] = v
    return out


def redact_url(url: str) -> str:
    if "?" not in url:
        return url
    base, _, query = url.partition("?")
    parts = query.split("&")
    redacted = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            if k.lower() in _SENSITIVE_QUERY_KEYS:
                redacted.append(f"{k}={_REDACTED}")
            else:
                redacted.append(p)
        else:
            redacted.append(p)
    return base + "?" + "&".join(redacted)


def redact_body(text: str, max_len: int = 4000) -> str:
    if text is None:
        return ""
    # Strip likely secrets inside JSON bodies
    text = re.sub(
        r'"(password|token|secret|api[_-]?key)"\s*:\s*"[^"]*"',
        r'"\1":"[REDACTED]"',
        text,
        flags=re.IGNORECASE,
    )
    if len(text) > max_len:
        return text[:max_len] + f"\n... [truncated at {max_len}]"
    return text


def redact_cookie_header(value: str) -> str:
    if not value:
        return value
    parts = value.split(";")
    out = []
    for p in parts:
        if "=" in p:
            k = p.split("=", 1)[0].strip()
            out.append(f"{k}={_REDACTED}")
        else:
            out.append(p.strip())
    return "; ".join(out)
