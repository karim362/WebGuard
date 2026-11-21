"""
CookieManager — parse cookies from header string, JSON file, or Netscape cookies.txt.
Never logs values. Never writes them to reports.
"""
from __future__ import annotations
import json
from pathlib import Path

class CookieError(Exception):
    pass

def parse_header(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if k:
            cookies[k] = v.strip()
    return cookies

def parse_json_file(path: str | Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):  # browser export style: [{name, value}, ...]
        out = {}
        for item in data:
            if isinstance(item, dict) and "name" in item and "value" in item:
                out[item["name"]] = str(item["value"])
        return out
    if isinstance(data, dict):  # plain {name: value}
        return {str(k): str(v) for k, v in data.items()}
    raise CookieError("Unsupported JSON cookie format")

def parse_netscape_file(path: str | Path) -> dict[str, str]:
    """Parse Netscape cookies.txt (curl/wget format)."""
    out: dict[str, str] = {}
    p = Path(path)
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            out[parts[5]] = parts[6]
    return out

def load_cookies(source: str) -> dict[str, str]:
    """
    Accepts either:
      - a raw Cookie header string:  "session=abc; csrftoken=xyz"
      - path to .json  -> parse_json_file
      - path to .txt   -> parse_netscape_file
    """
    if not source:
        return {}
    s = source.strip()
    if s.startswith("{") or s.startswith("["):
        return parse_header(s) if "=" in s and not s.startswith("{") else json.loads(s)
    p = Path(s)
    if p.exists() and p.is_file():
        suffix = p.suffix.lower()
        if suffix == ".json":
            return parse_json_file(p)
        if suffix in (".txt", ".cookies"):
            return parse_netscape_file(p)
        raise CookieError(f"Unsupported cookie file extension: {suffix}")
    return parse_header(s)
