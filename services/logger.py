"""Central logger. Never logs secrets (cookies, tokens, auth headers)."""
from __future__ import annotations
import logging, re
import config

_SENSITIVE_PATTERNS = [
    re.compile(r"(cookie\s*[:=]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(authorization\s*[:=]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(set-cookie\s*[:=]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)([^\s,;]+)", re.IGNORECASE),
]

def redact(text: str) -> str:
    for pat in _SENSITIVE_PATTERNS:
        text = pat.sub(r"\1[REDACTED]", text)
    return text

class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
            if record.args:
                record.args = tuple(
                    redact(str(a)) if isinstance(a, str) else a for a in record.args
                )
        except Exception:
            pass
        return True

def get_logger(name: str = "webguard") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(config.LOG_LEVEL)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt); fh.addFilter(_RedactingFilter()); logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt); sh.addFilter(_RedactingFilter()); logger.addHandler(sh)
    logger.propagate = False
    return logger
