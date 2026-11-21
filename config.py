"""WebGuard - Central configuration. Secrets go to .env (not here)."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
TARGETS_DIR = DATA_DIR / "targets"
RESULTS_DIR = DATA_DIR / "results"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"

# Internal storage export directory requested for HTML copies
INTERNAL_STORAGE_ROOT = Path.home() / "storage" / "shared"
HACK_WED_DIR = (
    INTERNAL_STORAGE_ROOT / "hack wed"
    if INTERNAL_STORAGE_ROOT.exists()
    else REPORTS_DIR / "hack wed"
)

for _p in (TARGETS_DIR, RESULTS_DIR, REPORTS_DIR, LOGS_DIR):
    _p.mkdir(parents=True, exist_ok=True)

APP_NAME = "WebGuard"
APP_VERSION = "1.0.0"
APP_STAGE = "V1.0 - Final Integration"

LOG_FILE = LOGS_DIR / "application.log"
LOG_LEVEL = "INFO"

DEFAULT_REQUEST_TIMEOUT = 15
DEFAULT_MAX_REQUESTS = 500
DEFAULT_RATE_LIMIT = 10
ALLOW_EXTERNAL_REDIRECTS = False
