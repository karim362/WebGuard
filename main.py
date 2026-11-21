"""WebGuard entrypoint (supports CLI and /hackrwed web UI)."""
from __future__ import annotations
import sys
from core.engine import Engine
from core.module_manager import ModuleManager
from interface.app import run_app
from interface.web_ui import serve_hackrwed
from services.logger import get_logger
from services.storage import Storage


def build_engine() -> Engine:
    manager = ModuleManager(package_name="modules")
    count = manager.discover()
    logger = get_logger("webguard.main")
    logger.info("Discovered %d module(s)", count)
    storage = Storage()
    services = {"logger": logger, "storage": storage}
    return Engine(module_manager=manager, services=services, storage=storage)


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    pos_urls = [a for a in args_list if not a.startswith('-') and ('.' in a or a.startswith('http'))]
    args = list(sys.argv[1:] if argv is None else argv)
    if "--web" in args or "hackrwed" in args:
        host = "127.0.0.1"
        port = 8765
        for i, item in enumerate(args):
            if item == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
            elif item == "--host" and i + 1 < len(args):
                host = args[i + 1]
        serve_hackrwed(host=host, port=port)
        return 0

    try:
        engine = build_engine()
    except Exception as e:
        print(f"[FATAL] Could not initialize engine: {e}")
        return 1
    if len(engine.module_manager.list_all()) == 0:
        print("[WARN] No modules discovered.")
    try:
        run_app(engine, direct_url=(pos_urls[0] if pos_urls else None))
    except KeyboardInterrupt:
        print("\n[Interrupted]")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
