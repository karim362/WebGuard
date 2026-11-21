"""
dispatcher — selects which registered modules should run for a given ScanConfig.
Pure selection. Does NOT execute.
"""
from __future__ import annotations
from core.module_manager import ModuleManager
from core.permissions import module_allowed
from models.module import BaseModule
from models.scan_config import ScanConfig

class Dispatcher:
    def __init__(self, manager: ModuleManager):
        self.manager = manager

    def select(self, config: ScanConfig, available_services: set[str]) -> list[BaseModule]:
        candidates = self.manager.list_by_mode(config.mode)

        if config.selected_modules or config.selected_categories:
            names = set(config.selected_modules)
            cats = set(config.selected_categories)
            filtered = []
            for m in candidates:
                category = m.__class__.__module__.split(".")[1] if "." in m.__class__.__module__ else ""
                if m.name in names or category in cats:
                    filtered.append(m)
            candidates = filtered

        selected: list[BaseModule] = []
        for m in candidates:
            ok, _reason = module_allowed(m, config.mode, available_services)
            if ok:
                selected.append(m)
        return selected
