"""ModuleManager — discovers and registers modules. Does NOT execute."""
from __future__ import annotations
import importlib, inspect, pkgutil
from types import ModuleType
from models.module import BaseModule, ScanMode

class ModuleManager:
    def __init__(self, package_name: str = "modules"):
        self.package_name = package_name
        self._registry: dict[str, BaseModule] = {}

    def discover(self) -> int:
        pkg = importlib.import_module(self.package_name)
        for mod_info in pkgutil.walk_packages(
            pkg.__path__, prefix=pkg.__name__ + "."
        ):
            # Import every .py file (not just packages)
            try:
                mod: ModuleType = importlib.import_module(mod_info.name)
            except Exception:
                continue
            self._register_from_module(mod)
        return len(self._registry)

    def _register_from_module(self, mod: ModuleType) -> None:
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj is BaseModule:
                continue
            if not issubclass(obj, BaseModule):
                continue
            if obj.__module__ != mod.__name__:
                continue
            try:
                instance = obj()
            except Exception:
                continue
            if instance.name in self._registry:
                continue
            self._registry[instance.name] = instance

    def register(self, module: BaseModule) -> None:
        self._registry[module.name] = module

    def get(self, name: str) -> BaseModule | None:
        return self._registry.get(name)

    def list_all(self) -> list[BaseModule]:
        return list(self._registry.values())

    def list_by_mode(self, mode: ScanMode) -> list[BaseModule]:
        order = {ScanMode.PASSIVE: 0, ScanMode.ACTIVE: 1, ScanMode.ADVANCED: 2}
        limit = order[mode]
        return [m for m in self._registry.values() if order[m.required_mode] <= limit]
