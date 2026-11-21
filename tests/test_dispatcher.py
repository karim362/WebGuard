from core.dispatcher import Dispatcher
from core.module_manager import ModuleManager
from models.module import ScanMode
from models.scan_config import ScanConfig

def _cfg(**kw):
    d = dict(target_url="https://example.com", authorization_confirmed=True,
             mode=ScanMode.PASSIVE)
    d.update(kw)
    return ScanConfig(**d)

def test_select_all_passive():
    m = ModuleManager("modules"); m.discover()
    d = Dispatcher(m)
    mods = d.select(_cfg(), available_services=set())
    names = [x.name for x in mods]
    assert "example_passive" in names

def test_select_by_name():
    m = ModuleManager("modules"); m.discover()
    d = Dispatcher(m)
    mods = d.select(_cfg(selected_modules=["example_passive"]),
                    available_services=set())
    assert [x.name for x in mods] == ["example_passive"]

def test_select_by_name_not_found():
    m = ModuleManager("modules"); m.discover()
    d = Dispatcher(m)
    mods = d.select(_cfg(selected_modules=["does_not_exist"]),
                    available_services=set())
    assert mods == []
