from core.event_bus import EventBus

def test_on_emit():
    bus = EventBus()
    seen = []
    bus.on("x", lambda v: seen.append(v))
    bus.emit("x", v=42)
    assert seen == [42]

def test_multiple_handlers():
    bus = EventBus()
    seen = []
    bus.on("x", lambda: seen.append("a"))
    bus.on("x", lambda: seen.append("b"))
    bus.emit("x")
    assert seen == ["a", "b"]

def test_broken_handler_does_not_break():
    bus = EventBus()
    seen = []
    def bad(): raise ValueError("boom")
    bus.on("x", bad)
    bus.on("x", lambda: seen.append("ok"))
    bus.emit("x")
    assert seen == ["ok"]
