# WebGuard

Advanced Web Security Testing Framework — Termux + Python.

## Status
**V0.1 — Foundation**. Structure, models, scope guard, engine, demo module.

## Run
    python main.py

## Tests
    python -m pytest -q

## Invariants
- Engine does not know module internals.
- Modules do not import services (DI via ModuleContext).
- Interface never performs scanning.
- ScopeGuard is closed-by-default.
- Logs never contain cookies/tokens (redacted).
