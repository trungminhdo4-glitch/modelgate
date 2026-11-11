"""SPY FIXTURE — must never execute.

ModelGate analyzes this file as bytes only. If any code path ever executed
it, the marker file below would be created and the acceptance test would
fail loudly. The fixture is intentionally a tripwire, not a payload.
"""
from pathlib import Path

_MARKER = Path(__file__).with_name("SPY_EXECUTED.marker")


def install_tripwire() -> None:
    _MARKER.write_text("model code was executed", encoding="utf-8")


install_tripwire()
raise SystemExit("spy fixture executed — ModelGate must never run model code")
