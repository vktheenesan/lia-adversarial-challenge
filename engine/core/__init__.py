"""
LIA Core Package
"""
import sys
import os
import importlib.util

_core_dir = os.path.dirname(os.path.abspath(__file__))
_bus_path = os.path.join(_core_dir, "event_bus", "bus.py")
if os.path.isfile(_bus_path) and "core.event_bus" not in sys.modules:
    spec = importlib.util.spec_from_file_location("core.event_bus", _bus_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["core.event_bus"] = mod
    spec.loader.exec_module(mod)
