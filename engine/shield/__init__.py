"""
LIA Shield — Deterministic Reference Monitor & Policy Hypervisor
"""
import sys
import os
import importlib.util

_dir = os.path.dirname(os.path.abspath(__file__))
_engine_path = os.path.join(_dir, "engine.py")

if os.path.isfile(_engine_path) and "shield.engine" not in sys.modules:
    spec = importlib.util.spec_from_file_location("shield.engine", _engine_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["shield.engine"] = mod
    spec.loader.exec_module(mod)

from .engine import ShieldEngine, PolicyDecision, EventBus, NormalizedEvent

__all__ = ["ShieldEngine", "PolicyDecision", "EventBus", "NormalizedEvent"]
