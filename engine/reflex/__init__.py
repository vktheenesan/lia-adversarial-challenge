"""
LIA Reflex — Immediate Deterministic Containment
"""
import sys
import os
import importlib.util

_dir = os.path.dirname(os.path.abspath(__file__))
_engine_path = os.path.join(_dir, "engine.py")

if os.path.isfile(_engine_path) and "reflex.engine" not in sys.modules:
    spec = importlib.util.spec_from_file_location("reflex.engine", _engine_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["reflex.engine"] = mod
    spec.loader.exec_module(mod)

from .engine import ReflexEngine

__all__ = ["ReflexEngine"]
