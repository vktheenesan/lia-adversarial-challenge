"""
LIA Immune Memory — Cryptographically Signed Structured Incident Memory
"""
import sys
import os
import importlib.util

_dir = os.path.dirname(os.path.abspath(__file__))
_store_path = os.path.join(_dir, "store.py")

if os.path.isfile(_store_path) and "memory.store" not in sys.modules:
    spec = importlib.util.spec_from_file_location("memory.store", _store_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["memory.store"] = mod
    spec.loader.exec_module(mod)

from .store import ImmuneMemoryStore

__all__ = ["ImmuneMemoryStore"]
