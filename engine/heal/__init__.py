"""
LIA Heal — Validated Recovery Pipeline
"""
import sys
import os
import importlib.util

_dir = os.path.dirname(os.path.abspath(__file__))
_pipeline_path = os.path.join(_dir, "pipeline.py")

if os.path.isfile(_pipeline_path) and "heal.pipeline" not in sys.modules:
    spec = importlib.util.spec_from_file_location("heal.pipeline", _pipeline_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["heal.pipeline"] = mod
    spec.loader.exec_module(mod)

from .pipeline import RecoveryPipeline

__all__ = ["RecoveryPipeline"]
