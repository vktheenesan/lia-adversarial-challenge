"""
LIA Engine Core System Package
"""
import sys
import os

_engine_dir = os.path.dirname(os.path.abspath(__file__))
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
