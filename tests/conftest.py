"""
conftest.py
===========
Pytest configuration for the closed-loop-adversarial-detection test suite.

Place this file at:
    closed-loop-adversarial-detection/tests/conftest.py

What it does
------------
Adds pipeline/detection to sys.path so test files can do:

    from engine import DetectionEngine, ...

without needing an installed package or a src-layout import.

Run tests from the project root:
    pytest tests/ -v
    pytest tests/test_engine.py -v
    pytest tests/test_engine.py -v -k "test_regexp"   # run one class/test
"""

import sys
from pathlib import Path

# Project root = one level up from this file (tests/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add pipeline/detection so `import engine` resolves directly
DETECTION_MODULE = PROJECT_ROOT / "pipeline" / "detection"

if str(DETECTION_MODULE) not in sys.path:
    sys.path.insert(0, str(DETECTION_MODULE))
