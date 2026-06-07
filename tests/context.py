"""Test import context — ensures the package is importable from tests.

Usage in individual test modules:
    from .context import rapid7_mcp
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import rapid7_mcp  # noqa: F811, F401