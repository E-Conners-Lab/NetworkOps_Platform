"""Root conftest.py for pytest.

This file ensures the project root is in sys.path before any test imports.
"""
import os
import sys

# Add project root to path at startup - MUST happen at import time
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Also ensure PYTHONPATH is set for subprocess
os.environ.setdefault("PYTHONPATH", project_root)

# pytest hook to configure path early
def pytest_configure(config):
    """Configure pytest path early in the process."""
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
