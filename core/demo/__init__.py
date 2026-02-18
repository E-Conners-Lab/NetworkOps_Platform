"""Demo mode for running NetworkOps without real network devices."""

import os

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
