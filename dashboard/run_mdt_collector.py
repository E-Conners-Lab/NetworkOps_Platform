"""
Standalone MDT collector entry point.

Run this when MDT_EXTERNAL=true to collect telemetry as a separate process.
Publishes updates to Redis for the WebSocket bridge in the API server.

Usage:
    python dashboard/run_mdt_collector.py
"""

import signal
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from dashboard.mdt_collector import get_mdt_collector


def main():
    collector = get_mdt_collector(port=57000)

    def shutdown(signum, frame):
        print("Shutting down MDT collector...")
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print("Starting standalone MDT collector on gRPC port 57000...")
    collector.start()

    # Keep the process alive
    signal.pause()


if __name__ == "__main__":
    main()
