#!/usr/bin/env python3
"""
Standalone memory database backup script.

Can be run from cron or manually:
    python scripts/backup_memory.py

Options:
    --maintenance    Also run pruning and vacuum
    --verbose        Enable debug logging
"""

import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from memory import MemoryStore, get_config


async def main(run_maintenance: bool = False, verbose: bool = False):
    """Run backup and optionally maintenance."""
    # Setup logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    config = get_config()

    # Initialize store
    store = MemoryStore(
        db_path=Path(__file__).parent.parent / "data" / "memory.db",
        chromadb_path=Path(__file__).parent.parent / "data" / "chromadb",
        enable_semantic=False  # Don't need embeddings for backup
    )

    # Check health first
    if not store.is_healthy():
        logger.error("Memory store is not healthy, aborting backup")
        sys.exit(1)

    # Create backup
    try:
        backup_path = await store.backup()
        logger.info(f"Backup created: {backup_path} ({backup_path.stat().st_size} bytes)")
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)

    # Run maintenance if requested
    if run_maintenance:
        logger.info("Running maintenance...")
        results = await store.run_maintenance()
        logger.info(f"Maintenance complete: {results}")

    logger.info("Done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backup memory database")
    parser.add_argument(
        "--maintenance", "-m",
        action="store_true",
        help="Also run pruning and vacuum after backup"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()
    asyncio.run(main(run_maintenance=args.maintenance, verbose=args.verbose))
