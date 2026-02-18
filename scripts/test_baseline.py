#!/usr/bin/env python3
"""
Pre/Post refactor baseline test script.
Run this before and after refactoring to verify nothing broke.

Usage:
    python scripts/test_baseline.py
    python scripts/test_baseline.py --quick  # Skip network tests
"""

import sys
import json
import subprocess
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

PASSED = []
FAILED = []


def test(name: str):
    """Decorator to register and run tests."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                if result:
                    PASSED.append(name)
                    print(f"  ✓ {name}")
                else:
                    FAILED.append(name)
                    print(f"  ✗ {name}")
            except Exception as e:
                FAILED.append(name)
                print(f"  ✗ {name}: {e}")
        return wrapper
    return decorator


# =============================================================================
# IMPORT TESTS
# =============================================================================

@test("Import: network_mcp_async")
def test_import_mcp():
    from network_mcp_async import mcp
    return mcp is not None


@test("Import: config.devices")
def test_import_config():
    from config.devices import DEVICES, get_scrapli_device
    return len(DEVICES) > 0


@test("Import: memory module")
def test_import_memory():
    from memory.store import MemoryStore
    from memory.embeddings import EmbeddingService
    return True


@test("Import: rag module")
def test_import_rag():
    from rag.ingest import DocumentIngestor
    from rag.query import RAGQueryEngine
    from rag.network_tools import NETWORK_TOOLS
    return len(NETWORK_TOOLS) > 0


@test("Syntax: dashboard/api_server.py")
def test_api_syntax():
    import ast
    with open("dashboard/api_server.py") as f:
        ast.parse(f.read())
    return True


# =============================================================================
# RAG TESTS
# =============================================================================

@test("RAG: ChromaDB stats")
def test_rag_stats():
    from rag.ingest import DocumentIngestor
    ingestor = DocumentIngestor()
    stats = ingestor.get_stats()
    return stats["chunk_count"] > 0


@test("RAG: Search works")
def test_rag_search():
    from rag.query import RAGQueryEngine
    engine = RAGQueryEngine()
    results = engine.search("OSPF", top_k=1)
    return len(results) > 0


@test("RAG: Network tools get_devices")
def test_rag_network_tools():
    from rag.network_tools import execute_tool_sync
    result = execute_tool_sync("get_devices", {})
    return result.get("count", 0) > 0


# =============================================================================
# NETWORK TESTS (optional, require live devices)
# =============================================================================

def run_network_tests():
    """Run tests that require live network devices."""

    @test("Network: RAG health_check R1")
    def test_rag_health():
        from rag.network_tools import execute_tool_sync
        result = execute_tool_sync("health_check", {"device_name": "R1"})
        return result.get("status") == "healthy"

    @test("Network: Dashboard API /health")
    def test_dashboard_health():
        result = subprocess.run(
            ["curl", "-s", "http://localhost:5001/api/health"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
        return data.get("status") == "ok"

    @test("Network: Dashboard API /devices")
    def test_dashboard_devices():
        result = subprocess.run(
            ["curl", "-s", "http://localhost:5001/api/devices"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
        return len(data) >= 10

    test_rag_health()
    test_dashboard_health()
    test_dashboard_devices()


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Baseline tests for refactoring")
    parser.add_argument("--quick", action="store_true", help="Skip network tests")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("BASELINE TESTS")
    print("=" * 60)

    print("\n[Import Tests]")
    test_import_mcp()
    test_import_config()
    test_import_memory()
    test_import_rag()
    test_api_syntax()

    print("\n[RAG Tests]")
    test_rag_stats()
    test_rag_search()
    test_rag_network_tools()

    if not args.quick:
        print("\n[Network Tests]")
        run_network_tests()
    else:
        print("\n[Network Tests] SKIPPED (--quick)")

    print("\n" + "=" * 60)
    print(f"RESULTS: {len(PASSED)} passed, {len(FAILED)} failed")
    print("=" * 60)

    if FAILED:
        print("\nFailed tests:")
        for name in FAILED:
            print(f"  - {name}")
        sys.exit(1)
    else:
        print("\n✓ ALL TESTS PASSED - Safe to proceed with refactoring")
        sys.exit(0)


if __name__ == "__main__":
    main()
