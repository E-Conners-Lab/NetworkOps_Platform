#!/usr/bin/env python3
"""
Feedback System Validation and Rollback Script.

Validates the error-learning feedback system implementation:
1. Runs unit tests for feedback components
2. Tests database schema and operations
3. Tests MCP tools registration
4. Tests context injection enhancement

If validation fails:
- Logs detailed error information
- Optionally rolls back to previous commit

Usage:
    python scripts/validate_feedback_system.py [--rollback-on-fail]
    python scripts/validate_feedback_system.py --dry-run
"""

import subprocess
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
LOG_DIR = PROJECT_ROOT / "logs" / "validation"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class ValidationResult:
    """Container for validation results."""

    def __init__(self):
        self.passed: list[str] = []
        self.failed: list[dict] = []
        self.warnings: list[str] = []
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None

    def add_pass(self, test_name: str):
        self.passed.append(test_name)
        logger.info(f"  PASS: {test_name}")

    def add_fail(self, test_name: str, error: str, traceback: Optional[str] = None):
        self.failed.append({
            "test": test_name,
            "error": error,
            "traceback": traceback
        })
        logger.error(f"  FAIL: {test_name} - {error}")

    def add_warning(self, message: str):
        self.warnings.append(message)
        logger.warning(f"  WARN: {message}")

    def is_success(self) -> bool:
        return len(self.failed) == 0

    def to_dict(self) -> dict:
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        return {
            "success": self.is_success(),
            "timestamp": self.start_time.isoformat(),
            "duration_seconds": duration,
            "summary": {
                "passed": len(self.passed),
                "failed": len(self.failed),
                "warnings": len(self.warnings)
            },
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings
        }


def run_command(cmd: list[str], cwd: Optional[Path] = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out after 5 minutes"
    except Exception as e:
        return -1, "", str(e)


def validate_imports(result: ValidationResult):
    """Validate that all new modules can be imported."""
    logger.info("Validating imports...")

    # Test FeedbackRecord model import
    try:
        from memory.models import FeedbackRecord
        result.add_pass("Import FeedbackRecord model")
    except Exception as e:
        result.add_fail("Import FeedbackRecord model", str(e))

    # Test feedback MCP tools import
    try:
        from mcp_tools.feedback import (
            feedback_record, feedback_search, feedback_stats, feedback_learn, TOOLS
        )
        result.add_pass("Import feedback MCP tools")
    except Exception as e:
        result.add_fail("Import feedback MCP tools", str(e))

    # Test context manager import
    try:
        from memory.context_manager import MemoryAwareToolManager, create_memory_hooks
        result.add_pass("Import context manager")
    except Exception as e:
        result.add_fail("Import context manager", str(e))

    # Test ALL_TOOLS registry
    try:
        from mcp_tools import ALL_TOOLS
        tool_names = [t["name"] for t in ALL_TOOLS]
        if "feedback_record" not in tool_names:
            result.add_fail("Feedback tools in ALL_TOOLS", "feedback_record not found")
        else:
            result.add_pass("Feedback tools in ALL_TOOLS registry")
    except Exception as e:
        result.add_fail("Import ALL_TOOLS", str(e))


def validate_database_schema(result: ValidationResult):
    """Validate database schema has feedback table."""
    logger.info("Validating database schema...")

    try:
        import tempfile
        import sqlite3
        from memory.store import MemoryStore

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = MemoryStore(
                db_path=db_path,
                chromadb_path=Path(tmpdir) / "chromadb"
            )

            # Use direct sqlite connection to verify schema
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row

            # Check feedback table exists
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'"
            )
            if cursor.fetchone():
                result.add_pass("Feedback table created")
            else:
                result.add_fail("Feedback table creation", "Table 'feedback' not found")

            # Check columns
            cursor = conn.execute("PRAGMA table_info(feedback)")
            columns = {row[1] for row in cursor.fetchall()}
            expected = {"id", "tool_name", "correct", "resolution", "learned"}

            missing = expected - columns
            if missing:
                result.add_fail("Feedback table columns", f"Missing columns: {missing}")
            else:
                result.add_pass("Feedback table schema")

            conn.close()

    except Exception as e:
        result.add_fail("Database schema validation", str(e))


def validate_mcp_tool_signatures(result: ValidationResult):
    """Validate MCP tool function signatures."""
    logger.info("Validating MCP tool signatures...")

    try:
        from mcp_tools.feedback import TOOLS
        import inspect

        for tool in TOOLS:
            fn = tool["fn"]
            sig = inspect.signature(fn)

            # Check it's async
            if not inspect.iscoroutinefunction(fn):
                result.add_fail(f"Tool {tool['name']} async", "Function is not async")
            else:
                result.add_pass(f"Tool {tool['name']} is async")

            # Check return type annotation
            if sig.return_annotation is str or sig.return_annotation is inspect.Parameter.empty:
                result.add_pass(f"Tool {tool['name']} return type")
            else:
                result.add_warning(f"Tool {tool['name']} has unexpected return type: {sig.return_annotation}")

    except Exception as e:
        result.add_fail("Tool signature validation", str(e))


def run_pytest(result: ValidationResult):
    """Run pytest on feedback system tests."""
    logger.info("Running pytest...")

    code, stdout, stderr = run_command([
        sys.executable, "-m", "pytest",
        "tests/test_feedback_system.py",
        "-v", "--tb=short", "-x"
    ])

    if code == 0:
        result.add_pass("Pytest: test_feedback_system.py")
    else:
        # Parse pytest output for specific failures
        output = stdout + stderr
        result.add_fail("Pytest: test_feedback_system.py", f"Exit code {code}", output[-2000:])


def validate_context_injection(result: ValidationResult):
    """Validate context injection includes feedback."""
    logger.info("Validating context injection...")

    try:
        from memory.context_manager import MemoryAwareToolManager
        import tempfile
        from memory.store import MemoryStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(
                db_path=Path(tmpdir) / "test.db",
                chromadb_path=Path(tmpdir) / "chromadb"
            )
            manager = MemoryAwareToolManager(memory_store=store)

            # Check manager has get_feedback_for_tool method
            if hasattr(manager, 'get_feedback_for_tool'):
                result.add_pass("Manager has get_feedback_for_tool method")
            else:
                result.add_fail("Manager method", "Missing get_feedback_for_tool")

            # Check format_context_for_injection accepts feedback
            import inspect
            sig = inspect.signature(manager.format_context_for_injection)
            params = list(sig.parameters.keys())

            if 'feedback_items' in params:
                result.add_pass("format_context_for_injection accepts feedback_items")
            else:
                result.add_fail("format_context_for_injection signature",
                              f"Missing feedback_items param. Has: {params}")

    except Exception as e:
        result.add_fail("Context injection validation", str(e))


def get_current_branch() -> str:
    """Get current git branch name."""
    code, stdout, _ = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return stdout.strip() if code == 0 else "unknown"


def get_last_commit_hash() -> str:
    """Get last commit hash."""
    code, stdout, _ = run_command(["git", "rev-parse", "HEAD"])
    return stdout.strip()[:8] if code == 0 else "unknown"


def rollback_to_main():
    """Rollback to main branch."""
    logger.warning("Rolling back to main branch...")

    # Stash any changes
    run_command(["git", "stash"])

    # Checkout main
    code, _, stderr = run_command(["git", "checkout", "main"])
    if code != 0:
        logger.error(f"Failed to checkout main: {stderr}")
        return False

    logger.info("Successfully rolled back to main branch")
    return True


def save_report(result: ValidationResult, rollback_performed: bool = False):
    """Save validation report to logs directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = LOG_DIR / f"validation_{timestamp}.json"

    report = result.to_dict()
    report["branch"] = get_current_branch()
    report["commit"] = get_last_commit_hash()
    report["rollback_performed"] = rollback_performed

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report saved to: {report_path}")
    return report_path


def main():
    """Main validation routine."""
    import argparse

    parser = argparse.ArgumentParser(description="Validate feedback system implementation")
    parser.add_argument("--rollback-on-fail", action="store_true",
                       help="Rollback to main if validation fails")
    parser.add_argument("--dry-run", action="store_true",
                       help="Only run import validation, skip pytest")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Feedback System Validation")
    logger.info(f"Branch: {get_current_branch()}")
    logger.info(f"Commit: {get_last_commit_hash()}")
    logger.info("=" * 60)

    result = ValidationResult()

    # Run validations
    validate_imports(result)
    validate_database_schema(result)
    validate_mcp_tool_signatures(result)
    validate_context_injection(result)

    if not args.dry_run:
        run_pytest(result)

    # Summary
    logger.info("=" * 60)
    logger.info("VALIDATION SUMMARY")
    logger.info(f"  Passed: {len(result.passed)}")
    logger.info(f"  Failed: {len(result.failed)}")
    logger.info(f"  Warnings: {len(result.warnings)}")
    logger.info("=" * 60)

    # Handle failure
    rollback_performed = False
    if not result.is_success():
        logger.error("VALIDATION FAILED")

        if result.failed:
            logger.error("Failed tests:")
            for failure in result.failed:
                logger.error(f"  - {failure['test']}: {failure['error']}")

        if args.rollback_on_fail:
            rollback_performed = rollback_to_main()

    else:
        logger.info("VALIDATION PASSED")

    # Save report
    report_path = save_report(result, rollback_performed)

    # Exit with appropriate code
    sys.exit(0 if result.is_success() else 1)


if __name__ == "__main__":
    main()
