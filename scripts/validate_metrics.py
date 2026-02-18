#!/usr/bin/env python3
"""
CI Metrics Validation Script

Validates that automation metrics meet required thresholds.
Used in CI/CD pipelines to ensure operational health standards.

Usage:
    # Validate against running API
    python scripts/validate_metrics.py --url http://localhost:5001

    # Validate with custom thresholds
    python scripts/validate_metrics.py --actionable-rate 90 --parser-success 95

    # Output JSON for CI parsing
    python scripts/validate_metrics.py --json

Exit codes:
    0 - All metrics meet thresholds
    1 - One or more metrics below threshold
    2 - Connection/parsing error
"""

import argparse
import json
import sys
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class MetricCheck:
    """Individual metric check result"""
    name: str
    value: float
    threshold: float
    passed: bool
    message: str


@dataclass
class ValidationResult:
    """Overall validation result"""
    passed: bool
    checks: List[MetricCheck]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": [
                {
                    "name": c.name,
                    "value": c.value,
                    "threshold": c.threshold,
                    "passed": c.passed,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "errors": self.errors,
        }


def fetch_metrics(base_url: str) -> Tuple[Dict[str, Any], List[str]]:
    """Fetch metrics from API endpoint"""
    errors = []
    metrics = {}

    # Try automation metrics endpoint
    try:
        resp = requests.get(f"{base_url}/api/metrics/automation", timeout=10)
        if resp.status_code == 200:
            metrics["automation"] = resp.json()
        else:
            errors.append(f"Automation metrics returned {resp.status_code}")
    except Exception as e:
        errors.append(f"Failed to fetch automation metrics: {e}")

    # Try Prometheus endpoint
    try:
        resp = requests.get(f"{base_url}/metrics", timeout=10)
        if resp.status_code == 200:
            metrics["prometheus"] = parse_prometheus(resp.text)
        else:
            errors.append(f"Prometheus metrics returned {resp.status_code}")
    except Exception as e:
        errors.append(f"Failed to fetch Prometheus metrics: {e}")

    return metrics, errors


def parse_prometheus(text: str) -> Dict[str, float]:
    """Parse Prometheus exposition format"""
    metrics = {}
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            # Handle lines like: metric_name{labels} value
            if "{" in line:
                name_part = line.split("{")[0]
                value_part = line.split("} ")[1] if "} " in line else line.split("}")[1]
            else:
                parts = line.split()
                if len(parts) >= 2:
                    name_part = parts[0]
                    value_part = parts[1]
                else:
                    continue
            metrics[name_part] = float(value_part)
        except (ValueError, IndexError):
            continue
    return metrics


def validate_metrics(
    metrics: Dict[str, Any],
    actionable_rate_threshold: float = 90.0,
    parser_success_threshold: float = 95.0,
    pass_rate_threshold: float = 80.0,
) -> ValidationResult:
    """Validate metrics against thresholds"""
    checks = []
    errors = []

    # Check actionable rate
    actionable_rate = None
    if "automation" in metrics and "tests" in metrics["automation"]:
        rate_str = metrics["automation"]["tests"].get("actionable_rate", "0%")
        try:
            actionable_rate = float(rate_str.replace("%", ""))
        except ValueError:
            errors.append(f"Invalid actionable_rate format: {rate_str}")

    if "prometheus" in metrics and actionable_rate is None:
        actionable_rate = metrics["prometheus"].get("test_actionable_rate")

    if actionable_rate is not None:
        passed = actionable_rate >= actionable_rate_threshold
        checks.append(MetricCheck(
            name="actionable_rate",
            value=actionable_rate,
            threshold=actionable_rate_threshold,
            passed=passed,
            message=f"{'PASS' if passed else 'FAIL'}: Actionable rate {actionable_rate:.1f}% >= {actionable_rate_threshold}%"
        ))

    # Check parser success rate
    parser_rate = None
    if "automation" in metrics and "parsers" in metrics["automation"]:
        rate_str = metrics["automation"]["parsers"].get("overall_success_rate", "0%")
        try:
            parser_rate = float(rate_str.replace("%", ""))
        except ValueError:
            errors.append(f"Invalid parser_success_rate format: {rate_str}")

    if "prometheus" in metrics and parser_rate is None:
        parser_rate = metrics["prometheus"].get("parser_overall_success_rate")

    if parser_rate is not None:
        passed = parser_rate >= parser_success_threshold
        checks.append(MetricCheck(
            name="parser_success_rate",
            value=parser_rate,
            threshold=parser_success_threshold,
            passed=passed,
            message=f"{'PASS' if passed else 'FAIL'}: Parser success rate {parser_rate:.1f}% >= {parser_success_threshold}%"
        ))

    # Check test pass rate
    pass_rate = None
    if "prometheus" in metrics:
        pass_rate = metrics["prometheus"].get("test_pass_rate")

    if pass_rate is not None:
        passed = pass_rate >= pass_rate_threshold
        checks.append(MetricCheck(
            name="test_pass_rate",
            value=pass_rate,
            threshold=pass_rate_threshold,
            passed=passed,
            message=f"{'PASS' if passed else 'FAIL'}: Test pass rate {pass_rate:.1f}% >= {pass_rate_threshold}%"
        ))

    # Overall result
    all_passed = all(c.passed for c in checks) if checks else False

    if not checks:
        errors.append("No metrics found to validate")

    return ValidationResult(
        passed=all_passed and not errors,
        checks=checks,
        errors=errors
    )


def main():
    parser = argparse.ArgumentParser(description="Validate automation metrics for CI/CD")
    parser.add_argument("--url", default="http://localhost:5001", help="API base URL")
    parser.add_argument("--actionable-rate", type=float, default=90.0, help="Minimum actionable rate %%")
    parser.add_argument("--parser-success", type=float, default=95.0, help="Minimum parser success rate %%")
    parser.add_argument("--pass-rate", type=float, default=80.0, help="Minimum test pass rate %%")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--skip-fetch", action="store_true", help="Skip fetching, use sample data")
    args = parser.parse_args()

    if not REQUESTS_AVAILABLE and not args.skip_fetch:
        print("Error: 'requests' library required. Install with: pip install requests")
        sys.exit(2)

    # Fetch metrics
    if args.skip_fetch:
        # Sample data for testing
        metrics = {
            "prometheus": {
                "test_actionable_rate": 95.0,
                "parser_overall_success_rate": 98.0,
                "test_pass_rate": 92.0,
            }
        }
        fetch_errors = []
    else:
        metrics, fetch_errors = fetch_metrics(args.url)

    if fetch_errors and not metrics:
        if args.json:
            print(json.dumps({"passed": False, "errors": fetch_errors}))
        else:
            print("Failed to fetch metrics:")
            for err in fetch_errors:
                print(f"  - {err}")
        sys.exit(2)

    # Validate
    result = validate_metrics(
        metrics,
        actionable_rate_threshold=args.actionable_rate,
        parser_success_threshold=args.parser_success,
        pass_rate_threshold=args.pass_rate,
    )

    # Add fetch errors
    result.errors.extend(fetch_errors)

    # Output
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("=" * 50)
        print("Automation Metrics Validation")
        print("=" * 50)
        for check in result.checks:
            status = "✓" if check.passed else "✗"
            print(f"{status} {check.message}")

        if result.errors:
            print("\nWarnings:")
            for err in result.errors:
                print(f"  ⚠ {err}")

        print("=" * 50)
        if result.passed:
            print("RESULT: PASSED - All metrics meet thresholds")
        else:
            print("RESULT: FAILED - One or more metrics below threshold")
        print("=" * 50)

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
