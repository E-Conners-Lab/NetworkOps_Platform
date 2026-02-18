#!/bin/bash
# NetworkOps wrk Benchmark Suite
#
# wrk is a C-based HTTP benchmarking tool that measures raw throughput.
# Use this for simple "what's the max capacity?" testing.
#
# Usage:
#   ./scripts/wrk_benchmark.sh                    # Test localhost:5001
#   API_URL=http://prod:5001 ./scripts/wrk_benchmark.sh  # Test custom URL
#
# Quick single test:
#   wrk -t4 -c100 -d10s http://localhost:5001/healthz

set -e

API_URL="${API_URL:-http://localhost:5001}"
DURATION="${DURATION:-30s}"

echo "========================================"
echo "  NetworkOps wrk Benchmark Suite"
echo "========================================"
echo ""
echo "Target: $API_URL"
echo "Duration per test: $DURATION"
echo ""

# Verify API is reachable
if ! curl -s -o /dev/null -w "%{http_code}" "$API_URL/healthz" | grep -q "200"; then
    echo "ERROR: API not reachable at $API_URL"
    exit 1
fi
echo "API is reachable. Starting benchmarks..."
echo ""

# Test 1: Health endpoint (baseline - lightweight JSON response)
echo "========================================"
echo "TEST 1: /healthz - Baseline"
echo "  4 threads, 100 connections, $DURATION"
echo "========================================"
wrk -t4 -c100 -d$DURATION "$API_URL/healthz"
echo ""

# Test 2: Metrics endpoint (larger response body)
echo "========================================"
echo "TEST 2: /metrics - Prometheus metrics"
echo "  4 threads, 100 connections, $DURATION"
echo "========================================"
wrk -t4 -c100 -d$DURATION "$API_URL/metrics"
echo ""

# Test 3: Higher concurrency
echo "========================================"
echo "TEST 3: /healthz - High Concurrency"
echo "  8 threads, 500 connections, $DURATION"
echo "========================================"
wrk -t8 -c500 -d$DURATION "$API_URL/healthz"
echo ""

# Test 4: Maximum throughput burst
echo "========================================"
echo "TEST 4: /healthz - Maximum Burst"
echo "  12 threads, 1000 connections, 10s"
echo "========================================"
wrk -t12 -c1000 -d10s "$API_URL/healthz"
echo ""

echo "========================================"
echo "  Benchmark Complete"
echo "========================================"
echo ""
echo "Compare with k6 baseline: ~2,150 req/sec @ 1000 VUs"
echo "wrk typically shows higher throughput due to lower overhead"
