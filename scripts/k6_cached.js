/**
 * NetworkOps API Cached Endpoints Benchmark
 * Tests ONLY fast, cached endpoints - no live device calls
 *
 * This measures true API capacity by avoiding:
 * - /api/topology (makes live SSH calls)
 * - Per-iteration authentication
 *
 * Usage:
 *   k6 run scripts/k6_cached.js
 *   k6 run --vus 500 --duration 1m scripts/k6_cached.js
 *   k6 run --vus 2000 --duration 2m scripts/k6_cached.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const healthzDuration = new Trend('healthz_duration');
const metricsDuration = new Trend('metrics_duration');
const deviceMetricsDuration = new Trend('device_metrics_duration');
const readyzDuration = new Trend('readyz_duration');
const successfulRequests = new Counter('successful_requests');

// Configuration
const BASE_URL = __ENV.API_URL || 'http://localhost:5001';

// Default options
export const options = {
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],  // Very fast for cached endpoints
    errors: ['rate<0.01'],
    healthz_duration: ['p(95)<50'],
    metrics_duration: ['p(95)<100'],
    device_metrics_duration: ['p(95)<150'],
  },
};

// No setup needed - all endpoints are public
export function setup() {
  console.log(`Testing cached endpoints at: ${BASE_URL}`);

  // Verify API is reachable
  const res = http.get(`${BASE_URL}/healthz`);
  if (res.status !== 200) {
    throw new Error(`API not reachable: ${res.status}`);
  }
  console.log('API is ready - starting benchmark');
  return {};
}

// Main test - only endpoints that work without external deps
export default function() {
  const random = Math.random() * 100;

  if (random < 60) {
    // 60% - Health check (K8s liveness probes)
    testHealthz();
  } else {
    // 40% - Prometheus metrics
    testMetrics();
  }

  // Minimal delay
  sleep(0.05);
}

function testHealthz() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/healthz`);
  healthzDuration.add(Date.now() - start);

  const success = check(res, {
    'healthz 200': (r) => r.status === 200,
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testReadyz() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/readyz`);
  readyzDuration.add(Date.now() - start);

  const success = check(res, {
    'readyz 200': (r) => r.status === 200,
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testMetrics() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/metrics`);
  metricsDuration.add(Date.now() - start);

  const success = check(res, {
    'metrics 200': (r) => r.status === 200,
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testDeviceMetrics() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/metrics/devices`);
  deviceMetricsDuration.add(Date.now() - start);

  const success = check(res, {
    'device_metrics 200': (r) => r.status === 200,
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

export function teardown() {
  console.log('Cached endpoints benchmark complete');
}

export function handleSummary(data) {
  const metrics = data.metrics || {};
  const lines = [];

  lines.push('\n' + '='.repeat(55));
  lines.push('  NetworkOps CACHED Endpoints Benchmark Results');
  lines.push('='.repeat(55) + '\n');

  if (metrics.http_reqs && metrics.http_reqs.values) {
    lines.push(`  Total Requests:      ${metrics.http_reqs.values.count || 0}`);
    lines.push(`  Requests/sec:        ${(metrics.http_reqs.values.rate || 0).toFixed(2)}`);
  }

  if (metrics.successful_requests && metrics.successful_requests.values) {
    lines.push(`  Successful:          ${metrics.successful_requests.values.count || 0}`);
  }

  if (metrics.http_req_duration && metrics.http_req_duration.values) {
    const dur = metrics.http_req_duration.values;
    lines.push(`  Avg Response Time:   ${(dur.avg || 0).toFixed(2)}ms`);
    lines.push(`  P95 Response Time:   ${(dur['p(95)'] || 0).toFixed(2)}ms`);
    lines.push(`  P99 Response Time:   ${(dur['p(99)'] || 0).toFixed(2)}ms`);
    lines.push(`  Min/Max:             ${(dur.min || 0).toFixed(2)}ms / ${(dur.max || 0).toFixed(2)}ms`);
  }

  if (metrics.errors && metrics.errors.values) {
    lines.push(`  Error Rate:          ${((metrics.errors.values.rate || 0) * 100).toFixed(3)}%`);
  }

  lines.push('\n  Endpoint Latencies (P95):');
  const endpoints = [
    { name: 'healthz', metric: 'healthz_duration' },
    { name: 'readyz', metric: 'readyz_duration' },
    { name: 'metrics', metric: 'metrics_duration' },
    { name: 'device_metrics', metric: 'device_metrics_duration' },
  ];

  for (const ep of endpoints) {
    if (metrics[ep.metric] && metrics[ep.metric].values) {
      const p95 = metrics[ep.metric].values['p(95)'] || 0;
      lines.push(`    ${ep.name.padEnd(15)} ${p95.toFixed(2).padStart(8)}ms`);
    }
  }

  lines.push('\n  Threshold Results:');
  for (const [name, result] of Object.entries(data.thresholds || {})) {
    const status = result.ok ? '  PASS' : '  FAIL';
    lines.push(`    ${status}: ${name}`);
  }

  lines.push('\n' + '='.repeat(55) + '\n');

  return {
    'stdout': lines.join('\n'),
    'data/benchmarks/benchmark_cached_results.json': JSON.stringify({
      timestamp: new Date().toISOString(),
      requests_per_sec: metrics.http_reqs ? metrics.http_reqs.values.rate : 0,
      p95_ms: metrics.http_req_duration ? metrics.http_req_duration.values['p(95)'] : 0,
      error_rate: metrics.errors ? metrics.errors.values.rate : 0,
    }, null, 2),
  };
}
