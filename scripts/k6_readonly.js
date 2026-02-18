/**
 * NetworkOps API Read-Only Benchmark
 * Tests pure API throughput without rate limiting interference
 *
 * This test:
 * - Authenticates ONCE in setup (shared token)
 * - Skips per-iteration login attempts
 * - Focuses on read-only cached endpoints
 * - Measures true API capacity
 *
 * Usage:
 *   # Quick test (default: 10 VUs, 30s)
 *   k6 run scripts/k6_readonly.js
 *
 *   # Load test (100 VUs, 2 minutes)
 *   k6 run --vus 100 --duration 2m scripts/k6_readonly.js
 *
 *   # Stress test (500 VUs, 5 minutes)
 *   k6 run --vus 500 --duration 5m scripts/k6_readonly.js
 *
 *   # Extreme test with config
 *   k6 run --config scripts/k6_readonly_extreme.json scripts/k6_readonly.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const healthzDuration = new Trend('healthz_duration');
const topologyDuration = new Trend('topology_duration');
const devicesDuration = new Trend('devices_duration');
const metricsDuration = new Trend('metrics_duration');
const deviceMetricsDuration = new Trend('device_metrics_duration');
const successfulRequests = new Counter('successful_requests');
const totalRequests = new Counter('total_requests');

// Configuration
const BASE_URL = __ENV.API_URL || 'http://localhost:5001';
const USERNAME = __ENV.API_USER || 'admin';
const PASSWORD = __ENV.API_PASS || 'admin';

// Default options (can be overridden by CLI or config file)
export const options = {
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],  // Tighter thresholds for cached endpoints
    errors: ['rate<0.01'],  // Less than 1% errors
    healthz_duration: ['p(95)<100'],      // Health check under 100ms
    topology_duration: ['p(95)<500'],     // Topology under 500ms
    devices_duration: ['p(95)<200'],      // Devices under 200ms
    metrics_duration: ['p(95)<200'],      // Metrics under 200ms
  },
};

// Setup - runs ONCE before all VUs start
// The returned data is shared across all VUs
export function setup() {
  console.log(`Testing API at: ${BASE_URL}`);
  console.log('Authenticating once for all VUs...');

  // Verify API is reachable
  const healthRes = http.get(`${BASE_URL}/healthz`);
  if (healthRes.status !== 200) {
    throw new Error(`API not reachable: ${healthRes.status}`);
  }

  // Get auth token ONCE for all VUs
  const loginRes = http.post(`${BASE_URL}/api/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (loginRes.status !== 200) {
    console.warn(`Login failed: ${loginRes.status} - running unauthenticated tests only`);
    return { token: null, headers: { 'Content-Type': 'application/json' } };
  }

  const token = JSON.parse(loginRes.body).access_token;
  console.log('Authentication successful - token shared across all VUs');

  return {
    token: token,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  };
}

// Main test function - runs for each VU iteration
// Uses shared token from setup - NO per-iteration auth
export default function(data) {
  const headers = data.headers;

  // Endpoint weights (controls traffic distribution)
  // Total = 100, mimics realistic read patterns
  const random = Math.random() * 100;

  if (random < 30) {
    // 30% - Health check (most frequent, monitoring probes)
    testHealthz();
  } else if (random < 55) {
    // 25% - Prometheus metrics (monitoring scrapes)
    testMetrics();
  } else if (random < 75) {
    // 20% - Topology (dashboard loads)
    testTopology(headers);
  } else if (random < 90) {
    // 15% - Devices list (API calls)
    testDevices(headers);
  } else {
    // 10% - Device metrics (Grafana scrapes)
    testDeviceMetrics();
  }

  // Minimal sleep to simulate realistic request patterns
  sleep(0.1);
}

function testHealthz() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/healthz`);
  healthzDuration.add(Date.now() - start);
  totalRequests.add(1);

  const success = check(res, {
    'healthz status 200': (r) => r.status === 200,
    'healthz has status field': (r) => {
      try { return JSON.parse(r.body).status !== undefined; }
      catch { return false; }
    },
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testMetrics() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/metrics`);
  metricsDuration.add(Date.now() - start);
  totalRequests.add(1);

  const success = check(res, {
    'metrics status 200': (r) => r.status === 200,
    'metrics has networkops prefix': (r) => r.body.includes('networkops_'),
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testDeviceMetrics() {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/metrics/devices`);
  deviceMetricsDuration.add(Date.now() - start);
  totalRequests.add(1);

  const success = check(res, {
    'device metrics status 200': (r) => r.status === 200,
    'device metrics has data': (r) => r.body.includes('network_device_'),
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testTopology(headers) {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/api/topology`, { headers });
  topologyDuration.add(Date.now() - start);
  totalRequests.add(1);

  const success = check(res, {
    'topology status 200': (r) => r.status === 200,
    'topology has nodes': (r) => {
      try { return JSON.parse(r.body).nodes !== undefined; }
      catch { return false; }
    },
    'topology has links': (r) => {
      try { return JSON.parse(r.body).links !== undefined; }
      catch { return false; }
    },
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

function testDevices(headers) {
  const start = Date.now();
  const res = http.get(`${BASE_URL}/api/devices`, { headers });
  devicesDuration.add(Date.now() - start);
  totalRequests.add(1);

  const success = check(res, {
    'devices status 200': (r) => r.status === 200,
    'devices is array': (r) => {
      try { return Array.isArray(JSON.parse(r.body)); }
      catch { return false; }
    },
  });

  errorRate.add(!success);
  if (success) successfulRequests.add(1);
}

// Teardown - runs once after all VUs complete
export function teardown(data) {
  console.log('Read-only benchmark complete');

  // Logout to clean up session
  if (data.token) {
    http.post(`${BASE_URL}/api/auth/logout`, null, {
      headers: { 'Authorization': `Bearer ${data.token}` }
    });
  }
}

// Custom summary output
export function handleSummary(data) {
  const metrics = data.metrics || {};
  const lines = [];

  lines.push('\n' + '='.repeat(50));
  lines.push('  NetworkOps Read-Only API Benchmark Results');
  lines.push('='.repeat(50) + '\n');

  // Overall stats
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
    lines.push(`  Min Response Time:   ${(dur.min || 0).toFixed(2)}ms`);
    lines.push(`  Max Response Time:   ${(dur.max || 0).toFixed(2)}ms`);
  }

  if (metrics.errors && metrics.errors.values) {
    lines.push(`  Error Rate:          ${((metrics.errors.values.rate || 0) * 100).toFixed(3)}%`);
  }

  // Per-endpoint breakdown
  lines.push('\n  Endpoint Latencies (P95):');

  const endpoints = [
    { name: 'healthz', metric: 'healthz_duration', weight: '30%' },
    { name: 'metrics', metric: 'metrics_duration', weight: '25%' },
    { name: 'topology', metric: 'topology_duration', weight: '20%' },
    { name: 'devices', metric: 'devices_duration', weight: '15%' },
    { name: 'device_metrics', metric: 'device_metrics_duration', weight: '10%' },
  ];

  for (const ep of endpoints) {
    if (metrics[ep.metric] && metrics[ep.metric].values) {
      const p95 = metrics[ep.metric].values['p(95)'] || 0;
      lines.push(`    ${ep.name.padEnd(15)} ${p95.toFixed(2).padStart(8)}ms  (${ep.weight} traffic)`);
    }
  }

  // Threshold results
  lines.push('\n  Threshold Results:');
  for (const [name, result] of Object.entries(data.thresholds || {})) {
    const status = result.ok ? '  PASS' : '  FAIL';
    lines.push(`    ${status}: ${name}`);
  }

  lines.push('\n' + '='.repeat(50) + '\n');

  // Calculate summary stats for JSON output
  const summary = {
    timestamp: new Date().toISOString(),
    test_type: 'readonly',
    duration_ms: data.state.testRunDurationMs,
    vus_max: metrics.vus ? metrics.vus.values.max : 0,
    requests: {
      total: metrics.http_reqs ? metrics.http_reqs.values.count : 0,
      rate_per_sec: metrics.http_reqs ? metrics.http_reqs.values.rate : 0,
      successful: metrics.successful_requests ? metrics.successful_requests.values.count : 0,
    },
    response_time_ms: {
      avg: metrics.http_req_duration ? metrics.http_req_duration.values.avg : 0,
      min: metrics.http_req_duration ? metrics.http_req_duration.values.min : 0,
      max: metrics.http_req_duration ? metrics.http_req_duration.values.max : 0,
      p95: metrics.http_req_duration ? metrics.http_req_duration.values['p(95)'] : 0,
      p99: metrics.http_req_duration ? metrics.http_req_duration.values['p(99)'] : 0,
    },
    error_rate: metrics.errors ? metrics.errors.values.rate : 0,
    thresholds_passed: Object.values(data.thresholds || {}).every(t => t.ok),
  };

  return {
    'stdout': lines.join('\n'),
    'data/benchmarks/benchmark_readonly_results.json': JSON.stringify(summary, null, 2),
  };
}
