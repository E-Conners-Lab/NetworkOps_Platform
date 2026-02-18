/**
 * NetworkOps API Benchmark Suite
 * k6 load testing script for comprehensive API performance testing
 *
 * Install k6: brew install k6
 *
 * Usage:
 *   # Quick smoke test (10 users, 30s)
 *   k6 run scripts/k6_benchmark.js
 *
 *   # Load test (50 users, 5 minutes)
 *   k6 run --vus 50 --duration 5m scripts/k6_benchmark.js
 *
 *   # Stress test (ramping to 200 users)
 *   k6 run --config scripts/k6_stress.json scripts/k6_benchmark.js
 *
 *   # With HTML report
 *   k6 run --out json=results.json scripts/k6_benchmark.js
 *   # Then: npx k6-reporter results.json
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const authDuration = new Trend('auth_duration');
const healthCheckDuration = new Trend('health_check_duration');
const topologyDuration = new Trend('topology_duration');
const commandDuration = new Trend('command_duration');
const metricsEndpointDuration = new Trend('metrics_endpoint_duration');
const successfulRequests = new Counter('successful_requests');

// Configuration
const BASE_URL = __ENV.API_URL || 'http://localhost:5001';
const USERNAME = __ENV.API_USER || 'admin';
const PASSWORD = __ENV.API_PASS || 'admin';

// Test options - only applied if no external config provided
// Use: k6 run --config scripts/k6_stress.json scripts/k6_benchmark.js
// to override with external config
export const options = {
  // Thresholds (can be overridden by config file)
  thresholds: {
    http_req_duration: ['p(95)<2000', 'p(99)<5000'],
    errors: ['rate<0.1'],
    auth_duration: ['p(95)<1000'],
    health_check_duration: ['p(95)<3000'],
    topology_duration: ['p(95)<2000'],
    command_duration: ['p(95)<5000'],
  },
};

// Stress test scenario (use with --config)
export const stressOptions = {
  scenarios: {
    stress: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 50 },   // Ramp up to 50 users
        { duration: '3m', target: 50 },   // Hold at 50
        { duration: '1m', target: 100 },  // Ramp to 100
        { duration: '3m', target: 100 },  // Hold at 100
        { duration: '1m', target: 200 },  // Ramp to 200
        { duration: '2m', target: 200 },  // Hold at 200
        { duration: '2m', target: 0 },    // Ramp down
      ],
      gracefulStop: '30s',
    },
  },
};

// Setup - runs once before all VUs
export function setup() {
  console.log(`Testing API at: ${BASE_URL}`);

  // Verify API is reachable
  const healthRes = http.get(`${BASE_URL}/healthz`);
  if (healthRes.status !== 200) {
    throw new Error(`API not reachable: ${healthRes.status}`);
  }

  // Get auth token for authenticated tests
  const loginRes = http.post(`${BASE_URL}/api/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (loginRes.status !== 200) {
    console.warn(`Login failed: ${loginRes.status} - some tests will be skipped`);
    return { token: null };
  }

  const token = JSON.parse(loginRes.body).access_token;
  console.log('Authentication successful');
  return { token };
}

// Main test function - runs for each VU
export default function(data) {
  const authHeaders = data.token ? {
    'Authorization': `Bearer ${data.token}`,
    'Content-Type': 'application/json',
  } : {
    'Content-Type': 'application/json',
  };

  // Group 1: Public endpoints (no auth required)
  group('Public Endpoints', function() {
    // Health check
    let res = http.get(`${BASE_URL}/healthz`);
    check(res, {
      'health check status 200': (r) => r.status === 200,
      'health check has status': (r) => JSON.parse(r.body).status !== undefined,
    }) || errorRate.add(1);
    successfulRequests.add(res.status === 200 ? 1 : 0);

    // Readiness probe
    res = http.get(`${BASE_URL}/readyz`);
    check(res, {
      'readyz status 200': (r) => r.status === 200,
    }) || errorRate.add(1);

    // Prometheus metrics endpoint
    const metricsStart = Date.now();
    res = http.get(`${BASE_URL}/metrics`);
    metricsEndpointDuration.add(Date.now() - metricsStart);
    check(res, {
      'metrics status 200': (r) => r.status === 200,
      'metrics has content': (r) => r.body.includes('networkops_'),
    }) || errorRate.add(1);

    // Device metrics endpoint
    res = http.get(`${BASE_URL}/metrics/devices`);
    check(res, {
      'device metrics status 200': (r) => r.status === 200,
      'device metrics has devices': (r) => r.body.includes('network_device_up'),
    }) || errorRate.add(1);
  });

  sleep(0.5);

  // Group 2: Authentication endpoints
  group('Authentication', function() {
    const authStart = Date.now();

    // Login (creates new token each time - simulates new user)
    let res = http.post(`${BASE_URL}/api/auth/login`,
      JSON.stringify({ username: USERNAME, password: PASSWORD }),
      { headers: { 'Content-Type': 'application/json' } }
    );
    authDuration.add(Date.now() - authStart);

    const loginSuccess = check(res, {
      'login status 200': (r) => r.status === 200,
      'login has access_token': (r) => {
        try { return JSON.parse(r.body).access_token !== undefined; }
        catch { return false; }
      },
      'login has refresh_token': (r) => {
        try { return JSON.parse(r.body).refresh_token !== undefined; }
        catch { return false; }
      },
    });

    if (!loginSuccess) {
      errorRate.add(1);
      // Check if rate limited
      if (res.status === 429) {
        console.log('Rate limited on login - backing off');
        sleep(5);
      }
    } else {
      successfulRequests.add(1);
    }
  });

  sleep(0.5);

  // Skip authenticated tests if no token
  if (!data.token) {
    return;
  }

  // Group 3: Topology & Device endpoints
  group('Topology & Devices', function() {
    // Get topology
    const topoStart = Date.now();
    let res = http.get(`${BASE_URL}/api/topology`, { headers: authHeaders });
    topologyDuration.add(Date.now() - topoStart);

    check(res, {
      'topology status 200': (r) => r.status === 200,
      'topology has nodes': (r) => {
        try { return JSON.parse(r.body).nodes !== undefined; }
        catch { return false; }
      },
      'topology has links': (r) => {
        try { return JSON.parse(r.body).links !== undefined; }
        catch { return false; }
      },
    }) || errorRate.add(1);
    successfulRequests.add(res.status === 200 ? 1 : 0);

    // Get devices
    res = http.get(`${BASE_URL}/api/devices`, { headers: authHeaders });
    check(res, {
      'devices status 200': (r) => r.status === 200,
      'devices is array': (r) => {
        try { return Array.isArray(JSON.parse(r.body)); }
        catch { return false; }
      },
    }) || errorRate.add(1);
  });

  sleep(0.5);

  // Group 4: Health check endpoints
  group('Health Checks', function() {
    const healthStart = Date.now();

    // Single device health (cached, should be fast)
    let res = http.get(`${BASE_URL}/api/health/R1`, { headers: authHeaders });
    healthCheckDuration.add(Date.now() - healthStart);

    check(res, {
      'R1 health status 200': (r) => r.status === 200,
    }) || errorRate.add(1);
    successfulRequests.add(res.status === 200 ? 1 : 0);

    // Linux health check
    res = http.get(`${BASE_URL}/api/linux-health/Alpine-1`, { headers: authHeaders });
    check(res, {
      'Alpine-1 health status 200': (r) => r.status === 200,
    }) || errorRate.add(1);
  });

  sleep(0.5);

  // Group 5: Command execution (rate limited)
  group('Command Execution', function() {
    const cmdStart = Date.now();

    // Execute show command
    let res = http.post(`${BASE_URL}/api/command`,
      JSON.stringify({
        device: 'R1',
        command: 'show clock'
      }),
      { headers: authHeaders }
    );
    commandDuration.add(Date.now() - cmdStart);

    const cmdSuccess = check(res, {
      'command status 200': (r) => r.status === 200,
      'command has output': (r) => {
        try { return JSON.parse(r.body).output !== undefined; }
        catch { return false; }
      },
    });

    if (!cmdSuccess) {
      errorRate.add(1);
      if (res.status === 429) {
        console.log('Rate limited on command - backing off');
        sleep(2);
      }
    } else {
      successfulRequests.add(1);
    }
  });

  sleep(0.5);

  // Group 6: Telemetry & Events
  group('Telemetry & Events', function() {
    // Get telemetry data
    let res = http.get(`${BASE_URL}/api/telemetry/data`, { headers: authHeaders });
    check(res, {
      'telemetry status 200': (r) => r.status === 200,
    }) || errorRate.add(1);

    // Get interface stats
    res = http.get(`${BASE_URL}/api/interface-stats`, { headers: authHeaders });
    check(res, {
      'interface stats status 200': (r) => r.status === 200,
    }) || errorRate.add(1);

    // Get event log
    res = http.get(`${BASE_URL}/api/events?limit=10`, { headers: authHeaders });
    check(res, {
      'events status 200': (r) => r.status === 200,
      'events is array': (r) => {
        try { return Array.isArray(JSON.parse(r.body)); }
        catch { return false; }
      },
    }) || errorRate.add(1);
  });

  sleep(1);
}

// Teardown - runs once after all VUs complete
export function teardown(data) {
  console.log('Benchmark complete');

  // Log out if we have a token
  if (data.token) {
    http.post(`${BASE_URL}/api/auth/logout`, null, {
      headers: { 'Authorization': `Bearer ${data.token}` }
    });
  }
}

// Handle test summary
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    duration: data.state.testRunDurationMs,
    vus: data.metrics.vus ? data.metrics.vus.values.max : 0,
    requests: {
      total: data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 0,
      rate: data.metrics.http_reqs ? data.metrics.http_reqs.values.rate : 0,
    },
    response_time: {
      avg: data.metrics.http_req_duration ? data.metrics.http_req_duration.values.avg : 0,
      p95: data.metrics.http_req_duration ? data.metrics.http_req_duration.values['p(95)'] : 0,
      p99: data.metrics.http_req_duration ? data.metrics.http_req_duration.values['p(99)'] : 0,
    },
    errors: data.metrics.errors ? data.metrics.errors.values.rate : 0,
    thresholds: data.thresholds,
  };

  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
    'data/benchmarks/benchmark_results.json': JSON.stringify(summary, null, 2),
  };
}

// Text summary helper
function textSummary(data, options) {
  const lines = [];
  lines.push('\n========================================');
  lines.push('  NetworkOps API Benchmark Results');
  lines.push('========================================\n');

  const metrics = data.metrics || {};

  if (metrics.http_reqs && metrics.http_reqs.values) {
    lines.push(`  Total Requests:     ${metrics.http_reqs.values.count || 0}`);
    lines.push(`  Request Rate:       ${(metrics.http_reqs.values.rate || 0).toFixed(2)}/s`);
  }

  if (metrics.http_req_duration && metrics.http_req_duration.values) {
    const dur = metrics.http_req_duration.values;
    lines.push(`  Avg Response Time:  ${(dur.avg || 0).toFixed(2)}ms`);
    lines.push(`  P95 Response Time:  ${(dur['p(95)'] || 0).toFixed(2)}ms`);
    lines.push(`  P99 Response Time:  ${(dur['p(99)'] || 0).toFixed(2)}ms`);
  }

  if (metrics.errors && metrics.errors.values) {
    lines.push(`  Error Rate:         ${((metrics.errors.values.rate || 0) * 100).toFixed(2)}%`);
  }

  if (metrics.successful_requests && metrics.successful_requests.values) {
    lines.push(`  Successful Reqs:    ${metrics.successful_requests.values.count || 0}`);
  }

  lines.push('\n  Custom Metrics:');
  if (metrics.auth_duration && metrics.auth_duration.values) {
    lines.push(`    Auth P95:         ${(metrics.auth_duration.values['p(95)'] || 0).toFixed(2)}ms`);
  }
  if (metrics.health_check_duration && metrics.health_check_duration.values) {
    lines.push(`    Health Check P95: ${(metrics.health_check_duration.values['p(95)'] || 0).toFixed(2)}ms`);
  }
  if (metrics.topology_duration && metrics.topology_duration.values) {
    lines.push(`    Topology P95:     ${(metrics.topology_duration.values['p(95)'] || 0).toFixed(2)}ms`);
  }
  if (metrics.command_duration && metrics.command_duration.values) {
    lines.push(`    Command P95:      ${(metrics.command_duration.values['p(95)'] || 0).toFixed(2)}ms`);
  }

  lines.push('\n  Threshold Results:');
  for (const [name, result] of Object.entries(data.thresholds || {})) {
    const status = result.ok ? '✓ PASS' : '✗ FAIL';
    lines.push(`    ${status}: ${name}`);
  }

  lines.push('\n========================================\n');

  return lines.join('\n');
}
