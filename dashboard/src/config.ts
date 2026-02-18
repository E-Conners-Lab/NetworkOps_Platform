/**
 * Centralized configuration for the dashboard.
 * Uses environment variables with fallbacks for development.
 */

// API base URL - used for all REST API calls
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

// WebSocket URL - used for Socket.IO connection
export const WS_URL = process.env.REACT_APP_WS_URL || API_BASE_URL;

// API endpoints
export const API = {
  // Base URL for dynamic endpoint construction
  base: API_BASE_URL,

  // Authentication
  authLogin: `${API_BASE_URL}/api/auth/login`,
  authMe: `${API_BASE_URL}/api/auth/me`,
  authVerify: `${API_BASE_URL}/api/auth/verify`,
  authUsers: `${API_BASE_URL}/api/auth/users`,
  authGroups: `${API_BASE_URL}/api/auth/groups`,
  authPermissions: `${API_BASE_URL}/api/auth/permissions`,
  authChangePassword: `${API_BASE_URL}/api/auth/change-password`,
  authUserByName: (username: string) => `${API_BASE_URL}/api/auth/users/${username}`,
  authReactivateUser: (username: string) => `${API_BASE_URL}/api/auth/users/${username}/reactivate`,

  // Core endpoints
  health: `${API_BASE_URL}/api/health`,
  topology: `${API_BASE_URL}/api/topology`,
  devices: `${API_BASE_URL}/api/devices`,
  netboxOptions: `${API_BASE_URL}/api/netbox/options`,

  // Hierarchy endpoints (requires ENABLE_HIERARCHICAL_VIEW=true on server)
  hierarchy: `${API_BASE_URL}/api/hierarchy`,
  topologyLevel: (type: string, id: string) => `${API_BASE_URL}/api/topology/level/${type}/${id}`,

  // Device operations
  command: `${API_BASE_URL}/api/command`,
  ping: `${API_BASE_URL}/api/ping`,
  pingSweep: `${API_BASE_URL}/api/ping-sweep`,
  remediate: `${API_BASE_URL}/api/remediate`,

  // Status endpoints
  bgpSummary: `${API_BASE_URL}/api/bgp-summary`,
  interfaceStats: `${API_BASE_URL}/api/interface-stats`,
  interfaceAcls: `${API_BASE_URL}/api/interface-acls`,
  dmvpnStatus: `${API_BASE_URL}/api/dmvpn-status`,
  switchStatus: `${API_BASE_URL}/api/switch-status`,
  ospfStatus: `${API_BASE_URL}/api/ospf-status`,
  events: `${API_BASE_URL}/api/events`,

  // Dynamic endpoints (require parameters)
  linuxHealth: (device: string) => `${API_BASE_URL}/api/linux-health/${device}`,
  containerlabHealth: (device: string) => `${API_BASE_URL}/api/containerlab-health/${device}`,
  interfaceDetail: (device: string, iface: string) => `${API_BASE_URL}/api/interface/${device}/${iface}`,

  // RAG endpoints
  chat: `${API_BASE_URL}/api/chat`,
  ingest: `${API_BASE_URL}/api/ingest`,
  ragStats: `${API_BASE_URL}/api/rag/stats`,

  // Telemetry
  telemetryStart: `${API_BASE_URL}/api/telemetry/start`,
  telemetryStop: `${API_BASE_URL}/api/telemetry/stop`,
  telemetryStats: `${API_BASE_URL}/api/telemetry/stats`,
  telemetryData: `${API_BASE_URL}/api/telemetry/data`,

  // MTU Calculator
  mtuCalculate: `${API_BASE_URL}/api/mtu/calculate`,
  mtuScenarios: `${API_BASE_URL}/api/mtu/scenarios`,

  // Provisioning
  provisionFeatures: `${API_BASE_URL}/api/provision/features`,
  provisionEveNgImages: `${API_BASE_URL}/api/provision/eve-ng/images`,
  provisionContainerlabImages: `${API_BASE_URL}/api/provision/containerlab/images`,
  provisionEveNg: `${API_BASE_URL}/api/provision/eve-ng`,
  provisionContainerlab: `${API_BASE_URL}/api/provision/containerlab`,
  provisionStatus: (jobId: string) => `${API_BASE_URL}/api/provision/status/${jobId}`,
  provisionCancel: (jobId: string) => `${API_BASE_URL}/api/provision/${jobId}/cancel`,
  deprovision: (deviceName: string) => `${API_BASE_URL}/api/provision/${deviceName}`,

  // Intent Drift Engine
  intentValidate: (device: string) => `${API_BASE_URL}/api/impact/intent/${device}`,
  intentValidateAll: `${API_BASE_URL}/api/impact/intent`,
  intentViolations: (device: string) => `${API_BASE_URL}/api/impact/intent/${device}/violations`,
  intentDefinitions: `${API_BASE_URL}/api/impact/intent/definitions`,
  graphBuild: `${API_BASE_URL}/api/impact/graph/build`,
  graphGet: `${API_BASE_URL}/api/impact/graph`,
  graphForward: (device: string) => `${API_BASE_URL}/api/impact/graph/forward/${device}`,
  graphBackward: (device: string) => `${API_BASE_URL}/api/impact/graph/backward/${device}`,
  graphBlastRadius: (device: string, iface: string) => `${API_BASE_URL}/api/impact/graph/blast-radius/${device}/${iface}`,
  impactEvents: `${API_BASE_URL}/api/impact/events`,
  driftWithImpact: (device: string) => `${API_BASE_URL}/api/impact/trending/${device}/drift-impact`,

  // Agent Operations
  agentStatus: `${API_BASE_URL}/api/agent/status`,
  agentDecisions: `${API_BASE_URL}/api/agent/decisions`,
  agentDecision: (id: string) => `${API_BASE_URL}/api/agent/decisions/${id}`,
  agentApprove: (id: string) => `${API_BASE_URL}/api/agent/decisions/${id}/approve`,
  agentReject: (id: string) => `${API_BASE_URL}/api/agent/decisions/${id}/reject`,
  agentAuditLog: `${API_BASE_URL}/api/agent/audit-log`,
  agentReports: `${API_BASE_URL}/api/agent/reports`,
  agentReport: (date: string) => `${API_BASE_URL}/api/agent/reports/${date}`,
  agentMetrics: `${API_BASE_URL}/api/agent/metrics`,
  agentEffectiveness: `${API_BASE_URL}/api/agent/effectiveness`,
  agentSSE: `${API_BASE_URL}/api/agent/events/stream`,
  agentEmergencyStop: `${API_BASE_URL}/api/agent/emergency-stop`,
  agentEmergencyResume: `${API_BASE_URL}/api/agent/emergency-resume`,
};
