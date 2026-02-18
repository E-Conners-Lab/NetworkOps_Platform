/**
 * Intent Drift Engine Component
 * Intent-based validation, dependency graph visualization,
 * impact analysis, and event tracking.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';
import './IntentDriftEngine.css';

// Types
interface DeviceInfo {
  name: string;
  host: string;
  platform: string;
}

interface Violation {
  device?: string;
  rule?: string;
  intent_type?: string;
  intent_key?: string;
  severity?: 'critical' | 'warning' | 'info';
  violation_severity?: string;
  description?: string;
  expected?: string;
  actual?: string;
  expected_state?: string;
  actual_state?: string;
  subsystem?: string;
  details?: Record<string, any>;
}

interface IntentCheck {
  intent_type: string;
  intent_key: string;
  expected_state: string;
  actual_state: string;
  passed: boolean;
  severity: string;
}

interface IntentValidation {
  device: string;
  status: string;
  total_violations: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
  violations: Violation[];
  checks?: IntentCheck[];
}

interface IntentDefinitionItem {
  key: string;
  expected_state: string;
  severity: string;
}

interface IntentDefinition {
  device: string;
  role: string;
  ospf_neighbors: IntentDefinitionItem[];
  bgp_peers: IntentDefinitionItem[];
  interfaces: IntentDefinitionItem[];
  routes: IntentDefinitionItem[];
}

interface GraphNode {
  id: string;
  type?: string;
  platform?: string;
  [key: string]: any;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship?: string;
  [key: string]: any;
}

interface GraphData {
  status: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
  device_count?: number;
}

interface AffectedDevice {
  device: string;
  type?: string;
  relationship?: string;
  depth?: number;
  [key: string]: any;
}

interface InterfaceInfo {
  name: string;
  status?: string;
}

interface ImpactFindings {
  risk_level: 'low' | 'medium' | 'high' | 'unknown';
  summary: string;
  findings: string[];
  warnings: string[];
}

interface EventItem {
  id?: string;
  timestamp: string;
  subsystem: string;
  severity: string;
  device: string;
  summary: string;
}

interface IntentDriftEngineProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedDevice?: string;
}

type TabType = 'validation' | 'graph' | 'impact' | 'events';
type AnalysisMode = 'forward' | 'backward' | 'blast-radius';

const SEVERITY_COLORS: Record<string, string> = {
  info: '#4a9eff',
  warning: '#eab308',
  critical: '#ef4444',
};

const NODE_COLORS: Record<string, string> = {
  router: '#4a9eff',
  containerlab: '#22c55e',
  interface: '#6b7280',
  switch: '#8b5cf6',
  default: '#888',
};

const IntentDriftEngine: React.FC<IntentDriftEngineProps> = ({
  isOpen,
  onClose,
  preselectedDevice,
}) => {
  const { getAuthHeaders } = useAuth();

  // Shared state
  const [device, setDevice] = useState(preselectedDevice || '');
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [activeTab, setActiveTab] = useState<TabType>('validation');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Validation tab state
  const [validation, setValidation] = useState<IntentValidation | null>(null);
  const [definitions, setDefinitions] = useState<IntentDefinition[] | null>(null);
  const [showDefinitions, setShowDefinitions] = useState(false);

  // Graph tab state
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const graphRef = useRef<any>(null);

  // Impact tab state
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>('forward');
  const [affectedDevices, setAffectedDevices] = useState<AffectedDevice[]>([]);
  const [impactFindings, setImpactFindings] = useState<ImpactFindings | null>(null);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');

  // Events tab state
  const [events, setEvents] = useState<EventItem[]>([]);
  const [eventSubsystem, setEventSubsystem] = useState('');
  const [eventSeverity, setEventSeverity] = useState('');
  const [eventDays, setEventDays] = useState('7');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const autoRefreshRef = useRef<NodeJS.Timeout | null>(null);

  // Fetch devices on open
  useEffect(() => {
    if (!isOpen) return;

    fetch(API.topology, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => {
        const allDevices = (data.nodes || []).map((d: any) => ({
          name: d.id,
          host: d.ip,
          platform: d.platform || '',
        }));
        setDevices(allDevices);
      })
      .catch(err => console.error('Failed to fetch devices:', err));
  }, [isOpen, getAuthHeaders]);

  // Reset when modal opens
  useEffect(() => {
    if (isOpen) {
      setError(null);
      setActiveTab('validation');
      if (preselectedDevice) setDevice(preselectedDevice);
    } else {
      // Clean up auto-refresh on close
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
        autoRefreshRef.current = null;
      }
    }
  }, [isOpen, preselectedDevice]);

  // Clear tab-specific results when device changes
  useEffect(() => {
    setValidation(null);
    setDefinitions(null);
    setAffectedDevices([]);
    setInterfaces([]);
    setSelectedInterface('');
    setError(null);
  }, [device]);

  // Fetch interfaces when device changes (for blast radius)
  useEffect(() => {
    if (!device) return;

    fetch(`${API.interfaceStats}?device=${encodeURIComponent(device)}`, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => {
        const ifaces = data.interfaces || data || [];
        const deviceInterfaces = (Array.isArray(ifaces) ? ifaces : [])
          .map((iface: any) => ({
            name: iface.interface || iface.name,
            status: iface.status,
          }));
        setInterfaces(deviceInterfaces);
      })
      .catch(() => setInterfaces([]));
  }, [device, getAuthHeaders]);

  // Auto-refresh events
  useEffect(() => {
    if (autoRefreshRef.current) {
      clearInterval(autoRefreshRef.current);
      autoRefreshRef.current = null;
    }

    if (autoRefresh && activeTab === 'events') {
      autoRefreshRef.current = setInterval(() => {
        fetchEvents();
      }, 30000);
    }

    return () => {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
    };
  }, [autoRefresh, activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // --- Validation Tab Actions ---

  const validateDevice = useCallback(async () => {
    if (!device) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(API.intentValidate(device), {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setError(errData.error || `Validation failed (${res.status})`);
        return;
      }
      const data = await res.json();
      if (data.status === 'no_intent') {
        setValidation({ ...data, violations: [], total_violations: 0, critical_count: 0, warning_count: 0, info_count: 0 });
      } else {
        setValidation({
          ...data,
          violations: data.violations || [],
          total_violations: data.total_violations || 0,
          critical_count: data.critical_count || 0,
          warning_count: data.warning_count || 0,
          info_count: data.info_count || 0,
        });
      }
    } catch (err) {
      setError('Failed to validate device intent');
    } finally {
      setLoading(false);
    }
  }, [device, getAuthHeaders]);

  const validateAll = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(API.intentValidateAll, {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setError(errData.error || `Validation failed (${res.status})`);
        return;
      }
      const data = await res.json();

      // Aggregate violations and checks from per-device results
      const allViolations: Violation[] = [];
      const allChecks: IntentCheck[] = [];
      let criticalCount = 0;
      let warningCount = 0;
      if (data.results) {
        for (const [dev, devResult] of Object.entries(data.results as Record<string, any>)) {
          const devViolations = devResult.violations || [];
          for (const v of devViolations) {
            allViolations.push({ ...v, device: dev });
          }
          const devChecks = devResult.checks || [];
          for (const c of devChecks) {
            allChecks.push({ ...c, intent_key: `${dev}: ${c.intent_key}` });
          }
          criticalCount += devResult.critical || 0;
          warningCount += devResult.warning || 0;
        }
      }

      setValidation({
        ...data,
        device: 'All Devices',
        violations: allViolations,
        checks: allChecks,
        total_violations: data.total_violations || allViolations.length,
        critical_count: criticalCount,
        warning_count: warningCount,
        info_count: 0,
      });
    } catch (err) {
      setError('Failed to validate all devices');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  const fetchDefinitions = useCallback(async () => {
    try {
      const res = await fetch(API.intentDefinitions, {
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      const defs = data.definitions || {};
      // Convert object { "R1": {...}, "R3": {...} } to array
      const defsArray: IntentDefinition[] = Object.values(defs);
      setDefinitions(defsArray);
    } catch (err) {
      console.error('Failed to fetch definitions:', err);
    }
  }, [getAuthHeaders]);

  // --- Graph Tab Actions ---

  const buildGraph = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // First try the backend graph build endpoint
      const res = await fetch(API.graphBuild, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
      });
      const data = await res.json();

      if (data.error || !res.ok) {
        // Backend graph engine not available — build from topology data
        await buildGraphFromTopology();
        return;
      }

      // Backend returned summary under data.graph — also build visual from topology
      await buildGraphFromTopology();
    } catch (err) {
      // Backend unavailable — fall back to topology
      await buildGraphFromTopology();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]); // eslint-disable-line react-hooks/exhaustive-deps

  const buildGraphFromTopology = useCallback(async () => {
    try {
      const res = await fetch(API.topology, { headers: getAuthHeaders() });
      const data = await res.json();

      const topoNodes: GraphNode[] = (data.nodes || []).map((n: any) => ({
        id: n.id,
        type: n.type || 'device',
        platform: n.platform || '',
      }));

      const topoEdges: GraphEdge[] = (data.links || []).map((l: any) => ({
        source: typeof l.source === 'object' ? l.source.id : l.source,
        target: typeof l.target === 'object' ? l.target.id : l.target,
        relationship: l.source_intf && l.target_intf
          ? `${l.source_intf} — ${l.target_intf}`
          : 'link',
      }));

      const deviceCount = new Set(topoNodes.map(n => n.id)).size;

      setGraphData({
        status: 'success',
        nodes: topoNodes,
        edges: topoEdges,
        node_count: topoNodes.length,
        edge_count: topoEdges.length,
        device_count: deviceCount,
      });
    } catch (err) {
      setError('Failed to build graph from topology');
    }
  }, [getAuthHeaders]);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(API.graphGet, { headers: getAuthHeaders() });
      const data = await res.json();

      if (data.error || !res.ok || data.status === 'not_built') {
        // No saved graph — try building from topology
        setGraphData(null);
      } else {
        // Backend returned summary only, build visual from topology
        await buildGraphFromTopology();
      }
    } catch (err) {
      // Backend unavailable — leave null so user can click Build
      setGraphData(null);
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders, buildGraphFromTopology]);

  // Load graph when tab opens
  useEffect(() => {
    if (activeTab === 'graph' && !graphData) {
      loadGraph();
    }
  }, [activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // --- Impact Tab Actions ---

  const analyzeImpact = useCallback(async () => {
    if (!device) return;
    setLoading(true);
    setError(null);
    setAffectedDevices([]);
    setImpactFindings(null);

    try {
      let url: string;
      if (analysisMode === 'forward') {
        url = API.graphForward(device);
      } else if (analysisMode === 'backward') {
        url = API.graphBackward(device);
      } else {
        if (!selectedInterface) {
          setError('Select an interface for blast radius analysis');
          setLoading(false);
          return;
        }
        url = API.graphBlastRadius(device, selectedInterface);
      }

      const res = await fetch(url, { headers: getAuthHeaders() });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setError(errData.error || errData.message || `Impact analysis failed (${res.status})`);
        return;
      }
      const data = await res.json();

      // API returns arrays of strings or objects — normalize to AffectedDevice[]
      const raw = data.affected || data.affected_devices || data.dependencies || data.devices || [];
      const normalized: AffectedDevice[] = raw.map((item: any) => {
        if (typeof item === 'string') {
          return { device: item };
        }
        return item;
      });

      // Enrich with classification data from the response
      if (data.direct_neighbors || data.direct_dependencies) {
        const directs = new Set(data.direct_neighbors || data.direct_dependencies || []);
        const bgp = new Set(data.bgp_affected || []);
        const ospf = new Set(data.ospf_affected || []);
        const physical = new Set(data.physical_affected || []);
        for (const d of normalized) {
          if (directs.has(d.device)) d.depth = 1;
          const rels: string[] = [];
          if (bgp.has(d.device)) rels.push('BGP');
          if (ospf.has(d.device)) rels.push('OSPF');
          if (physical.has(d.device)) rels.push('Physical');
          if (rels.length > 0) d.relationship = rels.join(', ');
        }
        // Sort: direct first, then alphabetical
        normalized.sort((a, b) => {
          if (a.depth === 1 && b.depth !== 1) return -1;
          if (b.depth === 1 && a.depth !== 1) return 1;
          return a.device.localeCompare(b.device);
        });
      }

      setAffectedDevices(normalized);
      setImpactFindings(data.findings || null);
    } catch (err) {
      setError('Failed to run impact analysis');
    } finally {
      setLoading(false);
    }
  }, [device, analysisMode, selectedInterface, getAuthHeaders]);

  // --- Events Tab Actions ---

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      if (device) params.set('device', device);
      if (eventSubsystem) params.set('subsystem', eventSubsystem);
      if (eventSeverity) params.set('severity', eventSeverity);
      params.set('days', eventDays);
      params.set('limit', '100');

      const res = await fetch(`${API.impactEvents}?${params.toString()}`, {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setError(errData.error || `Failed to fetch events (${res.status})`);
        return;
      }
      const data = await res.json();
      setEvents(data.events || (Array.isArray(data) ? data : []));
    } catch (err) {
      setError('Failed to fetch events');
    } finally {
      setLoading(false);
    }
  }, [device, eventSubsystem, eventSeverity, eventDays, getAuthHeaders]);

  // Fetch events when tab opens or filters change
  useEffect(() => {
    if (activeTab === 'events') {
      fetchEvents();
    }
  }, [activeTab, eventSubsystem, eventSeverity, eventDays]); // eslint-disable-line react-hooks/exhaustive-deps

  // --- Graph Helpers ---

  const getNodeColor = (node: GraphNode): string => {
    const platform = (node.platform || node.type || '').toLowerCase();
    if (platform.includes('c8000') || platform.includes('ios') || platform.includes('cat9') || platform.includes('csr')) {
      return NODE_COLORS.router;
    }
    if (platform.includes('frr') || platform.includes('srlinux') || platform.includes('containerlab')) {
      return NODE_COLORS.containerlab;
    }
    if (platform.includes('interface')) {
      return NODE_COLORS.interface;
    }
    if (platform.includes('switch')) {
      return NODE_COLORS.switch;
    }
    return NODE_COLORS.default;
  };

  const graphForceData = graphData ? {
    nodes: graphData.nodes.map(n => ({ ...n, color: getNodeColor(n) })),
    links: graphData.edges.map(e => ({
      source: e.source,
      target: e.target,
    })),
  } : null;

  // --- Format helpers ---

  const formatTimestamp = (ts: string): string => {
    try {
      const d = new Date(ts);
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return ts;
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="intent-drift-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Intent Drift Engine</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>

        <div className="modal-content">
          {/* Device Selector */}
          <div className="device-selector">
            <label>Device</label>
            <select
              value={device}
              onChange={e => setDevice(e.target.value)}
              disabled={loading}
            >
              <option value="">Select device...</option>
              {devices.map(d => (
                <option key={d.name} value={d.name}>{d.name}</option>
              ))}
            </select>
          </div>

          {/* Error Display */}
          {error && (
            <div className="intent-drift-error">{error}</div>
          )}

          {/* Tabs */}
          <div className="intent-drift-tabs">
            <button
              className={activeTab === 'validation' ? 'active' : ''}
              onClick={() => setActiveTab('validation')}
            >
              Intent Validation
            </button>
            <button
              className={activeTab === 'graph' ? 'active' : ''}
              onClick={() => setActiveTab('graph')}
            >
              Dependency Graph
            </button>
            <button
              className={activeTab === 'impact' ? 'active' : ''}
              onClick={() => setActiveTab('impact')}
            >
              Impact Analysis
            </button>
            <button
              className={activeTab === 'events' ? 'active' : ''}
              onClick={() => setActiveTab('events')}
            >
              Events
            </button>
          </div>

          {/* Tab Content */}
          <div className="intent-tab-content">

            {/* === Validation Tab === */}
            {activeTab === 'validation' && (
              <div>
                <div className="intent-action-row">
                  <button
                    className="intent-action-btn"
                    onClick={validateDevice}
                    disabled={loading || !device}
                    title={!device ? 'Select a device first' : ''}
                  >
                    {loading ? 'Validating...' : device ? `Validate ${device}` : 'Select a device'}
                  </button>
                  <button
                    className="intent-action-btn secondary"
                    onClick={validateAll}
                    disabled={loading}
                  >
                    {loading ? 'Validating...' : 'Validate All'}
                  </button>
                </div>

                {validation && validation.status === 'no_intent' && (
                  <div className="no-intent-message">
                    <strong>No intent definitions found for {validation.device || device}</strong>
                    <p>Define intent rules to start validating device configuration and state.</p>
                  </div>
                )}

                {validation && validation.status !== 'no_intent' && (
                  <>
                    <div className="intent-summary-grid">
                      <div className="intent-summary-card">
                        <span className={`card-value ${validation.total_violations > 0 ? 'critical' : ''}`}>
                          {validation.total_violations}
                        </span>
                        <span className="card-label">Total Violations</span>
                      </div>
                      <div className="intent-summary-card">
                        <span className={`card-value ${validation.critical_count > 0 ? 'critical' : ''}`}>
                          {validation.critical_count}
                        </span>
                        <span className="card-label">Critical</span>
                      </div>
                      <div className="intent-summary-card">
                        <span className={`card-value ${validation.warning_count > 0 ? 'warning' : ''}`}>
                          {validation.warning_count}
                        </span>
                        <span className="card-label">Warnings</span>
                      </div>
                    </div>

                    {validation.violations.length > 0 && (
                      <div className="violation-list">
                        {validation.violations.map((v, i) => {
                          const sev = v.severity || v.violation_severity || 'info';
                          const label = v.rule || v.intent_type || 'violation';
                          const desc = v.description || (v.intent_key ? `${v.intent_type}: ${v.intent_key}` : label);
                          const expected = v.expected || v.expected_state;
                          const actual = v.actual || v.actual_state;
                          return (
                          <div key={i} className={`violation-item ${sev}`}>
                            <div className="violation-header">
                              <span
                                className="severity-badge"
                                style={{ backgroundColor: SEVERITY_COLORS[sev] || '#888' }}
                              >
                                {sev.toUpperCase()}
                              </span>
                              {v.device && (
                                <span className="violation-device">{v.device}</span>
                              )}
                              <span className="violation-rule">{label}</span>
                              {v.intent_key && (
                                <span className="violation-rule">{v.intent_key}</span>
                              )}
                            </div>
                            <div className="violation-description">{desc}</div>
                            {(expected || actual) && (
                              <div className="violation-details">
                                {expected && (
                                  <span className="expected-val">Expected: {expected}</span>
                                )}
                                {actual && (
                                  <span className="actual-val">Actual: {actual}</span>
                                )}
                              </div>
                            )}
                          </div>
                          );
                        })}
                      </div>
                    )}

                    {validation.violations.length === 0 && (
                      <div className="no-intent-message" style={{ color: '#22c55e', borderColor: 'rgba(34, 197, 94, 0.2)', background: 'rgba(34, 197, 94, 0.05)' }}>
                        All intent checks passed. No violations detected.
                      </div>
                    )}

                    {validation.checks && validation.checks.length > 0 && (
                      <div className="checks-section">
                        <h4 className="checks-header">
                          Per-Item Checklist ({validation.checks.filter(c => c.passed).length}/{validation.checks.length} passed)
                        </h4>
                        <div className="checks-grid">
                          {(['ospf_neighbor', 'bgp_peer', 'interface', 'route'] as const).map(type => {
                            const typeChecks = validation.checks!.filter(c => c.intent_type === type);
                            if (typeChecks.length === 0) return null;
                            const typeLabel: Record<string, string> = {
                              ospf_neighbor: 'OSPF Neighbors',
                              bgp_peer: 'BGP Peers',
                              interface: 'Interfaces',
                              route: 'Routes',
                            };
                            return (
                              <div key={type} className="checks-group">
                                <div className="checks-group-label">{typeLabel[type]}</div>
                                {typeChecks.map((c, j) => (
                                  <div key={j} className={`check-item ${c.passed ? 'pass' : 'fail'}`}>
                                    <span className={`check-icon ${c.passed ? 'pass' : 'fail'}`}>
                                      {c.passed ? '\u2713' : '\u2717'}
                                    </span>
                                    <span className="check-key">{c.intent_key}</span>
                                    <span className="check-state">
                                      {c.actual_state}
                                    </span>
                                    {!c.passed && (
                                      <span className="check-expected">
                                        expected: {c.expected_state}
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </>
                )}

                {/* Definitions Section */}
                <div className="definitions-section">
                  <h3 onClick={() => {
                    setShowDefinitions(!showDefinitions);
                    if (!definitions) fetchDefinitions();
                  }}>
                    <span>{showDefinitions ? '▼' : '▶'}</span>
                    View Intent Definitions
                  </h3>
                  {showDefinitions && definitions && (
                    <div>
                      {definitions.length === 0 && (
                        <div className="intent-empty-state">No intent definitions configured.</div>
                      )}
                      {definitions.map((def, i) => {
                        const totalItems = (def.ospf_neighbors?.length || 0)
                          + (def.bgp_peers?.length || 0)
                          + (def.interfaces?.length || 0)
                          + (def.routes?.length || 0);
                        return (
                          <div key={i} className="definition-item">
                            <div className="def-name">{def.device} <span className="def-role">({def.role})</span></div>
                            <div className="def-description">
                              {def.ospf_neighbors?.length > 0 && <span className="def-tag">OSPF: {def.ospf_neighbors.length}</span>}
                              {def.bgp_peers?.length > 0 && <span className="def-tag">BGP: {def.bgp_peers.length}</span>}
                              {def.interfaces?.length > 0 && <span className="def-tag">Interfaces: {def.interfaces.length}</span>}
                              {def.routes?.length > 0 && <span className="def-tag">Routes: {def.routes.length}</span>}
                              {totalItems === 0 && <span className="def-tag">No items defined</span>}
                            </div>
                            {def.ospf_neighbors?.map((item, j) => (
                              <div key={`ospf-${j}`} className="def-rule">OSPF neighbor {item.key} — expected: {item.expected_state} ({item.severity})</div>
                            ))}
                            {def.bgp_peers?.map((item, j) => (
                              <div key={`bgp-${j}`} className="def-rule">BGP peer {item.key} — expected: {item.expected_state} ({item.severity})</div>
                            ))}
                            {def.interfaces?.map((item, j) => (
                              <div key={`iface-${j}`} className="def-rule">Interface {item.key} — expected: {item.expected_state} ({item.severity})</div>
                            ))}
                            {def.routes?.map((item, j) => (
                              <div key={`route-${j}`} className="def-rule">Route {item.key} — expected via: {item.expected_state} ({item.severity})</div>
                            ))}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {!device && !validation && (
                  <div className="intent-no-device">
                    Select a device to validate, or use "Validate All" to check all devices.
                  </div>
                )}
              </div>
            )}

            {/* === Graph Tab === */}
            {activeTab === 'graph' && (
              <div>
                <div className="intent-action-row">
                  <button
                    className="intent-action-btn"
                    onClick={buildGraph}
                    disabled={loading}
                  >
                    {loading ? 'Building...' : 'Build Graph'}
                  </button>
                  <button
                    className="intent-action-btn secondary"
                    onClick={loadGraph}
                    disabled={loading}
                  >
                    Reload Graph
                  </button>
                </div>

                {graphData ? (
                  <>
                    <div className="graph-stats-bar">
                      <span className="graph-stat">
                        <strong>{graphData.node_count}</strong> Nodes
                      </span>
                      <span className="graph-stat">
                        <strong>{graphData.edge_count}</strong> Edges
                      </span>
                      {graphData.device_count !== undefined && (
                        <span className="graph-stat">
                          <strong>{graphData.device_count}</strong> Devices
                        </span>
                      )}
                    </div>

                    <div className="graph-container">
                      {graphForceData && (
                        <ForceGraph2D
                          ref={graphRef}
                          graphData={graphForceData}
                          width={856}
                          height={400}
                          backgroundColor="#0d0d1a"
                          nodeLabel="id"
                          nodeColor={(node: any) => node.color || '#888'}
                          nodeRelSize={6}
                          linkColor={() => '#2d2d44'}
                          linkWidth={1.5}
                          onNodeClick={(node: any) => {
                            if (node.id) setDevice(node.id);
                          }}
                        />
                      )}
                    </div>

                    <div className="graph-legend">
                      <span className="legend-item">
                        <span className="legend-dot" style={{ background: NODE_COLORS.router }} />
                        Routers
                      </span>
                      <span className="legend-item">
                        <span className="legend-dot" style={{ background: NODE_COLORS.containerlab }} />
                        Containerlab
                      </span>
                      <span className="legend-item">
                        <span className="legend-dot" style={{ background: NODE_COLORS.interface }} />
                        Interfaces
                      </span>
                    </div>
                  </>
                ) : (
                  !loading && (
                    <div className="graph-not-built">
                      <h3>Graph Not Built</h3>
                      <p>Build the dependency graph to visualize device relationships.</p>
                    </div>
                  )
                )}

                {loading && !graphData && (
                  <div className="intent-loading-state">Building dependency graph...</div>
                )}
              </div>
            )}

            {/* === Impact Analysis Tab === */}
            {activeTab === 'impact' && (
              <div>
                {!device ? (
                  <div className="intent-no-device">
                    Select a device to analyze impact.
                  </div>
                ) : (
                  <>
                    <div className="analysis-mode-selector">
                      <button
                        className={analysisMode === 'forward' ? 'active' : ''}
                        onClick={() => { setAnalysisMode('forward'); setAffectedDevices([]); setImpactFindings(null); }}
                      >
                        Forward
                      </button>
                      <button
                        className={analysisMode === 'backward' ? 'active' : ''}
                        onClick={() => { setAnalysisMode('backward'); setAffectedDevices([]); setImpactFindings(null); }}
                      >
                        Backward
                      </button>
                      <button
                        className={analysisMode === 'blast-radius' ? 'active' : ''}
                        onClick={() => { setAnalysisMode('blast-radius'); setAffectedDevices([]); setImpactFindings(null); }}
                      >
                        Blast Radius
                      </button>
                    </div>

                    {analysisMode === 'blast-radius' && (
                      <div className="interface-selector">
                        <label>Interface</label>
                        <select
                          value={selectedInterface}
                          onChange={e => setSelectedInterface(e.target.value)}
                        >
                          <option value="">Select interface...</option>
                          {interfaces.map(iface => (
                            <option key={iface.name} value={iface.name}>{iface.name}</option>
                          ))}
                        </select>
                      </div>
                    )}

                    <div className="intent-action-row">
                      <button
                        className="intent-action-btn"
                        onClick={analyzeImpact}
                        disabled={loading || (analysisMode === 'blast-radius' && !selectedInterface)}
                      >
                        {loading ? 'Analyzing...' : `Analyze ${analysisMode === 'forward' ? 'Forward Impact' : analysisMode === 'backward' ? 'Dependencies' : 'Blast Radius'}`}
                      </button>
                    </div>

                    {affectedDevices.length > 0 && (
                      <>
                        {impactFindings && (
                          <div className={`impact-findings risk-${impactFindings.risk_level}`}>
                            <div className="findings-header">
                              <span className={`risk-badge ${impactFindings.risk_level}`}>
                                {impactFindings.risk_level.toUpperCase()} RISK
                              </span>
                              <span className="findings-summary">{impactFindings.summary}</span>
                            </div>
                            {impactFindings.findings.length > 0 && (
                              <ul className="findings-list">
                                {impactFindings.findings.map((f, i) => (
                                  <li key={i}>{f}</li>
                                ))}
                              </ul>
                            )}
                            {impactFindings.warnings.length > 0 && (
                              <div className="findings-warnings">
                                {impactFindings.warnings.map((w, i) => (
                                  <div key={i} className="finding-warning">
                                    <span className="warning-icon">!</span> {w}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        <div className="affected-count">
                          <strong>{affectedDevices.length}</strong> {analysisMode === 'backward' ? 'dependencies' : 'affected devices'} found
                        </div>
                        <div className="affected-devices">
                          {affectedDevices.map((d, i) => (
                            <div key={i} className="affected-device-card">
                              <div>
                                <div className="device-name">{d.device}</div>
                                {d.relationship && (
                                  <div className="device-detail">{d.relationship}</div>
                                )}
                                {d.depth !== undefined && (
                                  <div className="device-detail">Depth: {d.depth}</div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    {affectedDevices.length === 0 && !loading && analysisMode && (
                      <div className="intent-empty-state">
                        Run an analysis to see {analysisMode === 'backward' ? 'dependencies' : 'affected devices'}.
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* === Events Tab === */}
            {activeTab === 'events' && (
              <div>
                <div className="events-filter-bar">
                  <div className="filter-group">
                    <label>Subsystem</label>
                    <select
                      value={eventSubsystem}
                      onChange={e => setEventSubsystem(e.target.value)}
                    >
                      <option value="">All</option>
                      <option value="drift">Drift</option>
                      <option value="intent">Intent</option>
                      <option value="compliance">Compliance</option>
                      <option value="traffic">Traffic</option>
                    </select>
                  </div>
                  <div className="filter-group">
                    <label>Severity</label>
                    <select
                      value={eventSeverity}
                      onChange={e => setEventSeverity(e.target.value)}
                    >
                      <option value="">All</option>
                      <option value="critical">Critical</option>
                      <option value="warning">Warning</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div className="filter-group">
                    <label>Days</label>
                    <select
                      value={eventDays}
                      onChange={e => setEventDays(e.target.value)}
                    >
                      <option value="7">7 days</option>
                      <option value="14">14 days</option>
                      <option value="30">30 days</option>
                    </select>
                  </div>
                  <div className="auto-refresh-toggle">
                    <label>
                      <input
                        type="checkbox"
                        checked={autoRefresh}
                        onChange={e => setAutoRefresh(e.target.checked)}
                      />
                      Auto-refresh
                    </label>
                  </div>
                </div>

                {events.length > 0 ? (
                  <div className="event-list">
                    {events.map((evt, i) => (
                      <div key={evt.id || i} className="event-item">
                        <span className="event-timestamp">{formatTimestamp(evt.timestamp)}</span>
                        <span className={`subsystem-badge ${evt.subsystem}`}>{evt.subsystem}</span>
                        <span
                          className="event-severity"
                          style={{ backgroundColor: SEVERITY_COLORS[evt.severity] || '#888' }}
                        >
                          {evt.severity.toUpperCase()}
                        </span>
                        <span className="event-device">{evt.device}</span>
                        <span className="event-summary">{evt.summary}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  !loading && (
                    <div className="intent-empty-state">
                      No events found for the selected filters.
                    </div>
                  )
                )}

                {loading && (
                  <div className="intent-loading-state">Loading events...</div>
                )}
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};

export default IntentDriftEngine;
