/**
 * Impact Analysis Modal
 * Pre-change impact analysis for interface shutdown commands
 */

import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';
import './ImpactAnalysis.css';

interface OSPFAdjacency {
  neighbor_ip: string;
  neighbor_router_id: string;
  neighbor_device: string | null;
  area: string;
}

interface BGPPeer {
  peer_ip: string;
  peer_asn: number;
  peer_device: string | null;
}

interface AffectedRoute {
  prefix: string;
  type: string;
  alternate_exists: boolean;
}

interface ImpactResult {
  status: string;
  analysis_id: string;
  device: string;
  interface: string;
  command: string;
  risk_category: 'NO_IMPACT' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  current_state: {
    interface_status: string;
    ip_address: string | null;
  };
  impact: {
    ospf_adjacencies_lost: OSPFAdjacency[];
    bgp_peers_lost: BGPPeer[];
    routes_removed: AffectedRoute[];
    summary: {
      adjacencies_affected: number;
      routes_affected: number;
      routes_with_alternate: number;
      routes_without_alternate: number;
    };
  };
  data_quality: {
    overall_confidence: string;
    worst_data_age_sec: number;
  };
  warnings: string[];
  analysis_duration_ms: number;
  reason?: string;
  suggestion?: string;
}

interface DeviceInfo {
  name: string;
  host: string;
  platform: string;
}

interface ImpactAnalysisProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedDevice?: string;
  preselectedInterface?: string;
}

const RISK_COLORS: Record<string, string> = {
  'NO_IMPACT': '#6b7280',
  'LOW': '#22c55e',
  'MEDIUM': '#eab308',
  'HIGH': '#f97316',
  'CRITICAL': '#ef4444',
};

const ImpactAnalysis: React.FC<ImpactAnalysisProps> = ({
  isOpen,
  onClose,
  preselectedDevice,
  preselectedInterface,
}) => {
  const { getAuthHeaders } = useAuth();

  // Form state
  const [device, setDevice] = useState(preselectedDevice || '');
  const [interfaceName, setInterfaceName] = useState(preselectedInterface || '');
  const [command] = useState('shutdown');

  // Data state
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [result, setResult] = useState<ImpactResult | null>(null);
  const [featureEnabled, setFeatureEnabled] = useState<boolean | null>(null);

  // UI state
  const [loading, setLoading] = useState(false);
  const [loadingInterfaces, setLoadingInterfaces] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check feature status
  useEffect(() => {
    if (!isOpen) return;

    fetch(`${API.base}/api/impact/status`, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => setFeatureEnabled(data.enabled))
      .catch(() => setFeatureEnabled(false));
  }, [isOpen, getAuthHeaders]);

  // Fetch devices on open (use topology endpoint for full device info)
  useEffect(() => {
    if (!isOpen) return;

    fetch(`${API.base}/api/topology`, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => {
        // Filter to supported platforms (Phase 3: Cisco IOS-XE, FRR, Nokia SR Linux)
        // Platform values: C8000V, Cat9kv, FRRouting, Nokia SR Linux, etc.
        const supportedDevices = (data.nodes || [])
          .filter((d: any) => {
            const platform = (d.platform || '').toLowerCase();
            // Cisco IOS-XE platforms
            const isCisco = platform.includes('c8000') ||
                           platform.includes('cat9') ||
                           platform.includes('csr') ||
                           platform.includes('ios');
            // FRR platforms (containerlab) - platform value is "FRRouting"
            const isFRR = platform.includes('frr');
            // Nokia SR Linux platforms
            const isSRLinux = platform.includes('srlinux') ||
                             platform.includes('sr linux') ||
                             platform.includes('nokia');
            return isCisco || isFRR || isSRLinux;
          })
          .map((d: any) => ({
            name: d.id,
            host: d.ip,
            platform: d.platform
          }));
        setDevices(supportedDevices);
      })
      .catch(err => console.error('Failed to fetch devices:', err));
  }, [isOpen, getAuthHeaders]);

  // Fetch interfaces when device changes
  useEffect(() => {
    if (!device) {
      setInterfaces([]);
      return;
    }

    setLoadingInterfaces(true);
    fetch(`${API.base}/api/interface-stats?device=${device}`, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => {
        // Extract interface names, filter out management/logical interfaces
        const interfaceList = (data.interfaces || [])
          .map((i: any) => i.name || i.interface)
          .filter((name: string) =>
            name &&
            !name.toLowerCase().includes('vlan') &&
            !name.toLowerCase().includes('loopback') &&
            !name.toLowerCase().includes('tunnel') &&
            !name.toLowerCase().includes('null') &&
            !name.toLowerCase().includes('nve') &&
            !name.toLowerCase().includes('port-channel')
          );
        setInterfaces(interfaceList);
      })
      .catch(err => {
        console.error('Failed to fetch interfaces:', err);
        setInterfaces([]);
      })
      .finally(() => setLoadingInterfaces(false));
  }, [device, getAuthHeaders]);

  // Reset when modal opens
  useEffect(() => {
    if (isOpen) {
      setResult(null);
      setError(null);
      if (preselectedDevice) setDevice(preselectedDevice);
      if (preselectedInterface) setInterfaceName(preselectedInterface);
    }
  }, [isOpen, preselectedDevice, preselectedInterface]);

  const runAnalysis = useCallback(async () => {
    if (!device || !interfaceName) {
      setError('Please select a device and interface');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${API.base}/api/impact/analyze`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          device,
          interface: interfaceName,
          command,
          refresh_data: true,
        }),
      });

      const data = await response.json();

      if (data.status === 'error' || data.status === 'unsupported') {
        setError(data.reason || 'Analysis failed');
      } else {
        setResult(data);
      }
    } catch (err) {
      setError('Failed to run impact analysis');
      console.error('Impact analysis error:', err);
    } finally {
      setLoading(false);
    }
  }, [device, interfaceName, command, getAuthHeaders]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="impact-analysis-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Impact Analysis</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>

        <div className="modal-content">
          {featureEnabled === false && (
            <div className="feature-disabled-warning">
              Impact Analysis is disabled. Enable it in feature_flags.yaml or set FF_IMPACT_ANALYSIS_ENABLED=true
            </div>
          )}

          {/* Input Form */}
          <div className="impact-form">
            <div className="form-row">
              <div className="form-group">
                <label>Device</label>
                <select
                  value={device}
                  onChange={e => {
                    setDevice(e.target.value);
                    setInterfaceName('');
                    setResult(null);
                  }}
                  disabled={loading}
                >
                  <option value="">Select device...</option>
                  {devices.map(d => (
                    <option key={d.name} value={d.name}>{d.name}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Interface</label>
                <select
                  value={interfaceName}
                  onChange={e => {
                    setInterfaceName(e.target.value);
                    setResult(null);
                  }}
                  disabled={loading || loadingInterfaces || !device}
                >
                  <option value="">
                    {loadingInterfaces ? 'Loading...' : 'Select interface...'}
                  </option>
                  {interfaces.map(iface => (
                    <option key={iface} value={iface}>{iface}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Command</label>
                <input
                  type="text"
                  value={command}
                  disabled
                  className="command-input"
                />
              </div>
            </div>

            <button
              className="analyze-button"
              onClick={runAnalysis}
              disabled={loading || !device || !interfaceName || featureEnabled === false}
            >
              {loading ? 'Analyzing...' : 'Analyze Impact'}
            </button>
          </div>

          {/* Error Display */}
          {error && (
            <div className="impact-error">
              {error}
            </div>
          )}

          {/* Results Display */}
          {result && result.status === 'completed' && (
            <div className="impact-results">
              {/* Risk Badge */}
              <div
                className="risk-badge"
                style={{ backgroundColor: RISK_COLORS[result.risk_category] }}
              >
                {result.risk_category} RISK
              </div>

              {/* Current State */}
              <div className="result-section">
                <h3>Current State</h3>
                <div className="state-info">
                  <span className={`status-dot ${result.current_state.interface_status}`}></span>
                  <strong>{result.interface}</strong> is {result.current_state.interface_status}
                  {result.current_state.ip_address && (
                    <span className="ip-address">({result.current_state.ip_address})</span>
                  )}
                </div>
              </div>

              {/* Impact Summary */}
              <div className="result-section">
                <h3>Impact Summary</h3>
                <div className="impact-summary-grid">
                  <div className="summary-item">
                    <span className="summary-value">{result.impact.summary.adjacencies_affected}</span>
                    <span className="summary-label">Adjacencies Lost</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-value">{result.impact.summary.routes_affected}</span>
                    <span className="summary-label">Routes Removed</span>
                  </div>
                  <div className="summary-item warning">
                    <span className="summary-value">{result.impact.summary.routes_without_alternate}</span>
                    <span className="summary-label">No Alternate Path</span>
                  </div>
                </div>
              </div>

              {/* OSPF Adjacencies */}
              {result.impact.ospf_adjacencies_lost.length > 0 && (
                <div className="result-section">
                  <h3>OSPF Adjacencies Lost</h3>
                  <ul className="impact-list">
                    {result.impact.ospf_adjacencies_lost.map((adj, i) => (
                      <li key={i}>
                        <strong>{adj.neighbor_router_id}</strong>
                        {adj.neighbor_device && ` (${adj.neighbor_device})`}
                        <span className="detail"> via {adj.neighbor_ip}, Area {adj.area}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* BGP Peers */}
              {result.impact.bgp_peers_lost.length > 0 && (
                <div className="result-section">
                  <h3>BGP Peers Lost</h3>
                  <ul className="impact-list">
                    {result.impact.bgp_peers_lost.map((peer, i) => (
                      <li key={i}>
                        <strong>AS {peer.peer_asn}</strong>
                        {peer.peer_device && ` (${peer.peer_device})`}
                        <span className="detail"> - {peer.peer_ip}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Routes Removed */}
              {result.impact.routes_removed.length > 0 && (
                <div className="result-section">
                  <h3>Routes Removed</h3>
                  <ul className="impact-list routes">
                    {result.impact.routes_removed.map((route, i) => (
                      <li key={i} className={route.alternate_exists ? '' : 'no-alternate'}>
                        <span className="route-prefix">{route.prefix}</span>
                        <span className="route-type">{route.type}</span>
                        {!route.alternate_exists && (
                          <span className="no-alt-badge">NO ALTERNATE</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Warnings */}
              {result.warnings.length > 0 && (
                <div className="result-section warnings">
                  <h3>Warnings</h3>
                  <ul className="warning-list">
                    {result.warnings.map((warning, i) => (
                      <li key={i}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Metadata */}
              <div className="result-meta">
                Analysis completed in {result.analysis_duration_ms}ms
                <span className="confidence">Confidence: {result.data_quality.overall_confidence}</span>
              </div>
            </div>
          )}

          {/* No Impact Result */}
          {result && result.status === 'no_impact' && (
            <div className="impact-results no-impact">
              <div className="risk-badge" style={{ backgroundColor: RISK_COLORS['NO_IMPACT'] }}>
                NO IMPACT
              </div>
              <p>Shutting down this interface would have no detected impact on routing or adjacencies.</p>
            </div>
          )}

          {/* Insufficient Data */}
          {result && result.status === 'insufficient_data' && (
            <div className="impact-results insufficient">
              <div className="insufficient-message">
                <h3>Insufficient Data</h3>
                <p>{result.reason}</p>
                {result.suggestion && <p className="suggestion">{result.suggestion}</p>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ImpactAnalysis;
