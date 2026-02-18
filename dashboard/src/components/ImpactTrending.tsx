/**
 * Impact Trending Component
 * Historical state tracking, baseline management, and drift detection
 */

import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';
import './ImpactTrending.css';

// Types
interface OSPFNeighbor {
  neighbor_id: string;
  address: string;
  interface: string;
  state: string;
  area: string;
}

interface BGPPeer {
  peer_ip: string;
  peer_asn: number;
  state: string;
  prefixes_received: number;
}

interface Snapshot {
  snapshot_id: string;
  device: string;
  timestamp: string;
  ospf_neighbors: OSPFNeighbor[];
  bgp_peers: BGPPeer[];
  route_count: number;
  platform: string;
  is_baseline: boolean;
  notes: string | null;
}

interface Drift {
  drift_id: string;
  device: string;
  detected_at: string;
  drift_type: string;
  severity: 'info' | 'warning' | 'critical';
  description: string;
  baseline_value: string | null;
  current_value: string | null;
}

interface DriftReport {
  device: string;
  baseline_timestamp: string;
  current_timestamp: string;
  total_drifts: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
  drifts: Drift[];
  summary: string;
}

interface TrendingSummary {
  device: string;
  period_days: number;
  snapshot_count: number;
  has_baseline: boolean;
  baseline_timestamp: string | null;
  drift_counts: {
    critical: number;
    warning: number;
    info: number;
  };
  latest_state: {
    timestamp: string;
    ospf_neighbor_count: number;
    bgp_peer_count: number;
    route_count: number;
  } | null;
}

interface DeviceInfo {
  name: string;
  host: string;
  platform: string;
}

interface ImpactTrendingProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedDevice?: string;
}

type TabType = 'overview' | 'snapshots' | 'baseline' | 'drift';

const SEVERITY_COLORS: Record<string, string> = {
  info: '#4a9eff',
  warning: '#eab308',
  critical: '#ef4444',
};

const ImpactTrending: React.FC<ImpactTrendingProps> = ({
  isOpen,
  onClose,
  preselectedDevice,
}) => {
  const { getAuthHeaders } = useAuth();

  // Device selection
  const [device, setDevice] = useState(preselectedDevice || '');
  const [devices, setDevices] = useState<DeviceInfo[]>([]);

  // Tab state
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  // Data state
  const [summary, setSummary] = useState<TrendingSummary | null>(null);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [baseline, setBaseline] = useState<Snapshot | null>(null);
  const [driftReport, setDriftReport] = useState<DriftReport | null>(null);

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [snapshotNotes, setSnapshotNotes] = useState('');
  const [baselineReason, setBaselineReason] = useState('');

  // Fetch devices on open
  useEffect(() => {
    if (!isOpen) return;

    fetch(`${API.base}/api/topology`, { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => {
        const supportedDevices = (data.nodes || [])
          .filter((d: any) => {
            const platform = (d.platform || '').toLowerCase();
            const isCisco = platform.includes('c8000') ||
                           platform.includes('cat9') ||
                           platform.includes('csr') ||
                           platform.includes('ios');
            const isFRR = platform.includes('frr');
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

  // Reset when modal opens
  useEffect(() => {
    if (isOpen) {
      setError(null);
      setActiveTab('overview');
      if (preselectedDevice) setDevice(preselectedDevice);
    }
  }, [isOpen, preselectedDevice]);

  // Fetch summary when device changes
  useEffect(() => {
    if (!device) {
      setSummary(null);
      return;
    }

    setLoading(true);
    fetch(`${API.base}/api/impact/trending/${device}/summary?days=7`, {
      headers: getAuthHeaders()
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === 'error') {
          setError(data.reason);
        } else {
          setSummary(data);
        }
      })
      .catch(err => {
        console.error('Failed to fetch summary:', err);
        setError('Failed to load trending summary');
      })
      .finally(() => setLoading(false));
  }, [device, getAuthHeaders]);

  // Fetch snapshots when tab changes
  useEffect(() => {
    if (activeTab !== 'snapshots' || !device) return;

    setLoading(true);
    fetch(`${API.base}/api/impact/trending/${device}/snapshots?days=30&limit=50`, {
      headers: getAuthHeaders()
    })
      .then(res => res.json())
      .then(data => setSnapshots(data.snapshots || []))
      .catch(err => console.error('Failed to fetch snapshots:', err))
      .finally(() => setLoading(false));
  }, [activeTab, device, getAuthHeaders]);

  // Fetch baseline when tab changes
  useEffect(() => {
    if (activeTab !== 'baseline' || !device) return;

    setLoading(true);
    fetch(`${API.base}/api/impact/trending/${device}/baseline`, {
      headers: getAuthHeaders()
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          setBaseline(data.baseline);
        } else {
          setBaseline(null);
        }
      })
      .catch(err => console.error('Failed to fetch baseline:', err))
      .finally(() => setLoading(false));
  }, [activeTab, device, getAuthHeaders]);

  // Capture snapshot
  const captureSnapshot = useCallback(async () => {
    if (!device) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API.base}/api/impact/trending/${device}/snapshot`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ notes: snapshotNotes || undefined }),
      });

      const data = await response.json();

      if (data.status === 'success') {
        // Refresh snapshots list
        const listRes = await fetch(
          `${API.base}/api/impact/trending/${device}/snapshots?days=30`,
          { headers: getAuthHeaders() }
        );
        const listData = await listRes.json();
        setSnapshots(listData.snapshots || []);
        setSnapshotNotes('');
      } else {
        setError(data.reason || 'Failed to capture snapshot');
      }
    } catch (err) {
      setError('Failed to capture snapshot');
    } finally {
      setLoading(false);
    }
  }, [device, snapshotNotes, getAuthHeaders]);

  // Set baseline
  const setAsBaseline = useCallback(async (snapshotId?: string) => {
    if (!device) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API.base}/api/impact/trending/${device}/baseline`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          snapshot_id: snapshotId,
          reason: baselineReason || undefined,
        }),
      });

      const data = await response.json();

      if (data.status === 'success') {
        setBaseline(data.baseline);
        setBaselineReason('');
        // Refresh summary
        const sumRes = await fetch(
          `${API.base}/api/impact/trending/${device}/summary?days=7`,
          { headers: getAuthHeaders() }
        );
        const sumData = await sumRes.json();
        setSummary(sumData);
      } else {
        setError(data.reason || 'Failed to set baseline');
      }
    } catch (err) {
      setError('Failed to set baseline');
    } finally {
      setLoading(false);
    }
  }, [device, baselineReason, getAuthHeaders]);

  // Clear baseline
  const clearBaseline = useCallback(async () => {
    if (!device) return;

    setLoading(true);
    try {
      await fetch(`${API.base}/api/impact/trending/${device}/baseline`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      setBaseline(null);
      // Refresh summary
      const sumRes = await fetch(
        `${API.base}/api/impact/trending/${device}/summary?days=7`,
        { headers: getAuthHeaders() }
      );
      const sumData = await sumRes.json();
      setSummary(sumData);
    } catch (err) {
      setError('Failed to clear baseline');
    } finally {
      setLoading(false);
    }
  }, [device, getAuthHeaders]);

  // Check drift
  const checkDrift = useCallback(async () => {
    if (!device) return;

    setLoading(true);
    setError(null);
    setDriftReport(null);

    try {
      const response = await fetch(`${API.base}/api/impact/trending/${device}/drift`, {
        headers: getAuthHeaders(),
      });

      const data = await response.json();

      if (data.status === 'success') {
        setDriftReport(data.report);
      } else if (data.status === 'no_baseline') {
        setError('No baseline set. Set a baseline first to check for drift.');
      } else {
        setError(data.reason || 'Failed to check drift');
      }
    } catch (err) {
      setError('Failed to check drift');
    } finally {
      setLoading(false);
    }
  }, [device, getAuthHeaders]);

  // Format timestamp
  const formatTime = (ts: string) => {
    const date = new Date(ts);
    return date.toLocaleString();
  };

  // Format relative time
  const formatRelative = (ts: string) => {
    const diff = Date.now() - new Date(ts).getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'just now';
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="trending-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Impact Trending</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>

        <div className="modal-content">
          {/* Device Selector */}
          <div className="device-selector">
            <label>Device</label>
            <select
              value={device}
              onChange={e => {
                setDevice(e.target.value);
                setSummary(null);
                setSnapshots([]);
                setBaseline(null);
                setDriftReport(null);
              }}
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
            <div className="trending-error">{error}</div>
          )}

          {/* Tabs */}
          {device && (
            <div className="trending-tabs">
              <button
                className={activeTab === 'overview' ? 'active' : ''}
                onClick={() => setActiveTab('overview')}
              >
                Overview
              </button>
              <button
                className={activeTab === 'snapshots' ? 'active' : ''}
                onClick={() => setActiveTab('snapshots')}
              >
                Snapshots
              </button>
              <button
                className={activeTab === 'baseline' ? 'active' : ''}
                onClick={() => setActiveTab('baseline')}
              >
                Baseline
              </button>
              <button
                className={activeTab === 'drift' ? 'active' : ''}
                onClick={() => setActiveTab('drift')}
              >
                Drift Check
              </button>
            </div>
          )}

          {/* Tab Content */}
          {device && (
            <div className="tab-content">
              {/* Overview Tab */}
              {activeTab === 'overview' && summary && (
                <div className="overview-tab">
                  <div className="overview-grid">
                    <div className="overview-card">
                      <span className="card-value">{summary.snapshot_count}</span>
                      <span className="card-label">Snapshots (7d)</span>
                    </div>
                    <div className="overview-card">
                      <span className={`card-value ${summary.has_baseline ? 'success' : 'warning'}`}>
                        {summary.has_baseline ? 'Set' : 'Not Set'}
                      </span>
                      <span className="card-label">Baseline</span>
                    </div>
                    <div className="overview-card">
                      <span className={`card-value ${summary.drift_counts.critical > 0 ? 'critical' : ''}`}>
                        {summary.drift_counts.critical}
                      </span>
                      <span className="card-label">Critical Drifts</span>
                    </div>
                    <div className="overview-card">
                      <span className={`card-value ${summary.drift_counts.warning > 0 ? 'warning' : ''}`}>
                        {summary.drift_counts.warning}
                      </span>
                      <span className="card-label">Warnings</span>
                    </div>
                  </div>

                  {summary.latest_state && (
                    <div className="latest-state">
                      <h3>Latest State</h3>
                      <div className="state-details">
                        <div className="state-item">
                          <span className="state-value">{summary.latest_state.ospf_neighbor_count}</span>
                          <span className="state-label">OSPF Neighbors</span>
                        </div>
                        <div className="state-item">
                          <span className="state-value">{summary.latest_state.bgp_peer_count}</span>
                          <span className="state-label">BGP Peers</span>
                        </div>
                        <div className="state-item">
                          <span className="state-value">{summary.latest_state.route_count}</span>
                          <span className="state-label">Routes</span>
                        </div>
                      </div>
                      <div className="state-timestamp">
                        Last captured: {formatRelative(summary.latest_state.timestamp)}
                      </div>
                    </div>
                  )}

                  {summary.has_baseline && summary.baseline_timestamp && (
                    <div className="baseline-info">
                      <span className="baseline-badge">Baseline</span>
                      <span className="baseline-timestamp">
                        Set at {formatTime(summary.baseline_timestamp)}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Snapshots Tab */}
              {activeTab === 'snapshots' && (
                <div className="snapshots-tab">
                  <div className="capture-form">
                    <input
                      type="text"
                      placeholder="Notes (optional)"
                      value={snapshotNotes}
                      onChange={e => setSnapshotNotes(e.target.value)}
                      disabled={loading}
                    />
                    <button
                      className="capture-button"
                      onClick={captureSnapshot}
                      disabled={loading}
                    >
                      {loading ? 'Capturing...' : 'Capture Snapshot'}
                    </button>
                  </div>

                  <div className="snapshots-list">
                    {snapshots.length === 0 && !loading && (
                      <div className="empty-state">
                        No snapshots captured yet. Capture your first snapshot above.
                      </div>
                    )}
                    {snapshots.map(snapshot => (
                      <div
                        key={snapshot.snapshot_id}
                        className={`snapshot-item ${snapshot.is_baseline ? 'is-baseline' : ''}`}
                      >
                        <div className="snapshot-header">
                          <span className="snapshot-id">{snapshot.snapshot_id}</span>
                          {snapshot.is_baseline && (
                            <span className="baseline-tag">BASELINE</span>
                          )}
                          <span className="snapshot-time">
                            {formatRelative(snapshot.timestamp)}
                          </span>
                        </div>
                        <div className="snapshot-details">
                          <span>OSPF: {snapshot.ospf_neighbors.length}</span>
                          <span>BGP: {snapshot.bgp_peers.length}</span>
                          <span>Routes: {snapshot.route_count}</span>
                        </div>
                        {snapshot.notes && (
                          <div className="snapshot-notes">{snapshot.notes}</div>
                        )}
                        {!snapshot.is_baseline && (
                          <button
                            className="set-baseline-btn"
                            onClick={() => setAsBaseline(snapshot.snapshot_id)}
                            disabled={loading}
                          >
                            Set as Baseline
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Baseline Tab */}
              {activeTab === 'baseline' && (
                <div className="baseline-tab">
                  {baseline ? (
                    <div className="baseline-details">
                      <div className="baseline-header">
                        <h3>Current Baseline</h3>
                        <button
                          className="clear-baseline-btn"
                          onClick={clearBaseline}
                          disabled={loading}
                        >
                          Clear Baseline
                        </button>
                      </div>

                      <div className="baseline-meta">
                        <span>ID: {baseline.snapshot_id}</span>
                        <span>Captured: {formatTime(baseline.timestamp)}</span>
                      </div>

                      <div className="baseline-state">
                        <div className="state-section">
                          <h4>OSPF Neighbors ({baseline.ospf_neighbors.length})</h4>
                          {baseline.ospf_neighbors.length === 0 ? (
                            <p className="no-data">No OSPF neighbors</p>
                          ) : (
                            <ul className="neighbor-list">
                              {baseline.ospf_neighbors.map((n, i) => (
                                <li key={i}>
                                  <strong>{n.neighbor_id}</strong>
                                  <span className="detail">
                                    via {n.interface} ({n.state})
                                  </span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="state-section">
                          <h4>BGP Peers ({baseline.bgp_peers.length})</h4>
                          {baseline.bgp_peers.length === 0 ? (
                            <p className="no-data">No BGP peers</p>
                          ) : (
                            <ul className="peer-list">
                              {baseline.bgp_peers.map((p, i) => (
                                <li key={i}>
                                  <strong>AS{p.peer_asn}</strong>
                                  <span className="detail">
                                    {p.peer_ip} ({p.state})
                                  </span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="route-count">
                          <strong>{baseline.route_count}</strong> routes in table
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="no-baseline">
                      <h3>No Baseline Set</h3>
                      <p>Set a baseline to track state drift over time.</p>

                      <div className="set-baseline-form">
                        <input
                          type="text"
                          placeholder="Reason (optional)"
                          value={baselineReason}
                          onChange={e => setBaselineReason(e.target.value)}
                          disabled={loading}
                        />
                        <button
                          className="set-baseline-button"
                          onClick={() => setAsBaseline()}
                          disabled={loading}
                        >
                          {loading ? 'Setting...' : 'Capture & Set Baseline'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Drift Tab */}
              {activeTab === 'drift' && (
                <div className="drift-tab">
                  <button
                    className="check-drift-button"
                    onClick={checkDrift}
                    disabled={loading}
                  >
                    {loading ? 'Checking...' : 'Check for Drift'}
                  </button>

                  {driftReport && (
                    <div className="drift-report">
                      <div className="drift-summary">
                        <h3>{driftReport.summary}</h3>
                        <div className="drift-counts">
                          <span className="count critical">
                            {driftReport.critical_count} Critical
                          </span>
                          <span className="count warning">
                            {driftReport.warning_count} Warning
                          </span>
                          <span className="count info">
                            {driftReport.info_count} Info
                          </span>
                        </div>
                      </div>

                      {driftReport.drifts.length === 0 ? (
                        <div className="no-drift">
                          No drift detected. Current state matches baseline.
                        </div>
                      ) : (
                        <div className="drift-list">
                          {driftReport.drifts.map(drift => (
                            <div
                              key={drift.drift_id}
                              className={`drift-item ${drift.severity}`}
                            >
                              <div className="drift-header">
                                <span
                                  className="severity-badge"
                                  style={{ backgroundColor: SEVERITY_COLORS[drift.severity] }}
                                >
                                  {drift.severity.toUpperCase()}
                                </span>
                                <span className="drift-type">
                                  {drift.drift_type.replace(/_/g, ' ')}
                                </span>
                              </div>
                              <div className="drift-description">
                                {drift.description}
                              </div>
                              {(drift.baseline_value || drift.current_value) && (
                                <div className="drift-values">
                                  {drift.baseline_value && (
                                    <span className="baseline-val">
                                      Baseline: {drift.baseline_value}
                                    </span>
                                  )}
                                  {drift.current_value && (
                                    <span className="current-val">
                                      Current: {drift.current_value}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="drift-meta">
                        <span>Baseline: {formatTime(driftReport.baseline_timestamp)}</span>
                        <span>Checked: {formatTime(driftReport.current_timestamp)}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Loading State */}
              {loading && !summary && (
                <div className="loading-state">Loading...</div>
              )}
            </div>
          )}

          {/* No Device Selected */}
          {!device && (
            <div className="no-device">
              Select a device to view trending data
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ImpactTrending;
