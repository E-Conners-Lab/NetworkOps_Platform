/**
 * MTU Calculator Modal
 * Calculates optimal tunnel MTU and TCP MSS for VPN tunnels
 */

import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';
import './MTUCalculator.css';

interface OverheadBreakdown {
  [key: string]: number;
}

interface MTUResult {
  physical_mtu: number;
  tunnel_mtu: number;
  tcp_mss: number;
  total_overhead: number;
  overhead_breakdown: OverheadBreakdown;
  tunnel_type: string;
  encryption: string | null;
  nat_traversal: boolean;
  warnings: string[];
  config?: string;
  platform?: string;
}

interface Scenario {
  name: string;
  tunnel_mtu: number;
  tcp_mss: number;
  overhead: number;
}

interface ScenariosResponse {
  physical_mtu: number;
  scenarios: { [key: string]: Scenario };
}

interface MTUCalculatorProps {
  isOpen: boolean;
  onClose: () => void;
}

const TUNNEL_TYPES = [
  { value: 'gre', label: 'GRE (no encryption)' },
  { value: 'gre_ipsec', label: 'GRE over IPsec (DMVPN)' },
  { value: 'ipsec_tunnel', label: 'IPsec Tunnel Mode' },
  { value: 'ipsec_transport', label: 'IPsec Transport Mode' },
  { value: 'vxlan', label: 'VXLAN' },
  { value: 'wireguard', label: 'WireGuard' },
];

const ENCRYPTION_TYPES = [
  { value: '', label: '-- Auto (AES-256-GCM) --' },
  { value: 'aes-256-gcm', label: 'AES-256-GCM (Recommended)' },
  { value: 'aes-128-gcm', label: 'AES-128-GCM' },
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
  { value: 'chacha20-poly1305', label: 'ChaCha20-Poly1305' },
];

const AUTH_TYPES = [
  { value: '', label: '-- Auto --' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' },
  { value: 'sha1', label: 'SHA-1 (Legacy)' },
];

const PLATFORMS = [
  { value: '', label: '-- Select Platform --' },
  { value: 'cisco_ios', label: 'Cisco IOS / IOS-XE' },
  { value: 'cisco_nxos', label: 'Cisco NX-OS' },
  { value: 'cisco_asa', label: 'Cisco ASA' },
  { value: 'juniper_junos', label: 'Juniper JunOS' },
  { value: 'arista_eos', label: 'Arista EOS' },
  { value: 'palo_alto', label: 'Palo Alto PAN-OS' },
  { value: 'fortinet', label: 'Fortinet FortiOS' },
  { value: 'nokia_srlinux', label: 'Nokia SR Linux' },
  { value: 'nokia_sros', label: 'Nokia SR OS' },
  { value: 'mikrotik', label: 'MikroTik RouterOS' },
  { value: 'huawei_vrp', label: 'Huawei VRP' },
  { value: 'vyos', label: 'VyOS' },
  { value: 'linux', label: 'Linux (iptables)' },
];

const MTUCalculator: React.FC<MTUCalculatorProps> = ({ isOpen, onClose }) => {
  const { getAuthHeaders } = useAuth();

  // Form state
  const [tunnelType, setTunnelType] = useState('gre_ipsec');
  const [physicalMtu, setPhysicalMtu] = useState(1500);
  const [encryption, setEncryption] = useState('');
  const [auth, setAuth] = useState('');
  const [natTraversal, setNatTraversal] = useState(false);
  const [platform, setPlatform] = useState('');
  const [interfaceName, setInterfaceName] = useState('Tunnel0');

  // Results state
  const [result, setResult] = useState<MTUResult | null>(null);
  const [scenarios, setScenarios] = useState<ScenariosResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'calculator' | 'scenarios'>('calculator');
  const [copied, setCopied] = useState(false);

  const fetchScenarios = useCallback(async () => {
    try {
      const response = await fetch(API.mtuScenarios, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setScenarios(data);
      }
    } catch (err) {
      console.error('Failed to fetch scenarios:', err);
    }
  }, [getAuthHeaders]);

  // Fetch common scenarios on mount
  useEffect(() => {
    if (isOpen) {
      fetchScenarios();
    }
  }, [isOpen, fetchScenarios]);

  const calculateMTU = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const payload: any = {
        tunnel_type: tunnelType,
        physical_mtu: physicalMtu,
        nat_traversal: natTraversal,
      };

      if (encryption) payload.encryption = encryption;
      if (auth) payload.auth = auth;
      if (platform) {
        payload.platform = platform;
        payload.interface = interfaceName;
      }

      const response = await fetch(API.mtuCalculate, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Calculation failed');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to calculate MTU');
    } finally {
      setLoading(false);
    }
  };

  const copyConfig = () => {
    if (result?.config) {
      navigator.clipboard.writeText(result.config);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const needsIpsecOptions = ['gre_ipsec', 'ipsec_tunnel', 'ipsec_transport'].includes(tunnelType);

  if (!isOpen) return null;

  return (
    <div className="mtu-modal-overlay" onClick={onClose}>
      <div className="mtu-modal" onClick={(e) => e.stopPropagation()}>
        <div className="mtu-modal-header">
          <h2>Tunnel MTU & MSS Calculator</h2>
          <button className="mtu-close-btn" onClick={onClose}>&times;</button>
        </div>

        <div className="mtu-tabs">
          <button
            className={`mtu-tab ${activeTab === 'calculator' ? 'active' : ''}`}
            onClick={() => setActiveTab('calculator')}
          >
            Calculator
          </button>
          <button
            className={`mtu-tab ${activeTab === 'scenarios' ? 'active' : ''}`}
            onClick={() => setActiveTab('scenarios')}
          >
            Quick Reference
          </button>
        </div>

        <div className="mtu-modal-content">
          {activeTab === 'calculator' ? (
            <>
              <div className="mtu-form">
                <div className="mtu-form-row">
                  <label>Tunnel Type</label>
                  <select
                    value={tunnelType}
                    onChange={(e) => setTunnelType(e.target.value)}
                  >
                    {TUNNEL_TYPES.map((t) => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                </div>

                <div className="mtu-form-row">
                  <label>Physical MTU</label>
                  <input
                    type="number"
                    value={physicalMtu}
                    onChange={(e) => setPhysicalMtu(parseInt(e.target.value) || 1500)}
                    min={576}
                    max={9000}
                  />
                </div>

                {needsIpsecOptions && (
                  <>
                    <div className="mtu-form-row">
                      <label>Encryption</label>
                      <select
                        value={encryption}
                        onChange={(e) => setEncryption(e.target.value)}
                      >
                        {ENCRYPTION_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                    </div>

                    <div className="mtu-form-row">
                      <label>Authentication</label>
                      <select
                        value={auth}
                        onChange={(e) => setAuth(e.target.value)}
                      >
                        {AUTH_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                    </div>

                    <div className="mtu-form-row checkbox">
                      <label>
                        <input
                          type="checkbox"
                          checked={natTraversal}
                          onChange={(e) => setNatTraversal(e.target.checked)}
                        />
                        NAT Traversal (NAT-T)
                        <span className="mtu-hint">+8 bytes UDP encapsulation</span>
                      </label>
                    </div>
                  </>
                )}

                <div className="mtu-form-divider">
                  <span>Config Generation (Optional)</span>
                </div>

                <div className="mtu-form-row">
                  <label>Platform</label>
                  <select
                    value={platform}
                    onChange={(e) => setPlatform(e.target.value)}
                  >
                    {PLATFORMS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>

                {platform && (
                  <div className="mtu-form-row">
                    <label>Interface Name</label>
                    <input
                      type="text"
                      value={interfaceName}
                      onChange={(e) => setInterfaceName(e.target.value)}
                      placeholder="Tunnel0"
                    />
                  </div>
                )}

                <button
                  className="mtu-calculate-btn"
                  onClick={calculateMTU}
                  disabled={loading}
                >
                  {loading ? 'Calculating...' : 'Calculate'}
                </button>
              </div>

              {error && (
                <div className="mtu-error">{error}</div>
              )}

              {result && (
                <div className="mtu-results">
                  <h3>Results</h3>

                  <div className="mtu-result-cards">
                    <div className="mtu-result-card primary">
                      <div className="mtu-result-label">Tunnel MTU</div>
                      <div className="mtu-result-value">{result.tunnel_mtu}</div>
                      <div className="mtu-result-unit">bytes</div>
                    </div>
                    <div className="mtu-result-card primary">
                      <div className="mtu-result-label">TCP MSS</div>
                      <div className="mtu-result-value">{result.tcp_mss}</div>
                      <div className="mtu-result-unit">bytes</div>
                    </div>
                    <div className="mtu-result-card">
                      <div className="mtu-result-label">Overhead</div>
                      <div className="mtu-result-value">{result.total_overhead}</div>
                      <div className="mtu-result-unit">bytes</div>
                    </div>
                  </div>

                  <div className="mtu-breakdown">
                    <h4>Overhead Breakdown</h4>
                    <table>
                      <tbody>
                        {Object.entries(result.overhead_breakdown).map(([key, value]) => (
                          <tr key={key} className={key === 'Total Overhead' ? 'total' : ''}>
                            <td>{key}</td>
                            <td>{value} bytes</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {result.warnings.length > 0 && (
                    <div className="mtu-warnings">
                      {result.warnings.map((w, i) => (
                        <div key={i} className="mtu-warning">{w}</div>
                      ))}
                    </div>
                  )}

                  {result.config && (
                    <div className="mtu-config">
                      <div className="mtu-config-header">
                        <h4>Configuration ({result.platform})</h4>
                        <button onClick={copyConfig} className="mtu-copy-btn">
                          {copied ? '✓ Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre>{result.config}</pre>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="mtu-scenarios">
              <p className="mtu-scenarios-intro">
                Pre-calculated values for common tunnel configurations (1500 byte physical MTU)
              </p>
              {scenarios && (
                <table className="mtu-scenarios-table">
                  <thead>
                    <tr>
                      <th>Scenario</th>
                      <th>Overhead</th>
                      <th>Tunnel MTU</th>
                      <th>TCP MSS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(scenarios.scenarios).map(([key, scenario]) => (
                      <tr key={key}>
                        <td>{scenario.name}</td>
                        <td>{scenario.overhead} bytes</td>
                        <td><strong>{scenario.tunnel_mtu}</strong></td>
                        <td><strong>{scenario.tcp_mss}</strong></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MTUCalculator;
