/**
 * Subnet Calculator Modal
 * Calculates subnet information with visual binary representation
 */

import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';
import './SubnetCalculator.css';

interface SubnetResult {
  input: string;
  network: {
    address: string;
    broadcast: string;
    netmask: string;
    wildcard_mask: string;
    cidr: string;
    prefix_length: number;
  };
  hosts: {
    first_usable: string;
    last_usable: string;
    total_addresses: number;
    usable_hosts: number;
  };
  binary: {
    network: string;
    netmask: string;
  };
  info: {
    ip_version: number;
    is_private: boolean;
    network_class: string | null;
  };
}

interface SplitResult {
  original_network: string;
  new_prefix: number;
  subnet_count: number;
  subnets: Array<{
    network: string;
    first_usable: string;
    last_usable: string;
    broadcast: string;
    hosts: number;
  }>;
}

interface CommonSubnet {
  prefix: number;
  netmask: string;
  hosts: number;
  description: string;
}

interface SubnetCalculatorProps {
  isOpen: boolean;
  onClose: () => void;
}

const SubnetCalculator: React.FC<SubnetCalculatorProps> = ({ isOpen, onClose }) => {
  const { getAuthHeaders } = useAuth();

  // Form state
  const [address, setAddress] = useState('192.168.1.0/24');
  const [netmask, setNetmask] = useState('');
  const [splitNetwork, setSplitNetwork] = useState('');
  const [newPrefix, setNewPrefix] = useState(26);

  // Results state
  const [result, setResult] = useState<SubnetResult | null>(null);
  const [splitResult, setSplitResult] = useState<SplitResult | null>(null);
  const [reference, setReference] = useState<CommonSubnet[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'calculator' | 'vlsm' | 'reference'>('calculator');

  const fetchReference = useCallback(async () => {
    try {
      const response = await fetch(`${API.base}/api/subnet/reference`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setReference(data.common_subnets || []);
      }
    } catch (err) {
      console.error('Failed to fetch reference:', err);
    }
  }, [getAuthHeaders]);

  // Fetch reference on mount
  useEffect(() => {
    if (isOpen) {
      fetchReference();
    }
  }, [isOpen, fetchReference]);

  const calculateSubnet = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const payload: any = { address };
      if (netmask) payload.netmask = netmask;

      const response = await fetch(`${API.base}/api/subnet/calculate`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.error || 'Calculation failed');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to calculate subnet');
    } finally {
      setLoading(false);
    }
  };

  const calculateSplit = async () => {
    setLoading(true);
    setError(null);
    setSplitResult(null);

    try {
      const response = await fetch(`${API.base}/api/subnet/split`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          network: splitNetwork,
          new_prefix: newPrefix,
        }),
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.error || 'Split failed');
      }

      setSplitResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to split network');
    } finally {
      setLoading(false);
    }
  };

  const renderBinaryOctet = (octet: string, index: number, isNetmask: boolean = false) => {
    return (
      <span key={index} className="binary-octet">
        {octet.split('').map((bit, bitIndex) => (
          <span
            key={bitIndex}
            className={`binary-bit ${bit === '1' ? 'one' : 'zero'} ${isNetmask ? 'mask' : ''}`}
          >
            {bit}
          </span>
        ))}
      </span>
    );
  };

  const formatNumber = (num: number): string => {
    return num.toLocaleString();
  };

  if (!isOpen) return null;

  return (
    <div className="subnet-modal-overlay" onClick={onClose}>
      <div className="subnet-modal" onClick={(e) => e.stopPropagation()}>
        <div className="subnet-modal-header">
          <h2>Subnet Calculator</h2>
          <button className="subnet-close-btn" onClick={onClose}>&times;</button>
        </div>

        <div className="subnet-tabs">
          <button
            className={`subnet-tab ${activeTab === 'calculator' ? 'active' : ''}`}
            onClick={() => setActiveTab('calculator')}
          >
            Calculator
          </button>
          <button
            className={`subnet-tab ${activeTab === 'vlsm' ? 'active' : ''}`}
            onClick={() => setActiveTab('vlsm')}
          >
            VLSM Split
          </button>
          <button
            className={`subnet-tab ${activeTab === 'reference' ? 'active' : ''}`}
            onClick={() => setActiveTab('reference')}
          >
            Reference
          </button>
        </div>

        <div className="subnet-modal-content">
          {activeTab === 'calculator' && (
            <>
              <div className="subnet-form">
                <div className="subnet-form-row">
                  <label>IP Address / CIDR</label>
                  <input
                    type="text"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    placeholder="192.168.1.0/24 or 10.0.0.1"
                  />
                  <span className="subnet-hint">Enter IP with CIDR (e.g., 192.168.1.0/24) or use netmask below</span>
                </div>

                <div className="subnet-form-row">
                  <label>Netmask (optional)</label>
                  <input
                    type="text"
                    value={netmask}
                    onChange={(e) => setNetmask(e.target.value)}
                    placeholder="255.255.255.0"
                  />
                  <span className="subnet-hint">Only needed if not using CIDR notation</span>
                </div>

                <button
                  className="subnet-calculate-btn"
                  onClick={calculateSubnet}
                  disabled={loading || !address}
                >
                  {loading ? 'Calculating...' : 'Calculate'}
                </button>
              </div>

              {error && <div className="subnet-error">{error}</div>}

              {result && (
                <div className="subnet-results">
                  <div className="subnet-result-header">
                    <h3>{result.network.cidr}</h3>
                    <div className="subnet-badges">
                      <span className={`subnet-badge ${result.info.is_private ? 'private' : 'public'}`}>
                        {result.info.is_private ? 'Private' : 'Public'}
                      </span>
                      {result.info.network_class && (
                        <span className="subnet-badge class">Class {result.info.network_class}</span>
                      )}
                      <span className="subnet-badge version">IPv{result.info.ip_version}</span>
                    </div>
                  </div>

                  <div className="subnet-result-grid">
                    <div className="subnet-result-card">
                      <div className="subnet-result-label">Network Address</div>
                      <div className="subnet-result-value">{result.network.address}</div>
                    </div>
                    <div className="subnet-result-card">
                      <div className="subnet-result-label">Broadcast Address</div>
                      <div className="subnet-result-value">{result.network.broadcast}</div>
                    </div>
                    <div className="subnet-result-card">
                      <div className="subnet-result-label">Netmask</div>
                      <div className="subnet-result-value">{result.network.netmask}</div>
                    </div>
                    <div className="subnet-result-card">
                      <div className="subnet-result-label">Wildcard Mask</div>
                      <div className="subnet-result-value">{result.network.wildcard_mask}</div>
                    </div>
                  </div>

                  <div className="subnet-hosts-section">
                    <h4>Host Range</h4>
                    <div className="subnet-host-range">
                      <span className="host-address">{result.hosts.first_usable}</span>
                      <span className="host-separator">to</span>
                      <span className="host-address">{result.hosts.last_usable}</span>
                    </div>
                    <div className="subnet-host-counts">
                      <div className="host-count">
                        <span className="count-value">{formatNumber(result.hosts.usable_hosts)}</span>
                        <span className="count-label">Usable Hosts</span>
                      </div>
                      <div className="host-count">
                        <span className="count-value">{formatNumber(result.hosts.total_addresses)}</span>
                        <span className="count-label">Total Addresses</span>
                      </div>
                    </div>
                  </div>

                  {result.info.ip_version === 4 && (
                    <div className="subnet-binary-section">
                      <h4>Binary Representation</h4>
                      <div className="binary-row">
                        <span className="binary-label">Network:</span>
                        <div className="binary-value">
                          {result.binary.network.split('.').map((octet, i) => renderBinaryOctet(octet, i))}
                        </div>
                      </div>
                      <div className="binary-row">
                        <span className="binary-label">Netmask:</span>
                        <div className="binary-value">
                          {result.binary.netmask.split('.').map((octet, i) => renderBinaryOctet(octet, i, true))}
                        </div>
                      </div>
                      <div className="binary-legend">
                        <span><span className="binary-bit one">1</span> = Network bits</span>
                        <span><span className="binary-bit zero">0</span> = Host bits</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {activeTab === 'vlsm' && (
            <>
              <div className="subnet-form">
                <div className="subnet-form-row">
                  <label>Network to Split</label>
                  <input
                    type="text"
                    value={splitNetwork}
                    onChange={(e) => setSplitNetwork(e.target.value)}
                    placeholder="192.168.1.0/24"
                  />
                </div>

                <div className="subnet-form-row">
                  <label>New Prefix Length</label>
                  <input
                    type="number"
                    value={newPrefix}
                    onChange={(e) => setNewPrefix(parseInt(e.target.value) || 24)}
                    min={1}
                    max={32}
                  />
                  <span className="subnet-hint">Must be larger than original prefix</span>
                </div>

                <button
                  className="subnet-calculate-btn"
                  onClick={calculateSplit}
                  disabled={loading || !splitNetwork}
                >
                  {loading ? 'Splitting...' : 'Split Network'}
                </button>
              </div>

              {error && <div className="subnet-error">{error}</div>}

              {splitResult && (
                <div className="subnet-split-results">
                  <div className="split-summary">
                    <span>{splitResult.original_network}</span>
                    <span className="split-arrow">→</span>
                    <span>{splitResult.subnet_count} x /{splitResult.new_prefix} subnets</span>
                  </div>

                  <div className="split-table-container">
                    <table className="subnet-split-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Network</th>
                          <th>First Usable</th>
                          <th>Last Usable</th>
                          <th>Hosts</th>
                        </tr>
                      </thead>
                      <tbody>
                        {splitResult.subnets.slice(0, 50).map((subnet, index) => (
                          <tr key={index}>
                            <td>{index + 1}</td>
                            <td className="network-cell">{subnet.network}</td>
                            <td>{subnet.first_usable}</td>
                            <td>{subnet.last_usable}</td>
                            <td>{subnet.hosts}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {splitResult.subnet_count > 50 && (
                      <div className="split-more">
                        ...and {splitResult.subnet_count - 50} more subnets
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {activeTab === 'reference' && (
            <div className="subnet-reference">
              <p className="subnet-reference-intro">
                Common IPv4 subnet sizes and their properties
              </p>
              <table className="subnet-reference-table">
                <thead>
                  <tr>
                    <th>CIDR</th>
                    <th>Netmask</th>
                    <th>Usable Hosts</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {reference.map((subnet) => (
                    <tr key={subnet.prefix}>
                      <td className="cidr-cell">/{subnet.prefix}</td>
                      <td>{subnet.netmask}</td>
                      <td>{formatNumber(subnet.hosts)}</td>
                      <td>{subnet.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SubnetCalculator;
