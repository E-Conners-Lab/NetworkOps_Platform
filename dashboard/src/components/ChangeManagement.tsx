import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { API } from '../config';
import './ChangeManagement.css';

interface ChangeRequest {
  id: string;
  device: string;
  description: string;
  commands: string[];
  change_type: string;
  status: string;
  created_by: string;
  created_at: string;
  approved_by?: string;
  approved_at?: string;
  executed_at?: string;
  completed_at?: string;
  require_approval: boolean;
  auto_rollback: boolean;
  validation_checks: string[];
  pre_state?: {
    running_config?: string;
    interfaces?: Array<Record<string, unknown>>;
    routes?: Array<Record<string, unknown>>;
    neighbors?: Array<Record<string, unknown>>;
    captured_at?: string;
  };
  post_validation?: {
    checks: Array<{
      command: string;
      result: string;  // "passed", "failed", "error"
      output?: string;
      error?: string;
    }>;
    overall_result: string;  // "passed", "failed", "error"
  };
  rollback_commands?: string[];
  error_message?: string;
}

interface ChangeType {
  value: string;
  label: string;
  description: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

const ChangeManagement: React.FC<Props> = ({ isOpen, onClose }) => {
  const { user, getAuthHeaders } = useAuth();
  const userRole = user?.role || 'operator';
  const [changes, setChanges] = useState<ChangeRequest[]>([]);
  const [selectedChange, setSelectedChange] = useState<ChangeRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [changeTypes, setChangeTypes] = useState<ChangeType[]>([]);
  const [devices, setDevices] = useState<string[]>([]);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [deviceFilter, setDeviceFilter] = useState<string>('');

  // Create form state
  const [newChange, setNewChange] = useState({
    device: '',
    description: '',
    commands: '',
    change_type: 'config',
    validation_checks: '',
    require_approval: true,
    auto_rollback: true,
  });

  const isAdmin = userRole === 'admin';

  const fetchChanges = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (statusFilter) params.append('status', statusFilter);
      if (deviceFilter) params.append('device', deviceFilter);
      params.append('limit', '50');

      const response = await fetch(`${API.base}/api/changes?${params}`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch changes');
      const data = await response.json();
      setChanges(data.changes || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch changes');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders, statusFilter, deviceFilter]);

  const fetchChangeTypes = useCallback(async () => {
    try {
      const response = await fetch(`${API.base}/api/changes/types`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setChangeTypes(data.change_types || []);
      }
    } catch (err) {
      console.error('Failed to fetch change types:', err);
    }
  }, [getAuthHeaders]);

  const fetchDevices = useCallback(async () => {
    try {
      const response = await fetch(`${API.devices}`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        // API returns array of device names directly: ["R1", "R2", ...]
        if (Array.isArray(data)) {
          setDevices(data);
        } else if (data.devices) {
          // Fallback for legacy format
          setDevices(data.devices.map((d: any) => d.name || d));
        }
      }
    } catch (err) {
      console.error('Failed to fetch devices:', err);
    }
  }, [getAuthHeaders]);

  useEffect(() => {
    if (isOpen) {
      fetchChanges();
      fetchChangeTypes();
      fetchDevices();
    }
  }, [isOpen, fetchChanges, fetchChangeTypes, fetchDevices]);

  const handleCreateChange = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API.base}/api/changes`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          device: newChange.device,
          description: newChange.description,
          command_string: newChange.commands,
          change_type: newChange.change_type,
          validation_checks: newChange.validation_checks || undefined,
          require_approval: newChange.require_approval,
          auto_rollback: newChange.auto_rollback,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create change');
      }

      setShowCreateModal(false);
      setNewChange({
        device: '',
        description: '',
        commands: '',
        change_type: 'config',
        validation_checks: '',
        require_approval: true,
        auto_rollback: true,
      });
      fetchChanges();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create change');
    }
  };

  const handleAction = async (changeId: string, action: string) => {
    try {
      const response = await fetch(`${API.base}/api/changes/${changeId}/${action}`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to ${action} change`);
      }

      fetchChanges();
      if (selectedChange?.id === changeId) {
        const data = await response.json();
        setSelectedChange(data.change || null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action} change`);
    }
  };

  const viewChange = async (changeId: string) => {
    try {
      const response = await fetch(`${API.base}/api/changes/${changeId}`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setSelectedChange(data.change);
      }
    } catch (err) {
      console.error('Failed to fetch change details:', err);
    }
  };

  const formatDate = (dateStr: string) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  };

  const getStatusClass = (status: string) => {
    return `status-badge status-${status.toLowerCase().replace(' ', '_')}`;
  };

  const canApprove = (change: ChangeRequest) => {
    return isAdmin && change.status === 'pending_approval';
  };

  const canExecute = (change: ChangeRequest) => {
    return isAdmin && change.status === 'approved';
  };

  const canRollback = (change: ChangeRequest) => {
    return isAdmin && ['completed', 'failed'].includes(change.status);
  };

  const canCancel = (change: ChangeRequest) => {
    return isAdmin && ['draft', 'pending_approval', 'approved'].includes(change.status);
  };

  if (!isOpen) return null;

  if (selectedChange) {
    return (
      <div className="change-management-overlay" onClick={onClose}>
        <div className="change-management-panel" onClick={(e) => e.stopPropagation()}>
          <div className="change-management-header">
            <h2>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              Change Details
            </h2>
            <button className="close-btn" onClick={onClose}>×</button>
          </div>
          <div className="change-management">
            <button className="btn-back" onClick={() => setSelectedChange(null)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
              Back to List
            </button>

        <div className="change-detail">
          <div className="change-detail-header">
            <div className="change-detail-title">
              <h3>{selectedChange.description}</h3>
              <div className="change-detail-meta">
                <span className={getStatusClass(selectedChange.status)}>
                  {selectedChange.status.replace('_', ' ')}
                </span>
                <span className="type-badge">{selectedChange.change_type}</span>
                <span>Device: {selectedChange.device}</span>
                <span>ID: {selectedChange.id}</span>
              </div>
            </div>
            <div className="change-detail-actions">
              {canApprove(selectedChange) && (
                <>
                  <button
                    className="btn-action btn-approve"
                    onClick={() => handleAction(selectedChange.id, 'approve')}
                  >
                    Approve
                  </button>
                  <button
                    className="btn-action btn-reject"
                    onClick={() => handleAction(selectedChange.id, 'reject')}
                  >
                    Reject
                  </button>
                </>
              )}
              {canExecute(selectedChange) && (
                <button
                  className="btn-action btn-execute"
                  onClick={() => handleAction(selectedChange.id, 'execute')}
                >
                  Execute
                </button>
              )}
              {canRollback(selectedChange) && (
                <button
                  className="btn-action btn-rollback"
                  onClick={() => handleAction(selectedChange.id, 'rollback')}
                >
                  Rollback
                </button>
              )}
              {canCancel(selectedChange) && (
                <button
                  className="btn-action btn-cancel-change"
                  onClick={() => handleAction(selectedChange.id, 'cancel')}
                >
                  Cancel
                </button>
              )}
            </div>
          </div>

          {selectedChange.error_message && (
            <div className="error-message">{selectedChange.error_message}</div>
          )}

          <div className="change-detail-section">
            <h4>Commands</h4>
            <div className="command-list">
              {selectedChange.commands.map((cmd, i) => (
                <code key={i}>{cmd}</code>
              ))}
            </div>
          </div>

          {selectedChange.validation_checks.length > 0 && (
            <div className="change-detail-section">
              <h4>Validation Checks</h4>
              <div className="command-list">
                {selectedChange.validation_checks.map((check, i) => (
                  <code key={i}>{check}</code>
                ))}
              </div>
            </div>
          )}

          {selectedChange.post_validation && (
            <div className="change-detail-section">
              <h4>Validation Results</h4>
              <div className="validation-results">
                {selectedChange.post_validation.checks.map((check, i) => (
                  <div
                    key={i}
                    className={`validation-result ${check.result}`}
                  >
                    <div className="validation-header">
                      <code className="validation-command">{check.command}</code>
                      <span className={`status-badge status-${check.result}`}>
                        {check.result}
                      </span>
                    </div>
                    {check.output && (
                      <pre className="validation-output">{check.output}</pre>
                    )}
                    {check.error && (
                      <pre className="validation-error">{check.error}</pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {selectedChange.rollback_commands && selectedChange.rollback_commands.length > 0 && (
            <div className="change-detail-section">
              <h4>Rollback Commands</h4>
              <div className="command-list">
                {selectedChange.rollback_commands.map((cmd, i) => (
                  <code key={i}>{cmd}</code>
                ))}
              </div>
            </div>
          )}

          <div className="change-detail-section">
            <h4>Timeline</h4>
            <div className="change-timeline">
              <div className="timeline-item completed">
                <div className="timeline-time">{formatDate(selectedChange.created_at)}</div>
                <div className="timeline-text">
                  Created by {selectedChange.created_by}
                </div>
              </div>
              {selectedChange.approved_at && (
                <div className="timeline-item completed">
                  <div className="timeline-time">{formatDate(selectedChange.approved_at)}</div>
                  <div className="timeline-text">
                    Approved by {selectedChange.approved_by}
                  </div>
                </div>
              )}
              {selectedChange.executed_at && (
                <div className="timeline-item completed">
                  <div className="timeline-time">{formatDate(selectedChange.executed_at)}</div>
                  <div className="timeline-text">Execution started</div>
                </div>
              )}
              {selectedChange.completed_at && (
                <div className={`timeline-item ${selectedChange.status === 'failed' ? 'failed' : 'completed'}`}>
                  <div className="timeline-time">{formatDate(selectedChange.completed_at)}</div>
                  <div className="timeline-text">
                    {selectedChange.status === 'failed' ? 'Failed' :
                     selectedChange.status === 'rolled_back' ? 'Rolled back' : 'Completed'}
                  </div>
                </div>
              )}
            </div>
          </div>

          {selectedChange.pre_state && (
            <div className="change-detail-section">
              <h4>Pre-Change State</h4>
              <div className="command-list">
                <code>Config Lines: {selectedChange.pre_state.running_config?.split('\n').length || 0}</code>
                <code>Interfaces: {selectedChange.pre_state.interfaces?.length || 0}</code>
                <code>Routes: {selectedChange.pre_state.routes?.length || 0}</code>
                <code>Neighbors: {selectedChange.pre_state.neighbors?.length || 0}</code>
                {selectedChange.pre_state.captured_at && (
                  <code>Captured: {new Date(selectedChange.pre_state.captured_at).toLocaleString()}</code>
                )}
              </div>
            </div>
          )}
          </div>
        </div>
        </div>
      </div>
    );
  }

  return (
    <div className="change-management-overlay" onClick={onClose}>
      <div className="change-management-panel" onClick={(e) => e.stopPropagation()}>
        <div className="change-management-header">
          <h2>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
            </svg>
            Change Management
          </h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        <div className="change-management">
          {error && <div className="error-message">{error}</div>}

      <div className="change-header">
        <div className="change-filters">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="draft">Draft</option>
            <option value="pending_approval">Pending Approval</option>
            <option value="approved">Approved</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="rolled_back">Rolled Back</option>
            <option value="cancelled">Cancelled</option>
          </select>

          <select
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
          >
            <option value="">All Devices</option>
            {devices.map((device) => (
              <option key={device} value={device}>
                {device}
              </option>
            ))}
          </select>
        </div>

        <button className="btn-create-change" onClick={() => setShowCreateModal(true)}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 5v14M5 12h14" />
          </svg>
          Create Change
        </button>
      </div>

      {loading ? (
        <div className="loading">Loading changes</div>
      ) : changes.length === 0 ? (
        <div className="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <p>No change requests found</p>
          <p>Create your first change request to get started</p>
        </div>
      ) : (
        <table className="change-list">
          <thead>
            <tr>
              <th>ID</th>
              <th>Description</th>
              <th>Device</th>
              <th>Type</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((change) => (
              <tr key={change.id}>
                <td>{change.id.substring(0, 8)}</td>
                <td>{change.description}</td>
                <td>{change.device}</td>
                <td><span className="type-badge">{change.change_type}</span></td>
                <td>
                  <span className={getStatusClass(change.status)}>
                    {change.status.replace('_', ' ')}
                  </span>
                </td>
                <td>{formatDate(change.created_at)}</td>
                <td>
                  <div className="change-actions">
                    <button
                      className="btn-action btn-view"
                      onClick={() => viewChange(change.id)}
                    >
                      View
                    </button>
                    {canApprove(change) && (
                      <button
                        className="btn-action btn-approve"
                        onClick={() => handleAction(change.id, 'approve')}
                      >
                        Approve
                      </button>
                    )}
                    {canExecute(change) && (
                      <button
                        className="btn-action btn-execute"
                        onClick={() => handleAction(change.id, 'execute')}
                      >
                        Execute
                      </button>
                    )}
                    {canCancel(change) && (
                      <button
                        className="btn-action btn-cancel-change"
                        onClick={() => handleAction(change.id, 'cancel')}
                        title="Cancel this change request"
                      >
                        ✕
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {showCreateModal && (
        <div className="change-modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="change-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Create Change Request</h3>
            <form onSubmit={handleCreateChange}>
              <div className="form-row">
                <div className="form-group">
                  <label>Device *</label>
                  <select
                    value={newChange.device}
                    onChange={(e) => setNewChange({ ...newChange, device: e.target.value })}
                    required
                  >
                    <option value="">Select device...</option>
                    {devices.map((device) => (
                      <option key={device} value={device}>
                        {device}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label>Change Type *</label>
                  <select
                    value={newChange.change_type}
                    onChange={(e) => setNewChange({ ...newChange, change_type: e.target.value })}
                    required
                  >
                    {changeTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Description *</label>
                <input
                  type="text"
                  value={newChange.description}
                  onChange={(e) => setNewChange({ ...newChange, description: e.target.value })}
                  placeholder="Brief description of the change..."
                  required
                />
              </div>

              <div className="form-group">
                <label>Configuration Commands *</label>
                <textarea
                  value={newChange.commands}
                  onChange={(e) => setNewChange({ ...newChange, commands: e.target.value })}
                  placeholder="interface GigabitEthernet1&#10;description Updated by change management&#10;no shutdown"
                  required
                />
                <div className="form-hint">One command per line or semicolon-separated</div>
              </div>

              <div className="form-group">
                <label>Validation Commands (optional)</label>
                <textarea
                  value={newChange.validation_checks}
                  onChange={(e) => setNewChange({ ...newChange, validation_checks: e.target.value })}
                  placeholder="show interface GigabitEthernet1&#10;ping 10.0.0.1"
                />
                <div className="form-hint">Commands to verify the change was successful</div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label className="form-checkbox">
                    <input
                      type="checkbox"
                      checked={newChange.require_approval}
                      onChange={(e) => setNewChange({ ...newChange, require_approval: e.target.checked })}
                    />
                    Require approval before execution
                  </label>
                </div>
                <div className="form-group">
                  <label className="form-checkbox">
                    <input
                      type="checkbox"
                      checked={newChange.auto_rollback}
                      onChange={(e) => setNewChange({ ...newChange, auto_rollback: e.target.checked })}
                    />
                    Auto-rollback on validation failure
                  </label>
                </div>
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn-cancel"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-submit"
                  disabled={!newChange.device || !newChange.description || !newChange.commands}
                >
                  Create Change
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
        </div>
      </div>
    </div>
  );
};

export default ChangeManagement;
