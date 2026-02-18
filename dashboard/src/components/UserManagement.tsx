/**
 * User Management Panel
 * Provides UI for managing users, groups, and permissions
 */

import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';

interface User {
  id: number;
  username: string;
  role: string;
  is_active: boolean;
  groups: { id: number; name: string }[];
  created_at: string;
  last_login: string | null;
}

interface Group {
  id: number;
  name: string;
  description: string;
  permissions: string[];
}

interface UserManagementProps {
  isOpen: boolean;
  onClose: () => void;
}

const UserManagement: React.FC<UserManagementProps> = ({ isOpen, onClose }) => {
  const { getAuthHeaders } = useAuth();

  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);

  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [selectedGroups, setSelectedGroups] = useState<number[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const [usersRes, groupsRes] = await Promise.all([
        fetch(API.authUsers, { headers }),
        fetch(API.authGroups, { headers }),
      ]);
      if (!usersRes.ok || !groupsRes.ok) throw new Error('Failed to fetch data');
      setUsers(await usersRes.json());
      setGroups(await groupsRes.json());
    } catch (err) {
      setError('Failed to load user data');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  useEffect(() => {
    if (isOpen) fetchData();
  }, [isOpen, fetchData]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSaving(true);
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const createRes = await fetch(API.authUsers, {
        method: 'POST', headers,
        body: JSON.stringify({ username: newUsername, password: newPassword, role: 'operator' }),
      });
      if (!createRes.ok) {
        const data = await createRes.json();
        throw new Error(data.error || 'Failed to create user');
      }
      if (selectedGroups.length > 0) {
        await fetch(`${API.authUsers}/${newUsername}/groups`, {
          method: 'PUT', headers,
          body: JSON.stringify({ group_ids: selectedGroups }),
        });
      }
      setNewUsername(''); setNewPassword(''); setSelectedGroups([]);
      setShowAddModal(false);
      fetchData();
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateGroups = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    setFormError(null);
    setSaving(true);
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const res = await fetch(`${API.authUsers}/${selectedUser.username}/groups`, {
        method: 'PUT', headers,
        body: JSON.stringify({ group_ids: selectedGroups }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to update groups');
      }
      setShowEditModal(false);
      setSelectedUser(null);
      fetchData();
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteUser = async (hardDelete: boolean = false) => {
    if (!userToDelete) return;
    setSaving(true);
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const url = hardDelete
        ? `${API.authUsers}/${userToDelete.username}?hard=true`
        : `${API.authUsers}/${userToDelete.username}`;
      const res = await fetch(url, { method: 'DELETE', headers });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to delete user');
      }
      setShowDeleteConfirm(false);
      setUserToDelete(null);
      fetchData();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleReactivate = async (user: User) => {
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const res = await fetch(`${API.authUsers}/${user.username}/reactivate`, {
        method: 'POST', headers,
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to reactivate user');
      }
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const openEditModal = (user: User) => {
    setSelectedUser(user);
    setSelectedGroups(user.groups.map(g => g.id));
    setFormError(null);
    setShowEditModal(true);
  };

  const openDeleteConfirm = (user: User) => {
    setUserToDelete(user);
    setShowDeleteConfirm(true);
  };

  const toggleGroup = (groupId: number) => {
    setSelectedGroups(prev =>
      prev.includes(groupId) ? prev.filter(id => id !== groupId) : [...prev, groupId]
    );
  };

  if (!isOpen) return null;

  return (
    <div className="user-management-overlay" onClick={onClose}>
      <div className="user-management-panel" onClick={e => e.stopPropagation()}>
        <div className="user-management-header">
          <h2>User Management</h2>
          <div className="header-actions">
            <button className="add-user-btn" onClick={() => {
              setNewUsername(''); setNewPassword(''); setSelectedGroups([]); setFormError(null);
              setShowAddModal(true);
            }}>+ Add User</button>
            <button className="close-btn" onClick={onClose}>x</button>
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}

        <div className="user-management-content">
          {loading ? (
            <div className="loading">Loading users...</div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Groups</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id} className={!user.is_active ? 'inactive' : ''}>
                    <td className="username-cell">
                      <span className="username">{user.username}</span>
                      {user.role === 'admin' && <span className="admin-badge">Admin</span>}
                    </td>
                    <td className="groups-cell">
                      {user.groups.length > 0 ? (
                        user.groups.map(g => <span key={g.id} className="group-tag">{g.name}</span>)
                      ) : (
                        <span className="no-groups">No groups</span>
                      )}
                    </td>
                    <td>
                      <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                        {user.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="last-login">
                      {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="actions-cell">
                      {user.is_active ? (
                        <>
                          <button className="action-btn edit" onClick={() => openEditModal(user)} title="Edit groups">Edit</button>
                          {user.username !== 'admin' && (
                            <button className="action-btn delete" onClick={() => openDeleteConfirm(user)} title="Delete user">Delete</button>
                          )}
                        </>
                      ) : (
                        <>
                          <button className="action-btn reactivate" onClick={() => handleReactivate(user)} title="Reactivate user">Reactivate</button>
                          <button className="action-btn delete" onClick={() => openDeleteConfirm(user)} title="Permanently delete">Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {showAddModal && (
          <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
            <div className="modal" onClick={e => e.stopPropagation()}>
              <h3>Add New User</h3>
              <form onSubmit={handleCreateUser}>
                {formError && <div className="form-error">{formError}</div>}
                <div className="form-group">
                  <label>Username</label>
                  <input type="text" value={newUsername} onChange={e => setNewUsername(e.target.value)} required autoFocus />
                </div>
                <div className="form-group">
                  <label>Password</label>
                  <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} required minLength={4} />
                </div>
                <div className="form-group">
                  <label>Groups</label>
                  <div className="group-checkboxes">
                    {groups.map(group => (
                      <label key={group.id} className="checkbox-label">
                        <input type="checkbox" checked={selectedGroups.includes(group.id)} onChange={() => toggleGroup(group.id)} />
                        <span>{group.name}</span>
                        <small>{group.description}</small>
                      </label>
                    ))}
                  </div>
                </div>
                <div className="modal-actions">
                  <button type="button" onClick={() => setShowAddModal(false)}>Cancel</button>
                  <button type="submit" className="primary" disabled={saving}>{saving ? 'Creating...' : 'Create User'}</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {showEditModal && selectedUser && (
          <div className="modal-overlay" onClick={() => setShowEditModal(false)}>
            <div className="modal" onClick={e => e.stopPropagation()}>
              <h3>Edit User: {selectedUser.username}</h3>
              <form onSubmit={handleUpdateGroups}>
                {formError && <div className="form-error">{formError}</div>}
                <div className="form-group">
                  <label>Groups</label>
                  <div className="group-checkboxes">
                    {groups.map(group => (
                      <label key={group.id} className="checkbox-label">
                        <input type="checkbox" checked={selectedGroups.includes(group.id)} onChange={() => toggleGroup(group.id)} />
                        <span>{group.name}</span>
                        <small>{group.description}</small>
                      </label>
                    ))}
                  </div>
                </div>
                <div className="modal-actions">
                  <button type="button" onClick={() => setShowEditModal(false)}>Cancel</button>
                  <button type="submit" className="primary" disabled={saving}>{saving ? 'Saving...' : 'Save Changes'}</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {showDeleteConfirm && userToDelete && (
          <div className="modal-overlay" onClick={() => setShowDeleteConfirm(false)}>
            <div className="modal delete-modal" onClick={e => e.stopPropagation()}>
              <h3>Delete User</h3>
              <p>Are you sure you want to delete <strong>{userToDelete.username}</strong>?</p>
              <div className="delete-options">
                <button className="deactivate-btn" onClick={() => handleDeleteUser(false)} disabled={saving || !userToDelete.is_active}>
                  {!userToDelete.is_active ? 'Already Deactivated' : 'Deactivate'}
                </button>
                <p className="option-desc">User cannot login but data is preserved.</p>
                <button className="hard-delete-btn" onClick={() => handleDeleteUser(true)} disabled={saving}>Permanently Delete</button>
                <p className="option-desc warning">This action cannot be undone.</p>
              </div>
              <div className="modal-actions">
                <button onClick={() => setShowDeleteConfirm(false)}>Cancel</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UserManagement;
