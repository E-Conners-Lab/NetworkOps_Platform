/**
 * Authenticated App Wrapper
 * Shows Login screen when not authenticated, otherwise shows the main App
 * Handles SSO callback at /auth-callback
 */

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import App from '../App';
import Login from './Login';
import UserManagement from './UserManagement';
import AuthCallback from '../pages/AuthCallback';

const AuthenticatedApp: React.FC = () => {
  const { isAuthenticated, isLoading, user, logout } = useAuth();
  const [showUserManagement, setShowUserManagement] = useState(false);

  // Handle SSO callback route
  if (window.location.pathname === '/auth-callback') {
    return <AuthCallback />;
  }

  if (isLoading) {
    return (
      <div style={styles.loading}>
        <div style={styles.spinner} />
        <p>Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <>
      {/* User info bar */}
      <div style={styles.userBar}>
        <span style={styles.userInfo}>
          Logged in as <strong>{user?.username}</strong>
          <span style={styles.roleBadge}>{user?.role}</span>
        </span>
        <div style={styles.buttonGroup}>
          {user?.role === 'admin' && (
            <button onClick={() => setShowUserManagement(true)} style={styles.usersButton}>
              Users
            </button>
          )}
          <button onClick={logout} style={styles.logoutButton}>
            Logout
          </button>
        </div>
      </div>
      <App />
      <UserManagement isOpen={showUserManagement} onClose={() => setShowUserManagement(false)} />
    </>
  );
};

// =============================================================================
// Styles
// =============================================================================
const styles: { [key: string]: React.CSSProperties } = {
  loading: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#1a1a2e',
    color: '#fff',
    gap: '16px',
  },
  spinner: {
    width: '40px',
    height: '40px',
    border: '3px solid #2d2d44',
    borderTopColor: '#4361ee',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  },
  userBar: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'center',
    padding: '8px 16px',
    backgroundColor: '#16213e',
    borderBottom: '1px solid #2d2d44',
    gap: '16px',
  },
  buttonGroup: {
    display: 'flex',
    gap: '8px',
  },
  usersButton: {
    backgroundColor: '#4361ee',
    border: 'none',
    borderRadius: '6px',
    padding: '6px 12px',
    color: '#fff',
    fontSize: '14px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  userInfo: {
    color: '#ccd6f6',
    fontSize: '14px',
  },
  roleBadge: {
    marginLeft: '8px',
    padding: '2px 8px',
    backgroundColor: '#4361ee',
    borderRadius: '4px',
    fontSize: '12px',
    textTransform: 'uppercase',
  },
  logoutButton: {
    backgroundColor: 'transparent',
    border: '1px solid #4361ee',
    borderRadius: '6px',
    padding: '6px 12px',
    color: '#4361ee',
    fontSize: '14px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
};

export default AuthenticatedApp;
