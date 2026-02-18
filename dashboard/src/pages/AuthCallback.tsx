/**
 * SSO Authentication Callback
 *
 * Handles the redirect back from an SSO provider (e.g., SAML IdP).
 * Extracts token data from URL parameters and sets auth state.
 */

import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';

const AuthCallback: React.FC = () => {
  const { setTokens } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const refreshToken = params.get('refresh_token');
    const username = params.get('username');

    if (token && username) {
      setTokens({
        token,
        refreshToken: refreshToken || '',
        username,
        permissions: (params.get('permissions') || '').split(',').filter(Boolean),
        groups: (params.get('groups') || '').split(',').filter(Boolean),
      });
      window.location.href = '/';
    } else {
      setError('SSO authentication failed. Missing token or username.');
    }
  }, [setTokens]);

  if (error) {
    return (
      <div style={styles.container}>
        <p style={styles.error}>{error}</p>
        <a href="/" style={styles.link}>Return to login</a>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <p>Completing authentication...</p>
    </div>
  );
};

const styles: { [key: string]: React.CSSProperties } = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#1a1a2e',
    color: '#fff',
    gap: '16px',
  },
  error: {
    color: '#f38ba8',
  },
  link: {
    color: '#4361ee',
  },
};

export default AuthCallback;
