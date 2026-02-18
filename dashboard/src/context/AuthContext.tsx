/**
 * Authentication Context
 * Provides JWT-based authentication state and methods to the React app
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { API } from '../config';
import { safeLocalStorage } from '../utils/safeLocalStorage';

// =============================================================================
// Types
// =============================================================================
interface User {
  username: string;
  role: 'admin' | 'operator';
  permissions: string[];
  groups: string[];
}

interface SSOTokenData {
  token: string;
  refreshToken: string;
  username: string;
  permissions: string[];
  groups: string[];
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  getAuthHeaders: () => { Authorization: string } | {};
  hasPermission: (permission: string) => boolean;
  setTokens: (data: SSOTokenData) => void;
}

// =============================================================================
// Context
// =============================================================================
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// =============================================================================
// Storage Keys
// =============================================================================
const TOKEN_KEY = 'dashboard_token';
const USER_KEY = 'dashboard_user';

// =============================================================================
// Provider Component
// =============================================================================
interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load saved auth state on mount
  useEffect(() => {
    const savedToken = safeLocalStorage.getItem(TOKEN_KEY);
    const savedUser = safeLocalStorage.getItem(USER_KEY);

    if (savedToken && savedUser) {
      // Verify token is still valid
      verifyToken(savedToken).then((isValid) => {
        if (isValid) {
          setToken(savedToken);
          // Parse saved user and add defaults for new fields
          try {
            const parsedUser = JSON.parse(savedUser);
            setUser({
              ...parsedUser,
              permissions: parsedUser.permissions || [],
              groups: parsedUser.groups || [],
            });
          } catch {
            // Corrupt JSON in storage — clear and force re-login
            safeLocalStorage.removeItem(TOKEN_KEY);
            safeLocalStorage.removeItem(USER_KEY);
          }
        } else {
          // Token expired, clear storage
          safeLocalStorage.removeItem(TOKEN_KEY);
          safeLocalStorage.removeItem(USER_KEY);
        }
        setIsLoading(false);
      });
    } else {
      setIsLoading(false);
    }
  }, []);

  // Verify token with backend
  const verifyToken = async (tokenToVerify: string): Promise<boolean> => {
    try {
      const response = await fetch(API.authVerify, {
        headers: {
          Authorization: `Bearer ${tokenToVerify}`,
        },
      });
      const data = await response.json();
      return data.valid === true;
    } catch {
      return false;
    }
  };

  // Login function
  const login = useCallback(async (username: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const response = await fetch(API.authLogin, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok && data.token) {
        // Get permissions and groups from login response
        const permissions = data.permissions || [];
        const groups = data.groups || [];

        // Determine role based on permissions (for backwards compatibility)
        const hasAdminPerms = permissions.includes('manage_users') || permissions.includes('manage_groups');
        const role = hasAdminPerms ? 'admin' : 'operator';

        const newUser: User = {
          username: data.username,
          role: role as 'admin' | 'operator',
          permissions,
          groups,
        };

        // Save to state and storage
        setToken(data.token);
        setUser(newUser);
        safeLocalStorage.setItem(TOKEN_KEY, data.token);
        safeLocalStorage.setItem(USER_KEY, JSON.stringify(newUser));

        return { success: true };
      } else {
        return { success: false, error: data.error || 'Login failed' };
      }
    } catch (error) {
      return { success: false, error: 'Network error. Please try again.' };
    }
  }, []);

  // Logout function
  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    safeLocalStorage.removeItem(TOKEN_KEY);
    safeLocalStorage.removeItem(USER_KEY);
  }, []);

  // Get auth headers for API calls
  const getAuthHeaders = useCallback(() => {
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
    return {};
  }, [token]);

  // Check if user has a specific permission
  const hasPermission = useCallback((permission: string): boolean => {
    if (!user) return false;
    return user.permissions.includes(permission);
  }, [user]);

  // Set tokens from SSO callback
  const setTokens = useCallback((data: SSOTokenData) => {
    // Determine role based on permissions
    const hasAdminPerms = data.permissions.includes('manage_users') ||
                         data.permissions.includes('manage_groups');
    const role = hasAdminPerms ? 'admin' : 'operator';

    const newUser: User = {
      username: data.username,
      role: role as 'admin' | 'operator',
      permissions: data.permissions,
      groups: data.groups,
    };

    // Save to state and storage
    setToken(data.token);
    setUser(newUser);
    safeLocalStorage.setItem(TOKEN_KEY, data.token);
    safeLocalStorage.setItem(USER_KEY, JSON.stringify(newUser));

    // Also save refresh token
    safeLocalStorage.setItem('dashboard_refresh_token', data.refreshToken);
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token && !!user,
    isLoading,
    login,
    logout,
    getAuthHeaders,
    hasPermission,
    setTokens,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// =============================================================================
// Hook
// =============================================================================
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
