/**
 * API Utilities
 * Provides authenticated fetch functions for API calls
 */

import { safeLocalStorage } from './safeLocalStorage';

const TOKEN_KEY = 'dashboard_token';

/**
 * Get the stored auth token
 */
export const getToken = (): string | null => {
  return safeLocalStorage.getItem(TOKEN_KEY);
};

/**
 * Get authorization headers if token exists
 */
export const getAuthHeaders = (): Record<string, string> => {
  const token = getToken();
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
};

/**
 * Authenticated fetch wrapper
 * Automatically adds JWT token to requests
 */
export const authFetch = async (
  url: string,
  options: RequestInit = {}
): Promise<Response> => {
  const headers: Record<string, string> = {
    ...getAuthHeaders(),
    ...(options.headers as Record<string, string>),
  };

  // Add Content-Type for JSON if body is present
  if (options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  // Handle 401 - clear token and redirect to force re-login
  if (response.status === 401) {
    safeLocalStorage.removeItem(TOKEN_KEY);
    safeLocalStorage.removeItem('dashboard_user');
    window.location.href = '/';
  }

  return response;
};

/**
 * POST request with authentication
 */
export const authPost = async (
  url: string,
  data: unknown
): Promise<Response> => {
  return authFetch(url, {
    method: 'POST',
    body: JSON.stringify(data),
  });
};

/**
 * GET request with authentication
 */
export const authGet = async (url: string): Promise<Response> => {
  return authFetch(url, { method: 'GET' });
};
