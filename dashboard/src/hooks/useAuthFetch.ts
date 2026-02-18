/**
 * useAuthFetch Hook
 * Provides authenticated fetch functions that automatically include JWT tokens
 */

import { useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

interface FetchOptions extends RequestInit {
  skipAuth?: boolean;
}

export const useAuthFetch = () => {
  const { getAuthHeaders, logout } = useAuth();

  const authFetch = useCallback(
    async (url: string, options: FetchOptions = {}): Promise<Response> => {
      const { skipAuth, headers: customHeaders, ...restOptions } = options;

      // Merge auth headers with custom headers
      const headers: HeadersInit = {
        ...getAuthHeaders(),
        ...(customHeaders as Record<string, string>),
      };

      // Add Content-Type for JSON if body is present and not FormData
      if (restOptions.body && !(restOptions.body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
      }

      const response = await fetch(url, {
        ...restOptions,
        headers,
      });

      // Handle 401 - token expired or invalid
      if (response.status === 401 && !skipAuth) {
        logout();
      }

      return response;
    },
    [getAuthHeaders, logout]
  );

  // Convenience methods
  const get = useCallback(
    (url: string, options?: FetchOptions) => authFetch(url, { ...options, method: 'GET' }),
    [authFetch]
  );

  const post = useCallback(
    (url: string, data?: unknown, options?: FetchOptions) =>
      authFetch(url, {
        ...options,
        method: 'POST',
        body: data ? JSON.stringify(data) : undefined,
      }),
    [authFetch]
  );

  const put = useCallback(
    (url: string, data?: unknown, options?: FetchOptions) =>
      authFetch(url, {
        ...options,
        method: 'PUT',
        body: data ? JSON.stringify(data) : undefined,
      }),
    [authFetch]
  );

  const del = useCallback(
    (url: string, options?: FetchOptions) => authFetch(url, { ...options, method: 'DELETE' }),
    [authFetch]
  );

  return {
    authFetch,
    get,
    post,
    put,
    delete: del,
  };
};

export default useAuthFetch;
