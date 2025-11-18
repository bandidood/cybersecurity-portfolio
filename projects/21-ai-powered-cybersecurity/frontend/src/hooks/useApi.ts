/**
 * Custom React Hooks for API interactions
 * Provides reusable hooks for common API patterns with loading, error handling, and caching
 */

import { useState, useEffect, useCallback } from 'react';
import { AxiosResponse, AxiosError } from 'axios';
import { toast } from 'react-hot-toast';

// ==================== Generic API Hook ====================

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
}

interface UseApiOptions {
  onSuccess?: (data: any) => void;
  onError?: (error: Error) => void;
  immediate?: boolean;
}

/**
 * Generic hook for API calls with loading and error states
 */
export function useApi<T = any>(
  apiFunction: (...args: any[]) => Promise<AxiosResponse<T>>,
  options: UseApiOptions = {}
) {
  const { onSuccess, onError, immediate = false } = options;

  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });

  const execute = useCallback(
    async (...args: any[]) => {
      setState({ data: null, loading: true, error: null });

      try {
        const response = await apiFunction(...args);
        setState({ data: response.data, loading: false, error: null });

        if (onSuccess) {
          onSuccess(response.data);
        }

        return response.data;
      } catch (err) {
        const error = err as AxiosError;
        setState({ data: null, loading: false, error: error as Error });

        if (onError) {
          onError(error as Error);
        } else {
          console.error('API Error:', error);
        }

        throw error;
      }
    },
    [apiFunction, onSuccess, onError]
  );

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [immediate, execute]);

  return {
    ...state,
    execute,
    reset: () => setState({ data: null, loading: false, error: null }),
  };
}

// ==================== Specific Hooks ====================

/**
 * Hook for fetching data with automatic refresh
 */
export function useFetch<T = any>(
  apiFunction: () => Promise<AxiosResponse<T>>,
  dependencies: any[] = [],
  options: UseApiOptions = {}
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await apiFunction();
      setData(response.data);

      if (options.onSuccess) {
        options.onSuccess(response.data);
      }
    } catch (err) {
      const error = err as AxiosError;
      setError(error as Error);

      if (options.onError) {
        options.onError(error as Error);
      }
    } finally {
      setLoading(false);
    }
  }, [apiFunction, options]);

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return { data, loading, error, refetch: fetchData };
}

/**
 * Hook for mutations (POST, PUT, PATCH, DELETE)
 */
export function useMutation<T = any, V = any>(
  apiFunction: (variables: V) => Promise<AxiosResponse<T>>,
  options: UseApiOptions = {}
) {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });

  const mutate = useCallback(
    async (variables: V) => {
      setState({ data: null, loading: true, error: null });

      try {
        const response = await apiFunction(variables);
        setState({ data: response.data, loading: false, error: null });

        toast.success('Operation completed successfully');

        if (options.onSuccess) {
          options.onSuccess(response.data);
        }

        return response.data;
      } catch (err) {
        const error = err as AxiosError;
        setState({ data: null, loading: false, error: error as Error });

        if (options.onError) {
          options.onError(error as Error);
        }

        throw error;
      }
    },
    [apiFunction, options]
  );

  return {
    ...state,
    mutate,
    reset: () => setState({ data: null, loading: false, error: null }),
  };
}

/**
 * Hook for polling data at regular intervals
 */
export function usePoll<T = any>(
  apiFunction: () => Promise<AxiosResponse<T>>,
  interval: number = 5000,
  enabled: boolean = true
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const fetchData = async () => {
      try {
        const response = await apiFunction();
        setData(response.data);
        setError(null);
      } catch (err) {
        setError(err as Error);
      } finally {
        setLoading(false);
      }
    };

    // Initial fetch
    fetchData();

    // Setup polling
    const pollInterval = setInterval(fetchData, interval);

    return () => clearInterval(pollInterval);
  }, [apiFunction, interval, enabled]);

  return { data, loading, error };
}

/**
 * Hook for WebSocket connections
 */
export function useWebSocket(url: string) {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);

  useEffect(() => {
    const ws = new WebSocket(url);

    ws.onopen = () => {
      setConnected(true);
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      setLastMessage(message);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('WebSocket disconnected');
    };

    setSocket(ws);

    return () => {
      ws.close();
    };
  }, [url]);

  const send = useCallback(
    (data: any) => {
      if (socket && connected) {
        socket.send(JSON.stringify(data));
      }
    },
    [socket, connected]
  );

  return { socket, connected, lastMessage, send };
}

export default useApi;
