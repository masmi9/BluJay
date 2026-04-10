import { useState, useEffect, useCallback, useRef } from 'react';
import { secureFetch } from '../lib/api';

export interface UseApiQueryOptions<T> {
  /** Transform raw JSON response before storing. */
  transform?: (data: any) => T;
  /** Poll interval in ms. 0 = no polling. */
  pollIntervalMs?: number;
  /** Swallow errors silently (sets data to null, no error state). */
  silentError?: boolean;
  /** Set false to defer fetching until condition is met. */
  enabled?: boolean;
  /** Extra fetch init options (method, headers, body). */
  fetchInit?: RequestInit;
}

export interface UseApiQueryResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

/**
 * Fetch data from an API path with loading/error state, polling, and abort support.
 */
export function useApiQuery<T = any>(
  path: string | null,
  options?: UseApiQueryOptions<T>,
): UseApiQueryResult<T> {
  const {
    transform,
    pollIntervalMs = 0,
    silentError = false,
    enabled = true,
    fetchInit,
  } = options ?? {};

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const abortRef = useRef<AbortController | null>(null);

  // Stable refs for options that shouldn't trigger re-fetch
  const transformRef = useRef(transform);
  transformRef.current = transform;
  const silentErrorRef = useRef(silentError);
  silentErrorRef.current = silentError;
  const fetchInitRef = useRef(fetchInit);
  fetchInitRef.current = fetchInit;

  const doFetch = useCallback(async () => {
    if (!path || !enabled) return;

    // Abort previous in-flight request
    if (abortRef.current) {
      try { abortRef.current.abort(); } catch { /* ignore */ }
    }
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    try {
      const init: RequestInit = { ...(fetchInitRef.current || {}), signal: ac.signal };
      const r = await secureFetch(path, init);
      if (!mountedRef.current) return;
      if (!r.ok) throw new Error(`${r.status}`);
      const json = await r.json();
      if (!mountedRef.current) return;
      const result = transformRef.current ? transformRef.current(json) : json as T;
      setData(result);
      setError(null);
    } catch (e: any) {
      if (!mountedRef.current) return;
      if (e?.name === 'AbortError') return;
      if (silentErrorRef.current) {
        setData(null);
        setError(null);
      } else {
        setError(e?.message || 'Request failed');
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [path, enabled]);

  // Initial fetch
  useEffect(() => {
    mountedRef.current = true;
    doFetch();
    return () => {
      mountedRef.current = false;
      if (abortRef.current) {
        try { abortRef.current.abort(); } catch { /* ignore */ }
      }
    };
  }, [doFetch]);

  // Polling
  useEffect(() => {
    if (!pollIntervalMs || pollIntervalMs <= 0 || !enabled || !path) return;
    const id = setInterval(doFetch, pollIntervalMs);
    return () => clearInterval(id);
  }, [doFetch, pollIntervalMs, enabled, path]);

  return { data, loading, error, refetch: doFetch };
}
