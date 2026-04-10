import { useEffect, useRef, useState, useCallback } from 'react';

export interface UseSseStreamOptions {
  /** Full URL for the EventSource (including ?token= if needed). */
  url: string | null;
  /** Called for every `data:` message. */
  onMessage: (data: any) => void;
  /** Base delay in ms for exponential backoff (default 500). */
  baseDelay?: number;
  /** Maximum backoff delay in ms (default 10000). */
  maxDelay?: number;
  /** If no event received for this many ms, reconnect (default 60000). */
  idleTimeoutMs?: number;
  /** Maximum number of consecutive retries before giving up (default 10). */
  maxRetries?: number;
  /** Called when the stream appears to have hit an auth error (immediate close). */
  onAuthError?: () => void;
}

export interface UseSseStreamResult {
  connected: boolean;
  error: string | null;
  retryCount: number;
  /** True when maxRetries has been exhausted - will not reconnect further. */
  exhausted: boolean;
}

/**
 * Reusable hook for SSE streams with exponential backoff reconnection,
 * idle timeout detection, and clean `event: end` handling.
 *
 * Extracted from FridaConsole.tsx SSE pattern (Track 60).
 * Enhanced in Track 102: maxRetries, exhausted flag, onAuthError callback.
 */
export function useSseStream({
  url,
  onMessage,
  baseDelay = 500,
  maxDelay = 10000,
  idleTimeoutMs = 60_000,
  maxRetries = 10,
  onAuthError,
}: UseSseStreamOptions): UseSseStreamResult {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [exhausted, setExhausted] = useState(false);

  const esRef = useRef<EventSource | null>(null);
  const retryRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;
  const onAuthErrorRef = useRef(onAuthError);
  onAuthErrorRef.current = onAuthError;

  const clearTimers = useCallback(() => {
    if (timerRef.current) { clearTimeout(timerRef.current); timerRef.current = null; }
    if (idleTimerRef.current) { clearTimeout(idleTimerRef.current); idleTimerRef.current = null; }
  }, []);

  useEffect(() => {
    if (!url) {
      // No URL - tear down any existing connection
      clearTimers();
      if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
      setConnected(false);
      setError(null);
      setRetryCount(0);
      setExhausted(false);
      retryRef.current = 0;
      return;
    }

    let cancelled = false;

    function resetIdleTimer() {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      if (cancelled) return;
      idleTimerRef.current = setTimeout(() => {
        if (cancelled) return;
        // No events for idleTimeoutMs - close and reconnect
        if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
        setConnected(false);
        setError('Connection idle - reconnecting...');
        scheduleReconnect();
      }, idleTimeoutMs);
    }

    function scheduleReconnect() {
      if (cancelled) return;
      const attempt = retryRef.current + 1;
      retryRef.current = attempt;
      setRetryCount(attempt);

      // Check if we've exhausted retries
      if (attempt > maxRetries) {
        setExhausted(true);
        setError('Connection failed - max retries exhausted.');
        return;
      }

      const delay = Math.min(maxDelay, baseDelay * Math.pow(2, attempt - 1));
      setError(`Stream error. Reconnecting in ${Math.round(delay / 1000)}s...`);
      timerRef.current = setTimeout(() => { if (!cancelled) openSse(); }, delay);
    }

    function openSse() {
      if (cancelled) return;
      try {
        if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
        const es = new EventSource(url!);
        esRef.current = es;
        setError(null);

        const createdAt = Date.now();

        es.onopen = () => {
          if (cancelled) return;
          setConnected(true);
          setExhausted(false);
          retryRef.current = 0;
          setRetryCount(0);
          resetIdleTimer();
        };

        es.onmessage = (ev) => {
          if (cancelled) return;
          resetIdleTimer();
          try {
            const data = JSON.parse(ev.data);
            onMessageRef.current(data);
          } catch {}
        };

        es.addEventListener('end', () => {
          if (cancelled) return;
          clearTimers();
          try { es.close(); } catch {}
          esRef.current = null;
          setConnected(false);
        });

        es.onerror = () => {
          try { es.close(); } catch {}
          esRef.current = null;
          if (cancelled) return;
          setConnected(false);

          // Heuristic: if the connection errored very quickly (< 200ms) after
          // creation and readyState is CLOSED, it's likely an auth (401) error.
          const elapsed = Date.now() - createdAt;
          if (elapsed < 200 && es.readyState === EventSource.CLOSED) {
            onAuthErrorRef.current?.();
          }

          scheduleReconnect();
        };
      } catch {
        if (cancelled) return;
        setConnected(false);
        scheduleReconnect();
      }
    }

    openSse();

    return () => {
      cancelled = true;
      clearTimers();
      if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
      setConnected(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, baseDelay, maxDelay, idleTimeoutMs, maxRetries]);

  return { connected, error, retryCount, exhausted };
}
