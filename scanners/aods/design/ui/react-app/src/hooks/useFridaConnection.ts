import { useEffect, useRef, useState, useCallback } from 'react';
import { getApiBase, secureFetch } from '../lib/api';

function getToken(): string | null {
  try {
    const raw = localStorage.getItem('aodsAuth');
    if (!raw) return null;
    const j = JSON.parse(raw);
    return typeof j?.token === 'string' ? j.token : null;
  } catch {
    return null;
  }
}

async function buildWsUrl(): Promise<string> {
  const base = await getApiBase();
  try {
    const apiUrl = new URL(base, window.location.href);
    const wsBase = `${apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'}//${apiUrl.host}${apiUrl.pathname.replace(/\/$/, '')}`;
    return `${wsBase}/frida/ws`;
  } catch {
    const origin = window.location.origin.replace(/^http/, 'ws');
    return `${origin}${base.replace(/\/$/, '')}/frida/ws`;
  }
}

async function mintWsToken(): Promise<string> {
  const r = await secureFetch(`/frida/ws-token`, { method: 'POST' });
  if (!r.ok) throw new Error('WS token mint failed');
  const { token: wsTok } = await r.json();
  return wsTok;
}

async function openWsWithRetry(
  buildUrl: () => Promise<string>,
  mintToken: () => Promise<string>,
  onOpen: (ws: WebSocket) => void,
  onMessage: (ev: MessageEvent) => void,
  onError: (msg: string) => void,
) {
  let attempt = 0;
  const maxAttempts = 3;
  while (attempt < maxAttempts) {
    attempt++;
    try {
      const baseUrl = await buildUrl();
      const wsTok = await mintToken();
      const urlWithQuery = baseUrl.includes('?')
        ? `${baseUrl}&token=${encodeURIComponent(wsTok)}`
        : `${baseUrl}?token=${encodeURIComponent(wsTok)}`;
      const ws = new WebSocket(urlWithQuery, ['aods-frida', `token.${wsTok}`]);
      const timer = window.setTimeout(() => {
        try { ws.close(); } catch {}
      }, 8000);
      ws.onopen = () => { window.clearTimeout(timer); onOpen(ws); };
      ws.onmessage = onMessage;
      ws.onerror = () => { window.clearTimeout(timer); onError('WS error'); };
      ws.onclose = (ev) => {
        window.clearTimeout(timer);
        if (attempt >= maxAttempts) onError(`WS closed (${ev.code})`);
      };
      return;
    } catch (e: any) {
      if (attempt >= maxAttempts) onError(e?.message || 'WS init failed');
      await new Promise(r => setTimeout(r, 500 * attempt));
    }
  }
}

export interface UseFridaConnectionOptions {
  /** Package name for SSE event stream path. */
  pkg: string;
  /** Auth token (from useAuth). Triggers reconnect on change. */
  authToken: string | null;
  /** Whether to auto-connect WebSocket with exponential backoff. */
  autoConnectWs: boolean;
  /** Called when a WS message arrives (raw string data). */
  onWsMessage?: (data: string) => void;
  /** Called when an SSE event arrives. */
  onSseEvent?: (event: { ts?: string; script?: string; msg?: any }) => void;
  /** Called when an error occurs. */
  onError?: (msg: string) => void;
}

export interface UseFridaConnectionResult {
  wsStatus: 'disconnected' | 'connecting' | 'connected';
  wsLast: string;
  esConnected: boolean;
  wsReconnectMsg: string;
  wsRef: React.MutableRefObject<WebSocket | null>;
  esRef: React.MutableRefObject<EventSource | null>;
  /** Manually connect WebSocket. */
  connectWs: () => Promise<void>;
  /** Manually disconnect WebSocket + SSE. */
  disconnectAll: () => void;
  /** Send a message over WebSocket. */
  sendWs: (data: string) => void;
  /** Exposed for child components that need it (e.g. FridaHeaderBar). */
  buildWsUrl: () => Promise<string>;
  /** Exposed for child components that need it. */
  openWsWithRetry: typeof openWsWithRetry;
  setWsStatus: React.Dispatch<React.SetStateAction<'disconnected' | 'connecting' | 'connected'>>;
  setWsLast: React.Dispatch<React.SetStateAction<string>>;
}

/**
 * Manages Frida WebSocket + SSE connection lifecycle with reconnection logic.
 * Extracted from FridaConsole.tsx to reduce component complexity.
 */
export function useFridaConnection({
  pkg,
  authToken,
  autoConnectWs,
  onWsMessage,
  onSseEvent,
  onError,
}: UseFridaConnectionOptions): UseFridaConnectionResult {
  const wsRef = useRef<WebSocket | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const [wsStatus, setWsStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  const [wsLast, setWsLast] = useState<string>('');
  const [esConnected, setEsConnected] = useState<boolean>(false);
  const [wsReconnectMsg, setWsReconnectMsg] = useState<string>('');

  const sseRetryRef = useRef<number>(0);
  const sseTimerRef = useRef<any>(null);
  const wsRetryRef = useRef<number>(0);
  const wsTimerRef = useRef<any>(null);

  // Stable refs for callbacks to avoid re-triggering effects
  const onWsMessageRef = useRef(onWsMessage);
  onWsMessageRef.current = onWsMessage;
  const onSseEventRef = useRef(onSseEvent);
  onSseEventRef.current = onSseEvent;
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const connectWs = useCallback(async () => {
    try {
      if (wsRef.current && wsStatus === 'connected') return;
      setWsStatus('connecting');
      const token = getToken();
      if (!token) { setWsStatus('disconnected'); return; }
      await openWsWithRetry(
        buildWsUrl,
        mintWsToken,
        (ws) => {
          wsRef.current = ws;
          setWsStatus('connected');
          try {
            ws.onclose = () => { setWsStatus('disconnected'); };
          } catch {}
        },
        (ev) => {
          const data = String(ev.data || '');
          setWsLast(data);
          onWsMessageRef.current?.(data);
        },
        (msg) => {
          onErrorRef.current?.(msg);
          setWsStatus('disconnected');
        },
      );
    } catch {
      setWsStatus('disconnected');
      onErrorRef.current?.('WebSocket init failed');
    }
  }, [wsStatus]);

  const disconnectAll = useCallback(() => {
    try { wsRef.current?.close(); } catch {}
    wsRef.current = null;
    setWsStatus('disconnected');
    try { esRef.current?.close(); } catch {}
    esRef.current = null;
    setEsConnected(false);
  }, []);

  const sendWs = useCallback((data: string) => {
    try { wsRef.current?.send(data); } catch {}
  }, []);

  // Auto-connect WS with exponential backoff
  useEffect(() => {
    let cancelled = false;
    async function maybeConnect() {
      try {
        if (!autoConnectWs) { wsRetryRef.current = 0; setWsReconnectMsg(''); return; }
        if (wsStatus !== 'disconnected') { wsRetryRef.current = 0; setWsReconnectMsg(''); return; }
        const token = getToken();
        if (!token) return;
        const attempt = wsRetryRef.current;
        const delay = attempt > 0 ? Math.min(30000, 1000 * Math.pow(2, attempt - 1)) : 0;
        if (delay > 0) {
          setWsReconnectMsg(`Reconnecting in ${Math.round(delay / 1000)}s (attempt ${attempt})...`);
          if (wsTimerRef.current) { try { clearTimeout(wsTimerRef.current); } catch {} }
          wsTimerRef.current = setTimeout(() => { if (!cancelled) maybeConnect(); }, delay);
          return;
        }
        setWsReconnectMsg('');
        setWsStatus('connecting');
        await openWsWithRetry(
          buildWsUrl,
          mintWsToken,
          (ws) => {
            if (cancelled) { try { ws.close(); } catch {} return; }
            wsRef.current = ws;
            wsRetryRef.current = 0;
            setWsReconnectMsg('');
            setWsStatus('connected');
            ws.onclose = () => { setWsStatus('disconnected'); wsRetryRef.current += 1; };
          },
          (ev) => {
            const data = String(ev.data || '');
            setWsLast(data);
            onWsMessageRef.current?.(data);
          },
          (msg) => {
            onErrorRef.current?.(msg);
            setWsStatus('disconnected');
            wsRetryRef.current += 1;
          },
        );
      } catch {
        setWsStatus('disconnected');
        wsRetryRef.current += 1;
      }
    }
    maybeConnect();
    return () => {
      cancelled = true;
      if (wsTimerRef.current) { try { clearTimeout(wsTimerRef.current); } catch {} wsTimerRef.current = null; }
    };
  }, [autoConnectWs, wsStatus, authToken]);

  // WS heartbeat
  useEffect(() => {
    if (wsStatus !== 'connected' || !wsRef.current) return;
    const timer = window.setInterval(() => {
      try { wsRef.current?.send(JSON.stringify({ type: 'ping', ts: new Date().toISOString() })); } catch {}
    }, 25000);
    return () => { try { window.clearInterval(timer); } catch {} };
  }, [wsStatus]);

  // SSE stream for events with reconnect/backoff
  useEffect(() => {
    let cancelled = false;
    async function openSse() {
      try {
        const token = getToken();
        if (!token) return;
        const base = await getApiBase();
        if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
        const es = new EventSource(
          `${base}/frida/session/${encodeURIComponent(pkg)}/events/stream?token=${encodeURIComponent(token)}`,
        );
        esRef.current = es;
        es.onopen = () => {
          if (cancelled) return;
          setEsConnected(true);
          sseRetryRef.current = 0;
        };
        es.onmessage = (ev) => {
          try {
            const j = JSON.parse(ev.data);
            onSseEventRef.current?.(j);
          } catch {}
        };
        es.onerror = () => {
          try { es.close(); } catch {}
          if (cancelled) return;
          setEsConnected(false);
          const attempt = sseRetryRef.current + 1;
          sseRetryRef.current = attempt;
          const delay = Math.min(10000, 500 * Math.pow(2, attempt - 1));
          if (sseTimerRef.current) { try { clearTimeout(sseTimerRef.current); } catch {} }
          sseTimerRef.current = setTimeout(() => { if (!cancelled) openSse(); }, delay);
        };
      } catch {
        if (cancelled) return;
        const attempt = sseRetryRef.current + 1;
        sseRetryRef.current = attempt;
        const delay = Math.min(10000, 500 * Math.pow(2, attempt - 1));
        if (sseTimerRef.current) { try { clearTimeout(sseTimerRef.current); } catch {} }
        sseTimerRef.current = setTimeout(() => { if (!cancelled) openSse(); }, delay);
      }
    }
    openSse();
    return () => {
      cancelled = true;
      if (sseTimerRef.current) { try { clearTimeout(sseTimerRef.current); } catch {} sseTimerRef.current = null; }
      if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
      setEsConnected(false);
    };
  }, [pkg, authToken]);

  return {
    wsStatus,
    wsLast,
    esConnected,
    wsReconnectMsg,
    wsRef,
    esRef,
    connectWs,
    disconnectAll,
    sendWs,
    buildWsUrl,
    openWsWithRetry,
    setWsStatus,
    setWsLast,
  };
}
