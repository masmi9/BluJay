import { useState, useEffect, useCallback, useRef } from 'react';
import { secureFetch } from '../lib/api';
import { useLocalStorage } from './useLocalStorage';

export interface RecentRpc {
  fn: string;
  args: string;
  ts: string;
  ms?: number;
  status?: string;
  pinned?: boolean;
}

export interface RpcPreset {
  name: string;
  fn: string;
  args: string;
  tags?: string[];
}

export interface UseFridaRpcResult {
  rpcFn: string;
  setRpcFn: (v: string) => void;
  rpcArgs: string;
  setRpcArgs: (v: string) => void;
  rpcResult: string;
  rpcArgsError: string;
  rpcDurationMs: number | null;
  rpcError: string | null;
  rpcExpandedDetails: boolean;
  setRpcExpandedDetails: React.Dispatch<React.SetStateAction<boolean>>;
  lastRpcIso: string;
  recentRpcs: RecentRpc[];
  setRecentRpcs: React.Dispatch<React.SetStateAction<RecentRpc[]>>;
  rpcPresetName: string;
  setRpcPresetName: (v: string) => void;
  rpcPresets: RpcPreset[];
  rpcPresetSearch: string;
  setRpcPresetSearch: (v: string) => void;
  rpcPresetTag: string;
  setRpcPresetTag: (v: string) => void;
  runRpc: (sessionId: string) => Promise<void>;
  saveRpcPreset: () => void;
  loadRpcPresetByName: (nm: string) => void;
  normalizeRecent: (list: RecentRpc[]) => RecentRpc[];
  formatTime: (iso: string) => string;
  computeShouldCollapse: (text: string) => boolean;
  /** Reset all RPC state to defaults. */
  resetRpcState: () => void;
}

export function normalizeRecent(list: RecentRpc[]): RecentRpc[] {
  try {
    const seen = new Set<string>();
    const dedup: RecentRpc[] = [];
    for (const item of list) {
      const key = `${item.fn}|${item.args}`;
      if (seen.has(key)) {
        const idx = dedup.findIndex(x => `${x.fn}|${x.args}` === key);
        if (idx >= 0 && item.pinned && !dedup[idx].pinned) dedup[idx] = { ...dedup[idx], pinned: true };
        continue;
      }
      seen.add(key);
      dedup.push(item);
    }
    const pinned = dedup.filter(x => x.pinned);
    const unpinned = dedup.filter(x => !x.pinned);
    const max = 10;
    const keepPinned = pinned.slice(0, max);
    const keepUnpinned = unpinned.slice(0, Math.max(0, max - keepPinned.length));
    return [...keepPinned, ...keepUnpinned];
  } catch {
    return list.slice(0, 10);
  }
}

export function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
  } catch {
    return '';
  }
}

export function computeShouldCollapse(text: string): boolean {
  if (!text) return false;
  try { const bytes = new Blob([text]).size; if (bytes > 40960) return true; } catch {}
  const lines = text.split(/\n/).length;
  return lines > 80;
}

export interface UseFridaRpcOptions {
  /** Frida mode header value (read_only/standard/advanced). */
  fridaMode: string;
  /** Package name for the X-Frida-Package header. */
  pkg: string;
  /** Called to append a line to the events log. */
  appendEventLine?: (line: string) => void;
  /** Called to set a connect message. */
  setConnectMsg?: (msg: string) => void;
  /** Called to set an error message. */
  setError?: (msg: string | null) => void;
}

/**
 * Manages Frida RPC state: function name, args, result, presets, and recent calls.
 * Extracted from FridaConsole.tsx to reduce component complexity.
 */
export function useFridaRpc({
  fridaMode,
  pkg,
  appendEventLine,
  setConnectMsg,
  setError,
}: UseFridaRpcOptions): UseFridaRpcResult {
  const [rpcFn, setRpcFn] = useState('noop');
  const [rpcArgs, setRpcArgs] = useState<string>('{}');
  const [rpcResult, setRpcResult] = useState<string>('');
  const [rpcArgsError, setRpcArgsError] = useState<string>('');
  const [rpcDurationMs, setRpcDurationMs] = useState<number | null>(null);
  const [rpcError, setRpcError] = useState<string | null>(null);
  const [rpcExpandedDetails, setRpcExpandedDetails] = useState<boolean>(false);
  const [lastRpcIso, setLastRpcIso] = useState<string>('');
  const [rpcPresetName, setRpcPresetName] = useLocalStorage<string>('aodsFridaRpcPresetName', '');
  const [rpcPresets, setRpcPresets] = useState<RpcPreset[]>([]);
  const [rpcPresetSearch, setRpcPresetSearch] = useState<string>('');
  const [rpcPresetTag, setRpcPresetTag] = useState<string>('');
  const [recentRpcs, setRecentRpcs] = useLocalStorage<RecentRpc[]>('aodsFridaRecentRpcs', []);

  // Stable refs for callback props
  const appendEventLineRef = useRef(appendEventLine);
  appendEventLineRef.current = appendEventLine;
  const setConnectMsgRef = useRef(setConnectMsg);
  setConnectMsgRef.current = setConnectMsg;
  const setErrorRef = useRef(setError);
  setErrorRef.current = setError;

  // Load saved RPC state on mount
  useEffect(() => {
    try {
      const rf = localStorage.getItem('aodsFridaRpcFn');
      if (rf) setRpcFn(rf);
      const ra = localStorage.getItem('aodsFridaRpcArgs');
      if (ra) setRpcArgs(ra);
    } catch {}
    try {
      const rr = localStorage.getItem('aodsFridaRpcPresets');
      if (rr) { const arr = JSON.parse(rr); if (Array.isArray(arr)) setRpcPresets(arr); }
    } catch {}
  }, []);

  const runRpc = useCallback(async (sessionId: string) => {
    try {
      let parsed: any = {};
      try { parsed = JSON.parse(rpcArgs || '{}'); setRpcArgsError(''); } catch { setRpcArgsError('Invalid JSON'); return; }
      const startedAt = Date.now();
      setRpcDurationMs(null);
      setRpcError(null);
      try { appendEventLineRef.current?.(`[${new Date().toISOString()}] rpc: ${JSON.stringify({ type: 'rpc_call', fn: rpcFn, args: parsed })}`); } catch {}
      try {
        const entry = { fn: String(rpcFn || 'noop'), args: JSON.stringify(parsed), ts: new Date().toISOString() } as RecentRpc;
        setRecentRpcs(prev => normalizeRecent([entry, ...prev]));
      } catch {}
      try { localStorage.setItem('aodsFridaRpcFn', rpcFn); } catch {}
      try { localStorage.setItem('aodsFridaRpcArgs', rpcArgs); } catch {}
      const r = await secureFetch(`/frida/session/${encodeURIComponent(sessionId)}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Frida-Mode': fridaMode, 'X-Frida-Package': pkg },
        body: JSON.stringify({ function: rpcFn, args: parsed }),
      });
      const j = await r.json();
      setRpcResult(JSON.stringify(j, null, 2));
      const took = Date.now() - startedAt;
      setRpcDurationMs(took);
      setLastRpcIso(new Date().toISOString());
      try {
        setRecentRpcs(prev => {
          const first = prev[0]
            ? { ...prev[0], fn: String(rpcFn || 'noop'), args: JSON.stringify(parsed), ts: prev[0]?.ts || new Date().toISOString(), ms: took, status: j?.status }
            : { fn: String(rpcFn || 'noop'), args: JSON.stringify(parsed), ts: new Date().toISOString(), ms: took, status: j?.status } as RecentRpc;
          return normalizeRecent([first, ...prev.slice(1)]);
        });
      } catch {}
      try { appendEventLineRef.current?.(`[${new Date().toISOString()}] rpc: ${JSON.stringify({ type: 'rpc_result', fn: rpcFn, status: j?.status, result: j?.result })}`); } catch {}
    } catch (e: any) {
      setRpcError(String(e?.message || 'RPC failed'));
      setRpcResult(String(e?.message || 'RPC failed'));
    }
  }, [rpcFn, rpcArgs, fridaMode, pkg, setRecentRpcs]);

  const saveRpcPreset = useCallback(() => {
    try {
      const nm = (rpcPresetName || '').trim() || window.prompt('Save RPC preset as name:', '') || '';
      const name = String(nm).trim();
      if (!name) { setErrorRef.current?.('RPC preset name required'); return; }
      const existing = rpcPresets.find(p => p.name === name);
      let tags: string[] = existing?.tags || [];
      if (!existing) {
        const tagInput = (window.prompt('Optional comma-separated tags (e.g., android,crypto):', '') || '').trim();
        if (tagInput) tags = tagInput.split(',').map(s => s.trim()).filter(Boolean);
      }
      const entry: RpcPreset = { name, fn: String(rpcFn || 'noop'), args: String(rpcArgs || '{}'), tags };
      const next = [...rpcPresets];
      const idx = next.findIndex(p => p.name === name);
      if (idx >= 0) next[idx] = entry; else next.push(entry);
      setRpcPresets(next);
      try { localStorage.setItem('aodsFridaRpcPresets', JSON.stringify(next)); } catch {}
      setRpcPresetName(name);
      setConnectMsgRef.current?.('rpc preset saved');
      setTimeout(() => setConnectMsgRef.current?.(''), 1200);
    } catch (e: any) {
      setErrorRef.current?.(String(e?.message || 'RPC preset save failed'));
    }
  }, [rpcPresetName, rpcPresets, rpcFn, rpcArgs, setRpcPresetName]);

  const loadRpcPresetByName = useCallback((nm: string) => {
    try {
      const p = rpcPresets.find(x => x.name === nm);
      if (p) {
        setRpcFn(p.fn);
        setRpcArgs(p.args || '{}');
        setRpcPresetName(nm);
        setConnectMsgRef.current?.('rpc preset loaded');
        setTimeout(() => setConnectMsgRef.current?.(''), 1200);
      }
    } catch {}
  }, [rpcPresets, setRpcPresetName]);

  const resetRpcState = useCallback(() => {
    setRpcResult('');
    setRpcError(null);
    setRpcDurationMs(null);
    setRecentRpcs([]);
    setRpcExpandedDetails(false);
  }, [setRecentRpcs]);

  return {
    rpcFn,
    setRpcFn,
    rpcArgs,
    setRpcArgs,
    rpcResult,
    rpcArgsError,
    rpcDurationMs,
    rpcError,
    rpcExpandedDetails,
    setRpcExpandedDetails,
    lastRpcIso,
    recentRpcs,
    setRecentRpcs,
    rpcPresetName,
    setRpcPresetName,
    rpcPresets,
    rpcPresetSearch,
    setRpcPresetSearch,
    rpcPresetTag,
    setRpcPresetTag,
    runRpc,
    saveRpcPreset,
    loadRpcPresetByName,
    normalizeRecent,
    formatTime,
    computeShouldCollapse,
    resetRpcState,
  };
}
