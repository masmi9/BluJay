import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Box, Paper, Stack } from '@mui/material';
import { PageHeader } from '../components/PageHeader';
import useMediaQuery from '@mui/material/useMediaQuery';
import { useAuth } from '../context/AuthContext';
import { getApiBase, secureFetch } from '../lib/api';
import { useLocalStorage, useFridaConnection, useFridaRpc, normalizeRecent, formatTime, computeShouldCollapse } from '../hooks';
import { useToast } from '../hooks/useToast';
import { AppToast } from '../components';
import { FridaHeaderBar } from './frida/FridaHeaderBar';
import { FridaDeviceSelector } from './frida/FridaDeviceSelector';
import { FridaProcessList } from './frida/FridaProcessList';
import { FridaScriptEditor } from './frida/FridaScriptEditor';
import { FridaRpcPanel } from './frida/FridaRpcPanel';
import { FridaEventsLog } from './frida/FridaEventsLog';

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


export default function FridaConsole() {
  const isCompact = useMediaQuery('(max-width:900px)');
  const auth = useAuth();

  // ── UI Preferences ──
  const [compactMode, setCompactMode] = useLocalStorage<boolean>('aodsFridaUi.compactMode', false);
  const [autoScrollEvents, setAutoScrollEvents] = useLocalStorage<boolean>('aodsFridaAutoScrollEvents', true);
  const [pauseOnError, setPauseOnError] = useLocalStorage<boolean>('aodsFridaPauseOnError', true);
  const [eventsExpanded, setEventsExpanded] = useLocalStorage<boolean>('aodsFridaUi.eventsExpanded', true);
  const [rpcExpanded, setRpcExpanded] = useLocalStorage<boolean>('aodsFridaUi.rpcExpanded', false);
  const [rpcTab, setRpcTab] = useLocalStorage<number>('aodsFridaUi.rpcTab', 0);
  const [wsLastExpanded, setWsLastExpanded] = useLocalStorage<boolean>('aodsFridaUi.wsLastExpanded', true);
  const [baselineExpanded, setBaselineExpanded] = useLocalStorage<boolean>('aodsFridaUi.baselineExpanded', true);

  // ── Devices ──
  const [devices, setDevices] = useState<{ id: string; name: string }[]>([]);
  const [devicesLoading, setDevicesLoading] = useState<boolean>(true);
  const [devicesError, setDevicesError] = useState<string>('');
  const [selectedDeviceId, setSelectedDeviceId] = useLocalStorage<string | null>('aodsFridaSelectedDevice', null);
  const [deviceSearch, setDeviceSearch] = useLocalStorage<string>('aodsFridaDeviceSearch', '');
  const [deviceTypeFilter, setDeviceTypeFilter] = useLocalStorage<'all' | 'local' | 'remote' | 'usb'>('aodsFridaDeviceType', 'all');
  const [favoriteDeviceIds, setFavoriteDeviceIds] = useLocalStorage<string[]>('aodsFridaFavoriteDevices', []);

  // ── Processes ──
  const [processes, setProcesses] = useState<{ pid: number; name: string }[]>([]);
  const [procFilter, setProcFilter] = useLocalStorage<string>('aodsFridaProcFilter', '');
  const [procFilterDebounced, setProcFilterDebounced] = useState<string>('');
  const [procLoading, setProcLoading] = useState(false);
  const [procError, setProcError] = useState<string>('');
  const [favoritePids, setFavoritePids] = useLocalStorage<number[]>('aodsFridaFavoritePids', []);
  const [autoAttach, setAutoAttach] = useLocalStorage<boolean>('aodsFridaAutoAttach', false);
  const [autoReloadProcs, setAutoReloadProcs] = useLocalStorage<boolean>('aodsFridaAutoReloadProcs', false);
  const autoAttachedRef = useRef<string>('');

  // ── Script Editor ──
  const [pkg, setPkg] = useLocalStorage<string>('aodsFridaPkg', 'com.example.app');
  const [name, setName] = useLocalStorage<string>('aodsFridaScriptName', 'custom');
  const [js, setJs] = useLocalStorage<string>('aodsFridaInlineJs', 'Java.perform(function(){ console.log("hello from frida"); });');
  const [presetName, setPresetName] = useLocalStorage<string>('aodsFridaPresetName', '');
  const [presets, setPresets] = useState<{ name: string; content: string }[]>([]);
  const [loadUrl, setLoadUrl] = useLocalStorage<string>('aodsFridaLoadUrl', '');
  const [uploading, setUploading] = useState<boolean>(false);
  const [loadUrlLoading, setLoadUrlLoading] = useState<boolean>(false);
  const [lastUploadIso, setLastUploadIso] = useLocalStorage<string>('aodsFridaLastUploadIso', '');

  // ── Events ──
  const [events, setEvents] = useState<string[]>([]);
  const eventsBoxRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<any>(null);
  const [eventsFilter, setEventsFilter] = useLocalStorage<string>('aodsFridaEventsFilter', '');
  const [paused, setPaused] = useLocalStorage<boolean>('aodsFridaEventsPaused', false);
  const pausedRef = useRef<boolean>(paused);
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  // ── Connection (via hook) ──
  const [autoConnectWs, setAutoConnectWs] = useLocalStorage<boolean>('aodsFridaAutoConnectWs', false);

  // ── Status & Health ──
  const [status, setStatus] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<any>(null);
  const [lastUpdatedIso, setLastUpdatedIso] = useState<string>('');
  const [lastReceivedIso, setLastReceivedIso] = useState<string>('');
  const [lastProcsIso, setLastProcsIso] = useState<string>('');

  // ── Corellium ──
  const [corelliumIp, setCorelliumIp] = useLocalStorage<string>('aodsFridaCorelliumIp', '10.11.1.11');
  const [corelliumPort, setCorelliumPort] = useLocalStorage<number>('aodsFridaCorelliumPort', 5555);
  const [connecting, setConnecting] = useState<boolean>(false);
  const [connectMsg, setConnectMsg] = useState<string>('');
  const [ensureRunning, setEnsureRunning] = useState<boolean>(false);

  // ── Frida mode ──
  const [fridaMode, setFridaMode] = useState<'read_only' | 'standard' | 'advanced'>(() => {
    try { return (localStorage.getItem('aodsFridaMode') as any) as any || 'standard'; } catch { return 'standard'; }
  });

  // ── Misc UI ──
  const [policyMsg] = useState<string>('');
  const [helpAnchorEl, setHelpAnchorEl] = useState<null | HTMLElement>(null);
  const { toast, showToast, closeToast } = useToast();
  const [moreEl, setMoreEl] = useState<null | HTMLElement>(null);
  const [devicePopoverEl, setDevicePopoverEl] = useState<null | HTMLElement>(null);
  const [diagOpen, setDiagOpen] = useState<boolean>(false);
  const [diagBusy, setDiagBusy] = useState<boolean>(false);
  const [diagReport, setDiagReport] = useState<any>(null);

  // ── Telemetry ──
  const [telemetry, setTelemetry] = useState<Array<any>>([]);
  const [telemetryBusy, setTelemetryBusy] = useState<boolean>(false);
  const [telemetryFilter, setTelemetryFilter] = useLocalStorage<string>('aodsFridaTelemetryFilter', '');
  const [telemetryMode, setTelemetryMode] = useLocalStorage<string>('aodsFridaTelemetryMode', '');
  const telemetryModeDisplay = telemetryMode || '';
  const [telemetrySince, setTelemetrySince] = useLocalStorage<string>('aodsFridaTelemetrySince', '');
  const [telemetryUntil, setTelemetryUntil] = useLocalStorage<string>('aodsFridaTelemetryUntil', '');

  // ── Computed Values ──
  const controlHeight = 32;
  const btnSx = { height: controlHeight, borderRadius: 1.5, py: 0, px: 1.25 } as const;
  const chipSx = { height: controlHeight, '& .MuiChip-label': { px: 0.75, color: 'text.primary' } } as const;
  const fieldDenseSx = { '& .MuiOutlinedInput-root': { height: controlHeight }, '& .MuiOutlinedInput-input': { py: 0.5 } } as const;
  const isCompactUi = Boolean(isCompact || compactMode);
  const chipCompactSx = isCompactUi ? { height: 24, minWidth: 0, '& .MuiChip-label': { px: 0.5 } } : {} as const;
  const staticOnly = Boolean(health && ((health.executionMode === 'static') || (health.dynamicAllowed === false)));
  const determinismStatus: 'ok' | 'fail' | 'unknown' = (health && health.determinism && typeof health.determinism.status === 'string') ? (health.determinism.status as any) : 'unknown';
  const calibrationStatus: 'ok' | 'stale' | 'fail' | 'missing' | 'unknown' = (health && health.calibration && typeof health.calibration.status === 'string') ? (health.calibration.status as any) : 'unknown';

  // ── Event Helpers ──
  const clearEvents = () => { setEvents([]); conn.setWsLast(''); };

  const appendEventLine = useCallback((line: string) => {
    setEvents(prev => {
      const next = [...prev, line];
      if (next.length > 1000) next.splice(0, next.length - 1000);
      return next;
    });
    try {
      const isError = /\berror\b|\bfail\b|\bexception\b/i.test(line);
      if (pauseOnError && isError) setPaused(true);
    } catch {}
    try {
      if (autoScrollEvents && listRef.current) {
        const idx = Math.max(0, (events?.length || 1) - 1);
        listRef.current.scrollToItem(idx, 'end');
      }
    } catch {}
  }, [pauseOnError, autoScrollEvents, events?.length, setPaused]);

  // ── Connection Hook ──
  const conn = useFridaConnection({
    pkg,
    authToken: auth.token,
    autoConnectWs,
    onWsMessage: undefined,
    onSseEvent: useCallback((j: { ts?: string; script?: string; msg?: any }) => {
      setLastReceivedIso(new Date().toISOString());
      if (!pausedRef.current) {
        appendEventLine(`[${j.ts || ''}] ${j.script || ''}: ${typeof j.msg === 'string' ? j.msg : JSON.stringify(j.msg)}`);
      }
    }, [appendEventLine]),
    onError: useCallback((msg: string) => setError(msg), []),
  });

  // ── RPC Hook ──
  const rpc = useFridaRpc({
    fridaMode,
    pkg,
    appendEventLine,
    setConnectMsg,
    setError,
  });

  // ── Helper Functions ──

  async function fetchJsonWithTimeout<T = any>(path: string, init: RequestInit | undefined, timeoutMs: number): Promise<T> {
    const ac = new AbortController();
    const timer = window.setTimeout(() => { try { ac.abort(); } catch {} }, Math.max(1, timeoutMs));
    try {
      const r = await secureFetch(path, { ...(init || {}), signal: ac.signal } as any);
      if (!r.ok) throw new Error(String(r.status));
      return await r.json();
    } finally {
      try { window.clearTimeout(timer); } catch {}
    }
  }

  function enqueueToast(message: string, severity: 'success' | 'error' | 'warning' | 'info' = 'success') {
    showToast(message, severity);
  }

  function showCopyToast(message: string) { showToast(message); }

  function inferDeviceType(d: any): 'local' | 'remote' | 'usb' {
    try {
      const id = String(d?.id || '').toLowerCase();
      if (id.startsWith('socket@')) return 'remote';
      if (/^\d+\.\d+\.\d+\.\d+:\d+/.test(id)) return 'usb';
      return 'local';
    } catch { return 'local'; }
  }

  function buildStatusSnapshot(): any {
    return {
      timestamps: { lastUpdatedIso, lastProcsIso, lastReceivedIso },
      selectedDeviceId, devices, health, status,
    };
  }

  function verifyPreconditions(kind: 'attach' | 'upload' | 'ws'): boolean {
    if (staticOnly && (kind === 'attach' || kind === 'upload' || kind === 'ws')) {
      setError('Blocked by policy: static-only mode is enabled. Enable dynamic tools to continue.');
      return false;
    }
    const tok = getToken();
    if (!tok) { setError('Sign in required to perform this action.'); return false; }
    if (kind === 'attach' || kind === 'upload') {
      const hasDevice = Boolean(selectedDeviceId || devices[0]);
      if (!hasDevice) { setError('No devices detected. Use Ensure (ADB+Frida) or connect a device.'); return false; }
      if (kind === 'upload') {
        if (!health?.portOpen) { setError('Frida port 27042 is closed. Use Ensure (ADB+Frida) then retry.'); return false; }
      }
    }
    return true;
  }

  // ── API Functions ──

  async function reloadDevices() {
    setDevicesLoading(true);
    setDevicesError('');
    try {
      const token = getToken();
      if (!token) { setDevices([]); return; }
      const r = await secureFetch(`/frida/devices`);
      if (r.ok) {
        const j = await r.json();
        const items = Array.isArray(j.items) ? j.items : [];
        const sorted = items.slice().sort((a: any, b: any) => {
          const fa = favoriteDeviceIds.includes(a.id);
          const fb = favoriteDeviceIds.includes(b.id);
          if (fa && !fb) return -1;
          if (!fa && fb) return 1;
          const ra = String(a?.id || '').startsWith('socket@127.0.0.1:');
          const rb = String(b?.id || '').startsWith('socket@127.0.0.1:');
          if (ra && !rb) return -1;
          if (!ra && rb) return 1;
          return String(a.name || a.id).localeCompare(String(b.name || b.id));
        });
        setDevices(sorted);
      } else {
        try { setDevicesError(`devices error (${r.status})`); } catch {}
        setDevices([]);
      }
    } catch (e: any) {
      try { setDevicesError(String(e?.message || 'devices fetch failed')); } catch {}
      setDevices([]);
    } finally {
      setDevicesLoading(false);
    }
  }

  async function refreshStatus() {
    setError(null);
    try {
      const r = await secureFetch(`/frida/session/${encodeURIComponent(pkg)}/status`);
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      const available = (typeof j?.available === 'boolean') ? j.available : Boolean(
        (j && j.sslHooks && typeof j.sslHooks.available === 'boolean' && j.sslHooks.available) ||
        (j && j.baseline && j.baseline.sslHooks && typeof j.baseline.sslHooks.available === 'boolean' && j.baseline.sslHooks.available) ||
        (j && j.features && typeof j.features.available === 'boolean' && j.features.available)
      );
      setStatus((s: any) => ({ ...(s || {}), ...(j || {}), available }));
      setLastUpdatedIso(new Date().toISOString());
    } catch (e: any) {
      setError(e?.message || 'Failed to load status');
    }
  }

  async function refreshHealth() {
    try {
      const r = await secureFetch(`/frida/health`);
      if (r.ok) { const j = await r.json(); setHealth(j); }
    } catch {}
  }

  async function loadJsFromUrl(u: string): Promise<string> {
    const resp = await fetch(u, { cache: 'no-store' });
    const ct = String((resp as any)?.headers?.get?.('content-type') || '');
    const txt = await resp.text();
    const looksHtml = /<!doctype\s+html|<html[\s\S]*?>/i.test(txt);
    const urlLooksJs = /\.js(\?|#|$)/i.test(u);
    const typeLooksJs = /javascript/i.test(ct);
    if ((ct && !typeLooksJs) || looksHtml) throw new Error(`not JavaScript (received ${ct || 'HTML'})`);
    if (!ct && !urlLooksJs) {
      const trimmed = txt.trim();
      const looksJsHeuristic = /^(\/\/|\/\*|export\s+|import\s+|\(?function|Java\.perform|setImmediate|setTimeout|\(\)\s*=>)/.test(trimmed);
      if (!looksJsHeuristic) throw new Error('not JavaScript (unknown content)');
    }
    return txt;
  }

  async function loadProcesses(devId: string): Promise<number> {
    const resolveDeviceIdForProcesses = (wantedId: string): string => {
      try {
        const remote = devices.find((d: any) => typeof d?.id === 'string' && d.id.startsWith('socket@127.0.0.1:'))?.id as string | undefined;
        if (remote && /:\d+$/.test(wantedId) && !wantedId.startsWith('socket@')) return remote;
        return wantedId;
      } catch { return wantedId; }
    };
    const targetId = resolveDeviceIdForProcesses(devId);
    try {
      const j = await fetchJsonWithTimeout<{ items: any[] }>(`/frida/devices/${encodeURIComponent(targetId)}/processes`, undefined, 6000);
      setProcesses(Array.isArray(j.items) ? j.items : []);
      setSelectedDeviceId(targetId);
      setLastProcsIso(new Date().toISOString());
      setProcError('');
      try {
        if (autoAttach && !status?.sessionId) {
          const items = Array.isArray(j.items) ? j.items : [];
          const match = items.find((p: any) => String(p?.name || '').toLowerCase() === String(pkg).toLowerCase())
            || items.find((p: any) => String(p?.name || '').toLowerCase().includes(String(pkg).toLowerCase()));
          if (match) {
            const key = `${targetId}:${pkg}:${match.pid}`;
            if (autoAttachedRef.current !== key) {
              await attach(targetId, match.pid);
              autoAttachedRef.current = key;
            }
          }
        }
      } catch {}
      return Array.isArray(j.items) ? j.items.length : 0;
    } catch (e: any) {
      const msg = `Failed to load processes (client timeout). ${e?.name === 'AbortError' ? 'Request aborted' : (e?.message || '')}`;
      setError(msg);
      setProcError(msg);
      return 0;
    }
  }

  async function loadProcessesWithRetry(devId: string, attempts = 3) {
    setProcLoading(true);
    let count = 0;
    for (let i = 0; i < attempts; i++) {
      const start = Date.now();
      count = await loadProcesses(devId);
      const took = Date.now() - start;
      if (count > 0) break;
      if (took > 4500) break;
      await new Promise(r => setTimeout(r, 500 * (i + 1)));
    }
    setProcLoading(false);
    if (count === 0) {
      const msg = 'Failed to load processes (timeout). Ensure frida-server on 27042 and try Corellium Connect again.';
      setError(msg);
      setProcError(msg);
    } else {
      setProcError('');
    }
  }

  async function attach(devId: string, pid: number) {
    setError(null);
    try {
      const r = await secureFetch(`/frida/attach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: devId, pid, packageName: pkg })
      });
      if (r.status === 409) {
        setError('Blocked by policy: static-only mode is enabled. Enable dynamic tools to attach.');
        return;
      }
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setStatus((s: any) => ({ ...(s || {}), sessionId: j.sessionId, attachStatus: j.status }));
      try { await runBaseline(j.sessionId); } catch {}
      await refreshStatus();
    } catch (e: any) {
      setError(e?.message || 'Failed to attach');
    }
  }

  async function runBaseline(sessionId: string) {
    try {
      const r = await secureFetch(`/frida/session/${encodeURIComponent(sessionId)}/baseline`, { method: 'POST' });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setStatus((s: any) => ({ ...(s || {}), baseline: j.facts }));
    } catch (e: any) {
      setError(e?.message || 'Baseline failed');
    }
  }

  async function attachToPackageCurrentDevice() {
    try {
      if (!verifyPreconditions('attach')) return;
      const resolveDeviceIdForAttach = (wantedId?: string): string | undefined => {
        try {
          const remote = devices.find((d: any) => typeof d?.id === 'string' && d.id.startsWith('socket@127.0.0.1:'))?.id as string | undefined;
          const w = wantedId || selectedDeviceId || devices[0]?.id;
          if (remote && w && /:\d+$/.test(String(w)) && !String(w).startsWith('socket@')) return remote;
          return w;
        } catch { return wantedId || selectedDeviceId || devices[0]?.id; }
      };
      const devId = resolveDeviceIdForAttach();
      if (!devId) return;
      let list: any[] = [];
      try {
        const j = await fetchJsonWithTimeout<{ items: any[] }>(`/frida/devices/${encodeURIComponent(devId)}/processes`, undefined, 6000);
        list = Array.isArray(j.items) ? j.items : [];
        setProcesses(list);
        setSelectedDeviceId(devId);
      } catch {}
      const target = list.find(p => String(p.name).toLowerCase() === String(pkg).toLowerCase())
        || list.find(p => String(p.name).toLowerCase().includes(String(pkg).toLowerCase()));
      if (target) await attach(devId, target.pid);
      else setError('Package process not found');
    } catch (e: any) {
      setError(String(e?.message || 'Attach failed'));
    }
  }

  async function corelliumConnect() {
    setError(null);
    setConnectMsg('');
    setConnecting(true);
    const prevAuto = { ws: autoConnectWs, reload: autoReloadProcs };
    try { setAutoConnectWs(false); setAutoReloadProcs(false); } catch {}
    try {
      const body = { ip: corelliumIp.trim(), port: Number(corelliumPort) || 5555, manageFrida: true, forwardPort: 27042 } as any;
      const r = await secureFetch(`/frida/corellium/connect`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error || j?.stderr || `connect failed (${r.status})`);
      setConnectMsg(j?.frida_started ? 'frida-server started' : 'connect ok');
      try {
        const devs = await secureFetch(`/frida/devices`);
        if (devs.ok) { const jd = await devs.json(); setDevices(Array.isArray(jd.items) ? jd.items : []); }
      } catch {}
      try { await refreshHealth(); } catch {}
      try { await refreshStatus(); } catch {}
    } catch (e: any) {
      setError(e?.message || 'Corellium connect failed');
    } finally {
      setConnecting(false);
      try { setAutoConnectWs(prevAuto.ws); setAutoReloadProcs(prevAuto.reload); } catch {}
    }
  }

  async function ensureCorellium() {
    setError(null);
    setEnsureRunning(true);
    try {
      const body = { ip: corelliumIp.trim(), port: Number(corelliumPort) || 5555, forwardPort: 27042, retries: 4, manageFrida: true } as any;
      const r = await secureFetch(`/frida/corellium/ensure`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j?.ok) {
        setError(`Ensure failed: ${j?.summary ? JSON.stringify(j.summary) : (j?.error || r.status)}`);
      } else {
        setConnectMsg('ensure ok'); setTimeout(() => setConnectMsg(''), 1500);
        await reloadDevices();
        try { await refreshHealth(); } catch {}
        try { await refreshStatus(); } catch {}
      }
    } catch (e: any) {
      setError(e?.message || 'Ensure failed');
    } finally {
      setEnsureRunning(false);
    }
  }

  async function uploadInline() {
    setError(null);
    setUploading(true);
    try {
      if (staticOnly || !health || health.portOpen === false) {
        setConnectMsg('Blocked by policy');
        try { enqueueToast('Blocked by policy', 'warning'); } catch {}
        setTimeout(() => setConnectMsg(''), 3000);
        return;
      }
      try {
        if (!status?.sessionId) {
          try { await attachToPackageCurrentDevice(); } catch {}
          try { await new Promise(r => setTimeout(r, 200)); } catch {}
          try { await refreshStatus(); } catch {}
        }
      } catch {}
      const resolveDeviceId = (): string | undefined => {
        try {
          const remote = devices.find((d: any) => typeof d?.id === 'string' && d.id.startsWith('socket@127.0.0.1:'))?.id as string | undefined;
          if (remote && selectedDeviceId && /:\d+$/.test(String(selectedDeviceId)) && !String(selectedDeviceId).startsWith('socket@')) return remote;
          return selectedDeviceId || remote || devices[0]?.id;
        } catch { return selectedDeviceId || undefined; }
      };
      const xDevice = resolveDeviceId();
      const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Frida-Mode': fridaMode, 'X-Frida-Package': pkg } as any;
      if (xDevice) headers['X-Frida-Device'] = xDevice;
      const r = await secureFetch(`/frida/session/${encodeURIComponent(pkg)}/scripts`, {
        method: 'POST', headers, body: JSON.stringify({ mode: 'inline', name, content: js })
      });
      if (!r.ok) throw new Error(await r.text());
      setConnectMsg('script uploaded'); setTimeout(() => setConnectMsg(''), 1500);
      setLastUploadIso(new Date().toISOString());
      enqueueToast('Inline script uploaded', 'success');
      try { appendEventLine(`[${new Date().toISOString()}] rpc: ${JSON.stringify({ type: 'custom_script', name, device: xDevice || '-' })}`); } catch {}
      await refreshStatus();
    } catch (e: any) {
      setError(e?.message || 'Failed to upload script');
    } finally {
      setUploading(false);
    }
  }

  async function unload() {
    setError(null);
    try {
      const r = await secureFetch(`/frida/session/${encodeURIComponent(pkg)}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(await r.text());
      await refreshStatus();
    } catch (e: any) {
      setError(e?.message || 'Failed to unload');
    }
  }

  async function runDiagnosis() {
    setDiagBusy(true);
    const report: any = { checks: [] };
    try {
      try {
        const base = await getApiBase();
        const r = await fetch(`${base}/health`, { cache: 'no-store' });
        report.checks.push({ name: 'API /health', ok: r.ok, status: r.status });
      } catch (e: any) { report.checks.push({ name: 'API /health', ok: false, error: String(e?.message || e) }); }
      try { await refreshHealth(); report.checks.push({ name: 'frida health', ok: Boolean(health) }); } catch { report.checks.push({ name: 'frida health', ok: false }); }
      try { await reloadDevices(); report.checks.push({ name: 'devices', ok: (devices.length > 0) }); } catch { report.checks.push({ name: 'devices', ok: false }); }
      try {
        if (staticOnly) {
          report.checks.push({ name: 'ws-token', ok: false, status: 409, note: 'static-only' });
        } else {
          const resp = await secureFetch(`/frida/ws-token`, { method: 'POST' });
          report.checks.push({ name: 'ws-token', ok: resp.ok, status: resp.status });
        }
      } catch (e: any) { report.checks.push({ name: 'ws-token', ok: false, error: String(e?.message || e) }); }
    } finally {
      setDiagReport(report);
      setDiagBusy(false);
    }
  }

  async function resetEnvironment() {
    conn.disconnectAll();
    try { setUploading(false); } catch {}
    try { setLoadUrlLoading(false); } catch {}
    setEvents([]);
    conn.setWsLast('');
    setProcesses([]);
    setDevices([]);
    setSelectedDeviceId(null);
    setStatus(null);
    rpc.resetRpcState();
    setProcError('');
    setDevicesError('');
    setError(null);
    setLastUpdatedIso('');
    setLastReceivedIso('');
    setLastProcsIso('');
    setLastUploadIso('');
    setPaused(false);
    setEventsFilter('');
    setRpcExpanded(false);
    setRpcTab(0);
    setWsLastExpanded(true);
    setBaselineExpanded(true);
    setConnectMsg('environment reset'); setTimeout(() => setConnectMsg(''), 1200);
    try {
      const keys: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith('aodsFrida')) keys.push(k);
      }
      keys.forEach(k => { try { localStorage.removeItem(k); } catch {} });
    } catch {}
    try { await refreshHealth(); } catch {}
    try { await reloadDevices(); } catch {}
  }

  function savePresetsToStorage(arr: { name: string; content: string }[]) {
    try { localStorage.setItem('aodsFridaPresets', JSON.stringify(arr)); } catch {}
  }

  function savePreset() {
    const nm = (presetName || name || '').trim();
    if (!nm) { setError('Preset name required'); return; }
    const next = [...presets];
    const idx = next.findIndex(p => p.name === nm);
    if (idx >= 0) next[idx] = { name: nm, content: js };
    else next.push({ name: nm, content: js });
    setPresets(next); savePresetsToStorage(next); setConnectMsg('preset saved'); setTimeout(() => setConnectMsg(''), 1200);
  }

  function loadPresetByName(nm: string) {
    const p = presets.find(x => x.name === nm);
    if (p) { setName(nm); setPresetName(nm); setJs(p.content); setConnectMsg('preset loaded'); setTimeout(() => setConnectMsg(''), 1200); }
  }

  function deletePresetByName(nm: string) {
    const next = presets.filter(x => x.name !== nm);
    setPresets(next); savePresetsToStorage(next);
  }

  // ── Effects ──

  // Deep-link: initialize from URL on mount
  useEffect(() => {
    try {
      const sp = new URLSearchParams(window.location.search);
      const qDevice = sp.get('device');
      const qPkg = sp.get('pkg');
      const qRpcTab = sp.get('rpcTab');
      const qCompact = sp.get('compact');
      const qEvents = sp.get('eventsFilter');
      if (qDevice) setSelectedDeviceId(qDevice);
      if (qPkg) setPkg(qPkg);
      if (qRpcTab && /^\d+$/.test(qRpcTab)) setRpcTab(Number(qRpcTab));
      if (qCompact === '1') setCompactMode(true);
      if (qEvents) setEventsFilter(qEvents);
    } catch {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Deep-link: sync URL
  useEffect(() => {
    try {
      const sp = new URLSearchParams(window.location.search);
      if (selectedDeviceId) sp.set('device', selectedDeviceId); else sp.delete('device');
      if (pkg) sp.set('pkg', pkg); else sp.delete('pkg');
      if (rpcTab) sp.set('rpcTab', String(rpcTab)); else sp.delete('rpcTab');
      if (compactMode) sp.set('compact', '1'); else sp.delete('compact');
      if (eventsFilter) sp.set('eventsFilter', eventsFilter); else sp.delete('eventsFilter');
      const q = sp.toString();
      const url = q ? `${window.location.pathname}?${q}` : window.location.pathname;
      window.history.replaceState({}, '', url);
    } catch {}
  }, [selectedDeviceId, pkg, rpcTab, compactMode, eventsFilter]);

  // Keyboard shortcuts
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.ctrlKey && !e.shiftKey && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        (async () => { try { await conn.connectWs(); } catch {} })();
      }
      if (e.ctrlKey && e.shiftKey && (e.key === 'b' || e.key === 'B')) {
        e.preventDefault();
        (async () => { try { if (status?.sessionId) await runBaseline(status.sessionId); } catch {} })();
      }
      if (e.ctrlKey && !e.shiftKey && (e.key === 'e' || e.key === 'E')) {
        e.preventDefault();
        (async () => { try { await uploadInline(); } catch {} })();
      }
      if (e.ctrlKey && (e.key === '/')) {
        e.preventDefault();
        const el = document.querySelector('input[aria-label="RPC args (JSON)"]') as HTMLInputElement | null;
        if (el) try { el.focus(); } catch {}
      }
      if (!e.ctrlKey && !e.shiftKey && e.key === 'Escape') {
        e.preventDefault();
        conn.disconnectAll();
      }
      if (e.ctrlKey && !e.shiftKey && (e.key === 'l' || e.key === 'L')) {
        e.preventDefault();
        clearEvents();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [conn.wsStatus, status, rpc.rpcArgs, js, name, pkg, conn]);

  // Load devices on auth
  useEffect(() => { reloadDevices().catch(() => {}); }, [auth.token]);

  // Auto-load processes for last selected device
  useEffect(() => {
    if (!devices || devices.length === 0) return;
    try {
      const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id as string | undefined;
      if (remote && selectedDeviceId && /:\d+$/.test(String(selectedDeviceId)) && !String(selectedDeviceId).startsWith('socket@')) {
        if (selectedDeviceId !== remote) setSelectedDeviceId(remote);
      }
    } catch {}
    const effectiveId = ((): string | null => {
      try {
        const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id;
        if (remote && selectedDeviceId && /:\d+$/.test(String(selectedDeviceId)) && !String(selectedDeviceId).startsWith('socket@')) return remote;
        return selectedDeviceId;
      } catch { return selectedDeviceId; }
    })();
    if (!effectiveId) return;
    const exists = devices.some(d => d.id === effectiveId);
    if (exists && processes.length === 0) {
      loadProcessesWithRetry(effectiveId).catch(() => {});
    }
  }, [devices]);

  // Status auto-refresh
  useEffect(() => {
    let timer: any;
    (async () => {
      try {
        if (!status?.sessionId) return;
        await refreshStatus();
        timer = window.setInterval(() => { refreshStatus().catch(() => {}); }, 3000);
      } catch {}
    })();
    return () => { if (timer) window.clearInterval(timer); };
  }, [status?.sessionId]);

  // Load health on mount
  useEffect(() => { try { refreshHealth(); } catch {} }, []);

  // Auto-reload processes
  useEffect(() => {
    if (!autoReloadProcs) return;
    const dev = selectedDeviceId || devices[0]?.id;
    if (!dev) return;
    const timer = window.setInterval(() => {
      if (!procLoading) loadProcesses(dev).catch(() => {});
    }, 5000);
    return () => { try { window.clearInterval(timer); } catch {} };
  }, [autoReloadProcs, selectedDeviceId, devices, procLoading]);

  // Debounce process filter
  useEffect(() => {
    const t = window.setTimeout(() => setProcFilterDebounced(procFilter), 250);
    return () => { try { window.clearTimeout(t); } catch {} };
  }, [procFilter]);

  // Auto-scroll events
  useEffect(() => {
    try {
      if (autoScrollEvents && listRef.current) {
        const idx = Math.max(0, events.length - 1);
        listRef.current.scrollToItem(idx, 'end');
      }
    } catch {}
  }, [events, autoScrollEvents]);

  // Load saved presets on mount
  useEffect(() => {
    try {
      const raw = localStorage.getItem('aodsFridaPresets');
      if (raw) { const arr = JSON.parse(raw); if (Array.isArray(arr)) setPresets(arr); }
    } catch {}
  }, []);

  // ── Memoized Values ──

  const memoDevices = React.useMemo(() => {
    try {
      return devices.filter(d => {
        const type = inferDeviceType(d);
        if (deviceTypeFilter !== 'all' && type !== deviceTypeFilter) return false;
        if (deviceSearch && !String(d.name || d.id).toLowerCase().includes(deviceSearch.toLowerCase())) return false;
        return true;
      });
    } catch { return devices; }
  }, [devices, deviceTypeFilter, deviceSearch]);

  const memoProcesses = React.useMemo(() => {
    try {
      const q = procFilterDebounced;
      const list = processes.filter(p => !q || String(p.name).toLowerCase().includes(q.toLowerCase()));
      return list.slice().sort((a: any, b: any) => {
        const fa = favoritePids.includes(a.pid);
        const fb = favoritePids.includes(b.pid);
        if (fa && !fb) return -1;
        if (!fa && fb) return 1;
        return String(a.name).localeCompare(String(b.name));
      });
    } catch { return processes; }
  }, [processes, procFilterDebounced, favoritePids]);

  const activeDeviceId = React.useMemo(() => {
    try {
      const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id;
      if (remote && selectedDeviceId && /:\d+$/.test(String(selectedDeviceId)) && !String(selectedDeviceId).startsWith('socket@')) return remote;
      return selectedDeviceId || undefined;
    } catch { return selectedDeviceId || undefined; }
  }, [devices, selectedDeviceId]);

  const alsoHighlightCorellium = React.useMemo(() => {
    try {
      const hasSocket = devices.some((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'));
      const selIsIpPort = Boolean(selectedDeviceId && /:\d+$/.test(String(selectedDeviceId)) && !String(selectedDeviceId).startsWith('socket@'));
      const activeIsSocket = Boolean(activeDeviceId && String(activeDeviceId).startsWith('socket@'));
      return Boolean(hasSocket && (selIsIpPort || activeIsSocket));
    } catch { return false; }
  }, [devices, selectedDeviceId, activeDeviceId]);

  // ── Render ──

  return (
    <Box sx={{ maxWidth: '100%', overflowX: 'hidden' }}>
      <PageHeader title="Frida Console" subtitle="Real-time dynamic instrumentation and runtime analysis" />
      <Stack spacing={2}>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <FridaHeaderBar
            health={health} status={status} staticOnly={staticOnly}
            determinismStatus={determinismStatus} calibrationStatus={calibrationStatus}
            wsStatus={conn.wsStatus} wsReconnectMsg={conn.wsReconnectMsg} esConnected={conn.esConnected}
            error={error} policyMsg={policyMsg} lastUpdatedIso={lastUpdatedIso}
            devices={devices} selectedDeviceId={selectedDeviceId}
            favoriteDeviceIds={favoriteDeviceIds} setFavoriteDeviceIds={setFavoriteDeviceIds}
            isCompactUi={isCompactUi} chipCompactSx={chipCompactSx}
            fridaMode={fridaMode} setFridaMode={setFridaMode}
            compactMode={compactMode} setCompactMode={setCompactMode}
            autoConnectWs={autoConnectWs} setAutoConnectWs={setAutoConnectWs}
            setConnectMsg={setConnectMsg} ensureRunning={ensureRunning}
            helpAnchorEl={helpAnchorEl} setHelpAnchorEl={setHelpAnchorEl}
            moreEl={moreEl} setMoreEl={setMoreEl}
            devicePopoverEl={devicePopoverEl} setDevicePopoverEl={setDevicePopoverEl}
            diagOpen={diagOpen} setDiagOpen={setDiagOpen} diagBusy={diagBusy} diagReport={diagReport}
            wsRef={conn.wsRef} setWsStatus={conn.setWsStatus} setWsLast={conn.setWsLast} setError={setError}
            onRefreshStatus={refreshStatus} onRefreshHealth={refreshHealth}
            onResetEnvironment={resetEnvironment} onEnsureCorellium={ensureCorellium}
            onRunDiagnosis={runDiagnosis} onAttachToPackage={attachToPackageCurrentDevice}
            onLoadProcessesWithRetry={loadProcessesWithRetry}
            buildWsUrl={conn.buildWsUrl}
            openWsWithRetry={conn.openWsWithRetry} buildStatusSnapshot={buildStatusSnapshot}
            showCopyToast={showCopyToast} inferDeviceType={inferDeviceType}
          />
        </Paper>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <FridaDeviceSelector
            devices={devices} memoDevices={memoDevices}
            devicesLoading={devicesLoading} devicesError={devicesError}
            deviceSearch={deviceSearch} setDeviceSearch={setDeviceSearch}
            deviceTypeFilter={deviceTypeFilter} setDeviceTypeFilter={setDeviceTypeFilter}
            selectedDeviceId={selectedDeviceId} activeDeviceId={activeDeviceId}
            favoriteDeviceIds={favoriteDeviceIds} setFavoriteDeviceIds={setFavoriteDeviceIds}
            status={status} alsoHighlightCorellium={alsoHighlightCorellium}
            corelliumIp={corelliumIp} setCorelliumIp={setCorelliumIp}
            corelliumPort={corelliumPort} setCorelliumPort={setCorelliumPort}
            connecting={connecting} connectMsg={connectMsg} ensureRunning={ensureRunning}
            staticOnly={staticOnly} procLoading={procLoading} chipSx={chipSx}
            auth={{ roles: auth.roles || [] }}
            telemetry={telemetry} telemetryBusy={telemetryBusy}
            telemetryFilter={telemetryFilter} setTelemetryFilter={setTelemetryFilter}
            telemetryMode={telemetryMode} telemetryModeDisplay={telemetryModeDisplay}
            setTelemetryMode={setTelemetryMode}
            telemetrySince={telemetrySince} setTelemetrySince={setTelemetrySince}
            telemetryUntil={telemetryUntil} setTelemetryUntil={setTelemetryUntil}
            onReloadDevices={reloadDevices} onCorelliumConnect={corelliumConnect}
            onEnsureCorellium={ensureCorellium}
            onLoadProcessesWithRetry={loadProcessesWithRetry}
            fetchJsonWithTimeout={fetchJsonWithTimeout} enqueueToast={enqueueToast}
            setTelemetry={setTelemetry} setTelemetryBusy={setTelemetryBusy}
          />
        </Paper>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <FridaProcessList
            memoProcesses={memoProcesses} processes={processes}
            procFilter={procFilter} setProcFilter={setProcFilter}
            procLoading={procLoading} procError={procError}
            autoAttach={autoAttach} setAutoAttach={setAutoAttach}
            autoReloadProcs={autoReloadProcs} setAutoReloadProcs={setAutoReloadProcs}
            selectedDeviceId={selectedDeviceId} devices={devices}
            favoritePids={favoritePids} setFavoritePids={setFavoritePids}
            lastProcsIso={lastProcsIso} chipSx={chipSx}
            onLoadProcessesWithRetry={loadProcessesWithRetry}
            onEnsureCorellium={ensureCorellium} onAttach={attach}
            onShowCopyToast={showCopyToast}
            setConnectMsg={setConnectMsg}
          />
        </Paper>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <FridaScriptEditor
            status={status} baselineExpanded={baselineExpanded} setBaselineExpanded={setBaselineExpanded}
            pkg={pkg} setPkg={setPkg} name={name} setName={setName}
            presetName={presetName} setPresetName={setPresetName} presets={presets}
            js={js} setJs={setJs} lastUploadIso={lastUploadIso}
            fridaMode={fridaMode} uploading={uploading}
            loadUrl={loadUrl} setLoadUrl={setLoadUrl} loadUrlLoading={loadUrlLoading}
            staticOnly={staticOnly} selectedDeviceId={selectedDeviceId} devices={devices}
            setConnectMsg={setConnectMsg}
            btnSx={btnSx} fieldDenseSx={fieldDenseSx}
            setError={setError} onUploadInline={uploadInline} onUnload={unload}
            onRefreshStatus={refreshStatus} onRefreshHealth={refreshHealth}
            onSavePreset={savePreset} onDeletePreset={deletePresetByName}
            onLoadPreset={loadPresetByName} onLoadJsFromUrl={loadJsFromUrl}
            onAttachToPackage={attachToPackageCurrentDevice}
            onShowCopyToast={showCopyToast} setLoadUrlLoading={setLoadUrlLoading}
          />
        </Paper>
        <FridaRpcPanel
          rpcFn={rpc.rpcFn} setRpcFn={rpc.setRpcFn} rpcArgs={rpc.rpcArgs} setRpcArgs={rpc.setRpcArgs}
          rpcResult={rpc.rpcResult} rpcArgsError={rpc.rpcArgsError}
          rpcDurationMs={rpc.rpcDurationMs} rpcError={rpc.rpcError}
          rpcExpandedDetails={rpc.rpcExpandedDetails} setRpcExpandedDetails={rpc.setRpcExpandedDetails}
          rpcPresetName={rpc.rpcPresetName} setRpcPresetName={rpc.setRpcPresetName}
          rpcPresets={rpc.rpcPresets} rpcPresetSearch={rpc.rpcPresetSearch}
          setRpcPresetSearch={rpc.setRpcPresetSearch}
          rpcPresetTag={rpc.rpcPresetTag} setRpcPresetTag={rpc.setRpcPresetTag}
          rpcTab={rpcTab} setRpcTab={setRpcTab}
          rpcExpanded={rpcExpanded} setRpcExpanded={setRpcExpanded}
          recentRpcs={rpc.recentRpcs} setRecentRpcs={rpc.setRecentRpcs}
          lastRpcIso={rpc.lastRpcIso} status={status}
          btnSx={btnSx} fieldDenseSx={fieldDenseSx} chipSx={chipSx}
          setConnectMsg={setConnectMsg}
          onRunRpc={rpc.runRpc} onSaveRpcPreset={rpc.saveRpcPreset}
          onLoadRpcPreset={rpc.loadRpcPresetByName}
          normalizeRecent={normalizeRecent} formatTime={formatTime}
          computeShouldCollapse={computeShouldCollapse} showCopyToast={showCopyToast}
        />
        <Paper variant="outlined" sx={{ p: 2 }}>
          <FridaEventsLog
            events={events} eventsFilter={eventsFilter} setEventsFilter={setEventsFilter}
            paused={paused} setPaused={setPaused} clearEvents={clearEvents}
            autoScrollEvents={autoScrollEvents} setAutoScrollEvents={setAutoScrollEvents}
            pauseOnError={pauseOnError} setPauseOnError={setPauseOnError}
            eventsExpanded={eventsExpanded} setEventsExpanded={setEventsExpanded}
            eventsBoxRef={eventsBoxRef} listRef={listRef}
            wsLast={conn.wsLast} wsLastExpanded={wsLastExpanded} setWsLastExpanded={setWsLastExpanded}
            lastReceivedIso={lastReceivedIso} showCopyToast={showCopyToast}
          />
        </Paper>
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
