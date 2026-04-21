import React from 'react';
import {
  Box, Button, Chip, CircularProgress, FormControl,
  IconButton, InputLabel, MenuItem, Select, Stack,
  TextField, Typography,
} from '@mui/material';
import StarIcon from '@mui/icons-material/Star.js';
import StarBorderIcon from '@mui/icons-material/StarBorder.js';
import { getApiBase, secureFetch } from '../../lib/api';

interface FridaDeviceSelectorProps {
  devices: { id: string; name: string }[];
  memoDevices: { id: string; name: string }[];
  devicesLoading: boolean;
  devicesError: string;
  deviceSearch: string;
  setDeviceSearch: (v: string) => void;
  deviceTypeFilter: 'all' | 'local' | 'remote' | 'usb';
  setDeviceTypeFilter: (v: 'all' | 'local' | 'remote' | 'usb') => void;
  selectedDeviceId: string | null;
  activeDeviceId: string | undefined;
  favoriteDeviceIds: string[];
  setFavoriteDeviceIds: React.Dispatch<React.SetStateAction<string[]>>;
  status: any;
  alsoHighlightCorellium: boolean;
  corelliumIp: string;
  setCorelliumIp: (v: string) => void;
  corelliumPort: number;
  setCorelliumPort: (v: number) => void;
  connecting: boolean;
  connectMsg: string;
  ensureRunning: boolean;
  staticOnly: boolean;
  procLoading: boolean;
  chipSx: Record<string, any>;
  auth: { roles: string[] };
  // Telemetry state
  telemetry: any[];
  telemetryBusy: boolean;
  telemetryFilter: string;
  setTelemetryFilter: (v: string) => void;
  telemetryMode: string;
  telemetryModeDisplay: string;
  setTelemetryMode: (v: string) => void;
  telemetrySince: string;
  setTelemetrySince: (v: string) => void;
  telemetryUntil: string;
  setTelemetryUntil: (v: string) => void;
  // Callbacks
  onReloadDevices: () => void;
  onCorelliumConnect: () => void;
  onEnsureCorellium: () => void;
  onLoadProcessesWithRetry: (devId: string) => void;
  fetchJsonWithTimeout: <T = any>(path: string, init: RequestInit | undefined, timeoutMs: number) => Promise<T>;
  enqueueToast: (msg: string, severity: 'success' | 'error' | 'warning' | 'info') => void;
  setTelemetry: (v: any[]) => void;
  setTelemetryBusy: (v: boolean) => void;
}

export function FridaDeviceSelector({
  devices, memoDevices, devicesLoading, devicesError,
  deviceSearch, setDeviceSearch, deviceTypeFilter, setDeviceTypeFilter,
  selectedDeviceId, activeDeviceId, favoriteDeviceIds, setFavoriteDeviceIds,
  status, alsoHighlightCorellium,
  corelliumIp, setCorelliumIp, corelliumPort, setCorelliumPort,
  connecting, connectMsg, ensureRunning, staticOnly, procLoading, chipSx, auth,
  telemetry, telemetryBusy, telemetryFilter, setTelemetryFilter,
  telemetryMode, telemetryModeDisplay, setTelemetryMode,
  telemetrySince, setTelemetrySince, telemetryUntil, setTelemetryUntil,
  onReloadDevices, onCorelliumConnect, onEnsureCorellium,
  onLoadProcessesWithRetry,
  fetchJsonWithTimeout, enqueueToast, setTelemetry, setTelemetryBusy,
}: FridaDeviceSelectorProps) {

  const DeviceRow = React.useCallback(({ d }: { d: { id: string; name: string } }) => {
    const isCorelliumIpPort = /:\d+$/.test(String(d.id)) && !String(d.id).startsWith('socket@');
    const isCorelliumNamed = /corellium\s*generic/i.test(String(d.name || '')) || /corellium/i.test(String(d.name || ''));
    const targetIsSocket = String(activeDeviceId || '').startsWith('socket@');
    const isSelected = selectedDeviceId === d.id;
    const isActive = activeDeviceId === d.id || (alsoHighlightCorellium && (isCorelliumIpPort || isCorelliumNamed)) || (targetIsSocket && isCorelliumNamed);
    const isAttached = String(status?.attachStatus || '').toLowerCase() === 'attached' && isActive;
    const highlight = isSelected || isActive;
    const variant: any = highlight ? 'contained' : 'outlined';
    const color: any = isAttached ? 'success' : (highlight ? 'primary' : 'inherit');
    return (
      <Stack direction="row" spacing={0.5} alignItems="center">
        <IconButton size="small" aria-label={favoriteDeviceIds.includes(d.id) ? 'unpin device' : 'pin device'} data-testid={`pin-device-${(d.name || d.id).toString().replace(/[^a-zA-Z0-9_-]/g, '_')}`} onClick={() => {
          setFavoriteDeviceIds(prev => prev.includes(d.id) ? prev.filter(x => x !== d.id) : [...prev, d.id]);
        }}>
          {favoriteDeviceIds.includes(d.id) ? <StarIcon fontSize="small" color="warning" /> : <StarBorderIcon fontSize="small" />}
        </IconButton>
        <Button
          variant={variant}
          color={color}
          size="small"
          aria-current={isActive ? 'true' : undefined}
          data-testid={`select-device-${(d.name || d.id).toString().replace(/[^a-zA-Z0-9_-]/g, '_')}`}
          onClick={() => onLoadProcessesWithRetry(d.id)}
        >{d.name || d.id}</Button>
      </Stack>
    );
  }, [favoriteDeviceIds, selectedDeviceId, activeDeviceId, status?.attachStatus, alsoHighlightCorellium]);

  const loadTelemetry = async () => {
    setTelemetryBusy(true);
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (telemetryMode && telemetryMode !== '__none__') params.set('mode', telemetryMode);
      const toIso = (v: string) => {
        if (!v) return '';
        return v.endsWith('Z') ? v : (v.length === 10 ? `${v}T00:00:00Z` : `${v}:00Z`);
      };
      const sinceIso = toIso(telemetrySince);
      const untilIso = toIso(telemetryUntil);
      if (sinceIso) params.set('since', sinceIso);
      if (untilIso) params.set('until', untilIso);
      const j = await fetchJsonWithTimeout<{ items: any[] }>(`/frida/telemetry/recent?${params.toString()}`, undefined as any, 5000);
      setTelemetry(Array.isArray(j?.items) ? j.items : []);
    } catch (e: any) {
      enqueueToast(`telemetry error: ${e?.message || e}`, 'error');
    } finally { setTelemetryBusy(false); }
  };

  return (
    <Box>
      <Stack direction="row" spacing={1} alignItems="center">
        <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Devices</Typography>
        <Chip label="Reload" aria-label="reload devices" size="small" onClick={onReloadDevices} clickable sx={{ ...chipSx, color: 'text.primary' }} />
        <Chip label="All" aria-label="filter devices all" size="small" variant={deviceTypeFilter === 'all' ? 'filled' : 'outlined'} onClick={() => setDeviceTypeFilter('all')} clickable sx={{ ...chipSx, color: 'text.primary' }} />
        <Chip label="Local" aria-label="filter devices local" size="small" variant={deviceTypeFilter === 'local' ? 'filled' : 'outlined'} onClick={() => setDeviceTypeFilter('local')} clickable sx={{ ...chipSx, color: 'text.primary' }} />
        <Chip label="Remote" aria-label="filter devices remote" size="small" variant={deviceTypeFilter === 'remote' ? 'filled' : 'outlined'} onClick={() => setDeviceTypeFilter('remote')} clickable sx={{ ...chipSx, color: 'text.primary' }} />
        <Chip label="USB" aria-label="filter devices usb" size="small" variant={deviceTypeFilter === 'usb' ? 'filled' : 'outlined'} onClick={() => setDeviceTypeFilter('usb')} clickable sx={{ ...chipSx, color: 'text.primary' }} />
        <TextField size="small" label="Search" value={deviceSearch} onChange={(e) => setDeviceSearch(e.target.value)} sx={{ width: 180 }} />
        {devicesError && (
          <Chip label={devicesError} color="error" size="small" onDelete={onReloadDevices} deleteIcon={<Button color="inherit" size="small">Retry</Button>} />
        )}
        {(() => {
          try {
            const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id;
            const tgt = (selectedDeviceId && /:\d+$/.test(selectedDeviceId) && !String(selectedDeviceId).startsWith('socket@') && remote) ? remote : selectedDeviceId;
            return tgt ? <Chip size="small" variant="outlined" label={`Target: ${tgt}`} /> : null;
          } catch { return null; }
        })()}
      </Stack>
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', maxWidth: '100%' }}>
        {devicesLoading ? (
          <Chip label="loading..." size="small" />
        ) : memoDevices.length > 0 ? (
          memoDevices.map(d => (
            <DeviceRow key={d.id} d={d} />
          ))
        ) : (
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip label="No devices" size="small" />
            <Typography variant="caption" color="text.secondary">Tip: Click Ensure (ADB+Frida) or verify frida-server on 27042.</Typography>
            <Button size="small" variant="text" onClick={onReloadDevices}>Try again</Button>
          </Stack>
        )}
        {procLoading && <Chip label="loading..." size="small" />}
      </Box>
      {Boolean(auth?.roles?.includes?.('admin')) && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Telemetry</Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ xs: 'stretch', sm: 'center' }}>
            <Button size="small" variant="outlined" onClick={loadTelemetry}>Load telemetry</Button>
            <Typography variant="caption" color="text.secondary">Recent injections</Typography>
            <TextField size="small" label="Filter telemetry" value={telemetryFilter} onChange={(e) => setTelemetryFilter(e.target.value)} sx={{ minWidth: 200 }} />
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel id="telemetry-mode-label" shrink>Mode</InputLabel>
              <Select labelId="telemetry-mode-label" label="Mode" value={telemetryModeDisplay} onChange={(e) => setTelemetryMode(e.target.value)} displayEmpty renderValue={(v) => {
                const val = String(v || '');
                if (val === '') return 'All';
                if (val === '__none__') return 'None';
                return val;
              }}>
                <MenuItem value="">All</MenuItem>
                <MenuItem value="__none__">None</MenuItem>
                <MenuItem value="attach">attach</MenuItem>
                <MenuItem value="spawn">spawn</MenuItem>
                <MenuItem value="auto">auto</MenuItem>
              </Select>
            </FormControl>
            <TextField size="small" type="datetime-local" label="Since" InputLabelProps={{ shrink: true }} value={telemetrySince} onChange={(e) => setTelemetrySince(e.target.value)} />
            <TextField size="small" type="datetime-local" label="Until" InputLabelProps={{ shrink: true }} value={telemetryUntil} onChange={(e) => setTelemetryUntil(e.target.value)} />
            <Button size="small" variant="text" onClick={async () => {
              try {
                const j = await fetchJsonWithTimeout<{ total: number; by_mode: Record<string, number>; success: number; fail: number }>(`/frida/telemetry/summary`, undefined as any, 5000);
                enqueueToast(`Summary: total ${j?.total ?? 0}, success ${j?.success ?? 0}, fail ${j?.fail ?? 0}`, 'success');
              } catch (e: any) {
                enqueueToast(`summary error: ${e?.message || e}`, 'error');
              }
            }}>Load summary</Button>
            <Button size="small" variant="text" onClick={async () => {
              try {
                const r = await secureFetch('/frida/telemetry/summary');
                if (!r.ok) return;
                const blob = await r.blob();
                const url = URL.createObjectURL(blob);
                window.open(url, '_blank');
                setTimeout(() => URL.revokeObjectURL(url), 15000);
              } catch {}
            }}>Download summary</Button>
          </Stack>
          {telemetryBusy && <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>Loading telemetry…</Typography>}
          {!telemetryBusy && telemetry && telemetry.length > 0 && (
            <Box sx={{ mt: 1, p: 1, border: 1, borderColor: 'divider', borderRadius: 1, maxHeight: 240, overflow: 'auto' }}>
              <Stack spacing={0.5}>
                {telemetry.slice().reverse().filter((t: any) => {
                  const s = (() => { try { return JSON.stringify(t).toLowerCase(); } catch { return String(t).toLowerCase(); } })();
                  return telemetryFilter ? s.includes(telemetryFilter.toLowerCase()) : true;
                }).slice(0, 50).map((t: any, idx: number) => (
                  <Typography key={idx} variant="caption" sx={{ fontFamily: 'monospace' }}>{(() => { try { return JSON.stringify(t); } catch { return String(t); } })()}</Typography>
                ))}
              </Stack>
              <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                <Button size="small" variant="outlined" onClick={async () => {
                  try {
                    const filtered = telemetry.filter((t: any) => {
                      const s = (() => { try { return JSON.stringify(t).toLowerCase(); } catch { return String(t).toLowerCase(); } })();
                      return telemetryFilter ? s.includes(telemetryFilter.toLowerCase()) : true;
                    });
                    await navigator.clipboard.writeText(JSON.stringify(filtered, null, 2));
                    enqueueToast('Telemetry copied', 'success');
                  } catch {
                    enqueueToast('Copy failed', 'error');
                  }
                }}>Copy telemetry JSON</Button>
                <Button size="small" variant="outlined" onClick={async () => {
                  try {
                    const r = await secureFetch('/frida/telemetry/download');
                    if (!r.ok) return;
                    const blob = await r.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url; a.download = 'telemetry.json'; a.click();
                    setTimeout(() => URL.revokeObjectURL(url), 15000);
                  } catch {}
                }}>Download telemetry</Button>
              </Stack>
            </Box>
          )}
        </Box>
      )}
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
        <TextField label="Corellium IP" value={corelliumIp} onChange={e => setCorelliumIp(e.target.value)} size="small" sx={{ width: 180 }} />
        <TextField label="Port" value={corelliumPort} onChange={e => setCorelliumPort(Number(e.target.value) || 5555)} size="small" sx={{ width: 110 }} />
        <Button variant="outlined" size="small" onClick={onCorelliumConnect} disabled={connecting || staticOnly}>{connecting ? <CircularProgress size={16} /> : 'Corellium Connect'}</Button>
        <Button variant="outlined" size="small" onClick={onEnsureCorellium} disabled={ensureRunning || staticOnly}>{ensureRunning ? <CircularProgress size={16} /> : 'Ensure (ADB+Frida)'} </Button>
        {connectMsg && <Chip label={connectMsg} size="small" color="success" />}
      </Stack>
    </Box>
  );
}
