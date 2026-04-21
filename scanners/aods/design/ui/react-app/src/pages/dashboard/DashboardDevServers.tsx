import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Box, Button, Chip, FormControl, Grid, IconButton, InputLabel, MenuItem, Select, Stack, Tooltip, Typography } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { secureFetch } from '../../lib/api';
import { DataCard, AppToast } from '../../components';
import { useToast } from '../../hooks/useToast';
import type { DevServerProcess, DevServerStatus } from '../../types';

interface DashboardDevServersProps {
  devStatus: DevServerStatus | null;
  setDevStatus: (v: DevServerStatus | null) => void;
}

export function DashboardDevServers({ devStatus, setDevStatus }: DashboardDevServersProps) {
  const [devTargets, setDevTargets] = useState<{ api: boolean; ui: boolean }>(() => {
    try {
      const raw = localStorage.getItem('aodsDev_targets');
      if (raw) {
        const j = JSON.parse(raw);
        if (j && typeof j.api === 'boolean' && typeof j.ui === 'boolean') return { api: j.api, ui: j.ui };
      }
    } catch { /* ignore */ }
    return { api: true, ui: true };
  });
  const [devBusy, setDevBusy] = useState(false);
  const [devDetailsOpen, setDevDetailsOpen] = useState(false);
  const [devAutoRefresh, setDevAutoRefresh] = useState<boolean>(() => { try { return localStorage.getItem('aodsDev_auto') === '1'; } catch { return false; } });
  const [devRefreshMs, setDevRefreshMs] = useState<number>(() => { try { return Number(localStorage.getItem('aodsDev_ms') || '5000'); } catch { return 5000; } });
  const { toast, showToast, closeToast } = useToast();

  useEffect(() => { try { localStorage.setItem('aodsDev_targets', JSON.stringify(devTargets)); } catch { /* ignore */ } }, [devTargets]);
  useEffect(() => { try { localStorage.setItem('aodsDev_auto', devAutoRefresh ? '1' : '0'); } catch { /* ignore */ } }, [devAutoRefresh]);
  useEffect(() => { try { localStorage.setItem('aodsDev_ms', String(devRefreshMs)); } catch { /* ignore */ } }, [devRefreshMs]);

  useEffect(() => {
    if (!devAutoRefresh) return;
    const id = window.setInterval(() => { try { refreshDevStatus(); } catch { /* ignore */ } }, Math.max(1500, devRefreshMs || 0));
    return () => { window.clearInterval(id); };
  }, [devAutoRefresh, devRefreshMs]);

  async function refreshDevStatus() {
    try {
      const r = await secureFetch('/dev/servers/status');
      if (r.ok) { setDevStatus(await r.json()); return; }
    } catch { /* ignore */ }
    try {
      const rr = await secureFetch('/health');
      setDevStatus({ api: { pid: null, running: rr.ok }, ui: { pid: null, running: true }, ports: { api: rr.ok, ui: true } });
    } catch {
      setDevStatus({ api: { pid: null, running: false }, ui: { pid: null, running: true }, ports: { api: false, ui: true } });
    }
  }

  async function copyText(text: string) {
    try { await navigator.clipboard.writeText(text); showToast('Copied'); } catch { /* ignore */ }
  }

  async function controlDev(action: 'start' | 'stop' | 'restart', targets?: Array<'api' | 'ui'>) {
    if (devBusy) return;
    try {
      let chosen = (targets && targets.length ? targets : (devTargets.api && devTargets.ui) ? ['api', 'ui'] : (devTargets.api ? ['api'] : (devTargets.ui ? ['ui'] : ['api', 'ui']))) as Array<'api' | 'ui'>;
      try {
        const apiDown = !(devStatus && ((devStatus.api && devStatus.api.running) || (devStatus.ports && devStatus.ports.api)));
        if (apiDown && chosen.includes('api')) {
          showToast('API is offline. Start it via ./scripts/start_services.sh start', 'warning');
          chosen = chosen.filter(t => t !== 'api');
          if (chosen.length === 0) return;
        }
      } catch { /* ignore */ }
      if (action === 'restart' && chosen.includes('api')) {
        if (!window.confirm('Restarting API will temporarily disconnect UI controls and the page will auto-reload. Continue?')) return;
      }
      if (action === 'stop' && chosen.includes('api')) {
        if (!window.confirm('Stop API now? UI controls may fail until API is started again. Continue?')) return;
      }
      setDevBusy(true);
      const r = await secureFetch(`/dev/servers/${action}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ targets: chosen }) });
      if (!r.ok) throw new Error(String(r.status));
      setDevStatus(await r.json());
      showToast(`${action} ok`);
      setTimeout(() => { try { refreshDevStatus(); } catch { /* ignore */ } }, 1200);
      if (action === 'restart' && chosen.includes('api')) {
        setTimeout(() => { try { window.location.reload(); } catch { /* ignore */ } }, 2000);
      }
    } catch {
      showToast(`dev ${action} failed`, 'error');
    } finally { setDevBusy(false); }
  }

  const fallbackNet = { ips: ['127.0.0.1'], listeners: [] as Array<{ local: string }>, api: { url: (typeof window !== 'undefined' ? `${window.location.protocol}//127.0.0.1:8088/api` : 'http://127.0.0.1:8088/api') }, ui: { url: (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:5088') } };
  const st0: DevServerStatus = devStatus || { api: { running: false, pid: null }, ui: { running: true, pid: null }, ports: { api: false, ui: true }, network: fallbackNet };
  const ports = st0.ports || {};
  const apiRun = Boolean(st0.api?.running || ports.api);
  const uiRun = Boolean(st0.ui?.running || ports.ui);
  const st: DevServerStatus & { apiInstances: DevServerProcess[]; uiInstances: DevServerProcess[] } = {
    api: { pid: st0.api?.pid ?? null, running: apiRun },
    ui: { pid: st0.ui?.pid ?? null, running: uiRun },
    ports: { api: Boolean(ports.api), ui: Boolean(ports.ui) },
    network: { ...fallbackNet, ...(st0.network || {}) },
    apiInstances: st0.apiInstances || [],
    uiInstances: st0.uiInstances || [],
  };

  return (
    <Grid item xs={12}>
      <DataCard title="Dev Servers">
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems="center">
          <Chip size="small" label="API" clickable color={devTargets.api ? 'primary' : 'default'} onClick={() => setDevTargets((t) => ({ ...t, api: !t.api }))} aria-label="Target API" aria-pressed={devTargets.api} />
          <Chip size="small" label="UI" clickable color={devTargets.ui ? 'primary' : 'default'} onClick={() => setDevTargets((t) => ({ ...t, ui: !t.ui }))} aria-label="Target UI" aria-pressed={devTargets.ui} />
          <Button size="small" variant="outlined" onClick={refreshDevStatus} disabled={devBusy} aria-label="Refresh dev servers status">Status</Button>
          <Button size="small" variant="outlined" onClick={() => controlDev('start')} disabled={devBusy || (!devTargets.ui && !devTargets.api)} aria-label="Start selected dev servers">Start</Button>
          <Button size="small" variant="outlined" onClick={() => controlDev('stop')} disabled={devBusy || (!devTargets.ui && !devTargets.api)} aria-label="Stop selected dev servers">Stop</Button>
          <Button size="small" variant="outlined" onClick={() => controlDev('restart')} disabled={devBusy || (!devTargets.ui && !devTargets.api)} aria-label="Restart selected dev servers">Restart</Button>
          <Button size="small" variant="outlined" color="warning" onClick={async () => {
            if (!window.confirm('Stop ALL instances of API and UI?')) return;
            setDevBusy(true);
            try { const r = await secureFetch('/dev/servers/stop_all', { method: 'POST' }); if (r.ok) setDevStatus(await r.json()); } catch { /* ignore */ }
            finally { setDevBusy(false); setTimeout(() => refreshDevStatus(), 800); }
          }} aria-label="Stop all dev servers">Stop All</Button>
          <Button size="small" variant="outlined" color="success" onClick={async () => {
            if (!window.confirm('Start a clean API and UI instance?')) return;
            setDevBusy(true);
            try { const r = await secureFetch('/dev/servers/start_clean', { method: 'POST' }); if (r.ok) setDevStatus(await r.json()); } catch { /* ignore */ }
            finally { setDevBusy(false); setTimeout(() => refreshDevStatus(), 1200); }
          }} aria-label="Start clean dev servers">Start Clean</Button>
          <Chip size="small" clickable color={devAutoRefresh ? 'primary' : 'default'} label="Auto" aria-label="Toggle dev status auto-refresh" aria-pressed={devAutoRefresh} onClick={() => setDevAutoRefresh(v => !v)} />
          <Tooltip title="Polling interval for Dev Servers status" disableInteractive>
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel id="dev-interval-label">Refresh every</InputLabel>
              <Select labelId="dev-interval-label" label="Every" value={String(devRefreshMs)} onChange={(e) => setDevRefreshMs(Number(e.target.value))} aria-label="Dev status interval">
                {[2000, 5000, 10000, 15000, 30000].map(ms => (
                  <MenuItem key={ms} value={String(ms)}>{Math.round(ms / 1000)}s</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Tooltip>
          <Button size="small" variant="text" component={Link} to="/artifacts?cat=logs&path=api.log" aria-label="Open API log">API log</Button>
          <Button size="small" variant="text" component={Link} to="/artifacts?cat=logs&path=ui.log" aria-label="Open UI log">UI log</Button>
          <Box sx={{ flex: 1 }} />
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
            <Chip size="small" color={st.api?.running ? 'success' : 'error'} variant="filled" label={`API ${st.api?.running ? 'PASS' : 'FAIL'}`} />
            <Chip size="small" color={st.ui?.running ? 'success' : 'error'} variant="filled" label={`UI ${st.ui?.running ? 'PASS' : 'FAIL'}`} />
            {Array.isArray(st.network?.ips) && st.network.ips.length > 0 && (
              <Chip size="small" variant="outlined" label={`IPs ${st.network.ips.join(', ')}`} />
            )}
            <Chip size="small" variant="outlined" label={`API procs ${Array.isArray(st.apiInstances) ? st.apiInstances.length : 0}`} />
            <Chip size="small" variant="outlined" label={`UI procs ${Array.isArray(st.uiInstances) ? st.uiInstances.length : 0}`} />
          </Stack>
          <Button size="small" variant="text" onClick={() => setDevDetailsOpen(v => !v)} aria-label="Toggle dev servers details">{devDetailsOpen ? 'Hide details' : 'Details'}</Button>
        </Stack>
        {devDetailsOpen && (
          <Box sx={{ mt: 1, p: 2, border: 1, borderColor: 'divider', borderRadius: 1, width: '100%', bgcolor: 'background.paper' }}>
            <Grid container spacing={2} alignItems="flex-start">
              <Grid item xs={12} sm={5}>
                <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 0.5 }}>API instances</Typography>
                {Array.isArray(st.apiInstances) && st.apiInstances.length ? (
                  <Stack spacing={0.5}>
                    {st.apiInstances.map((p: DevServerProcess, idx: number) => (
                      <Stack key={`api-${idx}`} direction="row" spacing={0.5} alignItems="flex-start">
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{p.pid} - {String(p.cmd || '')}</Typography>
                        <Tooltip title="Copy PID"><IconButton size="small" onClick={() => copyText(String(p.pid))} aria-label="Copy API PID"><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>
                      </Stack>
                    ))}
                  </Stack>
                ) : (st.api?.pid ? <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>pid {st.api.pid}</Typography> : <Typography variant="body2">(none)</Typography>)}
              </Grid>
              <Grid item xs={12} sm={5}>
                <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 0.5 }}>UI instances</Typography>
                {Array.isArray(st.uiInstances) && st.uiInstances.length ? (
                  <Stack spacing={0.5}>
                    {st.uiInstances.map((p: DevServerProcess, idx: number) => (
                      <Stack key={`ui-${idx}`} direction="row" spacing={0.5} alignItems="flex-start">
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{p.pid} - {String(p.cmd || '')}</Typography>
                        <Tooltip title="Copy PID"><IconButton size="small" onClick={() => copyText(String(p.pid))} aria-label="Copy UI PID"><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>
                      </Stack>
                    ))}
                  </Stack>
                ) : (st.ui?.pid ? <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>pid {st.ui.pid}</Typography> : <Typography variant="body2">(none)</Typography>)}
              </Grid>
              <Grid item xs={12} sm={2}>
                <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 0.5 }}>Listeners</Typography>
                {Array.isArray(st.network?.listeners) && st.network.listeners.length ? (
                  <Stack spacing={0.5}>
                    {st.network.listeners.slice(0, 12).map((l: { local: string }, idx: number) => (
                      <Typography key={`ln-${idx}`} variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{l.local}</Typography>
                    ))}
                  </Stack>
                ) : <Typography variant="body2">(none)</Typography>}
              </Grid>
            </Grid>
          </Box>
        )}
      </DataCard>
      <AppToast toast={toast} onClose={closeToast} />
    </Grid>
  );
}
