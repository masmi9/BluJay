import React from 'react';
import {
  Alert, Badge, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, IconButton, Menu, MenuItem,
  Paper, Popover, Stack, Switch, Tooltip, Typography,
} from '@mui/material';
import LanIcon from '@mui/icons-material/Lan.js';
import NumbersIcon from '@mui/icons-material/Numbers.js';
import VerifiedIcon from '@mui/icons-material/Verified.js';
import LinkIcon from '@mui/icons-material/Link.js';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline.js';
import ContentCopyIcon from '@mui/icons-material/ContentCopy.js';
import MoreVertIcon from '@mui/icons-material/MoreVert.js';
import StarIcon from '@mui/icons-material/Star.js';
import StarBorderIcon from '@mui/icons-material/StarBorder.js';
import { useElapsedIso } from './useElapsedIso';
import { secureFetch } from '../../lib/api';

interface FridaHeaderBarProps {
  // Status & health
  health: any;
  status: any;
  staticOnly: boolean;
  determinismStatus: 'ok' | 'fail' | 'unknown';
  calibrationStatus: 'ok' | 'stale' | 'fail' | 'missing' | 'unknown';
  wsStatus: 'disconnected' | 'connecting' | 'connected';
  wsReconnectMsg: string;
  esConnected: boolean;
  error: string | null;
  policyMsg: string;
  lastUpdatedIso: string;
  // Devices
  devices: { id: string; name: string }[];
  selectedDeviceId: string | null;
  favoriteDeviceIds: string[];
  setFavoriteDeviceIds: React.Dispatch<React.SetStateAction<string[]>>;
  // UI toggles
  isCompactUi: boolean;
  chipCompactSx: Record<string, any>;
  fridaMode: string;
  setFridaMode: (v: any) => void;
  compactMode: boolean;
  setCompactMode: (v: boolean) => void;
  autoConnectWs: boolean;
  setAutoConnectWs: (v: boolean) => void;
  setConnectMsg: (v: string) => void;
  ensureRunning: boolean;
  // Popover/dialog state
  helpAnchorEl: HTMLElement | null;
  setHelpAnchorEl: (v: HTMLElement | null) => void;
  moreEl: HTMLElement | null;
  setMoreEl: (v: HTMLElement | null) => void;
  devicePopoverEl: HTMLElement | null;
  setDevicePopoverEl: (v: HTMLElement | null) => void;
  diagOpen: boolean;
  setDiagOpen: (v: boolean) => void;
  diagBusy: boolean;
  diagReport: any;
  // Callbacks
  wsRef: React.MutableRefObject<WebSocket | null>;
  setWsStatus: (v: 'disconnected' | 'connecting' | 'connected') => void;
  setWsLast: (v: string) => void;
  setError: (v: string | null) => void;
  onRefreshStatus: () => Promise<void>;
  onRefreshHealth: () => Promise<void>;
  onResetEnvironment: () => void;
  onEnsureCorellium: () => void;
  onRunDiagnosis: () => void;
  onAttachToPackage: () => void;
  onLoadProcessesWithRetry: (devId: string) => void;
  buildWsUrl: () => Promise<string>;
  openWsWithRetry: (buildUrl: () => Promise<string>, mintToken: () => Promise<string>, onOpen: (ws: WebSocket) => void, onMessage: (ev: MessageEvent) => void, onError: (msg: string) => void) => Promise<void>;
  buildStatusSnapshot: () => any;
  showCopyToast: (msg: string) => void;
  inferDeviceType: (d: any) => 'local' | 'remote' | 'usb';
}

export function FridaHeaderBar({
  health, status, staticOnly, determinismStatus, calibrationStatus,
  wsStatus, wsReconnectMsg, esConnected, error, policyMsg, lastUpdatedIso,
  devices, selectedDeviceId, favoriteDeviceIds, setFavoriteDeviceIds,
  isCompactUi, chipCompactSx, fridaMode, setFridaMode,
  compactMode, setCompactMode, autoConnectWs, setAutoConnectWs,
  setConnectMsg, ensureRunning,
  helpAnchorEl, setHelpAnchorEl, moreEl, setMoreEl,
  devicePopoverEl, setDevicePopoverEl, diagOpen, setDiagOpen, diagBusy, diagReport,
  wsRef, setWsStatus, setWsLast, setError,
  onRefreshStatus, onRefreshHealth, onResetEnvironment, onEnsureCorellium,
  onRunDiagnosis, onAttachToPackage, onLoadProcessesWithRetry,
  buildWsUrl, openWsWithRetry, buildStatusSnapshot,
  showCopyToast, inferDeviceType,
}: FridaHeaderBarProps) {
  const helpOpen = Boolean(helpAnchorEl);
  const moreOpen = Boolean(moreEl);
  const devicePopoverOpen = Boolean(devicePopoverEl);
  const lastUpdatedElapsed = useElapsedIso(lastUpdatedIso);

  return (
    <>
      <Stack id="frida-header" direction="row" alignItems="center" justifyContent="space-between" useFlexGap sx={{ mb: 1, flexWrap: 'wrap', rowGap: 1, columnGap: 1, maxWidth: '100%' }}>
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flex: 1, minWidth: 0, maxWidth: '100%', flexWrap: 'wrap', rowGap: 1 }}>
          {policyMsg && <Chip label={policyMsg} color="warning" size="small" />}
          <Tooltip title="WebSocket status">
            <Chip label={isCompactUi ? `WS` : `WS: ${wsStatus}`} size="small" color={staticOnly ? 'default' : (wsStatus === 'connected' ? 'success' : wsStatus === 'connecting' ? 'warning' : 'default')} sx={chipCompactSx} />
          </Tooltip>
          {wsReconnectMsg && (
            <Tooltip title="Auto-reconnect in progress">
              <Chip label={wsReconnectMsg} size="small" color="info" variant="outlined" sx={chipCompactSx} />
            </Tooltip>
          )}
          <Tooltip title="Server-Sent Events status">
            <Chip aria-label="sse-status" label={isCompactUi ? `SSE` : `SSE: ${esConnected ? 'connected' : 'disconnected'}`} size="small" color={staticOnly ? 'default' : (esConnected ? 'success' : 'default')} sx={chipCompactSx} />
          </Tooltip>
          {/* Frida status chip */}
          {(() => {
            const attached = String(status?.attachStatus || '').toLowerCase() === 'attached';
            const portOpen = Boolean(health?.portOpen);
            const pid = typeof health?.pid === 'number' && health.pid > 0;
            const serverVersion = typeof health?.serverVersion === 'string' && health.serverVersion.length > 0;
            const ready = attached || portOpen || pid || serverVersion;
            const disabled = staticOnly;
            const label = disabled ? 'Frida: disabled' : (ready ? 'Frida: ready' : 'Frida: unavailable');
            const color: any = disabled ? 'default' : (ready ? 'success' : 'default');
            const tip = disabled
              ? 'Disabled by policy (static-only mode)'
              : ready
                ? (attached ? 'Attached' : (portOpen ? 'Port 27042 open' : (pid ? `PID ${health?.pid}` : 'Server detected')))
                : 'Frida unavailable – use Ensure (ADB+Frida) then Refresh';
            return (
              <Tooltip title={tip}>
                <Chip label={label} size="small" color={color} />
              </Tooltip>
            );
          })()}
          {/* Health chips */}
          {health && (
            <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1, '& .MuiChip-root': { height: 24 }, '& .MuiChip-label': { px: 0.75 } }}>
              <Tooltip title="Frida forward port status (TCP 27042)">
                <Chip aria-label="frida-port-status" icon={<LanIcon sx={{ fontSize: 16 }} />} label={isCompactUi ? `27042` : `27042 ${health.portOpen ? 'open' : 'closed'}`} size="small" color={health.portOpen ? 'success' : 'error'} sx={chipCompactSx} />
              </Tooltip>
              <Tooltip title="frida-server PID (if detected)">
                <Chip icon={<NumbersIcon sx={{ fontSize: 16 }} />} label={isCompactUi ? `PID` : `PID ${health.pid ?? '-'}`} size="small" sx={chipCompactSx} />
              </Tooltip>
              <Tooltip title="Client version detected via API">
                <Chip icon={<VerifiedIcon sx={{ fontSize: 16 }} />} label={isCompactUi ? `v` : `v${health.clientVersion ?? '-'}`} size="small" sx={chipCompactSx} />
              </Tooltip>
              {typeof health?.serverVersion === 'string' && (
                <Tooltip title="frida-server version reported by device">
                  <Chip icon={<VerifiedIcon sx={{ fontSize: 16 }} />} label={isCompactUi ? `srv` : `server ${health.serverVersion}`} size="small" sx={chipCompactSx} />
                </Tooltip>
              )}
              {typeof health?.clientVersion === 'string' && typeof health?.serverVersion === 'string' && (
                <Tooltip title="Client/Server version match">
                  <Chip size="small" color={String(health.clientVersion) === String(health.serverVersion) ? 'success' : 'warning'} label={isCompactUi ? (String(health.clientVersion) === String(health.serverVersion) ? 'ok' : 'm') : (String(health.clientVersion) === String(health.serverVersion) ? 'match' : 'mismatch')} sx={chipCompactSx} />
                </Tooltip>
              )}
              <Tooltip title="Binding address of forwarded device">
                <Chip icon={<LinkIcon sx={{ fontSize: 16 }} />} label={isCompactUi ? 'bind' : (health.binding || '127.0.0.1')} size="small" sx={chipCompactSx} />
              </Tooltip>
              <Tooltip title={staticOnly ? 'Disabled in static-only mode (policy)' : 'Attempt Ensure (ADB+Frida) if port is closed or PID missing'}>
                <span>
                  <Button variant="outlined" size="small" onClick={onEnsureCorellium} disabled={ensureRunning || staticOnly} aria-label="ensure-health">Ensure</Button>
                </span>
              </Tooltip>
              <Chip aria-label="execution-mode" label={`Mode: ${health.executionMode || 'unknown'}`} size="small" color={staticOnly ? 'warning' : 'success'} />
              {staticOnly && <Chip aria-label="static-only" label="Static-only" size="small" color="warning" />}
              <Tooltip title={determinismStatus === 'ok' ? 'Determinism OK' : determinismStatus === 'fail' ? 'Determinism FAIL' : 'Determinism unknown'}>
                <Chip aria-label="determinism-status" label={`Determinism: ${determinismStatus}`} size="small" color={determinismStatus === 'ok' ? 'success' : determinismStatus === 'fail' ? 'error' : 'default'} />
              </Tooltip>
              <Tooltip title={calibrationStatus === 'ok' ? 'Calibration OK' : calibrationStatus === 'stale' ? 'Calibration stale' : calibrationStatus === 'fail' ? 'Calibration FAIL' : calibrationStatus === 'missing' ? 'Calibration missing' : 'Calibration unknown'}>
                <Chip aria-label="calibration-status" label={`Calibration: ${calibrationStatus}`} size="small" color={calibrationStatus === 'ok' ? 'success' : calibrationStatus === 'stale' ? 'warning' : calibrationStatus === 'fail' ? 'error' : 'default'} />
              </Tooltip>
            </Stack>
          )}
          {/* Device summary */}
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1, '& .MuiChip-root': { height: 24 }, '& .MuiChip-label': { px: 0.75 } }}>
            <Chip size="small" color={devices.length > 0 ? 'default' : 'warning'} label={`Devices (${devices.length})`} />
            {!staticOnly && (
              <Button size="small" variant="outlined" onClick={onAttachToPackage} aria-label="Attach">Attach</Button>
            )}
            {(() => {
              try {
                const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id;
                const sel = selectedDeviceId || remote || devices[0]?.id || '';
                const selected = devices.find((d: any) => d.id === sel);
                const name = (selected?.name) || sel || '-';
                const isSelected = Boolean(sel);
                const attached = String(status?.attachStatus || '').toLowerCase() === 'attached';
                const available = Boolean(status?.available);
                const portOpen = Boolean(health?.portOpen);
                let color: any = 'default';
                if (isSelected) {
                  if (attached) color = 'success';
                  else if (!portOpen) color = 'error';
                  else if (available) color = 'info';
                  else color = 'warning';
                }
                const statusLabel = attached ? 'Attached' : (!portOpen ? 'Port 27042 closed' : (available ? 'Available' : 'Unavailable'));
                const forwarded = typeof sel === 'string' && String(sel).startsWith('socket@127.0.0.1:');
                const chipEl = (
                  <Chip size="small" color={color} label={`Selected ${name || '-'}`} aria-label="selected device"
                    onClick={(e: any) => setDevicePopoverEl(e.currentTarget)} clickable />
                );
                return (
                  <Tooltip title={`Selected: ${name || '-'} • ${statusLabel}`}>
                    {forwarded ? (
                      <Badge overlap="circular" variant="dot" color={portOpen ? 'success' : 'error'} anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}>
                        {chipEl}
                      </Badge>
                    ) : chipEl}
                  </Tooltip>
                );
              } catch { return null; }
            })()}
          </Stack>
          {/* Device popover */}
          <Popover open={devicePopoverOpen} anchorEl={devicePopoverEl} onClose={() => setDevicePopoverEl(null)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }} transformOrigin={{ vertical: 'top', horizontal: 'left' }}>
            <Box sx={{ p: 2, minWidth: 260 }}>
              {(() => {
                try {
                  const selId = (() => { const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id; return selectedDeviceId || remote || devices[0]?.id || ''; })();
                  const d = devices.find((x: any) => x.id === selId);
                  const type = d ? inferDeviceType(d) : 'unknown';
                  return (
                    <Stack spacing={1}>
                      <Typography variant="subtitle2">Selected device</Typography>
                      <Typography variant="body2">ID: {selId || '-'}</Typography>
                      <Typography variant="body2">Name: {d?.name || '-'}</Typography>
                      <Typography variant="body2">Type: {type}</Typography>
                      <Typography variant="body2">Port 27042: {health?.portOpen ? 'open' : 'closed'}</Typography>
                      <Typography variant="body2">frida-server PID: {typeof health?.pid === 'number' ? health.pid : '-'}</Typography>
                      {typeof health?.serverVersion === 'string' && <Typography variant="body2">server: {String(health.serverVersion)}</Typography>}
                      <Stack direction="row" spacing={1}>
                        <IconButton size="small" aria-label={favoriteDeviceIds.includes(selId) ? 'unpin device' : 'pin device'} data-testid={`pin-device-${String(d?.name || d?.id).replace(/[^a-zA-Z0-9_-]/g, '_')}`} onClick={() => {
                          if (!selId) return;
                          setFavoriteDeviceIds(prev => prev.includes(selId) ? prev.filter(x => x !== selId) : [...prev, selId]);
                        }}>
                          {favoriteDeviceIds.includes(selId) ? <StarIcon fontSize="small" color="warning" /> : <StarBorderIcon fontSize="small" />}
                        </IconButton>
                        <Button size="small" variant="outlined" onClick={() => { setDevicePopoverEl(null); const id = selId || devices[0]?.id; if (id) onLoadProcessesWithRetry(id); }}>Reload</Button>
                        <Button size="small" variant="outlined" onClick={() => { setDevicePopoverEl(null); onAttachToPackage(); }} disabled={staticOnly}>Attach</Button>
                        <Button size="small" variant="outlined" onClick={() => { try { navigator.clipboard.writeText(JSON.stringify({ selId, name: d?.name, type, health }, null, 2)); showCopyToast('Copied device diag'); } catch {} }}>Copy diag</Button>
                      </Stack>
                    </Stack>
                  );
                } catch { return <Box sx={{ p: 1 }} />; }
              })()}
            </Box>
          </Popover>
        </Stack>
        {/* Right side actions */}
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1 }}>
          <Button size="small" variant="outlined" aria-label="header-refresh" onClick={async () => { await onRefreshStatus(); await onRefreshHealth(); }}>Refresh</Button>
          <Typography variant="caption" color="text.secondary">Last updated {lastUpdatedElapsed}</Typography>
          <Tooltip title="Copy a concise status snapshot to the clipboard">
            <IconButton size="small" onClick={async () => { try { await navigator.clipboard.writeText(JSON.stringify(buildStatusSnapshot(), null, 2)); setConnectMsg('status copied'); setTimeout(() => setConnectMsg(''), 1200); showCopyToast('Copied status'); } catch {} }} aria-label="copy-status">
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Keyboard shortcuts (Ctrl+K, Ctrl+Shift+B, Ctrl+E, Ctrl+/, Esc)">
            <IconButton size="small" onClick={(e) => setHelpAnchorEl(e.currentTarget)} aria-label="open-help" aria-haspopup="dialog" aria-expanded={helpOpen}>
              <HelpOutlineIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Reset environment: close WS/SSE, clear UI state, refresh health">
            <Button size="small" variant="outlined" onClick={onResetEnvironment} aria-label="reset-environment">Reset</Button>
          </Tooltip>
          <IconButton size="small" aria-label="more" onClick={(e) => setMoreEl(e.currentTarget)}>
            <MoreVertIcon fontSize="small" />
          </IconButton>
          <Menu anchorEl={moreEl} open={moreOpen} onClose={() => setMoreEl(null)} anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }} transformOrigin={{ vertical: 'top', horizontal: 'right' }}>
            <MenuItem onClick={() => { setMoreEl(null); onEnsureCorellium(); }}>Ensure (ADB+Frida)</MenuItem>
            <MenuItem onClick={() => { setMoreEl(null); onRefreshHealth(); onRefreshStatus(); }}>Refresh health/status</MenuItem>
            <MenuItem onClick={() => { setMoreEl(null); onResetEnvironment(); }}>Reset environment</MenuItem>
            <MenuItem onClick={() => { setMoreEl(null); setDiagOpen(true); onRunDiagnosis(); }}>Diagnose connectivity</MenuItem>
          </Menu>
        </Stack>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Shortcuts: Ctrl+K, Ctrl+Shift+B, Ctrl+E, Ctrl+/, Esc</Typography>
      {error && (
        <Alert id="frida-error" severity="warning" sx={{ mb: 1 }}>{error}</Alert>
      )}
      {/* Help popover */}
      <Popover open={helpOpen} anchorEl={helpAnchorEl} onClose={() => setHelpAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}>
        <Box sx={{ p: 2 }}>
          <Typography variant="subtitle2">Keyboard shortcuts</Typography>
          <Typography variant="body2">Ctrl+K: Connect WS</Typography>
          <Typography variant="body2">Ctrl+Shift+B: Baseline</Typography>
          <Typography variant="body2">Ctrl+E: Upload Inline Script</Typography>
          <Typography variant="body2">Ctrl+/: Focus RPC args</Typography>
          <Typography variant="body2">Ctrl+L: Clear events</Typography>
          <Typography variant="body2">Esc: Disconnect WS/SSE</Typography>
        </Box>
      </Popover>
      {/* Diagnosis dialog */}
      <Dialog open={diagOpen} onClose={() => setDiagOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Connectivity diagnosis</DialogTitle>
        <DialogContent>
          {diagBusy ? (
            <Stack direction="row" spacing={1} alignItems="center" sx={{ my: 1 }}>
              <CircularProgress size={16} />
              <Typography variant="body2">Running checks…</Typography>
            </Stack>
          ) : (
            <Box sx={{ my: 1 }}>
              {Array.isArray(diagReport?.checks) && diagReport.checks.length > 0 ? (
                <Stack spacing={0.5}>
                  {diagReport.checks.map((c: any, i: number) => (
                    <Typography key={i} variant="body2" color={c.ok ? 'success.main' : 'error.main'}>
                      {c.name}: {c.ok ? 'OK' : (c.status ? `FAIL (${c.status})` : 'FAIL')}
                      {c.note ? ` – ${c.note}` : ''}
                      {c.error ? ` – ${c.error}` : ''}
                    </Typography>
                  ))}
                </Stack>
              ) : (
                <Typography variant="body2">No results.</Typography>
              )}
              {!staticOnly && !health?.portOpen && (
                <Alert severity="warning" sx={{ mt: 1 }}>Port 27042 closed. Try Ensure (ADB+Frida).</Alert>
              )}
              {staticOnly && (
                <Alert severity="info" sx={{ mt: 1 }}>Static-only policy is enabled. Dynamic actions are intentionally blocked.</Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => onRunDiagnosis()} disabled={diagBusy}>Re-run</Button>
          <Button onClick={() => setDiagOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
      {/* Connection controls */}
      <Paper variant="outlined" sx={{ p: 1.5 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Connection Controls</Typography>
        <Stack direction="row" spacing={2} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1 }}>
          <FormControlLabel control={<Switch checked={fridaMode === 'read_only'} onChange={(e) => {
            const next = e.target.checked ? 'read_only' : (fridaMode === 'advanced' ? 'advanced' : 'standard');
            setFridaMode(next);
            try { localStorage.setItem('aodsFridaMode', next); } catch {}
          }} />} label={fridaMode === 'read_only' ? 'Mode: Read-only' : fridaMode === 'advanced' ? 'Mode: Advanced' : 'Mode: Standard'} />
          <FormControlLabel control={<Switch checked={compactMode} onChange={(e) => setCompactMode(e.target.checked)} />} label="Compact" />
          <FormControlLabel control={<Switch checked={autoConnectWs && !staticOnly} onChange={(e) => { if (!staticOnly) setAutoConnectWs(e.target.checked); }} />} label="Auto-connect WS" />
          <Tooltip title={staticOnly ? 'Disabled in static-only mode (policy)' : 'Connect WebSocket'}>
            <span>
              <Button size="small" variant="outlined" disabled={staticOnly} onClick={async () => {
                try {
                  if (wsRef.current && wsStatus === 'connected') return;
                  setWsStatus('connecting');
                  const token = (() => { try { const raw = localStorage.getItem('aodsAuth'); if (!raw) return null; const j = JSON.parse(raw); return typeof j?.token === 'string' ? j.token : null; } catch { return null; } })();
                  if (!token) { setWsStatus('disconnected'); return; }
                  const mint = async () => {
                    const resp = await secureFetch(`/frida/ws-token`, { method: 'POST' });
                    if (resp.status === 409) throw new Error('Blocked by policy: static-only mode is enabled.');
                    if (!resp.ok) throw new Error('WS token mint failed');
                    const { token: t } = await resp.json();
                    return t as string;
                  };
                  await openWsWithRetry(buildWsUrl, mint,
                    (ws) => { wsRef.current = ws; setWsStatus('connected'); try { ws.onclose = () => { setWsStatus('disconnected'); }; } catch {} },
                    (ev) => setWsLast(String(ev.data || '')),
                    (msg) => { setError(msg); setWsStatus('disconnected'); }
                  );
                } catch (err: any) { setWsStatus('disconnected'); setError(String(err?.message || 'WebSocket init failed')); }
              }}>Connect WS</Button>
            </span>
          </Tooltip>
          <Button size="small" variant="outlined" onClick={() => { try { wsRef.current?.close(); } catch {} wsRef.current = null; setWsStatus('disconnected'); }}>Disconnect</Button>
          <Button size="small" variant="outlined" onClick={() => { try { wsRef.current?.send(JSON.stringify({ type: 'ping', ts: new Date().toISOString() })); } catch {} }}>Ping WS</Button>
          <Button size="small" variant="outlined" onClick={() => { const next = fridaMode === 'advanced' ? 'standard' : 'advanced'; setFridaMode(next); try { localStorage.setItem('aodsFridaMode', next); } catch {} }}>Toggle Advanced</Button>
        </Stack>
      </Paper>
    </>
  );
}
