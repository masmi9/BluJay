import { useEffect, useMemo, useState, useCallback } from 'react';
import {
  Alert, Box, Button, Chip, CircularProgress, Divider, FormControl,
  FormControlLabel, Grid, InputLabel, MenuItem, Select, Stack, Switch,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DeleteSweepOutlinedIcon from '@mui/icons-material/DeleteSweepOutlined';
import DnsOutlinedIcon from '@mui/icons-material/DnsOutlined';
import ErrorIcon from '@mui/icons-material/Error';
import LogoutIcon from '@mui/icons-material/Logout';
import PaletteOutlinedIcon from '@mui/icons-material/PaletteOutlined';
import PersonOutlineIcon from '@mui/icons-material/PersonOutline';
import SaveIcon from '@mui/icons-material/Save';
import { secureFetch } from '../lib/api';
import { useApiQuery } from '../hooks';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { PageHeader, DataCard, ErrorDisplay, LoadingSkeleton, ConfirmDialog } from '../components';
import { useAuth } from '../context/AuthContext';
import type { EnvVarEntry } from '../types';
import { AODSApiClient } from '../services/api';
import { useToast } from '../hooks/useToast';
import { AppToast } from '../components';

/* ---------- constants ---------- */

const DASHBOARD_CARDS = ['Recent Scans', 'Gates Summary', 'Scan Trends', 'Active Scans', 'Tool Status'] as const;
const NOTIF_EVENTS = ['Scan complete', 'Scan failed', 'Gate violations'] as const;
const SHORTCUTS: { keys: string; description: string }[] = [
  { keys: 'Ctrl+K', description: 'Quick search' },
  { keys: 'Ctrl+N', description: 'New scan' },
  { keys: 'Esc', description: 'Close drawer/dialog' },
  { keys: '?', description: 'Show shortcuts' },
];
const FORMAT_OPTIONS = ['json', 'html', 'csv', 'txt'] as const;
const PROFILE_OPTIONS = [
  { value: 'lightning', label: 'Lightning', desc: '12 plugins, ~30s' },
  { value: 'fast', label: 'Fast', desc: '18 plugins, ~2 min' },
  { value: 'standard', label: 'Standard', desc: '41 plugins, ~5 min' },
  { value: 'deep', label: 'Deep', desc: '48 plugins, ~15 min' },
] as const;

/* ---------- helpers ---------- */

function decodeTokenExpiry(token: string | null): string | null {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (!payload.exp) return null;
    const diff = payload.exp * 1000 - Date.now();
    if (diff <= 0) return 'Expired';
    const hours = Math.floor(diff / 3600000);
    const mins = Math.floor((diff % 3600000) / 60000);
    return hours > 0 ? `Expires in ${hours}h ${mins}m` : `Expires in ${mins}m`;
  } catch {
    return null;
  }
}

/** Shared style for section headings with an icon. */
const sectionHeadingSx = {
  display: 'flex', alignItems: 'center', gap: 0.75,
  color: 'text.secondary', letterSpacing: 1.5, fontSize: '0.7rem',
} as const;

/** Forces Grid children to stretch to equal height. */
const stretchGridSx = { '& > .MuiGrid-item > *': { height: '100%' }, '& > .MuiGrid-item > * > .MuiPaper-root': { height: '100%' } } as const;

/* ---------- Kbd component ---------- */

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      component="span"
      sx={{
        fontFamily: 'monospace',
        fontSize: '0.8rem',
        fontWeight: 600,
        px: 0.8,
        py: 0.3,
        borderRadius: 0.5,
        bgcolor: 'action.selected',
        border: 1,
        borderColor: 'divider',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </Typography>
  );
}

/* ========================================================================== */
/*  Main Config Page                                                          */
/* ========================================================================== */

export function Config() {
  const auth = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean; title: string; message: string; action: () => void;
  }>({ open: false, title: '', message: '', action: () => {} });

  /* -- appearance -- */
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem('aodsSidebarOpen') === '0'; } catch { return false; }
  });
  const [themeMode, setThemeMode] = useState<'light' | 'dark'>(() => {
    try { return localStorage.getItem('aodsTheme') === 'dark' ? 'dark' : 'light'; } catch { return 'light'; }
  });
  const [contrast, setContrast] = useState<'normal' | 'high'>(() => {
    try { return localStorage.getItem('aodsContrast') === 'high' ? 'high' : 'normal'; } catch { return 'normal'; }
  });

  /* -- api health -- */
  const [apiHealthy, setApiHealthy] = useState<boolean | null>(null);
  const { data: infoData } = useApiQuery<{ apiVersion?: string; version?: string }>('/info', { silentError: true });
  const { data: toolsData } = useApiQuery<Record<string, { available?: boolean; version?: string }>>('/tools/status', { silentError: true });

  /* -- scan defaults -- */
  const [scanDefaults, setScanDefaults] = useLocalStorage<{ profile: string; formats: string[] }>(
    'aodsScanDefaults', { profile: 'standard', formats: ['json'] },
  );

  /* -- dashboard prefs -- */
  const [dashRefresh, setDashRefresh] = useLocalStorage<number>('aodsConfig_dashRefresh', 0);
  const [dashCards, setDashCards] = useLocalStorage<string[]>('aodsConfig_dashCards', [...DASHBOARD_CARDS]);

  /* -- table defaults -- */
  const [pageSize, setPageSize] = useLocalStorage<number>('aodsConfig_pageSize', 25);
  const [sortOrder, setSortOrder] = useLocalStorage<string>('aodsConfig_sortOrder', 'newest');
  const [compactRows, setCompactRows] = useLocalStorage<boolean>('aodsConfig_compactRows', false);

  /* -- notifications -- */
  const [notifEnabled, setNotifEnabled] = useLocalStorage<boolean>('aodsConfig_notifEnabled', false);
  const [notifEvents, setNotifEvents] = useLocalStorage<string[]>('aodsConfig_notifEvents', [...NOTIF_EVENTS]);
  const [notifPermission, setNotifPermission] = useState<string>(() => {
    try { return typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'; } catch { return 'unsupported'; }
  });

  /* -- session -- */
  const tokenExpiry = useMemo(() => decodeTokenExpiry(auth.token), [auth.token]);

  /* -- effects -- */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await secureFetch('/health');
        if (!cancelled) setApiHealthy(r.ok);
      } catch {
        if (!cancelled) setApiHealthy(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  /* -- handlers -- */
  function handleSidebarToggle(checked: boolean) {
    setSidebarCollapsed(checked);
    try { localStorage.setItem('aodsSidebarOpen', checked ? '0' : '1'); } catch { /* ignore */ }
  }

  function handleThemeToggle(checked: boolean) {
    const next = checked ? 'dark' : 'light';
    setThemeMode(next);
    try { localStorage.setItem('aodsTheme', next); } catch { /* ignore */ }
    try { (window as any).__aodsToggleTheme?.(); } catch { /* ignore */ }
  }

  function handleContrastToggle(checked: boolean) {
    const next = checked ? 'high' : 'normal';
    setContrast(next);
    try { localStorage.setItem('aodsContrast', next); } catch { /* ignore */ }
    try { (window as any).__aodsToggleContrast?.(); } catch { /* ignore */ }
  }

  async function handleNotifToggle(checked: boolean) {
    if (checked && typeof Notification !== 'undefined') {
      const perm = await Notification.requestPermission();
      setNotifPermission(perm);
      if (perm === 'granted') setNotifEnabled(true);
    } else {
      setNotifEnabled(false);
    }
  }

  function clearPreferences(prefix: string, label: string) {
    setConfirmDialog({
      open: true,
      title: `Clear ${label}?`,
      message: `This will remove all ${label.toLowerCase()} stored in your browser.`,
      action: () => {
        try {
          Object.keys(localStorage).filter(k => k.startsWith(prefix)).forEach(k => localStorage.removeItem(k));
          setOk(`Cleared ${label}`);
        } catch { setError('Failed to clear'); }
        setConfirmDialog(p => ({ ...p, open: false }));
      },
    });
  }

  function toggleChip<T extends string>(list: T[], item: T): T[] {
    return list.includes(item) ? list.filter(x => x !== item) : [...list, item];
  }

  const isAdmin = auth.roles.includes('admin');

  /* -- render -- */
  return (
    <Box sx={{ maxWidth: 960, mx: 'auto' }}>
      <PageHeader
        title="Configuration"
        subtitle="Manage preferences, appearance, and system configuration"
      />

      <Stack spacing={3}>
        <ErrorDisplay error={error} />
        {ok && <Alert severity="success" onClose={() => setOk(null)}>{ok}</Alert>}

        {/* ============ System Status ============ */}
        <DataCard title="General Settings">
          <Stack spacing={2}>
            <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>API Status:</Typography>
              {apiHealthy === null ? (
                <Chip label="Checking..." size="small" />
              ) : apiHealthy ? (
                <Chip icon={<CheckCircleIcon />} label="Connected" size="small" color="success" />
              ) : (
                <Chip icon={<ErrorIcon />} label="Disconnected" size="small" color="error" />
              )}
              {infoData?.version && (
                <Chip label={`v${infoData.version}`} size="small" variant="outlined" />
              )}
              {infoData?.apiVersion && (
                <Chip label={`API v${infoData.apiVersion}`} size="small" variant="outlined" />
              )}
            </Stack>
            {toolsData && (
              <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                {Object.entries(toolsData).map(([name, info]) => (
                  <Chip
                    key={name}
                    label={`${name}${info?.version ? ` v${info.version}` : ''}`}
                    size="small"
                    color={info?.available ? 'success' : 'default'}
                    variant="outlined"
                  />
                ))}
              </Stack>
            )}
          </Stack>
        </DataCard>

        {/* ============ Preferences Section ============ */}
        <Divider>
          <Typography variant="overline" sx={sectionHeadingSx}>
            <PaletteOutlinedIcon fontSize="small" /> Preferences
          </Typography>
        </Divider>

        <Grid container spacing={2} sx={stretchGridSx}>
          {/* Appearance */}
          <Grid item xs={12} md={6}>
            <DataCard title="Appearance">
              <Stack spacing={1}>
                <Typography variant="body2" color="text.secondary">
                  Customize the look and feel of the interface.
                </Typography>
                <FormControlLabel
                  control={<Switch checked={sidebarCollapsed} onChange={e => handleSidebarToggle(e.target.checked)} />}
                  label="Sidebar collapsed"
                />
                <FormControlLabel
                  control={<Switch checked={themeMode === 'dark'} onChange={e => handleThemeToggle(e.target.checked)} />}
                  label="Dark theme"
                />
                <FormControlLabel
                  control={<Switch checked={contrast === 'high'} onChange={e => handleContrastToggle(e.target.checked)} />}
                  label="High contrast"
                />
              </Stack>
            </DataCard>
          </Grid>

          {/* Scan Defaults */}
          <Grid item xs={12} md={6}>
            <DataCard title="Scan Defaults">
              <Stack spacing={2}>
                <Typography variant="body2" color="text.secondary">
                  Default scan settings used by the New Scan page.
                </Typography>
                <FormControl size="small" fullWidth>
                  <InputLabel id="default-profile-label">Default Profile</InputLabel>
                  <Select
                    labelId="default-profile-label"
                    label="Default Profile"
                    value={scanDefaults.profile}
                    onChange={e => setScanDefaults(p => ({ ...p, profile: e.target.value }))}
                  >
                    {PROFILE_OPTIONS.map(p => (
                      <MenuItem key={p.value} value={p.value}>
                        <Stack direction="row" justifyContent="space-between" sx={{ width: '100%' }}>
                          <span>{p.label}</span>
                          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                            {p.desc}
                          </Typography>
                        </Stack>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Typography variant="body2">Output formats:</Typography>
                  {FORMAT_OPTIONS.map(fmt => (
                    <Chip
                      key={fmt}
                      label={fmt.toUpperCase()}
                      size="small"
                      color={scanDefaults.formats.includes(fmt) ? 'primary' : 'default'}
                      variant={scanDefaults.formats.includes(fmt) ? 'filled' : 'outlined'}
                      onClick={() => setScanDefaults(p => ({ ...p, formats: toggleChip(p.formats, fmt) }))}
                    />
                  ))}
                </Stack>
              </Stack>
            </DataCard>
          </Grid>
        </Grid>

        <Grid container spacing={2} sx={stretchGridSx}>
          {/* Dashboard Preferences */}
          <Grid item xs={12} md={6}>
            <Box data-testid="config-dashboard-prefs">
              <DataCard title="Dashboard Preferences">
                <Stack spacing={2}>
                  <FormControl size="small" fullWidth>
                    <InputLabel id="dash-refresh-label">Auto-refresh interval</InputLabel>
                    <Select
                      labelId="dash-refresh-label"
                      label="Auto-refresh interval"
                      value={dashRefresh}
                      onChange={e => setDashRefresh(Number(e.target.value))}
                      data-testid="dash-refresh-select"
                    >
                      <MenuItem value={0}>Off</MenuItem>
                      <MenuItem value={30}>30s</MenuItem>
                      <MenuItem value={60}>60s</MenuItem>
                      <MenuItem value={120}>120s</MenuItem>
                    </Select>
                  </FormControl>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 0.75 }}>Visible cards:</Typography>
                    <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                      {DASHBOARD_CARDS.map(card => (
                        <Chip
                          key={card}
                          label={card}
                          size="small"
                          color={dashCards.includes(card) ? 'primary' : 'default'}
                          variant={dashCards.includes(card) ? 'filled' : 'outlined'}
                          onClick={() => setDashCards(prev => toggleChip([...prev], card))}
                        />
                      ))}
                    </Stack>
                  </Box>
                </Stack>
              </DataCard>
            </Box>
          </Grid>

          {/* Table Defaults */}
          <Grid item xs={12} md={6}>
            <Box data-testid="config-table-defaults">
              <DataCard title="Table Defaults">
                <Stack spacing={2}>
                  <FormControl size="small" fullWidth>
                    <InputLabel id="page-size-label">Default page size</InputLabel>
                    <Select
                      labelId="page-size-label"
                      label="Default page size"
                      value={pageSize}
                      onChange={e => setPageSize(Number(e.target.value))}
                      data-testid="page-size-select"
                    >
                      <MenuItem value={10}>10</MenuItem>
                      <MenuItem value={25}>25</MenuItem>
                      <MenuItem value={50}>50</MenuItem>
                      <MenuItem value={100}>100</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl size="small" fullWidth>
                    <InputLabel id="sort-order-label">Default sort order</InputLabel>
                    <Select
                      labelId="sort-order-label"
                      label="Default sort order"
                      value={sortOrder}
                      onChange={e => setSortOrder(e.target.value)}
                      data-testid="sort-order-select"
                    >
                      <MenuItem value="newest">Newest first</MenuItem>
                      <MenuItem value="oldest">Oldest first</MenuItem>
                      <MenuItem value="severity">Severity (desc)</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControlLabel
                    control={<Switch checked={compactRows} onChange={e => setCompactRows(e.target.checked)} />}
                    label="Compact rows"
                  />
                </Stack>
              </DataCard>
            </Box>
          </Grid>
        </Grid>

        <Grid container spacing={2} sx={stretchGridSx}>
          {/* Notifications */}
          <Grid item xs={12} md={6}>
            <Box data-testid="config-notifications">
              <DataCard title="Notification Preferences">
                <Stack spacing={2}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <FormControlLabel
                      control={
                        <Switch
                          checked={notifEnabled}
                          onChange={e => handleNotifToggle(e.target.checked)}
                          disabled={notifPermission === 'unsupported'}
                        />
                      }
                      label="Enable browser notifications"
                    />
                    <Chip
                      label={notifPermission === 'unsupported' ? 'Not supported' : notifPermission}
                      size="small"
                      color={notifPermission === 'granted' ? 'success' : notifPermission === 'denied' ? 'error' : 'default'}
                      data-testid="notif-permission-chip"
                    />
                  </Stack>
                  {notifEnabled && (
                    <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                      <Typography variant="body2">Notification events:</Typography>
                      {NOTIF_EVENTS.map(evt => (
                        <Chip
                          key={evt}
                          label={evt}
                          size="small"
                          color={notifEvents.includes(evt) ? 'primary' : 'default'}
                          variant={notifEvents.includes(evt) ? 'filled' : 'outlined'}
                          onClick={() => setNotifEvents(prev => toggleChip([...prev], evt))}
                        />
                      ))}
                    </Stack>
                  )}
                </Stack>
              </DataCard>
            </Box>
          </Grid>

          {/* Keyboard Shortcuts */}
          <Grid item xs={12} md={6}>
            <Box data-testid="config-shortcuts">
              <DataCard title="Keyboard Shortcuts">
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600, width: 120 }}>Shortcut</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {SHORTCUTS.map(s => (
                        <TableRow key={s.keys} sx={{ '&:last-child td': { borderBottom: 0 } }}>
                          <TableCell><Kbd>{s.keys}</Kbd></TableCell>
                          <TableCell>
                            <Typography variant="body2">{s.description}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </DataCard>
            </Box>
          </Grid>
        </Grid>

        {/* ============ Account Section ============ */}
        <Divider>
          <Typography variant="overline" sx={sectionHeadingSx}>
            <PersonOutlineIcon fontSize="small" /> Account
          </Typography>
        </Divider>

        <Box data-testid="config-session">
          <DataCard title="Session Info">
            <Stack spacing={1.5}>
              <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>Status:</Typography>
                {auth.token ? (
                  <Chip label="Logged in" size="small" color="success" />
                ) : (
                  <Chip label="Not logged in" size="small" color="default" />
                )}
                {tokenExpiry && (
                  <Chip
                    label={tokenExpiry}
                    size="small"
                    color={tokenExpiry === 'Expired' ? 'error' : 'default'}
                    variant="outlined"
                  />
                )}
              </Stack>
              {auth.roles.length > 0 && (
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>Roles:</Typography>
                  {auth.roles.map(role => (
                    <Chip key={role} label={role} size="small" color="primary" variant="outlined" />
                  ))}
                </Stack>
              )}
              <Box>
                <Button
                  size="small"
                  variant="outlined"
                  color="error"
                  startIcon={<LogoutIcon />}
                  onClick={() => auth.logout()}
                >
                  Sign out
                </Button>
              </Box>
            </Stack>
          </DataCard>
        </Box>

        {/* ============ Administration Section (admin only) ============ */}
        {isAdmin && (
          <>
            <Divider>
              <Typography variant="overline" sx={sectionHeadingSx}>
                <DnsOutlinedIcon fontSize="small" /> Administration
              </Typography>
            </Divider>

            <AgentSettingsCard setError={setError} setOk={setOk} />
            <EnvVarsCard />
          </>
        )}

        {/* ============ Data Management ============ */}
        <Divider>
          <Typography variant="overline" sx={sectionHeadingSx}>
            <DeleteSweepOutlinedIcon fontSize="small" /> Data
          </Typography>
        </Divider>

        <DataCard title="Data Management">
          <Stack spacing={2}>
            <Typography variant="body2" color="text.secondary">
              Clear cached preferences stored in your browser. This does not affect server-side data.
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              <Button size="small" variant="outlined" onClick={() => clearPreferences('aodsNewScan_', 'New Scan preferences')}>
                Clear New Scan preferences
              </Button>
              <Button size="small" variant="outlined" onClick={() => clearPreferences('aodsResults_', 'Table preferences')}>
                Clear table preferences
              </Button>
              <Button size="small" variant="outlined" color="warning" onClick={() => clearPreferences('aods', 'All AODS preferences')}>
                Clear all preferences
              </Button>
            </Stack>
          </Stack>
        </DataCard>
      </Stack>

      <ConfirmDialog
        open={confirmDialog.open}
        title={confirmDialog.title}
        message={confirmDialog.message}
        severity="warning"
        confirmLabel="Clear"
        onConfirm={confirmDialog.action}
        onCancel={() => setConfirmDialog(p => ({ ...p, open: false }))}
      />
    </Box>
  );
}

/* ========================================================================== */
/*  Agent Settings Card (admin-only)                                          */
/* ========================================================================== */

const apiClient = new AODSApiClient();

function AgentSettingsCard({ setError, setOk }: { setError: (s: string | null) => void; setOk: (s: string | null) => void }) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [provider, setProvider] = useState('anthropic');
  const [model, setModel] = useState('');
  const [maxIterations, setMaxIterations] = useState(20);
  const [costLimit, setCostLimit] = useState(1.0);
  const [maxWallTime, setMaxWallTime] = useState(300);
  const [perAgentOverrides, setPerAgentOverrides] = useState<Record<string, any>>({});

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true);
      const cfg = await apiClient.getAgentConfig();
      setEnabled(cfg.enabled);
      setProvider(cfg.provider || 'anthropic');
      setModel(cfg.model || '');
      setMaxIterations((cfg.budget as any)?.max_iterations ?? 20);
      setCostLimit((cfg.budget as any)?.cost_limit_usd ?? 1.0);
      setMaxWallTime((cfg.budget as any)?.max_wall_time_seconds ?? 300);
      setPerAgentOverrides(cfg.agents || {});
    } catch {
      // Agent system may be disabled (503) - show defaults
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchConfig(); }, [fetchConfig]);

  async function handleSave() {
    try {
      setSaving(true);
      setError(null);
      const updated = await apiClient.updateAgentConfig({
        enabled,
        provider,
        model: model || undefined,
        max_iterations: maxIterations,
        cost_limit_usd: costLimit,
        max_wall_time_seconds: maxWallTime,
      });
      setEnabled(updated.enabled);
      setProvider(updated.provider || 'anthropic');
      setModel(updated.model || '');
      setMaxIterations((updated.budget as any)?.max_iterations ?? maxIterations);
      setCostLimit((updated.budget as any)?.cost_limit_usd ?? costLimit);
      setMaxWallTime((updated.budget as any)?.max_wall_time_seconds ?? maxWallTime);
      setPerAgentOverrides(updated.agents || {});
      setOk('Agent settings saved');
    } catch (e: any) {
      setError(e?.message || 'Failed to save agent settings');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Box data-testid="config-agent-settings">
      <DataCard title="Agent Settings">
        {loading ? (
          <LoadingSkeleton variant="list" />
        ) : (
          <Stack spacing={2.5}>
            <FormControlLabel
              control={
                <Switch
                  checked={enabled}
                  onChange={e => setEnabled(e.target.checked)}
                  data-testid="agent-enabled-toggle"
                />
              }
              label="Agent system enabled"
            />

            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControl size="small" fullWidth>
                  <InputLabel id="agent-provider-label">Provider</InputLabel>
                  <Select
                    labelId="agent-provider-label"
                    label="Provider"
                    value={provider}
                    onChange={e => setProvider(e.target.value)}
                    data-testid="agent-provider-select"
                  >
                    <MenuItem value="anthropic">Anthropic</MenuItem>
                    <MenuItem value="openai">OpenAI</MenuItem>
                    <MenuItem value="ollama">Ollama</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  size="small"
                  fullWidth
                  label="Model"
                  value={model}
                  onChange={e => setModel(e.target.value)}
                  placeholder="e.g. claude-sonnet-4-6"
                  data-testid="agent-model-input"
                />
              </Grid>
            </Grid>

            <Grid container spacing={2}>
              <Grid item xs={6} sm={4}>
                <TextField
                  size="small"
                  fullWidth
                  label="Max iterations"
                  type="number"
                  value={maxIterations}
                  onChange={e => setMaxIterations(Math.max(1, Math.min(200, Number(e.target.value) || 1)))}
                  inputProps={{ min: 1, max: 200 }}
                  data-testid="agent-max-iterations-input"
                />
              </Grid>
              <Grid item xs={6} sm={4}>
                <TextField
                  size="small"
                  fullWidth
                  label="Max wall time (s)"
                  type="number"
                  value={maxWallTime}
                  onChange={e => setMaxWallTime(Math.max(10, Math.min(3600, Number(e.target.value) || 10)))}
                  inputProps={{ min: 10, max: 3600 }}
                  data-testid="agent-wall-time-input"
                />
              </Grid>
              <Grid item xs={6} sm={4}>
                <TextField
                  size="small"
                  fullWidth
                  label="Cost limit (USD)"
                  type="number"
                  value={costLimit}
                  onChange={e => setCostLimit(Math.max(0.01, Math.min(100, Number(e.target.value) || 0.01)))}
                  inputProps={{ min: 0.01, max: 100, step: 0.1 }}
                  data-testid="agent-cost-limit-input"
                />
              </Grid>
            </Grid>

            {Object.keys(perAgentOverrides).length > 0 && (
              <Box data-testid="agent-per-agent-overrides">
                <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>
                  Per-Agent Overrides
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                  {Object.entries(perAgentOverrides).map(([agent, cfg]) => (
                    <Chip
                      key={agent}
                      label={`${agent}: ${(cfg as any)?.max_iterations ?? ''} iters${(cfg as any)?.model ? `, ${(cfg as any).model}` : ''}`}
                      size="small"
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Box>
            )}

            <Box>
              <Button
                size="small"
                variant="contained"
                startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
                onClick={handleSave}
                disabled={saving}
                data-testid="agent-settings-save"
              >
                {saving ? 'Saving...' : 'Save'}
              </Button>
            </Box>
          </Stack>
        )}
      </DataCard>
    </Box>
  );
}

/* ========================================================================== */
/*  Environment Variables Card (admin-only)                                   */
/* ========================================================================== */

const CATEGORY_LABELS: Record<string, string> = {
  execution: 'Execution',
  ml: 'ML Pipeline',
  security: 'Security',
  frida: 'Frida',
  ui: 'UI',
  performance: 'Performance',
  debug: 'Debug',
  plugin: 'Plugin',
  reporting: 'Reporting',
  testing: 'Testing',
};

const CATEGORY_ORDER = ['execution', 'ml', 'security', 'frida', 'performance', 'plugin', 'reporting', 'ui', 'debug', 'testing'];

function EnvVarsCard() {
  const api = useMemo(() => new AODSApiClient(), []);
  const { toast, showToast, closeToast } = useToast();
  const [categories, setCategories] = useState<Record<string, EnvVarEntry[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [filterCategory, setFilterCategory] = useState('all');
  const [search, setSearch] = useState('');

  const fetchVars = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getEnvSummary();
      setCategories(res.categories || {});
    } catch (e: any) {
      setError(e?.message || 'Failed to load environment variables');
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { fetchVars(); }, [fetchVars]);

  const handleSave = async (name: string) => {
    setSaving(true);
    try {
      await api.updateEnvVar(name, editValue);
      showToast(`${name} updated`);
      setEditing(null);
      fetchVars();
    } catch (e: any) {
      showToast(e?.message || 'Update failed', 'error');
    } finally {
      setSaving(false);
    }
  };

  const sortedCategories = useMemo(() => CATEGORY_ORDER.filter(c => c in categories), [categories]);

  const filteredVars = useMemo(() => {
    const result: (EnvVarEntry & { category: string })[] = [];
    const cats = filterCategory === 'all' ? sortedCategories : [filterCategory];
    for (const cat of cats) {
      for (const v of (categories[cat] || [])) {
        if (search && !v.name.toLowerCase().includes(search.toLowerCase()) && !v.description.toLowerCase().includes(search.toLowerCase())) continue;
        result.push({ ...v, category: cat });
      }
    }
    return result;
  }, [categories, filterCategory, sortedCategories, search]);

  const isSensitive = (name: string) => name.includes('PASSWORD') || name.includes('SECRET') || name.includes('KEY');

  return (
    <Box data-testid="config-env-vars">
      <DataCard title="Environment Variables">
        {loading ? (
          <LoadingSkeleton variant="table" />
        ) : error ? (
          <ErrorDisplay error={error} onRetry={fetchVars} />
        ) : (
          <Stack spacing={2}>
            <Typography variant="body2" color="text.secondary">
              Runtime environment variables. Changes take effect immediately but do not persist across server restarts.
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <TextField
                size="small"
                placeholder="Search variables..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                sx={{ minWidth: 200, flexGrow: 1 }}
                inputProps={{ 'aria-label': 'Search environment variables' }}
              />
              <FormControl size="small" sx={{ minWidth: 140 }}>
                <InputLabel>Category</InputLabel>
                <Select
                  label="Category"
                  value={filterCategory}
                  onChange={e => setFilterCategory(e.target.value)}
                  data-testid="env-category-filter"
                >
                  <MenuItem value="all">All</MenuItem>
                  {sortedCategories.map(c => (
                    <MenuItem key={c} value={c}>{CATEGORY_LABELS[c] || c}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Chip label={`${filteredVars.length} variables`} size="small" variant="outlined" />
            </Stack>
            <TableContainer sx={{ borderRadius: 1 }}>
              <Table size="small" data-testid="env-vars-table">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Variable</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Value</TableCell>
                    <TableCell sx={{ fontWeight: 600, display: { xs: 'none', sm: 'table-cell' } }}>Default</TableCell>
                    <TableCell sx={{ fontWeight: 600, display: { xs: 'none', md: 'table-cell' } }}>Category</TableCell>
                    <TableCell sx={{ fontWeight: 600, width: 80 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredVars.map(v => (
                    <TableRow key={v.name} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', fontWeight: 500 }}>
                          {v.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', maxWidth: 300 }}>
                          {v.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {editing === v.name ? (
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <TextField
                              size="small"
                              value={editValue}
                              onChange={e => setEditValue(e.target.value)}
                              onKeyDown={e => {
                                if (e.key === 'Enter') handleSave(v.name);
                                if (e.key === 'Escape') setEditing(null);
                              }}
                              sx={{ minWidth: 120, '& input': { fontFamily: 'monospace', fontSize: '0.8rem' } }}
                              autoFocus
                            />
                            <Button size="small" variant="contained" onClick={() => handleSave(v.name)} disabled={saving}>
                              {saving ? '...' : 'Save'}
                            </Button>
                            <Button size="small" onClick={() => setEditing(null)}>Cancel</Button>
                          </Stack>
                        ) : (
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', fontVariantNumeric: 'tabular-nums' }}>
                              {isSensitive(v.name) ? '********' : String(v.current)}
                            </Typography>
                            {v.is_set && <Chip label="SET" size="small" color="primary" variant="outlined" sx={{ height: 18, fontSize: 10 }} />}
                          </Stack>
                        )}
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}>
                          {isSensitive(v.name) ? '********' : String(v.default)}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Chip label={CATEGORY_LABELS[v.category] || v.category} size="small" variant="outlined" sx={{ fontSize: 11 }} />
                      </TableCell>
                      <TableCell>
                        {!isSensitive(v.name) && editing !== v.name && (
                          <Button size="small" onClick={() => { setEditing(v.name); setEditValue(String(v.current)); }}>
                            Edit
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Stack>
        )}
      </DataCard>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
