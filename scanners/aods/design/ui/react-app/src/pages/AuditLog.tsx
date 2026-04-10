import React, { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import { AODSApiClient } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { secureFetch } from '../lib/api';
import type { AuditEvent } from '../types';
import {
  Box,
  Button,
  ButtonGroup,
  Chip,
  CircularProgress,
  Collapse,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { PageHeader, ErrorDisplay, LoadingSkeleton, EmptyState, AppToast } from '../components';
import { useToast } from '../hooks/useToast';
import EventNoteIcon from '@mui/icons-material/EventNote';
import { formatDateTime } from '../lib/format';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import RefreshIcon from '@mui/icons-material/Refresh';
import FilterListIcon from '@mui/icons-material/FilterList';
import ClearIcon from '@mui/icons-material/Clear';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import DownloadIcon from '@mui/icons-material/Download';

// Common audit actions for filtering
const COMMON_ACTIONS = [
  'login',
  'logout',
  'start_scan',
  'cancel_scan',
  'view_result',
  'download_artifact',
  'api_access',
  'config_change',
];

// Quick date range presets
const DATE_PRESETS = [
  { label: 'Last hour', hours: 1 },
  { label: 'Last 24h', hours: 24 },
  { label: 'Last 7 days', hours: 24 * 7 },
  { label: 'Last 30 days', hours: 24 * 30 },
];

const getISODateString = (hoursAgo: number): string => {
  const date = new Date(Date.now() - hoursAgo * 60 * 60 * 1000);
  return date.toISOString();
};

export function AuditLog() {
  const api = useMemo(() => new AODSApiClient(), []);
  const auth = useAuth();
  const { toast, showToast, closeToast } = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [exporting, setExporting] = useState(false);
  // Applied filters (what's actually sent to API)
  const [appliedFilters, setAppliedFilters] = useState({
    q: '',
    user: '',
    action: '',
    since: '',
    until: '',
  });
  // Pending filters (what's shown in the UI inputs)
  const [q, setQ] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [sinceFilter, setSinceFilter] = useState('');
  const [untilFilter, setUntilFilter] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const [uniqueUsers, setUniqueUsers] = useState<string[]>([]);
  const [uniqueActions, setUniqueActions] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState<string>('');
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load events with current applied filters
  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await api.getAuditEvents({
        resourceContains: appliedFilters.q || undefined,
        user: appliedFilters.user || undefined,
        action: appliedFilters.action || undefined,
        since: appliedFilters.since || undefined,
        until: appliedFilters.until || undefined,
        limit: pageSize,
        offset: page * pageSize,
        order: 'desc',
      });
      setEvents(res.items || []);
      setTotal(res.total || 0);
    } catch (e: any) {
      setError(e?.message || 'Failed to load audit');
    } finally {
      setLoading(false);
    }
  }, [api, appliedFilters, pageSize, page]);

  // Load unique users and actions once on mount (unfiltered)
  useEffect(() => {
    async function loadFilterOptions() {
      try {
        // Fetch a large batch without filters to get all unique users/actions
        const res = await api.getAuditEvents({ limit: 1000, offset: 0 });
        const users = new Set<string>();
        const actions = new Set<string>();
        (res.items || []).forEach((e: AuditEvent) => {
          if (e.user) users.add(e.user);
          if (e.action) actions.add(e.action);
        });
        setUniqueUsers(Array.from(users).sort());
        setUniqueActions(Array.from(new Set([...actions, ...COMMON_ACTIONS])).sort());
      } catch {
        // Fall back to common actions if fetch fails
        setUniqueActions([...COMMON_ACTIONS].sort());
      }
    }
    loadFilterOptions();
  }, [api]);

  // Load events when applied filters or pagination changes
  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(() => {
        load();
      }, 30000); // 30 seconds
    } else {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
        autoRefreshRef.current = null;
      }
    }
    return () => {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
        autoRefreshRef.current = null;
      }
    };
  }, [autoRefresh, load]);

  const toggleRow = (idx: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
      }
      return next;
    });
  };

  // Apply pending filters to trigger a reload
  const applyFilters = useCallback(() => {
    setAppliedFilters({
      q,
      user: userFilter,
      action: actionFilter,
      since: sinceFilter,
      until: untilFilter,
    });
    setPage(0);
  }, [q, userFilter, actionFilter, sinceFilter, untilFilter]);

  const clearFilters = () => {
    setQ('');
    setUserFilter('');
    setActionFilter('');
    setSinceFilter('');
    setUntilFilter('');
    setSelectedPreset('');
    setAppliedFilters({ q: '', user: '', action: '', since: '', until: '' });
    setPage(0);
  };

  const applyDatePreset = (hours: number, label: string) => {
    setSelectedPreset(label);
    const since = getISODateString(hours);
    setSinceFilter(since);
    setUntilFilter('');
    // Immediately apply the date preset
    setAppliedFilters((prev) => ({
      ...prev,
      since,
      until: '',
    }));
    setPage(0);
  };

  // Check if pending filters differ from applied filters
  const hasUnappliedChanges = q !== appliedFilters.q ||
    userFilter !== appliedFilters.user ||
    actionFilter !== appliedFilters.action ||
    sinceFilter !== appliedFilters.since ||
    untilFilter !== appliedFilters.until;

  const hasActiveFilters = appliedFilters.q || appliedFilters.user || appliedFilters.action || appliedFilters.since || appliedFilters.until;

  function exportCsv() {
    const headers = ['timestamp', 'user', 'action', 'resource', 'details'];
    const rows = events.map((e) => [
      e.timestamp,
      e.user,
      e.action,
      e.resource || '',
      JSON.stringify(e.details || {}),
    ]);
    const csv = [
      headers.join(','),
      ...rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_export_${new Date().toISOString().replace(/:/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('CSV exported');
  }

  async function exportFullLog() {
    setExporting(true);
    setError(null);
    try {
      const r = await secureFetch('/audit/export');
      if (!r.ok) throw new Error(`Export failed: ${r.status}`);
      const text = await r.text();
      // Convert NDJSON to CSV
      const lines = text.split('\n').filter((l) => l.trim());
      const parsed = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const headers = ['timestamp', 'user', 'action', 'resource', 'details'];
      const csvRows = parsed.map((e: any) => [
        e.timestamp || '',
        e.user || '',
        e.action || '',
        e.resource || '',
        JSON.stringify(e.details || {}),
      ]);
      const csv = [
        headers.join(','),
        ...csvRows.map((r: string[]) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')),
      ].join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_full_export_${new Date().toISOString().replace(/:/g, '-')}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('Full log exported');
    } catch (e: any) {
      setError(e?.message || 'Failed to export full log');
    } finally {
      setExporting(false);
    }
  }


  const getActionColor = (
    action: string
  ): 'success' | 'error' | 'warning' | 'info' | 'default' => {
    const a = action.toLowerCase();
    if (a.includes('login') || a.includes('success')) return 'success';
    if (a.includes('fail') || a.includes('error') || a.includes('denied')) return 'error';
    if (a.includes('cancel') || a.includes('warn')) return 'warning';
    if (a.includes('start') || a.includes('create')) return 'info';
    return 'default';
  };

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader
          title="Audit Log"
          subtitle="Track user actions and system events"
          actions={
            <Stack direction="row" spacing={1} alignItems="center">
              <FormControlLabel
                control={
                  <Switch
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                    size="small"
                  />
                }
                label={
                  <Stack direction="row" spacing={0.5} alignItems="center">
                    <AutorenewIcon fontSize="small" color={autoRefresh ? 'primary' : 'inherit'} />
                    <Typography variant="body2">Auto-refresh</Typography>
                  </Stack>
                }
              />
              <Tooltip title="Toggle Filters">
                <IconButton onClick={() => setShowFilters(!showFilters)} aria-label="Toggle filters">
                  <FilterListIcon color={hasActiveFilters ? 'primary' : 'inherit'} />
                </IconButton>
              </Tooltip>
              <Tooltip title="Refresh">
                <IconButton onClick={load} disabled={loading} aria-label="Refresh">
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Stack>
          }
        />

        {/* Filters Panel */}
        <Collapse in={showFilters}>
          <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
            <Stack spacing={2}>
              <Typography variant="subtitle2">Filters</Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                <TextField
                  label="Resource contains"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') applyFilters(); }}
                  size="small"
                  sx={{ minWidth: 200 }}
                />
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>User</InputLabel>
                  <Select
                    value={userFilter}
                    label="User"
                    onChange={(e) => setUserFilter(e.target.value)}
                  >
                    <MenuItem value="">All Users</MenuItem>
                    {uniqueUsers.map((u) => (
                      <MenuItem key={u} value={u}>
                        {u}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={actionFilter}
                    label="Action"
                    onChange={(e) => setActionFilter(e.target.value)}
                  >
                    <MenuItem value="">All Actions</MenuItem>
                    {uniqueActions.map((a) => (
                      <MenuItem key={a} value={a}>
                        {a}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <TextField
                  label="Since (ISO date)"
                  value={sinceFilter}
                  onChange={(e) => {
                    setSinceFilter(e.target.value);
                    setSelectedPreset('');
                  }}
                  size="small"
                  placeholder="2024-01-01T00:00:00Z"
                  sx={{ minWidth: 200 }}
                />
                <TextField
                  label="Until (ISO date)"
                  value={untilFilter}
                  onChange={(e) => {
                    setUntilFilter(e.target.value);
                    setSelectedPreset('');
                  }}
                  size="small"
                  placeholder="2024-12-31T23:59:59Z"
                  sx={{ minWidth: 200 }}
                />
              </Stack>
              {/* Date range presets */}
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" color="text.secondary">
                  Quick ranges:
                </Typography>
                <ButtonGroup size="small" variant="outlined">
                  {DATE_PRESETS.map((preset) => (
                    <Button
                      key={preset.label}
                      onClick={() => applyDatePreset(preset.hours, preset.label)}
                      variant={selectedPreset === preset.label ? 'contained' : 'outlined'}
                    >
                      {preset.label}
                    </Button>
                  ))}
                </ButtonGroup>
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <Button
                  variant="contained"
                  size="small"
                  onClick={applyFilters}
                  disabled={!hasUnappliedChanges}
                  color={hasUnappliedChanges ? 'primary' : 'inherit'}
                >
                  {hasUnappliedChanges ? 'Apply Filters' : 'Filters Applied'}
                </Button>
                {(hasActiveFilters || hasUnappliedChanges) && (
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<ClearIcon />}
                    onClick={clearFilters}
                  >
                    Clear Filters
                  </Button>
                )}
              </Stack>
            </Stack>
          </Paper>
        </Collapse>

        {/* Active filters as chips (shows applied filters) */}
        {hasActiveFilters && (
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {appliedFilters.q && (
              <Chip
                label={`Resource: ${appliedFilters.q}`}
                size="small"
                onDelete={() => {
                  setQ('');
                  setAppliedFilters((prev) => ({ ...prev, q: '' }));
                }}
              />
            )}
            {appliedFilters.user && (
              <Chip
                label={`User: ${appliedFilters.user}`}
                size="small"
                onDelete={() => {
                  setUserFilter('');
                  setAppliedFilters((prev) => ({ ...prev, user: '' }));
                }}
              />
            )}
            {appliedFilters.action && (
              <Chip
                label={`Action: ${appliedFilters.action}`}
                size="small"
                onDelete={() => {
                  setActionFilter('');
                  setAppliedFilters((prev) => ({ ...prev, action: '' }));
                }}
              />
            )}
            {appliedFilters.since && (
              <Chip
                label={`Since: ${appliedFilters.since}`}
                size="small"
                onDelete={() => {
                  setSinceFilter('');
                  setSelectedPreset('');
                  setAppliedFilters((prev) => ({ ...prev, since: '' }));
                }}
              />
            )}
            {appliedFilters.until && (
              <Chip
                label={`Until: ${appliedFilters.until}`}
                size="small"
                onDelete={() => {
                  setUntilFilter('');
                  setAppliedFilters((prev) => ({ ...prev, until: '' }));
                }}
              />
            )}
          </Stack>
        )}

        {/* Pagination controls */}
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Select
            size="small"
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(0);
            }}
            aria-label="Page size"
          >
            {[25, 50, 100, 200].map((n) => (
              <MenuItem key={n} value={n}>
                {n}
              </MenuItem>
            ))}
          </Select>
          <Typography variant="body2" color="text.secondary">
            Showing {total > 0 ? page * pageSize + 1 : 0}\u2013{Math.min((page + 1) * pageSize, total)} of {total} events
          </Typography>
          <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 1 }}>
            <Button
              aria-label="Prev page"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              Prev
            </Button>
            <Typography>
              Page {page + 1} / {Math.max(1, Math.ceil(total / pageSize))}
            </Typography>
            <Button
              aria-label="Next page"
              onClick={() =>
                setPage((p) => (p + 1 < Math.ceil(total / pageSize) ? p + 1 : p))
              }
              disabled={page + 1 >= Math.max(1, Math.ceil(total / pageSize))}
            >
              Next
            </Button>
            <Button variant="outlined" onClick={exportCsv}>
              Export Current View
            </Button>
            {auth.roles.includes('admin') && (
              <Button
                variant="outlined"
                onClick={exportFullLog}
                disabled={exporting}
                startIcon={exporting ? <CircularProgress size={16} /> : <DownloadIcon />}
                data-testid="export-full-log"
              >
                {exporting ? 'Exporting...' : 'Export Full Log'}
              </Button>
            )}
          </Box>
        </Stack>

        <ErrorDisplay error={error} onRetry={load} />

        {/* Events Table */}
        <Box
          role="table"
          aria-label="Audit Log"
          sx={{ border: 1, borderColor: 'divider', borderRadius: 2 }}
        >
          <Box
            role="row"
            sx={{
              display: 'grid',
              gridTemplateColumns: '40px 180px 100px 140px 1fr',
              px: 1,
              py: 0.75,
              bgcolor: 'background.default',
              fontWeight: 600,
            }}
          >
            <Box role="columnheader"></Box>
            <Box role="columnheader">Timestamp</Box>
            <Box role="columnheader">User</Box>
            <Box role="columnheader">Action</Box>
            <Box role="columnheader">Resource</Box>
          </Box>
          <Box>
            {loading && events.length === 0 && (
              <Box sx={{ p: 2 }}>
                <LoadingSkeleton variant="table" />
              </Box>
            )}
            {events.map((e, i) => (
              <React.Fragment key={i}>
                <Box
                  role="row"
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: '40px 180px 100px 140px 1fr',
                    px: 1,
                    py: 0.75,
                    borderTop: '1px solid',
                    borderColor: 'divider',
                    bgcolor: expandedRows.has(i) ? 'action.selected' : 'transparent',
                    '&:hover': { bgcolor: 'action.hover' },
                    cursor: 'pointer',
                    transition: 'background-color 0.15s',
                  }}
                  onClick={() => toggleRow(i)}
                >
                  <Box role="cell">
                    <IconButton size="small" aria-label={expandedRows.has(i) ? 'Collapse' : 'Expand'}>
                      {expandedRows.has(i) ? (
                        <ExpandLessIcon fontSize="small" />
                      ) : (
                        <ExpandMoreIcon fontSize="small" />
                      )}
                    </IconButton>
                  </Box>
                  <Box role="cell" sx={{ fontSize: '0.85rem', fontVariantNumeric: 'tabular-nums' }}>
                    {formatDateTime(e.timestamp)}
                  </Box>
                  <Box role="cell">
                    <Chip label={e.user} size="small" variant="outlined" />
                  </Box>
                  <Box role="cell">
                    <Chip
                      label={e.action}
                      size="small"
                      color={getActionColor(e.action)}
                    />
                  </Box>
                  <Tooltip title={e.resource || ''} placement="top-start" disableHoverListener={!e.resource || e.resource.length < 40}>
                    <Box
                      role="cell"
                      sx={{
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {e.resource}
                    </Box>
                  </Tooltip>
                </Box>
                <Collapse in={expandedRows.has(i)}>
                  <Box
                    sx={{
                      px: 2,
                      py: 1,
                      bgcolor: 'action.hover',
                      borderTop: '1px dashed',
                      borderColor: 'divider',
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>
                      Event Details
                    </Typography>
                    <Box
                      component="pre"
                      sx={{
                        fontSize: '0.75rem',
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        bgcolor: 'background.paper',
                        p: 1,
                        borderRadius: 1,
                        maxHeight: 200,
                        overflow: 'auto',
                      }}
                    >
                      {JSON.stringify(
                        {
                          timestamp: e.timestamp,
                          user: e.user,
                          action: e.action,
                          resource: e.resource,
                          ...(e.details || {}),
                        },
                        null,
                        2
                      )}
                    </Box>
                  </Box>
                </Collapse>
              </React.Fragment>
            ))}
            {!events.length && !loading && (
              <EmptyState icon={EventNoteIcon} message="No audit events found. Events will appear here as users interact with the system." />
            )}
          </Box>
        </Box>
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
