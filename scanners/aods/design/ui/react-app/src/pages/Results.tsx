import { useEffect, useMemo, useState, useRef, useCallback, Fragment } from 'react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import { AODSApiClient } from '../services/api';
import type { ScanResult } from '../types';
import {
  Box, Chip, IconButton, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
  FormControl, InputLabel, Select, MenuItem, Button, Collapse,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DownloadIcon from '@mui/icons-material/Download';
import SearchOffIcon from '@mui/icons-material/SearchOff';
import ScienceIcon from '@mui/icons-material/Science';
import FilterListOffIcon from '@mui/icons-material/FilterListOff';
import { secureFetch } from '../lib/api';
import { computeReportStats } from '../lib/reports';
import { formatDateTime } from '../lib/format';
import { PageHeader, ErrorDisplay, LoadingSkeleton, EmptyState, AppToast } from '../components';
import { useToast } from '../hooks/useToast';

/* ── Helpers ─────────────────────────────────────────────── */

const PERSIST_DELAY = 300;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
const pendingWrites: Record<string, string> = {};

function debouncedPersist(key: string, value: string) {
  pendingWrites[key] = value;
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      for (const [k, v] of Object.entries(pendingWrites)) localStorage.setItem(k, v);
    } catch {}
    for (const k of Object.keys(pendingWrites)) delete pendingWrites[k];
    persistTimer = null;
  }, PERSIST_DELAY);
}

const SEV_COLORS: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#1976d2',
  info: '#9e9e9e',
};

/** Thin proportional bar showing severity distribution at a glance. */
function SeverityBar({ critical = 0, high = 0, medium = 0, low = 0, info = 0 }: Record<string, number>) {
  const total = critical + high + medium + low + info;
  if (total === 0) return null;
  const segments = [
    { count: critical, color: SEV_COLORS.critical, label: 'Critical' },
    { count: high, color: SEV_COLORS.high, label: 'High' },
    { count: medium, color: SEV_COLORS.medium, label: 'Medium' },
    { count: low, color: SEV_COLORS.low, label: 'Low' },
    { count: info, color: SEV_COLORS.info, label: 'Info' },
  ];
  return (
    <Tooltip title={segments.filter(s => s.count > 0).map(s => `${s.label}: ${s.count}`).join(' · ')}>
      <Box sx={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', width: '100%', bgcolor: 'action.disabledBackground' }}>
        {segments.map((seg, i) => seg.count > 0 && (
          <Box key={i} sx={{ flex: seg.count, bgcolor: seg.color, minWidth: 2 }} />
        ))}
      </Box>
    </Tooltip>
  );
}

/** Human-readable relative time. */
function relativeTime(dateStr?: string): string {
  if (!dateStr) return '';
  const diff = Date.now() - Date.parse(dateStr);
  if (isNaN(diff)) return '';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

/** Extract a clean display name from a scan ID. */
function scanDisplayName(id: string, apkName?: string | null): string {
  if (apkName) return apkName;
  // scan_validation_YYYYMMDD_HHMMSS -> "Validation scan"
  if (/^scan_validation/i.test(id)) return 'Validation scan';
  // aods_parallel_<package>_<timestamp> or <package>_security_report
  let cleaned = id
    .replace(/^aods_parallel_/, '')
    .replace(/^aods_/, '')
    .replace(/_security_report.*$/, '')
    .replace(/_\d{10,}$/, '')         // unix timestamp
    .replace(/_\d{8}_\d{6}_\w+$/, '') // YYYYMMDD_HHMMSS_hash
    .replace(/_standard_path.*$/, ''); // profile suffix
  // Package name: jakhar.aseem.diva -> DIVA, owasp.sat.agoat -> AndroGoat
  const dotParts = cleaned.split('.');
  if (dotParts.length >= 2) {
    const last = dotParts[dotParts.length - 1];
    return last.charAt(0).toUpperCase() + last.slice(1);
  }
  return cleaned.replace(/_/g, ' ') || id;
}

/** Read page size from Config settings, fallback to 25. */
const PAGE_SIZE: number = (() => { try { const v = localStorage.getItem('aodsConfig_pageSize'); return v ? JSON.parse(v) : 25; } catch { return 25; } })();

/* ── Component ───────────────────────────────────────────── */

export function Results() {
  const api = useMemo(() => new AODSApiClient(), []);
  const navigate = useNavigate();
  const { toast, showToast, closeToast } = useToast();
  const [items, setItems] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState(() => { try { return localStorage.getItem('aodsResults_q') || ''; } catch { return ''; } });
  const [sev, setSev] = useState<'all' | 'high' | 'medium' | 'low' | 'critical' | 'info'>(() => { try { return (localStorage.getItem('aodsResults_sev') as any) || 'all'; } catch { return 'all'; } });
  const [sortBy, setSortBy] = useState<'started' | 'findings'>(() => {
    try { const v = localStorage.getItem('aodsResults_sortBy'); if (v) return v as any; } catch {}
    // Fall back to Config default sort order
    try { const cfg = localStorage.getItem('aodsConfig_sortOrder'); const c = cfg ? JSON.parse(cfg) : null; if (c === 'severity') return 'findings'; } catch {}
    return 'started';
  });
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>(() => {
    try { const v = localStorage.getItem('aodsResults_sortDir'); if (v) return v as any; } catch {}
    try { const cfg = localStorage.getItem('aodsConfig_sortOrder'); const c = cfg ? JSON.parse(cfg) : null; if (c === 'oldest') return 'asc'; } catch {}
    return 'desc';
  });
  const [fromDate, setFromDate] = useState<string>(() => { try { return localStorage.getItem('aodsResults_from') || ''; } catch { return ''; } });
  const [toDate, setToDate] = useState<string>(() => { try { return localStorage.getItem('aodsResults_to') || ''; } catch { return ''; } });
  const [summaries, setSummaries] = useState<Record<string, any>>({});
  const [openKeys, setOpenKeys] = useState<string[]>(() => { try { return JSON.parse(localStorage.getItem('aodsResults_open') || '[]'); } catch { return []; } });
  const lastKeyRef = useRef<string>('');
  const [page, setPage] = useState(0);

  const loadResults = useCallback(async () => {
    setError(null);
    setIsLoading(true);
    try { const res = await api.getScanResults(); setItems(Array.isArray(res) ? res : []); }
    catch (e: any) { setError(e?.message || 'Failed to load results'); }
    finally { setIsLoading(false); }
  }, [api]);

  useEffect(() => { loadResults(); }, [loadResults]);

  useEffect(() => { try { localStorage.setItem('aodsResults_open', JSON.stringify(openKeys)); } catch {} }, [openKeys]);

  useEffect(() => {
    openKeys.forEach((k) => {
      if (k && !summaries[k]) {
        (async () => {
          try {
            setSummaries(prev => ({ ...prev, [k]: { loading: true } }));
            const r = await secureFetch(`/reports/read?path=${encodeURIComponent(k)}`);
            if (!r.ok) throw new Error(String(r.status));
            const j = await r.json();
            let data: any = null;
            try { data = (j && typeof j.content === 'string') ? JSON.parse(j.content) : j; } catch { data = null; }
            const stats = computeReportStats(data);
            setSummaries(prev => ({ ...prev, [k]: stats ? stats : { error: true } }));
          } catch {
            setSummaries(prev => ({ ...prev, [k]: { error: true } }));
          }
        })();
      }
    });
  }, [openKeys]);

  useEffect(() => { debouncedPersist('aodsResults_q', q); }, [q]);
  useEffect(() => { debouncedPersist('aodsResults_sev', sev); }, [sev]);
  useEffect(() => { debouncedPersist('aodsResults_sortBy', sortBy); }, [sortBy]);
  useEffect(() => { debouncedPersist('aodsResults_sortDir', sortDir); }, [sortDir]);
  useEffect(() => { debouncedPersist('aodsResults_from', fromDate); }, [fromDate]);
  useEffect(() => { debouncedPersist('aodsResults_to', toDate); }, [toDate]);

  const filteredItems = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return items.filter(it => {
      const matchQ = !needle || it.id.toLowerCase().includes(needle) || (it.profile || '').toLowerCase().includes(needle) || (it.apkName || '').toLowerCase().includes(needle);
      const s = it.summary || ({} as any);
      const matchSev = sev === 'all' || (sev === 'critical' ? (s.critical || 0) > 0 : sev === 'high' ? (s.high || 0) > 0 : sev === 'medium' ? (s.medium || 0) > 0 : sev === 'low' ? (s.low || 0) > 0 : (s.info || 0) > 0);
      const ts = it.startedAt ? Date.parse(it.startedAt) : NaN;
      const inFrom = fromDate ? (!isNaN(ts) && ts >= Date.parse(fromDate)) : true;
      const inTo = toDate ? (!isNaN(ts) && ts <= Date.parse(toDate)) : true;
      return matchQ && matchSev && inFrom && inTo;
    });
  }, [items, q, sev, fromDate, toDate]);

  const filtered = useMemo(() => {
    return [...filteredItems].sort((a, b) => {
      // Scans with findings always sort above empty scans
      const aHas = (a.summary?.findings ?? 0) > 0 ? 1 : 0;
      const bHas = (b.summary?.findings ?? 0) > 0 ? 1 : 0;
      if (aHas !== bHas) return bHas - aHas;

      if (sortBy === 'findings') {
        const fa = a.summary?.findings ?? 0;
        const fb = b.summary?.findings ?? 0;
        return sortDir === 'asc' ? fa - fb : fb - fa;
      }
      const ta = a.startedAt ? Date.parse(a.startedAt) : 0;
      const tb = b.startedAt ? Date.parse(b.startedAt) : 0;
      return sortDir === 'asc' ? ta - tb : tb - ta;
    });
  }, [filteredItems, sortBy, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginatedItems = useMemo(() => filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), [filtered, page]);

  // Reset page when filters change
  useEffect(() => { setPage(0); }, [q, sev, fromDate, toDate, sortBy, sortDir]);

  const allPreviewKeys = useMemo(() => paginatedItems.map(it => String(it.path || '')).filter(Boolean), [paginatedItems]);
  const allOpen = useMemo(() => allPreviewKeys.length > 0 && allPreviewKeys.every(k => openKeys.includes(k)), [allPreviewKeys.join(','), openKeys.join(',')]);

  const hasActiveFilters = q.trim() !== '' || sev !== 'all' || fromDate !== '' || toDate !== '';

  const clearFilters = useCallback(() => {
    setQ('');
    setSev('all');
    setFromDate('');
    setToDate('');
  }, []);

  // Keyboard shortcuts: Shift+E expand all, Shift+C collapse all, Shift+P toggle last
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === 'e') { e.preventDefault(); setOpenKeys(filtered.map(it => String(it.path || '')).filter(Boolean)); }
      else if (k === 'c') { e.preventDefault(); setOpenKeys([]); }
      else if (k === 'p') { e.preventDefault(); const last = lastKeyRef.current; if (last) setOpenKeys(prev => prev.includes(last) ? prev.filter(x => x !== last) : [...prev, last]); }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [filtered.map(it => String(it.path || '')).join(',')]);

  function exportJSON() {
    try {
      const data = filtered.map(it => ({ id: it.id, startedAt: it.startedAt, profile: it.profile, summary: it.summary || {} }));
      const blob = new Blob([JSON.stringify({ items: data }, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'results.json'; document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showToast('JSON exported');
    } catch { showToast('Export failed', 'error'); }
  }

  function exportCSV() {
    try {
      const rows = [['id', 'apk', 'startedAt', 'profile', 'findings', 'critical', 'high', 'medium', 'low', 'info']];
      for (const it of filtered) {
        const s = it.summary || ({} as any);
        rows.push([it.id, it.apkName || '', it.startedAt || '', it.profile || '', String(s.findings ?? 0), String(s.critical ?? 0), String(s.high ?? 0), String(s.medium ?? 0), String(s.low ?? 0), String(s.info ?? 0)]);
      }
      const esc = (v: string) => /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
      const csv = rows.map(r => r.map(esc).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'results.csv'; document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showToast('CSV exported');
    } catch { showToast('Export failed', 'error'); }
  }

  function sevCounts(s: any) {
    const c = (s?.critical ?? 0);
    const h = (s?.high ?? 0);
    const m = (s?.medium ?? 0);
    const l = (s?.low ?? 0);
    const i = (s?.info ?? 0);
    const sum = c + h + m + l + i;
    const reported = s?.findings ?? sum;
    return { critical: c, high: h, medium: m, low: l, info: i, sum, reported, unaccounted: Math.max(0, reported - sum) };
  }

  async function toggleDetails(it: ScanResult) {
    const k = String(it.path);
    if (!k) return;
    lastKeyRef.current = k;
    setOpenKeys(prev => prev.includes(k) ? prev.filter(x => x !== k) : [...prev, k]);
    if (!summaries[k]) {
      try {
        setSummaries(prev => ({ ...prev, [k]: { loading: true } }));
        const r = await secureFetch(`/reports/read?path=${encodeURIComponent(k)}`);
        if (!r.ok) throw new Error(String(r.status));
        const j = await r.json();
        let data: any = null;
        try { data = (j && typeof j.content === 'string') ? JSON.parse(j.content) : j; } catch { data = null; }
        const stats = computeReportStats(data);
        setSummaries(prev => ({ ...prev, [k]: stats ? stats : { error: true } }));
      } catch {
        setSummaries(prev => ({ ...prev, [k]: { error: true } }));
      }
    }
  }

  /* ── Render ──────────────────────────────────────────── */

  return (
    <Box>
      <PageHeader
        title="Scan Results"
        subtitle={items.length > 0 ? `${filtered.length} of ${items.length} scans` : undefined}
        actions={
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Tooltip title={allOpen ? 'Collapse all (Shift+C)' : 'Expand all (Shift+E)'}>
              <Button
                size="small"
                variant="outlined"
                onClick={() => { if (allPreviewKeys.length) setOpenKeys(allOpen ? [] : allPreviewKeys); }}
                aria-label={allOpen ? 'Collapse all previews' : 'Expand all previews'}
              >
                {allOpen ? 'Collapse' : 'Expand'}
              </Button>
            </Tooltip>
            <Button size="small" variant="outlined" onClick={exportCSV} data-testid="export-csv" aria-label="Export Results as CSV">CSV</Button>
            <Button size="small" variant="outlined" onClick={exportJSON} data-testid="export-json" aria-label="Export Results as JSON">JSON</Button>
          </Stack>
        }
      />

      {/* ── Filters ──────────────────────────────────────── */}
      <Paper variant="outlined" sx={{ px: 2, py: 1.25, mb: 2, borderRadius: 1.5 }}>
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
          <TextField
            size="small"
            placeholder="Search scans..."
            value={q}
            onChange={e => setQ(e.target.value)}
            inputProps={{ 'aria-label': 'Search scan results' }}
            sx={{ minWidth: 180, '& .MuiOutlinedInput-root': { borderRadius: 2, height: 32 } }}
          />
          <Stack direction="row" spacing={0.5} sx={{ bgcolor: 'action.hover', px: 0.5, py: 0.25, borderRadius: 1 }} role="group" aria-label="Filter by severity">
            {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(level => {
              const colorMap: Record<string, any> = { all: 'primary', critical: 'error', high: 'warning', medium: 'info', low: 'success', info: 'default' };
              return (
                <Chip
                  key={level}
                  label={level.charAt(0).toUpperCase() + level.slice(1)}
                  color={sev === level ? colorMap[level] : 'default'}
                  variant={sev === level ? 'filled' : 'outlined'}
                  onClick={() => setSev(level)}
                  clickable
                  size="small"
                  aria-pressed={sev === level}
                  sx={{ fontWeight: sev === level ? 600 : 400, height: 26 }}
                />
              );
            })}
          </Stack>
          <Box sx={{ flex: 1 }} />
          <TextField size="small" type="date" label="From" InputLabelProps={{ shrink: true }} value={fromDate} onChange={e => setFromDate(e.target.value)} inputProps={{ 'aria-label': 'From date' }} sx={{ width: 130, '& .MuiOutlinedInput-root': { height: 32 } }} />
          <TextField size="small" type="date" label="To" InputLabelProps={{ shrink: true }} value={toDate} onChange={e => setToDate(e.target.value)} inputProps={{ 'aria-label': 'To date' }} sx={{ width: 130, '& .MuiOutlinedInput-root': { height: 32 } }} />
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel id="sort-label">Sort</InputLabel>
            <Select labelId="sort-label" label="Sort" value={`${sortBy}_${sortDir}`} onChange={e => {
              const [by, dir] = (e.target.value as string).split('_');
              setSortBy(by as any);
              setSortDir(dir as any);
            }} sx={{ height: 32 }}>
              <MenuItem value="started_desc">Newest first</MenuItem>
              <MenuItem value="started_asc">Oldest first</MenuItem>
              <MenuItem value="findings_desc">Most findings</MenuItem>
              <MenuItem value="findings_asc">Fewest findings</MenuItem>
            </Select>
          </FormControl>
          {hasActiveFilters && (
            <Tooltip title="Clear all filters">
              <IconButton size="small" onClick={clearFilters} aria-label="Clear filters" sx={{ ml: 0.5 }}>
                <FilterListOffIcon sx={{ fontSize: 18 }} />
              </IconButton>
            </Tooltip>
          )}
        </Stack>
      </Paper>

      {/* Aggregate summary */}
      {!isLoading && filtered.length > 0 && (() => {
        const totals = { findings: 0, critical: 0, high: 0, medium: 0, low: 0, scansWithFindings: 0 };
        for (const it of filtered) {
          const s = it.summary || ({} as any);
          const f = s.findings ?? 0;
          totals.findings += f;
          totals.critical += s.critical ?? 0;
          totals.high += s.high ?? 0;
          totals.medium += s.medium ?? 0;
          totals.low += s.low ?? 0;
          if (f > 0) totals.scansWithFindings++;
        }
        if (totals.findings === 0) return null;
        return (
          <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5, px: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              {totals.findings} findings in {totals.scansWithFindings} of {filtered.length} scans
            </Typography>
            {totals.critical > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.critical, color: '#fff' }} label={`${totals.critical} critical`} />}
            {totals.high > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.high, color: '#fff' }} label={`${totals.high} high`} />}
            {totals.medium > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.medium, color: '#000' }} label={`${totals.medium} medium`} />}
            {totals.low > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.low, color: '#fff' }} label={`${totals.low} low`} />}
          </Stack>
        );
      })()}

      <ErrorDisplay error={error} onRetry={loadResults} />

      {isLoading && <LoadingSkeleton variant="table" />}

      {/* ── Table ────────────────────────────────────────── */}
      {!isLoading && filtered.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 1.5 }}>
          <Table size={(() => { try { const v = localStorage.getItem('aodsConfig_compactRows'); return v && JSON.parse(v) ? 'small' : 'medium'; } catch { return 'medium'; } })()} aria-label="Scan results">
            <TableHead>
              <TableRow sx={{ '& th': { fontWeight: 700, fontSize: 12, py: 1.25, color: 'text.secondary', textTransform: 'uppercase', letterSpacing: '0.04em' } }}>
                <TableCell sx={{ width: '32%' }}>Scan</TableCell>
                <TableCell sx={{ width: '14%' }}>Date</TableCell>
                <TableCell sx={{ width: '44%' }}>Findings</TableCell>
                <TableCell sx={{ width: '10%', textAlign: 'center' }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedItems.map((it) => {
                const key = String(it.path || '');
                const sum = key ? summaries[key] : null;
                const isOpen = key ? openKeys.includes(key) : false;
                const s = it.summary || ({} as any);
                const sc = sevCounts(s);
                const displayName = scanDisplayName(it.id, it.apkName);
                const rel = relativeTime(it.startedAt);
                const isEmpty = sc.sum === 0 && sc.reported === 0;

                return (
                  <Fragment key={it.id}>
                    <TableRow
                      hover
                      onClick={() => navigate(`/runs/${encodeURIComponent(it.id)}`)}
                      sx={{
                        cursor: 'pointer',
                        opacity: isEmpty ? 0.55 : 1,
                        '&:hover': { bgcolor: 'action.hover', opacity: 1 },
                        borderLeft: sc.critical > 0 ? '3px solid' : sc.high > 0 ? '3px solid' : 'none',
                        borderLeftColor: sc.critical > 0 ? 'error.main' : sc.high > 0 ? 'warning.main' : 'transparent',
                        transition: 'opacity 0.15s',
                      }}
                    >
                      {/* Scan name + ID */}
                      <TableCell sx={{ py: 1.25 }}>
                        <Stack direction="row" spacing={0.75} alignItems="baseline">
                          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13, lineHeight: 1.3 }}>
                            {displayName}
                          </Typography>
                          {it.profile && !isEmpty && (
                            <Typography variant="caption" sx={{ fontSize: 10, color: 'text.secondary', textTransform: 'capitalize' }}>
                              {it.profile}
                            </Typography>
                          )}
                        </Stack>
                        <Tooltip title={it.id} placement="bottom-start" enterDelay={500}>
                          <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 280 }}>
                            {it.id}
                          </Typography>
                        </Tooltip>
                      </TableCell>

                      {/* Date */}
                      <TableCell sx={{ py: 1.25 }}>
                        <Typography variant="body2" sx={{ fontSize: 12 }}>{rel}</Typography>
                        <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>{formatDateTime(it.startedAt)}</Typography>
                      </TableCell>

                      {/* Findings - bar + counts */}
                      <TableCell sx={{ py: 1.25 }} onClick={e => e.stopPropagation()}>
                        {isEmpty ? (
                          <Typography variant="caption" color="text.disabled">No findings</Typography>
                        ) : (
                          <Stack spacing={0.5}>
                            <SeverityBar critical={sc.critical} high={sc.high} medium={sc.medium} low={sc.low} info={sc.info} />
                            <Stack direction="row" spacing={0.5} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
                              <Typography variant="body2" sx={{ fontWeight: 700, fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                                {sc.reported || sc.sum} findings
                              </Typography>
                              {sc.critical > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.critical, color: '#fff' }} label={`${sc.critical}C`} />}
                              {sc.high > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.high, color: '#fff' }} label={`${sc.high}H`} />}
                              {sc.medium > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.medium, color: '#000' }} label={`${sc.medium}M`} />}
                              {sc.low > 0 && <Chip size="small" sx={{ height: 18, fontSize: 10, bgcolor: SEV_COLORS.low, color: '#fff' }} label={`${sc.low}L`} />}
                              {sc.sum === 0 && sc.reported > 0 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>(breakdown unavailable)</Typography>
                              )}
                            </Stack>
                          </Stack>
                        )}
                      </TableCell>

                      {/* Actions */}
                      <TableCell sx={{ py: 1.25, textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                        <Stack direction="row" spacing={0.25} justifyContent="center">
                          <Tooltip title="View details">
                            <IconButton size="small" component={RouterLink} to={`/runs/${encodeURIComponent(it.id)}`} aria-label="View details">
                              <OpenInNewIcon sx={{ fontSize: 16 }} />
                            </IconButton>
                          </Tooltip>
                          {Boolean(it.path) && (
                            <>
                              <Tooltip title="Download report">
                                <IconButton size="small" aria-label="Download report" onClick={async () => {
                                  try {
                                    const rr = await secureFetch(`/reports/download?path=${encodeURIComponent(it.path || '')}`);
                                    if (!rr.ok) return;
                                    const blob = await rr.blob();
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a'); a.href = url; a.download = `${it.id}.json`; a.click();
                                    setTimeout(() => URL.revokeObjectURL(url), 15000);
                                  } catch {}
                                }}>
                                  <DownloadIcon sx={{ fontSize: 16 }} />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title={isOpen ? 'Hide preview' : 'Show preview'}>
                                <IconButton size="small" onClick={() => toggleDetails(it)} aria-expanded={isOpen} aria-label="Toggle preview">
                                  <ExpandMoreIcon sx={{ fontSize: 16, transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 200ms' }} />
                                </IconButton>
                              </Tooltip>
                            </>
                          )}
                        </Stack>
                      </TableCell>
                    </TableRow>

                    {/* Expanded detail row */}
                    <TableRow key={`${it.id}-details`}>
                      <TableCell colSpan={4} sx={{ p: 0, borderBottom: isOpen ? undefined : 'none' }}>
                        <Collapse in={Boolean(isOpen && key)} timeout="auto" unmountOnExit>
                          {sum && sum.loading ? (
                            <Box sx={{ px: 3, py: 1.5, bgcolor: 'action.hover' }} role="status" aria-live="polite">
                              <Typography variant="caption" color="text.secondary">Loading summary...</Typography>
                            </Box>
                          ) : sum && !sum.error ? (
                            <Box sx={{ px: 3, py: 1.5, bgcolor: 'action.hover', borderTop: 1, borderColor: 'divider' }}>
                              <Stack direction="row" spacing={3} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>Total</Typography>
                                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{sum.total_findings}</Typography>
                                </Box>
                                {sum.critical > 0 && (
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>Critical</Typography>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: SEV_COLORS.critical }}>{sum.critical}</Typography>
                                  </Box>
                                )}
                                {sum.high > 0 && (
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>High</Typography>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: SEV_COLORS.high }}>{sum.high}</Typography>
                                  </Box>
                                )}
                                {sum.medium > 0 && (
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>Medium</Typography>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: SEV_COLORS.medium }}>{sum.medium}</Typography>
                                  </Box>
                                )}
                                {sum.low > 0 && (
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>Low</Typography>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: SEV_COLORS.low }}>{sum.low}</Typography>
                                  </Box>
                                )}
                                {sum.info > 0 && (
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: 10 }}>Info</Typography>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: 'text.secondary' }}>{sum.info}</Typography>
                                  </Box>
                                )}
                                <Box sx={{ flex: 1 }} />
                                <Button
                                  size="small"
                                  variant="outlined"
                                  component={RouterLink}
                                  to={`/runs/${encodeURIComponent(it.id)}`}
                                  sx={{ fontSize: 11, textTransform: 'none' }}
                                >
                                  View full report
                                </Button>
                              </Stack>
                            </Box>
                          ) : sum?.error ? (
                            <Box sx={{ px: 3, py: 1.5, bgcolor: 'action.hover' }}>
                              <Typography variant="caption" color="text.disabled">Failed to load summary</Typography>
                            </Box>
                          ) : null}
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" sx={{ mt: 2 }}>
          <Button size="small" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</Button>
          <Typography variant="caption" color="text.secondary">
            Page {page + 1} of {totalPages} ({filtered.length} results)
          </Typography>
          <Button size="small" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next</Button>
        </Stack>
      )}

      {filtered.length === 0 && !error && !isLoading && (
        items.length === 0 ? (
          <EmptyState
            icon={ScienceIcon}
            message="No scan results yet. Start a new scan to see results here."
            action={{ label: 'New Scan', onClick: () => navigate('/new-scan') }}
          />
        ) : (
          <EmptyState
            icon={SearchOffIcon}
            message="No results match the current filters."
            action={{ label: 'Clear Filters', onClick: clearFilters }}
          />
        )
      )}
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
