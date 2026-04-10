import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Divider,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import StorageIcon from '@mui/icons-material/Storage';
import BuildIcon from '@mui/icons-material/Build';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import TuneIcon from '@mui/icons-material/Tune';
import KeyboardReturnIcon from '@mui/icons-material/KeyboardReturn';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import HubIcon from '@mui/icons-material/Hub';
import RefreshIcon from '@mui/icons-material/Refresh';
import SortIcon from '@mui/icons-material/Sort';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import HistoryIcon from '@mui/icons-material/History';
import { AODSApiClient } from '../services/api';
import { secureFetch } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../hooks/useToast';
import type { FindingInput, FindSimilarResponse, SimilarFinding, VectorIndexStatus, RebuildIndexResponse } from '../types';
import { PageHeader, ErrorDisplay, StatusChip, AppToast, ConfirmDialog } from '../components';

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLORS: Record<string, string> = {
  critical: 'error.main', high: 'warning.main', medium: 'info.main', low: 'text.disabled', info: 'text.secondary',
};

function similarityColor(pct: number): 'success' | 'info' | 'warning' {
  if (pct >= 80) return 'success';
  if (pct >= 50) return 'info';
  return 'warning';
}

function similarityLabel(pct: number): string {
  if (pct >= 90) return 'Excellent';
  if (pct >= 75) return 'Strong';
  if (pct >= 50) return 'Fair';
  return 'Weak';
}

/** Truncate a string in the middle: "abc...xyz" */
function truncMid(s: string, max: number): string {
  if (s.length <= max) return s;
  const half = Math.floor((max - 3) / 2);
  return `${s.slice(0, half)}...${s.slice(-half)}`;
}

const EXAMPLE_QUERIES = [
  'SQL injection in user input',
  'Hardcoded API key or secret',
  'Insecure WebView configuration',
  'Certificate pinning bypass',
  'Unencrypted shared preferences',
];

type ResultSort = 'similarity' | 'severity';

const SEV_LEVELS = ['critical', 'high', 'medium', 'low'] as const;

const MAX_RESULTS_PRESETS = [5, 10, 25, 50] as const;

/** Skeleton row for results loading state. */
function ResultRowSkeleton() {
  return (
    <TableRow>
      <TableCell><Skeleton variant="text" width={40} /><Skeleton variant="rounded" width={60} height={4} sx={{ mt: 0.5 }} /></TableCell>
      <TableCell><Skeleton variant="text" width="80%" /><Skeleton variant="text" width="50%" height={14} /></TableCell>
      <TableCell><Skeleton variant="rounded" width={50} height={22} /></TableCell>
      <TableCell><Skeleton variant="rounded" width={60} height={22} /></TableCell>
      <TableCell><Skeleton variant="text" width="70%" /></TableCell>
      <TableCell><Skeleton variant="text" width={90} /></TableCell>
    </TableRow>
  );
}

/** Skeleton for the index status card. */
function IndexStatusSkeleton() {
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" spacing={3} alignItems="center">
        <Stack direction="row" spacing={1} alignItems="center">
          <Skeleton variant="rounded" width={32} height={32} />
          <Stack spacing={0.5}>
            <Skeleton variant="text" width={160} height={18} />
            <Skeleton variant="text" width={220} height={14} />
          </Stack>
        </Stack>
        <Skeleton variant="rectangular" width={1} height={36} />
        <Stack alignItems="center" spacing={0.25}>
          <Skeleton variant="text" width={40} height={24} />
          <Skeleton variant="text" width={50} height={14} />
        </Stack>
        <Stack alignItems="center" spacing={0.25}>
          <Skeleton variant="text" width={30} height={24} />
          <Skeleton variant="text" width={60} height={14} />
        </Stack>
      </Stack>
    </Paper>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function VectorSearch() {
  const api = useMemo(() => new AODSApiClient(), []);
  const navigate = useNavigate();
  const auth = useAuth();
  const isAdmin = auth.roles.includes('admin');
  const searchInputRef = useRef<HTMLTextAreaElement>(null);

  // Index status
  const [indexStatus, setIndexStatus] = useState<VectorIndexStatus | null>(null);
  const [indexError, setIndexError] = useState<string | null>(null);
  const [indexLoading, setIndexLoading] = useState(true);

  // Rebuild & Delete
  const [rebuilding, setRebuilding] = useState(false);
  const [deleteScanId, setDeleteScanId] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{ type: 'rebuild' | 'delete' | 'deleteIocs' } | null>(null);
  const { toast: snackbar, showToast, closeToast } = useToast();

  // Search form
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('any');
  const [cweId, setCweId] = useState('');
  const [vulnType, setVulnType] = useState('');
  const [maxResults, setMaxResults] = useState(10);
  const [showFilters, setShowFilters] = useState(true);

  // Results
  const [results, setResults] = useState<SimilarFinding[]>([]);
  const [queryTimeMs, setQueryTimeMs] = useState<number | null>(null);
  const [totalIndexed, setTotalIndexed] = useState<number | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [showAdmin, setShowAdmin] = useState(false);
  const [resultSort, setResultSort] = useState<ResultSort>('similarity');
  const [recentQueries, setRecentQueries] = useState<string[]>(() => {
    try { const raw = localStorage.getItem('aodsVectorSearch_recent'); return raw ? JSON.parse(raw) : []; } catch { return []; }
  });

  const hasFilters = severity !== 'any' || cweId.trim() !== '' || vulnType.trim() !== '';
  const activeFilterCount = [severity !== 'any', cweId.trim() !== '', vulnType.trim() !== ''].filter(Boolean).length;

  // Fetch index status on mount
  const fetchIndexStatus = useCallback(async () => {
    try {
      setIndexLoading(true);
      const status = await api.getVectorIndexStatus();
      setIndexStatus(status);
      setIndexError(null);
    } catch (e: any) {
      setIndexError(e?.message || 'Failed to fetch vector index status');
    } finally {
      setIndexLoading(false);
    }
  }, [api]);

  useEffect(() => { fetchIndexStatus(); }, [fetchIndexStatus]);

  // Auto-focus search input on mount
  useEffect(() => {
    const t = setTimeout(() => searchInputRef.current?.focus(), 300);
    return () => clearTimeout(t);
  }, []);

  async function handleRebuild() {
    setRebuilding(true);
    try {
      const result: RebuildIndexResponse = await api.rebuildVectorIndex();
      showToast(`Rebuild complete: ${result.indexed} indexed, ${result.errors} errors`, result.errors > 0 ? 'error' : 'success');
      // Refresh status
      try {
        const status = await api.getVectorIndexStatus();
        setIndexStatus(status);
      } catch {}
    } catch (e: any) {
      showToast(e?.message || 'Rebuild failed', 'error');
    } finally {
      setRebuilding(false);
    }
  }

  async function handleDeleteScan() {
    const trimmedId = deleteScanId.trim();
    if (!trimmedId) return;
    setDeleting(true);
    try {
      const r = await secureFetch(`/vector/index/scan/${encodeURIComponent(trimmedId)}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(String(r.status));
      const result = await r.json();
      showToast(`Deleted ${result.deleted ?? 0} findings for scan ${trimmedId}`, 'success');
      setDeleteScanId('');
      // Refresh index status
      try {
        const status = await api.getVectorIndexStatus();
        setIndexStatus(status);
      } catch {}
    } catch (e: any) {
      showToast(`Delete failed: ${e?.message || 'error'}`, 'error');
    } finally {
      setDeleting(false);
    }
  }

  async function handleDeleteScanIoCs() {
    const trimmedId = deleteScanId.trim();
    if (!trimmedId) return;
    setDeleting(true);
    try {
      const result = await api.deleteScanIoCs(trimmedId);
      showToast(`Deleted ${result.deleted ?? 0} IoCs for scan ${trimmedId}`, 'success');
    } catch (e: any) {
      showToast(`IoC delete failed: ${e?.message || 'error'}`, 'error');
    } finally {
      setDeleting(false);
    }
  }

  async function handleSearch() {
    const trimmed = description.trim();
    if (!trimmed) return;
    setSearching(true);
    setSearchError(null);
    setHasSearched(true);
    setExpandedRow(null);
    // Save to recent queries
    setRecentQueries(prev => {
      const next = [trimmed, ...prev.filter(q => q !== trimmed)].slice(0, 5);
      try { localStorage.setItem('aodsVectorSearch_recent', JSON.stringify(next)); } catch {}
      return next;
    });
    try {
      const finding: FindingInput = { description: trimmed };
      if (severity !== 'any') finding.severity = severity;
      if (cweId.trim()) finding.cwe_id = cweId.trim();
      if (vulnType.trim()) finding.vulnerability_type = vulnType.trim();
      const resp: FindSimilarResponse = await api.findSimilarFindings(finding, maxResults);
      setResults(resp.results);
      setQueryTimeMs(resp.query_time_ms);
      setTotalIndexed(resp.total_indexed);
    } catch (e: any) {
      const msg = e?.message || 'Search failed';
      if (msg.includes('503') || msg.toLowerCase().includes('disabled')) {
        setSearchError('Vector database is not available. Enable AODS_VECTOR_DB_ENABLED=1 on the server.');
      } else {
        setSearchError(msg);
      }
      setResults([]);
      setQueryTimeMs(null);
      setTotalIndexed(null);
    } finally {
      setSearching(false);
    }
  }

  function clearSearch() {
    setDescription('');
    setSeverity('any');
    setCweId('');
    setVulnType('');
    setResults([]);
    setQueryTimeMs(null);
    setTotalIndexed(null);
    setHasSearched(false);
    setSearchError(null);
    setExpandedRow(null);
    searchInputRef.current?.focus();
  }

  function exportResultsCsv() {
    if (!sortedResults.length) return;
    const header = 'similarity,title,severity,cwe_id,vulnerability_type,scan_id,finding_id';
    const rows = sortedResults.map(r =>
      [
        Math.round(r.similarity_score * 100),
        `"${(r.title || '').replace(/"/g, '""')}"`,
        r.severity || '',
        r.cwe_id || '',
        `"${(r.vulnerability_type || '').replace(/"/g, '""')}"`,
        r.scan_id,
        r.finding_id,
      ].join(',')
    );
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `vector_search_results.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast(`Exported ${sortedResults.length} results`, 'success');
  }

  const indexAvailable = indexStatus?.enabled && indexStatus?.available;

  const sortedResults = useMemo(() => {
    return [...results].sort((a, b) => {
      if (resultSort === 'severity') {
        const sa = SEV_ORDER[(a.severity || '').toLowerCase()] ?? 99;
        const sb = SEV_ORDER[(b.severity || '').toLowerCase()] ?? 99;
        if (sa !== sb) return sa - sb;
      }
      return b.similarity_score - a.similarity_score;
    });
  }, [results, resultSort]);

  const sevBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const r of sortedResults) {
      const s = (r.severity || 'unknown').toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return Object.entries(counts).sort(([a], [b]) => (SEV_ORDER[a] ?? 99) - (SEV_ORDER[b] ?? 99));
  }, [sortedResults]);

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title="Vector Search"
          subtitle="Find similar vulnerabilities using semantic embeddings"
          actions={
            <Stack direction="row" spacing={1} alignItems="center">
              {indexAvailable && !indexLoading && (
                <Chip
                  icon={<CheckCircleOutlineIcon sx={{ fontSize: '14px !important' }} />}
                  label={`${indexStatus!.collection_count.toLocaleString()} indexed`}
                  size="small"
                  color="success"
                  variant="outlined"
                  sx={{ fontVariantNumeric: 'tabular-nums' }}
                />
              )}
              <Tooltip title="Refresh index status">
                <IconButton size="small" onClick={fetchIndexStatus} disabled={indexLoading}>
                  <RefreshIcon sx={{
                    fontSize: 18,
                    transition: 'transform 0.3s',
                    ...(indexLoading && {
                      animation: 'spin 1s linear infinite',
                      '@keyframes spin': { '0%': { transform: 'rotate(0deg)' }, '100%': { transform: 'rotate(360deg)' } },
                    }),
                  }} />
                </IconButton>
              </Tooltip>
              {isAdmin && indexAvailable && (
                <Tooltip title="Admin tools">
                  <IconButton size="small" onClick={() => setShowAdmin(p => !p)}>
                    <BuildIcon sx={{ fontSize: 18 }} />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>
          }
        />

        {/* ---- Index Status ---- */}
        {indexLoading && <IndexStatusSkeleton />}
        {!indexLoading && indexError && (
          <Alert severity="error">{indexError}</Alert>
        )}
        {!indexLoading && indexStatus && !indexAvailable && (
          <Alert severity="error" icon={<ErrorOutlineIcon />}>
            Vector database is not available. Set <Box component="code" sx={{ fontSize: 'inherit', bgcolor: 'action.hover', px: 0.5, borderRadius: 0.5 }}>AODS_VECTOR_DB_ENABLED=1</Box> on the server to enable semantic search.
            {indexStatus.error && <> ({indexStatus.error})</>}
          </Alert>
        )}
        {!indexLoading && indexAvailable && (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" spacing={3} alignItems="center" flexWrap="wrap" useFlexGap>
              <Stack direction="row" spacing={1} alignItems="center">
                <Box sx={{ width: 32, height: 32, borderRadius: 1, bgcolor: 'success.main', display: 'flex', alignItems: 'center', justifyContent: 'center', opacity: 0.9 }}>
                  <HubIcon sx={{ fontSize: 18, color: 'common.white' }} />
                </Box>
                <Stack spacing={0}>
                  <Typography variant="body2" sx={{ fontWeight: 600, lineHeight: 1.2 }}>
                    Vector index operational
                  </Typography>
                  <Stack direction="row" spacing={0.75} alignItems="center">
                    <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.2 }}>
                      {indexStatus!.collection_count.toLocaleString()} findings indexed
                    </Typography>
                    <Chip
                      label={indexStatus!.model}
                      size="small"
                      variant="outlined"
                      sx={{ height: 16, fontSize: 9, fontFamily: 'monospace', '& .MuiChip-label': { px: 0.5 } }}
                    />
                  </Stack>
                </Stack>
              </Stack>
              <Divider orientation="vertical" flexItem />
              <Stack alignItems="center" spacing={0}>
                <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.1, fontVariantNumeric: 'tabular-nums' }}>
                  {indexStatus!.collection_count.toLocaleString()}
                </Typography>
                <Typography variant="caption" color="text.secondary">Indexed</Typography>
              </Stack>
              {indexStatus!.embedding_dimension && (
                <Stack alignItems="center" spacing={0}>
                  <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.1, fontVariantNumeric: 'tabular-nums' }}>
                    {indexStatus!.embedding_dimension}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">Dimensions</Typography>
                </Stack>
              )}
              {indexStatus!.cache_stats && (
                <Stack alignItems="center" spacing={0}>
                  <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.1, fontVariantNumeric: 'tabular-nums' }}>
                    {Math.round(((indexStatus!.cache_stats.hits || 0) / Math.max(1, (indexStatus!.cache_stats.hits || 0) + (indexStatus!.cache_stats.misses || 0))) * 100)}%
                  </Typography>
                  <Typography variant="caption" color="text.secondary">Cache hit</Typography>
                </Stack>
              )}
              <Box sx={{ flex: 1 }} />
              {isAdmin && (
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => setConfirmAction({ type: 'rebuild' })}
                  disabled={rebuilding}
                  startIcon={rebuilding ? <CircularProgress size={14} /> : <BuildIcon sx={{ fontSize: 14 }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  {rebuilding ? 'Rebuilding...' : 'Rebuild Index'}
                </Button>
              )}
            </Stack>
          </Paper>
        )}

        {/* ---- Admin Tools ---- */}
        {isAdmin && indexAvailable && (
          <Collapse in={showAdmin} unmountOnExit>
            <Paper variant="outlined" sx={{ p: 2, borderColor: 'warning.main', borderStyle: 'dashed' }}>
              <Stack spacing={0.5} sx={{ mb: 1.5 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, color: 'warning.main' }}>
                  Admin: Delete Scan from Index
                </Typography>
                <Typography variant="caption" color="text.disabled">
                  Remove all indexed findings for a specific scan. This cannot be undone.
                </Typography>
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <TextField
                  size="small"
                  label="Scan ID"
                  placeholder="Enter scan ID to remove"
                  value={deleteScanId}
                  onChange={(e) => setDeleteScanId(e.target.value)}
                  inputProps={{ 'aria-label': 'Scan ID to delete' }}
                  onKeyDown={(e) => { if (e.key === 'Enter' && deleteScanId.trim()) setConfirmAction({ type: 'delete' }); }}
                  sx={{ minWidth: 260 }}
                  InputProps={{
                    endAdornment: deleteScanId ? (
                      <InputAdornment position="end">
                        <IconButton size="small" onClick={() => setDeleteScanId('')} edge="end">
                          <ClearIcon sx={{ fontSize: 14 }} />
                        </IconButton>
                      </InputAdornment>
                    ) : undefined,
                  }}
                />
                <Button
                  size="small"
                  variant="outlined"
                  color="error"
                  onClick={() => setConfirmAction({ type: 'delete' })}
                  disabled={deleting || !deleteScanId.trim()}
                  startIcon={deleting ? <CircularProgress size={14} /> : <DeleteOutlineIcon sx={{ fontSize: 16 }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  {deleting ? 'Deleting...' : 'Delete Scan'}
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  color="warning"
                  onClick={() => setConfirmAction({ type: 'deleteIocs' })}
                  disabled={deleting || !deleteScanId.trim()}
                  startIcon={deleting ? <CircularProgress size={14} /> : <DeleteOutlineIcon sx={{ fontSize: 16 }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                  data-testid="delete-iocs-button"
                >
                  Delete IoCs
                </Button>
              </Stack>
            </Paper>
          </Collapse>
        )}

        {/* ---- Search Form ---- */}
        <Paper variant="outlined" sx={{ p: 2.5, position: 'relative', overflow: 'hidden', opacity: indexAvailable ? 1 : 0.5, pointerEvents: indexAvailable ? 'auto' : 'none' }}>
          {searching && <LinearProgress sx={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2 }} />}
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
            <SearchIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>
              Search Query
            </Typography>
            {hasFilters && (
              <Chip
                label={`${activeFilterCount} filter${activeFilterCount > 1 ? 's' : ''}`}
                size="small"
                color="primary"
                variant="outlined"
                sx={{ height: 20, fontSize: 10, fontWeight: 600 }}
              />
            )}
          </Stack>

          <TextField
            label="Description / Title"
            placeholder="Describe the vulnerability to search for..."
            multiline
            minRows={2}
            maxRows={6}
            fullWidth
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey && description.trim()) {
                e.preventDefault();
                handleSearch();
              }
              if (e.key === 'Escape') {
                setDescription('');
                (e.target as HTMLElement).blur();
              }
            }}
            inputRef={searchInputRef}
            sx={{ mb: 1.5 }}
            helperText={description.length > 0 ? `${description.trim().split(/\s+/).length} words` : 'Enter to search, Shift+Enter for newline'}
            FormHelperTextProps={{ sx: { opacity: 0.5, fontSize: 10 } }}
            inputProps={{ 'aria-label': 'Search description' }}
            InputProps={{
              endAdornment: description ? (
                <InputAdornment position="end" sx={{ alignSelf: 'flex-start', mt: 1 }}>
                  <IconButton size="small" onClick={() => { setDescription(''); searchInputRef.current?.focus(); }} edge="end" aria-label="Clear description">
                    <ClearIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </InputAdornment>
              ) : undefined,
            }}
          />

          {/* Filter toggle */}
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: showFilters ? 1.5 : 0 }}>
            <Button
              size="small"
              variant="text"
              startIcon={<TuneIcon sx={{ fontSize: 14 }} />}
              onClick={() => setShowFilters(p => !p)}
              sx={{ textTransform: 'none', fontSize: 12, color: 'text.secondary' }}
            >
              {showFilters ? 'Hide filters' : 'Filters'}
              {hasFilters && !showFilters && ` (${activeFilterCount})`}
            </Button>
            <Box sx={{ flex: 1 }} />
            {hasSearched && (
              <Button size="small" variant="text" onClick={clearSearch} sx={{ textTransform: 'none', fontSize: 12, color: 'text.secondary' }}>
                Clear all
              </Button>
            )}
            <Tooltip title={<>Search <KeyboardReturnIcon sx={{ fontSize: 12, ml: 0.5, verticalAlign: 'middle' }} /></>}>
              <span>
                <Button
                  variant="contained"
                  size="small"
                  onClick={handleSearch}
                  disabled={searching || !description.trim()}
                  startIcon={searching ? <CircularProgress size={16} color="inherit" /> : <SearchIcon sx={{ fontSize: 16 }} />}
                  sx={{ minWidth: 100, height: 36 }}
                >
                  {searching ? 'Searching...' : 'Search'}
                </Button>
              </span>
            </Tooltip>
          </Stack>

          {/* Collapsible filters */}
          <Collapse in={showFilters} unmountOnExit>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ xs: 'stretch', sm: 'center' }} flexWrap="wrap" useFlexGap>
              <FormControl size="small" sx={{ minWidth: 140 }}>
                <InputLabel id="vs-sev-label">Severity</InputLabel>
                <Select
                  labelId="vs-sev-label"
                  label="Severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  renderValue={(v) => {
                    if (v === 'any') return 'Any';
                    const dot = SEV_COLORS[v];
                    return (
                      <Stack direction="row" spacing={0.75} alignItems="center">
                        {dot && <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: dot, flexShrink: 0 }} />}
                        <span style={{ textTransform: 'capitalize' }}>{v}</span>
                      </Stack>
                    );
                  }}
                >
                  <MenuItem value="any">Any</MenuItem>
                  {SEV_LEVELS.map(s => (
                    <MenuItem key={s} value={s}>
                      <Stack direction="row" spacing={0.75} alignItems="center">
                        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: SEV_COLORS[s] }} />
                        <span style={{ textTransform: 'capitalize' }}>{s}</span>
                      </Stack>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField
                size="small"
                label="CWE ID"
                placeholder="e.g. CWE-89"
                value={cweId}
                onChange={(e) => setCweId(e.target.value)}
                inputProps={{ 'aria-label': 'CWE ID filter' }}
                sx={{ minWidth: 120 }}
                InputProps={{
                  endAdornment: cweId ? (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setCweId('')} edge="end"><ClearIcon sx={{ fontSize: 14 }} /></IconButton>
                    </InputAdornment>
                  ) : undefined,
                }}
              />
              <TextField
                size="small"
                label="Vulnerability Type"
                placeholder="e.g. SQL Injection"
                value={vulnType}
                onChange={(e) => setVulnType(e.target.value)}
                inputProps={{ 'aria-label': 'Vulnerability type filter' }}
                sx={{ minWidth: 180 }}
                InputProps={{
                  endAdornment: vulnType ? (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setVulnType('')} edge="end"><ClearIcon sx={{ fontSize: 14 }} /></IconButton>
                    </InputAdornment>
                  ) : undefined,
                }}
              />
              <FormControl size="small" sx={{ minWidth: 90 }}>
                <InputLabel id="max-results-label" sx={{ fontSize: 13 }}>Maximum results</InputLabel>
                <Select
                  labelId="max-results-label"
                  label="Maximum results"
                  value={maxResults}
                  onChange={e => setMaxResults(Number(e.target.value))}
                  sx={{ fontSize: 13, '& .MuiSelect-select': { py: 0.75 } }}
                >
                  {MAX_RESULTS_PRESETS.map(n => (
                    <MenuItem key={n} value={n}>{n}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              {hasFilters && (
                <Button
                  size="small"
                  variant="text"
                  onClick={() => { setSeverity('any'); setCweId(''); setVulnType(''); }}
                  sx={{ textTransform: 'none', fontSize: 12, color: 'text.secondary' }}
                >
                  Clear filters
                </Button>
              )}
            </Stack>
          </Collapse>

          {/* Query stats */}
          {queryTimeMs !== null && (
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 1.5, pt: 1, borderTop: 1, borderColor: 'divider' }}>
              <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {results.length} result{results.length !== 1 ? 's' : ''} in {queryTimeMs.toFixed(1)} ms
              </Typography>
              {totalIndexed !== null && (
                <>
                  <Typography variant="caption" color="text.disabled">&middot;</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                    {totalIndexed.toLocaleString()} total indexed findings
                  </Typography>
                </>
              )}
              <Box sx={{ flex: 1 }} />
              <Tooltip title="Re-run search">
                <IconButton size="small" onClick={handleSearch} disabled={searching || !description.trim()}>
                  <RefreshIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
            </Stack>
          )}
        </Paper>

        {/* ---- Search Error ---- */}
        <ErrorDisplay error={searchError} />

        {/* ---- Results ---- */}
        {searching && (
          <Paper variant="outlined" sx={{ borderRadius: 2 }}>
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small" sx={{ tableLayout: 'fixed' }} aria-label="Similar findings">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ width: '10%' }}>Similarity</TableCell>
                    <TableCell sx={{ width: '30%' }}>Title</TableCell>
                    <TableCell sx={{ width: '12%' }}>Severity</TableCell>
                    <TableCell sx={{ width: '12%' }}>CWE</TableCell>
                    <TableCell sx={{ width: '20%' }}>Vuln Type</TableCell>
                    <TableCell sx={{ width: '16%' }}>Scan ID</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {Array.from({ length: 3 }).map((_, i) => <ResultRowSkeleton key={i} />)}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        )}

        {!searching && hasSearched && results.length === 0 && !searchError && (
          <Paper variant="outlined" sx={{ py: 5, textAlign: 'center' }}>
            <SearchIcon sx={{ fontSize: 40, color: 'text.disabled', mb: 1 }} />
            <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
              No similar findings found
            </Typography>
            <Typography variant="caption" color="text.disabled">
              {hasFilters
                ? 'Try removing some filters or broadening your search description'
                : 'Try broadening your search description or adjusting filters'}
            </Typography>
            {hasFilters && (
              <Box sx={{ mt: 1.5 }}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => { setSeverity('any'); setCweId(''); setVulnType(''); }}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  Clear filters & retry
                </Button>
              </Box>
            )}
          </Paper>
        )}

        {!searching && sortedResults.length > 0 && (
          <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
            {/* Results header */}
            <Stack direction="row" alignItems="center" sx={{ px: 2, py: 1.5 }} spacing={1} flexWrap="wrap" useFlexGap>
              <StorageIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>
                Results
              </Typography>
              <Chip
                label={sortedResults.length}
                size="small"
                variant="outlined"
                sx={{ height: 20, fontSize: 11, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}
              />
              {description.trim() && (
                <Typography variant="caption" color="text.disabled" noWrap sx={{ maxWidth: 220 }} title={description.trim()}>
                  for &ldquo;{description.trim().length > 30 ? description.trim().slice(0, 28) + '...' : description.trim()}&rdquo;
                </Typography>
              )}
              <Box sx={{ flex: 1 }} />
              {/* Sort toggle */}
              <Tooltip title={resultSort === 'similarity' ? 'Sort by severity' : 'Sort by similarity'}>
                <Button
                  size="small"
                  variant="text"
                  startIcon={<SortIcon sx={{ fontSize: 14 }} />}
                  onClick={() => setResultSort(p => p === 'similarity' ? 'severity' : 'similarity')}
                  sx={{ textTransform: 'none', fontSize: 11, color: 'text.secondary', minWidth: 0, px: 1 }}
                >
                  {resultSort === 'similarity' ? 'By match' : 'By severity'}
                </Button>
              </Tooltip>
              {/* Export */}
              <Tooltip title="Export results as CSV">
                <IconButton size="small" onClick={exportResultsCsv}>
                  <FileDownloadIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
              {/* Severity breakdown chips */}
              {sevBreakdown.map(([sev, n]) => (
                <Tooltip key={sev} title={`${n} ${sev}`}>
                  <Chip
                    icon={<Box component="span" sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: SEV_COLORS[sev] || 'text.secondary', ml: '4px !important', mr: '-2px !important' }} />}
                    label={`${n}${sev.charAt(0).toUpperCase()}`}
                    size="small"
                    variant="outlined"
                    sx={{ height: 20, fontSize: 10, fontVariantNumeric: 'tabular-nums' }}
                  />
                </Tooltip>
              ))}
            </Stack>

            {/* Active filter chips */}
            {hasFilters && (
              <>
                <Divider />
                <Stack direction="row" spacing={0.5} alignItems="center" sx={{ px: 2, py: 0.75 }} flexWrap="wrap" useFlexGap>
                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, mr: 0.5 }}>Filtered by:</Typography>
                  {severity !== 'any' && (
                    <Chip
                      icon={<Box component="span" sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: SEV_COLORS[severity] || 'text.secondary', ml: '4px !important', mr: '-2px !important' }} />}
                      label={severity}
                      size="small"
                      onDelete={() => setSeverity('any')}
                      sx={{ height: 20, fontSize: 10, textTransform: 'capitalize' }}
                    />
                  )}
                  {cweId.trim() && (
                    <Chip
                      label={cweId.trim()}
                      size="small"
                      onDelete={() => setCweId('')}
                      sx={{ height: 20, fontSize: 10, fontFamily: 'monospace' }}
                    />
                  )}
                  {vulnType.trim() && (
                    <Chip
                      label={vulnType.trim()}
                      size="small"
                      onDelete={() => setVulnType('')}
                      sx={{ height: 20, fontSize: 10 }}
                    />
                  )}
                </Stack>
              </>
            )}
            <Divider />
            <TableContainer sx={{ maxHeight: 600 }}>
              <Table size="small" sx={{ tableLayout: 'fixed' }} aria-label="Similar findings" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ width: '10%', bgcolor: 'background.paper' }}>Similarity</TableCell>
                    <TableCell sx={{ width: '30%', bgcolor: 'background.paper' }}>Title</TableCell>
                    <TableCell sx={{ width: '12%', bgcolor: 'background.paper' }}>Severity</TableCell>
                    <TableCell sx={{ width: '12%', bgcolor: 'background.paper' }}>CWE</TableCell>
                    <TableCell sx={{ width: '20%', bgcolor: 'background.paper' }}>Vuln Type</TableCell>
                    <TableCell sx={{ width: '16%', bgcolor: 'background.paper' }}>Scan ID</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedResults.map((r, idx) => {
                    const pct = Math.round(r.similarity_score * 100);
                    const sev = (r.severity || '').toLowerCase();
                    const rowKey = r.finding_id || String(idx);
                    const isExpanded = expandedRow === rowKey;
                    return (
                      <TableRow
                        key={rowKey}
                        hover
                        tabIndex={0}
                        onClick={() => setExpandedRow(isExpanded ? null : rowKey)}
                        onDoubleClick={() => { if (r.scan_id) navigate(`/runs/${encodeURIComponent(r.scan_id)}`); }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpandedRow(isExpanded ? null : rowKey); }
                        }}
                        sx={{
                          bgcolor: idx % 2 === 0 ? 'background.paper' : 'action.hover',
                          cursor: 'pointer',
                          '&:hover, &:focus-visible': { bgcolor: 'action.selected' },
                          '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 },
                          borderLeft: 3,
                          borderColor: SEV_COLORS[sev] || 'divider',
                          transition: 'background-color 0.15s',
                        }}
                      >
                        <TableCell sx={{ py: 1.5 }}>
                          <Tooltip title={`${(r.similarity_score * 100).toFixed(1)}% - ${similarityLabel(pct)}`} placement="right">
                            <Stack spacing={0} alignItems="center" sx={{ width: 'fit-content' }}>
                              <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                                <CircularProgress
                                  variant="determinate"
                                  value={100}
                                  size={36}
                                  thickness={3}
                                  sx={{ color: 'action.hover', position: 'absolute' }}
                                />
                                <CircularProgress
                                  variant="determinate"
                                  value={pct}
                                  size={36}
                                  thickness={3}
                                  color={similarityColor(pct)}
                                />
                                <Box sx={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                  <Typography variant="caption" sx={{ fontWeight: 700, fontSize: 10, fontVariantNumeric: 'tabular-nums', lineHeight: 1 }}>
                                    {pct}%
                                  </Typography>
                                </Box>
                              </Box>
                            </Stack>
                          </Tooltip>
                        </TableCell>
                        <TableCell sx={{ py: 1.5 }}>
                          <Stack spacing={0.25}>
                            <Typography variant="body2" sx={{ fontSize: 13, fontWeight: 500, wordBreak: 'break-word', lineHeight: 1.3 }}>
                              {r.title || <Typography component="span" variant="caption" color="text.disabled">Untitled</Typography>}
                            </Typography>
                            <Collapse in={isExpanded} unmountOnExit timeout={150}>
                              <Stack spacing={0.5} sx={{ mt: 0.5, pt: 0.5, borderTop: 1, borderColor: 'divider' }}>
                                {r.finding_id && (
                                  <Stack direction="row" spacing={0.5} alignItems="center">
                                    <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>ID:</Typography>
                                    <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, fontFamily: 'monospace' }}>
                                      {r.finding_id}
                                    </Typography>
                                    <IconButton
                                      size="small"
                                      onClick={(e) => { e.stopPropagation(); try { navigator.clipboard.writeText(r.finding_id); showToast('Finding ID copied'); } catch {} }}
                                      sx={{ p: 0, ml: 0.25 }}
                                    >
                                      <ContentCopyIcon sx={{ fontSize: 10 }} />
                                    </IconButton>
                                  </Stack>
                                )}
                                <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap divider={<Typography variant="caption" color="text.disabled" sx={{ fontSize: 8 }}>&middot;</Typography>}>
                                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, fontVariantNumeric: 'tabular-nums' }}>
                                    Match: {(r.similarity_score * 100).toFixed(1)}%
                                  </Typography>
                                  {sev && <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, textTransform: 'capitalize' }}>Severity: {sev}</Typography>}
                                  {r.cwe_id && <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, fontFamily: 'monospace' }}>{r.cwe_id}</Typography>}
                                  {r.vulnerability_type && <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>Type: {r.vulnerability_type}</Typography>}
                                </Stack>
                              </Stack>
                            </Collapse>
                          </Stack>
                        </TableCell>
                        <TableCell sx={{ py: 1.5 }}>
                          {sev ? (
                            <StatusChip status={sev} size="small" />
                          ) : (
                            <Typography variant="caption" color="text.disabled">&mdash;</Typography>
                          )}
                        </TableCell>
                        <TableCell sx={{ py: 1.5 }}>
                          {r.cwe_id ? (
                            <Chip
                              label={r.cwe_id}
                              size="small"
                              variant="outlined"
                              sx={{ height: 22, fontSize: 11, fontWeight: 500, fontFamily: 'monospace' }}
                            />
                          ) : (
                            <Typography variant="caption" color="text.disabled">&mdash;</Typography>
                          )}
                        </TableCell>
                        <TableCell sx={{ py: 1.5 }}>
                          <Typography variant="body2" sx={{ fontSize: 13, wordBreak: 'break-word' }}>
                            {r.vulnerability_type || <Typography component="span" variant="caption" color="text.disabled">&mdash;</Typography>}
                          </Typography>
                        </TableCell>
                        <TableCell sx={{ py: 1.5 }}>
                          <Stack direction="row" spacing={0.25} alignItems="center" className="scan-id-cell" sx={{ '& .scan-actions': { opacity: 0, transition: 'opacity 0.15s' }, '&:hover .scan-actions': { opacity: 1 } }}>
                            <Tooltip title={r.scan_id} placement="top-start" enterDelay={400}>
                              <Link
                                to={`/runs/${encodeURIComponent(r.scan_id)}`}
                                style={{ fontSize: 12, color: 'inherit', fontFamily: 'monospace', textDecoration: 'none' }}
                                onClick={(e) => e.stopPropagation()}
                              >
                                {truncMid(r.scan_id, 16)}
                              </Link>
                            </Tooltip>
                            <Stack direction="row" spacing={0} className="scan-actions" alignItems="center">
                              <Tooltip title="Copy ID">
                                <IconButton
                                  size="small"
                                  onClick={(e) => { e.stopPropagation(); try { navigator.clipboard.writeText(r.scan_id); showToast('Scan ID copied'); } catch {} }}
                                  sx={{ p: 0.25 }}
                                >
                                  <ContentCopyIcon sx={{ fontSize: 12 }} />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Open scan">
                                <IconButton
                                  size="small"
                                  component={Link}
                                  to={`/runs/${encodeURIComponent(r.scan_id)}`}
                                  onClick={(e: React.MouseEvent) => e.stopPropagation()}
                                  sx={{ p: 0.25 }}
                                >
                                  <OpenInNewIcon sx={{ fontSize: 12 }} />
                                </IconButton>
                              </Tooltip>
                            </Stack>
                          </Stack>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Results footer */}
            <Divider />
            <Stack direction="row" alignItems="center" sx={{ px: 2, py: 1 }} spacing={1}>
              <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {sortedResults.length} result{sortedResults.length !== 1 ? 's' : ''}
              </Typography>
              <Box sx={{ flex: 1 }} />
              <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>
                Click a row to expand details &middot; Double-click to view scan
              </Typography>
            </Stack>
          </Paper>
        )}

        {/* Pre-search guidance */}
        {!hasSearched && !searching && (
          <Paper variant="outlined" sx={{ py: 4, textAlign: 'center' }}>
            <HubIcon sx={{ fontSize: 40, color: 'text.disabled', mb: 1 }} />
            <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
              Search for similar vulnerabilities
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ display: 'block', mb: 2 }}>
              Describe a vulnerability above to find semantically similar findings across all scans
            </Typography>
            {recentQueries.length > 0 && (
              <Stack spacing={1} alignItems="center" sx={{ mb: 2 }}>
                <Stack direction="row" spacing={0.5} alignItems="center">
                  <HistoryIcon sx={{ fontSize: 12, color: 'text.disabled' }} />
                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                    Recent searches
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" justifyContent="center" useFlexGap>
                  {recentQueries.map((q, i) => (
                    <Chip
                      key={i}
                      label={q.length > 40 ? q.slice(0, 37) + '...' : q}
                      size="small"
                      variant="outlined"
                      onClick={() => { setDescription(q); searchInputRef.current?.focus(); }}
                      onDelete={() => {
                        setRecentQueries(prev => {
                          const next = prev.filter((_, j) => j !== i);
                          try { localStorage.setItem('aodsVectorSearch_recent', JSON.stringify(next)); } catch {}
                          return next;
                        });
                      }}
                      sx={{ fontSize: 11, cursor: 'pointer' }}
                    />
                  ))}
                </Stack>
              </Stack>
            )}
            <Stack spacing={1} alignItems="center">
              <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                Try an example
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" justifyContent="center" useFlexGap>
                {EXAMPLE_QUERIES.map((q, i) => (
                  <Chip
                    key={i}
                    label={q}
                    size="small"
                    color="primary"
                    variant="outlined"
                    onClick={() => { setDescription(q); searchInputRef.current?.focus(); }}
                    sx={{ fontSize: 11, cursor: 'pointer' }}
                  />
                ))}
              </Stack>
            </Stack>
          </Paper>
        )}
      </Stack>

      <ConfirmDialog
        open={confirmAction !== null}
        title={
          confirmAction?.type === 'rebuild'
            ? 'Rebuild Vector Index?'
            : confirmAction?.type === 'delete'
              ? 'Delete Scan from Index?'
              : 'Delete IoCs from Index?'
        }
        message={
          confirmAction?.type === 'rebuild'
            ? 'This will re-index all findings. Existing search results will be temporarily unavailable.'
            : confirmAction?.type === 'delete'
              ? `Remove all indexed findings for scan "${deleteScanId}"? This cannot be undone.`
              : `Remove all IoCs for scan "${deleteScanId}"? This cannot be undone.`
        }
        severity={confirmAction?.type === 'rebuild' ? 'warning' : 'error'}
        confirmLabel={confirmAction?.type === 'rebuild' ? 'Rebuild' : 'Delete'}
        onCancel={() => setConfirmAction(null)}
        onConfirm={() => {
          const action = confirmAction;
          setConfirmAction(null);
          if (action?.type === 'rebuild') handleRebuild();
          else if (action?.type === 'delete') handleDeleteScan();
          else if (action?.type === 'deleteIocs') handleDeleteScanIoCs();
        }}
      />
      <AppToast toast={snackbar} onClose={closeToast} />
    </Box>
  );
}
