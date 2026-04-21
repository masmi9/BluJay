import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Pagination,
  Paper,
  Select,
  Skeleton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import DescriptionIcon from '@mui/icons-material/Description';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CodeIcon from '@mui/icons-material/Code';
import HtmlIcon from '@mui/icons-material/Html';
import TableChartIcon from '@mui/icons-material/TableChart';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import SelectAllIcon from '@mui/icons-material/SelectAll';
import SortIcon from '@mui/icons-material/Sort';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import SortByAlphaIcon from '@mui/icons-material/SortByAlpha';
import StorageIcon from '@mui/icons-material/Storage';
import { secureFetch } from '../lib/api';
import { formatDateTime, formatRelativeTime, formatTime, formatSize, sevSummary } from '../lib/format';
import { computeReportStats } from '../lib/reports';
import { PageHeader, ErrorDisplay, AppToast } from '../components';
import { useToast } from '../hooks/useToast';
import type { ScanResult } from '../types';

/* ------------------------------------------------------------------ */
/*  Types & helpers                                                    */
/* ------------------------------------------------------------------ */

type ReportItem = { name: string; path: string; size: number; modified: number };
type GenerateFormat = 'html' | 'csv' | 'json' | 'pdf';

const FORMAT_META: Record<GenerateFormat, { label: string; icon: typeof HtmlIcon }> = {
  html: { label: 'HTML', icon: HtmlIcon },
  csv: { label: 'CSV', icon: TableChartIcon },
  json: { label: 'JSON', icon: CodeIcon },
  pdf: { label: 'PDF', icon: PictureAsPdfIcon },
};



/** Turn epoch-ms into a relative time string via shared formatter. */
function relativeTime(epochMs: number): string {
  return formatRelativeTime(new Date(epochMs).toISOString());
}

type FileType = 'all' | 'json' | 'html' | 'csv' | 'pdf' | 'other';

function getFileExt(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot >= 0 ? name.slice(dot + 1).toLowerCase() : '';
}

const FILE_TYPE_LABELS: Record<FileType, string> = {
  all: 'All',
  json: 'JSON',
  html: 'HTML',
  csv: 'CSV',
  pdf: 'PDF',
  other: 'Other',
};

/** Dot color for type-filter chips - matches EXT_ACCENT. */
const TYPE_DOT_COLOR: Record<string, string> = {
  json: '#5c6bc0', html: '#ef6c00', csv: '#2e7d32', pdf: '#c62828',
};

/** Whether an epoch-ms timestamp is < 1 hour old. */
function isRecent(epochMs: number): boolean {
  return Date.now() - epochMs < 3_600_000;
}

const ALL_FORMATS: GenerateFormat[] = ['html', 'csv', 'json', 'pdf'];

const SORT_ICON: Record<string, typeof SortIcon> = {
  'modified-desc': AccessTimeIcon, 'modified-asc': AccessTimeIcon,
  'name-asc': SortByAlphaIcon, 'name-desc': SortByAlphaIcon,
  'size-desc': StorageIcon, 'size-asc': StorageIcon,
};

/** Extract a human-readable display name from a raw report filename.
 *  e.g. "com.moonton.mobilehero_security_report_20260310_190915_0f216525.html"
 *  →  { displayName: "com.moonton.mobilehero", timestamp: "Mar 10, 7:09 PM" }
 */
function parseReportName(raw: string): { displayName: string; timestamp: string } {
  // Pattern: <package>_security_report_<YYYYMMDD>_<HHMMSS>_<hash>.<ext>
  const m = raw.match(/^(.+?)_security_report_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_[0-9a-f]+\.\w+$/);
  if (m) {
    const pkg = m[1];
    try {
      const d = new Date(`${m[2]}-${m[3]}-${m[4]}T${m[5]}:${m[6]}:${m[7]}`);
      if (!isNaN(d.getTime())) {
        return {
          displayName: pkg,
          timestamp: formatDateTime(d.toISOString()),
        };
      }
    } catch { /* fall through */ }
    return { displayName: pkg, timestamp: '' };
  }
  // Fallback: keep full filename (tests rely on seeing the raw name)
  return { displayName: raw, timestamp: '' };
}

/** Color accent per file type for left border indicator. */
const EXT_ACCENT: Record<string, string> = {
  json: '#5c6bc0',   // indigo
  html: '#ef6c00',   // orange
  csv: '#2e7d32',    // green
  pdf: '#c62828',    // red
};

/** Compact stacked severity bar (proportional widths). */
function SeverityBar({ critical = 0, high = 0, medium = 0, low = 0, total = 0 }: { critical?: number; high?: number; medium?: number; low?: number; total?: number }) {
  if (!total) return null;
  const segments = [
    { n: critical, color: 'error.main' },
    { n: high, color: 'warning.main' },
    { n: medium, color: 'info.main' },
    { n: low, color: 'text.disabled' },
  ].filter(s => s.n > 0);
  return (
    <Box sx={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', width: '100%', maxWidth: 180, bgcolor: 'action.hover' }}>
      {segments.map((s, i) => (
        <Box key={i} sx={{ width: `${(s.n / total) * 100}%`, bgcolor: s.color, minWidth: 3, transition: 'width 0.3s' }} />
      ))}
    </Box>
  );
}

/** Skeleton placeholder that mimics a report row. */
function ReportRowSkeleton() {
  return (
    <Box sx={{ px: 2, py: 1.25, borderLeft: 3, borderColor: 'divider' }}>
      <Stack direction="row" alignItems="center" spacing={1.5}>
        <Skeleton variant="circular" width={20} height={20} />
        <Box sx={{ flex: 1 }}>
          <Skeleton variant="text" width="60%" height={20} />
          <Skeleton variant="text" width="35%" height={16} />
        </Box>
        <Skeleton variant="rounded" width={60} height={24} />
      </Stack>
    </Box>
  );
}

/** Icon for a file extension with subtle background. */
function FileTypeIcon({ ext }: { ext: string }) {
  const color = EXT_ACCENT[ext] || undefined;
  const iconSx = { fontSize: 16, color: color ?? 'text.disabled' } as const;
  let icon: React.ReactElement;
  switch (ext) {
    case 'html': icon = <HtmlIcon sx={iconSx} />; break;
    case 'csv': icon = <TableChartIcon sx={iconSx} />; break;
    case 'pdf': icon = <PictureAsPdfIcon sx={iconSx} />; break;
    case 'json': icon = <CodeIcon sx={iconSx} />; break;
    default: icon = <DescriptionIcon sx={iconSx} />; break;
  }
  return (
    <Box sx={{
      width: 28, height: 28, borderRadius: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
      bgcolor: color ? `${color}14` : 'action.hover', flexShrink: 0,
    }}>
      {icon}
    </Box>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function Reports() {
  const [items, setItems] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [summaries, setSummaries] = useState<Record<string, any>>({});
  const [aggregate, setAggregate] = useState<any | null>(null);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(() => { try { return Number(localStorage.getItem('aodsReports_pageSize') || 25); } catch { return 25; } });
  const [sortOption, setSortOption] = useState<string>(() => { try { return localStorage.getItem('aodsReports_sort') || 'modified-desc'; } catch { return 'modified-desc'; } });
  const { toast, showToast, closeToast } = useToast();
  const [typeFilter, setTypeFilter] = useState<FileType>('all');
  const [exportAnchor, setExportAnchor] = useState<null | HTMLElement>(null);
  const browserRef = useRef<HTMLDivElement>(null);

  // Generate Report state
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [genResultId, setGenResultId] = useState('');
  const [genFormats, setGenFormats] = useState<GenerateFormat[]>(['html']);
  const [genBusy, setGenBusy] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genSuccess, setGenSuccess] = useState(false);
  const [genCurrentFmt, setGenCurrentFmt] = useState<GenerateFormat | ''>('');
  const [lastRefreshed, setLastRefreshed] = useState<number>(0);

  /* ---- Data fetching ---- */

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await secureFetch('/reports/list');
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      const list = Array.isArray(j.items) ? j.items : [];
      setItems(list);
      // Aggregate: only read JSON reports (HTML/CSV can't be parsed for stats)
      const jsonReports = list.filter((it: ReportItem) => getFileExt(it.name) === 'json').slice(0, 5);
      const agg = { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0 };
      const results = await Promise.allSettled(jsonReports.map(async (it: ReportItem) => {
        const rr = await secureFetch(`/reports/read?path=${encodeURIComponent(it.path)}`);
        if (!rr.ok) return null;
        const jj = await rr.json();
        let data: any = null;
        try { data = (jj && typeof jj.content === 'string') ? JSON.parse(jj.content) : jj; } catch { data = null; }
        return computeReportStats(data);
      }));
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          agg.total_findings += r.value.total_findings;
          agg.critical += r.value.critical;
          agg.high += r.value.high;
          agg.medium += r.value.medium;
          agg.low += r.value.low;
        }
      }
      setAggregate(jsonReports.length > 0 ? agg : null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load reports');
    } finally {
      setLoading(false);
      setLastRefreshed(Date.now());
    }
  }, []);

  const fetchScanResults = useCallback(async () => {
    try {
      const r = await secureFetch('/scans/results?limit=100');
      if (!r.ok) return;
      const body = await r.json();
      const raw: ScanResult[] = Array.isArray(body) ? body : body.items || [];
      // Deduplicate: keep only the most recent scan per apkName
      const seen = new Map<string, ScanResult>();
      for (const s of raw) {
        const key = s.apkName || s.id;
        const existing = seen.get(key);
        if (!existing || (s.startedAt && (!existing.startedAt || s.startedAt > existing.startedAt))) {
          seen.set(key, s);
        }
      }
      setScanResults(Array.from(seen.values()));
    } catch { /* best-effort */ }
  }, []);

  useEffect(() => { fetchReports(); }, [fetchReports]);
  useEffect(() => { fetchScanResults(); }, [fetchScanResults]);
  useEffect(() => { setPage(1); }, [query, typeFilter]);
  useEffect(() => { try { localStorage.setItem('aodsReports_pageSize', String(pageSize)); } catch {} }, [pageSize]);
  useEffect(() => { try { localStorage.setItem('aodsReports_sort', sortOption); } catch {} }, [sortOption]);

  /* ---- Sorting & pagination ---- */

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = { all: items.length, json: 0, html: 0, csv: 0, pdf: 0, other: 0 };
    for (const it of items) {
      const ext = getFileExt(it.name);
      if (ext in counts) counts[ext]++;
      else counts.other++;
    }
    return counts;
  }, [items]);

  const filteredItems = useMemo(() => {
    let arr = items;
    if (typeFilter !== 'all') {
      arr = arr.filter((it) => {
        const ext = getFileExt(it.name);
        return typeFilter === 'other' ? !['json', 'html', 'csv', 'pdf'].includes(ext) : ext === typeFilter;
      });
    }
    if (query) {
      const q = query.toLowerCase();
      arr = arr.filter((it) => {
        if ((it.name || '').toLowerCase().includes(q)) return true;
        // Also search the parsed display name (e.g. package name)
        const { displayName } = parseReportName(it.name);
        return displayName.toLowerCase().includes(q);
      });
    }
    const [sortKey, sortDir] = sortOption.split('-') as [string, string];
    return [...arr].sort((a, b) => {
      const ak = sortKey === 'name' ? (a.name || '') : sortKey === 'size' ? (a.size || 0) : a.modified || 0;
      const bk = sortKey === 'name' ? (b.name || '') : sortKey === 'size' ? (b.size || 0) : b.modified || 0;
      const cmp = typeof ak === 'string' && typeof bk === 'string' ? ak.localeCompare(bk) : (Number(ak) - Number(bk));
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [items, query, sortOption, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / Math.max(1, pageSize)));
  const startIdx = (page - 1) * pageSize;
  const endIdx = Math.min(filteredItems.length, startIdx + pageSize);
  const pageItems = useMemo(() => filteredItems.slice(startIdx, endIdx), [filteredItems, startIdx, endIdx]);

  /** Indices where a new package-name group starts (for visual grouping). */
  const groupStarts = useMemo(() => {
    const starts = new Map<number, { pkg: string; count: number }>();
    let lastPkg = '';
    let groupIdx = -1;
    for (let i = 0; i < pageItems.length; i++) {
      const { displayName } = parseReportName(pageItems[i].name);
      if (displayName !== lastPkg) {
        groupIdx = i;
        starts.set(i, { pkg: displayName, count: 1 });
        lastPkg = displayName;
      } else if (groupIdx >= 0) {
        starts.get(groupIdx)!.count++;
      }
    }
    // Only return groups if there are 2+ groups or a group has 2+ items (otherwise grouping adds noise)
    if (starts.size <= 1 && pageItems.length <= pageSize) return new Map<number, { pkg: string; count: number }>();
    return starts;
  }, [pageItems, pageSize]);

  /* ---- Report actions ---- */

  async function previewSummary(it: ReportItem) {
    try {
      setSummaries((prev) => ({ ...prev, [it.path]: { loading: true } }));
      const r = await secureFetch(`/reports/read?path=${encodeURIComponent(it.path)}`);
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      if (!j || typeof j.content !== 'string') throw new Error('invalid content');
      let data: any = null;
      try { data = JSON.parse(j.content); } catch { data = null; }
      const stats = computeReportStats(data);
      setSummaries((prev) => ({ ...prev, [it.path]: (stats ? { ...stats } : { error: true }) }));
    } catch {
      setSummaries((prev) => ({ ...prev, [it.path]: { error: true } }));
    }
  }

  async function handleGenerate() {
    if (!genResultId || genFormats.length === 0) return;
    setGenBusy(true);
    setGenError(null);
    setGenSuccess(false);
    setGenCurrentFmt('');
    let successCount = 0;
    for (const fmt of genFormats) {
      setGenCurrentFmt(fmt);
      try {
        const r = await secureFetch('/reports/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ result_id: genResultId, format: fmt }),
        });
        if (!r.ok) {
          const detail = await r.json().then(j => j.detail).catch(() => `HTTP ${r.status}`);
          setGenError(prev => prev ? `${prev}; ${fmt}: ${detail}` : `${fmt}: ${detail}`);
          continue;
        }
        const blob = await r.blob();
        const disposition = r.headers.get('content-disposition') || '';
        const filenameMatch = disposition.match(/filename="?([^"]+)"?/);
        const filename = filenameMatch?.[1] || `report.${fmt}`;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        successCount++;
      } catch (e: any) {
        setGenError(prev => prev ? `${prev}; ${fmt}: ${e?.message}` : `${fmt}: ${e?.message}`);
      }
    }
    setGenBusy(false);
    setGenCurrentFmt('');
    if (successCount > 0) {
      setGenSuccess(true);
      showToast(`Generated ${successCount} report${successCount > 1 ? 's' : ''}`);
      fetchReports();
    }
  }

  function toggleFormat(fmt: GenerateFormat) {
    setGenFormats(prev =>
      prev.includes(fmt) ? prev.filter(f => f !== fmt) : [...prev, fmt]
    );
  }

  function exportPageCsv() {
    try {
      const rows = pageItems.map((it) => ({
        name: it.name,
        path: it.path,
        size: it.size,
        modifiedIso: it.modified ? new Date(it.modified).toISOString() : '',
      }));
      const csv = ['name,path,size,modifiedIso']
        .concat(rows.map(r => [r.name, r.path, r.size, r.modifiedIso].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')))
        .join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'reports_page.csv'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* ignore */ }
  }

  function exportPageJson() {
    try {
      const rows = pageItems.map((it) => ({
        name: it.name,
        path: it.path,
        size: it.size,
        modified: it.modified || null,
      }));
      const blob = new Blob([JSON.stringify({ items: rows }, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'reports_page.json'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* ignore */ }
  }

  async function downloadReport(it: ReportItem) {
    try {
      const r = await secureFetch(`/reports/download?path=${encodeURIComponent(it.path)}`);
      if (!r.ok) throw new Error(String(r.status));
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = it.name || 'report'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 15000);
      const { displayName } = parseReportName(it.name);
      showToast(`Downloaded ${displayName}.${getFileExt(it.name)}`, 'info');
    } catch { showToast('Failed to download report', 'error'); }
  }

  async function openReport(it: ReportItem) {
    try {
      const r = await secureFetch(`/reports/read?path=${encodeURIComponent(it.path)}`);
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      const blob = new Blob([j?.content || ''], { type: j?.contentType || 'text/plain' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      setTimeout(() => URL.revokeObjectURL(url), 15000);
    } catch { showToast('Failed to open report', 'error'); }
  }

  function handlePageChange(_: unknown, v: number) {
    setPage(v);
    browserRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function clearFilters() {
    setQuery('');
    setTypeFilter('all');
  }

  const hasActiveFilters = query !== '' || typeFilter !== 'all';

  const totalSize = useMemo(() => filteredItems.reduce((s, it) => s + (it.size || 0), 0), [filteredItems]);

  /* ---- Render ---- */

  const isJsonFile = (name: string) => getFileExt(name) === 'json';

  const selectedScan = genResultId ? scanResults.find(x => x.id === genResultId) : undefined;

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title="Reports"
          subtitle="Generate, browse, and download scan reports"
          actions={
            <Tooltip title="Refresh report list">
              <IconButton
                size="small"
                onClick={() => { fetchReports(); fetchScanResults(); }}
                aria-label="Refresh reports"
                disabled={loading}
              >
                <RefreshIcon sx={{
                  transition: 'transform 0.3s',
                  ...(loading && {
                    animation: 'spin 1s linear infinite',
                    '@keyframes spin': { '0%': { transform: 'rotate(0deg)' }, '100%': { transform: 'rotate(360deg)' } },
                  }),
                }} />
              </IconButton>
            </Tooltip>
          }
        />
        <ErrorDisplay error={error} onRetry={fetchReports} />

        {/* ---- Generate Report ---- */}
        <Paper
          variant="outlined"
          sx={{ p: 2.5, position: 'relative', overflow: 'hidden' }}
          data-testid="generate-report-card"
          onKeyDown={(e) => { if (e.key === 'Enter' && genResultId && genFormats.length > 0 && !genBusy) handleGenerate(); }}
        >
          {genBusy && <LinearProgress sx={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2 }} />}
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 2 }}>
            Generate Report
          </Typography>

          {/* Row: Scan picker + format chips + generate button */}
          <Stack spacing={2}>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ sm: 'center' }}>
              <FormControl size="small" sx={{ flex: 1, minWidth: 260 }}>
                <InputLabel id="gen-scan-label">Scan Result</InputLabel>
                <Select
                  labelId="gen-scan-label"
                  label="Scan Result"
                  value={genResultId}
                  onChange={e => { setGenResultId(e.target.value); setGenSuccess(false); }}
                  data-testid="gen-scan-picker"
                  MenuProps={{ PaperProps: { sx: { maxHeight: 320 } } }}
                  renderValue={v => {
                    const s = scanResults.find(x => x.id === v);
                    if (!s) return v;
                    const parts = [s.apkName || s.id];
                    if (s.profile) parts.push(`[${s.profile}]`);
                    if (s.summary?.findings != null) parts.push(`${s.summary.findings} findings`);
                    if (s.startedAt) parts.push(formatDateTime(s.startedAt));
                    return parts.join(' \u00b7 ');
                  }}
                >
                  {scanResults.map(s => (
                    <MenuItem key={s.id} value={s.id} sx={{ py: 1 }}>
                      <Stack spacing={0} sx={{ minWidth: 0 }}>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography variant="body2" fontWeight={500} noWrap>
                            {s.apkName || s.id}
                          </Typography>
                          {s.profile && <Chip label={s.profile} size="small" variant="outlined" sx={{ height: 18, fontSize: 10 }} />}
                          {s.summary?.findings != null && (
                            <Typography variant="caption" color="text.secondary">
                              {s.summary.findings} findings {sevSummary(s.summary) ? `(${sevSummary(s.summary)})` : ''}
                            </Typography>
                          )}
                        </Stack>
                        <Typography variant="caption" color="text.disabled" noWrap>
                          {formatDateTime(s.startedAt)}
                        </Typography>
                      </Stack>
                    </MenuItem>
                  ))}
                  {scanResults.length === 0 && (
                    <MenuItem disabled value="">
                      <Typography variant="body2" color="text.secondary">No scan results available</Typography>
                    </MenuItem>
                  )}
                </Select>
              </FormControl>

              <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
                {(Object.keys(FORMAT_META) as GenerateFormat[]).map(fmt => {
                  const { label, icon: Icon } = FORMAT_META[fmt];
                  return (
                    <Chip
                      key={fmt}
                      icon={<Icon sx={{ fontSize: '14px !important' }} />}
                      label={label}
                      size="small"
                      color={genFormats.includes(fmt) ? 'primary' : 'default'}
                      variant={genFormats.includes(fmt) ? 'filled' : 'outlined'}
                      onClick={() => toggleFormat(fmt)}
                      data-testid={`gen-fmt-${fmt}`}
                    />
                  );
                })}
                <Tooltip title={genFormats.length === ALL_FORMATS.length ? 'Deselect all formats' : 'Select all formats'}>
                  <Chip
                    icon={<SelectAllIcon sx={{ fontSize: '14px !important' }} />}
                    label="All"
                    size="small"
                    color={genFormats.length === ALL_FORMATS.length ? 'primary' : 'default'}
                    variant={genFormats.length === ALL_FORMATS.length ? 'filled' : 'outlined'}
                    onClick={() => setGenFormats(genFormats.length === ALL_FORMATS.length ? ['html'] : [...ALL_FORMATS])}
                  />
                </Tooltip>
              </Stack>

              <Button
                variant="contained"
                size="small"
                disabled={!genResultId || genFormats.length === 0 || genBusy}
                onClick={handleGenerate}
                startIcon={genBusy ? <CircularProgress size={16} /> : <DownloadIcon />}
                aria-label="Generate report"
                data-testid="gen-report-btn"
                sx={{ minWidth: 130, height: 40, whiteSpace: 'nowrap' }}
              >
                {genBusy
                  ? genCurrentFmt
                    ? `${genCurrentFmt.toUpperCase()} (${genFormats.indexOf(genCurrentFmt as GenerateFormat) + 1}/${genFormats.length})`
                    : 'Generating...'
                  : genFormats.length > 1 ? `Generate ${genFormats.length} formats` : 'Generate'}
              </Button>
            </Stack>

            {/* Multi-format progress chips */}
            {genBusy && genFormats.length > 1 && (
              <Stack direction="row" spacing={0.5} alignItems="center">
                {genFormats.map(fmt => {
                  const Icon = FORMAT_META[fmt].icon;
                  const isCurrent = genCurrentFmt === fmt;
                  const isDone = genCurrentFmt ? genFormats.indexOf(fmt) < genFormats.indexOf(genCurrentFmt) : false;
                  return (
                    <Chip
                      key={fmt}
                      icon={isCurrent ? <CircularProgress size={12} /> : <Icon sx={{ fontSize: '14px !important' }} />}
                      label={FORMAT_META[fmt].label}
                      size="small"
                      color={isDone ? 'success' : isCurrent ? 'primary' : 'default'}
                      variant={isDone || isCurrent ? 'filled' : 'outlined'}
                      sx={{ opacity: isDone || isCurrent ? 1 : 0.5, transition: 'all 0.2s' }}
                    />
                  );
                })}
              </Stack>
            )}
            {/* Step hints, scan selection summary, or no-scans hint */}
            {scanResults.length === 0 && (
              <Typography variant="caption" color="text.disabled">
                No scan results available yet. Run a scan first, then come back to generate reports.
              </Typography>
            )}
            {!genResultId && scanResults.length > 0 && (
              <Stack direction="row" spacing={2} alignItems="center">
                {[
                  { step: '1', text: 'Select a scan result', done: false },
                  { step: '2', text: 'Choose formats', done: genFormats.length > 0 },
                  { step: '3', text: 'Generate', done: false },
                ].map(({ step, text, done }) => (
                  <Stack key={step} direction="row" spacing={0.5} alignItems="center">
                    <Box sx={{
                      width: 18, height: 18, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      bgcolor: done ? 'primary.main' : 'action.hover', color: done ? 'primary.contrastText' : 'text.disabled',
                      fontSize: 10, fontWeight: 700,
                    }}>
                      {step}
                    </Box>
                    <Typography variant="caption" color={done ? 'text.primary' : 'text.disabled'}>{text}</Typography>
                  </Stack>
                ))}
              </Stack>
            )}
            {selectedScan?.summary && (
              <Stack direction="row" spacing={1} alignItems="center" sx={{ pl: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  {selectedScan.apkName || selectedScan.id}:
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
                  {selectedScan.summary.findings ?? 0} findings
                </Typography>
                {selectedScan.summary.critical ? <Chip size="small" color="error" label={`${selectedScan.summary.critical}C`} sx={{ height: 16, fontSize: 10, '& .MuiChip-label': { px: 0.4 } }} /> : null}
                {selectedScan.summary.high ? <Chip size="small" color="warning" label={`${selectedScan.summary.high}H`} sx={{ height: 16, fontSize: 10, '& .MuiChip-label': { px: 0.4 } }} /> : null}
                {selectedScan.summary.medium ? <Chip size="small" variant="outlined" label={`${selectedScan.summary.medium}M`} sx={{ height: 16, fontSize: 10, '& .MuiChip-label': { px: 0.4 } }} /> : null}
                <SeverityBar critical={selectedScan.summary.critical} high={selectedScan.summary.high} medium={selectedScan.summary.medium} low={selectedScan.summary.low} total={selectedScan.summary.findings ?? 0} />
              </Stack>
            )}
            {genSuccess && !genError && (
              <Alert severity="success" variant="outlined" icon={<CheckCircleOutlineIcon fontSize="small" />} onClose={() => setGenSuccess(false)}>
                Report generated successfully - check the browser below or your downloads
              </Alert>
            )}
            {genError && <Alert severity="error" variant="outlined" onClose={() => setGenError(null)}>{genError}</Alert>}
          </Stack>
        </Paper>

        {/* ---- Aggregate summary ---- */}
        {aggregate && items.length > 0 && (
          <Paper variant="outlined" sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 3, flexWrap: 'wrap' }}>
            <Stack spacing={0.5} sx={{ mr: 1, minWidth: 100 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', lineHeight: 1.2 }}>
                Finding Summary
              </Typography>
              <Typography variant="caption" color="text.disabled" sx={{ lineHeight: 1.2 }}>
                {Math.min(typeCounts.json, 5)} latest reports
              </Typography>
              <SeverityBar
                critical={aggregate.critical}
                high={aggregate.high}
                medium={aggregate.medium}
                low={aggregate.low}
                total={aggregate.total_findings}
              />
            </Stack>
            <Divider orientation="vertical" flexItem />
            <Stack alignItems="center" spacing={0}>
              <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1.1, fontVariantNumeric: 'tabular-nums' }}>{aggregate.total_findings}</Typography>
              <Typography variant="caption" color="text.secondary">Total</Typography>
            </Stack>
            {[
              { n: aggregate.critical, label: 'Critical', color: 'error.main' },
              { n: aggregate.high, label: 'High', color: 'warning.main' },
              { n: aggregate.medium, label: 'Medium', color: 'info.main' },
              { n: aggregate.low, label: 'Low', color: 'text.disabled' },
            ].filter(({ n }) => n > 0).map(({ n, label, color }) => (
              <Stack key={label} alignItems="center" spacing={0}>
                <Stack direction="row" spacing={0.5} alignItems="center">
                  <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: color }} />
                  <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.1, color, fontVariantNumeric: 'tabular-nums' }}>{n}</Typography>
                </Stack>
                <Typography variant="caption" color="text.secondary">{label}</Typography>
              </Stack>
            ))}
          </Paper>
        )}

        {/* ---- Report browser ---- */}
        <Paper variant="outlined" sx={{ overflow: 'hidden' }} ref={browserRef}>
          {/* Header: title + count + pagination + export */}
          <Stack direction="row" alignItems="center" sx={{ px: 2, pt: 2, pb: 0.5 }} flexWrap="wrap" useFlexGap spacing={1}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>
              Report Browser
            </Typography>
            {!loading && (
              <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {filteredItems.length > 0
                  ? `${startIdx + 1}\u2013${endIdx} of ${filteredItems.length}${totalSize > 0 ? ` \u00b7 ${formatSize(totalSize)}` : ''}`
                  : '0 reports'}
              </Typography>
            )}
            {loading && (
              <Typography variant="caption" color="text.disabled">loading...</Typography>
            )}
            {!loading && lastRefreshed > 0 && (
              <Tooltip title={formatTime(new Date(lastRefreshed).toISOString())}>
                <Typography variant="caption" color="text.disabled" sx={{ cursor: 'default', opacity: 0.6 }}>
                  updated {relativeTime(lastRefreshed)}
                </Typography>
              </Tooltip>
            )}
            <Box sx={{ flex: 1 }} />
            {totalPages > 1 && (
              <Pagination
                count={totalPages}
                page={Math.min(page, totalPages)}
                onChange={handlePageChange}
                size="small"
              />
            )}
            <Tooltip title="Export current page">
              <Button
                size="small"
                variant="text"
                onClick={(e) => setExportAnchor(e.currentTarget)}
                endIcon={<ArrowDropDownIcon sx={{ fontSize: 14 }} />}
                startIcon={<FileDownloadIcon sx={{ fontSize: 14 }} />}
                aria-label="Export current page"
                sx={{ fontSize: 11, textTransform: 'none', minWidth: 0, px: 1 }}
              >
                Export
              </Button>
            </Tooltip>
            <Menu anchorEl={exportAnchor} open={Boolean(exportAnchor)} onClose={() => setExportAnchor(null)}>
              <MenuItem onClick={() => { exportPageCsv(); setExportAnchor(null); }}>
                <ListItemIcon><TableChartIcon fontSize="small" /></ListItemIcon>
                <ListItemText>Export as CSV</ListItemText>
              </MenuItem>
              <MenuItem onClick={() => { exportPageJson(); setExportAnchor(null); }}>
                <ListItemIcon><CodeIcon fontSize="small" /></ListItemIcon>
                <ListItemText>Export as JSON</ListItemText>
              </MenuItem>
            </Menu>
          </Stack>

          {/* Toolbar: search + type chips + sort + per-page */}
          <Stack direction="row" spacing={1} alignItems="center" sx={{ px: 2, pb: 1.5, pt: 0.5, position: 'sticky', top: 0, bgcolor: 'background.paper', zIndex: 1 }} flexWrap="wrap" useFlexGap rowGap={1}>
            <TextField
              size="small"
              placeholder="Search reports..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Escape') { setQuery(''); (e.target as HTMLInputElement).blur(); } }}
              sx={{ minWidth: 180, maxWidth: 280 }}
              inputProps={{ 'aria-label': 'Search reports by name' }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ fontSize: 18, color: 'text.disabled' }} />
                  </InputAdornment>
                ),
                endAdornment: query ? (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setQuery('')} edge="end" aria-label="Clear search">
                      <ClearIcon sx={{ fontSize: 16 }} />
                    </IconButton>
                  </InputAdornment>
                ) : undefined,
              }}
            />
            {(Object.keys(FILE_TYPE_LABELS) as FileType[])
              .filter(t => t === 'all' || typeCounts[t] > 0)
              .map(t => {
                const dot = TYPE_DOT_COLOR[t];
                return (
                  <Chip
                    key={t}
                    icon={dot ? <Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: dot, ml: '4px !important', mr: '-2px !important' }} component="span" /> : undefined}
                    label={`${FILE_TYPE_LABELS[t]} (${typeCounts[t]})`}
                    size="small"
                    color={typeFilter === t ? 'primary' : 'default'}
                    variant={typeFilter === t ? 'filled' : 'outlined'}
                    onClick={() => setTypeFilter(t)}
                    sx={{ fontVariantNumeric: 'tabular-nums' }}
                  />
                );
              })}
            {hasActiveFilters && (
              <Chip
                label="Clear"
                size="small"
                variant="outlined"
                onDelete={clearFilters}
                onClick={clearFilters}
                sx={{ height: 22, fontSize: 11 }}
              />
            )}
            <Box sx={{ flex: 1 }} />
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel id="reports-sort-label">Sort</InputLabel>
              <Select
                labelId="reports-sort-label"
                label="Sort"
                value={sortOption}
                onChange={(e) => setSortOption(e.target.value)}
                renderValue={(v) => {
                  const SIcon = SORT_ICON[v] || SortIcon;
                  const labels: Record<string, string> = { 'modified-desc': 'Newest', 'modified-asc': 'Oldest', 'name-asc': 'A-Z', 'name-desc': 'Z-A', 'size-desc': 'Largest', 'size-asc': 'Smallest' };
                  return <Stack direction="row" spacing={0.5} alignItems="center"><SIcon sx={{ fontSize: 14, color: 'text.secondary' }} /><span>{labels[v] || v}</span></Stack>;
                }}
              >
                <MenuItem value="modified-desc"><ListItemIcon><AccessTimeIcon fontSize="small" /></ListItemIcon><ListItemText>Newest first</ListItemText></MenuItem>
                <MenuItem value="modified-asc"><ListItemIcon><AccessTimeIcon fontSize="small" /></ListItemIcon><ListItemText>Oldest first</ListItemText></MenuItem>
                <MenuItem value="name-asc"><ListItemIcon><SortByAlphaIcon fontSize="small" /></ListItemIcon><ListItemText>Name A-Z</ListItemText></MenuItem>
                <MenuItem value="name-desc"><ListItemIcon><SortByAlphaIcon fontSize="small" /></ListItemIcon><ListItemText>Name Z-A</ListItemText></MenuItem>
                <MenuItem value="size-desc"><ListItemIcon><StorageIcon fontSize="small" /></ListItemIcon><ListItemText>Largest first</ListItemText></MenuItem>
                <MenuItem value="size-asc"><ListItemIcon><StorageIcon fontSize="small" /></ListItemIcon><ListItemText>Smallest first</ListItemText></MenuItem>
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 80 }}>
              <InputLabel id="reports-page-size-label">Show</InputLabel>
              <Select labelId="reports-page-size-label" label="Show" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}>
                {[10, 25, 50, 100].map((sz) => (
                  <MenuItem key={sz} value={sz}>{sz}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>

          <Divider />

          {/* Loading skeleton */}
          {loading && (
            <Stack spacing={0} divider={<Divider />}>
              {Array.from({ length: 5 }).map((_, i) => <ReportRowSkeleton key={i} />)}
            </Stack>
          )}

          {/* Report items */}
          {!loading && pageItems.length > 0 && (
            <Stack spacing={0}>
              {pageItems.map((it, idx) => {
                const ext = getFileExt(it.name);
                const { displayName, timestamp } = parseReportName(it.name);
                const canPreview = isJsonFile(it.name);
                const summaryData = summaries[it.path];
                const summaryOpen = Boolean(summaryData) && !summaryData?.loading;
                const fresh = typeof it.modified === 'number' && isRecent(it.modified);
                const group = groupStarts.get(idx);
                return (
                  <Box key={idx}>
                    {/* Package group header */}
                    {group && (
                      <Stack
                        direction="row"
                        alignItems="center"
                        spacing={1}
                        sx={{ px: 2, py: 0.5, bgcolor: 'action.hover', borderBottom: 1, borderTop: idx > 0 ? 1 : 0, borderColor: 'divider' }}
                      >
                        <Typography variant="caption" sx={{ fontWeight: 700, fontSize: 11, letterSpacing: '0.02em', color: 'text.secondary' }}>
                          {group.pkg}
                        </Typography>
                        {group.count > 1 && (
                          <Chip
                            label={group.count}
                            size="small"
                            variant="outlined"
                            sx={{ height: 16, fontSize: 9, fontWeight: 600, '& .MuiChip-label': { px: 0.4 } }}
                          />
                        )}
                      </Stack>
                    )}
                    <Box
                      tabIndex={0}
                      role="row"
                      sx={{
                        px: 2, py: 1.25,
                        borderLeft: 3, borderColor: EXT_ACCENT[ext] || 'divider',
                        bgcolor: idx % 2 === 1 ? 'action.hover' : 'transparent',
                        '&:hover, &:focus-visible': { bgcolor: 'action.selected' },
                        '&:hover .row-actions, &:focus-visible .row-actions': { opacity: 1 },
                        '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2, borderRadius: 0.5 },
                        transition: 'background-color 0.15s',
                        cursor: 'default',
                      }}
                      onDoubleClick={() => downloadReport(it)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') { e.preventDefault(); downloadReport(it); }
                        if (e.key === 'o' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); openReport(it); }
                      }}
                    >
                    <Stack direction="row" alignItems="center" spacing={1.5}>
                      <FileTypeIcon ext={ext} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Stack direction="row" spacing={0.75} alignItems="center">
                          <Tooltip title={it.name !== displayName ? it.name : ''} placement="top-start" enterDelay={600}>
                            <Typography variant="body2" sx={{ fontWeight: 600, lineHeight: 1.3 }} noWrap>
                              {displayName}
                            </Typography>
                          </Tooltip>
                          {fresh && (
                            <Chip
                              label="New"
                              size="small"
                              color="success"
                              variant="outlined"
                              sx={{ height: 16, fontSize: 9, fontWeight: 700, '& .MuiChip-label': { px: 0.5 } }}
                            />
                          )}
                        </Stack>
                        <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mt: 0.125 }}>
                          <Typography variant="caption" color="text.secondary" noWrap>
                            {[ext.toUpperCase(), timestamp || null, formatSize(it.size)].filter(Boolean).join(' \u00b7 ')}
                          </Typography>
                          {typeof it.modified === 'number' && (
                            <Tooltip title={formatDateTime(new Date(it.modified).toISOString())} placement="top">
                              <Typography variant="caption" color="text.disabled" sx={{ cursor: 'default', flexShrink: 0 }}>
                                {relativeTime(it.modified)}
                              </Typography>
                            </Tooltip>
                          )}
                        </Stack>
                      </Box>
                      <Stack
                        className="row-actions"
                        direction="row"
                        spacing={0.25}
                        alignItems="center"
                        sx={{ opacity: { xs: 1, md: 0 }, transition: 'opacity 0.15s' }}
                      >
                        <Tooltip title="Copy path">
                          <IconButton
                            size="small"
                            aria-label={`Copy path for ${it.name}`}
                            onClick={() => {
                              try { navigator.clipboard.writeText(it.path); showToast('Path copied'); } catch { showToast('Failed to copy path', 'error'); }
                            }}
                          >
                            <ContentCopyIcon sx={{ fontSize: 15 }} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={<>Open in new tab <Typography component="span" variant="caption" sx={{ opacity: 0.7, ml: 0.5 }}>Cmd+O</Typography></>}>
                          <IconButton
                            size="small"
                            aria-label={`Open report ${it.name}`}
                            onClick={() => openReport(it)}
                          >
                            <OpenInNewIcon sx={{ fontSize: 15 }} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={<>Download <Typography component="span" variant="caption" sx={{ opacity: 0.7, ml: 0.5 }}>Enter</Typography></>}>
                          <IconButton
                            size="small"
                            aria-label={`Download report ${it.name}`}
                            onClick={() => downloadReport(it)}
                          >
                            <DownloadIcon sx={{ fontSize: 16 }} />
                          </IconButton>
                        </Tooltip>
                        {canPreview && (
                          <Button
                            size="small"
                            variant="text"
                            aria-label={`${summaryOpen ? 'Hide' : 'Preview'} summary for ${it.name}`}
                            aria-expanded={summaryOpen}
                            onClick={() => {
                              if (summaryOpen) {
                                setSummaries((prev) => { const next = { ...prev }; delete next[it.path]; return next; });
                              } else {
                                previewSummary(it);
                              }
                            }}
                            disabled={Boolean(summaryData?.loading)}
                            sx={{ fontSize: 12, textTransform: 'none', minWidth: 0, px: 0.75 }}
                          >
                            {summaryOpen ? 'Hide' : 'Preview'}
                          </Button>
                        )}
                      </Stack>
                    </Stack>

                    {/* Preview severity bar - animated */}
                    {summaryData?.loading && (
                      <Box sx={{ ml: 4.5, mt: 0.75 }}>
                        <LinearProgress sx={{ borderRadius: 1, maxWidth: 200, height: 3 }} />
                      </Box>
                    )}
                    <Collapse in={summaryOpen && !summaryData?.error} timeout={200} unmountOnExit>
                      <Stack spacing={0.5} sx={{ ml: 4.5, mt: 0.75, pt: 0.75, borderTop: 1, borderColor: 'divider' }}>
                        <Stack direction="row" spacing={0.75} alignItems="center">
                          <Typography variant="caption" sx={{ fontWeight: 600 }}>
                            {summaryData?.total_findings ?? 0} findings:
                          </Typography>
                          {(summaryData?.critical ?? 0) > 0 && <Chip size="small" color="error" label={`${summaryData.critical} Critical`} sx={{ height: 20, fontSize: 11 }} />}
                          {(summaryData?.high ?? 0) > 0 && <Chip size="small" color="warning" label={`${summaryData.high} High`} sx={{ height: 20, fontSize: 11 }} />}
                          {(summaryData?.medium ?? 0) > 0 && <Chip size="small" variant="outlined" label={`${summaryData.medium} Med`} sx={{ height: 20, fontSize: 11 }} />}
                          {(summaryData?.low ?? 0) > 0 && <Chip size="small" variant="outlined" label={`${summaryData.low} Low`} sx={{ height: 20, fontSize: 11 }} />}
                        </Stack>
                        <SeverityBar
                          critical={summaryData?.critical}
                          high={summaryData?.high}
                          medium={summaryData?.medium}
                          low={summaryData?.low}
                          total={summaryData?.total_findings}
                        />
                      </Stack>
                    </Collapse>
                    {summaryData?.error && (
                      <Typography variant="caption" color="text.secondary" sx={{ ml: 4.5, mt: 0.75, display: 'block' }}>
                        Could not load preview
                      </Typography>
                    )}
                    </Box>
                  </Box>
                );
              })}
            </Stack>
          )}

          {/* Empty state */}
          {!loading && pageItems.length === 0 && (
            <Box sx={{ py: 4, textAlign: 'center' }}>
              <FolderOpenIcon sx={{ fontSize: 40, color: 'text.disabled', mb: 1 }} />
              <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                {hasActiveFilters
                  ? 'No reports match your filters'
                  : 'No reports found'}
              </Typography>
              <Typography variant="caption" color="text.disabled">
                {hasActiveFilters
                  ? 'Try broadening your search or changing the file type filter'
                  : scanResults.length > 0
                    ? 'Use the Generate Report card above to create your first report'
                    : 'Run a scan first, then generate reports from the results'}
              </Typography>
              {hasActiveFilters && (
                <Box sx={{ mt: 1.5 }}>
                  <Button size="small" variant="outlined" onClick={clearFilters} sx={{ textTransform: 'none', fontSize: 12 }}>
                    Clear all filters
                  </Button>
                </Box>
              )}
            </Box>
          )}

          {/* Bottom pagination */}
          {!loading && totalPages > 1 && (
            <>
              <Divider />
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ px: 2, py: 1 }}>
                <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                  {startIdx + 1}&ndash;{endIdx} of {filteredItems.length}
                </Typography>
                <Pagination
                  count={totalPages}
                  page={Math.min(page, totalPages)}
                  onChange={handlePageChange}
                  size="small"
                />
              </Stack>
            </>
          )}
        </Paper>
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
