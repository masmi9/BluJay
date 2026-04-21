import { useEffect, useState, useMemo, useCallback } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Button,
  Chip,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Pagination,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Tooltip,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  FormControlLabel,
  Switch,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CancelIcon from '@mui/icons-material/Cancel';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { secureFetch } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { PageHeader, ErrorDisplay, LoadingSkeleton, StatusChip, EmptyState } from '../components';

interface RecentJob {
  id: string;
  source: string;
  apkName: string;
  apkPath: string | null;
  status: string;
  profile: string | null;
  mode: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingsCount: number | null;
  reportPath?: string;
  createdAt?: number;
}

type SortField = 'startedAt' | 'durationMs' | 'findingsCount' | 'status';
type SortOrder = 'asc' | 'desc';

export function RecentJobs() {
  const [jobs, setJobs] = useState<RecentJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('startedAt');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [jobToCancel, setJobToCancel] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const fetchJobs = useCallback(async () => {
    try {
      const offset = (page - 1) * pageSize;
      const statusParam = statusFilter !== 'all' ? `&status=${statusFilter}` : '';
      const r = await secureFetch(`/scans/recent?limit=${pageSize}&offset=${offset}${statusParam}`);
      if (!r.ok) {
        const detail = await r.text();
        throw new Error(`HTTP ${r.status}: ${detail}`);
      }
      const data = await r.json();
      setJobs(data.items || []);
      setTotal(data.total || 0);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to fetch recent jobs');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, statusFilter]);

  useEffect(() => {
    setLoading(true);
    fetchJobs();
  }, [fetchJobs]);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchJobs();
    }, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchJobs]);

  // Sort jobs locally
  const sortedJobs = useMemo(() => {
    const sorted = [...jobs].sort((a, b) => {
      let aVal: any;
      let bVal: any;

      switch (sortField) {
        case 'startedAt':
          aVal = a.startedAt || a.createdAt || 0;
          bVal = b.startedAt || b.createdAt || 0;
          break;
        case 'durationMs':
          aVal = a.durationMs ?? 0;
          bVal = b.durationMs ?? 0;
          break;
        case 'findingsCount':
          aVal = a.findingsCount ?? 0;
          bVal = b.findingsCount ?? 0;
          break;
        case 'status':
          aVal = a.status || '';
          bVal = b.status || '';
          break;
        default:
          return 0;
      }

      if (typeof aVal === 'string') {
        const cmp = aVal.localeCompare(bVal);
        return sortOrder === 'asc' ? cmp : -cmp;
      }
      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
    });
    return sorted;
  }, [jobs, sortField, sortOrder]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const handleCancelClick = (jobId: string) => {
    setJobToCancel(jobId);
    setCancelDialogOpen(true);
  };

  const handleCancelConfirm = async () => {
    if (!jobToCancel) return;
    setCancelling(true);
    try {
      const r = await secureFetch(`/scans/${jobToCancel}/cancel`, { method: 'POST' });
      if (!r.ok) {
        const detail = await r.text();
        throw new Error(`Failed to cancel: ${detail}`);
      }
      // Refresh the list
      fetchJobs();
    } catch (e: any) {
      setError(e?.message || 'Failed to cancel scan');
    } finally {
      setCancelling(false);
      setCancelDialogOpen(false);
      setJobToCancel(null);
    }
  };

  const formatDuration = (ms: number | null): string => {
    if (ms === null || ms === undefined) return '-';
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    const mins = Math.floor(ms / 60000);
    const secs = Math.floor((ms % 60000) / 1000);
    return `${mins}m ${secs}s`;
  };


  const totalPages = Math.ceil(total / pageSize);

  if (loading && jobs.length === 0) {
    return <LoadingSkeleton variant="table" />;
  }

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader
          title="Recent Jobs"
          subtitle="Monitor scan history, status, and results"
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
              label="Auto-refresh (30s)"
            />
            <Tooltip title="Refresh">
              <IconButton onClick={fetchJobs} disabled={loading} aria-label="Refresh">
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        }
      />

      <ErrorDisplay error={error} onRetry={fetchJobs} />

      {/* Filters */}
      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={statusFilter}
            label="Status"
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="running">Running</MenuItem>
            <MenuItem value="queued">Queued</MenuItem>
            <MenuItem value="completed">Completed</MenuItem>
            <MenuItem value="failed">Failed</MenuItem>
            <MenuItem value="cancelled">Cancelled</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 100 }}>
          <InputLabel>Per Page</InputLabel>
          <Select
            value={pageSize}
            label="Per Page"
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
          >
            <MenuItem value={20}>20</MenuItem>
            <MenuItem value={50}>50</MenuItem>
            <MenuItem value={100}>100</MenuItem>
          </Select>
        </FormControl>
        <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
          {total} total jobs
        </Typography>
      </Stack>

      {/* Jobs Table */}
      <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
        <Table size="small" aria-label="Recent jobs table">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 600 }}>ID</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>APK</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Profile</TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'status'}
                  direction={sortField === 'status' ? sortOrder : 'asc'}
                  onClick={() => handleSort('status')}
                >
                  Status
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'startedAt'}
                  direction={sortField === 'startedAt' ? sortOrder : 'asc'}
                  onClick={() => handleSort('startedAt')}
                >
                  Started
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'durationMs'}
                  direction={sortField === 'durationMs' ? sortOrder : 'asc'}
                  onClick={() => handleSort('durationMs')}
                >
                  Duration
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'findingsCount'}
                  direction={sortField === 'findingsCount' ? sortOrder : 'asc'}
                  onClick={() => handleSort('findingsCount')}
                >
                  Findings
                </TableSortLabel>
              </TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sortedJobs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} align="center">
                  <EmptyState message="No jobs found" />
                </TableCell>
              </TableRow>
            ) : (
              sortedJobs.map((job) => (
                <TableRow key={job.id} hover>
                  <TableCell>
                    <Tooltip title={job.id}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.75rem',
                          maxWidth: 100,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {job.id.slice(0, 8)}...
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Tooltip title={job.apkPath || job.apkName}>
                      <Typography
                        variant="body2"
                        sx={{
                          maxWidth: 200,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {job.apkName}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    {job.profile ? (
                      <Chip label={job.profile} size="small" variant="outlined" />
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell>
                    <StatusChip status={job.status} size="small" />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                      {formatDateTime(job.startedAt)}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{formatDuration(job.durationMs)}</TableCell>
                  <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>
                    {job.findingsCount !== null ? job.findingsCount : '-'}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5}>
                      {job.status === 'completed' && (
                        <Tooltip title="View Details">
                          <IconButton
                            component={RouterLink}
                            to={`/runs/${job.id}`}
                            size="small"
                            aria-label="View result details"
                          >
                            <OpenInNewIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {(job.status === 'running' || job.status === 'queued') && (
                        <Tooltip title="Cancel">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleCancelClick(job.id)}
                            aria-label="Cancel scan"
                          >
                            <CancelIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Pagination */}
      {totalPages > 1 && (
        <Stack direction="row" justifyContent="center">
          <Pagination
            count={totalPages}
            page={page}
            onChange={(_, p) => setPage(p)}
            color="primary"
            showFirstButton
            showLastButton
          />
        </Stack>
      )}
      </Stack>

      {/* Cancel Confirmation Dialog */}
      <Dialog open={cancelDialogOpen} onClose={() => setCancelDialogOpen(false)}>
        <DialogTitle>Cancel Scan</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to cancel scan {jobToCancel?.slice(0, 8)}...? This action cannot be
            undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCancelDialogOpen(false)} disabled={cancelling}>
            No, Keep Running
          </Button>
          <Button
            onClick={handleCancelConfirm}
            color="error"
            variant="contained"
            disabled={cancelling}
          >
            {cancelling ? 'Cancelling...' : 'Yes, Cancel'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default RecentJobs;
