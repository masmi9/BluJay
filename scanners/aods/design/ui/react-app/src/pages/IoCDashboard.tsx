import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Slider,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  IconButton,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import HubIcon from '@mui/icons-material/Hub';
import { AODSApiClient } from '../services/api';
import { PageHeader, ErrorDisplay, LoadingSkeleton, AppToast } from '../components';
import { useToast } from '../hooks/useToast';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';

const api = new AODSApiClient();

type IoCStats = {
  total_iocs: number;
  total_scans: number;
  type_distribution: Record<string, number>;
};

type Cluster = {
  ioc_value: string;
  ioc_type: string;
  apk_names?: string[];
  scan_ids?: string[];
  count: number;
};

type Correlation = {
  scan_id: string;
  apk_name?: string;
  ioc_type?: string;
  ioc_value?: string;
  confidence?: number;
};

export function IoCDashboard() {
  const { toast, showToast, closeToast } = useToast();
  const copy = useCopyToClipboard({ toast: { showToast, closeToast, toast } });
  const [stats, setStats] = useState<IoCStats | null>(null);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [loading, setLoading] = useState(true);
  const [clusterLoading, setClusterLoading] = useState(false);
  const [searchLoading, setSearchLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchValue, setSearchValue] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [minApks, setMinApks] = useState(2);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getIoCStats();
      setStats(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load IoC statistics');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchClusters = useCallback(async () => {
    setClusterLoading(true);
    try {
      const data = await api.getIoCClusters(minApks);
      setClusters(data.clusters || []);
    } catch {
      setClusters([]);
    } finally {
      setClusterLoading(false);
    }
  }, [minApks]);

  const handleSearch = useCallback(async () => {
    if (!searchValue.trim()) return;
    setSearchLoading(true);
    setSearchQuery(searchValue.trim());
    try {
      const data = await api.getIoCCorrelations(searchValue.trim());
      setCorrelations(data.correlations || []);
    } catch {
      setCorrelations([]);
    } finally {
      setSearchLoading(false);
    }
  }, [searchValue]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    fetchClusters();
  }, [fetchClusters]);

  const typeEntries = useMemo(() => {
    if (!stats?.type_distribution) return [];
    return Object.entries(stats.type_distribution)
      .filter(([, v]) => v > 0)
      .sort(([, a], [, b]) => b - a);
  }, [stats]);

  return (
    <Box data-testid="ioc-dashboard-page">
      <PageHeader
        title="IoC Dashboard"
        subtitle="Indicators of Compromise intelligence and cross-APK correlation"
      />

      {error && <ErrorDisplay error={error} onRetry={fetchStats} />}
      {loading && <LoadingSkeleton variant="card" />}

      {!loading && !error && stats && (
        <>
          {/* Stats Cards */}
          <Stack direction="row" spacing={2} sx={{ mb: 3 }} flexWrap="wrap" useFlexGap>
            <Card variant="outlined" sx={{ minWidth: 160, borderRadius: 2 }}>
              <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                <Typography variant="caption" color="text.secondary">Total IoCs</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }} data-testid="total-iocs">
                  {stats.total_iocs.toLocaleString()}
                </Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 160, borderRadius: 2 }}>
              <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                <Typography variant="caption" color="text.secondary">Scans with IoCs</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }} data-testid="total-scans">
                  {stats.total_scans.toLocaleString()}
                </Typography>
              </CardContent>
            </Card>
            {typeEntries.length > 0 && (
              <Card variant="outlined" sx={{ flex: 1, minWidth: 240, borderRadius: 2 }}>
                <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                  <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>
                    Type Distribution
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {typeEntries.map(([type, count]) => (
                      <Chip
                        key={type}
                        label={`${type.replace(/_/g, ' ')}: ${count}`}
                        size="small"
                        variant="outlined"
                        color={['c2_ip', 'crypto_wallet', 'onion_address'].includes(type) ? 'error' : 'default'}
                      />
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}
          </Stack>

          {/* IoC Value Search */}
          <Card variant="outlined" sx={{ mb: 3, borderRadius: 2 }}>
            <CardContent>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                <SearchIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  IoC Value Search
                </Typography>
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <TextField
                  size="small"
                  label="IoC Value"
                  placeholder="Search for IP, domain, URL, hash..."
                  value={searchValue}
                  onChange={(e) => setSearchValue(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleSearch(); }}
                  sx={{ minWidth: 320 }}
                  inputProps={{ 'aria-label': 'IoC value to search' }}
                />
                <Button
                  size="small"
                  variant="contained"
                  onClick={handleSearch}
                  disabled={searchLoading || !searchValue.trim()}
                  startIcon={searchLoading ? <CircularProgress size={14} /> : <SearchIcon sx={{ fontSize: 16 }} />}
                  sx={{ textTransform: 'none' }}
                >
                  Search
                </Button>
              </Stack>

              {searchQuery && !searchLoading && (
                <Box sx={{ mt: 2 }}>
                  {correlations.length === 0 ? (
                    <Typography variant="body2" color="text.secondary" data-testid="no-correlations">
                      No correlations found for "{searchQuery}"
                    </Typography>
                  ) : (
                    <>
                      <Typography variant="body2" sx={{ mb: 1, fontWeight: 500 }} data-testid="correlation-count">
                        {correlations.length} correlation(s) found for "{searchQuery}"
                      </Typography>
                      <TableContainer sx={{ maxHeight: 300 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ fontWeight: 600 }}>Scan ID</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>APK</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>Confidence</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {correlations.map((c, i) => (
                              <TableRow key={i} hover>
                                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                                  <Stack direction="row" alignItems="center" spacing={0.5}>
                                    <span>{c.scan_id}</span>
                                    <Tooltip title="Copy scan ID">
                                      <IconButton size="small" onClick={() => copy(c.scan_id, 'Scan ID')} aria-label="Copy scan ID">
                                        <ContentCopyIcon sx={{ fontSize: 14 }} />
                                      </IconButton>
                                    </Tooltip>
                                  </Stack>
                                </TableCell>
                                <TableCell>{c.apk_name || '-'}</TableCell>
                                <TableCell>
                                  <Chip label={c.ioc_type || 'unknown'} size="small" variant="outlined" />
                                </TableCell>
                                <TableCell>
                                  {typeof c.confidence === 'number' ? `${(c.confidence * 100).toFixed(0)}%` : '-'}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </>
                  )}
                </Box>
              )}
            </CardContent>
          </Card>

          {/* Cross-APK Clusters */}
          <Card variant="outlined" sx={{ borderRadius: 2 }}>
            <CardContent>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                <HubIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  Cross-APK IoC Clusters
                </Typography>
                <Chip label={`${clusters.length} clusters`} size="small" variant="outlined" />
              </Stack>

              <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2, maxWidth: 360 }}>
                <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: 'nowrap' }}>
                  Min APKs:
                </Typography>
                <Slider
                  size="small"
                  value={minApks}
                  min={2}
                  max={10}
                  step={1}
                  onChange={(_, v) => setMinApks(v as number)}
                  valueLabelDisplay="auto"
                  aria-label="Minimum APKs sharing IoC"
                  sx={{ flex: 1 }}
                />
                <Typography variant="body2" sx={{ fontWeight: 600, minWidth: 20 }}>{minApks}</Typography>
              </Stack>

              {clusterLoading ? (
                <LoadingSkeleton variant="table" />
              ) : clusters.length === 0 ? (
                <Typography variant="body2" color="text.secondary" data-testid="no-clusters">
                  No clusters found with {minApks}+ APKs sharing IoCs
                </Typography>
              ) : (
                <TableContainer sx={{ maxHeight: 400 }}>
                  <Table size="small" data-testid="clusters-table">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>IoC Value</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>APKs Sharing</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Scan Count</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {clusters.map((c, i) => (
                        <TableRow key={i} hover>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 300 }}>
                            <Stack direction="row" alignItems="center" spacing={0.5}>
                              <Tooltip title={c.ioc_value}>
                                <Typography variant="body2" noWrap sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 260 }}>
                                  {c.ioc_value}
                                </Typography>
                              </Tooltip>
                              <Tooltip title="Copy IoC value">
                                <IconButton size="small" onClick={() => copy(c.ioc_value, 'IoC value')} aria-label="Copy IoC value">
                                  <ContentCopyIcon sx={{ fontSize: 14 }} />
                                </IconButton>
                              </Tooltip>
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Chip label={c.ioc_type?.replace(/_/g, ' ') || 'unknown'} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>{c.apk_names?.length || c.count}</TableCell>
                          <TableCell>{c.scan_ids?.length || '-'}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </>
      )}
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
