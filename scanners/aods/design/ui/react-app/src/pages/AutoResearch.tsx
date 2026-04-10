import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { AODSApiClient } from '../services/api';
import { PageHeader, ErrorDisplay, LoadingSkeleton } from '../components';
import type { AutoResearchExperiment, AutoResearchConfig } from '../types';

const api = new AODSApiClient();

const TIER_LABELS: Record<string, string> = {
  tier_1: 'Tier 1 - Global FP Controls',
  tier_2: 'Tier 2 - Per-Source Noise Weights',
  tier_3: 'Tier 3 - Per-Category Detection Thresholds',
};

export function AutoResearch() {
  const [config, setConfig] = useState<AutoResearchConfig | null>(null);
  const [experiments, setExperiments] = useState<AutoResearchExperiment[]>([]);
  const [bestExperiments, setBestExperiments] = useState<AutoResearchExperiment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewType, setViewType] = useState<'recent' | 'best' | 'accepted'>('recent');

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [configRes, recentRes, bestRes] = await Promise.all([
        api.getAutoResearchConfig(),
        api.getAutoResearchExperiments({ type: 'recent', n: 50 }),
        api.getAutoResearchExperiments({ type: 'best', n: 5 }),
      ]);
      setConfig(configRes);
      setExperiments(recentRes.experiments);
      setBestExperiments(bestRes.experiments);
    } catch (err: any) {
      setError(err?.message || 'Failed to load AutoResearch data');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchExperiments = useCallback(async (type: 'recent' | 'best' | 'accepted') => {
    try {
      const res = await api.getAutoResearchExperiments({ type, n: 50 });
      setExperiments(res.experiments);
    } catch {
      setExperiments([]);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    fetchExperiments(viewType);
  }, [viewType, fetchExperiments]);

  const runIds = useMemo(() => {
    const ids = new Set(experiments.map((e) => e.run_id));
    return Array.from(ids);
  }, [experiments]);

  return (
    <Box data-testid="autoresearch-page">
      <PageHeader
        title="AutoResearch"
        subtitle="Autonomous FP/detection parameter optimization"
      />

      {error && <ErrorDisplay error={error} onRetry={fetchData} />}
      {loading && <LoadingSkeleton variant="card" />}

      {!loading && !error && config && (
        <>
          {/* Config Overview */}
          <Card variant="outlined" sx={{ mb: 3, borderRadius: 2 }}>
            <CardContent>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1.5 }}>
                Parameter Space
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 1.5 }} flexWrap="wrap" useFlexGap>
                <Chip label={`${config.total_params} parameters`} size="small" color="primary" />
                <Chip label={`AQS: ${config.aqs_formula}`} size="small" variant="outlined" />
                <Chip label={`Mode: ${config.defaults.mode}`} size="small" variant="outlined" />
                <Chip label={`Max experiments: ${config.defaults.max_experiments}`} size="small" variant="outlined" />
              </Stack>

              {/* Parameter tiers */}
              {Object.entries(config.parameter_space).map(([tierKey, params]) => (
                <Box key={tierKey} sx={{ mb: 1.5 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                    {TIER_LABELS[tierKey] || tierKey} ({params.length} params)
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {params.map((p) => (
                      <Chip
                        key={p.name}
                        label={`${p.name}: ${p.default_value} [${p.min_value}–${p.max_value}]`}
                        size="small"
                        variant="outlined"
                        sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                      />
                    ))}
                  </Stack>
                </Box>
              ))}
            </CardContent>
          </Card>

          {/* Best Experiments Highlight */}
          {bestExperiments.length > 0 && (
            <Card variant="outlined" sx={{ mb: 3, borderRadius: 2, borderColor: 'success.main' }}>
              <CardContent>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: 'success.main' }}>
                  Top Experiments by AQS
                </Typography>
                <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                  {bestExperiments.map((e) => (
                    <Card key={e.id} variant="outlined" sx={{ minWidth: 180, borderRadius: 1 }}>
                      <CardContent sx={{ py: 1, px: 1.5, '&:last-child': { pb: 1 } }}>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: 'success.main' }}>
                          {e.aqs?.toFixed(4)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Run: {e.run_id?.slice(0, 8)} #{e.experiment_num}
                        </Typography>
                        <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                          <Chip label={`D: ${e.detection_score?.toFixed(3)}`} size="small" color="primary" variant="outlined" sx={{ fontSize: '0.65rem' }} />
                          <Chip label={`FP: ${e.fp_penalty?.toFixed(3)}`} size="small" color="error" variant="outlined" sx={{ fontSize: '0.65rem' }} />
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Experiment History */}
          <Card variant="outlined" sx={{ borderRadius: 2 }}>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  Experiment History
                </Typography>
                <FormControl size="small" sx={{ minWidth: 140 }}>
                  <InputLabel>View</InputLabel>
                  <Select
                    label="View"
                    value={viewType}
                    onChange={(e) => setViewType(e.target.value as any)}
                    data-testid="view-type-select"
                  >
                    <MenuItem value="recent">Recent</MenuItem>
                    <MenuItem value="best">Best AQS</MenuItem>
                    <MenuItem value="accepted">Accepted Only</MenuItem>
                  </Select>
                </FormControl>
                <Chip label={`${experiments.length} experiments`} size="small" variant="outlined" />
                {runIds.length > 0 && (
                  <Chip label={`${runIds.length} run(s)`} size="small" variant="outlined" />
                )}
              </Stack>

              {experiments.length === 0 ? (
                <Typography variant="body2" color="text.secondary" data-testid="no-experiments">
                  No experiments found. Run autoresearch via CLI to generate data.
                </Typography>
              ) : (
                <TableContainer sx={{ maxHeight: 500 }}>
                  <Table size="small" data-testid="experiments-table">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>#</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Run</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>AQS</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Detection</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>FP Penalty</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Stability</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Accepted</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Reason</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Elapsed</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {experiments.map((e) => (
                        <TableRow key={e.id} hover sx={{ bgcolor: e.accepted ? 'success.50' : undefined }}>
                          <TableCell>{e.experiment_num}</TableCell>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {e.run_id?.slice(0, 8)}
                          </TableCell>
                          <TableCell sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{e.aqs?.toFixed(4)}</TableCell>
                          <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{e.detection_score?.toFixed(3)}</TableCell>
                          <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{e.fp_penalty?.toFixed(3)}</TableCell>
                          <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{e.stability_bonus?.toFixed(3)}</TableCell>
                          <TableCell>
                            {e.accepted ? (
                              <CheckCircleIcon sx={{ fontSize: 16, color: 'success.main' }} />
                            ) : (
                              <CancelIcon sx={{ fontSize: 16, color: 'text.disabled' }} />
                            )}
                          </TableCell>
                          <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.8rem' }}>
                            {e.reason || '-'}
                          </TableCell>
                          <TableCell>{e.elapsed_seconds ? `${e.elapsed_seconds.toFixed(0)}s` : '-'}</TableCell>
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
    </Box>
  );
}
