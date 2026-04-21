import { useCallback } from 'react';
import {
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { Link } from 'react-router-dom';
import RefreshIcon from '@mui/icons-material/Refresh';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ScienceOutlinedIcon from '@mui/icons-material/ScienceOutlined';
import TuneOutlinedIcon from '@mui/icons-material/TuneOutlined';
import BarChartOutlinedIcon from '@mui/icons-material/BarChartOutlined';
import SchoolOutlinedIcon from '@mui/icons-material/SchoolOutlined';
import { useApiQuery } from '../hooks';
import { formatRelativeTime, formatDateTime } from '../lib/format';
import { PageHeader, DataCard, ErrorDisplay, StatusChip, EmptyState } from '../components';
import type { MLAccuracySummary, MLThresholdsData, MLPRMetricsData } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function thresholdColor(value: number, threshold: number): 'success' | 'warning' | 'error' {
  if (value >= threshold) return 'success';
  if (value >= threshold * 0.9) return 'warning';
  return 'error';
}

function metricColor(value: number | undefined | null): string {
  if (value == null) return 'text.primary';
  if (value >= 0.9) return 'success.main';
  if (value >= 0.8) return 'text.primary';
  if (value >= 0.7) return 'warning.main';
  return 'error.main';
}

/** Color for a "lower is better" metric (e.g. FP threshold). */
function fpHealthColor(val: number | undefined | null): string {
  if (val == null) return 'text.disabled';
  if (val <= 0.15) return 'success.main';
  if (val <= 0.25) return 'warning.main';
  return 'error.main';
}

/** Color for a "higher is better" metric (e.g. confidence min). */
function confHealthColor(val: number | undefined | null): string {
  if (val == null) return 'text.disabled';
  if (val >= 0.6) return 'success.main';
  if (val >= 0.4) return 'warning.main';
  return 'error.main';
}

function humanizeKey(key: string): string {
  return key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatValue(val: unknown): string {
  if (val == null) return 'N/A';
  if (typeof val === 'number') return val.toLocaleString();
  if (typeof val === 'boolean') return val ? 'Yes' : 'No';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

/** Section label reusable across cards. */
function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption"
      sx={{ fontWeight: 600, fontSize: 11, letterSpacing: '0.05em', textTransform: 'uppercase', color: 'text.disabled', mb: 1, display: 'block' }}
    >
      {children}
    </Typography>
  );
}

/** Format a relative time string from an ISO timestamp. */

/** Small colored dot indicating health status. */
function HealthDot({ color }: { color: string }) {
  return (
    <Box
      aria-hidden="true"
      sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: color, flexShrink: 0, boxShadow: `0 0 0 2px color-mix(in srgb, currentColor 10%, transparent)` }}
    />
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

type MLAnalyticsSummaryResponse = {
  source: string;
  summary: Record<string, unknown>;
};

/** Accuracy metric row: label + value + threshold + progress bar with marker + status chip. */
function AccuracyMetricRow({
  label,
  value,
  threshold,
}: {
  label: string;
  value: number | undefined | null;
  threshold: number;
}) {
  const pct = value != null ? Math.min(value * 100, 100) : 0;
  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1.5} alignItems="baseline">
          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13 }}>{label}</Typography>
          <Typography variant="h6" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 700, color: metricColor(value), fontSize: 18, lineHeight: 1 }}>
            {value?.toFixed?.(3) ?? 'N/A'}
          </Typography>
        </Stack>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums', fontSize: 11 }}>
            min {threshold}
          </Typography>
          {value != null && <StatusChip status={value >= threshold ? 'PASS' : 'FAIL'} />}
        </Stack>
      </Stack>
      {value != null && (
        <Stack direction="row" spacing={1} alignItems="center">
          <Box sx={{ flex: 1, position: 'relative' }}>
            <LinearProgress
              variant="determinate"
              value={pct}
              color={thresholdColor(value, threshold)}
              sx={{ height: 10, borderRadius: 5 }}
            />
            <Box
              aria-hidden="true"
              sx={{
                position: 'absolute',
                left: `${threshold * 100}%`,
                top: -2,
                bottom: -2,
                width: 2,
                bgcolor: 'text.primary',
                borderRadius: 0.5,
                opacity: 0.5,
              }}
            />
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums', fontSize: 11, minWidth: 32, textAlign: 'right', fontWeight: 600 }}>
            {pct.toFixed(0)}%
          </Typography>
        </Stack>
      )}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function MLOverview() {
  const { data: acc, loading: accLoading, error: accErr, refetch: refetchAcc } = useApiQuery<MLAccuracySummary>('/ml/metrics/detection_accuracy/summary');
  const { data: thr, loading: thrLoading, error: thrErr, refetch: refetchThr } = useApiQuery<MLThresholdsData>('/ml/thresholds');
  const { data: pr, loading: prLoading, error: prErr, refetch: refetchPr } = useApiQuery<MLPRMetricsData>('/ml/metrics/pr');
  const { data: analytics, loading: analyticsLoading, error: analyticsErr, refetch: refetchAnalytics } = useApiQuery<MLAnalyticsSummaryResponse>('/ml/analytics/summary');

  const loading = accLoading || thrLoading || prLoading || analyticsLoading;
  const queryError = accErr || thrErr || prErr || analyticsErr;

  const precision = acc?.precision ?? pr?.precision;
  const recall = acc?.recall ?? pr?.recall;
  const minP = acc?.min_precision ?? 0.85;
  const minR = acc?.min_recall ?? 0.80;

  const handleRefresh = useCallback(() => {
    refetchAcc(); refetchThr(); refetchPr(); refetchAnalytics();
  }, [refetchAcc, refetchThr, refetchPr, refetchAnalytics]);

  const f1Derived = precision != null && recall != null && (precision + recall) > 0
    ? (2 * precision * recall) / (precision + recall) : null;

  const thrPluginCount = thr?.plugins ? Object.keys(thr.plugins).length : 0;
  const thrCategoryCount = thr?.categories ? Object.keys(thr.categories).length : 0;

  return (
    <Box sx={{ width: '100%', maxWidth: 1080, mx: 'auto' }}>
      <PageHeader
        title="ML Overview"
        subtitle="Model metrics, thresholds, and learning analytics"
        actions={
          <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
            {!accLoading && acc?.status && (
              <Tooltip title="Overall detection accuracy status">
                <Box><StatusChip status={String(acc.status)} /></Box>
              </Tooltip>
            )}
            <Tooltip title="Refresh all data">
              <span>
                <IconButton size="small" aria-label="Refresh ML data" onClick={handleRefresh} disabled={loading}>
                  <RefreshIcon sx={{ fontSize: 18, transition: 'transform 0.3s', ...(loading && { animation: 'spin 1s linear infinite', '@keyframes spin': { '100%': { transform: 'rotate(360deg)' } } }) }} />
                </IconButton>
              </span>
            </Tooltip>
          </Stack>
        }
      />
      <Stack spacing={2}>
        <ErrorDisplay error={queryError} onRetry={handleRefresh} />

        {/* ---- Row 1: Detection Accuracy + Active Thresholds ---- */}
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '7fr 5fr' }, gap: 2, alignItems: 'stretch' }}>
          <Box sx={{ minWidth: 0 }}>
            <DataCard title="Detection Accuracy" loading={accLoading}>
              {acc ? (
                <Stack spacing={2.5}>
                  <AccuracyMetricRow label="Precision" value={precision} threshold={minP} />
                  <AccuracyMetricRow label="Recall" value={recall} threshold={minR} />
                  {f1Derived != null && (
                    <>
                      <Divider />
                      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ py: 0.5 }}>
                        <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.secondary' }}>F1 Score</Typography>
                        <Chip
                          size="small"
                          label={f1Derived.toFixed(3)}
                          color={f1Derived >= 0.9 ? 'success' : f1Derived >= 0.7 ? 'warning' : 'error'}
                          sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', fontSize: 13 }}
                        />
                      </Stack>
                    </>
                  )}
                  {acc.pass_rate != null && (
                    <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums', textAlign: 'right' }}>
                      Pass rate: {(acc.pass_rate > 1 ? acc.pass_rate : acc.pass_rate * 100).toFixed(0)}%
                      {acc.failed != null && ` · ${acc.failed} failed`}
                    </Typography>
                  )}
                </Stack>
              ) : !accLoading && (
                <EmptyState message="No summary available" icon={ScienceOutlinedIcon} action={{ label: 'Refresh', onClick: handleRefresh }} />
              )}
            </DataCard>
          </Box>

          <Box sx={{ minWidth: 0 }}>
            <DataCard
              title="Active Thresholds"
              loading={thrLoading}
              actions={
                <Button
                  size="small"
                  component={Link}
                  to="/ml/thresholds"
                  endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  Manage
                </Button>
              }
            >
              {thr ? (
                <Stack spacing={1.5}>
                  <Stack spacing={0}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ py: 1, px: 1, borderRadius: 1, '&:hover': { bgcolor: 'action.hover' }, transition: 'background-color 0.15s' }}>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13 }}>FP Threshold</Typography>
                      <Stack direction="row" spacing={0.75} alignItems="center">
                        <HealthDot color={fpHealthColor(thr.fp_threshold)} />
                        <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 700, fontSize: 14 }}>{thr.fp_threshold ?? 'N/A'}</Typography>
                      </Stack>
                    </Stack>
                    <Divider />
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ py: 1, px: 1, borderRadius: 1, '&:hover': { bgcolor: 'action.hover' }, transition: 'background-color 0.15s' }}>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13 }}>Confidence Min</Typography>
                      <Stack direction="row" spacing={0.75} alignItems="center">
                        <HealthDot color={confHealthColor(thr.confidence_min)} />
                        <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 700, fontSize: 14 }}>{thr.confidence_min ?? 'N/A'}</Typography>
                      </Stack>
                    </Stack>
                  </Stack>

                  {thr.severity_weights && (
                    <>
                      <Divider />
                      <Box>
                        <SectionLabel>Severity Weights</SectionLabel>
                        <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                          {Object.entries(thr.severity_weights).map(([sev, w]) => (
                            <Chip
                              key={sev}
                              size="small"
                              label={`${sev}: ${w}`}
                              color={sev === 'CRITICAL' || sev === 'HIGH' ? 'error' : sev === 'MEDIUM' ? 'warning' : 'default'}
                              variant="outlined"
                            />
                          ))}
                        </Stack>
                      </Box>
                    </>
                  )}

                  {(thrPluginCount > 0 || thrCategoryCount > 0) && (
                    <>
                      <Divider />
                      <Stack direction="row" spacing={1} alignItems="center">
                        {thrPluginCount > 0 && (
                          <Tooltip title={`${thrPluginCount} plugin-level threshold override(s)`} arrow>
                            <Chip size="small" label={`${thrPluginCount} plugin override${thrPluginCount !== 1 ? 's' : ''}`} variant="outlined" sx={{ fontSize: 11 }} />
                          </Tooltip>
                        )}
                        {thrCategoryCount > 0 && (
                          <Tooltip title={`${thrCategoryCount} category-level threshold override(s)`} arrow>
                            <Chip size="small" label={`${thrCategoryCount} category override${thrCategoryCount !== 1 ? 's' : ''}`} variant="outlined" sx={{ fontSize: 11 }} />
                          </Tooltip>
                        )}
                      </Stack>
                    </>
                  )}
                </Stack>
              ) : !thrLoading && (
                <EmptyState message="No thresholds" icon={TuneOutlinedIcon} action={{ label: 'Refresh', onClick: handleRefresh }} />
              )}
            </DataCard>
          </Box>
        </Box>

        {/* ---- Row 2: PR Metrics + Learning Analytics ---- */}
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '7fr 5fr' }, gap: 2, alignItems: 'stretch' }}>
          <Box sx={{ minWidth: 0 }}>
            <DataCard
              title="PR Metrics"
              loading={prLoading}
              actions={
                <Button
                  size="small"
                  component={Link}
                  to="/ml/metrics"
                  endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  Details
                </Button>
              }
            >
              {pr ? (
                <Stack spacing={2}>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                    {([
                      ['Precision', pr.precision, 'success.main', false],
                      ['Recall', pr.recall, 'info.main', false],
                      ['F1 Score', pr.f1, 'primary.main', true],
                    ] as const).map(([label, value, fallbackColor, isComposite]) => (
                      <Paper
                        key={label}
                        variant="outlined"
                        sx={{
                          flex: 1,
                          minWidth: 0,
                          textAlign: 'center',
                          p: 2.5,
                          borderRadius: 2,
                          transition: 'border-color 0.2s, box-shadow 0.2s, transform 0.15s',
                          '&:hover': { borderColor: 'primary.main', transform: 'translateY(-1px)', boxShadow: 1 },
                          ...(isComposite && {
                            borderColor: 'primary.light',
                            bgcolor: 'action.hover',
                          }),
                        }}
                      >
                        <Typography
                          variant="h4"
                          sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: value != null ? metricColor(value) : fallbackColor, mb: 0.5 }}
                        >
                          {value?.toFixed?.(2) ?? 'N/A'}
                        </Typography>
                        <LinearProgress
                          variant="determinate"
                          value={value != null ? Math.min(value * 100, 100) : 0}
                          color={value != null && value >= 0.9 ? 'success' : value != null && value >= 0.7 ? 'warning' : 'inherit'}
                          sx={{ height: 6, borderRadius: 3, mt: 0.5, mb: 0.75, opacity: value != null ? 1 : 0.15 }}
                        />
                        <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>
                          {label}
                          {isComposite && (
                            <Typography component="span" sx={{ fontSize: 10, ml: 0.5, color: 'text.disabled' }}>(composite)</Typography>
                          )}
                        </Typography>
                      </Paper>
                    ))}
                  </Stack>

                  {/* Supplementary info chips: dataset size, ECE, FPR, freshness */}
                  <Stack direction="row" spacing={1} justifyContent="center" alignItems="center" flexWrap="wrap" useFlexGap>
                    {pr.dataset_size != null && (
                      <Chip size="small" variant="outlined" label={`Dataset: ${pr.dataset_size.toLocaleString()} samples`} sx={{ fontSize: 11, fontVariantNumeric: 'tabular-nums' }} />
                    )}
                    {pr.ece != null && (
                      <Tooltip title="Expected Calibration Error - lower is better" arrow>
                        <Chip
                          size="small"
                          variant="outlined"
                          label={`ECE: ${pr.ece.toFixed(3)}`}
                          color={pr.ece <= 0.05 ? 'success' : pr.ece <= 0.10 ? 'warning' : 'error'}
                          sx={{ fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                        />
                      </Tooltip>
                    )}
                    {pr.fpr != null && (
                      <Tooltip title="False Positive Rate - lower is better" arrow>
                        <Chip
                          size="small"
                          variant="outlined"
                          label={`FPR: ${pr.fpr.toFixed(3)}`}
                          color={pr.fpr <= 0.05 ? 'success' : pr.fpr <= 0.15 ? 'warning' : 'error'}
                          sx={{ fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                        />
                      </Tooltip>
                    )}
                    {pr.generated_at && (
                      <Tooltip title={`Generated: ${formatDateTime(pr.generated_at)}`} arrow>
                        <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums', fontSize: 11 }}>
                          {formatRelativeTime(pr.generated_at)}
                        </Typography>
                      </Tooltip>
                    )}
                  </Stack>
                </Stack>
              ) : !prLoading && (
                <EmptyState message="No metrics" icon={BarChartOutlinedIcon} action={{ label: 'Refresh', onClick: handleRefresh }} />
              )}
            </DataCard>
          </Box>

          <Box sx={{ minWidth: 0 }}>
            <DataCard
              title="Learning Analytics"
              loading={analyticsLoading}
              actions={analytics ? <Chip size="small" label={`Source: ${analytics.source}`} variant="outlined" /> : undefined}
            >
              {analytics?.summary ? (
                <Stack spacing={0}>
                  {Object.entries(analytics.summary).map(([key, val], idx) => (
                    <Stack
                      key={key}
                      direction="row"
                      justifyContent="space-between"
                      alignItems="center"
                      sx={{
                        py: 0.75,
                        px: 1.5,
                        borderRadius: 1,
                        bgcolor: idx % 2 === 1 ? 'action.hover' : 'transparent',
                        transition: 'background-color 0.15s',
                        '&:hover': { bgcolor: 'action.selected' },
                      }}
                    >
                      <Typography variant="body2" sx={{ fontWeight: 500, flexShrink: 0, fontSize: 13 }}>{humanizeKey(key)}</Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          fontVariantNumeric: 'tabular-nums',
                          fontWeight: typeof val === 'number' ? 700 : 400,
                          color: typeof val === 'number' ? 'text.primary' : 'text.secondary',
                          minWidth: 0,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          ml: 1,
                          fontSize: 13,
                        }}
                      >
                        {formatValue(val)}
                      </Typography>
                    </Stack>
                  ))}
                </Stack>
              ) : analyticsErr ? (
                <EmptyState message="Analytics not available" icon={SchoolOutlinedIcon} action={{ label: 'Retry', onClick: handleRefresh }} />
              ) : !analyticsLoading && (
                <EmptyState message="No analytics data" icon={SchoolOutlinedIcon} action={{ label: 'Refresh', onClick: handleRefresh }} />
              )}
            </DataCard>
          </Box>
        </Box>

        {/* ---- Explore: quick navigation to ML sub-pages ---- */}
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography
              variant="caption"
              sx={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'text.disabled', mr: 1 }}
            >
              Explore
            </Typography>
            {[
              { label: 'Thresholds', to: '/ml/thresholds', icon: TuneOutlinedIcon, tip: 'Configure FP and confidence thresholds' },
              { label: 'Metrics (PR)', to: '/ml/metrics', icon: BarChartOutlinedIcon, tip: 'Detailed precision, recall, and per-category metrics' },
              { label: 'FP Breakdown', to: '/ml/fp-breakdown', icon: ScienceOutlinedIcon, tip: 'False positive distribution by plugin and category' },
              { label: 'Training', to: '/ml/training', icon: SchoolOutlinedIcon, tip: 'Model training status and calibration' },
            ].map(({ label, to, icon: Icon, tip }) => (
              <Tooltip key={to} title={tip} arrow>
                <Button
                  size="small"
                  variant="outlined"
                  component={Link}
                  to={to}
                  startIcon={<Icon sx={{ fontSize: '14px !important' }} />}
                  sx={{ textTransform: 'none', fontSize: 12 }}
                >
                  {label}
                </Button>
              </Tooltip>
            ))}
          </Stack>
        </Paper>
      </Stack>
    </Box>
  );
}
