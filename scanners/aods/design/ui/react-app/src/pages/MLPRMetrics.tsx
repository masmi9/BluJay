import { Box, Grid, LinearProgress, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { useApiQuery } from '../hooks';
import { formatDateTime } from '../lib/format';
import { PageHeader, DataCard, ErrorDisplay, StatusChip } from '../components';
import type { MLPRMetricsData } from '../types';

function bestF1Point(points: { t: number; P: number; R: number; F1: number }[]) {
  if (!points || points.length === 0) return null;
  return points.reduce((best, pt) => (pt.F1 > best.F1 ? pt : best), points[0]);
}

export function MLPRMetrics() {
  const { data, loading, error, refetch } = useApiQuery<MLPRMetricsData>('/ml/metrics/pr');

  const precision = data?.precision;
  const recall = data?.recall;
  const f1 = data?.f1;

  const categoryEntries = data?.per_category
    ? Object.entries(data.per_category).sort(([a], [b]) => a.localeCompare(b))
    : [];

  const pluginEntries = data?.per_plugin
    ? Object.entries(data.per_plugin).sort(([a], [b]) => a.localeCompare(b))
    : [];

  return (
    <Box>
      <PageHeader title="ML Precision/Recall Metrics" subtitle="Evaluate model performance across categories and plugins" />
      {data?.generated_at && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
          Generated: {formatDateTime(data.generated_at)}
        </Typography>
      )}
      <Stack spacing={2}>
        <ErrorDisplay error={error} onRetry={refetch} />

        {/* Summary Cards */}
        <Grid container spacing={2}>
          {([
            { title: 'Precision', value: precision, color: 'success.main' },
            { title: 'Recall', value: recall, color: 'info.main' },
            { title: 'F1 Score', value: f1, color: 'primary.main' },
          ] as const).map(({ title, value, color }) => (
            <Grid item xs={12} md={4} key={title}>
              <DataCard title={title} loading={loading}>
                <Box sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h3" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', color }}>
                    {value != null ? value.toFixed(2) : 'N/A'}
                  </Typography>
                  {value != null && (
                    <LinearProgress
                      variant="determinate"
                      value={Math.min(value * 100, 100)}
                      color={value >= 0.9 ? 'success' : value >= 0.7 ? 'warning' : 'error'}
                      sx={{ height: 6, borderRadius: 3, mt: 1.5, mx: 'auto', maxWidth: 120 }}
                    />
                  )}
                </Box>
              </DataCard>
            </Grid>
          ))}
        </Grid>

        {/* Visual Comparison */}
        {data && (
          <DataCard title="Visual Comparison">
            <Stack spacing={2}>
              <Box>
                <Stack direction="row" justifyContent="space-between">
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>Precision</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{precision != null ? (precision * 100).toFixed(1) + '%' : ''}</Typography>
                </Stack>
                <LinearProgress variant="determinate" value={precision != null ? precision * 100 : 0} color="success" sx={{ height: 10, borderRadius: 5 }} />
              </Box>
              <Box>
                <Stack direction="row" justifyContent="space-between">
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>Recall</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{recall != null ? (recall * 100).toFixed(1) + '%' : ''}</Typography>
                </Stack>
                <LinearProgress variant="determinate" value={recall != null ? recall * 100 : 0} color="info" sx={{ height: 10, borderRadius: 5 }} />
              </Box>
            </Stack>
          </DataCard>
        )}

        {/* Detail Table */}
        {data && (
          <DataCard title="Detail">
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Metric</TableCell>
                    <TableCell align="right">Value</TableCell>
                    <TableCell align="center">Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow hover>
                    <TableCell>Precision</TableCell>
                    <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{precision?.toFixed(4) ?? 'N/A'}</TableCell>
                    <TableCell align="center"><StatusChip status={precision != null && precision >= 0.8 ? 'PASS' : 'WARN'} /></TableCell>
                  </TableRow>
                  <TableRow hover>
                    <TableCell>Recall</TableCell>
                    <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{recall?.toFixed(4) ?? 'N/A'}</TableCell>
                    <TableCell align="center"><StatusChip status={recall != null && recall >= 0.8 ? 'PASS' : 'WARN'} /></TableCell>
                  </TableRow>
                  <TableRow hover>
                    <TableCell>F1</TableCell>
                    <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{f1?.toFixed(4) ?? 'N/A'}</TableCell>
                    <TableCell align="center"><StatusChip status={f1 != null && f1 >= 0.8 ? 'PASS' : 'WARN'} /></TableCell>
                  </TableRow>
                  {data.fpr != null && (
                    <TableRow>
                      <TableCell>False Positive Rate</TableCell>
                      <TableCell align="right">{data.fpr.toFixed(4)}</TableCell>
                      <TableCell align="center"><StatusChip status={data.fpr <= 0.05 ? 'PASS' : 'WARN'} /></TableCell>
                    </TableRow>
                  )}
                  {data.ece != null && (
                    <TableRow>
                      <TableCell>Expected Calibration Error</TableCell>
                      <TableCell align="right">{data.ece.toFixed(4)}</TableCell>
                      <TableCell align="center"><StatusChip status={data.ece <= 0.05 ? 'PASS' : 'WARN'} /></TableCell>
                    </TableRow>
                  )}
                  {data.dataset_size != null && (
                    <TableRow>
                      <TableCell>Dataset Size</TableCell>
                      <TableCell align="right">{data.dataset_size.toLocaleString()}</TableCell>
                      <TableCell />
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </DataCard>
        )}

        {/* Per-Category Breakdown */}
        {categoryEntries.length > 0 && (
          <DataCard title="Per-Category Breakdown">
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Category</TableCell>
                    <TableCell align="right">Samples</TableCell>
                    <TableCell align="right">Best Threshold</TableCell>
                    <TableCell align="right">Precision</TableCell>
                    <TableCell align="right">Recall</TableCell>
                    <TableCell align="right">F1</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {categoryEntries.map(([cat, catData]) => {
                    const best = bestF1Point(catData.points);
                    return (
                      <TableRow key={cat} hover>
                        <TableCell>{cat}</TableCell>
                        <TableCell align="right">{catData.count ?? catData.points.length}</TableCell>
                        <TableCell align="right">{best?.t.toFixed(2) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.P.toFixed(4) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.R.toFixed(4) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.F1.toFixed(4) ?? 'N/A'}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </DataCard>
        )}

        {/* Per-Plugin Breakdown */}
        {pluginEntries.length > 0 && (
          <DataCard title="Per-Plugin Breakdown">
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Plugin</TableCell>
                    <TableCell align="right">Samples</TableCell>
                    <TableCell align="right">Best Threshold</TableCell>
                    <TableCell align="right">Precision</TableCell>
                    <TableCell align="right">Recall</TableCell>
                    <TableCell align="right">F1</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pluginEntries.map(([plg, plgData]) => {
                    const best = bestF1Point(plgData.points);
                    return (
                      <TableRow key={plg} hover>
                        <TableCell>{plg}</TableCell>
                        <TableCell align="right">{plgData.count ?? plgData.points.length}</TableCell>
                        <TableCell align="right">{best?.t.toFixed(2) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.P.toFixed(4) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.R.toFixed(4) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{best?.F1.toFixed(4) ?? 'N/A'}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </DataCard>
        )}
      </Stack>
    </Box>
  );
}
