import { Box, Button, Grid, LinearProgress, Stack, Typography } from '@mui/material';
import { useApiQuery } from '../hooks';
import { useToast } from '../hooks/useToast';
import { PageHeader, DataCard, ErrorDisplay, EmptyState, AppToast } from '../components';
import type { MLFPBreakdownData } from '../types';

function BarRow({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ py: 0.75, px: 1, borderRadius: 1, transition: 'background-color 0.15s', '&:hover': { bgcolor: 'action.hover' } }}>
      <Typography variant="body2" sx={{ minWidth: 200, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 13 }}>
        {label}
      </Typography>
      <Box sx={{ flexGrow: 1 }}>
        <LinearProgress variant="determinate" value={pct} sx={{ height: 10, borderRadius: 5, '& .MuiLinearProgress-bar': { backgroundColor: color, borderRadius: 5 } }} />
      </Box>
      <Typography variant="body2" sx={{ minWidth: 40, textAlign: 'right', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{value}</Typography>
    </Stack>
  );
}

export function MLFPBreakdown() {
  const { data, loading, error, refetch } = useApiQuery<MLFPBreakdownData>('/ml/metrics/fp_breakdown');

  const { toast, showToast, closeToast } = useToast();
  const pluginEntries = data?.fp_by_plugin ? Object.entries(data.fp_by_plugin).sort(([, a], [, b]) => b - a) : [];
  const categoryEntries = data?.fp_by_category ? Object.entries(data.fp_by_category).sort(([, a], [, b]) => b - a) : [];
  const pluginMax = pluginEntries.length > 0 ? Math.max(...pluginEntries.map(([, v]) => v)) : 1;
  const categoryMax = categoryEntries.length > 0 ? Math.max(...categoryEntries.map(([, v]) => v)) : 1;
  const pluginTotal = pluginEntries.reduce((s, [, v]) => s + v, 0);
  const categoryTotal = categoryEntries.reduce((s, [, v]) => s + v, 0);

  function exportCsv() {
    try {
      const rows: string[] = ['type,key,value'];
      pluginEntries.forEach(([k, v]) => rows.push(`plugin,"${k}",${v}`));
      categoryEntries.forEach(([k, v]) => rows.push(`category,"${k}",${v}`));
      const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `fp_breakdown_${Date.now()}.csv`; a.click(); URL.revokeObjectURL(url);
      showToast('CSV exported');
    } catch { showToast('Export failed', 'error'); }
  }

  return (
    <Box>
      <PageHeader title="ML False-Positive Breakdown" subtitle="Analyze false-positive distribution across plugins and categories" actions={<Button variant="outlined" onClick={exportCsv} disabled={!data}>Export CSV</Button>} />
      <Stack spacing={2}>
        <ErrorDisplay error={error} onRetry={refetch} />

        {/* Summary */}
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <DataCard title="Total FPs by Plugin" loading={loading}>
              <Typography variant="h3" sx={{ textAlign: 'center', fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: 'error.main', py: 1 }}>{pluginTotal}</Typography>
            </DataCard>
          </Grid>
          <Grid item xs={12} sm={6}>
            <DataCard title="Total FPs by Category" loading={loading}>
              <Typography variant="h3" sx={{ textAlign: 'center', fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: 'warning.main', py: 1 }}>{categoryTotal}</Typography>
            </DataCard>
          </Grid>
        </Grid>

        {/* FP by Plugin */}
        <DataCard title="FP by Plugin" loading={loading}>
          {pluginEntries.length > 0 ? (
            <Box>
              {pluginEntries.map(([name, count]) => (
                <BarRow key={name} label={name} value={count} max={pluginMax} color="error.main" />
              ))}
            </Box>
          ) : <EmptyState message="No plugin FP data available" />}
        </DataCard>

        {/* FP by Category */}
        <DataCard title="FP by Category" loading={loading}>
          {categoryEntries.length > 0 ? (
            <Box>
              {categoryEntries.map(([name, count]) => (
                <BarRow key={name} label={name} value={count} max={categoryMax} color="warning.main" />
              ))}
            </Box>
          ) : <EmptyState message="No category FP data available" />}
        </DataCard>
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
