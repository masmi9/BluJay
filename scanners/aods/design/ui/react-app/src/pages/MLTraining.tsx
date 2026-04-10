import { useState } from 'react';
import { Box, Button, Chip, Stack, Typography } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { secureFetch } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, ErrorDisplay, StatusChip, EmptyState } from '../components';
import type { MLCalibrationSummary, MLTrainingStatus } from '../types';

function metricColor(value: number, good: number, warn: number): 'success.main' | 'warning.main' | 'error.main' {
  if (value < good) return 'success.main';
  if (value < warn) return 'warning.main';
  return 'error.main';
}

export function MLTraining() {
  const { data: summary, error: summaryErr } = useApiQuery<MLCalibrationSummary>('/ml/calibration/summary');
  const { data: status, loading, error: statusErr, refetch } = useApiQuery<MLTrainingStatus>('/ml/training/status');
  const [error, setError] = useState<string | null>(null);
  const queryError = summaryErr || statusErr;

  async function runCalibration() {
    setError(null);
    try {
      const r = await secureFetch('/ml/training/run_calibration', { method: 'POST' });
      if (!r.ok) throw new Error(String(r.status));
      refetch();
    } catch (e: unknown) { setError((e as Error)?.message || 'Calibration failed'); }
  }

  return (
    <Box>
      <PageHeader title="ML Training & Calibration" subtitle="Train models and calibrate confidence scores" actions={<Button variant="contained" onClick={runCalibration}>Run Calibration</Button>} />
      <Stack spacing={2}>
        <ErrorDisplay error={error || queryError} onRetry={refetch} />

        {/* Training Status */}
        <DataCard title="Training Status" loading={loading}>
          {status ? (
            <Stack spacing={2}>
              <Stack direction="row" spacing={2} alignItems="center">
                <StatusChip status={String(status.status || 'unknown')} />
                {status.last_run && (
                  <Typography variant="body2" color="text.secondary">
                    Last run: {formatDateTime(status.last_run)}
                  </Typography>
                )}
              </Stack>
              {status.models && (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {(status.models as string[]).map((m: string) => (
                    <Chip key={m} label={m} size="small" variant="outlined" />
                  ))}
                </Stack>
              )}
            </Stack>
          ) : <EmptyState message="No status available" />}
        </DataCard>

        {/* Calibration Summary */}
        <DataCard title="Calibration Summary">
          {summary ? (
            <Stack direction="row" spacing={4} flexWrap="wrap" useFlexGap justifyContent="center">
              <Box sx={{ textAlign: 'center', minWidth: 120, py: 1 }}>
                {summary.calibrated
                  ? <CheckCircleIcon color="success" sx={{ fontSize: 44 }} />
                  : <CancelIcon color="error" sx={{ fontSize: 44 }} />}
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, fontWeight: 500 }}>Calibrated</Typography>
              </Box>
              <Box sx={{ textAlign: 'center', minWidth: 120, py: 1 }}>
                <Typography variant="h4" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: metricColor(summary.brier_score ?? 1, 0.1, 0.2) }}>
                  {summary.brier_score?.toFixed?.(3) ?? 'N/A'}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>Brier Score</Typography>
              </Box>
              <Box sx={{ textAlign: 'center', minWidth: 120, py: 1 }}>
                <Typography variant="h4" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: metricColor(summary.ece ?? 1, 0.1, 0.2) }}>
                  {summary.ece?.toFixed?.(3) ?? 'N/A'}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>ECE</Typography>
              </Box>
            </Stack>
          ) : <EmptyState message="No calibration data" />}
        </DataCard>
      </Stack>
    </Box>
  );
}
