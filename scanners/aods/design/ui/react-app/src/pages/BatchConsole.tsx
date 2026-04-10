import { useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { emitAudit } from '../utils/audit';
import { AODSApiClient } from '../services/api';
import { Box, Button, Chip, Collapse, FormControl, Grid, InputLabel, LinearProgress, MenuItem, Select, Slider, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { getApiBase, secureFetch } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useSseStream } from '../hooks/useSseStream';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, ErrorDisplay, StatusChip, ConfirmDialog } from '../components';
import type { BatchStatus } from '../types';

export function BatchConsole() {
  const auth = useAuth();
  const api = useMemo(() => new AODSApiClient(), []);
  const [manifest, setManifest] = useState('');
  const [apkList, setApkList] = useState('');
  const [profile, setProfile] = useState('lightning');
  const [concurrency, setConcurrency] = useState(4);
  const [outDir, setOutDir] = useState('artifacts/scans/lightning');
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<BatchStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sseUrl, setSseUrl] = useState<string | null>(null);
  const [showStdout, setShowStdout] = useState(false);
  const [showStderr, setShowStderr] = useState(false);
  const [cancelDialog, setCancelDialog] = useState(false);
  const startTimeRef = useRef<number | null>(null);

  const { data: jobHistoryData } = useApiQuery<{ items?: any[] }>('/jobs/history', { silentError: true });
  const jobHistory = jobHistoryData?.items ?? [];

  const canStart = !!(manifest.trim() || apkList.trim());

  async function start() {
    if (!canStart) return;
    setError(null);
    try {
      const r = await secureFetch(`/batch/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest: manifest || undefined, apkList: apkList || undefined, profile, concurrency, outDir })
      });
      if (!r.ok) throw new Error(String(r.status));
      const data = await r.json();
      setJobId(data.jobId);
      setStatus({ status: data.status });
      startTimeRef.current = Date.now();
      emitAudit('start_batch', auth.roles.includes('admin') ? 'admin' : 'user', manifest || apkList, { jobId: data.jobId, profile, concurrency });
    } catch (e: unknown) {
      setError((e as Error)?.message || 'Failed to start batch job');
    }
  }

  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const jid = params.get('jobId');
      if (jid) {
        setJobId(jid);
        setStatus({ status: 'queued' });
        startTimeRef.current = Date.now();
      }
    } catch {}
  }, []);

  useEffect(() => {
    if (!jobId) { setSseUrl(null); return; }
    let cancelled = false;
    (async () => {
      try {
        const base = await getApiBase();
        const tokenParam = auth.token ? `?token=${encodeURIComponent(auth.token)}` : '';
        if (!cancelled) setSseUrl(`${base}/batch/${encodeURIComponent(jobId)}/status/stream${tokenParam}`);
      } catch {}
    })();
    return () => { cancelled = true; };
  }, [jobId, auth.token]);

  const { error: sseError } = useSseStream({
    url: sseUrl,
    onMessage: (d: Record<string, unknown>) => { setStatus(s => ({ ...(s || {}), ...d } as BatchStatus)); },
  });

  const isRunning = status?.status === 'running' || status?.status === 'queued';

  // Estimated time remaining
  const eta = useMemo(() => {
    if (!isRunning || !startTimeRef.current || !status?.progress) return null;
    const elapsed = Date.now() - startTimeRef.current;
    const pct = status.progress;
    if (pct <= 0) return null;
    const totalEstimated = elapsed / pct;
    const remaining = totalEstimated - elapsed;
    if (remaining < 1000) return 'Almost done';
    const mins = Math.ceil(remaining / 60000);
    return `~${mins} min remaining`;
  }, [isRunning, status?.progress]);

  async function handleCancel() {
    if (!jobId) return;
    setCancelDialog(false);
    try {
      const res = await api.cancelBatch(jobId);
      setStatus(s => ({ ...(s || {}), status: res.status || 'cancelled' } as BatchStatus));
      emitAudit('cancel_batch', auth.roles.includes('admin') ? 'admin' : 'user', jobId);
    } catch (e: unknown) {
      setError((e as Error)?.message || 'Failed to cancel job');
    }
  }

  return (
    <Box>
      <PageHeader title="Batch Scanning Console" subtitle="Run parallel APK scans with batch configuration" />
      <Stack spacing={2}>
        <ErrorDisplay error={error} onRetry={start} />
        <ErrorDisplay error={sseError} severity="warning" />

        {/* Job Configuration */}
        <DataCard title="Job Configuration">
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <TextField fullWidth label="manifest.json path" value={manifest} onChange={e => setManifest(e.target.value)} helperText="Path to batch manifest file" />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField fullWidth label="apk-list path" value={apkList} onChange={e => setApkList(e.target.value)} helperText="Path to APK list file" />
            </Grid>
            <Grid item xs={12} md={4}>
              <FormControl fullWidth>
                <InputLabel id="profile-label">Profile</InputLabel>
                <Select labelId="profile-label" label="Profile" value={profile} onChange={e => setProfile(String(e.target.value))}>
                  <MenuItem value="lightning">lightning</MenuItem>
                  <MenuItem value="fast">fast</MenuItem>
                  <MenuItem value="standard">standard</MenuItem>
                  <MenuItem value="deep">deep</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="body2" gutterBottom>Concurrency: <Typography component="span" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>{concurrency}</Typography></Typography>
              <Slider aria-label="Concurrency" value={concurrency} onChange={(_e, v) => setConcurrency(v as number)} min={1} max={16} step={1} marks={[{ value: 1, label: '1' }, { value: 8, label: '8' }, { value: 16, label: '16' }]} valueLabelDisplay="auto" />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField fullWidth label="Output directory" value={outDir} onChange={e => setOutDir(e.target.value)} />
            </Grid>
          </Grid>
          <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
            <Button variant="contained" onClick={start} disabled={!canStart}>Start Batch</Button>
            <Button variant="outlined" onClick={() => setCancelDialog(true)} disabled={!jobId || !isRunning}>Cancel Job</Button>
          </Stack>
          {!canStart && <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>Provide a manifest or APK list path to start</Typography>}
        </DataCard>

        {/* Job Status */}
        {(jobId || status) && (
          <DataCard title="Job Status">
            <Stack spacing={2}>
              <Stack direction="row" spacing={2} alignItems="center">
                {status?.status && <StatusChip status={String(status.status).toUpperCase()} />}
                {jobId && <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>Job: {jobId}</Typography>}
                {eta && <Chip label={eta} size="small" variant="outlined" />}
              </Stack>
              {isRunning && status?.progress != null && (
                <Box>
                  <LinearProgress variant="determinate" value={Math.min((status.progress ?? 0) * 100, 100)} sx={{ height: 8, borderRadius: 1 }} />
                  <Typography variant="caption" color="text.secondary">{Math.round((status.progress ?? 0) * 100)}%</Typography>
                </Box>
              )}
            </Stack>
          </DataCard>
        )}

        {/* Output */}
        {status?.stdout && (
          <DataCard title="Output">
            <Button size="small" variant="text" onClick={() => setShowStdout(p => !p)}>{showStdout ? 'Hide stdout' : 'Show stdout'}</Button>
            <Collapse in={showStdout}>
              <Box component="pre" sx={{ m: 0, mt: 1, p: 1.5, bgcolor: 'background.default', borderRadius: 1, overflow: 'auto', maxHeight: 300, fontFamily: 'monospace', fontSize: '0.8rem', whiteSpace: 'pre-wrap' }}>
                {status.stdout}
              </Box>
            </Collapse>
          </DataCard>
        )}
        {status?.stderr && (
          <DataCard title="Errors">
            <Button size="small" variant="text" onClick={() => setShowStderr(p => !p)}>{showStderr ? 'Hide stderr' : 'Show stderr'}</Button>
            <Collapse in={showStderr || status.status === 'failed'}>
              <Box component="pre" sx={{ m: 0, mt: 1, p: 1.5, bgcolor: 'background.default', border: 1, borderColor: 'error.main', borderRadius: 1, overflow: 'auto', maxHeight: 300, fontFamily: 'monospace', fontSize: '0.8rem', whiteSpace: 'pre-wrap', color: 'error.main' }}>
                {status.stderr}
              </Box>
            </Collapse>
          </DataCard>
        )}

        {/* Job History */}
        {jobHistory.length > 0 && (
          <DataCard title="Job History">
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Job ID</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Profile</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Started</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {jobHistory.slice(0, 10).map((job: any, i: number) => (
                    <TableRow key={i} hover>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{job.jobId || job.id || '-'}</TableCell>
                      <TableCell><StatusChip status={String(job.status || '').toUpperCase()} /></TableCell>
                      <TableCell>{job.profile || '-'}</TableCell>
                      <TableCell>{formatDateTime(job.startedAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DataCard>
        )}
      </Stack>

      <ConfirmDialog
        open={cancelDialog}
        title="Cancel Batch Job?"
        message="This will stop the running batch job. In-progress scans may be interrupted."
        severity="warning"
        confirmLabel="Cancel Job"
        onConfirm={handleCancel}
        onCancel={() => setCancelDialog(false)}
      />
    </Box>
  );
}
