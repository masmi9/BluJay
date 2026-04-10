import { useState } from 'react';
import { Box, Button, Chip, Divider, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import ScienceIcon from '@mui/icons-material/Science';
import { secureFetch } from '../lib/api';
import { AODSApiClient } from '../services/api';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, ErrorDisplay, StatusChip, EmptyState } from '../components';
import type { MLThresholdsData } from '../types';

const api = new AODSApiClient();

type EvalResult = { precision?: number; recall?: number; filtered?: number; total?: number };
type PreviewFinding = Record<string, unknown> & { title?: string; severity?: string; confidence?: number; _threshold?: number; _over_threshold?: boolean };

export function MLThresholds() {
  const { data: current, loading, error: queryError, refetch } = useApiQuery<MLThresholdsData>('/ml/thresholds');
  const [candidate, setCandidate] = useState<string>('{}');
  const [result, setResult] = useState<EvalResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [previewInput, setPreviewInput] = useState<string>('[\n  {"title":"Low conf test","severity":"low","category":"crypto","plugin_source":"advanced_ssl_tls_analyzer","confidence":0.2},\n  {"title":"High conf test","severity":"low","category":"crypto","plugin_source":"advanced_ssl_tls_analyzer","confidence":0.95}\n]');
  const [previewOutput, setPreviewOutput] = useState<PreviewFinding[] | null>(null);
  const [previewStats, setPreviewStats] = useState<{ before: number; after: number; filtered: number } | null>(null);

  async function evaluate() {
    setError(null); setResult(null);
    try {
      let payload: Record<string, unknown> = {};
      try { payload = JSON.parse(candidate || '{}'); } catch { setError('Invalid JSON'); return; }
      const r = await secureFetch('/ml/metrics/eval_thresholds', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
      });
      if (!r.ok) throw new Error(String(r.status));
      setResult(await r.json());
    } catch (e: unknown) { setError((e as Error)?.message || 'Evaluation failed'); }
  }

  function appliedThreshold(thr: MLThresholdsData | null, category: string, plugin: string): number {
    try {
      if (!thr) return 0.5;
      const d = typeof thr.default === 'number' ? thr.default : 0.5;
      if (thr.plugins && typeof thr.plugins[plugin] === 'number') return Number(thr.plugins[plugin]);
      if (thr.categories && typeof thr.categories[category] === 'number') return Number(thr.categories[category]);
      return Number(d);
    } catch { return 0.5; }
  }

  function applyPreviewFilter() {
    setError(null); setPreviewOutput(null); setPreviewStats(null);
    try {
      const thr = current || {};
      const arr = JSON.parse(previewInput || '[]');
      if (!Array.isArray(arr)) { setError('Preview input must be a JSON array of findings'); return; }
      const keep: PreviewFinding[] = [];
      let filtered = 0;
      for (const f of arr) {
        if (!f || typeof f !== 'object') { continue; }
        const sev = String(f.severity || 'low').toLowerCase();
        if (sev === 'high' || sev === 'critical') { keep.push(f); continue; }
        const category = String(f.category || 'security');
        const plugin = String(f.plugin_source || f.plugin || '');
        let conf = 0.0;
        for (const k of ['confidence', 'probability', 'score', 'conf']) {
          if (k in f) { try { conf = Math.max(0, Math.min(1, Number(f[k]))); } catch { /* ignore */ } break; }
        }
        const t = appliedThreshold(thr, category, plugin);
        if (conf >= t) keep.push({ ...f, _threshold: t, _over_threshold: true });
        else filtered += 1;
      }
      setPreviewOutput(keep);
      setPreviewStats({ before: arr.length, after: keep.length, filtered });
    } catch (e: unknown) {
      setError((e as Error)?.message || 'Failed to apply preview filter');
    }
  }

  return (
    <Box>
      <PageHeader title="ML Thresholds" subtitle="Configure and evaluate ML confidence thresholds" />
      <Stack spacing={2}>
        <ErrorDisplay error={error || queryError} onRetry={refetch} />

        {/* Current Thresholds */}
        <DataCard title="Current Thresholds" loading={loading}>
          {current ? (
            <Stack spacing={2}>
              <TableContainer sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 600 }}>Parameter</TableCell>
                      <TableCell sx={{ fontWeight: 600 }} align="right">Value</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow hover>
                      <TableCell>FP Threshold</TableCell>
                      <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{current.fp_threshold ?? 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow hover>
                      <TableCell>Confidence Min</TableCell>
                      <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{current.confidence_min ?? 'N/A'}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
              {current.severity_weights && (
                <>
                  <Typography variant="subtitle2">Severity Weights</Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {Object.entries(current.severity_weights).map(([sev, w]) => (
                      <StatusChip key={sev} status={sev} label={`${sev}: ${w}`} />
                    ))}
                  </Stack>
                </>
              )}
            </Stack>
          ) : <EmptyState message="No thresholds loaded" />}
        </DataCard>

        {/* Candidate Evaluation */}
        <DataCard title="Candidate Mapping (JSON)">
          <TextField fullWidth multiline minRows={8} value={candidate} onChange={e => setCandidate(e.target.value)} sx={{ fontFamily: 'monospace', '& textarea': { fontFamily: 'monospace', fontSize: 12 } }} />
          <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
            <Button variant="contained" onClick={evaluate} size="large">Evaluate</Button>
            <Button
              variant="outlined"
              size="large"
              startIcon={<ScienceIcon />}
              data-testid="load-autoresearch-best"
              onClick={async () => {
                try {
                  const res = await api.getAutoResearchExperiments({ type: 'best', n: 1 });
                  if (res.experiments.length > 0) {
                    setCandidate(JSON.stringify(res.experiments[0].params, null, 2));
                  } else {
                    setError('No AutoResearch experiments found');
                  }
                } catch {
                  setError('Failed to load AutoResearch params');
                }
              }}
            >
              Load Best AutoResearch
            </Button>
          </Stack>
          {result && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Evaluation Result</Typography>
              <Stack direction="row" spacing={3} flexWrap="wrap" useFlexGap>
                {([
                  { label: 'Precision', value: result.precision?.toFixed?.(2) ?? 'N/A', color: 'success.main' },
                  { label: 'Recall', value: result.recall?.toFixed?.(2) ?? 'N/A', color: 'info.main' },
                  { label: 'Filtered', value: String(result.filtered ?? 'N/A'), color: 'warning.main' },
                  { label: 'Total', value: String(result.total ?? 'N/A'), color: 'text.primary' },
                ] as const).map(({ label, value, color }) => (
                  <Box key={label} sx={{ textAlign: 'center', minWidth: 80 }}>
                    <Typography variant="h5" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums', color }}>{value}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 500 }}>{label}</Typography>
                  </Box>
                ))}
              </Stack>
            </Box>
          )}
        </DataCard>

        <Divider />

        {/* Preview Filter */}
        <DataCard title="Preview Threshold Filtering (client-side)">
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Paste a findings array to preview which entries pass the active thresholds. High/Critical are always preserved.
          </Typography>
          <TextField fullWidth multiline minRows={8} value={previewInput} onChange={e => setPreviewInput(e.target.value)} sx={{ fontFamily: 'monospace', '& textarea': { fontFamily: 'monospace', fontSize: 12 } }} />
          <Box sx={{ mt: 1.5 }}>
            <Button variant="contained" onClick={applyPreviewFilter} disabled={!current} size="large">Apply Filter Using Current Thresholds</Button>
          </Box>
          {previewStats && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Preview Stats</Typography>
              <Stack direction="row" spacing={1}>
                <Chip label={`Before: ${previewStats.before}`} color="default" />
                <Chip label={`After: ${previewStats.after}`} color="success" />
                <Chip label={`Filtered: ${previewStats.filtered}`} color="warning" />
              </Stack>
            </Box>
          )}
          {previewOutput && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Preview Results</Typography>
              <TableContainer sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 600 }}>Title</TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                      <TableCell sx={{ fontWeight: 600 }} align="right">Confidence</TableCell>
                      <TableCell sx={{ fontWeight: 600 }} align="right">Threshold</TableCell>
                      <TableCell sx={{ fontWeight: 600 }} align="center">Passed</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {previewOutput.map((f, i) => (
                      <TableRow key={i} hover>
                        <TableCell>{f.title || 'Untitled'}</TableCell>
                        <TableCell><StatusChip status={String(f.severity || 'low').toUpperCase()} /></TableCell>
                        <TableCell align="right">{f.confidence?.toFixed?.(2) ?? 'N/A'}</TableCell>
                        <TableCell align="right">{f._threshold?.toFixed?.(2) ?? '-'}</TableCell>
                        <TableCell align="center"><StatusChip status="PASS" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </DataCard>
      </Stack>
    </Box>
  );
}
