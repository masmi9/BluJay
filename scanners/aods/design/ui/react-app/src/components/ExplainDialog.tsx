import { useEffect, useState } from 'react';
import {
  Box,
  Chip,
  CircularProgress,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import { secureFetch } from '../lib/api';
import type { Finding } from './FindingsTable';
import type { UnifiedExplanation } from '../types';

export interface ExplainDialogProps {
  open: boolean;
  onClose: () => void;
  finding: Finding | null;
}

export function ExplainDialog({ open, onClose, finding }: ExplainDialogProps) {
  const [explanation, setExplanation] = useState<UnifiedExplanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !finding) {
      setExplanation(null);
      setError(null);
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const r = await secureFetch('/explain/finding', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: finding.title,
            severity: finding.severity,
            category: finding.category,
            cwe_id: finding.cwe_id,
            confidence: finding.confidence,
            plugin_source: finding.plugin_source,
          }),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        if (!cancelled) setExplanation(data);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load explanation');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [open, finding]);

  const sortedFactors = explanation?.contributing_factors
    ? [...explanation.contributing_factors].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    : [];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth data-testid="explain-dialog">
      <DialogTitle>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Typography variant="h6">ML Explanation</Typography>
          <IconButton onClick={onClose} size="small" aria-label="Close">
            <CloseIcon />
          </IconButton>
        </Stack>
      </DialogTitle>
      <DialogContent>
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress data-testid="explain-loading" />
          </Box>
        )}
        {error && (
          <Typography color="error" data-testid="explain-error">{error}</Typography>
        )}
        {explanation && !loading && (
          <Stack spacing={2}>
            {/* Summary */}
            <Typography variant="body1" data-testid="explain-summary">{explanation.summary}</Typography>

            {/* Confidence + Method */}
            <Stack direction="row" spacing={2} alignItems="center">
              <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                <CircularProgress
                  variant="determinate"
                  value={Math.round(explanation.confidence * 100)}
                  size={56}
                  data-testid="explain-confidence"
                />
                <Box sx={{ position: 'absolute', top: 0, left: 0, bottom: 0, right: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Typography variant="caption" fontWeight={700}>{Math.round(explanation.confidence * 100)}%</Typography>
                </Box>
              </Box>
              <Chip label={explanation.method} variant="outlined" data-testid="explain-method" />
            </Stack>

            {/* Contributing Factors */}
            {sortedFactors.length > 0 && (
              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Contributing Factors</Typography>
                <Table size="small" data-testid="explain-factors-table">
                  <TableHead>
                    <TableRow>
                      <TableCell>Factor</TableCell>
                      <TableCell>Contribution</TableCell>
                      <TableCell>Direction</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sortedFactors.map((f, i) => (
                      <TableRow key={i}>
                        <TableCell>{f.factor}</TableCell>
                        <TableCell>{f.contribution.toFixed(3)}</TableCell>
                        <TableCell>
                          {f.direction === 'positive' ? (
                            <ArrowUpwardIcon fontSize="small" color="error" />
                          ) : (
                            <ArrowDownwardIcon fontSize="small" color="success" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            )}

            {/* Risk Factors */}
            {explanation.risk_factors.length > 0 && (
              <Box>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Risk Factors</Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {explanation.risk_factors.map((rf, i) => (
                    <Chip key={i} label={rf} color="error" size="small" variant="outlined" />
                  ))}
                </Stack>
              </Box>
            )}

            {/* Mitigating Factors */}
            {explanation.mitigating_factors.length > 0 && (
              <Box>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Mitigating Factors</Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {explanation.mitigating_factors.map((mf, i) => (
                    <Chip key={i} label={mf} color="success" size="small" variant="outlined" />
                  ))}
                </Stack>
              </Box>
            )}
          </Stack>
        )}
      </DialogContent>
    </Dialog>
  );
}
