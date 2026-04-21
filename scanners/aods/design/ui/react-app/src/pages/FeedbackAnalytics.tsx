import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Chip,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import RefreshIcon from '@mui/icons-material/Refresh';
import { secureFetch } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { PageHeader, DataCard, ErrorDisplay, LoadingSkeleton, EmptyState, AppToast } from '../components';
import { useToast } from '../hooks/useToast';

interface FeedbackEntry {
  finding_title: string;
  action: string;
  new_classification?: string;
  reason?: string;
  user?: string;
  timestamp?: string;
  scan_id?: string;
  similarity_score?: number;
}

interface FeedbackExportResponse {
  feedback: FeedbackEntry[];
  count: number;
  scan_ids: string[];
}

function actionColor(action: string): 'success' | 'error' | 'warning' | 'default' {
  const a = action.toLowerCase();
  if (a === 'accept') return 'success';
  if (a === 'reject') return 'error';
  if (a === 'reclassify') return 'warning';
  return 'default';
}


export function FeedbackAnalytics() {
  const { toast, showToast, closeToast } = useToast();
  const [feedback, setFeedback] = useState<FeedbackEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await secureFetch('/agent/triage/feedback/export');
      if (!res.ok) throw new Error(`Failed to fetch feedback: ${res.status}`);
      const data: FeedbackExportResponse = await res.json();
      setFeedback(data.feedback || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load feedback data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // --- Computed summaries ---
  const totalCount = feedback.length;

  const actionBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of feedback) {
      const a = f.action || 'unknown';
      counts[a] = (counts[a] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [feedback]);

  const userBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of feedback) {
      const u = f.user || 'unknown';
      counts[u] = (counts[u] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [feedback]);

  const overrideFrequency = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of feedback) {
      const title = f.finding_title || 'Unknown';
      counts[title] = (counts[title] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);
  }, [feedback]);

  const recentFeedback = useMemo(() => {
    return [...feedback]
      .sort((a, b) => {
        if (!a.timestamp && !b.timestamp) return 0;
        if (!a.timestamp) return 1;
        if (!b.timestamp) return -1;
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      })
      .slice(0, 50);
  }, [feedback]);

  // --- Export ---
  const exportJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(feedback, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `feedback_export_${new Date().toISOString().replace(/:/g, '-')}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('JSON exported');
  }, [feedback, showToast]);

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader
          title="Feedback Analytics"
          subtitle="Analyst triage feedback patterns and override frequency"
          actions={
            <Stack direction="row" spacing={1}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<RefreshIcon />}
                onClick={load}
                disabled={loading}
              >
                Refresh
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<DownloadIcon />}
                onClick={exportJson}
                disabled={!feedback.length}
                data-testid="export-feedback-json"
              >
                Export JSON
              </Button>
            </Stack>
          }
        />

        <ErrorDisplay error={error} onRetry={load} />

        {loading && <LoadingSkeleton variant="table" />}

        {!loading && !error && (
          <>
            {/* Summary Section */}
            <DataCard title="Summary">
              {totalCount === 0 ? (
                <EmptyState message="No feedback recorded yet" />
              ) : (
                <Stack spacing={2}>
                  <Typography variant="body2">
                    <strong>Total feedback entries:</strong>{' '}
                    <Typography component="span" sx={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{totalCount}</Typography>
                  </Typography>

                  {/* Action breakdown */}
                  <Box>
                    <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                      By Action
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {actionBreakdown.map(([action, count]) => (
                        <Chip
                          key={action}
                          label={`${action}: ${count}`}
                          size="small"
                          color={actionColor(action)}
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </Box>

                  {/* User breakdown */}
                  <Box>
                    <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                      By User
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {userBreakdown.map(([user, count]) => (
                        <Chip
                          key={user}
                          label={`${user}: ${count}`}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </Box>
                </Stack>
              )}
            </DataCard>

            {/* Override Frequency */}
            {overrideFrequency.length > 0 && (
              <DataCard title="Most Frequently Overridden Findings">
                <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                  <Table size="small" aria-label="Override frequency">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>Finding Title</TableCell>
                        <TableCell align="right" sx={{ fontWeight: 600 }}>Count</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {overrideFrequency.map(([title, count]) => (
                        <TableRow key={title} hover>
                          <TableCell>{title}</TableCell>
                          <TableCell align="right">
                            <Chip label={count} size="small" color={count > 3 ? 'warning' : 'default'} sx={{ fontVariantNumeric: 'tabular-nums' }} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </DataCard>
            )}

            {/* Recent Feedback */}
            {recentFeedback.length > 0 && (
              <DataCard title="Recent Feedback">
                <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                  <Table size="small" aria-label="Recent feedback">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>Finding Title</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Action</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>New Classification</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Reason</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>User</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Timestamp</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {recentFeedback.map((entry, idx) => (
                        <TableRow key={idx} hover>
                          <TableCell
                            sx={{
                              maxWidth: 250,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={entry.finding_title}
                          >
                            {entry.finding_title}
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={entry.action}
                              size="small"
                              color={actionColor(entry.action)}
                            />
                          </TableCell>
                          <TableCell>{entry.new_classification || '-'}</TableCell>
                          <TableCell
                            sx={{
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={entry.reason || ''}
                          >
                            {entry.reason || '-'}
                          </TableCell>
                          <TableCell>
                            {entry.user ? (
                              <Chip label={entry.user} size="small" variant="outlined" />
                            ) : (
                              '-'
                            )}
                          </TableCell>
                          <TableCell sx={{ fontSize: '0.85rem', whiteSpace: 'nowrap' }}>
                            {formatDateTime(entry.timestamp)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </DataCard>
            )}
          </>
        )}
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
