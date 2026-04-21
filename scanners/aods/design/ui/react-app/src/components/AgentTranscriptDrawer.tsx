import { useCallback, useEffect, useRef, useState } from 'react';
import { formatTime } from '../lib/format';
import {
  Box,
  Chip,
  CircularProgress,
  Drawer,
  IconButton,
  Stack,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord';
import { secureFetch, getApiBase, getAuthToken } from '../lib/api';
import { useSseStream } from '../hooks/useSseStream';
import type { AgentObservation } from '../types';

export interface AgentTranscriptDrawerProps {
  open: boolean;
  onClose: () => void;
  taskId: string | null;
  taskStatus: string;
}

function typeColor(type: string): 'primary' | 'success' | 'warning' | 'error' | 'default' {
  switch (type) {
    case 'tool_call': return 'primary';
    case 'tool_result': return 'success';
    case 'thinking': return 'warning';
    case 'error': return 'error';
    default: return 'default';
  }
}

export function AgentTranscriptDrawer({ open, onClose, taskId, taskStatus }: AgentTranscriptDrawerProps) {
  const [observations, setObservations] = useState<AgentObservation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // SSE URL: only build for running/pending tasks while drawer is open
  const [sseUrl, setSseUrl] = useState<string | null>(null);
  const isRunning = ['pending', 'running'].includes(taskStatus);

  useEffect(() => {
    if (!open || !taskId || !isRunning) {
      setSseUrl(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const base = await getApiBase();
        const token = getAuthToken();
        const url = `${base}/agent/tasks/${encodeURIComponent(taskId)}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;
        if (!cancelled) setSseUrl(url);
      } catch {
        if (!cancelled) setSseUrl(null);
      }
    })();
    return () => { cancelled = true; };
  }, [open, taskId, isRunning]);

  const handleSseMessage = useCallback((data: any) => {
    if (data && typeof data === 'object' && data.type) {
      setObservations(prev => [...prev, data as AgentObservation]);
    }
  }, []);

  const { connected } = useSseStream({
    url: sseUrl,
    onMessage: handleSseMessage,
    maxRetries: 5,
    idleTimeoutMs: 90_000,
  });

  // One-shot fetch for completed/failed/cancelled tasks
  const fetchTranscript = async (id: string) => {
    try {
      const r = await secureFetch(`/agent/tasks/${encodeURIComponent(id)}/transcript`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      setObservations(data.observations || data || []);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load transcript');
    }
  };

  useEffect(() => {
    if (!open || !taskId) {
      setObservations([]);
      setError(null);
      return;
    }
    // For completed tasks, use one-shot fetch
    if (!isRunning) {
      setLoading(true);
      fetchTranscript(taskId).finally(() => setLoading(false));
    } else {
      // For running tasks, SSE handles it; do initial fetch for existing observations
      setLoading(true);
      fetchTranscript(taskId).finally(() => setLoading(false));
    }
  }, [open, taskId, taskStatus]);

  // Auto-scroll for active tasks
  useEffect(() => {
    if (isRunning && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [observations, taskStatus]);

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: '50vw' } } }}
      data-testid="transcript-drawer"
    >
      <Box sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="h6">Agent Transcript</Typography>
            {taskId && (
              <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                {taskId.slice(0, 8)}
              </Typography>
            )}
            <Chip
              label={taskStatus}
              size="small"
              color={
                taskStatus === 'completed' ? 'success'
                : taskStatus === 'running' ? 'primary'
                : taskStatus === 'failed' ? 'error'
                : 'default'
              }
              data-testid="transcript-status"
            />
            {isRunning && (
              <FiberManualRecordIcon
                sx={{ fontSize: 12, color: connected ? 'success.main' : 'text.disabled' }}
                data-testid="sse-connection-indicator"
                titleAccess={connected ? 'Connected' : 'Disconnected'}
              />
            )}
          </Stack>
          <IconButton onClick={onClose} aria-label="Close transcript">
            <CloseIcon />
          </IconButton>
        </Stack>

        {/* Content */}
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          {loading && (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress data-testid="transcript-loading" />
            </Box>
          )}
          {error && (
            <Typography color="error" data-testid="transcript-error">{error}</Typography>
          )}
          {!loading && !error && observations.length === 0 && (
            <Typography color="text.secondary" data-testid="transcript-empty">
              No observations recorded yet.
            </Typography>
          )}
          {!loading && observations.length > 0 && (
            <Stepper orientation="vertical" activeStep={observations.length - 1} data-testid="transcript-steps">
              {observations.map((obs, i) => (
                <Step key={i} completed={i < observations.length - 1 || !isRunning}>
                  <StepLabel>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Chip label={obs.type} size="small" color={typeColor(obs.type)} variant="outlined" />
                      {obs.tool_name && <Chip label={obs.tool_name} size="small" variant="outlined" />}
                    </Stack>
                  </StepLabel>
                  <StepContent>
                    <Box
                      component="pre"
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        bgcolor: 'background.default',
                        p: 1,
                        borderRadius: 1,
                        maxHeight: 200,
                        overflow: 'auto',
                      }}
                    >
                      {obs.content}
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      Step {obs.step} - {obs.timestamp ? formatTime(obs.timestamp) : ''}
                    </Typography>
                  </StepContent>
                </Step>
              ))}
            </Stepper>
          )}
          <div ref={bottomRef} />
        </Box>
      </Box>
    </Drawer>
  );
}
