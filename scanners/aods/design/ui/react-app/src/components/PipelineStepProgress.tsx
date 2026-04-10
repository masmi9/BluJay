import { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Step,
  StepLabel,
  Stepper,
  Typography,
} from '@mui/material';
import { useSseStream } from '../hooks/useSseStream';
import { getApiBase, getAuthToken } from '../lib/api';

export interface PipelineStepProgressProps {
  taskId: string;
  taskStatus: string;
}

type StepState = 'pending' | 'running' | 'completed' | 'failed';

const PIPELINE_STEPS = ['triage', 'verify', 'remediate', 'narrate'] as const;

export function PipelineStepProgress({ taskId, taskStatus }: PipelineStepProgressProps) {
  const [stepStates, setStepStates] = useState<Record<string, { state: StepState; elapsed?: number }>>({
    triage: { state: 'pending' },
    verify: { state: 'pending' },
    remediate: { state: 'pending' },
    narrate: { state: 'pending' },
  });

  const [sseUrl, setSseUrl] = useState<string | null>(null);
  const isActive = ['pending', 'running'].includes(taskStatus);

  useEffect(() => {
    if (!isActive) {
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
  }, [taskId, isActive]);

  const handleMessage = useCallback((data: any) => {
    if (!data || typeof data !== 'object') return;
    const agentType = data.agent_type as string;
    if (!agentType) return;

    if (data.type === 'pipeline_step_start') {
      setStepStates(prev => ({
        ...prev,
        [agentType]: { state: 'running' },
      }));
    } else if (data.type === 'pipeline_step_complete') {
      setStepStates(prev => ({
        ...prev,
        [agentType]: {
          state: data.step_status === 'completed' ? 'completed' : 'failed',
          elapsed: data.elapsed_seconds,
        },
      }));
    }
  }, []);

  useSseStream({
    url: sseUrl,
    onMessage: handleMessage,
    maxRetries: 5,
    idleTimeoutMs: 120_000,
  });

  // Compute active step index for MUI Stepper
  const activeStepIdx = PIPELINE_STEPS.findIndex(s => stepStates[s]?.state === 'running');
  const completedCount = PIPELINE_STEPS.filter(s => stepStates[s]?.state === 'completed').length;
  const activeStep = activeStepIdx >= 0 ? activeStepIdx : completedCount;

  return (
    <Box data-testid="pipeline-step-progress" sx={{ py: 1 }}>
      <Stepper activeStep={activeStep} alternativeLabel>
        {PIPELINE_STEPS.map((step) => {
          const info = stepStates[step];
          const isError = info?.state === 'failed';
          return (
            <Step
              key={step}
              completed={info?.state === 'completed'}
              data-testid={`pipeline-step-${step}`}
            >
              <StepLabel error={isError}>
                <Typography variant="caption" sx={{ textTransform: 'capitalize' }}>
                  {step}
                </Typography>
                {info?.elapsed != null && (
                  <Typography variant="caption" color="text.secondary" display="block">
                    {info.elapsed.toFixed(1)}s
                  </Typography>
                )}
              </StepLabel>
            </Step>
          );
        })}
      </Stepper>
    </Box>
  );
}
