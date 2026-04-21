import React from 'react';
import {
  Box, Button, Chip, CircularProgress, Divider, FormControl, FormControlLabel,
  Grid, IconButton, InputLabel, MenuItem, Select, Slider, Stack, Switch,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Typography, Paper,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import SaveIcon from '@mui/icons-material/Save';
import CloseIcon from '@mui/icons-material/Close';
import SmartToyOutlinedIcon from '@mui/icons-material/SmartToyOutlined';
import { PageHeader, DataCard, ErrorDisplay, LoadingSkeleton, EmptyState } from '../components';
import { secureFetch } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { AgentTranscriptDrawer } from '../components/AgentTranscriptDrawer';
import { AgentTokenMetrics } from '../components/AgentTokenMetrics';
import { PipelineStepProgress } from '../components/PipelineStepProgress';
import { AgentTrendsPanel } from '../components/AgentTrendsPanel';
import { AODSApiClient } from '../services/api';
import type { AgentTask, AgentConfig as AgentConfigType } from '../types';

const api = new AODSApiClient();

function statusColor(status: string): 'default' | 'primary' | 'success' | 'error' | 'warning' {
  switch (status) {
    case 'running': return 'primary';
    case 'completed': return 'success';
    case 'failed': return 'error';
    case 'cancelled': return 'warning';
    default: return 'default';
  }
}

const sectionSx = { display: 'flex', alignItems: 'center', gap: 0.75, color: 'text.secondary', letterSpacing: 1.5, fontSize: '0.7rem' } as const;

export function AgentDashboard() {
  const [tasks, setTasks] = React.useState<AgentTask[]>([]);
  const [config, setConfig] = React.useState<AgentConfigType | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [agentType, setAgentType] = React.useState<string>('analyze');
  const [scanId, setScanId] = React.useState('');
  const [reportFile, setReportFile] = React.useState('');
  const [starting, setStarting] = React.useState(false);
  const [transcriptTaskId, setTranscriptTaskId] = React.useState<string | null>(null);
  const [transcriptStatus, setTranscriptStatus] = React.useState<string>('pending');
  const [transcriptOpen, setTranscriptOpen] = React.useState(false);

  // Quick Actions state
  const [quickFile, setQuickFile] = React.useState('');
  const [quickActionLoading, setQuickActionLoading] = React.useState<string | null>(null);

  // Config Editor state
  const [configEditing, setConfigEditing] = React.useState(false);
  const [editProvider, setEditProvider] = React.useState('');
  const [editModel, setEditModel] = React.useState('');
  const [editMaxIter, setEditMaxIter] = React.useState(10);
  const [editCostLimit, setEditCostLimit] = React.useState(1.0);
  const [editEnabled, setEditEnabled] = React.useState(true);
  const [savingConfig, setSavingConfig] = React.useState(false);

  // Pipeline state
  const [pipelineReportFile, setPipelineReportFile] = React.useState('');
  const [pipelineTokenBudget, setPipelineTokenBudget] = React.useState(200000);
  const [pipelineStopOnFailure, setPipelineStopOnFailure] = React.useState(false);
  const [pipelineSteps, setPipelineSteps] = React.useState({
    triage: true, verify: true, remediate: true, narrate: true,
  });
  const [startingPipeline, setStartingPipeline] = React.useState(false);

  const fetchTasks = React.useCallback(async () => {
    try {
      const resp = await api.getAgentTasks({ limit: 50 });
      setTasks(resp.tasks);
      setError(null);
    } catch (e: any) {
      if (e.message?.includes('503')) {
        setError('Agent system is disabled. Set AODS_AGENT_ENABLED=1 to enable.');
      } else {
        setError(e.message || 'Failed to load agent tasks');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchConfig = React.useCallback(async () => {
    try {
      const cfg = await api.getAgentConfig();
      setConfig(cfg);
    } catch {
      // Config is admin-only, ignore if forbidden
    }
  }, []);

  React.useEffect(() => {
    fetchTasks();
    fetchConfig();
    const interval = setInterval(fetchTasks, 5000);
    return () => clearInterval(interval);
  }, [fetchTasks, fetchConfig]);

  const handleStart = async () => {
    setStarting(true);
    try {
      const input: any = { agent_type: agentType };
      if (scanId.trim()) input.scan_id = scanId.trim();
      if (reportFile.trim()) input.report_file = reportFile.trim();
      await api.startAgentTask(input);
      setScanId('');
      setReportFile('');
      await fetchTasks();
    } catch (e: any) {
      setError(e.message || 'Failed to start agent task');
    } finally {
      setStarting(false);
    }
  };

  const handleStartPipeline = async () => {
    if (!pipelineReportFile.trim()) return;
    setStartingPipeline(true);
    try {
      const steps = Object.entries(pipelineSteps).map(([agent_type, enabled]) => ({
        agent_type, enabled,
      }));
      await api.startPipeline({
        report_file: pipelineReportFile.trim(),
        steps,
        total_token_budget: pipelineTokenBudget,
        stop_on_failure: pipelineStopOnFailure,
      });
      await fetchTasks();
    } catch (e: any) {
      setError(e.message || 'Failed to start pipeline');
    } finally {
      setStartingPipeline(false);
    }
  };

  const handleQuickAction = async (type: string) => {
    if (!quickFile.trim()) return;
    setQuickActionLoading(type);
    try {
      const body = type === 'orchestrate'
        ? { apk_path: quickFile.trim() }
        : { report_file: quickFile.trim() };
      const r = await secureFetch(`/agent/${type}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.detail || `HTTP ${r.status}`);
      }
      await fetchTasks();
    } catch (e: any) {
      setError(e.message || `Failed to start ${type}`);
    } finally {
      setQuickActionLoading(null);
    }
  };

  const handleEditConfig = () => {
    if (!config) return;
    setEditProvider((config as any).provider || 'anthropic');
    setEditModel(config.model || '');
    setEditMaxIter((config.budget as any)?.max_iterations ?? 10);
    setEditCostLimit((config.budget as any)?.cost_limit_usd ?? 1.0);
    setEditEnabled(config.enabled ?? true);
    setConfigEditing(true);
  };

  const handleSaveConfig = async () => {
    setSavingConfig(true);
    try {
      await api.updateAgentConfig({
        enabled: editEnabled,
        provider: editProvider,
        model: editModel,
        max_iterations: editMaxIter,
        cost_limit_usd: editCostLimit,
      });
      setConfigEditing(false);
      await fetchConfig();
    } catch (e: any) {
      setError(e.message || 'Failed to save config');
    } finally {
      setSavingConfig(false);
    }
  };

  const handleCancel = async (taskId: string) => {
    try {
      await api.cancelAgentTask(taskId);
      await fetchTasks();
    } catch (e: any) {
      setError(e.message || 'Failed to cancel task');
    }
  };

  const runningPipeline = tasks.find(t => t.agent_type === 'pipeline' && ['pending', 'running'].includes(t.status));
  const costLimitUsd = (config?.budget as any)?.cost_limit_usd;

  return (
    <Box sx={{ maxWidth: 1060, mx: 'auto' }}>
      <PageHeader title="Agent Intelligence" subtitle="Manage AI-powered analysis agents and pipelines" />

      <ErrorDisplay error={error} severity="warning" />

      <Stack spacing={3}>
        {/* ============ Configuration ============ */}
        {config && (
          <Box data-testid="agent-config-panel">
            <DataCard
              title="Configuration"
              actions={
                !configEditing ? (
                  <IconButton size="small" onClick={handleEditConfig} data-testid="config-edit-btn" aria-label="Edit config">
                    <EditIcon fontSize="small" />
                  </IconButton>
                ) : (
                  <Stack direction="row" spacing={0.5}>
                    <IconButton size="small" onClick={handleSaveConfig} disabled={savingConfig} data-testid="config-save-btn" aria-label="Save config" color="primary">
                      {savingConfig ? <CircularProgress size={16} /> : <SaveIcon fontSize="small" />}
                    </IconButton>
                    <IconButton size="small" onClick={() => setConfigEditing(false)} data-testid="config-cancel-btn" aria-label="Cancel editing">
                      <CloseIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                )
              }
            >
              {!configEditing ? (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Chip label={config.enabled ? 'Enabled' : 'Disabled'} color={config.enabled ? 'success' : 'default'} size="small" />
                  <Chip label={`Provider: ${(config as any).provider || 'unknown'}`} variant="outlined" size="small" />
                  <Chip label={`Model: ${config.model}`} variant="outlined" size="small" />
                  <Chip label={`Max Iterations: ${(config.budget as any)?.max_iterations ?? '?'}`} variant="outlined" size="small" />
                  <Chip label={`Cost Limit: $${(config.budget as any)?.cost_limit_usd ?? '?'}`} variant="outlined" size="small" />
                </Stack>
              ) : (
                <Grid container spacing={2} alignItems="center">
                  <Grid item>
                    <FormControlLabel
                      control={<Switch checked={editEnabled} onChange={e => setEditEnabled(e.target.checked)} size="small" data-testid="config-enabled-switch" />}
                      label="Enabled"
                    />
                  </Grid>
                  <Grid item xs={12} sm={3}>
                    <FormControl size="small" fullWidth>
                      <InputLabel>Provider</InputLabel>
                      <Select value={editProvider} label="Provider" onChange={e => setEditProvider(e.target.value)} data-testid="config-provider-select">
                        <MenuItem value="anthropic">Anthropic</MenuItem>
                        <MenuItem value="openai">OpenAI</MenuItem>
                        <MenuItem value="ollama">Ollama</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} sm={3}>
                    <TextField size="small" fullWidth label="Model" value={editModel} onChange={e => setEditModel(e.target.value)} data-testid="config-model-input" />
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <TextField size="small" fullWidth label="Max Iterations" type="number" value={editMaxIter} onChange={e => setEditMaxIter(Number(e.target.value))} inputProps={{ min: 1, max: 200 }} data-testid="config-iterations-input" />
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <TextField size="small" fullWidth label="Cost Limit ($)" type="number" value={editCostLimit} onChange={e => setEditCostLimit(Number(e.target.value))} inputProps={{ min: 0.01, max: 100, step: 0.1 }} data-testid="config-cost-limit" />
                  </Grid>
                </Grid>
              )}
            </DataCard>
          </Box>
        )}

        {/* ============ Actions ============ */}
        <Divider>
          <Typography variant="overline" sx={sectionSx}>
            <PlayArrowIcon fontSize="small" /> Actions
          </Typography>
        </Divider>

        <Grid container spacing={2}>
          {/* Quick Actions */}
          <Grid item xs={12} md={6}>
            <Box data-testid="quick-actions-card">
              <DataCard title="Quick Actions">
                <Stack spacing={2}>
                  <TextField
                    size="small"
                    fullWidth
                    label="Report File / APK Path"
                    value={quickFile}
                    onChange={e => setQuickFile(e.target.value)}
                    data-testid="quick-action-file"
                  />
                  <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                    {(['narrate', 'verify', 'triage', 'remediate', 'orchestrate'] as const).map(type => (
                      <Button
                        key={type}
                        variant="outlined"
                        size="small"
                        onClick={() => handleQuickAction(type)}
                        disabled={!quickFile.trim() || quickActionLoading !== null}
                        startIcon={quickActionLoading === type ? <CircularProgress size={14} /> : undefined}
                        data-testid={`quick-action-${type}`}
                      >
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </Button>
                    ))}
                  </Stack>
                </Stack>
              </DataCard>
            </Box>
          </Grid>

          {/* Start Agent Task */}
          <Grid item xs={12} md={6}>
            <Box data-testid="agent-start-form">
              <DataCard title="Start Agent Task">
                <Stack spacing={2}>
                  <FormControl size="small" fullWidth>
                    <InputLabel id="agent-type-label">Agent Type</InputLabel>
                    <Select
                      labelId="agent-type-label"
                      label="Agent Type"
                      value={agentType}
                      onChange={e => setAgentType(e.target.value)}
                      data-testid="agent-type-select"
                    >
                      <MenuItem value="analyze">Analyze</MenuItem>
                      <MenuItem value="narrate">Narrate</MenuItem>
                      <MenuItem value="verify">Verify</MenuItem>
                      <MenuItem value="triage">Triage</MenuItem>
                      <MenuItem value="remediate">Remediate</MenuItem>
                    </Select>
                  </FormControl>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <TextField size="small" fullWidth label="Scan ID" value={scanId} onChange={e => setScanId(e.target.value)} data-testid="agent-scan-id" placeholder="optional" />
                    </Grid>
                    <Grid item xs={6}>
                      <TextField size="small" fullWidth label="Report File" value={reportFile} onChange={e => setReportFile(e.target.value)} data-testid="agent-report-file" placeholder="optional" />
                    </Grid>
                  </Grid>
                  <Box>
                    <Button variant="contained" onClick={handleStart} disabled={starting} data-testid="agent-start-btn">
                      {starting ? <CircularProgress size={20} /> : 'Start'}
                    </Button>
                  </Box>
                </Stack>
              </DataCard>
            </Box>
          </Grid>
        </Grid>

        {/* Pipeline */}
        <Box data-testid="pipeline-card">
          <DataCard title="Run Pipeline">
            {runningPipeline && (
              <Box sx={{ mb: 2 }}>
                <PipelineStepProgress taskId={runningPipeline.id} taskStatus={runningPipeline.status} />
              </Box>
            )}
            <Grid container spacing={2} alignItems="flex-end">
              <Grid item xs={12} sm={4}>
                <TextField
                  size="small"
                  fullWidth
                  label="Report File"
                  value={pipelineReportFile}
                  onChange={e => setPipelineReportFile(e.target.value)}
                  data-testid="pipeline-report-file"
                />
              </Grid>
              <Grid item xs={12} sm={3}>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                  Token Budget: {(pipelineTokenBudget / 1000).toFixed(0)}K
                </Typography>
                <Slider
                  value={pipelineTokenBudget}
                  min={50000}
                  max={500000}
                  step={10000}
                  onChange={(_e, v) => setPipelineTokenBudget(v as number)}
                  data-testid="pipeline-token-budget"
                  size="small"
                />
              </Grid>
              <Grid item xs={12} sm={5}>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap alignItems="center">
                  {(['triage', 'verify', 'remediate', 'narrate'] as const).map(step => (
                    <FormControlLabel
                      key={step}
                      control={
                        <Switch
                          checked={pipelineSteps[step]}
                          onChange={e => setPipelineSteps(prev => ({ ...prev, [step]: e.target.checked }))}
                          size="small"
                        />
                      }
                      label={<Typography variant="caption">{step.charAt(0).toUpperCase() + step.slice(1)}</Typography>}
                      data-testid={`pipeline-step-${step}`}
                      sx={{ mr: 1 }}
                    />
                  ))}
                </Stack>
              </Grid>
            </Grid>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={pipelineStopOnFailure}
                    onChange={e => setPipelineStopOnFailure(e.target.checked)}
                    data-testid="pipeline-stop-on-failure"
                    size="small"
                  />
                }
                label="Stop on failure"
              />
              <Box sx={{ flexGrow: 1 }} />
              <Button
                variant="contained"
                onClick={handleStartPipeline}
                disabled={startingPipeline || !pipelineReportFile.trim()}
                data-testid="pipeline-start-btn"
              >
                {startingPipeline ? <CircularProgress size={20} /> : 'Run Pipeline'}
              </Button>
            </Stack>
          </DataCard>
        </Box>

        {/* ============ Metrics ============ */}
        <Divider>
          <Typography variant="overline" sx={sectionSx}>
            <SmartToyOutlinedIcon fontSize="small" /> Metrics
          </Typography>
        </Divider>

        <Grid container spacing={2}>
          {/* Token Metrics */}
          {tasks.length > 0 && (
            <Grid item xs={12} md={6}>
              <Box data-testid="token-metrics-card">
                <DataCard title="Token Usage">
                  <AgentTokenMetrics tasks={tasks} costLimitUsd={costLimitUsd} />
                </DataCard>
              </Box>
            </Grid>
          )}

          {/* Agent Trends */}
          <Grid item xs={12} md={tasks.length > 0 ? 6 : 12}>
            <Box data-testid="agent-trends-card">
              <DataCard title="Agent Trends (7 days)">
                <AgentTrendsPanel />
              </DataCard>
            </Box>
          </Grid>
        </Grid>

        {/* ============ Task History ============ */}
        {loading ? (
          <LoadingSkeleton variant="table" />
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
            <Table size="small" data-testid="agent-tasks-table">
              <TableHead>
                <TableRow sx={{ '& th': { fontWeight: 600, fontSize: 12, color: 'text.secondary', textTransform: 'uppercase', letterSpacing: '0.04em' } }}>
                  <TableCell>ID</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>User</TableCell>
                  <TableCell align="right">Iterations</TableCell>
                  <TableCell align="right">Tokens</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tasks.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <EmptyState message="No agent tasks yet" />
                    </TableCell>
                  </TableRow>
                ) : (
                  tasks.map(task => (
                    <TableRow key={task.id} hover data-testid={`agent-task-row-${task.id}`}>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {task.id.slice(0, 8)}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>{task.agent_type}</Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={task.status} color={statusColor(task.status)} size="small" />
                      </TableCell>
                      <TableCell>{task.user || '-'}</TableCell>
                      <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{task.iterations}</TableCell>
                      <TableCell align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        {task.token_usage
                          ? `${(task.token_usage.input_tokens + task.token_usage.output_tokens).toLocaleString()}`
                          : '-'}
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {formatDateTime(task.created_at)}
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5}>
                          {['pending', 'running'].includes(task.status) && (
                            <Button size="small" color="warning" onClick={() => handleCancel(task.id)} data-testid={`cancel-task-${task.id}`}>
                              Cancel
                            </Button>
                          )}
                          <Button
                            size="small"
                            variant="outlined"
                            onClick={() => {
                              setTranscriptTaskId(task.id);
                              setTranscriptStatus(task.status);
                              setTranscriptOpen(true);
                            }}
                            data-testid={`transcript-btn-${task.id}`}
                          >
                            Transcript
                          </Button>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Stack>

      <AgentTranscriptDrawer
        open={transcriptOpen}
        onClose={() => { setTranscriptOpen(false); setTranscriptTaskId(null); }}
        taskId={transcriptTaskId}
        taskStatus={transcriptStatus}
      />
    </Box>
  );
}
