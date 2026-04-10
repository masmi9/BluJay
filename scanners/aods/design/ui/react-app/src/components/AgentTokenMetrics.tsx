import { useMemo } from 'react';
import {
  Box,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { TrendChart } from './TrendChart';
import type { AgentTask } from '../types';

export interface AgentTokenMetricsProps {
  tasks: AgentTask[];
  costLimitUsd?: number;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function AgentTokenMetrics({ tasks, costLimitUsd }: AgentTokenMetricsProps) {
  const metrics = useMemo(() => {
    const byType: Record<string, { count: number; input: number; output: number }> = {};
    let totalInput = 0;
    let totalOutput = 0;
    const chronological: number[] = [];

    for (const t of tasks) {
      const inp = t.token_usage?.input_tokens ?? 0;
      const out = t.token_usage?.output_tokens ?? 0;
      totalInput += inp;
      totalOutput += out;

      const key = t.agent_type;
      if (!byType[key]) byType[key] = { count: 0, input: 0, output: 0 };
      byType[key].count++;
      byType[key].input += inp;
      byType[key].output += out;

      chronological.push(inp + out);
    }

    const totalTokens = totalInput + totalOutput;
    // Use actual cost from task metadata if available, else approximate
    const actualCostSum = tasks.reduce((sum, t) => {
      const cost = (t as any).cost_usd ?? (t as any).metadata?.cost_usd;
      return cost ? sum + Number(cost) : sum;
    }, 0);
    const estimatedCost = actualCostSum > 0
      ? actualCostSum
      : (totalInput * 3 + totalOutput * 15) / 1_000_000;
    const completedCount = tasks.filter(t => t.status === 'completed').length;

    const costIsActual = actualCostSum > 0;
    return { byType, totalTokens, totalInput, totalOutput, estimatedCost, costIsActual, completedCount, chronological };
  }, [tasks]);

  return (
    <Box data-testid="agent-token-metrics">
      {/* Row 1: Summary chips */}
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
        <Chip
          label={`Total: ${formatTokens(metrics.totalTokens)} tokens`}
          variant="outlined"
          data-testid="token-total-chip"
        />
        <Chip
          label={`${metrics.costIsActual ? 'Cost' : 'Est. Cost'}: $${metrics.estimatedCost.toFixed(4)}`}
          variant="outlined"
          color="primary"
          data-testid="token-cost-chip"
        />
        <Chip
          label={`${metrics.completedCount} completed`}
          variant="outlined"
          color="success"
        />
      </Box>

      {/* Row 2: Per-agent breakdown table */}
      <TableContainer sx={{ mb: 2 }}>
        <Table size="small" data-testid="token-breakdown-table">
          <TableHead>
            <TableRow>
              <TableCell>Type</TableCell>
              <TableCell align="right">Tasks</TableCell>
              <TableCell align="right">Input</TableCell>
              <TableCell align="right">Output</TableCell>
              <TableCell align="right">Total</TableCell>
              <TableCell align="right">Est. Cost</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {Object.entries(metrics.byType).map(([type, data]) => {
              const total = data.input + data.output;
              const cost = (data.input * 3 + data.output * 15) / 1_000_000;
              return (
                <TableRow key={type}>
                  <TableCell>{type}</TableCell>
                  <TableCell align="right">{data.count}</TableCell>
                  <TableCell align="right">{formatTokens(data.input)}</TableCell>
                  <TableCell align="right">{formatTokens(data.output)}</TableCell>
                  <TableCell align="right">{formatTokens(total)}</TableCell>
                  <TableCell align="right">${cost.toFixed(4)}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Row 3: Sparkline */}
      {metrics.chronological.length > 1 && (
        <Box sx={{ mb: 2 }} data-testid="token-trend-chart">
          <Typography variant="caption" color="text.secondary" gutterBottom>
            Tokens per task (chronological)
          </Typography>
          <TrendChart data={metrics.chronological} width={300} height={50} />
        </Box>
      )}

      {/* Row 4: Budget bar */}
      {costLimitUsd != null && costLimitUsd > 0 && (
        <Box data-testid="token-budget-bar">
          <Typography variant="caption" color="text.secondary">
            Budget: ${metrics.estimatedCost.toFixed(4)} / ${costLimitUsd.toFixed(2)}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={Math.min(100, (metrics.estimatedCost / costLimitUsd) * 100)}
            color={metrics.estimatedCost > costLimitUsd * 0.9 ? 'error' : 'primary'}
            sx={{ height: 8, borderRadius: 1 }}
          />
        </Box>
      )}
    </Box>
  );
}
