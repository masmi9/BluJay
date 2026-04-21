import { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { TrendChart } from './TrendChart';
import { AODSApiClient } from '../services/api';
import type { AgentStats } from '../types';

const api = new AODSApiClient();

export function AgentTrendsPanel() {
  const [stats, setStats] = useState<AgentStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getAgentStats(7);
      setStats(data);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load agent stats');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  if (loading) {
    return (
      <Box data-testid="agent-trends-panel" sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  if (error || !stats) {
    return (
      <Box data-testid="agent-trends-panel">
        <Typography color="text.secondary" variant="body2">{error || 'No stats available'}</Typography>
      </Box>
    );
  }

  const recentTrend = Array.isArray(stats.recent_trend) ? stats.recent_trend : [];
  const byAgentType = stats.by_agent_type && typeof stats.by_agent_type === 'object' ? stats.by_agent_type : {};
  const byStatus = stats.by_status && typeof stats.by_status === 'object' ? stats.by_status : {};
  const trendTokens = recentTrend.map(d => d.tokens);
  const trendLabels = recentTrend.map(d => d.date);

  return (
    <Box data-testid="agent-trends-panel">
      {/* Summary row */}
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2, alignItems: 'center' }}>
        <Chip
          label={`${stats.total_tasks} tasks`}
          variant="outlined"
          data-testid="trends-total-tasks"
        />
        <Chip
          label={`${(stats.total_tokens / 1000).toFixed(1)}K tokens`}
          variant="outlined"
        />
        {typeof stats.avg_elapsed_seconds === 'number' && (
          <Chip
            label={`Avg ${stats.avg_elapsed_seconds.toFixed(0)}s`}
            variant="outlined"
          />
        )}
        {/* Status chips */}
        {Object.entries(byStatus).map(([status, count]) => (
          <Chip
            key={status}
            label={`${status}: ${count}`}
            size="small"
            color={status === 'completed' ? 'success' : status === 'failed' ? 'error' : 'default'}
            variant="outlined"
          />
        ))}
        <Button size="small" startIcon={<RefreshIcon />} onClick={fetchStats} sx={{ ml: 'auto' }}>
          Refresh
        </Button>
      </Box>

      {/* Agent type breakdown table */}
      <TableContainer sx={{ mb: 2 }}>
        <Table size="small" data-testid="trends-by-type-table">
          <TableHead>
            <TableRow>
              <TableCell>Type</TableCell>
              <TableCell align="right">Count</TableCell>
              <TableCell align="right">Tokens</TableCell>
              <TableCell align="right">Avg Time</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {Object.entries(byAgentType).map(([type, data]) => (
              <TableRow key={type}>
                <TableCell sx={{ textTransform: 'capitalize' }}>{type}</TableCell>
                <TableCell align="right">{data.count}</TableCell>
                <TableCell align="right">{(data.tokens / 1000).toFixed(1)}K</TableCell>
                <TableCell align="right">{data.avg_elapsed.toFixed(0)}s</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Daily trend sparkline */}
      {trendTokens.length > 1 && (
        <Box data-testid="trends-daily-chart">
          <Typography variant="caption" color="text.secondary" gutterBottom>
            Daily token usage (last 7 days)
          </Typography>
          <TrendChart data={trendTokens} labels={trendLabels} width={300} height={50} />
        </Box>
      )}
    </Box>
  );
}
