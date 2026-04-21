import { Link } from 'react-router-dom';
import { Box, Button, Chip, Grid, LinearProgress, Stack, Typography } from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { DataCard } from '../../components';
import type { ActiveScan, ScanResult } from '../../types';

function formatRelativeTime(dateStr: string | undefined): string {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const diffMs = Date.now() - d.getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return dateStr;
  }
}

interface DashboardActivityProps {
  runs: ScanResult[];
  active: ActiveScan[];
  roles: string[];
}

export function DashboardActivity({ runs, active, roles }: DashboardActivityProps) {
  return (
    <>
      <Grid item xs={12} md={8}>
        <DataCard title="Latest Runs" actions={<Button size="small" variant="text" component={Link} to="/runs">View all</Button>}>
          {runs.length === 0 ? (
            <Typography color="text.secondary" variant="body2">No completed scans yet</Typography>
          ) : (
            <Stack spacing={0}>
              {runs.map((r) => {
                const s = r.summary || {} as any;
                return (
                  <Stack
                    key={r.id}
                    component={Link}
                    to={`/runs/${encodeURIComponent(r.id)}`}
                    direction="row"
                    alignItems="center"
                    spacing={1}
                    sx={{
                      py: 1,
                      px: 1,
                      mx: -1,
                      borderRadius: 1,
                      textDecoration: 'none',
                      color: 'inherit',
                      '&:hover': { bgcolor: 'action.hover' },
                      '&:not(:last-child)': { borderBottom: 1, borderColor: 'divider' },
                    }}
                  >
                    <Typography variant="body2" sx={{ fontWeight: 500, minWidth: 0, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.apkName || r.id}
                    </Typography>
                    {(s.findings ?? 0) > 0 && <Chip size="small" label={`${s.findings} findings`} sx={{ fontSize: 11 }} />}
                    {(s.critical ?? 0) > 0 && <Chip size="small" color="error" label={s.critical} sx={{ fontSize: 11, minWidth: 24 }} />}
                    {(s.high ?? 0) > 0 && <Chip size="small" color="warning" label={s.high} sx={{ fontSize: 11, minWidth: 24 }} />}
                    <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: 'nowrap' }}>
                      {formatRelativeTime(r.startedAt)}
                    </Typography>
                  </Stack>
                );
              })}
            </Stack>
          )}
        </DataCard>
      </Grid>
      <Grid item xs={12} md={4}>
        <DataCard title="Quick Actions">
          <Stack spacing={1}>
            {roles.some(r => r === 'admin' || r === 'analyst') && (
              <Button variant="contained" component={Link} to="/new-scan" startIcon={<PlayArrowIcon />} fullWidth>New Scan</Button>
            )}
            <Button size="small" variant="outlined" component={Link} to="/gates" fullWidth>CI Gates</Button>
            <Button size="small" variant="outlined" component={Link} to="/reports" fullWidth>Reports</Button>
            {roles.includes('admin') && (
              <Button size="small" variant="outlined" component={Link} to="/ml" fullWidth>ML Overview</Button>
            )}
          </Stack>
        </DataCard>
      </Grid>
      {(active || []).length > 0 && (
        <Grid item xs={12}>
          <DataCard title="Active Scans">
            <Stack spacing={1}>
              {active.map((s) => (
                <Stack key={s.id} direction="row" alignItems="center" spacing={1.5} sx={{ py: 0.5 }}>
                  <Typography variant="body2" sx={{ fontWeight: 500, minWidth: 0, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.id}</Typography>
                  <Chip size="small" label={s.stage || s.status} sx={{ fontSize: 11 }} />
                  {typeof s.pct === 'number' && (
                    <Box sx={{ width: 80 }}>
                      <LinearProgress variant="determinate" value={Math.round(s.pct)} sx={{ borderRadius: 1 }} />
                    </Box>
                  )}
                  {typeof s.pct === 'number' && (
                    <Typography variant="caption" color="text.secondary" sx={{ minWidth: 32 }}>{Math.round(s.pct)}%</Typography>
                  )}
                  <Button size="small" variant="text" component={Link} to={`/runs/${encodeURIComponent(s.id)}`}>Open</Button>
                </Stack>
              ))}
            </Stack>
          </DataCard>
        </Grid>
      )}
    </>
  );
}
