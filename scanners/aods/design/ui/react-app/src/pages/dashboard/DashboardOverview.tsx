import { Link } from 'react-router-dom';
import { Box, Button, Chip, FormControlLabel, Grid, Stack, Switch, Typography } from '@mui/material';
import { DataCard } from '../../components';
import type { GatesSummary } from '../../types';

interface DashboardOverviewProps {
  runsCount: number;
  gates: GatesSummary | null;
  deltasAuto: boolean;
  onDeltasAutoChange: (v: boolean) => void;
  gatesDelta: { WARN?: number; FAIL?: number } | null;
  onRefreshDeltas: () => void;
}

export function DashboardOverview({ runsCount, gates, gatesDelta, deltasAuto, onDeltasAutoChange, onRefreshDeltas }: DashboardOverviewProps) {
  const totals = gates?.totals;
  return (
    <Grid item xs={12}>
      <DataCard title="">
        <Stack direction="row" spacing={4} sx={{ flexWrap: 'wrap' }} useFlexGap>
          {/* Scans */}
          <Box sx={{ textAlign: 'center', minWidth: 80 }}>
            <Typography variant="h4" sx={{ fontWeight: 700, lineHeight: 1 }}>{runsCount || 0}</Typography>
            <Typography variant="caption" color="text.secondary">Scans</Typography>
          </Box>

          {/* Gates */}
          {totals && (
            <>
              <Box sx={{ borderLeft: 1, borderColor: 'divider', pl: 3 }}>
                <Stack direction="row" spacing={2}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, lineHeight: 1, color: 'success.main' }}>{totals.PASS || 0}</Typography>
                    <Typography variant="caption" color="text.secondary">Pass</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, lineHeight: 1, color: 'warning.main' }}>{totals.WARN || 0}</Typography>
                    <Typography variant="caption" color="text.secondary">Warn</Typography>
                    {deltasAuto && gatesDelta?.WARN && gatesDelta.WARN > 0 && (
                      <Chip data-testid="gates-delta-warn" size="small" label={`+${gatesDelta.WARN}`} color="warning" variant="outlined" sx={{ ml: 0.5, height: 16, fontSize: 9 }} />
                    )}
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, lineHeight: 1, color: 'error.main' }}>{totals.FAIL || 0}</Typography>
                    <Typography variant="caption" color="text.secondary">Fail</Typography>
                    {deltasAuto && gatesDelta?.FAIL && gatesDelta.FAIL > 0 && (
                      <Chip data-testid="gates-delta-fail" size="small" label={`+${gatesDelta.FAIL}`} color="error" variant="outlined" sx={{ ml: 0.5, height: 16, fontSize: 9 }} />
                    )}
                  </Box>
                </Stack>
              </Box>
            </>
          )}

          <Box sx={{ flex: 1 }} />

          {/* Quick links + settings */}
          <Stack direction="row" spacing={1} alignItems="center">
            <FormControlLabel
              control={<Switch size="small" checked={deltasAuto} onChange={(e) => onDeltasAutoChange(e.target.checked)} />}
              label={<Typography variant="caption" sx={{ fontSize: 10 }}>Auto deltas</Typography>}
              sx={{ mr: 0 }}
            />
            <Button size="small" variant="text" onClick={onRefreshDeltas} sx={{ fontSize: 11, minWidth: 0 }}>Refresh</Button>
            <Box sx={{ borderLeft: 1, borderColor: 'divider', height: 20, mx: 0.5 }} />
            <Button size="small" variant="outlined" component={Link} to="/gates">Gates</Button>
            <Button size="small" variant="outlined" component={Link} to="/runs">Results</Button>
            <Button size="small" variant="outlined" component={Link} to="/reports">Reports</Button>
          </Stack>
        </Stack>
      </DataCard>
    </Grid>
  );
}
