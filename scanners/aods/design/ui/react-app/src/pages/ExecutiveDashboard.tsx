import { useCallback, useMemo } from 'react';
import { Box, Button, Chip, Grid, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, ErrorDisplay, LoadingSkeleton, StatusChip, SeverityChip, EmptyState } from '../components';

export function ExecutiveDashboard() {
  const { data: gates, loading: gatesLoading, error: gatesErr, refetch: refetchGates } = useApiQuery('/gates/summary');
  const { data: ml, loading: mlLoading, error: mlErr, refetch: refetchMl } = useApiQuery('/ml/metrics/detection_accuracy/summary');
  const { data: unknown } = useApiQuery('/artifacts/read?subdir=ci_gates&relPath=unknown_fields%2Fsummary.json', { silentError: true });
  const { data: severity } = useApiQuery('/artifacts/read?subdir=ci_gates&relPath=severity%2Fsummary.json', { silentError: true });
  const { data: pluginAuditData } = useApiQuery('/artifacts/list?subdir=plugin_audit', { silentError: true });
  const { data: recentScans } = useApiQuery<{ items?: any[] }>('/scans/recent?limit=5', { silentError: true });
  const { data: scansResults } = useApiQuery<any[]>('/scans/results', { silentError: true });

  const pluginAudit = useMemo(() => {
    if (!pluginAuditData) return false;
    return Array.isArray(pluginAuditData?.items) && pluginAuditData.items.some((it: any) => String(it.relPath) === 'index.html');
  }, [pluginAuditData]);

  const unknownReportRel = useMemo(() => {
    try {
      const p = String(unknown?.report || '');
      const idx = p.lastIndexOf('/reports/');
      if (idx >= 0) return p.slice(idx + '/reports/'.length);
      return p.split('/').pop() || '';
    } catch { return ''; }
  }, [unknown]);

  const loading = gatesLoading || mlLoading;
  const queryError = gatesErr || mlErr;
  const refetchAll = useCallback(() => { refetchGates(); refetchMl(); }, [refetchGates, refetchMl]);

  const gateTotals = useMemo(() => {
    if (!gates) return null;
    if (gates.totals) return gates.totals;
    const items: any[] = gates?.summary?.gates ? Object.values(gates.summary.gates) : [];
    return {
      PASS: items.filter((i: any) => String(i?.status || '').toUpperCase() === 'PASS').length,
      WARN: items.filter((i: any) => String(i?.status || '').toUpperCase() === 'WARN').length,
      FAIL: items.filter((i: any) => String(i?.status || '').toUpperCase() === 'FAIL').length,
    };
  }, [gates]);

  // Severity breakdown from latest result
  const sevBreakdown = useMemo(() => {
    if (!scansResults || !Array.isArray(scansResults)) return null;
    const latest = scansResults[0];
    if (!latest) return null;
    const findings = latest.vulnerabilities || latest.findings || [];
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f: any) => {
      const sev = (f.severity || 'INFO').toUpperCase();
      if (sev in counts) counts[sev]++;
      else counts['INFO']++;
    });
    return counts;
  }, [scansResults]);

  // Top findings from latest result
  const topFindings = useMemo(() => {
    if (!scansResults || !Array.isArray(scansResults)) return [];
    const latest = scansResults[0];
    if (!latest) return [];
    const findings = latest.vulnerabilities || latest.findings || [];
    const titleCounts: Record<string, { title: string; severity: string; count: number }> = {};
    findings.forEach((f: any) => {
      const t = f.title || 'Unknown';
      if (!titleCounts[t]) titleCounts[t] = { title: t, severity: f.severity || 'INFO', count: 0 };
      titleCounts[t].count++;
    });
    return Object.values(titleCounts).sort((a, b) => b.count - a.count).slice(0, 5);
  }, [scansResults]);

  const recentItems = recentScans?.items ?? [];

  return (
    <Box>
      <PageHeader title="Executive Dashboard" subtitle="Security posture overview for stakeholders" />
      <Stack spacing={2}>
        <Stack direction="row" justifyContent="flex-end">
          <Button size="small" startIcon={<RefreshIcon />} onClick={refetchGates}>Refresh</Button>
        </Stack>
        <ErrorDisplay error={queryError} onRetry={refetchAll} />
        {loading ? (
          <LoadingSkeleton variant="card" />
        ) : (
          <Grid container spacing={2}>
            {/* CI Gates */}
            <Grid item xs={12} md={6}>
              <DataCard title="CI Gates">
                {gateTotals ? (
                  <Stack direction="row" spacing={1}>
                    <StatusChip status="PASS" label={`PASS ${gateTotals.PASS || 0}`} />
                    <StatusChip status="WARN" label={`WARN ${gateTotals.WARN || 0}`} />
                    <StatusChip status="FAIL" label={`FAIL ${gateTotals.FAIL || 0}`} />
                  </Stack>
                ) : (
                  <EmptyState message="No gates data available" />
                )}
              </DataCard>
            </Grid>

            {/* ML Accuracy */}
            <Grid item xs={12} md={6}>
              <DataCard title="ML Accuracy">
                {ml ? (
                  <Stack spacing={0.5}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography>Overall:</Typography>
                      <StatusChip status={String(ml?.overall_status || ml?.status || 'UNKNOWN')} />
                    </Stack>
                    {ml?.precision != null && (
                      <Typography variant="body2" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        Precision: {(ml.precision * 100).toFixed(0)}% | Recall: {((ml?.recall ?? 0) * 100).toFixed(0)}%
                      </Typography>
                    )}
                  </Stack>
                ) : (
                  <EmptyState message="No accuracy summary available" />
                )}
              </DataCard>
            </Grid>

            {/* Scan Activity */}
            <Grid item xs={12} md={6}>
              <DataCard title="Scan Activity">
                {recentItems.length > 0 ? (
                  <TableContainer sx={{ borderRadius: 2 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>APK</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Profile</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Findings</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {recentItems.slice(0, 5).map((s: any, i: number) => (
                          <TableRow key={i} hover>
                            <TableCell sx={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.apkName || '-'}</TableCell>
                            <TableCell><Chip label={s.profile || '-'} size="small" variant="outlined" /></TableCell>
                            <TableCell><StatusChip status={String(s.status || '').toUpperCase()} /></TableCell>
                            <TableCell sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{s.findingsCount ?? '-'}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                ) : (
                  <EmptyState message="No recent scans" />
                )}
              </DataCard>
            </Grid>

            {/* Severity Breakdown */}
            <Grid item xs={12} md={6}>
              <DataCard title="Severity Breakdown">
                {sevBreakdown ? (
                  <Stack spacing={1}>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {Object.entries(sevBreakdown).map(([sev, count]) => (
                        count > 0 && <Chip key={sev} label={`${sev}: ${count}`} size="small" color={sev === 'CRITICAL' ? 'error' : sev === 'HIGH' ? 'warning' : sev === 'MEDIUM' ? 'info' : sev === 'LOW' ? 'success' : 'default'} />
                      ))}
                    </Stack>
                    <Typography variant="caption" color="text.secondary">From latest scan result</Typography>
                  </Stack>
                ) : (
                  <EmptyState message="No scan results available" />
                )}
              </DataCard>
            </Grid>

            {/* Top Findings */}
            {topFindings.length > 0 && (
              <Grid item xs={12} md={6}>
                <DataCard title="Top Findings">
                  <Stack spacing={0.5}>
                    {topFindings.map((f, i) => (
                      <Stack key={i} direction="row" spacing={1} alignItems="center">
                        <SeverityChip severity={f.severity} />
                        <Typography variant="body2" sx={{ flexGrow: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</Typography>
                        <Chip label={`x${f.count}`} size="small" variant="outlined" />
                      </Stack>
                    ))}
                  </Stack>
                </DataCard>
              </Grid>
            )}

            {/* Existing cards */}
            {unknown && (
              <Grid item xs={12} md={6}>
                <DataCard title="Unknown Fields">
                  <Stack spacing={0.5}>
                    <StatusChip status={String(unknown.status)} />
                    <Typography variant="body2" color="text.secondary">{String(unknown.message || '')}</Typography>
                    {unknownReportRel && (
                      <Typography variant="body2" sx={{ mt: 0.5 }}>
                        <Box component="a" href={`#/artifacts?cat=reports&path=${encodeURIComponent(unknownReportRel)}`} sx={{ color: 'primary.main' }}>Open report</Box>
                      </Typography>
                    )}
                  </Stack>
                </DataCard>
              </Grid>
            )}
            {severity && (
              <Grid item xs={12} md={6}>
                <DataCard title="Severity Gate">
                  <Stack spacing={0.5}>
                    <StatusChip status={String(severity.status || '')} />
                    <Typography variant="body2" color="text.secondary">High: {severity?.details?.high ?? 0} / Max {severity?.details?.max_high ?? 0}; Critical: {severity?.details?.critical ?? 0} / Max {severity?.details?.max_critical ?? 0}</Typography>
                  </Stack>
                </DataCard>
              </Grid>
            )}
            {pluginAudit && (
              <Grid item xs={12} md={6}>
                <DataCard title="Plugin Audit">
                  <Typography><Box component="a" href={`#/artifacts?cat=plugin_audit&path=${encodeURIComponent('index.html')}`} sx={{ color: 'primary.main' }}>Open Plugin Audit</Box></Typography>
                </DataCard>
              </Grid>
            )}
          </Grid>
        )}
      </Stack>
    </Box>
  );
}

export default ExecutiveDashboard;
