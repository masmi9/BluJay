import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Box, Button, Chip, Grid, Stack, Typography } from '@mui/material';
import { secureFetch, getApiBase, buildSecurityHeaders } from '../lib/api';
import { fireNotification } from '../lib/notify';
import { getUiVersion } from '../lib/env';
import { formatTime } from '../lib/format';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../hooks/useToast';
import { PageHeader, DataCard, ErrorDisplay, LoadingSkeleton, TrendChart, AppToast } from '../components';
import { DashboardOverview } from './dashboard/DashboardOverview';
import { DashboardActivity } from './dashboard/DashboardActivity';
import { DashboardHealth } from './dashboard/DashboardHealth';
import { DashboardDevServers } from './dashboard/DashboardDevServers';
import type { ActiveScan, AuditEvent, ApiInfo, DevServerStatus, GatesSummary, GatesTotals, MLSnapshot, ScanResult, ToolsStatusResponse } from '../types';

const ALL_DASH_CARDS = ['Recent Scans', 'Gates Summary', 'Scan Trends', 'Active Scans', 'Tool Status'];

export function Dashboard() {
  const auth = useAuth();
  const roles = (auth?.roles ?? []) as string[];
  const visCards: string[] = (() => { try { const v = localStorage.getItem('aodsConfig_dashCards'); return v ? JSON.parse(v) : ALL_DASH_CARDS; } catch { return ALL_DASH_CARDS; } })();
  const [summary, setSummary] = useState<{ gates: GatesSummary | null; runsCount: number }>({ gates: null, runsCount: 0 });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<ScanResult[]>([]);
  const [tools, setTools] = useState<ToolsStatusResponse | null>(null);
  const [active, setActive] = useState<ActiveScan[]>([]);
  const [gatesDelta, setGatesDelta] = useState<{ WARN?: number; FAIL?: number } | null>(null);
  const lastTotalsRef = useRef<GatesTotals | null>(null);
  const [mlSnapshot, setMlSnapshot] = useState<MLSnapshot | null>(null);
  const [apiInfo, setApiInfo] = useState<ApiInfo | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [lastRefreshIso, setLastRefreshIso] = useState<string>('');
  const [deltasAuto, setDeltasAuto] = useState<boolean>(() => { try { return localStorage.getItem('aodsGatesDeltasAuto') !== '0'; } catch { return true; } });
  const { toast, showToast, closeToast } = useToast();
  const [devStatus, setDevStatus] = useState<DevServerStatus | null>(null);
  const uiVersion = useMemo(() => getUiVersion(), []);

  useEffect(() => {
    let timer: number;
    (async () => {
      async function load() {
        try {
          let gatesRaw = await secureFetch('/gates/summary').then(r => r.ok ? r.json() : null).catch(() => null);
          if (!gatesRaw) {
            try {
              const origin = window.location.origin.replace(/\/$/, '');
              const r2 = await fetch(`${origin}/api/gates/summary`, { credentials: 'same-origin', headers: buildSecurityHeaders() as HeadersInit });
              if (r2.ok) gatesRaw = await r2.json();
            } catch { /* ignore */ }
          }
          const runsResp = await secureFetch('/scans/results').then(r => r.ok ? r.json() : []).catch(() => []);
          const toolsResp = await secureFetch('/tools/status').then(r => r.ok ? r.json() : null).catch(() => null);
          const actResp = await secureFetch('/scans/active').then(r => r.ok ? r.json() : { items: [] }).catch(() => ({ items: [] }));
          let mlSnap: MLSnapshot | null = null;
          if (roles.includes('admin')) {
            const th = await secureFetch('/ml/thresholds').then(r => r.ok ? r.json() : null).catch(() => null);
            const acc = await secureFetch('/ml/metrics/detection_accuracy/summary').then(r => r.ok ? r.json() : null).catch(() => null);
            mlSnap = { thresholds: th, accuracy: acc };
          }
          let audits: AuditEvent[] = [];
          if (roles.includes('admin')) {
            const ae = await secureFetch('/audit/events?limit=10').then(r => r.ok ? r.json() : null).catch(() => null);
            if (ae && Array.isArray(ae.items)) audits = ae.items;
          }
          const inf = await secureFetch('/info').then(r => r.ok ? r.json() : null).catch(() => null);
          let gates: GatesSummary | null = gatesRaw;
          if (gatesRaw && gatesRaw.summary && !gatesRaw.totals) {
            const toUpper = (v: unknown) => String(v || '').toUpperCase();
            const counts = { PASS: 0, WARN: 0, FAIL: 0 } as Record<string, number>;
            const s = gatesRaw.summary;
            const sections = (s as Record<string, unknown>).gates ? [(s as Record<string, unknown>).gates] : Object.values(s);
            sections.forEach((section: unknown) => {
              if (!section) return;
              if (Array.isArray(section)) {
                section.forEach((entry: Record<string, unknown>) => { const st = toUpper(entry?.status || entry?.gate_status || entry?.result); if (st === 'PASS' || st === 'WARN' || st === 'FAIL') counts[st]++; });
              } else if (typeof section === 'object') {
                Object.values(section as Record<string, unknown>).forEach((entry: unknown) => { const e = entry as Record<string, unknown>; const st = toUpper(e?.status || e?.gate_status || e?.result); if (st === 'PASS' || st === 'WARN' || st === 'FAIL') counts[st]++; });
              }
            });
            gates = { totals: counts as unknown as GatesTotals };
          }
          setRuns(Array.isArray(runsResp) ? runsResp.slice(0, 5) : []);
          const nextRunsCount = Array.isArray(runsResp) ? runsResp.length : 0;
          let serverDelta: { WARN?: number; FAIL?: number } | null = null;
          if (deltasAuto) {
            try {
              const d = await secureFetch('/gates/deltas').then(r => r.ok ? r.json() : null).catch(() => null);
              if (d && d.delta && (typeof d.delta.WARN === 'number' || typeof d.delta.FAIL === 'number')) serverDelta = d.delta;
            } catch { /* ignore */ }
          }
          if (serverDelta) {
            setGatesDelta(serverDelta);
          } else if (gates && gates.totals) {
            const prev = lastTotalsRef.current;
            const curr = { PASS: gates.totals.PASS || 0, WARN: gates.totals.WARN || 0, FAIL: gates.totals.FAIL || 0 };
            if (prev) {
              const delta: { WARN?: number; FAIL?: number } = {};
              const dWarn = Math.max(0, (curr.WARN - prev.WARN) || 0);
              const dFail = Math.max(0, (curr.FAIL - prev.FAIL) || 0);
              if (dWarn > 0) delta.WARN = dWarn;
              if (dFail > 0) { delta.FAIL = dFail; fireNotification('Gate violations', `${dFail} new gate failure${dFail > 1 ? 's' : ''} detected`); }
              setGatesDelta(Object.keys(delta).length ? delta : null);
            } else { setGatesDelta(null); }
            lastTotalsRef.current = curr;
          } else { setGatesDelta(null); }
          setSummary(prev => ({ gates: gates || prev?.gates || null, runsCount: nextRunsCount }));
          setTools(toolsResp);
          setActive(Array.isArray(actResp?.items) ? actResp.items : []);
          setMlSnapshot(mlSnap);
          setApiInfo(inf);
          setAuditEvents(audits);
          setIsLoading(false);
          try {
            if (roles.some(r => r === 'admin' || r === 'analyst')) {
              const ds = await secureFetch('/dev/servers/status').then(r => r.ok ? r.json() : null).catch(() => null);
              setDevStatus(ds);
            }
          } catch { /* ignore */ }
          try { setLastRefreshIso(new Date().toISOString()); } catch { /* ignore */ }
        } catch (e: unknown) {
          setError((e as Error)?.message || 'Failed to load dashboard');
          setRuns([]); setSummary({ gates: null, runsCount: 0 }); setTools(null); setActive([]);
          setGatesDelta(null); setMlSnapshot(null); setApiInfo(null); setAuditEvents([]);
          setIsLoading(false);
          try { setLastRefreshIso(new Date().toISOString()); } catch { /* ignore */ }
        }
      }
      await load();
      const cfgMs = (() => { try { const v = localStorage.getItem('aodsConfig_dashRefresh'); const n = v ? JSON.parse(v) : 0; return typeof n === 'number' && n > 0 ? n * 1000 : 15000; } catch { return 15000; } })();
      timer = window.setInterval(load, cfgMs);
    })();
    return () => { if (timer) window.clearInterval(timer); };
  }, []);

  useEffect(() => { try { localStorage.setItem('aodsGatesDeltasAuto', deltasAuto ? '1' : '0'); } catch { /* ignore */ } }, [deltasAuto]);

  // SSE for active scans
  useEffect(() => {
    const sources: EventSource[] = [];
    const timers: ReturnType<typeof setTimeout>[] = [];
    let cancelled = false;
    const tokenParam = auth.token ? `?token=${encodeURIComponent(auth.token)}` : '';
    (async () => {
      const base = await getApiBase();
      if (cancelled) return;
      (active || []).forEach((s) => {
        let retries = 0;
        function connect() {
          if (cancelled) return;
          try {
            const es = new EventSource(`${base}/scans/${encodeURIComponent(s.id)}/progress/stream${tokenParam}`);
            sources.push(es);
            es.onopen = () => { retries = 0; };
            es.onmessage = (ev) => { try { const d = JSON.parse(ev.data || '{}'); setActive((prev) => prev.map((x) => x.id === s.id ? { ...x, pct: d.pct, stage: d.stage } : x)); } catch { /* ignore */ } };
            es.addEventListener('end', () => { try { es.close(); } catch { /* ignore */ } });
            es.onerror = () => { try { es.close(); } catch { /* ignore */ } if (cancelled) return; retries++; timers.push(setTimeout(connect, Math.min(10000, 500 * Math.pow(2, retries - 1)))); };
          } catch { /* ignore */ }
        }
        connect();
      });
    })();
    return () => { cancelled = true; sources.forEach((es) => { try { es.close(); } catch { /* ignore */ } }); timers.forEach((t) => clearTimeout(t)); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active.map(a => a.id).join(','), auth.token]);

  async function refreshDeltas() {
    try { setLastRefreshIso(new Date().toISOString()); } catch { /* ignore */ }
    try { const d = await secureFetch('/gates/deltas').then(r => r.ok ? r.json() : null).catch(() => null); setGatesDelta(d?.delta || null); } catch { /* ignore */ }
  }

  const trendData = runs.map(r => r.summary?.findings ?? 0);
  const scanTrendsContent = trendData.length < 2
    ? <Typography variant="body2" color="text.secondary">Not enough scan data for trends</Typography>
    : (() => {
        const latest = runs[runs.length - 1]?.summary;
        const previous = runs[runs.length - 2]?.summary;
        const delta = latest && previous ? (latest.findings ?? 0) - (previous.findings ?? 0) : null;
        return (
          <Stack spacing={1}>
            <TrendChart data={trendData} labels={runs.map(r => r.apkName || r.id)} width={280} height={60} />
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              {delta !== null && (
                <Chip
                  size="small"
                  label={delta > 0 ? `+${delta} new` : delta < 0 ? `${delta} fewer` : 'No change'}
                  color={delta > 0 ? 'warning' : delta < 0 ? 'success' : 'default'}
                  data-testid="trend-delta"
                />
              )}
              {latest && (
                <>
                  {(latest.critical ?? 0) > 0 && <Chip size="small" label={`Critical: ${latest.critical}`} color="error" />}
                  {(latest.high ?? 0) > 0 && <Chip size="small" label={`High: ${latest.high}`} color="warning" />}
                  {(latest.medium ?? 0) > 0 && <Chip size="small" label={`Medium: ${latest.medium}`} />}
                </>
              )}
            </Stack>
          </Stack>
        );
      })();

  const lastRefreshLabel = formatTime(lastRefreshIso);

  const handleRetry = useCallback(() => {
    setError(null);
    setIsLoading(true);
  }, []);

  return (
    <Box>
      <PageHeader title="Dashboard" subtitle="System overview and recent activity" />
      <ErrorDisplay error={error} onRetry={handleRetry} />
      {isLoading ? (
        <LoadingSkeleton variant="card" />
      ) : (
        <Grid container spacing={2}>
          {visCards.includes('Gates Summary') && <DashboardOverview runsCount={summary.runsCount} gates={summary.gates} deltasAuto={deltasAuto} onDeltasAutoChange={setDeltasAuto} gatesDelta={gatesDelta} onRefreshDeltas={refreshDeltas} />}
          {(visCards.includes('Recent Scans') || visCards.includes('Active Scans')) && <DashboardActivity runs={runs} active={active} roles={roles} />}
          {visCards.includes('Tool Status') && <DashboardHealth tools={tools} showFrida={roles.some(r => r === 'admin' || r === 'analyst')} />}
          {roles.includes('admin') && <DashboardDevServers devStatus={devStatus} setDevStatus={setDevStatus} />}

          {/* Scan Trends */}
          {visCards.includes('Scan Trends') && (
            <Grid item xs={12} data-testid="scan-trends-card">
              <DataCard title="Scan Trends">
                {scanTrendsContent}
              </DataCard>
            </Grid>
          )}

          {/* ML Snapshot - only show if data available */}
          {roles.includes('admin') && mlSnapshot && (mlSnapshot.thresholds || mlSnapshot.accuracy) && (
            <Grid item xs={12} md={6}>
              <DataCard title="ML Snapshot">
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  {mlSnapshot.thresholds && <Chip size="small" label={`Default threshold: ${mlSnapshot.thresholds.default ?? 'n/a'}`} variant="outlined" />}
                  {mlSnapshot.accuracy && typeof mlSnapshot.accuracy.pass_rate !== 'undefined' && (
                    <Chip size="small" color="success" label={`Pass rate: ${Math.round((mlSnapshot.accuracy.pass_rate || 0) * 100)}%`} />
                  )}
                  {mlSnapshot.accuracy && typeof mlSnapshot.accuracy.failed !== 'undefined' && mlSnapshot.accuracy.failed > 0 && (
                    <Chip size="small" color="error" label={`${mlSnapshot.accuracy.failed} failed`} />
                  )}
                  <Box sx={{ flex: 1 }} />
                  <Button size="small" variant="text" component={Link} to="/ml">Details</Button>
                </Stack>
              </DataCard>
            </Grid>
          )}

          {/* Recent Audit Events - only show if events exist */}
          {roles.includes('admin') && auditEvents.length > 0 && (
            <Grid item xs={12} md={mlSnapshot ? 6 : 12}>
              <DataCard title="Recent Activity" actions={<Button size="small" variant="text" onClick={async () => { try { const r = await secureFetch('/audit/export'); if (!r.ok) return; const blob = await r.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'audit_export.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 15000); showToast('Audit exported'); } catch { showToast('Export failed', 'error'); } }}>Export</Button>}>
                <Stack spacing={0}>
                  {auditEvents.slice(0, 5).map((ev, idx) => (
                    <Stack key={idx} direction="row" alignItems="center" spacing={1} sx={{ py: 0.5, '&:not(:last-child)': { borderBottom: 1, borderColor: 'divider' } }}>
                      <Chip size="small" label={ev.action} sx={{ fontSize: 10, fontWeight: 600, height: 20 }} />
                      <Typography variant="body2" color="text.secondary" sx={{ flex: 1, fontSize: 12 }}>
                        {ev.user || 'user'}
                        {ev.resource ? <> &middot; <Box component="code" sx={{ fontSize: 10 }}>{String(ev.resource).slice(0, 40)}</Box></> : null}
                      </Typography>
                      {ev.timestamp && <Typography variant="caption" color="text.disabled" sx={{ whiteSpace: 'nowrap', fontSize: 10 }}>{formatTime(ev.timestamp)}</Typography>}
                    </Stack>
                  ))}
                </Stack>
              </DataCard>
            </Grid>
          )}

          {/* Footer */}
          <Grid item xs={12}>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ px: 1, py: 1.5, borderTop: 1, borderColor: 'divider', mt: 1 }}>
              <Typography variant="caption" color="text.disabled">
                API {apiInfo?.apiVersion || 'n/a'} &middot; UI {uiVersion}
              </Typography>
              <Typography variant="caption" color="text.disabled">
                Last refresh {lastRefreshLabel}
              </Typography>
            </Stack>
          </Grid>
        </Grid>
      )}
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
