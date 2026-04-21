import { useEffect, useMemo, useRef, useState } from 'react';
import { Box, IconButton, Stack, Tooltip, Typography } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { secureFetch } from '../lib/api';
import { formatTime } from '../lib/format';
import { GateItem, humanizeName } from '../components/GateCard';
import { PageHeader, ErrorDisplay, LoadingSkeleton } from '../components';
import { GateSummaryChips } from './gates/GateSummaryChips';
import { GateFilterBar } from './gates/GateFilterBar';
import { GateList } from './gates/GateList';

const STATUS_PRIORITY: Record<string, number> = { FAIL: 0, WARN: 1, PASS: 2 };

/** Fetch JSON from an artifacts/read endpoint, returning parsed content or null. */
async function readArtifact(subdir: string, relPath: string): Promise<any> {
  const r = await secureFetch(`/artifacts/read?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(relPath)}`);
  if (!r.ok) return null;
  const j = await r.json();
  return j && typeof j.content === 'string' ? JSON.parse(j.content) : (j || null);
}

/** Normalize status values to canonical PASS/WARN/FAIL. */
function normalizeStatus(raw: string): string {
  const s = raw.toUpperCase().trim();
  if (s === 'WARNING') return 'WARN';
  if (s === 'ERROR' || s === 'FAILURE' || s === 'FAILED') return 'FAIL';
  if (s === 'PASSED' || s === 'SUCCESS' || s === 'OK') return 'PASS';
  if (s === 'SKIPPED') return 'SKIP';
  return s;
}

/** Deduplicate timestamped gate files: keep only the latest per subdirectory. */
function deduplicateGates(items: GateItem[]): GateItem[] {
  const tsPattern = /\/summary_\d{8}T\d{6}Z\.json$/;
  const groups = new Map<string, GateItem[]>();
  const unique: GateItem[] = [];
  for (const item of items) {
    const rel = item.relPath || item.name;
    if (tsPattern.test(rel)) {
      const dir = rel.split('/')[0];
      const arr = groups.get(dir) || [];
      arr.push(item);
      groups.set(dir, arr);
    } else {
      unique.push(item);
    }
  }
  for (const entries of groups.values()) {
    const sorted = [...entries].sort((a, b) => {
      if (!a.mtime && !b.mtime) return 0;
      if (!a.mtime) return 1;
      if (!b.mtime) return -1;
      return new Date(b.mtime).getTime() - new Date(a.mtime).getTime();
    });
    unique.push(sorted[0]);
  }
  return unique;
}

/** Parse a gates summary response into normalized { totals, items }. */
function parseGatesSummary(j: any): { totals: Record<string, number>; items: GateItem[] } {
  let items: GateItem[] = [];
  let totals: Record<string, number> = {};

  if (j && (j.items || j.totals)) {
    items = (j.items || []).map((g: any) => ({
      ...g,
      status: g.status ? normalizeStatus(String(g.status)) : g.status,
    }));
    totals = j.totals || {};
  } else if (j?.summary) {
    const toUpper = (v: any) => normalizeStatus(String(v || ''));
    const counts: Record<string, number> = { PASS: 0, WARN: 0, FAIL: 0 };
    const sections = j.summary.gates ? [j.summary.gates] : Object.values(j.summary);
    for (const section of sections) {
      if (!section) continue;
      if (Array.isArray(section)) {
        section.forEach((entry: any, idx: number) => {
          const status = toUpper(entry?.status || entry?.gate_status || entry?.result || 'UNKNOWN');
          if (counts[status] !== undefined) counts[status]++;
          items.push({ name: entry?.name || `gate_${idx}`, status });
        });
      } else if (typeof section === 'object') {
        for (const [rel, entry] of Object.entries(section) as [string, any][]) {
          const status = toUpper(entry?.status || entry?.gate_status || entry?.result || 'UNKNOWN');
          if (counts[status] !== undefined) counts[status]++;
          const failures = Array.isArray(entry?.failures) ? entry.failures : [];
          const prevFail = typeof entry?.previous_failures === 'number' ? entry.previous_failures : null;
          let trend: 'up' | 'down' | 'flat' | undefined;
          if (typeof prevFail === 'number') {
            trend = failures.length > prevFail ? 'up' : failures.length < prevFail ? 'down' : 'flat';
          }
          items.push({ name: rel, relPath: rel, status, failures, trend });
        }
      }
    }
    totals = counts;
  }

  // Deduplicate timestamped files (e.g. detection_accuracy/summary_*.json)
  items = deduplicateGates(items);

  // Recompute totals from deduplicated items
  const freshTotals: Record<string, number> = { PASS: 0, WARN: 0, FAIL: 0 };
  for (const g of items) {
    const s = String(g.status || '').toUpperCase();
    if (s in freshTotals) freshTotals[s]++;
  }
  totals = freshTotals;

  return { totals, items };
}

export function GatesDashboard() {
  const [data, setData] = useState<{ totals?: any; items?: GateItem[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [pluginAudit, setPluginAudit] = useState(false);
  const [unknownFieldsReport, setUnknownFieldsReport] = useState(false);
  const [severityReport, setSeverityReport] = useState(false);
  const [severitySummary, setSeveritySummary] = useState<any>(null);
  const [calibMeta, setCalibMeta] = useState<{ family?: string; artifact?: string } | null>(null);
  const [gateQuery, setGateQuery] = useState(() => {
    try { return sessionStorage.getItem('gates.query') || ''; } catch { return ''; }
  });
  const [gateStatus, setGateStatus] = useState(() => {
    try { return sessionStorage.getItem('gates.status') || 'ALL'; } catch { return 'ALL'; }
  });
  const [gatesDelta, setGatesDelta] = useState<{ WARN?: number; FAIL?: number } | null>(null);
  const lastTotalsRef = useRef<{ PASS: number; WARN: number; FAIL: number } | null>(null);
  const [datasetVintage, setDatasetVintage] = useState<{ mtime?: string; size?: number } | null>(null);
  const [accuracySummaryPath, setAccuracySummaryPath] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(() => {
    try { return localStorage.getItem('gates.autoRefresh') === '1'; } catch { return false; }
  });
  const refreshTimerRef = useRef<number | null>(null);
  const [uiPerf, setUiPerf] = useState<{ render?: number; jankP95?: number; heapMb?: number; domNodes?: number; toggleAvgMs?: number } | null>(null);
  const [mlDrift, setMlDrift] = useState<{ chi2?: number; nBaseline?: number; nCurrent?: number } | null>(null);
  const [lastUpdatedIso, setLastUpdatedIso] = useState('');
  const [curationCounts, setCurationCounts] = useState<any>(null);
  const [baselineStale, setBaselineStale] = useState<any>(null);
  const [calibStale, setCalibStale] = useState<any>(null);
  const [mlStamps, setMlStamps] = useState<any>(null);
  const [promotion, setPromotion] = useState<any>(null);
  const [accuracyStrict, setAccuracyStrict] = useState(false);

  async function loadDashboard() {
    setLoading(true);
    try {
      // ---- Primary: gates summary ----
      const r = await secureFetch('/gates/summary');
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      const parsed = parseGatesSummary(j);
      setData(parsed);

      // ---- Deltas ----
      try {
        const d = await secureFetch('/gates/deltas').then(rr => rr.ok ? rr.json() : null).catch(() => null);
        if (d?.delta && (typeof d.delta.WARN === 'number' || typeof d.delta.FAIL === 'number')) {
          setGatesDelta(d.delta);
        } else {
          // Compute delta from previous totals if available
          const prev = lastTotalsRef.current;
          const curr = { PASS: parsed.totals.PASS || 0, WARN: parsed.totals.WARN || 0, FAIL: parsed.totals.FAIL || 0 };
          if (prev) {
            const delta: Record<string, number> = {};
            const dWarn = Math.max(0, curr.WARN - prev.WARN);
            const dFail = Math.max(0, curr.FAIL - prev.FAIL);
            if (dWarn > 0) delta.WARN = dWarn;
            if (dFail > 0) delta.FAIL = dFail;
            setGatesDelta(Object.keys(delta).length ? delta : null);
          } else {
            setGatesDelta(null);
          }
          lastTotalsRef.current = curr;
        }
      } catch { /* ignore delta errors */ }

      // ---- Artifact probes (run concurrently) ----
      const [calibRaw, accRaw, accAltRaw, perfRaw, baseRaw, calibStaleRaw, mlStampsRaw, promoRaw, sevRaw, curationRaw] = await Promise.allSettled([
        readArtifact('ci_gates', 'ml_calibration_quality/summary.json'),
        readArtifact('ci_gates', 'detection_accuracy_summary.json'),
        readArtifact('ci_gates', 'detection_accuracy/summary.json'),
        readArtifact('ui_perf', 'perf_metrics.json'),
        readArtifact('ci_gates', 'baseline_staleness/summary.json'),
        readArtifact('ci_gates', 'calibration_staleness/summary.json'),
        readArtifact('ci_gates', 'ml_version_stamps/summary.json'),
        readArtifact('ci_gates', 'promotion_suggester/summary.json'),
        readArtifact('ci_gates', 'severity/summary.json'),
        secureFetch('/curation/summary').then(rr => rr.ok ? rr.json() : null).catch(() => null),
      ]);

      const val = (r: PromiseSettledResult<any>) => r.status === 'fulfilled' ? r.value : null;

      // Calibration meta
      const calib = val(calibRaw);
      setCalibMeta(calib ? { family: calib.family || calib.thresholds?.family, artifact: calib.artifact || calib.summary } : null);

      // Detection accuracy
      const acc = val(accRaw) || val(accAltRaw);
      if (acc) {
        setDatasetVintage({ mtime: acc.dataset_mtime, size: typeof acc.dataset_size_bytes === 'number' ? acc.dataset_size_bytes : undefined });
        setAccuracySummaryPath(val(accRaw) ? 'detection_accuracy_summary.json' : 'detection_accuracy/summary.json');
        setAccuracyStrict(Boolean(acc.strict));
      } else {
        setDatasetVintage(null);
        setAccuracySummaryPath(null);
        setAccuracyStrict(false);
      }

      // UI perf
      const perf = val(perfRaw);
      if (perf && typeof perf === 'object') {
        setUiPerf({
          render: typeof perf.render_time_ms === 'number' ? perf.render_time_ms : undefined,
          jankP95: typeof perf.jank_p95_ms === 'number' ? perf.jank_p95_ms : undefined,
          heapMb: typeof perf.heap_used_mb === 'number' ? perf.heap_used_mb : undefined,
          domNodes: typeof perf.dom_nodes_count === 'number' ? perf.dom_nodes_count : undefined,
          toggleAvgMs: typeof perf.toggle_avg_ms === 'number' ? perf.toggle_avg_ms : undefined,
        });
      } else {
        setUiPerf(null);
      }

      // Staleness & stamps
      setBaselineStale(val(baseRaw));
      setCalibStale(val(calibStaleRaw));
      setMlStamps(val(mlStampsRaw));
      setPromotion(val(promoRaw));

      // Severity gate
      const sev = val(sevRaw);
      setSeverityReport(!!sev);
      setSeveritySummary(sev);

      // Curation
      setCurationCounts(val(curationRaw));

      // ---- ML Drift (chi-square) ----
      try {
        const [baseConf, currConf] = await Promise.all([
          readArtifact('ml_datasets/metrics', 'baseline_confidences.json'),
          readArtifact('ml_datasets/metrics', 'current_confidences.json'),
        ]);
        const bvals: number[] = (baseConf?.confidences || []).map(Number).filter(isFinite);
        const cvals: number[] = (currConf?.confidences || []).map(Number).filter(isFinite);
        if (bvals.length >= 100 && cvals.length >= 100) {
          const bins = 10;
          const hist = (vals: number[]) => {
            const counts = Array(bins).fill(0);
            for (const raw of vals) counts[Math.min(Math.floor(Math.max(0, Math.min(1, raw)) * bins), bins - 1)]++;
            return counts;
          };
          const hb = hist(bvals), hc = hist(cvals);
          const tb = hb.reduce((a, b) => a + b, 0) || 1;
          const tc = hc.reduce((a, b) => a + b, 0) || 1;
          let chi2 = 0;
          for (let i = 0; i < bins; i++) {
            const e = Math.max((hb[i] / tb) * tc, 1e-6);
            chi2 += ((hc[i] - e) ** 2) / e;
          }
          setMlDrift({ chi2, nBaseline: bvals.length, nCurrent: cvals.length });
        } else {
          setMlDrift(null);
        }
      } catch { setMlDrift(null); }

      // ---- Plugin audit & unknown fields probes ----
      try {
        const par = await secureFetch('/artifacts/list?subdir=plugin_audit');
        setPluginAudit(par.ok && ((await par.json())?.items?.length > 0));
      } catch { setPluginAudit(false); }

      try {
        const ufr = await secureFetch(`/artifacts/read?subdir=ci_gates&relPath=${encodeURIComponent('unknown_fields/summary.json')}`);
        setUnknownFieldsReport(ufr.ok);
      } catch { setUnknownFieldsReport(false); }

    } catch (e: any) {
      setError(e?.message || 'Failed to load gates summary');
    } finally {
      setLoading(false);
      try { setLastUpdatedIso(new Date().toISOString()); } catch {}
    }
  }

  // ---- Centralized filtering ----
  const allItems = data?.items || [];
  const hasItems = allItems.length > 0;

  // Step 1: text filter - match against both raw name AND humanized name
  const textFiltered = useMemo(() => {
    if (!gateQuery) return allItems;
    const q = gateQuery.toLowerCase();
    return allItems.filter((g) => {
      const raw = (g.name || '').toLowerCase();
      const display = humanizeName(g.name).toLowerCase();
      return raw.includes(q) || display.includes(q);
    });
  }, [allItems, gateQuery]);

  // Step 2: compute status counts from the text-filtered set
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = { PASS: 0, WARN: 0, FAIL: 0 };
    for (const g of textFiltered) {
      const s = String(g.status || '').toUpperCase();
      if (s in counts) counts[s]++;
    }
    return counts;
  }, [textFiltered]);

  // Step 3: auto-reset stale persisted status filter on FIRST data load only.
  //   If sessionStorage had e.g. "FAIL" but the new data has 0 FAILs, reset to ALL.
  //   Only fires once - never during active use.
  const didInitialResetRef = useRef(false);
  useEffect(() => {
    if (didInitialResetRef.current || !hasItems || gateStatus === 'ALL') return;
    didInitialResetRef.current = true;
    const count = statusCounts[gateStatus] ?? 0;
    if (count === 0) {
      setGateStatus('ALL');
    }
  }, [hasItems]); // eslint-disable-line react-hooks/exhaustive-deps -- intentionally first-load only

  // Step 4: status filter + sort by priority (FAIL → WARN → PASS)
  const filtered = useMemo(() => {
    const result = gateStatus === 'ALL'
      ? textFiltered
      : textFiltered.filter((g) => String(g.status || '').toUpperCase() === gateStatus);
    return [...result].sort((a, b) =>
      (STATUS_PRIORITY[String(a.status).toUpperCase()] ?? 3) - (STATUS_PRIORITY[String(b.status).toUpperCase()] ?? 3)
    );
  }, [textFiltered, gateStatus]);

  const hasActiveFilters = gateQuery !== '' || gateStatus !== 'ALL';
  const clearFilters = () => { setGateQuery(''); setGateStatus('ALL'); };

  // Persist filter state
  useEffect(() => { try { sessionStorage.setItem('gates.query', gateQuery); } catch {} }, [gateQuery]);
  useEffect(() => { try { sessionStorage.setItem('gates.status', gateStatus); } catch {} }, [gateStatus]);
  useEffect(() => { try { localStorage.setItem('gates.autoRefresh', autoRefresh ? '1' : '0'); } catch {} }, [autoRefresh]);

  useEffect(() => { loadDashboard(); }, []);

  useEffect(() => {
    if (refreshTimerRef.current) {
      window.clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    if (autoRefresh) {
      refreshTimerRef.current = window.setInterval(loadDashboard, 30_000);
    }
    return () => {
      if (refreshTimerRef.current) {
        window.clearInterval(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [autoRefresh]);

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title="CI Gates Dashboard"
          subtitle="Quality gate results from CI pipelines"
          actions={
            <Stack direction="row" spacing={1} alignItems="center">
              {lastUpdatedIso && (
                <Typography variant="caption" color="text.disabled" aria-label="Last updated" sx={{ fontVariantNumeric: 'tabular-nums', fontSize: 11 }}>
                  {lastUpdatedIso ? `Updated ${formatTime(lastUpdatedIso)}` : ''}
                </Typography>
              )}
              <Tooltip title="Refresh gates data">
                <IconButton size="small" aria-label="Refresh gate deltas" onClick={() => loadDashboard()} disabled={loading}>
                  <RefreshIcon sx={{ fontSize: 18, transition: 'transform 0.3s', ...(loading && { animation: 'spin 1s linear infinite', '@keyframes spin': { '100%': { transform: 'rotate(360deg)' } } }) }} />
                </IconButton>
              </Tooltip>
            </Stack>
          }
        />
        <ErrorDisplay error={error} onRetry={loadDashboard} />
        {!data ? (
          <LoadingSkeleton variant="card" />
        ) : (
          <>
            {data.totals && (
              <GateSummaryChips
                totals={data.totals}
                gatesDelta={gatesDelta}
                calibMeta={calibMeta}
                datasetVintage={datasetVintage}
                accuracySummaryPath={accuracySummaryPath}
                accuracyStrict={accuracyStrict}
                uiPerf={uiPerf}
                mlDrift={mlDrift}
                baselineStale={baselineStale}
                calibStale={calibStale}
                mlStamps={mlStamps}
                promotion={promotion}
                curationCounts={curationCounts}
              />
            )}
            {hasItems && (
              <GateFilterBar
                gateQuery={gateQuery}
                setGateQuery={setGateQuery}
                gateStatus={gateStatus}
                setGateStatus={setGateStatus}
                autoRefresh={autoRefresh}
                setAutoRefresh={setAutoRefresh}
                totalCount={allItems.length}
                filteredCount={filtered.length}
                textFilteredCount={textFiltered.length}
                statusCounts={statusCounts}
              />
            )}
            <GateList
              items={filtered}
              totalCount={allItems.length}
              hasActiveFilters={hasActiveFilters}
              gateQuery={gateQuery}
              gateStatus={gateStatus}
              onClearFilters={clearFilters}
              pluginAudit={pluginAudit}
              unknownFieldsReport={unknownFieldsReport}
              severityReport={severityReport}
              severitySummary={severitySummary}
            />
          </>
        )}
      </Stack>
    </Box>
  );
}
