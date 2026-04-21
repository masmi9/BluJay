import { useEffect, useMemo, useState } from 'react';
import { secureFetch } from '../lib/api';
import { formatDateTime, sevSummary } from '../lib/format';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  IconButton,
  InputLabel,
  ListItemText,
  MenuItem,
  Select,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tooltip,
  Typography,
  Paper,
} from '@mui/material';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import { PageHeader, SeverityChip, ErrorDisplay, LoadingSkeleton } from '../components';
import type { ScanResult, AttackSurfaceGraph, AttackSurfaceNode, AttackSurfaceEdge, DiffStatus } from '../types';
import { AODSApiClient } from '../services/api';
import { lazy, Suspense } from 'react';

const AttackSurfaceGraphView = lazy(() => import('../components/AttackSurfaceGraph/AttackSurfaceGraph'));

type Finding = {
  title: string;
  severity: string;
  cwe_id?: string;
  confidence?: number;
  file_path?: string;
  category?: string;
};

type DiffEntry = {
  key: string;
  finding: Finding;
  counterpart?: Finding;
  status: 'added' | 'removed' | 'changed' | 'unchanged';
};

function computeDiff(findingsA: Finding[], findingsB: Finding[]): DiffEntry[] {
  const keyFn = (f: Finding) => `${f.title}||${f.cwe_id || ''}`;
  const mapA = new Map(findingsA.map(f => [keyFn(f), f]));
  const mapB = new Map(findingsB.map(f => [keyFn(f), f]));

  const result: DiffEntry[] = [];

  for (const [k, f] of mapB) {
    if (!mapA.has(k)) result.push({ key: k, finding: f, status: 'added' });
  }
  for (const [k, f] of mapA) {
    if (!mapB.has(k)) result.push({ key: k, finding: f, status: 'removed' });
  }
  for (const [k, fB] of mapB) {
    const fA = mapA.get(k);
    if (!fA) continue;
    const changed = fA.severity !== fB.severity || fA.confidence !== fB.confidence;
    result.push({ key: k, finding: fB, counterpart: fA, status: changed ? 'changed' : 'unchanged' });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Attack Surface Diff
// ---------------------------------------------------------------------------

type NodeDiff = {
  id: string;
  nodeType: string;
  label: string;
  status: 'added' | 'removed' | 'changed' | 'unchanged';
  findingsA: number;
  findingsB: number;
  severityA: string | null;
  severityB: string | null;
  exportedA?: boolean;
  exportedB?: boolean;
};

function diffGraphs(graphA: AttackSurfaceGraph | null, graphB: AttackSurfaceGraph | null): NodeDiff[] {
  if (!graphA && !graphB) return [];
  const compTypes = new Set(['activity', 'service', 'receiver', 'provider']);
  const nodesA = new Map((graphA?.nodes || []).filter(n => compTypes.has(n.node_type)).map(n => [n.id, n]));
  const nodesB = new Map((graphB?.nodes || []).filter(n => compTypes.has(n.node_type)).map(n => [n.id, n]));
  const diffs: NodeDiff[] = [];

  for (const [id, n] of nodesB) {
    if (!nodesA.has(id)) {
      diffs.push({ id, nodeType: n.node_type, label: n.label, status: 'added', findingsA: 0, findingsB: n.findings.length, severityA: null, severityB: n.severity, exportedB: n.metadata?.exported });
    }
  }
  for (const [id, n] of nodesA) {
    if (!nodesB.has(id)) {
      diffs.push({ id, nodeType: n.node_type, label: n.label, status: 'removed', findingsA: n.findings.length, findingsB: 0, severityA: n.severity, severityB: null, exportedA: n.metadata?.exported });
    }
  }
  for (const [id, nB] of nodesB) {
    const nA = nodesA.get(id);
    if (!nA) continue;
    const changed = nA.findings.length !== nB.findings.length || nA.severity !== nB.severity || nA.metadata?.exported !== nB.metadata?.exported;
    diffs.push({ id, nodeType: nB.node_type, label: nB.label, status: changed ? 'changed' : 'unchanged', findingsA: nA.findings.length, findingsB: nB.findings.length, severityA: nA.severity, severityB: nB.severity, exportedA: nA.metadata?.exported, exportedB: nB.metadata?.exported });
  }
  return diffs;
}

/** Merge two attack surface graphs into one + diff annotations */
function mergeGraphs(
  graphA: AttackSurfaceGraph | null,
  graphB: AttackSurfaceGraph | null,
): { merged: AttackSurfaceGraph; annotations: Map<string, DiffStatus> } {
  const annotations = new Map<string, DiffStatus>();
  const nodesA = new Map((graphA?.nodes || []).map(n => [n.id, n]));
  const nodesB = new Map((graphB?.nodes || []).map(n => [n.id, n]));
  const mergedNodes: AttackSurfaceNode[] = [];
  const allIds = new Set([...nodesA.keys(), ...nodesB.keys()]);

  for (const id of allIds) {
    const nA = nodesA.get(id);
    const nB = nodesB.get(id);
    if (nB && !nA) {
      mergedNodes.push(nB);
      annotations.set(id, 'added');
    } else if (nA && !nB) {
      mergedNodes.push(nA);
      annotations.set(id, 'removed');
    } else if (nA && nB) {
      mergedNodes.push(nB);
      const changed = nA.findings.length !== nB.findings.length || nA.severity !== nB.severity || nA.metadata?.exported !== nB.metadata?.exported;
      annotations.set(id, changed ? 'changed' : 'unchanged');
    }
  }

  // Merge edges (union, deduplicated by source+target+relationship)
  const edgeKey = (e: AttackSurfaceEdge) => `${e.source}|${e.target}|${e.relationship}`;
  const edgeMap = new Map<string, AttackSurfaceEdge>();
  for (const e of [...(graphA?.edges || []), ...(graphB?.edges || [])]) {
    edgeMap.set(edgeKey(e), e);
  }

  const merged: AttackSurfaceGraph = {
    nodes: mergedNodes,
    edges: Array.from(edgeMap.values()),
    stats: {
      total_components: mergedNodes.filter(n => ['activity', 'service', 'receiver', 'provider'].includes(n.node_type)).length,
      exported: mergedNodes.filter(n => n.metadata?.exported).length,
      permissions: mergedNodes.filter(n => n.node_type === 'permission').length,
      deep_links: mergedNodes.filter(n => n.node_type === 'deep_link').length,
      findings_mapped: 0,
      attack_chains: 0,
      total_findings: 0,
    },
  };
  return { merged, annotations };
}

const NODE_TYPE_ICON: Record<string, string> = { activity: '\u{1F4F1}', service: '\u{2699}', receiver: '\u{1F4E1}', provider: '\u{1F5C4}' };

type FilterType = 'all' | 'added' | 'removed' | 'changed';

export function ScanCompare() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [scanA, setScanA] = useState('');
  const [scanB, setScanB] = useState('');
  const [findingsA, setFindingsA] = useState<Finding[]>([]);
  const [findingsB, setFindingsB] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterType>('all');
  const [viewTab, setViewTab] = useState(0);
  const [graphA, setGraphA] = useState<AttackSurfaceGraph | null>(null);
  const [graphB, setGraphB] = useState<AttackSurfaceGraph | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [surfaceFilter, setSurfaceFilter] = useState<FilterType>('all');

  const api = useMemo(() => new AODSApiClient(), []);

  useEffect(() => {
    (async () => {
      try {
        const r = await secureFetch('/scans/results');
        if (!r.ok) return;
        const data = await r.json();
        setScans(Array.isArray(data) ? data : data.items || []);
      } catch {}
    })();
  }, []);

  useEffect(() => {
    if (!scanA || !scanB) return;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const [rA, rB] = await Promise.all([
          secureFetch(`/scans/result/${encodeURIComponent(scanA)}`),
          secureFetch(`/scans/result/${encodeURIComponent(scanB)}`),
        ]);
        if (!rA.ok || !rB.ok) throw new Error('Failed to load scan results');
        const dA = await rA.json();
        const dB = await rB.json();
        const extract = (d: any): Finding[] => {
          const raw = d?.vulnerabilities || d?.findings || [];
          return Array.isArray(raw) ? raw.map((f: any) => ({
            title: f.title || f.name || 'Untitled',
            severity: f.severity || 'INFO',
            cwe_id: f.cwe_id || (f.cwe_ids?.[0]),
            confidence: typeof f.confidence === 'number' ? f.confidence : undefined,
            file_path: f.file_path || f.location,
            category: f.category,
          })) : [];
        };
        setFindingsA(extract(dA));
        setFindingsB(extract(dB));
      } catch (e: any) {
        setError(e?.message || 'Load failed');
      } finally {
        setLoading(false);
      }
    })();
  }, [scanA, scanB]);

  useEffect(() => {
    if (!scanA || !scanB) { setGraphA(null); setGraphB(null); return; }
    setGraphLoading(true);
    Promise.all([
      api.getAttackSurface(scanA).catch(() => null),
      api.getAttackSurface(scanB).catch(() => null),
    ]).then(([a, b]) => { setGraphA(a); setGraphB(b); })
      .finally(() => setGraphLoading(false));
  }, [scanA, scanB, api]);

  const diff = useMemo(() => computeDiff(findingsA, findingsB), [findingsA, findingsB]);
  const filtered = useMemo(() => filter === 'all' ? diff : diff.filter(d => d.status === filter), [diff, filter]);
  const counts = useMemo(() => { const c = { added: 0, removed: 0, changed: 0, unchanged: 0 }; diff.forEach(d => c[d.status]++); return c; }, [diff]);

  const surfaceDiff = useMemo(() => diffGraphs(graphA, graphB), [graphA, graphB]);
  const surfaceFiltered = useMemo(() => surfaceFilter === 'all' ? surfaceDiff : surfaceDiff.filter(d => d.status === surfaceFilter), [surfaceDiff, surfaceFilter]);
  const surfaceCounts = useMemo(() => { const c = { added: 0, removed: 0, changed: 0, unchanged: 0 }; surfaceDiff.forEach(d => c[d.status]++); return c; }, [surfaceDiff]);

  const sevCountsA = useMemo(() => { const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }; findingsA.forEach(f => { const s = (f.severity || 'INFO').toUpperCase(); if (s in c) c[s]++; }); return c; }, [findingsA]);
  const sevCountsB = useMemo(() => { const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }; findingsB.forEach(f => { const s = (f.severity || 'INFO').toUpperCase(); if (s in c) c[s]++; }); return c; }, [findingsB]);

  const scanMetaA = scans.find(s => s.id === scanA);
  const scanMetaB = scans.find(s => s.id === scanB);
  const hasBoth = scanA && scanB && findingsA.length + findingsB.length > 0;

  function handleSwap() {
    const tmpId = scanA; const tmpFindings = findingsA; const tmpGraph = graphA;
    setScanA(scanB); setScanB(tmpId); setFindingsA(findingsB); setFindingsB(tmpFindings); setGraphA(graphB); setGraphB(tmpGraph);
  }

  function renderScanMenuItem(s: ScanResult) {
    const date = formatDateTime(s.startedAt);
    const sev = sevSummary(s.summary);
    const total = s.summary?.findings;
    return (
      <MenuItem key={s.id} value={s.id}>
        <ListItemText
          primary={<Stack direction="row" spacing={1} alignItems="center"><Typography variant="body2" fontWeight={500} noWrap>{s.apkName || s.id}</Typography>{s.profile && <Chip label={s.profile} size="small" variant="outlined" sx={{ height: 20, fontSize: 11 }} />}</Stack>}
          secondary={<Typography variant="caption" color="text.secondary" component="span">{s.id}{date ? ` · ${date}` : ''}{total != null ? ` · ${total} findings` : ''}{sev ? ` (${sev})` : ''}</Typography>}
        />
      </MenuItem>
    );
  }

  return (
    <Box>
      <PageHeader title="Scan Comparison" subtitle="Select two scans to compare findings and attack surface" />

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems="center" sx={{ mb: 3 }}>
        <FormControl fullWidth>
          <InputLabel id="scan-a-label">Baseline (A)</InputLabel>
          <Select labelId="scan-a-label" value={scanA} label="Baseline (A)" onChange={e => setScanA(e.target.value)} data-testid="scan-a-picker"
            renderValue={v => { const s = scans.find(x => x.id === v); if (!s) return v; return `${s.apkName || s.id} [${s.profile || '?'}] ${formatDateTime(s.startedAt)}`; }}>
            {scans.map(renderScanMenuItem)}
          </Select>
        </FormControl>
        <Tooltip title="Swap scans A and B"><span>
          <IconButton onClick={handleSwap} disabled={!scanA || !scanB} aria-label="Swap scans" data-testid="swap-scans" sx={{ border: 1, borderColor: 'divider' }}><SwapHorizIcon /></IconButton>
        </span></Tooltip>
        <FormControl fullWidth>
          <InputLabel id="scan-b-label">Compare (B)</InputLabel>
          <Select labelId="scan-b-label" value={scanB} label="Compare (B)" onChange={e => setScanB(e.target.value)} data-testid="scan-b-picker"
            renderValue={v => { const s = scans.find(x => x.id === v); if (!s) return v; return `${s.apkName || s.id} [${s.profile || '?'}] ${formatDateTime(s.startedAt)}`; }}>
            {scans.map(renderScanMenuItem)}
          </Select>
        </FormControl>
      </Stack>

      {scanA && scanA === scanB && <Alert severity="warning" sx={{ mb: 2 }}>You selected the same scan for both A and B.</Alert>}
      {error && <ErrorDisplay error={error} />}
      {loading && <LoadingSkeleton variant="table" />}

      {!scanA && !scanB && (
        <Paper variant="outlined" sx={{ p: 6, textAlign: 'center', borderRadius: 2 }}>
          <CompareArrowsIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
          <Typography color="text.secondary" data-testid="empty-state">Select two scans above to compare their findings side-by-side.</Typography>
          <Typography variant="caption" color="text.disabled" sx={{ mt: 0.5, display: 'block' }}>Scan A is the baseline. Scan B is the comparison target.</Typography>
        </Paper>
      )}

      {hasBoth && (
        <>
          {/* Summary cards */}
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }} data-testid="comparison-summary">
            <Card variant="outlined" sx={{ flex: 1, borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}><Chip label="A" size="small" color="default" sx={{ fontWeight: 700, minWidth: 28 }} /><Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13 }}>{scanMetaA?.apkName || scanA}</Typography></Stack>
              {scanMetaA && <Stack direction="row" spacing={1} sx={{ mb: 1 }} useFlexGap flexWrap="wrap">{scanMetaA.profile && <Chip label={scanMetaA.profile} size="small" variant="outlined" />}{scanMetaA.startedAt && <Typography variant="caption" color="text.secondary" sx={{ lineHeight: '24px' }}>{formatDateTime(scanMetaA.startedAt)}</Typography>}</Stack>}
              <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums', mb: 0.5 }}>{findingsA.length} finding{findingsA.length !== 1 ? 's' : ''}</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>C:{sevCountsA.CRITICAL} H:{sevCountsA.HIGH} M:{sevCountsA.MEDIUM} L:{sevCountsA.LOW} I:{sevCountsA.INFO}</Typography>
            </CardContent></Card>

            <Card variant="outlined" sx={{ flex: 1, bgcolor: 'action.hover', borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, mb: 1 }}>Delta</Typography>
              <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap" sx={{ mb: 1 }}>
                <Chip label={`+${counts.added} new`} size="small" color="error" variant="outlined" />
                <Chip label={`-${counts.removed} fixed`} size="small" color="success" variant="outlined" />
                <Chip label={`~${counts.changed} changed`} size="small" color="warning" variant="outlined" />
                <Chip label={`=${counts.unchanged} same`} size="small" variant="outlined" />
              </Stack>
              <Typography variant="caption" color="text.secondary">{findingsA.length} → {findingsB.length} findings{findingsB.length > findingsA.length ? ` (+${findingsB.length - findingsA.length})` : findingsB.length < findingsA.length ? ` (${findingsB.length - findingsA.length})` : ' (no change)'}</Typography>
            </CardContent></Card>

            <Card variant="outlined" sx={{ flex: 1, borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}><Chip label="B" size="small" color="primary" sx={{ fontWeight: 700, minWidth: 28 }} /><Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13 }}>{scanMetaB?.apkName || scanB}</Typography></Stack>
              {scanMetaB && <Stack direction="row" spacing={1} sx={{ mb: 1 }} useFlexGap flexWrap="wrap">{scanMetaB.profile && <Chip label={scanMetaB.profile} size="small" variant="outlined" />}{scanMetaB.startedAt && <Typography variant="caption" color="text.secondary" sx={{ lineHeight: '24px' }}>{formatDateTime(scanMetaB.startedAt)}</Typography>}</Stack>}
              <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums', mb: 0.5 }}>{findingsB.length} finding{findingsB.length !== 1 ? 's' : ''}</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>C:{sevCountsB.CRITICAL} H:{sevCountsB.HIGH} M:{sevCountsB.MEDIUM} L:{sevCountsB.LOW} I:{sevCountsB.INFO}</Typography>
            </CardContent></Card>
          </Stack>

          {/* View tabs */}
          <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
            <Tabs value={viewTab} onChange={(_e, v) => setViewTab(v)}>
              <Tab label="Findings Diff" data-testid="findings-diff-tab" />
              <Tab label="Attack Surface Diff" data-testid="surface-diff-tab" />
            </Tabs>
          </Box>

          {/* Findings Diff Tab */}
          {viewTab === 0 && (
            <>
              <Stack direction="row" spacing={1} sx={{ mb: 2 }} useFlexGap flexWrap="wrap">
                {([['all', `All (${diff.length})`], ['added', `New (${counts.added})`], ['removed', `Fixed (${counts.removed})`], ['changed', `Changed (${counts.changed})`]] as [FilterType, string][]).map(([f, label]) => (
                  <Chip key={f} label={label} onClick={() => setFilter(f)} color={filter === f ? 'primary' : 'default'} variant={filter === f ? 'filled' : 'outlined'} data-testid={`filter-${f}`} />
                ))}
              </Stack>
              <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                <Table size="small" data-testid="diff-table">
                  <TableHead><TableRow>
                    <TableCell>Status</TableCell><TableCell>Title</TableCell><TableCell>CWE</TableCell><TableCell>File</TableCell><TableCell>Severity A</TableCell><TableCell>Severity B</TableCell><TableCell>Confidence</TableCell>
                  </TableRow></TableHead>
                  <TableBody>
                    {filtered.map((d, i) => (
                      <TableRow key={i} hover sx={{ opacity: d.status === 'unchanged' ? 0.7 : 1, ...(d.status !== 'unchanged' && { bgcolor: (theme) => { const p = d.status === 'added' ? theme.palette.error : d.status === 'removed' ? theme.palette.success : theme.palette.warning; return theme.palette.mode === 'dark' ? `${p.dark}22` : `${p.light}44`; } }) }}>
                        <TableCell><Chip label={d.status} size="small" color={d.status === 'added' ? 'error' : d.status === 'removed' ? 'success' : d.status === 'changed' ? 'warning' : 'default'} data-testid="status-chip" /></TableCell>
                        <TableCell><Typography variant="body2" fontWeight={d.status !== 'unchanged' ? 500 : 400}>{d.finding.title}</Typography></TableCell>
                        <TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{d.finding.cwe_id || '-'}</Typography></TableCell>
                        <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><Tooltip title={d.finding.file_path || d.counterpart?.file_path || ''}><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }} noWrap>{d.finding.file_path || d.counterpart?.file_path || '-'}</Typography></Tooltip></TableCell>
                        <TableCell>{d.status === 'added' ? <Typography variant="caption" color="text.disabled">{'\u2014'}</Typography> : <SeverityChip severity={d.counterpart?.severity || d.finding.severity} size="small" />}</TableCell>
                        <TableCell>{d.status === 'removed' ? <Typography variant="caption" color="text.disabled">{'\u2014'}</Typography> : <SeverityChip severity={d.finding.severity} size="small" />}</TableCell>
                        <TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{d.counterpart?.confidence != null && d.finding.confidence != null ? `${(d.counterpart.confidence * 100).toFixed(0)}% → ${(d.finding.confidence * 100).toFixed(0)}%` : d.finding.confidence != null ? `${(d.finding.confidence * 100).toFixed(0)}%` : '-'}</Typography></TableCell>
                      </TableRow>
                    ))}
                    {filtered.length === 0 && <TableRow><TableCell colSpan={7} align="center"><Typography color="text.secondary" sx={{ py: 2 }}>No findings match the selected filter.</Typography></TableCell></TableRow>}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}

          {/* Attack Surface Diff Tab */}
          {viewTab === 1 && (
            <>
              {graphLoading && <LoadingSkeleton variant="table" />}
              {!graphLoading && !graphA && !graphB && <Alert severity="info" data-testid="surface-diff-empty">No attack surface data available for these scans.</Alert>}
              {!graphLoading && (graphA || graphB) && (
                <>
                  <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }} data-testid="surface-summary">
                    <Card variant="outlined" sx={{ flex: 1, borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
                      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}><Chip label="A" size="small" color="default" sx={{ fontWeight: 700, minWidth: 28 }} /><Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13 }}>Attack Surface</Typography></Stack>
                      <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>{graphA?.stats.total_components ?? 0} components, {graphA?.stats.exported ?? 0} exported</Typography>
                      {(graphA?.stats.deep_links ?? 0) > 0 && <Typography variant="caption" color="text.secondary">{graphA?.stats.deep_links} deep links</Typography>}
                    </CardContent></Card>
                    <Card variant="outlined" sx={{ flex: 1, bgcolor: 'action.hover', borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, mb: 0.5 }}>Component Delta</Typography>
                      <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap">
                        <Chip label={`+${surfaceCounts.added} new`} size="small" color="error" variant="outlined" data-testid="surface-added" />
                        <Chip label={`-${surfaceCounts.removed} removed`} size="small" color="success" variant="outlined" data-testid="surface-removed" />
                        <Chip label={`~${surfaceCounts.changed} changed`} size="small" color="warning" variant="outlined" />
                        <Chip label={`=${surfaceCounts.unchanged} same`} size="small" variant="outlined" />
                      </Stack>
                    </CardContent></Card>
                    <Card variant="outlined" sx={{ flex: 1, borderRadius: 2 }}><CardContent sx={{ pb: '12px !important' }}>
                      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}><Chip label="B" size="small" color="primary" sx={{ fontWeight: 700, minWidth: 28 }} /><Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13 }}>Attack Surface</Typography></Stack>
                      <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>{graphB?.stats.total_components ?? 0} components, {graphB?.stats.exported ?? 0} exported</Typography>
                      {(graphB?.stats.deep_links ?? 0) > 0 && <Typography variant="caption" color="text.secondary">{graphB?.stats.deep_links} deep links</Typography>}
                    </CardContent></Card>
                  </Stack>

                  <Stack direction="row" spacing={1} sx={{ mb: 2 }} useFlexGap flexWrap="wrap">
                    {([['all', `All (${surfaceDiff.length})`], ['added', `New (${surfaceCounts.added})`], ['removed', `Removed (${surfaceCounts.removed})`], ['changed', `Changed (${surfaceCounts.changed})`]] as [FilterType, string][]).map(([f, label]) => (
                      <Chip key={f} label={label} onClick={() => setSurfaceFilter(f)} color={surfaceFilter === f ? 'primary' : 'default'} variant={surfaceFilter === f ? 'filled' : 'outlined'} data-testid={`surface-filter-${f}`} />
                    ))}
                  </Stack>

                  <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                    <Table size="small" data-testid="surface-diff-table">
                      <TableHead><TableRow>
                        <TableCell>Status</TableCell><TableCell>Type</TableCell><TableCell>Component</TableCell><TableCell>Exported</TableCell><TableCell>Findings A</TableCell><TableCell>Findings B</TableCell><TableCell>Severity</TableCell>
                      </TableRow></TableHead>
                      <TableBody>
                        {surfaceFiltered.map((d, i) => (
                          <TableRow key={i} hover sx={{ opacity: d.status === 'unchanged' ? 0.7 : 1, ...(d.status !== 'unchanged' && { bgcolor: (theme) => { const p = d.status === 'added' ? theme.palette.error : d.status === 'removed' ? theme.palette.success : theme.palette.warning; return theme.palette.mode === 'dark' ? `${p.dark}22` : `${p.light}44`; } }) }}>
                            <TableCell><Chip label={d.status} size="small" color={d.status === 'added' ? 'error' : d.status === 'removed' ? 'success' : d.status === 'changed' ? 'warning' : 'default'} /></TableCell>
                            <TableCell><Typography variant="body2">{NODE_TYPE_ICON[d.nodeType] || ''} {d.nodeType}</Typography></TableCell>
                            <TableCell><Typography variant="body2" fontWeight={d.status !== 'unchanged' ? 500 : 400}>{d.label}</Typography></TableCell>
                            <TableCell>
                              {d.status === 'added' ? (d.exportedB ? <Chip label="yes" size="small" color="warning" sx={{ height: 20 }} /> : <Typography variant="caption">no</Typography>)
                                : d.status === 'removed' ? (d.exportedA ? <Chip label="yes" size="small" color="warning" sx={{ height: 20 }} /> : <Typography variant="caption">no</Typography>)
                                : d.exportedA !== d.exportedB ? <Typography variant="body2" fontWeight={500}>{d.exportedA ? 'yes' : 'no'} → {d.exportedB ? 'yes' : 'no'}</Typography>
                                : <Typography variant="caption">{d.exportedB ? 'yes' : 'no'}</Typography>}
                            </TableCell>
                            <TableCell><Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>{d.findingsA}</Typography></TableCell>
                            <TableCell><Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: d.findingsA !== d.findingsB ? 600 : 400 }}>{d.findingsB}</Typography></TableCell>
                            <TableCell>
                              {d.severityA !== d.severityB ? (
                                <Stack direction="row" spacing={0.5} alignItems="center">
                                  {d.severityA && <SeverityChip severity={d.severityA} size="small" />}
                                  {d.severityA && d.severityB && <Typography variant="caption">→</Typography>}
                                  {d.severityB && <SeverityChip severity={d.severityB} size="small" />}
                                  {!d.severityA && !d.severityB && <Typography variant="caption" color="text.disabled">{'\u2014'}</Typography>}
                                </Stack>
                              ) : d.severityB ? <SeverityChip severity={d.severityB} size="small" /> : <Typography variant="caption" color="text.disabled">{'\u2014'}</Typography>}
                            </TableCell>
                          </TableRow>
                        ))}
                        {surfaceFiltered.length === 0 && <TableRow><TableCell colSpan={7} align="center"><Typography color="text.secondary" sx={{ py: 2 }}>No components match the selected filter.</Typography></TableCell></TableRow>}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {/* Merged diff graph visualization */}
                  {(graphA || graphB) && (() => {
                    const { merged, annotations } = mergeGraphs(graphA, graphB);
                    return merged.nodes.length > 0 ? (
                      <Box sx={{ mt: 3 }} data-testid="merged-diff-graph">
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>Visual Diff Graph</Typography>
                        <Suspense fallback={<CircularProgress size={24} />}>
                          <AttackSurfaceGraphView graphData={merged} diffAnnotations={annotations} />
                        </Suspense>
                      </Box>
                    ) : null;
                  })()}
                </>
              )}
            </>
          )}
        </>
      )}
    </Box>
  );
}
