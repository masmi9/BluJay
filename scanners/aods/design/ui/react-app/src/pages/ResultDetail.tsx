import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { secureFetch } from '../lib/api';
import { useParams } from 'react-router-dom';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  FormControlLabel,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Tooltip,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import { PageHeader, ErrorDisplay, LoadingSkeleton, SeverityChip, FindingsTable, ExplainDialog, FindingDetailDrawer, AppToast, AttackSurfaceGraph, EmptyState } from '../components';
import type { Finding } from '../components';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../hooks/useToast';
import { formatDateTime } from '../lib/format';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import WarningIcon from '@mui/icons-material/Warning';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import BugReportIcon from '@mui/icons-material/BugReport';
import LinkIcon from '@mui/icons-material/Link';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import type { AgenticAnalysis, VerificationData, FindingVerification, OrchestrationData, PluginSelection, TriageData, ClassifiedFinding as ClassifiedFindingType, FindingGroup as FindingGroupType, RemediationData, FindingRemediation, TriageFeedbackHistoryItem } from '../types';
import { AODSApiClient } from '../services/api';

// Schema type definition
interface ResultSchema {
  topLevelKeys?: string[];
  findingKeys?: string[];
  apkInfoKeys?: string[];
  severityLevels?: string[];
  statusValues?: string[];
  version?: string;
}

// JSON Node with unknown field highlighting
interface JsonNodeProps {
  label: string;
  value: unknown;
  depth: number;
  knownKeys?: Set<string>;
  isUnknown?: boolean;
  showOnlyUnknown?: boolean;
  defaultExpanded?: boolean;
}

const MAX_DEPTH = 25;
const MAX_COLLAPSED_ITEMS = 5;

function JsonNode({
  label,
  value,
  depth,
  knownKeys,
  isUnknown = false,
  showOnlyUnknown = false,
  defaultExpanded = false,
}: JsonNodeProps) {
  const [expanded, setExpanded] = useState(defaultExpanded || depth < 2);

  if (depth > MAX_DEPTH) {
    return (
      <Typography component="span" sx={{ color: 'warning.main', ml: depth * 1.5 }}>
        [Max depth exceeded]
      </Typography>
    );
  }

  const isObject = value !== null && typeof value === 'object';
  const isArray = Array.isArray(value);
  const keyIsUnknown = isUnknown || (knownKeys && !!label && !knownKeys.has(label));

  if (!isObject) {
    if (showOnlyUnknown && !keyIsUnknown) return null;

    let display: React.ReactNode;
    let color = 'text.primary';

    if (value === null) { display = 'null'; color = 'text.disabled'; }
    else if (typeof value === 'boolean') { display = String(value); color = value ? 'success.main' : 'error.main'; }
    else if (typeof value === 'number') { display = String(value); color = 'info.main'; }
    else if (typeof value === 'string') {
      const truncated = value.length > 300 ? value.slice(0, 300) + '...' : value;
      display = `"${truncated}"`; color = 'success.main';
    } else { display = String(value); }

    return (
      <Box sx={{ ml: depth * 1.5, py: 0.25, px: 0.5, borderLeft: keyIsUnknown ? '2px solid' : 'none', borderColor: 'warning.main', borderRadius: 0.5, display: 'flex', alignItems: 'center', gap: 0.5, bgcolor: keyIsUnknown ? 'rgba(255, 152, 0, 0.04)' : 'transparent' }}>
        {keyIsUnknown && <Tooltip title="Unknown field not in schema"><WarningIcon sx={{ fontSize: 14, color: 'warning.main', opacity: 0.6 }} /></Tooltip>}
        {label && <Typography component="span" sx={{ color: 'primary.main', fontWeight: 500 }}>{label}:{' '}</Typography>}
        <Typography component="span" sx={{ color, fontFamily: 'monospace', fontSize: '0.85rem' }}>{display}</Typography>
      </Box>
    );
  }

  const entries = isArray ? value.map((v, i) => [String(i), v] as [string, unknown]) : Object.entries(value);

  const filteredEntries = useMemo(() => {
    if (!showOnlyUnknown) return entries;
    return entries.filter(([key, val]) => {
      if (knownKeys && !isArray && !knownKeys.has(key)) return true;
      if (val !== null && typeof val === 'object') return true;
      return false;
    });
  }, [entries, showOnlyUnknown, knownKeys, isArray]);

  if (showOnlyUnknown && filteredEntries.length === 0 && !keyIsUnknown) return null;

  const itemCount = filteredEntries.length;
  const displayEntries = expanded ? filteredEntries : filteredEntries.slice(0, MAX_COLLAPSED_ITEMS);

  return (
    <Box sx={{ ml: depth > 0 ? depth * 1.5 : 0 }}>
      <Box onClick={() => setExpanded(!expanded)} sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', py: 0.25, px: 0.5, borderLeft: keyIsUnknown ? '2px solid' : 'none', borderColor: 'warning.main', bgcolor: keyIsUnknown ? 'rgba(255, 152, 0, 0.04)' : 'transparent', borderRadius: 0.5, '&:hover': { bgcolor: 'action.hover' } }}>
        {expanded ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
        {keyIsUnknown && <Tooltip title="Unknown field not in schema"><WarningIcon sx={{ fontSize: 14, color: 'warning.main', opacity: 0.6, mr: 0.5 }} /></Tooltip>}
        {label && <Typography component="span" sx={{ color: 'primary.main', fontWeight: 500, mr: 0.5 }}>{label}:</Typography>}
        <Typography component="span" sx={{ color: 'text.secondary', fontSize: '0.85rem' }}>{isArray ? `Array(${itemCount})` : `Object(${itemCount} keys)`}</Typography>
      </Box>
      <Collapse in={expanded}>
        {displayEntries.map(([key, val]) => (
          <JsonNode key={key} label={isArray ? `[${key}]` : key} value={val} depth={depth + 1} knownKeys={knownKeys} isUnknown={keyIsUnknown} showOnlyUnknown={showOnlyUnknown} />
        ))}
      </Collapse>
    </Box>
  );
}

export function ResultDetail() {
  const { id } = useParams<{ id: string }>();
  const auth = useAuth();
  const { toast, showToast, closeToast } = useToast();
  const [data, setData] = useState<any>(null);
  const [explainFinding, setExplainFinding] = useState<Finding | null>(null);
  const [explainOpen, setExplainOpen] = useState(false);
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());
  const [drawerFinding, setDrawerFinding] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [raw, setRaw] = useState<string | null>(null);
  const [accSummary, setAccSummary] = useState<any>(null);
  const [fpBreakdown, setFpBreakdown] = useState<any>(null);
  const [thresholds, setThresholds] = useState<any>(null);
  const [schema, setSchema] = useState<ResultSchema | null>(null);
  const [showOnlyUnknown, setShowOnlyUnknown] = useState(false);
  const [viewMode, setViewMode] = useState<'tree' | 'raw'>('tree');
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadProgress, setLoadProgress] = useState(0);
  const [activeTab, setActiveTab] = useState(0);

  // Agent feedback state (Track 96 + Final Gaps Item 2)
  const [feedbackDialogOpen, setFeedbackDialogOpen] = useState(false);
  const [feedbackFinding, setFeedbackFinding] = useState('');
  const [feedbackClassification, setFeedbackClassification] = useState('');
  const [feedbackReason, setFeedbackReason] = useState('');
  const [feedbackAgentType, setFeedbackAgentType] = useState('triage');
  const feedbackApi = useMemo(() => new AODSApiClient(), []);

  // Fetch schema
  useEffect(() => {
    (async () => {
      try {
        const r = await secureFetch('/schemas/result_schema');
        if (r.ok) { setSchema(await r.json()); return; }
      } catch {}
      try {
        const r = await fetch('/config/schemas/result_schema.json');
        if (r.ok) { setSchema(await r.json()); return; }
      } catch {}
      setSchema(null);
    })();
  }, []);

  // Fetch result data
  const fetchResult = useCallback(async () => {
    try {
      setError(null);
      const r = await secureFetch(`/scans/result/${encodeURIComponent(id || '')}`);
      if (!r.ok) throw new Error(String(r.status));
      const obj = await r.json();
      setData(obj);
      try { setRaw(JSON.stringify(obj, null, 2)); } catch { setRaw(null); }

      // Extract ML insights from the scan report first, fall back to global endpoints
      const reportAccuracy = obj?.learning_analytics_summary || obj?.detection_accuracy || null;
      const reportFpBreakdown = obj?.ml_filtering || null;
      if (reportAccuracy) {
        // Build accuracy summary from per-scan data
        const kpis = reportAccuracy?.key_performance_indicators;
        const riskAssess = reportAccuracy?.risk_assessment;
        if (kpis) {
          setAccSummary({
            status: parseFloat(String(kpis.false_positive_rate || '0').replace('%', '')) < 5 ? 'PASS' : 'WARN',
            metrics: {
              precision: parseFloat(String(kpis.vulnerability_detection_rate || '0').replace('%', '')) / 100,
              recall: parseFloat(String(kpis.vulnerability_detection_rate || '0').replace('%', '')) / 100,
            },
            min_precision: 0.80,
            min_recall: 0.70,
            fp_rate: kpis.false_positive_rate,
            risk_level: riskAssess?.overall_risk_level,
          });
        } else {
          setAccSummary(null);
        }
      } else {
        try { const a = await secureFetch('/ml/metrics/detection_accuracy/summary'); if (a.ok) setAccSummary(await a.json()); else setAccSummary(null); } catch { setAccSummary(null); }
      }
      if (reportFpBreakdown && reportFpBreakdown.applied) {
        // Build FP breakdown from per-scan ml_filtering data
        const findings = obj?.findings || obj?.vulnerabilities || [];
        const fpByPlugin: Record<string, number> = {};
        const fpByCategory: Record<string, number> = {};
        for (const f of findings) {
          if (f?.false_positive_probability > 0.5) {
            const plugin = f.plugin_source || f.plugin || 'unknown';
            const cat = f.category || 'unknown';
            fpByPlugin[plugin] = (fpByPlugin[plugin] || 0) + 1;
            fpByCategory[cat] = (fpByCategory[cat] || 0) + 1;
          }
        }
        setFpBreakdown({
          ...reportFpBreakdown,
          fp_by_plugin: Object.keys(fpByPlugin).length > 0 ? fpByPlugin : null,
          fp_by_category: Object.keys(fpByCategory).length > 0 ? fpByCategory : null,
        });
      } else {
        try { const f = await secureFetch('/ml/metrics/fp_breakdown'); if (f.ok) setFpBreakdown(await f.json()); else setFpBreakdown(null); } catch { setFpBreakdown(null); }
      }
      try { const t = await secureFetch('/ml/thresholds'); if (t.ok) setThresholds(await t.json()); else setThresholds(null); } catch { setThresholds(null); }
    } catch (e: any) {
      setError(e?.message || 'Failed to load result');
    }
  }, [id]);

  useEffect(() => { fetchResult(); }, [fetchResult]);

  const knownKeys = useMemo(() => {
    if (!schema) return undefined;
    const keys = new Set<string>();
    if (schema.topLevelKeys) schema.topLevelKeys.forEach((k) => keys.add(k));
    if (schema.findingKeys) schema.findingKeys.forEach((k) => keys.add(k));
    if (schema.apkInfoKeys) schema.apkInfoKeys.forEach((k) => keys.add(k));
    return keys;
  }, [schema]);

  const unknownCount = useMemo(() => {
    if (!data || !knownKeys) return 0;
    let count = 0;
    const countUnknown = (obj: any, depth = 0): void => {
      if (depth > MAX_DEPTH || obj === null || typeof obj !== 'object') return;
      if (Array.isArray(obj)) { obj.forEach((item) => countUnknown(item, depth + 1)); }
      else { Object.keys(obj).forEach((key) => { if (!knownKeys.has(key)) count++; countUnknown(obj[key], depth + 1); }); }
    };
    countUnknown(data);
    return count;
  }, [data, knownKeys]);

  // Extract findings from result data
  const findings: Finding[] = useMemo(() => {
    if (!data) return [];
    const rawFindings = data.vulnerabilities || data.findings || data?.context?.processed_findings || [];
    if (!Array.isArray(rawFindings)) return [];
    return rawFindings.map((f: any) => ({
      id: f.id || undefined,
      finding_id: f.finding_id || f.id || undefined,
      title: f.title || f.name || 'Untitled',
      severity: f.severity || f?.classification?.severity || 'INFO',
      confidence: typeof f.confidence === 'number' ? f.confidence : undefined,
      file_path: f.file_path || f.location || f?.evidence?.file_path,
      line_number: f.line_number ?? f?.evidence?.line_number,
      description: f.description || f?.evidence?.description,
      recommendation: f.recommendation,
      code_snippet: f.code_snippet || f?.evidence?.code_snippet,
      cwe_id: f.cwe_id || (f.cwe_ids?.[0]),
      masvs_category: f.masvs_category || f.masvs,
      references: f.references,
      category: f.category,
      plugin_source: f.plugin_source || f.plugin,
    }));
  }, [data]);

  const malwareFindings = useMemo(() => {
    if (!data) return [];
    const rawFindings = data.vulnerabilities || data.findings || data?.context?.processed_findings || [];
    if (!Array.isArray(rawFindings)) return [];
    return rawFindings.filter((f: any) =>
      f.vulnerability_type === 'malware-family' || f.vulnerability_type === 'malware' ||
      (f.plugin_source || f.plugin || '').includes('malware')
    );
  }, [data]);

  // Extract IoC findings (Track 117 - Cross-APK IoC Correlation)
  const iocExtracted = useMemo(() => {
    if (!data) return null;
    const rawFindings = data.vulnerabilities || data.findings || data?.context?.processed_findings || [];
    if (!Array.isArray(rawFindings)) return null;
    const f = rawFindings.find((x: any) => x.finding_id === 'MALWARE_IOC_EXTRACTED' || x.vulnerability_type === 'malware-ioc');
    return f || null;
  }, [data]);

  const crossApkCorrelation = useMemo(() => {
    if (!data) return null;
    const rawFindings = data.vulnerabilities || data.findings || data?.context?.processed_findings || [];
    if (!Array.isArray(rawFindings)) return null;
    const f = rawFindings.find((x: any) => x.finding_id === 'MALWARE_CROSS_APK_IOC' || x.vulnerability_type === 'malware-correlation');
    return f || null;
  }, [data]);

  // Severity counts for summary bar
  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => {
      const sev = (f.severity || 'INFO').toUpperCase();
      if (sev in counts) counts[sev]++;
      else counts['INFO']++;
    });
    return counts;
  }, [findings]);

  // Build executive_summary from findings if not present in report
  const execSummary = useMemo(() => {
    if (data?.executive_summary) return data.executive_summary;
    // Compute from findings
    const f = data?.findings || data?.vulnerabilities || [];
    if (!Array.isArray(f) || f.length === 0) return null;
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const confBins = Array.from({ length: 5 }, (_, i) => ({ bin_start: i * 0.2, bin_end: (i + 1) * 0.2, count: 0 }));
    for (const finding of f) {
      const sev = (finding.severity || 'info').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
      const conf = typeof finding.confidence === 'number' ? finding.confidence : null;
      if (conf !== null) {
        const bin = Math.min(Math.floor(conf * 5), 4);
        confBins[bin].count++;
      }
    }
    return { ...counts, total: f.length, confidence_histogram: confBins };
  }, [data]);

  // Per-scan ML filtering stats
  const mlFilteringStats = useMemo(() => {
    if (!data?.ml_filtering) return null;
    const mf = data.ml_filtering;
    if (!mf.applied) return null;
    return {
      original: mf.original_count ?? 0,
      filtered: mf.filtered_count ?? 0,
      final: (mf.original_count ?? 0) - (mf.filtered_count ?? 0),
      reduction: mf.reduction_percentage ?? 0,
      stages: mf.stages || [],
    };
  }, [data]);

  const isCalibrated = useMemo(() => {
    if (!data) return false;
    try {
      if (data?.report?.calibration_summary || data?.report?.calibrator) return true;
      const f = data?.vulnerabilities || data?.context?.processed_findings || data?.findings;
      if (Array.isArray(f)) return f.some((x: any) => x && x.calibrated === true);
    } catch {}
    return false;
  }, [data]);

  const eceSummary = useMemo(() => {
    try {
      const s = data?.report?.calibration_summary;
      if (!s) return null;
      const before = typeof s.ece_before === 'number' ? s.ece_before : undefined;
      const after = typeof s.ece_after === 'number' ? s.ece_after : undefined;
      if (before === undefined && after === undefined) return null;
      return { before, after };
    } catch { return null; }
  }, [data]);

  const confidenceHistogram = useMemo(() => {
    try {
      const bins = execSummary?.confidence_histogram;
      if (!Array.isArray(bins)) return null;
      return bins.slice(0, 5);
    } catch { return null; }
  }, [execSummary]);

  const thresholdSummary = useMemo(() => {
    try {
      const f = data?.vulnerabilities || data?.context?.processed_findings || data?.findings;
      if (!Array.isArray(f)) return null;
      let over = 0, total = 0;
      const tvals: number[] = [];
      f.forEach((x: any) => {
        const thr = x?.evidence?.threshold;
        if (thr && typeof thr === 'object') {
          total += 1;
          if (thr.over_threshold) over += 1;
          if (typeof thr.applied_threshold === 'number') tvals.push(thr.applied_threshold);
        }
      });
      if (total === 0) return null;
      const avgT = tvals.length ? tvals.reduce((a, b) => a + b, 0) / tvals.length : undefined;
      return { over, total, avgT };
    } catch { return null; }
  }, [data]);

  function resolveAppliedThreshold(category: string, plugin: string): number | null {
    try {
      const thr = thresholds || {};
      const d = typeof thr.default === 'number' ? thr.default : 0.5;
      if (thr.plugins && typeof thr.plugins[plugin] === 'number') return Number(thr.plugins[plugin]);
      if (thr.categories && typeof thr.categories[category] === 'number') return Number(thr.categories[category]);
      return Number(d);
    } catch { return null; }
  }

  // Extract agentic analysis (Track 91)
  const agenticAnalysis: AgenticAnalysis | null = useMemo(() => {
    if (!data?.agentic_analysis) return null;
    return data.agentic_analysis as AgenticAnalysis;
  }, [data]);

  // Extract verification data (Track 92)
  const verificationData: VerificationData | null = useMemo(() => {
    if (!data?.verification) return null;
    return data.verification as VerificationData;
  }, [data]);

  // Extract orchestration data (Track 93)
  const orchestrationData: OrchestrationData | null = useMemo(() => {
    if (!data?.orchestration) return null;
    return data.orchestration as OrchestrationData;
  }, [data]);

  // Extract triage data (Track 99)
  const triageData: TriageData | null = useMemo(() => {
    if (!data?.triage) return null;
    return data.triage as TriageData;
  }, [data]);

  // Historical context from vector DB (Track 101)
  const [historyItems, setHistoryItems] = useState<TriageFeedbackHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [historyVectorAvail, setHistoryVectorAvail] = useState<boolean | null>(null);

  useEffect(() => {
    if (!historyExpanded || historyLoaded || !triageData) return;
    setHistoryLoading(true);
    const apiClient = new AODSApiClient();
    const highFindings = (triageData.classified_findings || [])
      .filter((f: ClassifiedFindingType) => ['CRITICAL', 'HIGH'].includes(f.severity.toUpperCase()))
      .slice(0, 3);
    const queryTitle = highFindings.length > 0
      ? highFindings.map((f: ClassifiedFindingType) => f.finding_title).join(' ')
      : (triageData.classified_findings[0]?.finding_title || 'vulnerability');
    apiClient.getTriageFeedbackHistory(queryTitle, 10)
      .then((resp) => {
        setHistoryItems(resp.results || []);
        setHistoryVectorAvail(resp.vector_db_available);
        setHistoryLoaded(true);
      })
      .catch(() => {
        setHistoryVectorAvail(false);
        setHistoryLoaded(true);
      })
      .finally(() => setHistoryLoading(false));
  }, [historyExpanded, historyLoaded, triageData]);

  // Extract remediation data (Track 100)
  const remediationData: RemediationData | null = useMemo(() => {
    if (!data?.remediation) return null;
    return data.remediation as RemediationData;
  }, [data]);

  // Extract native binary analysis data from findings
  const nativeAnalysis = useMemo(() => {
    if (!data) return null;
    const rawFindings = data.vulnerabilities || data.findings || data?.context?.processed_findings || [];
    if (!Array.isArray(rawFindings)) return null;
    const nativeFindings = rawFindings.filter((f: any) =>
      (f.plugin_source || f.plugin || '').includes('native_binary') ||
      (f.file_path || '').startsWith('lib/') ||
      (f.title || '').startsWith('Native:')
    );
    if (nativeFindings.length === 0 && !data?.metadata?.plugins_summary?.findings_per_plugin?.native_binary_analysis) return null;

    // Extract library info from findings
    const libraries = new Set<string>();
    const architectures = new Set<string>();
    const hardeningIssues: Array<{ title: string; severity: string; library: string }> = [];
    const deepFindings: Array<{ title: string; severity: string; cwe?: string }> = [];

    for (const f of nativeFindings) {
      const fp = f.file_path || '';
      if (fp.startsWith('lib/')) {
        const parts = fp.split('/');
        if (parts.length >= 3) {
          architectures.add(parts[1]); // e.g., arm64-v8a
          libraries.add(parts[parts.length - 1]); // e.g., libnative.so
        }
      }
      const title = f.title || '';
      if (title.includes('hardening') || title.includes('No PIE') || title.includes('No NX') ||
          title.includes('No RELRO') || title.includes('No Stack Canary')) {
        hardeningIssues.push({ title: title.replace('Native: ', ''), severity: f.severity || 'low', library: fp.split('/').pop() || fp });
      } else if (title.includes('buffer') || title.includes('format string') || title.includes('crypto') ||
                 title.includes('overflow') || title.includes('injection') || title.includes('decompil')) {
        deepFindings.push({ title: title.replace('Native: ', ''), severity: f.severity || 'medium', cwe: f.cwe_id });
      }
    }

    return {
      totalFindings: nativeFindings.length,
      libraries: Array.from(libraries),
      architectures: Array.from(architectures),
      hardeningIssues,
      deepFindings,
      ghidraUsed: deepFindings.length > 0, // deep findings imply Ghidra was used
    };
  }, [data]);

  const handleLoadMore = useCallback(async () => {
    if (loadingMore) return;
    setLoadingMore(true);
    try {
      const current = raw ?? JSON.stringify(data, null, 2);
      setLoadProgress(10);
      const r = await secureFetch(`/scans/result/${encodeURIComponent(id || '')}/chunk?offset=${current.length}&numBytes=131072`);
      setLoadProgress(60);
      if (!r.ok) { setLoadingMore(false); return; }
      const j = await r.json();
      setLoadProgress(90);
      if (!j?.content) { setLoadingMore(false); return; }
      const appended = j.content || '';
      const marker = `\n/* +${appended.length} bytes */`;
      setRaw((prev) => (prev ?? current) + appended + marker);
      setLoadProgress(100);
    } catch { /* silent */ }
    setLoadingMore(false);
    setTimeout(() => setLoadProgress(0), 500);
  }, [loadingMore, raw, data, id]);

  const handleCopyAll = useCallback(() => {
    const content = raw ?? JSON.stringify(data, null, 2);
    navigator.clipboard.writeText(content).then(() => { showToast('JSON copied'); }).catch(() => {});
  }, [raw, data, showToast]);

  if (error) return <ErrorDisplay error={error} onRetry={fetchResult} />;
  if (!data) return <LoadingSkeleton variant="detail" />;

  return (
    <Box>
      <PageHeader
        title={`Result ${id}`}
        subtitle={data?.metadata?.apk_path ? `Scan of ${(data.metadata.apk_path as string).split('/').pop()}` : 'Scan result details'}
        actions={
          <Stack direction="row" spacing={0.5}>
            <Tooltip title="Copy JSON">
              <IconButton onClick={handleCopyAll} size="small" aria-label="Copy JSON">
                <ContentCopyIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Download report">
              <IconButton size="small" onClick={() => {
                const blob = new Blob([raw ?? JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = `${id || 'report'}.json`; a.click();
                URL.revokeObjectURL(url);
              }} aria-label="Download report">
                <FileDownloadIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        }
      />

      {/* Summary bar */}
      <Paper variant="outlined" sx={{ px: 2, py: 1.25, mb: 2, borderRadius: 1.5 }}>
        <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{findings.length} findings</Typography>
          <Stack direction="row" spacing={0.5}>
            {Object.entries(sevCounts).map(([sev, count]) => (
              count > 0 && <SeverityChip key={sev} severity={sev} size="small" />
            ))}
          </Stack>
          {data?.metadata?.profile && <Chip label={data.metadata.profile} size="small" variant="outlined" sx={{ textTransform: 'capitalize', fontWeight: 500 }} />}
          {data?.metadata?.analysis_duration != null && <Chip label={`${Math.round(data.metadata.analysis_duration as number)}s`} size="small" variant="outlined" />}
          {data?.metadata?.business_domain && <Chip label={data.metadata.business_domain as string} size="small" color="info" variant="outlined" sx={{ textTransform: 'capitalize' }} />}
          {data?.metadata?.timestamp && (
            <Typography variant="caption" color="text.disabled" sx={{ ml: 'auto' }}>
              {formatDateTime(data.metadata.timestamp as string)}
            </Typography>
          )}
        </Stack>
      </Paper>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs value={activeTab} onChange={(_e, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab label={<Badge badgeContent={findings.length} color="primary" max={999}><span>Findings</span></Badge>} />
          <Tab label="Raw JSON" />
          <Tab label="ML Insights" />
          <Tab label="Attack Surface" data-testid="attack-surface-tab" />
          {agenticAnalysis && <Tab label="AI Analysis" data-testid="ai-analysis-tab" />}
          {verificationData && <Tab label="Verification" data-testid="verification-tab" />}
          {orchestrationData && <Tab label="Scan Strategy" data-testid="scan-strategy-tab" />}
          {triageData && <Tab label="Triage" data-testid="triage-tab" />}
          {remediationData && <Tab label="Remediation" data-testid="remediation-tab" />}
        </Tabs>
      </Box>

      {/* Findings Tab */}
      {activeTab === 0 && (
        <Box sx={{ borderRadius: 1.5 }}>
          {malwareFindings.length > 0 && (
            <Card variant="outlined" sx={{ mb: 2, borderRadius: 2, borderColor: 'error.main' }} data-testid="malware-detection-card">
              <CardContent>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <BugReportIcon color="error" />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: 'error.main' }}>
                    Malware Detection ({malwareFindings.length} finding{malwareFindings.length > 1 ? 's' : ''})
                  </Typography>
                </Stack>
                {malwareFindings.map((f: any, idx: number) => (
                  <Paper key={idx} variant="outlined" sx={{ p: 1.5, mb: 1 }} data-testid={`malware-finding-${idx}`}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                      <Typography fontWeight={600}>{f.title || f.evidence?.family_name || 'Malware Detected'}</Typography>
                      {f.evidence?.category && <Chip label={f.evidence.category.replace(/_/g, ' ')} size="small" variant="outlined" />}
                      <Chip label={f.severity || 'HIGH'} size="small" color={
                        (f.severity || '').toUpperCase() === 'CRITICAL' ? 'error' :
                        (f.severity || '').toUpperCase() === 'HIGH' ? 'warning' : 'info'
                      } />
                      {typeof f.confidence === 'number' && (
                        <Chip label={`${(f.confidence * 100).toFixed(0)}% confidence`} size="small" color="default" />
                      )}
                      {f.cwe_id && <Chip label={f.cwe_id} size="small" variant="outlined" />}
                    </Stack>
                    {f.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{f.description}</Typography>}
                    {f.evidence?.indicators && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                        {f.evidence.total_indicators || f.evidence.indicators.length} indicator(s) matched
                        {f.evidence.matched_files?.length ? ` in ${f.evidence.matched_files.length} file(s)` : ''}
                      </Typography>
                    )}
                    {f.evidence?.consensus && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                        ML consensus: {f.evidence.consensus.malware_votes}/{f.evidence.consensus.total_votes} models flagged malware
                      </Typography>
                    )}
                  </Paper>
                ))}
              </CardContent>
            </Card>
          )}
          {/* IoC Correlation Card (Track 117) */}
          {(iocExtracted || crossApkCorrelation) && (
            <Card variant="outlined" sx={{ mb: 2, borderRadius: 2, borderColor: crossApkCorrelation ? 'error.main' : 'warning.main' }} data-testid="ioc-correlation-card">
              <CardContent>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <LinkIcon color={crossApkCorrelation ? 'error' : 'warning'} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: crossApkCorrelation ? 'error.main' : 'warning.main' }}>
                    {crossApkCorrelation ? 'Cross-APK IoC Correlation Detected' : 'Indicators of Compromise Extracted'}
                  </Typography>
                </Stack>

                {/* IoC extraction summary */}
                {iocExtracted?.evidence && (
                  <Paper variant="outlined" sx={{ p: 1.5, mb: crossApkCorrelation ? 1.5 : 0 }} data-testid="ioc-extracted-summary">
                    <Typography variant="body2" sx={{ mb: 1 }}>{iocExtracted.description}</Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {Object.entries(iocExtracted.evidence.ioc_summary || {}).map(([type, count]: [string, any]) => (
                        count > 0 && (
                          <Chip
                            key={type}
                            label={`${type.replace(/_/g, ' ')}: ${count}`}
                            size="small"
                            variant="outlined"
                            color={
                              ['crypto_wallet', 'stratum_url', 'onion_address'].includes(type) ? 'error' :
                              ['c2_ip', 'dga_domain', 'encoded_c2_url'].includes(type) ? 'warning' : 'default'
                            }
                          />
                        )
                      ))}
                    </Stack>
                    {iocExtracted.evidence.iocs && iocExtracted.evidence.iocs.length > 0 && (
                      <TableContainer sx={{ mt: 1, maxHeight: 200 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>Value</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>File</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {iocExtracted.evidence.iocs.slice(0, 15).map((ioc: any, i: number) => (
                              <TableRow key={i}>
                                <TableCell>
                                  <Chip label={ioc.type?.replace(/_/g, ' ') || 'unknown'} size="small" variant="outlined" />
                                </TableCell>
                                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {ioc.value || ''}
                                </TableCell>
                                <TableCell sx={{ fontSize: '0.8rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {ioc.file || ''}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}
                    {iocExtracted.evidence.total_iocs > 15 && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                        Showing 15 of {iocExtracted.evidence.total_iocs} IoCs
                      </Typography>
                    )}
                  </Paper>
                )}

                {/* Cross-APK correlation details */}
                {crossApkCorrelation?.evidence?.correlation_summary && (
                  <Paper variant="outlined" sx={{ p: 1.5, borderColor: 'error.light' }} data-testid="cross-apk-correlation">
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                      <Chip label={crossApkCorrelation.severity || 'HIGH'} size="small" color="error" />
                      <Typography variant="body2" fontWeight={600}>
                        {crossApkCorrelation.evidence.correlation_summary.shared_ioc_count} shared IoC(s) found across{' '}
                        {crossApkCorrelation.evidence.correlation_summary.correlated_apk_count} other APK(s)
                      </Typography>
                      {typeof crossApkCorrelation.confidence === 'number' && (
                        <Chip label={`${(crossApkCorrelation.confidence * 100).toFixed(0)}% confidence`} size="small" />
                      )}
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{crossApkCorrelation.description}</Typography>

                    {/* Shared IoC types */}
                    {crossApkCorrelation.evidence.correlation_summary.ioc_types_shared?.length > 0 && (
                      <Stack direction="row" spacing={0.5} sx={{ mb: 1 }} flexWrap="wrap" useFlexGap>
                        <Typography variant="caption" sx={{ fontWeight: 600, mr: 0.5 }}>Shared types:</Typography>
                        {crossApkCorrelation.evidence.correlation_summary.ioc_types_shared.map((t: string) => (
                          <Chip key={t} label={t.replace(/_/g, ' ')} size="small" color="error" variant="outlined" />
                        ))}
                      </Stack>
                    )}

                    {/* Correlated APKs */}
                    {crossApkCorrelation.evidence.correlation_summary.correlated_apks?.length > 0 && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600 }}>Correlated APKs:</Typography>
                        <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                          {crossApkCorrelation.evidence.correlation_summary.correlated_apks.slice(0, 10).map((apk: string, i: number) => (
                            <Typography key={i} variant="caption" sx={{ fontFamily: 'monospace', pl: 1 }}>
                              {apk}
                            </Typography>
                          ))}
                        </Stack>
                      </Box>
                    )}

                    {/* Dominant family/category */}
                    {(crossApkCorrelation.evidence.dominant_family || crossApkCorrelation.evidence.dominant_category) && (
                      <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                        {crossApkCorrelation.evidence.dominant_family && (
                          <Chip label={`Family: ${crossApkCorrelation.evidence.dominant_family}`} size="small" color="warning" />
                        )}
                        {crossApkCorrelation.evidence.dominant_category && (
                          <Chip label={`Category: ${crossApkCorrelation.evidence.dominant_category.replace(/_/g, ' ')}`} size="small" variant="outlined" />
                        )}
                      </Stack>
                    )}
                  </Paper>
                )}
              </CardContent>
            </Card>
          )}
          {/* IoC Export Buttons */}
          {(iocExtracted || crossApkCorrelation) && (auth.roles.includes('admin') || auth.roles.includes('analyst')) && (
            <Stack direction="row" spacing={1} sx={{ mb: 2 }} data-testid="ioc-export-buttons">
              <Button
                size="small"
                variant="outlined"
                startIcon={<FileDownloadIcon sx={{ fontSize: 16 }} />}
                sx={{ textTransform: 'none', fontSize: 12 }}
                onClick={async () => {
                  try {
                    const client = new AODSApiClient();
                    const data = await client.getScanIoCs(id!, 'json');
                    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `iocs-${id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  } catch { /* ignore */ }
                }}
              >
                Export IoCs (JSON)
              </Button>
              <Button
                size="small"
                variant="outlined"
                startIcon={<FileDownloadIcon sx={{ fontSize: 16 }} />}
                sx={{ textTransform: 'none', fontSize: 12 }}
                onClick={async () => {
                  try {
                    const client = new AODSApiClient();
                    const data = await client.getScanIoCs(id!, 'stix');
                    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `iocs-${id}-stix.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  } catch { /* ignore */ }
                }}
              >
                Export IoCs (STIX 2.1)
              </Button>
            </Stack>
          )}
          {/* Native Binary Analysis Card */}
          {nativeAnalysis && (
            <Card variant="outlined" sx={{ mb: 2, borderRadius: 2, borderColor: 'info.main' }} data-testid="native-analysis-card">
              <CardContent>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <Typography sx={{ fontSize: 18 }}>{'\u{1F9EC}'}</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: 'info.main' }}>
                    Native Binary Analysis ({nativeAnalysis.totalFindings} finding{nativeAnalysis.totalFindings !== 1 ? 's' : ''})
                  </Typography>
                  {nativeAnalysis.ghidraUsed && (
                    <Chip label="Ghidra deep analysis" size="small" color="success" variant="outlined" data-testid="ghidra-used-badge" />
                  )}
                  {!nativeAnalysis.ghidraUsed && (
                    <Chip label="Basic (no Ghidra)" size="small" variant="outlined" />
                  )}
                </Stack>

                {/* Library inventory */}
                {nativeAnalysis.libraries.length > 0 && (
                  <Paper variant="outlined" sx={{ p: 1.5, mb: 1.5 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                      Native Libraries ({nativeAnalysis.libraries.length})
                    </Typography>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {nativeAnalysis.architectures.map((arch: string) => (
                        <Chip key={arch} label={arch} size="small" color="info" variant="outlined" sx={{ fontSize: 10 }} />
                      ))}
                      {nativeAnalysis.libraries.slice(0, 20).map((lib: string) => (
                        <Chip key={lib} label={lib} size="small" variant="outlined" sx={{ fontSize: 10, fontFamily: 'monospace' }} />
                      ))}
                      {nativeAnalysis.libraries.length > 20 && (
                        <Chip label={`+${nativeAnalysis.libraries.length - 20} more`} size="small" variant="outlined" sx={{ fontSize: 10 }} />
                      )}
                    </Stack>
                  </Paper>
                )}

                {/* Hardening issues */}
                {nativeAnalysis.hardeningIssues.length > 0 && (
                  <Paper variant="outlined" sx={{ p: 1.5, mb: 1.5 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                      Binary Hardening Issues ({nativeAnalysis.hardeningIssues.length})
                    </Typography>
                    <Stack spacing={0.5}>
                      {nativeAnalysis.hardeningIssues.slice(0, 10).map((issue: { title: string; severity: string; library: string }, i: number) => (
                        <Stack key={i} direction="row" spacing={1} alignItems="center">
                          <Chip label={issue.severity} size="small" color={issue.severity.toUpperCase() === 'HIGH' ? 'error' : issue.severity.toUpperCase() === 'MEDIUM' ? 'warning' : 'default'} sx={{ minWidth: 56 }} />
                          <Typography variant="body2" sx={{ fontSize: 12 }}>{issue.title}</Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 10 }}>{issue.library}</Typography>
                        </Stack>
                      ))}
                    </Stack>
                  </Paper>
                )}

                {/* Deep analysis findings (Ghidra) */}
                {nativeAnalysis.deepFindings.length > 0 && (
                  <Paper variant="outlined" sx={{ p: 1.5 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                      Ghidra Decompilation Findings ({nativeAnalysis.deepFindings.length})
                    </Typography>
                    <Stack spacing={0.5}>
                      {nativeAnalysis.deepFindings.slice(0, 10).map((df: { title: string; severity: string; cwe?: string }, i: number) => (
                        <Stack key={i} direction="row" spacing={1} alignItems="center">
                          <Chip label={df.severity} size="small" color={df.severity.toUpperCase() === 'CRITICAL' ? 'error' : df.severity.toUpperCase() === 'HIGH' ? 'error' : 'warning'} sx={{ minWidth: 56 }} />
                          <Typography variant="body2" sx={{ fontSize: 12 }}>{df.title}</Typography>
                          {df.cwe && <Chip label={df.cwe} size="small" variant="outlined" sx={{ fontSize: 10 }} />}
                        </Stack>
                      ))}
                    </Stack>
                  </Paper>
                )}

                {!nativeAnalysis.ghidraUsed && (
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    Enable Ghidra deep analysis with AODS_NATIVE_DEEP=1 to detect buffer overflows, format strings, weak crypto, and command injection in native code.
                  </Typography>
                )}
              </CardContent>
            </Card>
          )}
          <FindingsTable
            findings={findings}
            selectable
            selected={selectedFindings}
            onSelectionChange={setSelectedFindings}
            onFindingClick={(f) => setDrawerFinding(f)}
            onExplainClick={
              auth.roles.includes('admin') || auth.roles.includes('analyst')
                ? (f) => { setExplainFinding(f); setExplainOpen(true); }
                : undefined
            }
          />
          {selectedFindings.size > 0 && (
            <Paper
              variant="outlined"
              data-testid="export-bar"
              sx={{
                position: 'sticky', bottom: 0, mt: 2, p: 1.5,
                display: 'flex', alignItems: 'center', gap: 2,
                borderTop: 1, borderColor: 'divider',
              }}
            >
              <Typography variant="body2" data-testid="selection-count">
                {selectedFindings.size} selected
              </Typography>
              <Button
                size="small"
                variant="outlined"
                data-testid="export-json-btn"
                onClick={() => {
                  const selected = findings.filter((_, i) => selectedFindings.has(i));
                  const blob = new Blob([JSON.stringify(selected, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `findings-${id || 'export'}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Export JSON
              </Button>
              <Button
                size="small"
                variant="outlined"
                data-testid="export-csv-btn"
                onClick={() => {
                  const selected = findings.filter((_, i) => selectedFindings.has(i));
                  const headers = ['title', 'severity', 'confidence', 'cwe_id', 'file_path', 'line_number'];
                  const rows = selected.map(f =>
                    headers.map(h => {
                      const val = (f as Record<string, unknown>)[h];
                      const s = val == null ? '' : String(val);
                      return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
                    }).join(',')
                  );
                  const csv = [headers.join(','), ...rows].join('\n');
                  const blob = new Blob([csv], { type: 'text/csv' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `findings-${id || 'export'}.csv`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Export CSV
              </Button>
              <Button size="small" onClick={() => setSelectedFindings(new Set())} data-testid="clear-selection-btn">
                Clear
              </Button>
            </Paper>
          )}
        </Box>
      )}

      {/* Finding Detail Drawer */}
      <FindingDetailDrawer
        finding={drawerFinding}
        onClose={() => setDrawerFinding(null)}
        onExplain={
          auth.roles.includes('admin') || auth.roles.includes('analyst')
            ? (f) => { setDrawerFinding(null); setExplainFinding(f); setExplainOpen(true); }
            : undefined
        }
      />

      {/* Raw JSON Tab */}
      {activeTab === 1 && (
        <>
          <Paper variant="outlined" sx={{ px: 1.5, py: 1, mb: 1, borderRadius: 1.5 }}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap' }}>
              <Chip label="Tree View" onClick={() => setViewMode('tree')} color={viewMode === 'tree' ? 'primary' : 'default'} variant={viewMode === 'tree' ? 'filled' : 'outlined'} size="small" />
              <Chip label="Raw JSON" onClick={() => setViewMode('raw')} color={viewMode === 'raw' ? 'primary' : 'default'} variant={viewMode === 'raw' ? 'filled' : 'outlined'} size="small" />
              {viewMode === 'tree' && schema && (
                <FormControlLabel
                  control={<Switch checked={showOnlyUnknown} onChange={(e) => setShowOnlyUnknown(e.target.checked)} size="small" />}
                  label={<Stack direction="row" spacing={0.5} alignItems="center"><WarningIcon fontSize="small" sx={{ color: 'warning.main' }} /><Typography variant="caption">Unknown fields ({unknownCount})</Typography></Stack>}
                  sx={{ mr: 0 }}
                />
              )}
              <Box sx={{ flex: 1 }} />
              {schema && <Chip label={`Schema v${schema.version || '?'}`} size="small" color="success" variant="outlined" />}
              {!schema && <Chip label="No schema" size="small" color="warning" variant="outlined" />}
              <Tooltip title="Copy JSON to clipboard">
                <IconButton size="small" onClick={() => { navigator.clipboard.writeText(raw ?? JSON.stringify(data, null, 2)); showToast('Copied to clipboard', 'success'); }} aria-label="Copy JSON">
                  <ContentCopyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Download JSON file">
                <IconButton size="small" onClick={() => {
                  const blob = new Blob([raw ?? JSON.stringify(data, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url; a.download = `${id || 'report'}.json`; a.click();
                  URL.revokeObjectURL(url);
                }} aria-label="Download JSON">
                  <FileDownloadIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Stack>
          </Paper>

          <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 1.5, p: 2, height: 'calc(100vh - 320px)', minHeight: 400, overflow: 'auto', bgcolor: 'background.paper', fontFamily: 'monospace' }}>
            {viewMode === 'tree' ? (
              <JsonNode label="" value={data} depth={0} knownKeys={knownKeys} showOnlyUnknown={showOnlyUnknown} defaultExpanded />
            ) : (
              <Box component="pre" sx={{ whiteSpace: 'pre-wrap', m: 0, fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", monospace', fontSize: '0.8rem', lineHeight: 1.6, tabSize: 2 }}>
                {raw ?? JSON.stringify(data, null, 2)}
              </Box>
            )}
          </Box>

          <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1 }}>
            <Button variant="outlined" size="small" onClick={handleLoadMore} disabled={loadingMore}>
              {loadingMore ? 'Loading...' : 'Load more'}
            </Button>
            {loadingMore && <Box sx={{ flex: 1, maxWidth: 200 }}><LinearProgress variant="determinate" value={loadProgress} /></Box>}
            {data && <Typography variant="caption" color="text.disabled">{Object.keys(data).length} top-level keys</Typography>}
          </Stack>
        </>
      )}

      {/* ML Insights Tab */}
      {activeTab === 2 && (
        <Stack spacing={2}>
          {/* Severity Distribution Card */}
          {execSummary && (
            <Card variant="outlined">
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>Severity Distribution</Typography>
                <Stack direction="row" spacing={1.5} sx={{ flexWrap: 'wrap' }}>
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                    const count = execSummary[sev] ?? 0;
                    if (count === 0) return null;
                    const colors: Record<string, string> = { critical: '#d32f2f', high: '#f57c00', medium: '#fbc02d', low: '#1976d2', info: '#9e9e9e' };
                    return (
                      <Box key={sev} sx={{ textAlign: 'center', minWidth: 55 }}>
                        <Typography variant="h5" sx={{ fontWeight: 700, color: colors[sev], lineHeight: 1 }}>{count}</Typography>
                        <Typography variant="caption" sx={{ color: 'text.secondary', textTransform: 'capitalize' }}>{sev}</Typography>
                      </Box>
                    );
                  })}
                  {execSummary.total && (
                    <Box sx={{ textAlign: 'center', minWidth: 55, ml: 1, borderLeft: 1, borderColor: 'divider', pl: 1.5 }}>
                      <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1 }}>{execSummary.total}</Typography>
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>Total</Typography>
                    </Box>
                  )}
                </Stack>
                {/* Severity bar */}
                {(() => {
                  const es = execSummary;
                  const total = (es.critical ?? 0) + (es.high ?? 0) + (es.medium ?? 0) + (es.low ?? 0) + (es.info ?? 0);
                  if (total === 0) return null;
                  const colors: Record<string, string> = { critical: '#d32f2f', high: '#f57c00', medium: '#fbc02d', low: '#1976d2', info: '#9e9e9e' };
                  return (
                    <Stack direction="row" sx={{ height: 6, borderRadius: 1, overflow: 'hidden', mt: 1.5 }}>
                      {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                        const pct = ((es[sev] ?? 0) / total) * 100;
                        if (pct === 0) return null;
                        return <Box key={sev} sx={{ width: `${pct}%`, bgcolor: colors[sev], minWidth: pct > 0 ? 2 : 0 }} />;
                      })}
                    </Stack>
                  );
                })()}
              </CardContent>
            </Card>
          )}

          {/* ML Filtering Stats */}
          {mlFilteringStats && (
            <Card variant="outlined">
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>ML Filtering (This Scan)</Typography>
                <Stack direction="row" spacing={3}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'text.secondary' }}>{mlFilteringStats.original}</Typography>
                    <Typography variant="caption" color="text.secondary">Before</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'warning.main' }}>{mlFilteringStats.filtered}</Typography>
                    <Typography variant="caption" color="text.secondary">Removed</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'success.main' }}>{mlFilteringStats.final}</Typography>
                    <Typography variant="caption" color="text.secondary">After</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'info.main' }}>{mlFilteringStats.reduction.toFixed(1)}%</Typography>
                    <Typography variant="caption" color="text.secondary">Reduction</Typography>
                  </Box>
                </Stack>
                {mlFilteringStats.stages.length > 0 && (
                  <Stack direction="row" spacing={0.5} sx={{ mt: 1.5, flexWrap: 'wrap' }}>
                    {mlFilteringStats.stages.map((s: string, i: number) => (
                      <Chip key={i} label={s.replace(/_/g, ' ')} size="small" variant="outlined" sx={{ fontSize: 10, textTransform: 'capitalize' }} />
                    ))}
                  </Stack>
                )}
              </CardContent>
            </Card>
          )}

          {/* Calibration & Accuracy Row */}
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            {/* Calibration Card */}
            <Card variant="outlined" sx={{ flex: 1 }}>
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Probability Calibration</Typography>
                {isCalibrated ? (
                  <Stack spacing={1}>
                    <Chip label="Enabled" color="success" size="small" sx={{ width: 'fit-content' }} />
                    {eceSummary && (
                      <Stack direction="row" spacing={3}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">ECE Before</Typography>
                          <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>{eceSummary.before?.toFixed(4) ?? 'n/a'}</Typography>
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">ECE After</Typography>
                          <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1, color: 'success.main' }}>{eceSummary.after?.toFixed(4) ?? 'n/a'}</Typography>
                        </Box>
                      </Stack>
                    )}
                  </Stack>
                ) : (
                  <Chip label="Not Applied" color="default" size="small" variant="outlined" />
                )}
              </CardContent>
            </Card>

            {/* Detection Accuracy Card */}
            {accSummary && (
              <Card variant="outlined" sx={{ flex: 1 }}>
                <CardContent sx={{ pb: '12px !important' }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Detection Accuracy</Typography>
                  <Chip
                    label={String(accSummary.status)}
                    size="small"
                    color={accSummary.status === 'PASS' ? 'success' : accSummary.status === 'WARN' ? 'warning' : 'error'}
                    sx={{ mb: 1 }}
                  />
                  <Stack direction="row" spacing={3}>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Precision</Typography>
                      <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>
                        {accSummary.metrics ? accSummary.metrics.precision.toFixed(3) : (accSummary.precision?.toFixed ? accSummary.precision.toFixed(3) : 'n/a')}
                      </Typography>
                      <Typography variant="caption" color="text.disabled">min: {accSummary.min_precision?.toFixed ? accSummary.min_precision.toFixed(2) : 'n/a'}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Recall</Typography>
                      <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>
                        {accSummary.metrics ? accSummary.metrics.recall.toFixed(3) : (accSummary.recall?.toFixed ? accSummary.recall.toFixed(3) : 'n/a')}
                      </Typography>
                      <Typography variant="caption" color="text.disabled">min: {accSummary.min_recall?.toFixed ? accSummary.min_recall.toFixed(2) : 'n/a'}</Typography>
                    </Box>
                  </Stack>
                </CardContent>
              </Card>
            )}
          </Stack>

          {/* Confidence Histogram */}
          {confidenceHistogram && (
            <Card variant="outlined">
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Confidence Distribution</Typography>
                <Stack direction="row" spacing={0.5} alignItems="flex-end" sx={{ height: 80 }}>
                  {confidenceHistogram.map((b: any, i: number) => {
                    const maxCount = Math.max(...confidenceHistogram.map((x: any) => x.count || 0), 1);
                    const heightPct = ((b.count || 0) / maxCount) * 100;
                    const rangeLabel = `${(b.bin_start * 100).toFixed(0)}-${(b.bin_end * 100).toFixed(0)}%`;
                    return (
                      <Tooltip key={i} title={`${rangeLabel}: ${b.count} findings`}>
                        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <Box sx={{ width: '80%', height: `${Math.max(heightPct, 3)}%`, bgcolor: 'primary.main', borderRadius: '4px 4px 0 0', minHeight: 2, transition: 'height 0.3s' }} />
                          <Typography variant="caption" sx={{ fontSize: 8, color: 'text.disabled', mt: 0.25 }}>{rangeLabel}</Typography>
                        </Box>
                      </Tooltip>
                    );
                  })}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Thresholds Row */}
          {(thresholdSummary || thresholds) && (
            <Card variant="outlined">
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>ML Thresholds</Typography>
                <Stack direction="row" spacing={3} sx={{ mb: thresholds ? 1.5 : 0 }}>
                  {thresholdSummary && (
                    <>
                      <Box>
                        <Typography variant="caption" color="text.secondary">Over Threshold</Typography>
                        <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>{thresholdSummary.over}/{thresholdSummary.total}</Typography>
                      </Box>
                      {thresholdSummary.avgT !== undefined && (
                        <Box>
                          <Typography variant="caption" color="text.secondary">Avg Threshold</Typography>
                          <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>{thresholdSummary.avgT.toFixed(3)}</Typography>
                        </Box>
                      )}
                    </>
                  )}
                  {thresholds && (
                    <Box>
                      <Typography variant="caption" color="text.secondary">Default</Typography>
                      <Typography variant="h6" sx={{ fontWeight: 600, lineHeight: 1 }}>{(typeof thresholds.default === 'number' ? thresholds.default : 0.5).toFixed(2)}</Typography>
                    </Box>
                  )}
                </Stack>
                {thresholds && Array.isArray(data?.vulnerabilities) && data.vulnerabilities.length > 0 && (
                  <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                    {data.vulnerabilities.slice(0, 8).map((f: any, idx: number) => (
                      <Chip key={idx} size="small" variant="outlined"
                        label={`${(f.category || 'unknown').slice(0, 15)}: ${(resolveAppliedThreshold(String(f.category || 'security'), String(f.plugin_source || f.plugin || '')) ?? 0.5).toFixed(2)}`}
                        sx={{ fontSize: 10 }}
                      />
                    ))}
                  </Stack>
                )}
              </CardContent>
            </Card>
          )}

          {/* FP Breakdown */}
          {fpBreakdown && (
            <Card variant="outlined">
              <CardContent sx={{ pb: '12px !important' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>False Positive Breakdown</Typography>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
                  {fpBreakdown.fp_by_plugin && Object.keys(fpBreakdown.fp_by_plugin).length > 0 && (
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>By Plugin</Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableBody>
                            {Object.entries(fpBreakdown.fp_by_plugin).sort(([, a]: any, [, b]: any) => b - a).slice(0, 8).map(([k, v]: any) => (
                              <TableRow key={k} sx={{ '& td': { py: 0.25, borderBottom: '1px solid', borderColor: 'divider' } }}>
                                <TableCell sx={{ fontSize: 11 }}>{k}</TableCell>
                                <TableCell align="right" sx={{ fontWeight: 600, fontSize: 11 }}>{v}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  )}
                  {fpBreakdown.fp_by_category && Object.keys(fpBreakdown.fp_by_category).length > 0 && (
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>By Category</Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableBody>
                            {Object.entries(fpBreakdown.fp_by_category).sort(([, a]: any, [, b]: any) => b - a).slice(0, 8).map(([k, v]: any) => (
                              <TableRow key={k} sx={{ '& td': { py: 0.25, borderBottom: '1px solid', borderColor: 'divider' } }}>
                                <TableCell sx={{ fontSize: 11 }}>{k}</TableCell>
                                <TableCell align="right" sx={{ fontWeight: 600, fontSize: 11 }}>{v}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Empty state */}
          {!isCalibrated && !accSummary && !fpBreakdown && !thresholds && !execSummary && !confidenceHistogram && !mlFilteringStats && (
            <EmptyState message="No ML insights available for this result" />
          )}
        </Stack>
      )}

      {/* Attack Surface Tab */}
      {activeTab === 3 && (
        <Box data-testid="attack-surface-panel">
          {id && (
            <AttackSurfaceGraph
              resultId={id}
              findings={findings}
              verificationData={verificationData ?? undefined}
              onFindingClick={(f) => setDrawerFinding(f)}
            />
          )}
        </Box>
      )}

      {/* AI Analysis Tab (Track 91) */}
      {activeTab === 4 && agenticAnalysis && (
        <Stack spacing={2} data-testid="ai-analysis-content">
          {agenticAnalysis.method && agenticAnalysis.method.includes('heuristic') && (
            <Chip label="Heuristic Fallback - LLM unavailable" color="warning" size="small" sx={{ alignSelf: 'flex-start' }} />
          )}
          {/* Narration Feedback */}
          <Chip
            label="Provide Feedback on Analysis"
            size="small"
            variant="outlined"
            onClick={() => { setFeedbackFinding('Overall AI Analysis'); setFeedbackAgentType('narrate'); setFeedbackDialogOpen(true); }}
            sx={{ alignSelf: 'flex-start' }}
            data-testid="narration-feedback-btn"
          />
          {/* Executive Summary */}
          <Card variant="outlined">
            <CardContent>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Executive Summary</Typography>
                <Chip
                  label={agenticAnalysis.risk_rating}
                  size="small"
                  data-testid="risk-rating-chip"
                  sx={{
                    fontWeight: 700,
                    color: 'white',
                    bgcolor:
                      agenticAnalysis.risk_rating === 'CRITICAL' ? 'error.dark'
                      : agenticAnalysis.risk_rating === 'HIGH' ? 'warning.dark'
                      : agenticAnalysis.risk_rating === 'MEDIUM' ? 'warning.light'
                      : 'success.main',
                  }}
                />
              </Stack>
              <Typography variant="body1" data-testid="executive-summary">{agenticAnalysis.executive_summary}</Typography>
              {agenticAnalysis.risk_rationale && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{agenticAnalysis.risk_rationale}</Typography>
              )}
            </CardContent>
          </Card>

          {/* Attack Chains */}
          {agenticAnalysis.attack_chains.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Attack Chains</Typography>
              {agenticAnalysis.attack_chains.map((chain, idx) => (
                <Accordion key={idx} variant="outlined" defaultExpanded={idx === 0}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography fontWeight={500}>{chain.name}</Typography>
                      <Chip label={chain.likelihood} size="small" variant="outlined" />
                    </Stack>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box component="ol" sx={{ m: 0, pl: 2.5 }}>
                      {chain.steps.map((step, si) => <li key={si}><Typography variant="body2">{step}</Typography></li>)}
                    </Box>
                    {chain.impact && <Typography variant="body2" color="error" sx={{ mt: 1 }}>Impact: {chain.impact}</Typography>}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}

          {/* Priority Findings */}
          {agenticAnalysis.priority_findings.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Priority Findings</Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Title</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>CWE</TableCell>
                      <TableCell>Exploitability</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {agenticAnalysis.priority_findings.map((f, idx) => (
                      <TableRow key={idx} hover>
                        <TableCell>{f.title}</TableCell>
                        <TableCell><Chip label={f.severity} size="small" /></TableCell>
                        <TableCell>{f.cwe_id || '-'}</TableCell>
                        <TableCell>{f.exploitability || '-'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Remediation Plan */}
          {agenticAnalysis.remediation_plan.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Remediation Plan</Typography>
              <Box component="ol" sx={{ m: 0, pl: 2.5 }}>
                {agenticAnalysis.remediation_plan.map((step, idx) => (
                  <Box component="li" key={idx} sx={{ mb: 1 }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography fontWeight={500}>{step.title}</Typography>
                      <Chip label={step.effort} size="small" variant="outlined" />
                    </Stack>
                    {step.description && <Typography variant="body2" color="text.secondary">{step.description}</Typography>}
                  </Box>
                ))}
              </Box>
            </Box>
          )}

          {/* Full Narrative (collapsible) */}
          {agenticAnalysis.full_narrative && (
            <Accordion variant="outlined">
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={500}>Full Narrative</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{agenticAnalysis.full_narrative}</Typography>
              </AccordionDetails>
            </Accordion>
          )}
        </Stack>
      )}

      {/* Verification Tab (Track 92) */}
      <ExplainDialog
        open={explainOpen}
        onClose={() => { setExplainOpen(false); setExplainFinding(null); }}
        finding={explainFinding}
      />

      {activeTab === 4 + (agenticAnalysis ? 1 : 0) && verificationData && (
        <Stack spacing={2} data-testid="verification-content">
          {verificationData.method && verificationData.method.includes('heuristic') && (
            <Chip label="Heuristic Fallback - LLM unavailable" color="warning" size="small" sx={{ alignSelf: 'flex-start' }} />
          )}
          {/* Summary Card */}
          <Card variant="outlined">
            <CardContent sx={{ pb: '12px !important' }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Verification Summary</Typography>
                <Chip
                  label={verificationData.frida_available ? 'Frida Available' : 'Frida Unavailable'}
                  size="small"
                  color={verificationData.frida_available ? 'success' : 'default'}
                  variant="outlined"
                  data-testid="frida-status-chip"
                />
              </Stack>
              <Stack direction="row" spacing={3} sx={{ mb: 1.5 }}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1 }}>{verificationData.total_verified}</Typography>
                  <Typography variant="caption" color="text.secondary">Verified</Typography>
                </Box>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'success.main' }}>{verificationData.total_confirmed}</Typography>
                  <Typography variant="caption" color="text.secondary">Confirmed</Typography>
                </Box>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'warning.main' }}>{verificationData.total_fp_detected}</Typography>
                  <Typography variant="caption" color="text.secondary">FP Detected</Typography>
                </Box>
              </Stack>
              {verificationData.summary && (
                <Typography variant="body2" color="text.secondary">{verificationData.summary}</Typography>
              )}
            </CardContent>
          </Card>

          {/* Verifications Table */}
          {verificationData.verifications.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Finding Verifications</Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Finding</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Original</TableCell>
                      <TableCell>Verified</TableCell>
                      <TableCell>Evidence</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {verificationData.verifications.map((v: FindingVerification, idx: number) => (
                      <TableRow key={idx} hover>
                        <TableCell>{v.finding_title}</TableCell>
                        <TableCell>
                          <Chip
                            label={v.status}
                            size="small"
                            color={
                              v.status === 'confirmed' ? 'success'
                              : v.status === 'likely' ? 'info'
                              : v.status === 'likely_fp' ? 'warning'
                              : 'default'
                            }
                          />
                        </TableCell>
                        <TableCell>{(v.original_confidence * 100).toFixed(0)}%</TableCell>
                        <TableCell>{(v.verified_confidence * 100).toFixed(0)}%</TableCell>
                        <TableCell sx={{ maxWidth: 300 }}>
                          <Typography variant="body2" noWrap title={v.evidence}>{v.evidence || '-'}</Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Expandable details per verification */}
          {verificationData.verifications.filter((v: FindingVerification) => v.frida_script || v.reasoning).length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Verification Details</Typography>
              {verificationData.verifications
                .filter((v: FindingVerification) => v.frida_script || v.reasoning)
                .map((v: FindingVerification, idx: number) => (
                <Accordion key={idx} variant="outlined">
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography fontWeight={500}>{v.finding_title}</Typography>
                      <Chip label={v.status} size="small" variant="outlined" />
                    </Stack>
                  </AccordionSummary>
                  <AccordionDetails>
                    {v.reasoning && (
                      <Typography variant="body2" sx={{ mb: 1 }}><strong>Reasoning:</strong> {v.reasoning}</Typography>
                    )}
                    {v.frida_script && (
                      <Box sx={{ mb: 1 }}>
                        <Typography variant="body2" fontWeight={500}>Frida Script:</Typography>
                        <Box component="pre" sx={{ fontSize: 12, bgcolor: 'background.default', p: 1, borderRadius: 1, overflow: 'auto', maxHeight: 200 }}>
                          {v.frida_script}
                        </Box>
                      </Box>
                    )}
                    {v.frida_output && (
                      <Box>
                        <Typography variant="body2" fontWeight={500}>Frida Output:</Typography>
                        <Box component="pre" sx={{ fontSize: 12, bgcolor: 'background.default', p: 1, borderRadius: 1, overflow: 'auto', maxHeight: 200 }}>
                          {v.frida_output}
                        </Box>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}
        </Stack>
      )}

      {/* Orchestration Strategy Tab (Track 96) */}
      {activeTab === 4 + (agenticAnalysis ? 1 : 0) + (verificationData ? 1 : 0) && orchestrationData && (
        <Stack spacing={2} data-testid="orchestration-content">
          {/* Summary Card */}
          <Card variant="outlined">
            <CardContent>
              <Stack spacing={1.5}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Scan Strategy</Typography>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Chip label={orchestrationData.app_category} size="small" color="primary" data-testid="app-category-chip" />
                  <Chip label={`Profile: ${orchestrationData.profile_name}`} size="small" variant="outlined" />
                  <Chip label={orchestrationData.estimated_time} size="small" variant="outlined" data-testid="estimated-time" />
                </Stack>
                {orchestrationData.attack_surface.length > 0 && (
                  <Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>Attack Surface</Typography>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {orchestrationData.attack_surface.map((s, i) => (
                        <Chip key={i} label={s} size="small" variant="outlined" data-testid="attack-surface-chip" />
                      ))}
                    </Stack>
                  </Box>
                )}
                {orchestrationData.reasoning && (
                  <Typography variant="body2" color="text.secondary" data-testid="orchestration-reasoning">{orchestrationData.reasoning}</Typography>
                )}
              </Stack>
            </CardContent>
          </Card>

          {/* Selected Plugins Table */}
          {orchestrationData.selected_plugins.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Selected Plugins</Typography>
              <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Plugin Name</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Time Budget</TableCell>
                    <TableCell>Reason</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[...orchestrationData.selected_plugins]
                    .sort((a, b) => a.priority - b.priority)
                    .map((p: PluginSelection, idx: number) => (
                    <TableRow key={idx} hover>
                      <TableCell>{p.plugin_name}</TableCell>
                      <TableCell>
                        <Chip
                          label={p.priority === 1 ? 'Must Run' : p.priority === 2 ? 'Recommended' : 'Nice to Have'}
                          size="small"
                          color={p.priority === 1 ? 'error' : p.priority === 2 ? 'primary' : 'default'}
                          data-testid="priority-chip"
                        />
                      </TableCell>
                      <TableCell>{p.time_budget_seconds}s</TableCell>
                      <TableCell sx={{ maxWidth: 300 }}>
                        <Typography variant="body2" noWrap title={p.reason}>{p.reason}</Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </TableContainer>
            </Box>
          )}

          {/* Excluded Plugins Accordion */}
          {orchestrationData.excluded_plugins.length > 0 && (
            <Accordion variant="outlined" data-testid="excluded-plugins-section">
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={500}>Excluded Plugins ({orchestrationData.excluded_plugins.length})</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Plugin</TableCell>
                      <TableCell>Reason</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {orchestrationData.excluded_plugins.map((p, idx) => (
                      <TableRow key={idx} hover>
                        <TableCell>{p.name}</TableCell>
                        <TableCell>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </AccordionDetails>
            </Accordion>
          )}
        </Stack>
      )}

      {/* Triage Tab (Track 99) */}
      {activeTab === 4 + (agenticAnalysis ? 1 : 0) + (verificationData ? 1 : 0) + (orchestrationData ? 1 : 0) && triageData && (
        <Stack spacing={2} data-testid="triage-content">
          {/* Heuristic fallback warning */}
          {triageData.method && triageData.method.includes('heuristic') && (
            <Chip label="Heuristic Fallback - LLM unavailable" color="warning" size="small" sx={{ alignSelf: 'flex-start' }} />
          )}
          {/* Summary Card */}
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Triage Summary</Typography>
              {triageData.summary && (
                <Typography variant="body1" sx={{ mb: 1.5 }} data-testid="triage-summary">{triageData.summary}</Typography>
              )}
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap data-testid="triage-stats">
                {(() => {
                  const counts: Record<string, number> = {};
                  triageData.classified_findings.forEach((f: ClassifiedFindingType) => {
                    counts[f.classification] = (counts[f.classification] || 0) + 1;
                  });
                  const colorMap: Record<string, 'success' | 'info' | 'warning' | 'error' | 'default'> = {
                    confirmed_tp: 'error',
                    likely_tp: 'warning',
                    needs_review: 'info',
                    likely_fp: 'success',
                    informational: 'default',
                  };
                  return Object.entries(counts).map(([cls, count]) => (
                    <Chip
                      key={cls}
                      label={`${count} ${cls.replace(/_/g, ' ')}`}
                      size="small"
                      color={colorMap[cls] || 'default'}
                      data-testid={`triage-stat-${cls}`}
                    />
                  ));
                })()}
              </Stack>
            </CardContent>
          </Card>

          {/* Classified Findings Table */}
          {triageData.classified_findings.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Classified Findings</Typography>
              <TableContainer component={Paper} variant="outlined">
              <Table size="small" data-testid="classified-findings-table">
                <TableHead>
                  <TableRow>
                    <TableCell>Finding</TableCell>
                    <TableCell>Classification</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Reasoning</TableCell>
                    <TableCell>Feedback</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {triageData.classified_findings.map((f: ClassifiedFindingType, idx: number) => {
                    const colorMap: Record<string, 'success' | 'info' | 'warning' | 'error' | 'default'> = {
                      confirmed_tp: 'error',
                      likely_tp: 'warning',
                      needs_review: 'info',
                      likely_fp: 'success',
                      informational: 'default',
                    };
                    return (
                      <TableRow key={idx} hover>
                        <TableCell>{f.finding_title}</TableCell>
                        <TableCell>
                          <Chip
                            label={f.classification.replace(/_/g, ' ')}
                            size="small"
                            color={colorMap[f.classification] || 'default'}
                            data-testid="classification-chip"
                          />
                        </TableCell>
                        <TableCell><Chip label={f.severity} size="small" /></TableCell>
                        <TableCell>{(f.confidence * 100).toFixed(0)}%</TableCell>
                        <TableCell sx={{ maxWidth: 300 }}>
                          <Typography variant="body2" noWrap title={f.reasoning}>{f.reasoning || '-'}</Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            <Button
                              size="small"
                              color="success"
                              data-testid={`accept-finding-${idx}`}
                              onClick={async () => {
                                try {
                                  const reportFile = data?.metadata?.report_file || id || '';
                                  await feedbackApi.submitTriageFeedback({
                                    report_file: String(reportFile),
                                    finding_title: f.finding_title,
                                    action: 'accept',
                                  });
                                } catch { /* best-effort */ }
                              }}
                            >
                              Accept
                            </Button>
                            <Button
                              size="small"
                              color="warning"
                              data-testid={`reject-finding-${idx}`}
                              onClick={() => {
                                setFeedbackFinding(f.finding_title);
                                setFeedbackDialogOpen(true);
                              }}
                            >
                              Reject
                            </Button>
                          </Box>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              </TableContainer>
            </Box>
          )}

          {/* Finding Groups */}
          {triageData.groups.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Finding Groups</Typography>
              {triageData.groups.map((g: FindingGroupType, idx: number) => (
                <Accordion key={idx} variant="outlined" defaultExpanded={idx === 0}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography fontWeight={500} data-testid="group-label">{g.label}</Typography>
                      <Chip label={`${g.finding_titles.length} findings`} size="small" variant="outlined" />
                    </Stack>
                  </AccordionSummary>
                  <AccordionDetails>
                    {g.root_cause && (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        <strong>Root Cause:</strong> {g.root_cause}
                      </Typography>
                    )}
                    <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                      {g.finding_titles.map((title, ti) => (
                        <li key={ti}><Typography variant="body2">{title}</Typography></li>
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}

          {/* Priority Order */}
          {triageData.priority_order.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>Priority Order</Typography>
              <Box component="ol" sx={{ m: 0, pl: 2.5 }} data-testid="priority-order-list">
                {triageData.priority_order.map((title, idx) => (
                  <li key={idx}><Typography variant="body2">{title}</Typography></li>
                ))}
              </Box>
            </Box>
          )}

          {/* Triage Notes */}
          {Object.keys(triageData.triage_notes).length > 0 && (
            <Accordion variant="outlined" data-testid="triage-notes-section">
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={500}>Triage Notes ({Object.keys(triageData.triage_notes).length})</Typography>
              </AccordionSummary>
              <AccordionDetails>
                {Object.entries(triageData.triage_notes).map(([key, value]) => (
                  <Box key={key} sx={{ mb: 1 }}>
                    <Typography variant="body2" fontWeight={500}>{key}</Typography>
                    <Typography variant="body2" color="text.secondary">{value}</Typography>
                  </Box>
                ))}
              </AccordionDetails>
            </Accordion>
          )}

          {/* Historical Context (Track 101) */}
          <Accordion
            variant="outlined"
            data-testid="historical-context-section"
            expanded={historyExpanded}
            onChange={(_, isExpanded) => setHistoryExpanded(isExpanded)}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography fontWeight={500}>Historical Context</Typography>
                {historyLoaded && historyItems.length > 0 && (
                  <Chip label={`${historyItems.length} matches`} size="small" variant="outlined" />
                )}
              </Stack>
            </AccordionSummary>
            <AccordionDetails>
              {historyLoading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }} data-testid="history-loading">
                  <CircularProgress size={24} />
                </Box>
              )}
              {historyLoaded && historyVectorAvail === false && (
                <Alert severity="info" data-testid="history-vector-disabled">
                  Vector database is not available. Enable AODS_VECTOR_DB_ENABLED=1 for historical context.
                </Alert>
              )}
              {historyLoaded && historyVectorAvail && historyItems.length === 0 && (
                <Typography variant="body2" color="text.secondary" data-testid="history-empty">
                  No historical triage decisions found for similar findings.
                </Typography>
              )}
              {historyLoaded && historyItems.length > 0 && (
                <Table size="small" data-testid="history-table">
                  <TableHead>
                    <TableRow>
                      <TableCell>Similar Finding</TableCell>
                      <TableCell>Classification</TableCell>
                      <TableCell>Analyst</TableCell>
                      <TableCell>Similarity</TableCell>
                      <TableCell>Date</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {historyItems.map((item, idx) => (
                      <TableRow key={idx} hover>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 280 }}>
                            {item.finding_title}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={item.new_classification || item.action}
                            size="small"
                            color={item.new_classification?.includes('tp') ? 'error' : item.new_classification?.includes('fp') ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell>{item.user}</TableCell>
                        <TableCell>{(item.similarity_score * 100).toFixed(0)}%</TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap>
                            {item.timestamp ? formatDateTime(item.timestamp) : ' - '}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </AccordionDetails>
          </Accordion>
        </Stack>
      )}

      {/* Remediation Tab (Track 100) */}
      {activeTab === 4 + (agenticAnalysis ? 1 : 0) + (verificationData ? 1 : 0) + (orchestrationData ? 1 : 0) + (triageData ? 1 : 0) && remediationData && (
        <Stack spacing={2} data-testid="remediation-panel">
          {remediationData.method && remediationData.method.includes('heuristic') && (
            <Chip label="Heuristic Fallback - LLM unavailable" color="warning" size="small" sx={{ alignSelf: 'flex-start' }} />
          )}
          <Card variant="outlined">
            <CardContent sx={{ pb: '12px !important' }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Remediation Summary</Typography>
              {remediationData.summary && (
                <Typography variant="body2" sx={{ mb: 1.5, whiteSpace: 'pre-line', color: 'text.secondary' }} data-testid="remediation-summary">
                  {remediationData.summary}
                </Typography>
              )}
              <Stack direction="row" spacing={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, color: 'success.main' }}>{remediationData.total_with_patches}</Typography>
                  <Typography variant="caption" color="text.secondary">of {remediationData.total_findings} patched</Typography>
                </Box>
                <Box sx={{ textAlign: 'center' }}>
                  <Chip
                    label={remediationData.overall_effort}
                    color={
                      remediationData.overall_effort === 'easy' ? 'success' :
                      remediationData.overall_effort === 'moderate' ? 'warning' : 'error'
                    }
                    size="small"
                    sx={{ mt: 0.5, textTransform: 'capitalize' }}
                  />
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.25 }}>Overall effort</Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {remediationData.remediations.length > 0 && (
            <>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Code Patches ({remediationData.remediations.length})</Typography>
              {remediationData.remediations.map((r: FindingRemediation, idx: number) => (
                <Accordion key={idx} variant="outlined" data-testid={`remediation-item-${idx}`}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                      <Typography sx={{ flexGrow: 1 }}>{r.finding_title}</Typography>
                      <Chip
                        label={r.difficulty}
                        color={r.difficulty === 'easy' ? 'success' : r.difficulty === 'moderate' ? 'warning' : 'error'}
                        size="small"
                      />
                      {r.cwe_id && <Chip label={r.cwe_id} variant="outlined" size="small" />}
                      <Chip
                        label="Feedback"
                        size="small"
                        variant="outlined"
                        onClick={(e) => { e.stopPropagation(); setFeedbackFinding(r.finding_title); setFeedbackAgentType('remediate'); setFeedbackDialogOpen(true); }}
                        data-testid={`remediation-feedback-${idx}`}
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {r.explanation && (
                      <Typography variant="body2" sx={{ mb: 2 }}>{r.explanation}</Typography>
                    )}
                    {r.current_code && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="caption" color="error.main" fontWeight={600} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'error.main' }} />
                          Vulnerable Code
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 1.5, borderColor: 'error.main', borderLeftWidth: 3, fontFamily: '"Fira Code", "JetBrains Mono", monospace', fontSize: '0.78rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', overflow: 'auto', maxHeight: 300, bgcolor: 'action.hover' }} data-testid={`current-code-${idx}`}>
                          {r.current_code}
                        </Paper>
                      </Box>
                    )}
                    {r.fixed_code && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="caption" color="success.main" fontWeight={600} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'success.main' }} />
                          Fixed Code
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 1.5, borderColor: 'success.main', borderLeftWidth: 3, fontFamily: '"Fira Code", "JetBrains Mono", monospace', fontSize: '0.78rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', overflow: 'auto', maxHeight: 300, bgcolor: 'action.hover' }} data-testid={`fixed-code-${idx}`}>
                          {r.fixed_code}
                        </Paper>
                      </Box>
                    )}
                    {r.breaking_changes && (
                      <Alert severity="warning" sx={{ mb: 1 }}>{r.breaking_changes}</Alert>
                    )}
                    {r.test_suggestion && (
                      <Typography variant="body2" sx={{ mb: 1 }}><strong>Test:</strong> {r.test_suggestion}</Typography>
                    )}
                    {r.references.length > 0 && (
                      <Box>
                        <Typography variant="caption" fontWeight={600}>References</Typography>
                        {r.references.map((ref, ri) => (
                          <Typography key={ri} variant="body2" sx={{ fontSize: '0.75rem' }}>
                            {ref}
                          </Typography>
                        ))}
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </>
          )}
        </Stack>
      )}

      {/* Triage Feedback Dialog (Track 96) */}
      <Dialog open={feedbackDialogOpen} onClose={() => setFeedbackDialogOpen(false)} data-testid="triage-feedback-dialog">
        <DialogTitle>Reclassify Finding</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>{feedbackFinding}</Typography>
          <FormControl fullWidth sx={{ mb: 2, mt: 1 }}>
            <InputLabel>New Classification</InputLabel>
            <Select
              value={feedbackClassification}
              label="New Classification"
              onChange={e => setFeedbackClassification(e.target.value)}
              data-testid="feedback-classification-select"
            >
              <MenuItem value="confirmed_tp">Confirmed TP</MenuItem>
              <MenuItem value="likely_tp">Likely TP</MenuItem>
              <MenuItem value="needs_review">Needs Review</MenuItem>
              <MenuItem value="likely_fp">Likely FP</MenuItem>
              <MenuItem value="informational">Informational</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Reason (optional)"
            value={feedbackReason}
            onChange={e => setFeedbackReason(e.target.value)}
            data-testid="feedback-reason"
            multiline
            rows={2}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFeedbackDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!feedbackClassification}
            data-testid="feedback-submit-btn"
            onClick={async () => {
              try {
                const reportFile = data?.metadata?.report_file || id || '';
                await feedbackApi.submitTriageFeedback({
                  report_file: String(reportFile),
                  finding_title: feedbackFinding,
                  action: 'reject',
                  new_classification: feedbackClassification,
                  reason: feedbackReason || undefined,
                  agent_type: feedbackAgentType,
                });
                setFeedbackDialogOpen(false);
                setFeedbackClassification('');
                setFeedbackReason('');
              } catch {
                // Silently handle - feedback is best-effort
              }
            }}
          >
            Submit
          </Button>
        </DialogActions>
      </Dialog>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
