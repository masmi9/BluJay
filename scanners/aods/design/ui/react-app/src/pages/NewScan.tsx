import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AODSApiClient } from '../services/api';
import { fireNotification } from '../lib/notify';
import { useAuth } from '../context/AuthContext';
import { emitAudit } from '../utils/audit';
import { useLocalStorage, useScanOptions } from '../hooks';
import {
  Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Divider,
  FormControl, IconButton, InputLabel, LinearProgress, OutlinedInput,
  Stack, Tooltip, Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import SecurityIcon from '@mui/icons-material/Security';
import { secureFetch } from '../lib/api';
import { PackageConfirmDialog } from '../components/PackageConfirmDialog';
import { useToast } from '../hooks/useToast';
import { AppToast } from '../components';
import type { PackageDetectionInfo, ApkInspectResult } from '../types';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { ScanPresetsBar } from './newscan/ScanPresetsBar';
import type { PresetTarget } from './newscan/ScanPresetsBar';
import { ScanOptionsForm } from './newscan/ScanOptionsForm';
import { ScanProgressPanel } from './newscan/ScanProgressPanel';
import { RecentApksBar } from './newscan/RecentApksBar';

export function NewScan() {
  const api = useMemo(() => new AODSApiClient(), []);
  const auth = useAuth();
  const [apkPath, setApkPath] = useLocalStorage('aodsNewScan_apk', '');
  const { options, updateOption, bulkUpdate } = useScanOptions();
  const [sessionId, setSessionId] = useState<string | null>(() => { try { return localStorage.getItem('aodsNewScan_session') || null; } catch { return null; } });
  const [status, setStatus] = useState<string | null>(() => { try { return localStorage.getItem('aodsNewScan_status') || null; } catch { return null; } });
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string | null>(() => { try { return localStorage.getItem('aodsNewScan_progress') || null; } catch { return null; } });
  const esRef = useRef<EventSource | null>(null);
  const logEsRef = useRef<EventSource | null>(null);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [policy, setPolicy] = useState<any | null>(null);
  const [policyBusy, setPolicyBusy] = useState<boolean>(false);
  const { toast, showToast, closeToast } = useToast();
  const [effOpts, setEffOpts] = useState<{ applied?: any; ignored?: any } | null>(null);
  const [recents, setRecents] = useLocalStorage<string[]>('aodsNewScan_recents', []);
  const [uploadBusy, setUploadBusy] = useState<boolean>(false);
  const [showPackageConfirm, setShowPackageConfirm] = useState<boolean>(false);
  const [pendingDetection, setPendingDetection] = useState<PackageDetectionInfo | null>(null);
  const [pendingSessionId, setPendingSessionId] = useState<string | null>(null);
  const [confirmLoading, setConfirmLoading] = useState<boolean>(false);
  const [skipPackageConfirmation, setSkipPackageConfirmation] = useState<boolean>(false);
  const [showLogs, setShowLogs] = useState<boolean>(false);
  const [stageHistory, setStageHistory] = useState<Array<{ stage: string; pct: number; timestamp: number }>>([]);
  const [inspectResult, setInspectResult] = useState<ApkInspectResult | null>(null);
  const [inspectBusy, setInspectBusy] = useState(false);
  const [toolCaps, setToolCaps] = useState<Record<string, boolean>>({});

  // Load tool capabilities on mount
  useEffect(() => {
    secureFetch('/tools/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data) {
          setToolCaps({
            static: true, // Always available
            dynamic: !!data.adb?.available && !!data.frida?.available,
            native: !!data.ghidra?.available,
            jadx: !!data.jadx?.available,
          });
        }
      })
      .catch(() => {});
  }, []);

  // Destructure scan options for convenient access
  const {
    scanProfile, scanMode, outputFormats, staticOnly, enableFilter, profile,
    fridaMode, resourceConstrained, maxWorkers, timeoutsProfile,
    pluginsIncludeCSV, pluginsExcludeCSV, ciMode, failOnCritical, failOnHigh,
    frameworks, compliance, mlConfidence, mlModelsPath,
    dedupStrategy, dedupThreshold, progressiveAnalysis, sampleRate,
    agentEnabled, agentSteps,
  } = options;

  const [apkTouched, setApkTouched] = useState(false);
  const errors = useMemo<string[]>(() => {
    const msgs: string[] = [];
    try { if (!apkPath && apkTouched) msgs.push('APK path is required'); } catch {}
    if (staticOnly && fridaMode) msgs.push('Frida mode is ignored when Static Only is enabled');
    if (maxWorkers && (isNaN(Number(maxWorkers)) || Number(maxWorkers) < 1 || Number(maxWorkers) > 64)) msgs.push('Max Workers must be an integer between 1 and 64');
    if (mlConfidence && (isNaN(Number(mlConfidence)) || Number(mlConfidence) < 0 || Number(mlConfidence) > 1)) msgs.push('ML Confidence must be between 0.0 and 1.0');
    if (dedupThreshold && (isNaN(Number(dedupThreshold)) || Number(dedupThreshold) < 0 || Number(dedupThreshold) > 1)) msgs.push('Dedup Threshold must be between 0.0 and 1.0');
    if (progressiveAnalysis && sampleRate && (isNaN(Number(sampleRate)) || Number(sampleRate) < 0.1 || Number(sampleRate) > 1.0)) msgs.push('Sample Rate must be between 0.1 and 1.0');
    return msgs;
  }, [apkPath, apkTouched, staticOnly, fridaMode, maxWorkers, mlConfidence, dedupThreshold, progressiveAnalysis, sampleRate]);

  // CLI preview string for ScanProgressPanel
  const cliPreview = useMemo(() => {
    const qp = (s: string) => /\s/.test(s) ? `"${s}"` : s;
    const parts: string[] = ['python', 'dyna.py', '--apk', qp(apkPath || '<apk>')];
    const m = String(scanMode || '').toLowerCase();
    if (m === 'safe' || m === 'deep') parts.push('--mode', m);
    const sp = String(scanProfile || '').toLowerCase();
    if (['lightning','fast','standard','deep'].includes(sp)) parts.push('--profile', sp);
    const f = (outputFormats && outputFormats.length ? outputFormats : ['json','html']).filter(x => ['json','html','txt','csv'].includes(String(x)));
    if (f.length) parts.push('--formats', ...f);
    if (staticOnly) parts.push('--static-only');
    if (maxWorkers && !isNaN(Number(maxWorkers))) parts.push('--max-workers', String(Number(maxWorkers)));
    if (ciMode) parts.push('--ci-mode');
    if (failOnCritical) parts.push('--fail-on-critical');
    if (failOnHigh) parts.push('--fail-on-high');
    if (frameworks && frameworks.length) {
      const fw = frameworks.filter(x => ['flutter','react_native','xamarin','pwa','all'].includes(String(x)));
      if (fw.length) parts.push('--frameworks', ...fw);
    }
    if (compliance) {
      if (String(compliance) === 'all') parts.push('--compliance', 'owasp');
      else if (['nist','masvs','owasp','iso27001'].includes(String(compliance))) parts.push('--compliance', String(compliance));
    }
    if (mlConfidence && !isNaN(Number(mlConfidence))) parts.push('--ml-confidence', String(Number(mlConfidence)));
    if (mlModelsPath) parts.push('--ml-models-path', qp(mlModelsPath));
    if (dedupStrategy && ['basic','intelligent','aggressive','conservative'].includes(String(dedupStrategy))) parts.push('--dedup-strategy', String(dedupStrategy));
    if (dedupThreshold && !isNaN(Number(dedupThreshold))) parts.push('--dedup-threshold', String(Number(dedupThreshold)));
    if (progressiveAnalysis) {
      parts.push('--progressive-analysis');
      if (sampleRate && !isNaN(Number(sampleRate))) parts.push('--sample-rate', String(Number(sampleRate)));
    }
    return parts.join(' ');
  }, [apkPath, scanMode, scanProfile, outputFormats, staticOnly, maxWorkers, ciMode, failOnCritical, failOnHigh, frameworks, compliance, mlConfidence, mlModelsPath, dedupStrategy, dedupThreshold, progressiveAnalysis, sampleRate]);

  // --- SSE stream helpers ---
  function setupProgressStream(base: string, sid: string, tokenParam: string) {
    const es = new EventSource(`${base}/scans/${encodeURIComponent(sid)}/progress/stream${tokenParam}`);
    esRef.current = es;
    const handler = (ev: MessageEvent) => {
      try {
        const p = JSON.parse(ev.data);
        setProgress(`${Number(p.pct || 0).toFixed(0)}% - ${p.stage}`);
        const s = String(p.stage || '').toLowerCase();
        if (s) {
          setStageHistory(prev => {
            if (prev.length === 0 || prev[prev.length - 1].stage !== s) {
              return [...prev, { stage: s, pct: Number(p.pct || 0), timestamp: Date.now() }];
            }
            return prev;
          });
        }
        if (['running','completed','failed','cancelled','queued','starting'].includes(s)) {
          setStatus(s);
          try { localStorage.setItem('aodsNewScan_status', s); } catch {}
        }
      } catch {}
    };
    es.onmessage = handler;
    es.addEventListener('end', () => { try { es.close(); } catch {} esRef.current = null; });
    let retries = 0;
    es.onerror = () => {
      try { es.close(); } catch {}
      esRef.current = null;
      retries++;
      const delay = Math.min(10000, 500 * Math.pow(2, retries - 1));
      setProgress(`Stream error. Reconnecting in ${Math.round(delay / 1000)}s...`);
      setTimeout(() => {
        try {
          const rEs = new EventSource(`${base}/scans/${encodeURIComponent(sid)}/progress/stream${tokenParam}`);
          esRef.current = rEs;
          rEs.onopen = () => { retries = 0; };
          rEs.onmessage = handler;
          rEs.addEventListener('end', () => { try { rEs.close(); } catch {} esRef.current = null; });
          rEs.onerror = es.onerror;
        } catch {}
      }, delay);
    };
    return es;
  }

  function setupPolling(sid: string, es: EventSource) {
    const timer = setInterval(async () => {
      try {
        const det = await api.getScanDetails(sid);
        if (det && det.effectiveOptions) setEffOpts(det.effectiveOptions);
        if (det && det.status) {
          const ds = String(det.status).toLowerCase();
          setStatus(ds);
          try { localStorage.setItem('aodsNewScan_status', ds); } catch {}
          if (['completed','failed','cancelled'].includes(ds)) clearInterval(timer);
        }
      } catch {}
    }, 1500);
    es.addEventListener('end', () => { try { clearInterval(timer); } catch {} });
  }

  function setupLogsStream(base: string, sid: string, tokenParam: string) {
    const les = new EventSource(`${base}/scans/${encodeURIComponent(sid)}/logs/stream${tokenParam}`);
    logEsRef.current = les;
    les.onmessage = (ev) => {
      try {
        const j = JSON.parse(ev.data);
        if (j && typeof j.line === 'string') setLogLines((prev) => [...prev.slice(-999), j.line]);
      } catch {}
    };
    les.addEventListener('end', () => { try { les.close(); } catch {} logEsRef.current = null; });
    les.onerror = () => { /* ignore */ };
  }

  async function connectStreams(sid: string) {
    const base = await (api as any).baseUrlPromise;
    const tokenParam = auth.token ? `?token=${encodeURIComponent(auth.token)}` : '';
    const es = setupProgressStream(base, sid, tokenParam);
    try { setupPolling(sid, es); } catch {}
    try { setupLogsStream(base, sid, tokenParam); } catch {}
  }

  // --- Handlers ---
  async function handleStart() {
    setError(null);
    setStatus('starting');
    showToast('Starting...');
    try {
      if (!apkPath) throw new Error('Enter an APK path');
      try { if (esRef.current) { esRef.current.close(); esRef.current = null; } } catch {}
      try { if (logEsRef.current) { logEsRef.current.close(); logEsRef.current = null; } } catch {}
      setLogLines([]); setStageHistory([]);
      const resp = await api.startScan(apkPath, { enableThresholdFiltering: enableFilter, scanOptions: {
        profile: scanProfile, mode: scanMode,
        formats: outputFormats && outputFormats.length ? outputFormats : ['json','html'],
        staticOnly, resourceConstrained,
        fridaMode: staticOnly ? undefined : (fridaMode || undefined),
        maxWorkers: maxWorkers ? Number(maxWorkers) : undefined,
        timeoutsProfile: timeoutsProfile || undefined,
        pluginsInclude: (pluginsIncludeCSV || '').split(',').map(s => s.trim()).filter(Boolean) || undefined,
        pluginsExclude: (pluginsExcludeCSV || '').split(',').map(s => s.trim()).filter(Boolean) || undefined,
        ciMode, failOnCritical, failOnHigh,
        frameworks: frameworks && frameworks.length ? frameworks : undefined,
        compliance: compliance || undefined,
        mlConfidence: mlConfidence ? Number(mlConfidence) : undefined,
        mlModelsPath: mlModelsPath || undefined,
        dedupStrategy: dedupStrategy || undefined,
        dedupThreshold: dedupThreshold ? Number(dedupThreshold) : undefined,
        progressiveAnalysis: progressiveAnalysis || undefined,
        sampleRate: sampleRate ? Number(sampleRate) : undefined,
        agentEnabled: agentEnabled || undefined,
        agentSteps: agentEnabled && agentSteps.length ? agentSteps : undefined,
      } });
      const sid = (resp as any).sessionId ?? (resp as any).id ?? null;
      if (!sid) throw new Error('missing session id');

      // Package confirmation flow
      if (resp.status === 'awaiting_confirmation' && resp.packageDetection) {
        if (skipPackageConfirmation && resp.packageDetection.packageName) {
          showToast('Auto-confirming package (skip enabled)...');
          try {
            const confirmResp = await api.confirmPackage(sid, resp.packageDetection.packageName);
            setSessionId(sid); setStatus(confirmResp.status || 'queued'); setProgress('0% - queued');
            try { localStorage.setItem('aodsNewScan_session', sid); localStorage.setItem('aodsNewScan_status', confirmResp.status || 'queued'); } catch {}
            emitAudit('confirm_package', auth.roles.includes('admin') ? 'admin' : 'user', sid, { packageName: resp.packageDetection.packageName, autoConfirmed: true });
          } catch (e: any) {
            setError(`Auto-confirm failed: ${e?.message || 'Unknown error'}`);
            setSessionId(sid); setStatus('awaiting_confirmation');
            setPendingSessionId(sid); setPendingDetection(resp.packageDetection); setShowPackageConfirm(true);
            return;
          }
        } else {
          setSessionId(sid); setStatus('awaiting_confirmation');
          setPendingSessionId(sid); setPendingDetection(resp.packageDetection); setShowPackageConfirm(true);
          try { localStorage.setItem('aodsNewScan_session', sid); localStorage.setItem('aodsNewScan_status', 'awaiting_confirmation'); } catch {}
          showToast('Package confirmation needed');
          return;
        }
      }

      if (resp.warning) showToast(resp.warning, 'warning');

      setSessionId(sid); setStatus(resp.status); setProgress('0% - queued');
      try { localStorage.setItem('aodsNewScan_session', sid); localStorage.setItem('aodsNewScan_status', String(resp.status)); localStorage.setItem('aodsNewScan_progress', '0% - queued'); } catch {}
      try {
        const next = [apkPath, ...recents.filter(r => r !== apkPath)].slice(0, 5);
        setRecents(next);
      } catch {}
      emitAudit('start_scan', auth.roles.includes('admin') ? 'admin' : 'user', apkPath, { sessionId: sid });
      try { await connectStreams(sid); } catch {}
    } catch (e: any) {
      setError(e?.message || 'Failed to start scan');
      setStatus('error');
      setProgress(null);
      try { localStorage.setItem('aodsNewScan_status', 'error'); } catch {}
    }
  }

  async function handleCancel() {
    if (!sessionId) return;
    setError(null);
    try {
      if (esRef.current) { try { esRef.current.close(); } catch {} esRef.current = null; }
      if (logEsRef.current) { try { logEsRef.current.close(); } catch {} logEsRef.current = null; }
      setProgress('100% - cancelled'); setStatus('cancelled');
      const res = await api.cancelScan(sessionId);
      if (res?.status && res.status !== 'cancelled') setStatus(res.status);
      emitAudit('cancel_scan', auth.roles.includes('admin') ? 'admin' : 'user', sessionId);
      try { localStorage.removeItem('aodsNewScan_session'); localStorage.setItem('aodsNewScan_status', 'cancelled'); localStorage.setItem('aodsNewScan_progress', '100% - cancelled'); } catch {}
      setSessionId(null); setLogLines([]);
    } catch (e: any) {
      setError(e?.message || 'Failed to cancel');
    }
  }

  async function handleConfirmPackage(packageName: string, skipFuture?: boolean) {
    if (!pendingSessionId) {
      setError('Session expired or not found. Please start a new scan.');
      setShowPackageConfirm(false); setPendingDetection(null);
      return;
    }
    setConfirmLoading(true); setError(null);
    if (skipFuture) setSkipPackageConfirmation(true);
    try {
      const resp = await api.confirmPackage(pendingSessionId, packageName);
      setShowPackageConfirm(false); setPendingDetection(null);
      setStatus(resp.status || 'queued'); setProgress('0% - queued');
      try { localStorage.setItem('aodsNewScan_status', resp.status || 'queued'); localStorage.setItem('aodsNewScan_progress', '0% - queued'); } catch {}
      showToast('Package confirmed, scan starting...');
      emitAudit('confirm_package', auth.roles.includes('admin') ? 'admin' : 'user', pendingSessionId, { packageName });
      const sid = pendingSessionId;
      setPendingSessionId(null);
      try { await connectStreams(sid); } catch {}
    } catch (e: any) {
      setError(e?.message || 'Failed to confirm package');
    } finally {
      setConfirmLoading(false);
    }
  }

  async function handleCancelConfirm() {
    setShowPackageConfirm(false); setPendingDetection(null);
    if (pendingSessionId) {
      try {
        await api.cancelScan(pendingSessionId);
        emitAudit('cancel_scan', auth.roles.includes('admin') ? 'admin' : 'user', pendingSessionId, { reason: 'package_confirmation_cancelled' });
      } catch {}
    }
    setPendingSessionId(null); setSessionId(null); setStatus(null); setProgress(null);
    try { localStorage.removeItem('aodsNewScan_session'); localStorage.removeItem('aodsNewScan_status'); localStorage.removeItem('aodsNewScan_progress'); } catch {}
    showToast('Scan cancelled');
  }

  async function handleRetryDetection(): Promise<{ improved: boolean; detection?: PackageDetectionInfo; error?: string }> {
    if (!pendingSessionId) return { improved: false, error: 'No pending session' };
    try {
      const resp = await api.retryDetection(pendingSessionId);
      if (resp.improved && resp.packageDetection) {
        setPendingDetection(resp.packageDetection as PackageDetectionInfo);
        return { improved: true, detection: resp.packageDetection as PackageDetectionInfo };
      }
      return { improved: false, error: resp.error };
    } catch (e: any) {
      return { improved: false, error: e?.message || 'Retry failed' };
    }
  }

  async function refreshPolicy() {
    setPolicyBusy(true);
    try {
      const params = new URLSearchParams({ apkPath, profile });
      if (enableFilter) params.set('requirements', 'imports');
      const pol = await secureFetch(`/decomp/policy?${params.toString()}`).then(r => r.ok ? r.json() : null).catch(() => null);
      setPolicy(pol);
    } catch (e: any) {
      setError(e?.message || 'Failed to load decompilation policy');
    } finally { setPolicyBusy(false); }
  }

  function handleSelectPreset(preset: PresetTarget) {
    bulkUpdate({
      scanProfile: preset.scanProfile,
      scanMode: preset.scanMode,
      staticOnly: preset.staticOnly,
      fridaMode: preset.fridaMode,
      resourceConstrained: preset.resourceConstrained,
      ...(preset.outputFormats ? { outputFormats: preset.outputFormats } : {}),
      ...(preset.ciMode !== undefined ? { ciMode: preset.ciMode } : {}),
      ...(preset.failOnCritical !== undefined ? { failOnCritical: preset.failOnCritical } : {}),
      ...(preset.failOnHigh !== undefined ? { failOnHigh: preset.failOnHigh } : {}),
    });
  }

  function handleSelectRecentApk(path: string) {
    setApkPath(path);
    setSessionId(null);
    setStatus(null);
    setProgress(null);
    setLogLines([]);
  }

  // --- Effects ---
  useEffect(() => {
    if (!apkPath) { setPolicy(null); return; }
    refreshPolicy().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apkPath, enableFilter, profile]);

  // localStorage persistence for status/progress (managed manually, not via useLocalStorage)
  useEffect(() => { try { if (status) localStorage.setItem('aodsNewScan_status', status); } catch {} }, [status]);
  useEffect(() => { try { if (progress) localStorage.setItem('aodsNewScan_progress', progress); } catch {} }, [progress]);

  // Keyboard shortcuts
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const key = (e.key || '').toLowerCase();
      if ((e.ctrlKey || e.metaKey) && key === 'enter') { e.preventDefault(); if (apkPath) handleStart(); }
      else if (key === 'escape') { if (sessionId) { e.preventDefault(); handleCancel(); } }
      else if (e.altKey && key === 'f') { e.preventDefault(); updateOption('enableFilter', !enableFilter); }
      else if (e.altKey && key === 'p') {
        e.preventDefault();
        const order = ['dev', 'staging', 'prod'];
        const idx = order.indexOf(String(profile));
        updateOption('profile', order[(idx + 1) % order.length]);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [apkPath, sessionId, profile, enableFilter]);

  // Auto-resume progress stream on mount
  useEffect(() => {
    (async () => {
      try {
        const sid = sessionId || (localStorage.getItem('aodsNewScan_session') || null);
        if (!sid || esRef.current) return;
        const storedStatus = status || localStorage.getItem('aodsNewScan_status');
        if (storedStatus === 'awaiting_confirmation') return;
        const base = await (api as any).baseUrlPromise;
        const tokenParam = auth.token ? `?token=${encodeURIComponent(auth.token)}` : '';
        const es = new EventSource(`${base}/scans/${encodeURIComponent(sid)}/progress/stream${tokenParam}`);
        esRef.current = es;
        es.onmessage = (ev) => { try { const p = JSON.parse(ev.data); setProgress(`${Number(p.pct || 0).toFixed(0)}% - ${p.stage}`); } catch {} };
        es.addEventListener('end', () => { es.close(); esRef.current = null; });
        es.onerror = () => { if (!progress) setProgress('stream unavailable'); };
        try {
          const timer = setInterval(async () => {
            try {
              const det = await api.getScanDetails(sid);
              if (det && det.effectiveOptions) setEffOpts(det.effectiveOptions);
              if (det && det.status && ['completed','failed','cancelled'].includes(String(det.status).toLowerCase())) clearInterval(timer);
            } catch {}
          }, 1500);
          es.addEventListener('end', () => { try { clearInterval(timer); } catch {} });
        } catch {}
        try { setupLogsStream(base, sid, tokenParam); } catch {}
      } catch {}
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, status, auth.token]);

  // Cleanup streams on unmount
  useEffect(() => {
    return () => {
      try { if (esRef.current) { esRef.current.close(); esRef.current = null; } } catch {}
      try { if (logEsRef.current) { logEsRef.current.close(); logEsRef.current = null; } } catch {}
    };
  }, []);

  // Clear persisted session on completion
  useEffect(() => {
    const done = (status || '').toLowerCase();
    if (['completed','failed','cancelled'].includes(done)) {
      try { localStorage.removeItem('aodsNewScan_session'); } catch {}
      if (done === 'completed') fireNotification('Scan complete', `Scan ${sessionId || ''} finished successfully`);
      if (done === 'failed') fireNotification('Scan failed', `Scan ${sessionId || ''} failed`);
    }
  }, [status]);

  // Discover latest report
  const [latestReport, setLatestReport] = useState<{ name: string; path: string } | null>(null);
  useEffect(() => {
    (async () => {
      try {
        if (!status || String(status).toLowerCase() !== 'completed') { setLatestReport(null); return; }
        const r = await secureFetch('/reports/list');
        if (!r.ok) return;
        const j = await r.json();
        const list = Array.isArray(j.items) ? j.items : [];
        if (list.length) setLatestReport({ name: list[0].name, path: list[0].path });
      } catch {}
    })();
  }, [status]);

  // --- Render ---
  return (
    <Box sx={{ maxWidth: 900, mx: 'auto' }}>
      <Stack spacing={3}>
        {/* Header */}
        <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
          <Stack direction="row" spacing={1} alignItems="center">
            <SecurityIcon color="primary" />
            <Typography variant="h4" component="h1">New Scan</Typography>
            <Tooltip title={
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>Keyboard Shortcuts</Typography>
                <Typography variant="caption">Ctrl/Cmd+Enter: Start scan</Typography><br/>
                <Typography variant="caption">Esc: Cancel scan</Typography><br/>
                <Typography variant="caption">Alt+F: Toggle ML filter</Typography><br/>
                <Typography variant="caption">Alt+P: Cycle profile</Typography>
              </Box>
            }>
              <IconButton size="small" aria-label="Keyboard shortcuts">
                <HelpOutlineIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Button size="small" variant="text" component={Link} to="/reports">Reports</Button>
            <Button size="small" variant="text" component={Link} to="/runs">Results</Button>
          </Stack>
        </Stack>

        {/* Primary Section - APK Selection */}
        <Card variant="outlined" sx={{ borderRadius: 2 }}>
          <CardContent>
            <Stack spacing={2}>
              {/* APK Path Input */}
              <Stack direction="row" spacing={1} alignItems="flex-start">
                <FormControl fullWidth error={errors.length > 0 && !apkPath}>
                  <InputLabel htmlFor="aods-apk">APK Path</InputLabel>
                  <OutlinedInput
                    id="aods-apk" label="APK Path" aria-label="APK Path"
                    value={apkPath}
                    onChange={e => { setApkPath(e.target.value); setSessionId(null); setStatus(null); setProgress(null); setLogLines([]); setInspectResult(null); }}
                    onBlur={() => setApkTouched(true)}
                    placeholder="/path/to/app.apk"
                    startAdornment={<FolderOpenIcon sx={{ mr: 1, color: 'action.active' }} />}
                    aria-describedby={errors.length > 0 ? 'aods-scan-errors' : undefined}
                  />
                </FormControl>
                <Button component="label" variant="outlined" disabled={uploadBusy} aria-label="Browse and upload APK" sx={{ minWidth: 100, height: 56 }}>
                  {uploadBusy ? 'Uploading...' : 'Browse'}
                  <input type="file" accept=".apk" hidden onChange={async (e) => {
                    try {
                      const file = e.target.files && e.target.files[0];
                      if (!file) return;
                      setUploadBusy(true);
                      const fd = new FormData(); fd.append('file', file);
                      let resp = await secureFetch('/scans/upload_apk', { method: 'POST', body: fd });
                      if (resp.status === 404) {
                        const r2 = await secureFetch('/apk/inspect', { method: 'POST', body: fd });
                        if (r2.ok) setError('Server does not support uploads yet. Copy APK to server and paste absolute path.');
                        else throw new Error(`upload not supported (404) and inspect failed (${r2.status})`);
                      } else if (!resp.ok) { throw new Error(`upload failed: ${resp.status}`); }
                      else {
                        const data = await resp.json();
                        if (data?.path) { setApkPath(String(data.path)); showToast('APK uploaded'); }
                      }
                    } catch (err: any) { setError(err?.message || 'Upload failed'); }
                    finally { setUploadBusy(false); try { (e.target as HTMLInputElement).value = ''; } catch {} }
                  }} />
                </Button>
              </Stack>

              {/* Recent APKs */}
              <RecentApksBar recentApks={recents} onSelect={handleSelectRecentApk} currentApk={apkPath} />

              <ScanPresetsBar
                scanProfile={scanProfile} scanMode={scanMode} staticOnly={staticOnly} fridaMode={fridaMode}
                resourceConstrained={resourceConstrained} ciMode={ciMode} failOnCritical={failOnCritical} failOnHigh={failOnHigh}
                onSelectPreset={handleSelectPreset}
              />

              {/* Analysis capabilities indicator */}
              {Object.keys(toolCaps).length > 0 && (
                <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Typography variant="caption" color="text.secondary" sx={{ mr: 0.5 }}>Analysis:</Typography>
                  <Chip size="small" label="Static" color="success" variant="outlined" sx={{ fontSize: 11 }} />
                  <Chip size="small" label="JADX" color={toolCaps.jadx ? 'success' : 'default'} variant="outlined" sx={{ fontSize: 11 }} />
                  <Chip size="small" label="Dynamic" color={toolCaps.dynamic ? 'success' : 'default'} variant="outlined" sx={{ fontSize: 11 }} />
                  {toolCaps.native ? (
                    <Tooltip title="Native binary decompilation via Ghidra is available but opt-in. Enable with AODS_NATIVE_DEEP=1. Adds 5-30 min per scan depending on .so count. Detects buffer overflows, weak crypto, command injection in native code.">
                      <Chip size="small" label="Native (opt-in)" color="info" variant="outlined" sx={{ fontSize: 11, cursor: 'help' }} />
                    </Tooltip>
                  ) : (
                    <Tooltip title="Native .so decompilation requires Ghidra. Production apps contain crypto, parsers, and security logic in native code that Java analysis cannot reach. Run: python scripts/check_ghidra.py">
                      <Chip size="small" label="Native" color="default" variant="outlined" sx={{ fontSize: 11, cursor: 'help' }} />
                    </Tooltip>
                  )}
                </Stack>
              )}

              <Divider />

              {/* Action Buttons */}
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Button onClick={() => { setApkTouched(true); handleStart(); }} disabled={!apkPath || errors.length > 0 || ['starting', 'running', 'queued', 'awaiting_confirmation'].includes(status || '')} variant="contained" color="primary" startIcon={<PlayArrowIcon />} aria-label="Start Scan" sx={{ px: 3 }}>Start Scan</Button>
                {sessionId && (
                  <Button onClick={handleCancel} variant="outlined" color="error" size="small" startIcon={<StopIcon />} aria-label="Cancel Scan">Cancel</Button>
                )}
                <Box sx={{ flex: 1 }} />
                <Button onClick={async () => {
                  setError(null); setApkTouched(true);
                  try {
                    if (!apkPath) { setError('Enter an APK path'); return; }
                    const res = await api.validateApkPathWithInspect(apkPath);
                    if (res.ok) { showToast('APK path looks valid'); }
                    else setError(res.detail || 'APK path invalid');
                  } catch (e: any) { setError(e?.message || 'validation failed'); }
                }} variant="outlined" size="small" disabled={!apkPath} aria-label="Validate APK path">Validate</Button>
                <Button onClick={async () => {
                  try {
                    const chk = await api.checkConnectivity();
                    if (chk.health && chk.auth) { showToast('API health OK; auth OK'); }
                    else setError(chk.message || 'Connectivity failed');
                  } catch (e: any) { setError(e?.message || 'connectivity failed'); }
                }} variant="outlined" size="small" aria-label="Check connectivity">Check API</Button>
                <Button
                  onClick={async () => {
                    if (!apkPath) return;
                    setInspectBusy(true); setError(null); setInspectResult(null);
                    try {
                      const result = await api.inspectApkPath(apkPath);
                      setInspectResult(result);
                    } catch (e: any) { setError(e?.message || 'Inspect failed'); }
                    finally { setInspectBusy(false); }
                  }}
                  variant="outlined"
                  size="small"
                  disabled={!apkPath || inspectBusy}
                  startIcon={inspectBusy ? <CircularProgress size={16} /> : <InfoOutlinedIcon />}
                  aria-label="Inspect APK"
                  data-testid="inspect-apk-btn"
                >
                  Inspect
                </Button>
              </Stack>

              {/* APK Inspect Result */}
              {inspectResult && (
                <Card variant="outlined" sx={{ bgcolor: 'action.hover', borderRadius: 2 }} data-testid="inspect-result">
                  <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                      {inspectResult.packageName && (
                        <Chip label={`Package: ${inspectResult.packageName}`} size="small" color="primary" />
                      )}
                      <Chip label={inspectResult.file_name} size="small" variant="outlined" />
                      <Chip label={`${(inspectResult.file_size / 1024 / 1024).toFixed(1)} MB`} size="small" variant="outlined" />
                      {inspectResult.warning && (
                        <Chip label={inspectResult.warning} size="small" color="warning" />
                      )}
                    </Stack>
                  </CardContent>
                </Card>
              )}

              {/* Validation Errors */}
              {errors.length > 0 && (
                <Alert severity="error" role="alert" aria-live="assertive" id="aods-scan-errors">{errors.join(' | ')}</Alert>
              )}

              {/* API / Runtime Error - shown inline so it's immediately visible */}
              {error && <Alert severity="error" role="alert" aria-live="assertive">{error}</Alert>}

              {/* Inline Progress */}
              {(status || progress) && (
                <Box sx={{ mt: 1 }} role="status" aria-live="polite">
                  {status && <Typography variant="body2" sx={{ mb: 1 }}>Status: <strong>{status}</strong></Typography>}
                  {sessionId && (
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                      <Typography variant="caption" color="text.secondary">Session: {sessionId}</Typography>
                      <Tooltip title="Copy Session ID">
                        <IconButton size="small" aria-label="Copy Session ID" onClick={async () => { try { await navigator.clipboard.writeText(sessionId); showToast('Session copied'); } catch {} }}>
                          <ContentCopyIcon fontSize="inherit" />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  )}
                  {progress && (
                    <Stack spacing={0.5}>
                      <LinearProgress variant="determinate" value={Number((progress.split('%')[0] || '0'))} aria-label="Scan Progress" />
                      <Typography variant="caption" aria-live="polite">{progress}</Typography>
                    </Stack>
                  )}
                </Box>
              )}
            </Stack>
          </CardContent>
        </Card>

        <ScanOptionsForm
          scanProfile={scanProfile} setScanProfile={v => updateOption('scanProfile', v)}
          scanMode={scanMode} setScanMode={v => updateOption('scanMode', v)}
          outputFormats={outputFormats} setOutputFormats={v => updateOption('outputFormats', v)}
          staticOnly={staticOnly} setStaticOnly={v => updateOption('staticOnly', v)}
          ciMode={ciMode} setCiMode={v => updateOption('ciMode', v)}
          enableFilter={enableFilter} setEnableFilter={v => updateOption('enableFilter', v)}
          profile={profile} setProfile={v => updateOption('profile', v)}
          fridaMode={fridaMode} setFridaMode={v => updateOption('fridaMode', v)}
          resourceConstrained={resourceConstrained} setResourceConstrained={v => updateOption('resourceConstrained', v)}
          maxWorkers={maxWorkers} setMaxWorkers={v => updateOption('maxWorkers', v)}
          timeoutsProfile={timeoutsProfile} setTimeoutsProfile={v => updateOption('timeoutsProfile', v)}
          pluginsIncludeCSV={pluginsIncludeCSV} setPluginsIncludeCSV={v => updateOption('pluginsIncludeCSV', v)}
          pluginsExcludeCSV={pluginsExcludeCSV} setPluginsExcludeCSV={v => updateOption('pluginsExcludeCSV', v)}
          failOnCritical={failOnCritical} setFailOnCritical={v => updateOption('failOnCritical', v)}
          failOnHigh={failOnHigh} setFailOnHigh={v => updateOption('failOnHigh', v)}
          frameworks={frameworks} setFrameworks={v => updateOption('frameworks', v)}
          compliance={compliance} setCompliance={v => updateOption('compliance', v)}
          mlConfidence={mlConfidence} setMlConfidence={v => updateOption('mlConfidence', v)}
          mlModelsPath={mlModelsPath} setMlModelsPath={v => updateOption('mlModelsPath', v)}
          dedupStrategy={dedupStrategy} setDedupStrategy={v => updateOption('dedupStrategy', v)}
          dedupThreshold={dedupThreshold} setDedupThreshold={v => updateOption('dedupThreshold', v)}
          progressiveAnalysis={progressiveAnalysis} setProgressiveAnalysis={v => updateOption('progressiveAnalysis', v)}
          sampleRate={sampleRate} setSampleRate={v => updateOption('sampleRate', v)}
          agentEnabled={agentEnabled} setAgentEnabled={v => updateOption('agentEnabled', v)}
          agentSteps={agentSteps} setAgentSteps={v => updateOption('agentSteps', v)}
          isAdmin={auth.roles.includes('admin')}
          policy={policy} policyBusy={policyBusy}
          onRefreshPolicy={refreshPolicy}
          onCopyPolicy={async () => { try { await navigator.clipboard.writeText(JSON.stringify(policy, null, 2)); showToast('Policy copied'); } catch {} }}
        />

        <ScanProgressPanel
          status={status} sessionId={sessionId}
          effOpts={effOpts} latestReport={latestReport}
          logLines={logLines} showLogs={showLogs} setShowLogs={setShowLogs}
          cliPreview={cliPreview}
          stageHistory={stageHistory}
          progressPct={progress ? (Number(progress.split('%')[0]) || 0) : 0}
          onCopyCliPreview={async () => { try { const text = (document.getElementById('aods-scan-cli-preview')?.textContent || '').trim(); if (text) { await navigator.clipboard.writeText(text); showToast('CLI copied'); } } catch {} }}
        />

      </Stack>

      <AppToast toast={toast} onClose={closeToast} />
      <PackageConfirmDialog
        open={showPackageConfirm} detection={pendingDetection}
        onConfirm={handleConfirmPackage} onCancel={handleCancelConfirm} onRetry={handleRetryDetection}
        loading={confirmLoading} sessionId={pendingSessionId || undefined}
      />
    </Box>
  );
}
