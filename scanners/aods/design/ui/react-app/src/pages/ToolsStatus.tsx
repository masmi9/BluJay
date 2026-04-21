import { useEffect, useRef, useState } from 'react';
import { Box, Button, Chip, Paper, Stack, Typography, Switch, FormControl, InputLabel, Select, MenuItem, TextField } from '@mui/material';
import { secureFetch } from '../lib/api';
import { formatTime } from '../lib/format';
import { PageHeader, ErrorDisplay, LoadingSkeleton } from '../components';

type ToolInfo = {
  tool_type: string;
  available: boolean;
  executable_path?: string;
  version?: string;
  default_timeout?: number;
  max_retries?: number;
  last_checked?: string;
  install_hint?: string;
  // Ghidra-specific fields
  ghidra_path?: string;
  analyze_headless?: string;
  java_version?: string;
  ghidra_version?: string;
  search_paths_checked?: string[];
};

type OptionalDepInfo = {
  available: boolean;
  feature_description?: string;
  performance_impact?: string;
  load_time?: number;
  error_message?: string | null;
  install_command?: string | null;
  version?: string | null;
  min_version?: string | null;
  supported?: boolean;
};

export function ToolsStatus() {
  const [data, setData] = useState<Record<string, ToolInfo> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedIso, setLastUpdatedIso] = useState<string>('');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false);
  const timerRef = useRef<number | null>(null);
  const [optDeps, setOptDeps] = useState<Record<string, OptionalDepInfo> | null>(null);
  const [decompPolicy, setDecompPolicy] = useState<any | null>(null);
  const [decompPreset, setDecompPreset] = useState<'optimized'|'balanced'|'full'|'custom'>('optimized');
  const [decompThreads, setDecompThreads] = useState<number | ''>('');
  const [decompMemoryMb, setDecompMemoryMb] = useState<number | ''>('');
  const [decompFlagsText, setDecompFlagsText] = useState<string>('');
  const [saveBusy, setSaveBusy] = useState<boolean>(false);
  const [saveMsg, setSaveMsg] = useState<string>('');
  const [busy, setBusy] = useState<boolean>(false);
  const [ciToggles, setCiToggles] = useState<{ failOnCritical: boolean; failOnHigh: boolean; dedupStrict: boolean; last_updated?: string } | null>(null);
  const [healthMl, setHealthMl] = useState<any>(null);
  const [healthPlugins, setHealthPlugins] = useState<any>(null);
  const [healthScan, setHealthScan] = useState<any>(null);

  async function loadTools() {
    try {
      const r = await secureFetch(`/tools/status`);
      if (!r.ok) throw new Error(String(r.status));
      setData(await r.json());
      try {
        const o = await secureFetch(`/optional-deps/status`);
        if (o.ok) setOptDeps(await o.json()); else setOptDeps(null);
      } catch { setOptDeps(null); }
      try {
        const t = await secureFetch(`/ci/toggles`);
        if (t.ok) setCiToggles(await t.json()); else setCiToggles(null);
      } catch { setCiToggles(null); }
      try {
        const [hml, hpl, hsc] = await Promise.all([
          secureFetch(`/health/ml`).then(r => r.ok ? r.json() : null).catch(() => null),
          secureFetch(`/health/plugins`).then(r => r.ok ? r.json() : null).catch(() => null),
          secureFetch(`/health/scan`).then(r => r.ok ? r.json() : null).catch(() => null),
        ]);
        setHealthMl(hml);
        setHealthPlugins(hpl);
        setHealthScan(hsc);
      } catch {}
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load tool status');
    } finally {
      try { setLastUpdatedIso(new Date().toISOString()); } catch {}
    }
  }

  useEffect(() => {
    try {
      const s = localStorage.getItem('toolsAutoRefresh');
      if (s) setAutoRefresh(s === '1');
      const lu = localStorage.getItem('toolsLastUpdated');
      if (lu) setLastUpdatedIso(lu);
    } catch {}
    loadTools();
  }, []);

  useEffect(() => {
    if (timerRef.current) { window.clearInterval(timerRef.current); timerRef.current = null; }
    if (autoRefresh) {
      timerRef.current = window.setInterval(() => { loadTools(); }, 30_000);
    }
    return () => { if (timerRef.current) { window.clearInterval(timerRef.current); timerRef.current = null; } };
  }, [autoRefresh]);

  useEffect(() => {
    try { localStorage.setItem('toolsAutoRefresh', autoRefresh ? '1' : '0'); } catch {}
  }, [autoRefresh]);

  useEffect(() => {
    if (lastUpdatedIso) {
      try { localStorage.setItem('toolsLastUpdated', lastUpdatedIso); } catch {}
    }
  }, [lastUpdatedIso]);

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader
          title="Tools & Dependencies"
          subtitle="External tool availability, CI gate toggles, and optional dependencies"
          actions={
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip
                size="small"
                color={autoRefresh ? 'success' : 'default'}
                variant={autoRefresh ? 'filled' : 'outlined'}
                label={autoRefresh ? 'Auto-refresh: ON' : 'Auto-refresh: OFF'}
                aria-label={`Auto refresh ${autoRefresh ? 'on' : 'off'}`}
                onClick={() => setAutoRefresh(v => !v)}
                sx={{ cursor: 'pointer' }}
              />
              <Button size="small" variant="outlined" onClick={() => loadTools()}>Refresh</Button>
              <Typography variant="caption" color="text.secondary" aria-label="Last updated">
{lastUpdatedIso ? `Last updated ${formatTime(lastUpdatedIso)}` : ''}
              </Typography>
            </Stack>
          }
        />
        <ErrorDisplay error={error} onRetry={loadTools} />
        {!data ? (
          <LoadingSkeleton variant="table" />
        ) : (
          <Stack spacing={2}>
            <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1.5 }}>Required Tools</Typography>
              <Stack spacing={1.5}>
                {Object.entries(data).map(([k, v]) => (
                  <Box key={k} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1, px: 2, border: 1, borderColor: 'divider', borderRadius: 1.5 }}>
                  <Chip
                    size="small"
                    label={v.available ? 'Ready' : 'Missing'}
                    color={v.available ? 'success' : 'error'}
                    sx={{ minWidth: 64, fontWeight: 600 }}
                  />
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Stack direction="row" spacing={1} alignItems="baseline">
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{k.toUpperCase()}</Typography>
                      {v.version && <Typography variant="caption" color="text.secondary">v{v.version}</Typography>}
                      {k === 'ghidra' && v.ghidra_version && <Typography variant="caption" color="text.secondary">v{v.ghidra_version}</Typography>}
                    </Stack>
                    <Stack direction="row" spacing={2} sx={{ mt: 0.25 }} flexWrap="wrap" useFlexGap>
                      {v.executable_path && <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 11 }}>{v.executable_path}</Typography>}
                      {typeof v.default_timeout === 'number' && <Typography variant="caption" color="text.secondary">timeout: {Math.round(v.default_timeout)}s</Typography>}
                      {typeof v.max_retries === 'number' && <Typography variant="caption" color="text.secondary">retries: {v.max_retries}</Typography>}
                    </Stack>
                    {/* Ghidra-specific details */}
                    {k === 'ghidra' && (
                      <Stack spacing={0.25} sx={{ mt: 0.5 }}>
                        {v.java_version && (
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                            Java: {v.java_version}
                          </Typography>
                        )}
                        {v.ghidra_path && (
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                            Path: {v.ghidra_path}
                          </Typography>
                        )}
                        {v.ghidra_version && (
                          <Typography variant="caption" color="text.secondary">
                            Ghidra {v.ghidra_version}
                          </Typography>
                        )}
                        {v.available && (
                          <Stack spacing={0.25}>
                            <Typography variant="caption" color="success.main" sx={{ fontSize: 11 }}>
                              Ready for native binary decompilation (opt-in)
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: 10 }}>
                              Enable with AODS_NATIVE_DEEP=1. Analyzes up to 5 .so files per scan (configurable). Detects buffer overflows, format strings, weak crypto, command injection in native code. Adds 5-30 min per scan.
                            </Typography>
                          </Stack>
                        )}
                        {!v.available && (
                          <Stack spacing={0.25}>
                            <Typography variant="caption" color="warning.main" sx={{ fontSize: 11 }}>
                              Native binary analysis not available
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: 10 }}>
                              Production apps contain .so libraries with crypto, parsers, and security logic invisible to Java/Kotlin analysis. Install Ghidra to decompile and scan native code for vulnerabilities.
                            </Typography>
                          </Stack>
                        )}
                        {!v.available && v.search_paths_checked && v.search_paths_checked.length > 0 && (
                          <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>
                            Searched: {v.search_paths_checked.join(', ')}
                          </Typography>
                        )}
                      </Stack>
                    )}
                    {v.install_hint && !v.available && (
                      <Typography variant="caption" color="warning.main" sx={{ mt: 0.5, display: 'block', whiteSpace: 'pre-line' }}>{v.install_hint}</Typography>
                    )}
                  </Box>
                  {v.last_checked && (
                    <Typography variant="caption" color="text.disabled" sx={{ whiteSpace: 'nowrap' }}>
                      {formatTime(v.last_checked)}
                    </Typography>
                  )}
                </Box>
                ))}
              </Stack>
            </Paper>
            <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>CI Gate Toggles</Typography>
                {ciToggles?.last_updated && (
                  <Typography variant="caption" color="text.disabled" aria-label="CI toggles last updated">
                    Updated {formatTime(ciToggles.last_updated)}
                  </Typography>
                )}
              </Stack>
              {!ciToggles ? (
                <Typography variant="caption" color="text.secondary">Loading toggles…</Typography>
              ) : (
                <Stack spacing={0}>
                  {([
                    { key: 'failOnCritical' as const, label: 'Fail on Critical', desc: 'Block pipeline when critical findings are detected' },
                    { key: 'failOnHigh' as const, label: 'Fail on High', desc: 'Block pipeline when high-severity findings are detected' },
                    { key: 'dedupStrict' as const, label: 'Strict Deduplication', desc: 'Enforce strict dedup rules before gate evaluation' },
                  ] as const).map(({ key, label, desc }) => (
                    <Stack key={key} direction="row" alignItems="center" spacing={1.5} sx={{ py: 1, '&:not(:last-child)': { borderBottom: 1, borderColor: 'divider' } }}>
                      <Switch
                        size="small"
                        inputProps={{ 'aria-label': label }}
                        checked={ciToggles[key]}
                        onChange={async (e) => {
                          const next = e.target.checked;
                          setCiToggles(prev => prev ? { ...prev, [key]: next } : prev);
                          try { await secureFetch(`/ci/toggles`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ [key]: next }) }); } catch {}
                        }}
                      />
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>{label}</Typography>
                        <Typography variant="caption" color="text.secondary">{desc}</Typography>
                      </Box>
                    </Stack>
                  ))}
                </Stack>
              )}
            </Paper>
            <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Decompilation Policy</Typography>
                {!decompPolicy && (
                  <Button size="small" variant="outlined" disabled={busy} onClick={async () => {
                    setBusy(true);
                    try {
                      const resp = await secureFetch(`/decomp/policy?apkPath=/tmp/fake.apk&profile=dev`);
                      if (resp.ok) {
                        const j = await resp.json();
                        setDecompPolicy(j);
                        try {
                          const mode = String(j.mode || '').toLowerCase();
                          const thr = typeof j.maxThreads === 'number' ? j.maxThreads : '';
                          const mem = typeof j.memoryLimitMb === 'number' ? j.memoryLimitMb : '';
                          const flags = Array.isArray(j.flags) ? j.flags : [];
                          let preset: 'optimized'|'balanced'|'full'|'custom' = 'custom';
                          const fset = new Set(flags);
                          if (mode === 'optimized' && thr === 4 && mem === 2048 && fset.has('--no-debug-info') && fset.size === 1) preset = 'optimized';
                          else if (mode === 'optimized' && thr === 8 && mem === 4096 && fset.has('--no-debug-info') && fset.has('--deobf') && fset.size === 2) preset = 'balanced';
                          else if (mode === 'full' && thr === 8 && mem === 8192 && fset.has('--no-debug-info') && fset.has('--deobf') && fset.has('--no-replace-consts') && fset.size === 3) preset = 'full';
                          setDecompPreset(preset);
                          setDecompThreads(thr);
                          setDecompMemoryMb(mem);
                          setDecompFlagsText(flags.join(', '));
                        } catch {}
                      } else {
                        setDecompPolicy(null);
                      }
                    } catch {
                      setDecompPolicy(null);
                    } finally {
                      setBusy(false);
                    }
                  }}>{busy ? 'Loading…' : 'Load Policy'}</Button>
                )}
              </Stack>
              {!decompPolicy ? (
                <Typography variant="caption" color="text.secondary">Load the current decompilation policy to view and adjust settings.</Typography>
              ) : (
                <>
                  <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap' }} useFlexGap>
                    {typeof decompPolicy.mode !== 'undefined' && <Chip size="small" label={`Mode: ${decompPolicy.mode}`} variant="outlined" />}
                    {typeof decompPolicy.maxThreads !== 'undefined' && <Chip size="small" label={`Threads: ${decompPolicy.maxThreads}`} variant="outlined" />}
                    {typeof decompPolicy.memoryLimitMb !== 'undefined' && <Chip size="small" label={`Memory: ${decompPolicy.memoryLimitMb} MB`} variant="outlined" />}
                    {decompPolicy.flags && Array.isArray(decompPolicy.flags) && <Chip size="small" label={`Flags: ${decompPolicy.flags.length}`} variant="outlined" />}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5, fontWeight: 500 }}>Adjust Settings</Typography>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ xs: 'stretch', sm: 'center' }} sx={{ flexWrap: 'wrap' }} useFlexGap>
                    <FormControl size="small" sx={{ minWidth: 140 }}>
                      <InputLabel id="decomp-preset-label">Preset</InputLabel>
                      <Select labelId="decomp-preset-label" label="Preset" value={decompPreset} onChange={(e) => setDecompPreset(e.target.value as any)}>
                        <MenuItem value="optimized">Optimized</MenuItem>
                        <MenuItem value="balanced">Balanced</MenuItem>
                        <MenuItem value="full">Full</MenuItem>
                        <MenuItem value="custom">Custom</MenuItem>
                      </Select>
                    </FormControl>
                    <TextField size="small" type="number" label="Threads" aria-label="Decomp threads" value={decompThreads} onChange={(e) => setDecompThreads(e.target.value === '' ? '' : Number(e.target.value))} sx={{ width: 100 }} />
                    <TextField size="small" type="number" label="Memory MB" aria-label="Decomp memory MB" value={decompMemoryMb} onChange={(e) => setDecompMemoryMb(e.target.value === '' ? '' : Number(e.target.value))} sx={{ width: 120 }} />
                    <TextField size="small" label="Flags" aria-label="Decomp flags" value={decompFlagsText} onChange={(e) => setDecompFlagsText(e.target.value)} sx={{ minWidth: 200 }} placeholder="--no-debug-info, --deobf" />
                    <Button size="small" variant="contained" disabled={saveBusy} onClick={async () => {
                      setSaveMsg(''); setSaveBusy(true);
                      try {
                        const payload: any = {};
                        if (decompPreset && decompPreset !== 'custom') payload.preset = decompPreset;
                        if (decompThreads !== '') payload.max_threads = decompThreads;
                        if (decompMemoryMb !== '') payload.memory_mb = decompMemoryMb;
                        if (decompFlagsText.trim()) payload.flags = decompFlagsText.split(',').map(s => s.trim()).filter(Boolean);
                        const r = await secureFetch(`/decomp/policy`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                        if (!r.ok) throw new Error(String(r.status));
                        await r.json();
                        setSaveMsg('Saved');
                        try {
                          const g = await secureFetch(`/decomp/policy?apkPath=/tmp/fake.apk&profile=dev`);
                          if (g.ok) setDecompPolicy(await g.json());
                        } catch {}
                      } catch (e: any) {
                        setSaveMsg(`Save failed: ${e?.message || 'error'}`);
                      } finally {
                        setSaveBusy(false);
                        setTimeout(() => setSaveMsg(''), 2000);
                      }
                    }}>Save</Button>
                    {saveMsg && <Typography variant="caption" color={saveMsg === 'Saved' ? 'success.main' : 'error.main'}>{saveMsg}</Typography>}
                  </Stack>
                </>
              )}
            </Paper>
            {/* Infrastructure Health Cards */}
            {(healthMl || healthPlugins || healthScan) && (
              <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1.5 }}>Infrastructure Health</Typography>
                <Stack spacing={1.5}>
                  {healthMl && (
                    <Box sx={{ py: 1, px: 2, border: 1, borderColor: 'divider', borderRadius: 1.5 }}>
                      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                        <Chip size="small" label={healthMl.status === 'ok' ? 'Healthy' : 'Degraded'} color={healthMl.status === 'ok' ? 'success' : 'warning'} sx={{ minWidth: 64, fontWeight: 600 }} />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>ML Subsystem</Typography>
                      </Stack>
                      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                        {healthMl.malware_detection && (
                          <Typography variant="caption" color="text.secondary">Malware models: {healthMl.malware_detection.models_found ?? 0} ({healthMl.malware_detection.status})</Typography>
                        )}
                        {healthMl.calibration && (
                          <Typography variant="caption" color="text.secondary">Calibration: {healthMl.calibration.models_found ?? 0} ({healthMl.calibration.status})</Typography>
                        )}
                        {healthMl.fp_reducer && (
                          <Typography variant="caption" color="text.secondary">FP Reducer: {healthMl.fp_reducer.models_found ?? 0} ({healthMl.fp_reducer.status})</Typography>
                        )}
                      </Stack>
                    </Box>
                  )}
                  {healthPlugins && (
                    <Box sx={{ py: 1, px: 2, border: 1, borderColor: 'divider', borderRadius: 1.5 }}>
                      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                        <Chip size="small" label={healthPlugins.status === 'ok' ? 'Healthy' : 'Degraded'} color={healthPlugins.status === 'ok' ? 'success' : 'warning'} sx={{ minWidth: 64, fontWeight: 600 }} />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>Plugin System</Typography>
                      </Stack>
                      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                        {healthPlugins.discovery && (
                          <Typography variant="caption" color="text.secondary">Discovered: {healthPlugins.discovery.plugins_discovered ?? 0} ({healthPlugins.discovery.status})</Typography>
                        )}
                        {healthPlugins.v2_plugins && (
                          <Typography variant="caption" color="text.secondary">V2 plugins: {healthPlugins.v2_plugins.v2_plugin_count ?? 0} ({healthPlugins.v2_plugins.status})</Typography>
                        )}
                      </Stack>
                    </Box>
                  )}
                  {healthScan && (
                    <Box sx={{ py: 1, px: 2, border: 1, borderColor: 'divider', borderRadius: 1.5 }}>
                      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                        <Chip size="small" label={healthScan.status === 'ok' ? 'Healthy' : 'Degraded'} color={healthScan.status === 'ok' ? 'success' : 'warning'} sx={{ minWidth: 64, fontWeight: 600 }} />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>Scan Infrastructure</Typography>
                      </Stack>
                      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                        {healthScan.jadx && (
                          <Typography variant="caption" color="text.secondary">JADX: {healthScan.jadx.status}{healthScan.jadx.path ? ` (${healthScan.jadx.path})` : ''}</Typography>
                        )}
                        {healthScan.sessions && (
                          <Typography variant="caption" color="text.secondary">Sessions: {healthScan.sessions.active_scans ?? 0} active / {healthScan.sessions.total_sessions ?? 0} total</Typography>
                        )}
                        {healthScan.reports && (
                          <Typography variant="caption" color="text.secondary">Reports: {healthScan.reports.report_count ?? 0} ({healthScan.reports.writable ? 'writable' : 'read-only'})</Typography>
                        )}
                      </Stack>
                    </Box>
                  )}
                </Stack>
              </Paper>
            )}
            {optDeps && (
              <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1.5 }}>Optional Dependencies</Typography>
                <Stack spacing={1}>
                  {Object.entries(optDeps).map(([name, info]) => (
                    <Box key={`opt-${name}`} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1, px: 2, border: 1, borderColor: 'divider', borderRadius: 1.5 }}>
                      <Chip
                        size="small"
                        label={info.available ? 'Ready' : 'Missing'}
                        color={info.available ? 'success' : 'warning'}
                        sx={{ minWidth: 64, fontWeight: 600 }}
                      />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Stack direction="row" spacing={1} alignItems="baseline">
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{name}</Typography>
                          {info.version && <Typography variant="caption" color="text.secondary">v{info.version}</Typography>}
                          {info.min_version && <Typography variant="caption" color="text.disabled">(min {info.min_version})</Typography>}
                        </Stack>
                        <Stack direction="row" spacing={2} sx={{ mt: 0.25 }} flexWrap="wrap" useFlexGap>
                          {info.feature_description && <Typography variant="caption" color="text.secondary">{info.feature_description}</Typography>}
                          {info.performance_impact && <Typography variant="caption" color="text.secondary">Impact: {info.performance_impact}</Typography>}
                          {typeof info.load_time === 'number' && <Typography variant="caption" color="text.secondary">{info.load_time.toFixed(3)}s load</Typography>}
                          {typeof info.supported === 'boolean' && !info.supported && <Typography variant="caption" color="warning.main">Unsupported version</Typography>}
                        </Stack>
                        {!info.available && info.install_command && (
                          <Typography variant="caption" color="warning.main" sx={{ mt: 0.5, display: 'block', fontFamily: 'monospace', fontSize: 11 }}>{info.install_command}</Typography>
                        )}
                        {!info.available && info.error_message && (
                          <Typography variant="caption" color="error.main" sx={{ mt: 0.25, display: 'block' }}>{info.error_message}</Typography>
                        )}
                      </Box>
                      {(info as any).last_checked && (
                        <Typography variant="caption" color="text.disabled" sx={{ whiteSpace: 'nowrap' }}>
                          {formatTime((info as any).last_checked as string)}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Stack>
              </Paper>
            )}
          </Stack>
        )}
      </Stack>
    </Box>
  );
}


