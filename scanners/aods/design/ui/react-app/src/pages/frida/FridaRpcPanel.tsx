import React from 'react';
import {
  Box, Button, Chip, Collapse, MenuItem, Paper,
  Stack, Tab, Tabs, TextField, Typography,
} from '@mui/material';

interface RecentRpc {
  fn: string;
  args: string;
  ts: string;
  ms?: number;
  status?: string;
  pinned?: boolean;
}

interface FridaRpcPanelProps {
  rpcFn: string;
  setRpcFn: (v: string) => void;
  rpcArgs: string;
  setRpcArgs: (v: string) => void;
  rpcResult: string;
  rpcArgsError: string;
  rpcDurationMs: number | null;
  rpcError: string | null;
  rpcExpandedDetails: boolean;
  setRpcExpandedDetails: React.Dispatch<React.SetStateAction<boolean>>;
  rpcPresetName: string;
  setRpcPresetName: (v: string) => void;
  rpcPresets: Array<{ name: string; fn: string; args: string; tags?: string[] }>;
  rpcPresetSearch: string;
  setRpcPresetSearch: (v: string) => void;
  rpcPresetTag: string;
  setRpcPresetTag: (v: string) => void;
  rpcTab: number;
  setRpcTab: (v: number) => void;
  rpcExpanded: boolean;
  setRpcExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  recentRpcs: RecentRpc[];
  setRecentRpcs: React.Dispatch<React.SetStateAction<RecentRpc[]>>;
  lastRpcIso: string;
  status: any;
  btnSx: Record<string, any>;
  fieldDenseSx: Record<string, any>;
  chipSx: Record<string, any>;
  setConnectMsg: (v: string) => void;
  onRunRpc: (sessionId: string) => void;
  onSaveRpcPreset: () => void;
  onLoadRpcPreset: (nm: string) => void;
  normalizeRecent: (list: RecentRpc[]) => RecentRpc[];
  formatTime: (iso: string) => string;
  computeShouldCollapse: (text: string) => boolean;
  showCopyToast: (msg: string) => void;
}

export function FridaRpcPanel({
  rpcFn, setRpcFn, rpcArgs, setRpcArgs, rpcResult, rpcArgsError,
  rpcDurationMs, rpcError, rpcExpandedDetails, setRpcExpandedDetails,
  rpcPresetName, setRpcPresetName, rpcPresets, rpcPresetSearch, setRpcPresetSearch,
  rpcPresetTag, setRpcPresetTag, rpcTab, setRpcTab, rpcExpanded, setRpcExpanded,
  recentRpcs, setRecentRpcs, lastRpcIso, status, btnSx, fieldDenseSx, chipSx,
  setConnectMsg, onRunRpc, onSaveRpcPreset, onLoadRpcPreset,
  normalizeRecent, formatTime, computeShouldCollapse, showCopyToast,
}: FridaRpcPanelProps) {
  return (
    <>
      <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1 }}>RPC Controls</Typography>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1 }}>
            <TextField label="RPC function" value={rpcFn} onChange={e => setRpcFn(e.target.value)} size="small" inputProps={{ 'aria-label': 'RPC function' }} sx={fieldDenseSx} />
            <TextField label="RPC args (JSON)" value={rpcArgs} onChange={e => setRpcArgs(e.target.value)} size="small" sx={{ flex: 1, minWidth: 260, ...fieldDenseSx }} inputProps={{ 'aria-label': 'RPC args (JSON)' }} error={Boolean(rpcArgsError)} helperText={rpcArgsError || ' '} />
            <Button variant="outlined" onClick={() => status?.sessionId && onRunRpc(status.sessionId)} aria-label="Run RPC" sx={btnSx}>Run RPC</Button>
            <TextField size="small" label="Search presets" value={rpcPresetSearch} onChange={(e) => setRpcPresetSearch(e.target.value)} sx={{ width: 180, ...fieldDenseSx }} />
            <TextField size="small" label="Tag" placeholder="tag filter" value={rpcPresetTag} onChange={(e) => setRpcPresetTag(e.target.value)} sx={{ width: 140, ...fieldDenseSx }} />
            <TextField label="RPC Presets" select value={rpcPresetName} onChange={(e) => { setRpcPresetName(e.target.value); onLoadRpcPreset(e.target.value); }} size="small" sx={{ minWidth: 200, ...fieldDenseSx }}>
              {(() => {
                const q = rpcPresetSearch.trim().toLowerCase();
                const tg = rpcPresetTag.trim().toLowerCase();
                const filtered = rpcPresets.filter(p => {
                  const inName = !q || p.name.toLowerCase().includes(q) || p.fn.toLowerCase().includes(q);
                  const inTag = !tg || (Array.isArray(p.tags) && p.tags.some(t => t.toLowerCase().includes(tg)));
                  return inName && inTag;
                });
                return filtered.length === 0 ? (<MenuItem value="">(none)</MenuItem>) : filtered.map(p => (
                  <MenuItem key={p.name} value={p.name}>{p.name}{Array.isArray(p.tags) && p.tags.length > 0 ? ` - [${p.tags.join(', ')}]` : ''}</MenuItem>
                ));
              })()}
            </TextField>
            <Button size="small" variant="outlined" onClick={onSaveRpcPreset} sx={btnSx}>Save RPC preset</Button>
          </Stack>
          {recentRpcs.length > 0 && (
            <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ mt: 1, flexWrap: 'wrap', rowGap: 1 }}>
              <Typography variant="caption" color="text.secondary">Recent RPCs:</Typography>
              <Button size="small" variant="text" onClick={() => setRecentRpcs([])}>Clear</Button>
              {recentRpcs.map((rc, i) => (
                <Stack key={`${rc.fn}|${rc.args}|${i}`} direction="row" spacing={0.5} alignItems="center">
                  <Chip size="small" label={`${rc.fn}(${(rc.args || '').length > 24 ? (rc.args.slice(0, 24) + '…') : rc.args})`} onClick={() => { setRpcFn(rc.fn); setRpcArgs(rc.args || '{}'); }} onDelete={() => { setRecentRpcs(prev => normalizeRecent(prev.filter((_, idx) => idx !== i))); }} sx={chipSx} />
                  {typeof rc.ms === 'number' && <Chip size="small" variant="outlined" label={`${rc.ms} ms`} />}
                  {rc.status && <Chip size="small" color={rc.status.toLowerCase() === 'ok' ? 'success' : 'error'} label={rc.status.toUpperCase()} />}
                  <Button size="small" variant="outlined" onClick={() => { setRpcFn(rc.fn); setRpcArgs(rc.args || '{}'); if (status?.sessionId) onRunRpc(status.sessionId); }}>Run</Button>
                  <Button size="small" variant={rc.pinned ? 'contained' : 'outlined'} color={rc.pinned ? 'success' : 'inherit'} onClick={() => {
                    setRecentRpcs(prev => {
                      const next = prev.map((x, idx) => idx === i ? { ...x, pinned: !x.pinned } : x);
                      return normalizeRecent(next);
                    });
                  }}>{rc.pinned ? 'Unpin' : 'Pin'}</Button>
                </Stack>
              ))}
            </Stack>
          )}
        </Paper>
      {(rpcResult || status) && (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>RPC Output</Typography>
            </Stack>
            <Tabs value={rpcTab} onChange={(_, v) => setRpcTab(v)} variant="scrollable" allowScrollButtonsMobile>
              <Tab label="Result" />
              <Tab label="Status" />
              <Tab label="Raw" />
            </Tabs>
            <Box sx={{ p: 1 }}>
              {rpcTab === 0 && (
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ mb: 1, flexWrap: 'wrap', rowGap: 1 }}>
                    {(() => {
                      try { const j = rpcResult ? JSON.parse(rpcResult) : null; const st = String(j?.status || ''); if (!st) return null; return <Chip size="small" color={st.toLowerCase() === 'ok' ? 'success' : 'error'} label={(st || '').toUpperCase()} />; } catch { return null; }
                    })()}
                    {rpcDurationMs !== null && <Chip size="small" variant="outlined" label={`${rpcDurationMs} ms`} />}
                    <Chip size="small" variant="outlined" label={`fn: ${rpcFn || '-'}`} />
                    <Chip size="small" variant="outlined" label={`args: ${(() => { try { const a = JSON.parse(rpcArgs || '{}'); const s = JSON.stringify(a); return s.length > 40 ? s.slice(0, 40) + '…' : s; } catch { return (rpcArgs || '{}').slice(0, 40); } })()}`} />
                    {lastRpcIso && <Chip size="small" variant="outlined" label={`at ${formatTime(lastRpcIso)}`} />}
                    <Button size="small" variant="outlined" onClick={async () => { try { await navigator.clipboard.writeText(rpcResult || ''); showCopyToast('Copied result'); } catch {} }}>Copy result (JSON)</Button>
                    <Button size="small" variant="outlined" onClick={async () => { try { const j = rpcResult ? JSON.parse(rpcResult) : null; const v = (j && (typeof j.result === 'string' || typeof j.result === 'number' || typeof j.result === 'boolean')) ? String(j.result) : ''; if (v) { await navigator.clipboard.writeText(v); showCopyToast('Copied value'); } } catch {} }}>Copy value</Button>
                    <Button size="small" variant="outlined" onClick={() => { if (status?.sessionId) onRunRpc(status.sessionId); }}>Run again</Button>
                    <Button size="small" variant="outlined" onClick={async () => { try { await navigator.clipboard.writeText(JSON.stringify({ function: rpcFn, args: (() => { try { return JSON.parse(rpcArgs || '{}'); } catch { return {}; } })() }, null, 2)); showCopyToast('Copied request'); } catch {} }}>Copy request</Button>
                    <Button size="small" variant="outlined" onClick={onSaveRpcPreset}>Save as preset</Button>
                  </Stack>
                  {(() => {
                    try { const j = rpcResult ? JSON.parse(rpcResult) : null; const v = j?.result; if (['string', 'number', 'boolean'].includes(typeof v)) { return <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 15, mb: 1 }}>{String(v)}</Typography>; } } catch {}
                    return null;
                  })()}
                  <Typography variant="body2" sx={{ mb: 1 }}>{rpcError ? `Error: ${rpcError}` : (lastRpcIso ? `Last call at ${formatTime(lastRpcIso)}` : '(no result yet)')}</Typography>
                  {(() => {
                    const shouldCollapse = computeShouldCollapse(rpcResult || '');
                    const content = (() => { try { const j = rpcResult ? JSON.parse(rpcResult) : null; return JSON.stringify(j, null, 2); } catch { return rpcResult || '(no result yet)'; } })();
                    return (
                      <>
                        <Box component="pre" sx={{ whiteSpace: 'pre-wrap', m: 0, maxHeight: shouldCollapse && !rpcExpandedDetails ? 120 : 400, overflow: 'auto' }}>{content}</Box>
                        {shouldCollapse && (
                          <Button size="small" variant="text" onClick={() => setRpcExpandedDetails(v => !v)}>{rpcExpandedDetails ? 'Collapse' : 'Expand details'}</Button>
                        )}
                      </>
                    );
                  })()}
                </Box>
              )}
              {rpcTab === 1 && (
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1 }}>
                    <Chip size="small" variant="outlined" label={`Session ${(status?.sessionId || '').slice(0, 4)}…${(status?.sessionId || '').slice(-4)}`} onClick={async () => { try { await navigator.clipboard.writeText(String(status?.sessionId || '')); } catch {} }} />
                    <Chip size="small" color={String(status?.attachStatus || '').toLowerCase() === 'attached' ? 'success' : 'default'} label={`Attach ${(status?.attachStatus || 'unknown')}`} />
                    <Chip size="small" color={status?.available ? 'success' : 'default'} label={`Availability ${status?.available ? 'Available' : 'Unavailable'}`} />
                    <Chip size="small" variant="outlined" label={`Last fn: ${rpcFn || '-'}`} />
                    {rpcDurationMs !== null && <Chip size="small" variant="outlined" label={`Duration ${rpcDurationMs} ms`} />}
                  </Stack>
                </Box>
              )}
              {rpcTab === 2 && (
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <Button size="small" variant="outlined" onClick={() => setRpcExpanded(v => !v)} aria-label="toggle-rpc-raw">
                      {rpcExpanded ? 'Collapse raw' : 'Expand raw'}
                    </Button>
                    <Button size="small" variant="outlined" onClick={async () => { try { await navigator.clipboard.writeText(JSON.stringify({ status, rpcRaw: rpcResult }, null, 2)); setConnectMsg('raw copied'); setTimeout(() => setConnectMsg(''), 1000); showCopyToast('Copied raw'); } catch {} }}>Copy raw</Button>
                  </Stack>
                  <Collapse in={rpcExpanded}>
                    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', m: 0, maxHeight: 420, overflow: 'auto' }}>{JSON.stringify({ status, rpcRaw: rpcResult }, null, 2)}</Box>
                  </Collapse>
                </Box>
              )}
            </Box>
          </Paper>
      )}
    </>
  );
}
