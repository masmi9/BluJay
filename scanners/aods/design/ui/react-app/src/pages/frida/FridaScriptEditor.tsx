import {
  Box, Button, Collapse, IconButton, Input,
  MenuItem, Stack, TextField, Typography,
} from '@mui/material';
import type React from 'react';
import ExpandLessIcon from '@mui/icons-material/ExpandLess.js';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore.js';
import { secureFetch } from '../../lib/api';
import { formatTime } from '../../lib/format';

interface FridaScriptEditorProps {
  status: any;
  baselineExpanded: boolean;
  setBaselineExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  pkg: string;
  setPkg: (v: string) => void;
  name: string;
  setName: (v: string) => void;
  presetName: string;
  setPresetName: (v: string) => void;
  presets: { name: string; content: string }[];
  js: string;
  setJs: (v: string) => void;
  lastUploadIso: string;
  fridaMode: string;
  uploading: boolean;
  loadUrl: string;
  setLoadUrl: (v: string) => void;
  loadUrlLoading: boolean;
  staticOnly: boolean;
  selectedDeviceId: string | null;
  devices: { id: string; name: string }[];
  setConnectMsg: (v: string) => void;
  btnSx: Record<string, any>;
  fieldDenseSx: Record<string, any>;
  setError: (v: string | null) => void;
  onUploadInline: () => void;
  onUnload: () => void;
  onRefreshStatus: () => Promise<void>;
  onRefreshHealth: () => Promise<void>;
  onSavePreset: () => void;
  onDeletePreset: (nm: string) => void;
  onLoadPreset: (nm: string) => void;
  onLoadJsFromUrl: (u: string) => Promise<string>;
  onAttachToPackage: () => void;
  onShowCopyToast: (msg: string) => void;
  setLoadUrlLoading: (v: boolean) => void;
  setUploading?: (v: boolean) => void;
}

export function FridaScriptEditor({
  status, baselineExpanded, setBaselineExpanded,
  pkg, setPkg, name, setName, presetName, setPresetName, presets,
  js, setJs, lastUploadIso, fridaMode, uploading,
  loadUrl, setLoadUrl, loadUrlLoading, staticOnly, selectedDeviceId, devices,
  setConnectMsg, btnSx, fieldDenseSx,
  setError, onUploadInline, onUnload, onRefreshStatus, onRefreshHealth,
  onSavePreset, onDeletePreset, onLoadPreset, onLoadJsFromUrl,
  onAttachToPackage, onShowCopyToast, setLoadUrlLoading,
}: FridaScriptEditorProps) {
  return (
    <>
      {status?.baseline && (
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Baseline Facts</Typography>
            <IconButton size="small" onClick={() => setBaselineExpanded(v => !v)} aria-label="toggle-baseline" aria-expanded={baselineExpanded} aria-controls="baseline-panel">
              {baselineExpanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
            </IconButton>
          </Stack>
          <Collapse in={baselineExpanded}>
            <Box component="pre" id="baseline-panel" sx={{ whiteSpace: 'pre-wrap', m: 0 }}>{JSON.stringify(status.baseline, null, 2)}</Box>
          </Collapse>
        </Box>
      )}
      <Stack direction="row" spacing={1} alignItems="center">
        <TextField label="Package" value={pkg} onChange={e => setPkg(e.target.value)} fullWidth />
        <Box component="label" htmlFor="apk-file" sx={{ display: 'inline-block' }}>
          <Input id="apk-file" type="file" inputProps={{ accept: '.apk' }} sx={{ display: 'none' }} onChange={async (e: any) => {
            try {
              const file = e?.target?.files?.[0];
              if (!file) return;
              const form = new FormData();
              form.append('file', file, file.name || 'app.apk');
              const r = await secureFetch(`/apk/inspect`, { method: 'POST', body: form });
              if (r.ok) {
                const j = await r.json();
                if (j?.packageName) setPkg(String(j.packageName));
              } else {
                let msg = '';
                try { msg = await r.text(); } catch { msg = String(r.status); }
                setError(`APK inspect failed: ${msg}`);
              }
            } catch (err: any) {
              setError(String(err?.message || 'APK inspect error'));
            } finally {
              try { if (e?.target) e.target.value = ''; } catch {}
            }
          }} />
          <Button variant="outlined" size="small" component="span">Select APK</Button>
        </Box>
        <Button size="small" variant="outlined" onClick={onAttachToPackage} disabled={staticOnly || (!selectedDeviceId && !devices[0])}>Attach to package</Button>
      </Stack>
      <Stack direction="row" spacing={1} alignItems="center">
        <TextField label="Script name" value={name} onChange={e => setName(e.target.value)} fullWidth />
        <TextField label="Presets" select value={presetName} onChange={(e) => { setPresetName(e.target.value); onLoadPreset(e.target.value); }} size="small" sx={{ minWidth: 180 }}>
          {presets.length === 0 ? (<MenuItem value="">(none)</MenuItem>) : presets.map(p => (
            <MenuItem key={p.name} value={p.name}>{p.name}</MenuItem>
          ))}
        </TextField>
        <Button size="small" variant="outlined" onClick={onSavePreset}>Save preset</Button>
        <Button size="small" variant="text" color="error" onClick={() => { if (presetName) onDeletePreset(presetName); }} disabled={!presetName}>Delete</Button>
      </Stack>
      <TextField label="Inline JS" value={js} onChange={e => setJs(e.target.value)} fullWidth multiline minRows={6} />
      {lastUploadIso && (
        <Typography variant="caption" color="text.secondary">Last uploaded {formatTime(lastUploadIso)}</Typography>
      )}
      <Stack direction="row" spacing={1}>
        <Button variant="contained" onClick={onUploadInline} disabled={fridaMode === 'read_only' || uploading} sx={btnSx}>{uploading ? 'Uploading…' : 'Upload Inline Script'}</Button>
        <Button variant="outlined" color="error" onClick={onUnload} sx={btnSx}>Unload</Button>
        <Button variant="outlined" onClick={async () => { await onRefreshStatus(); await onRefreshHealth(); }} sx={btnSx}>Refresh Status</Button>
        <Button size="small" variant="outlined" sx={btnSx} onClick={async () => {
          try {
            await navigator.clipboard.writeText(js);
            setConnectMsg('script copied');
            setTimeout(() => setConnectMsg(''), 1500);
            onShowCopyToast('Copied script');
          } catch {}
        }}>Copy</Button>
        <Box component="label" htmlFor="js-file" sx={{ display: 'inline-block' }}>
          <Input id="js-file" type="file" inputProps={{ accept: '.js,text/javascript' }} sx={{ display: 'none' }} onChange={async (e: any) => {
            try {
              const file = e?.target?.files?.[0];
              if (!file) return;
              const text = await file.text();
              setJs(text);
              setConnectMsg('file loaded'); setTimeout(() => setConnectMsg(''), 1200);
            } catch (err: any) {
              setError(String(err?.message || 'JS file load error'));
            } finally { try { if (e?.target) e.target.value = ''; } catch {} }
          }} />
          <Button size="small" variant="outlined" component="span" sx={btnSx}>Load JS File</Button>
        </Box>
        <TextField size="small" label="Load URL" placeholder="https://.../script.js" value={loadUrl} onChange={e => setLoadUrl(e.target.value)} sx={{ minWidth: 220, ...fieldDenseSx }} />
        <Button size="small" variant="outlined" sx={btnSx} aria-label="Load" disabled={loadUrlLoading} onClick={async () => {
          setLoadUrlLoading(true);
          try {
            const txt = await onLoadJsFromUrl(loadUrl);
            setJs(txt);
            setConnectMsg('url loaded'); setTimeout(() => setConnectMsg(''), 1200);
          } catch (e: any) { setError(`URL load failed: ${String(e?.message || 'not JavaScript')}`); }
          finally { setLoadUrlLoading(false); }
        }}>{loadUrlLoading ? 'Loading…' : 'Load'}</Button>
      </Stack>
    </>
  );
}
