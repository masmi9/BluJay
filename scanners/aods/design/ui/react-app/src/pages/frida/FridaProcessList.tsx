import React from 'react';
import {
  Alert, Box, Button, Chip, FormControlLabel, IconButton,
  Skeleton, Stack, Switch, TextField, Typography,
} from '@mui/material';
import StarIcon from '@mui/icons-material/Star.js';
import StarBorderIcon from '@mui/icons-material/StarBorder.js';
import { useElapsedIso } from './useElapsedIso';

interface FridaProcessListProps {
  memoProcesses: { pid: number; name: string }[];
  processes: { pid: number; name: string }[];
  procFilter: string;
  setProcFilter: (v: string) => void;
  procLoading: boolean;
  procError: string;
  autoAttach: boolean;
  setAutoAttach: (v: boolean) => void;
  autoReloadProcs: boolean;
  setAutoReloadProcs: (v: boolean) => void;
  selectedDeviceId: string | null;
  devices: { id: string; name: string }[];
  favoritePids: number[];
  setFavoritePids: React.Dispatch<React.SetStateAction<number[]>>;
  lastProcsIso: string;
  chipSx: Record<string, any>;
  onLoadProcessesWithRetry: (devId: string) => void;
  onEnsureCorellium: () => void;
  onAttach: (devId: string, pid: number) => void;
  onShowCopyToast: (msg: string) => void;
  setConnectMsg: (v: string) => void;
}

export function FridaProcessList({
  memoProcesses, processes, procFilter, setProcFilter, procLoading, procError,
  autoAttach, setAutoAttach, autoReloadProcs, setAutoReloadProcs,
  selectedDeviceId, devices, favoritePids, setFavoritePids,
  lastProcsIso, chipSx, onLoadProcessesWithRetry, onEnsureCorellium,
  onAttach, onShowCopyToast, setConnectMsg,
}: FridaProcessListProps) {
  const procsElapsed = useElapsedIso(lastProcsIso);

  const resolveDevId = () => {
    const remote = devices.find((d: any) => String(d?.id || '').startsWith('socket@127.0.0.1:'))?.id;
    return remote || selectedDeviceId || devices[0]?.id || 'local';
  };

  const ProcessRow = React.useCallback(({ p }: { p: { pid: number; name: string } }) => (
    <Stack key={p.pid} direction="row" spacing={0.5} alignItems="center">
      <IconButton size="small" aria-label={favoritePids.includes(p.pid) ? `unpin pid ${p.pid}` : `pin pid ${p.pid}`} onClick={() => {
        setFavoritePids(prev => prev.includes(p.pid) ? prev.filter(x => x !== p.pid) : [...prev, p.pid]);
      }}>
        {favoritePids.includes(p.pid) ? <StarIcon fontSize="small" color="warning" /> : <StarBorderIcon fontSize="small" />}
      </IconButton>
      <Button aria-label={`attach ${p.name}`} variant="outlined" size="small" onClick={() => { onAttach(resolveDevId(), p.pid); }}>{p.name} ({p.pid})</Button>
      <Button aria-label={`copy pid ${p.pid}`} variant="text" size="small" onClick={async () => { try { await navigator.clipboard.writeText(String(p.pid)); setConnectMsg('PID copied'); setTimeout(() => setConnectMsg(''), 800); onShowCopyToast('Copied PID'); } catch {} }}>Copy PID</Button>
    </Stack>
  ), [favoritePids, selectedDeviceId, devices]);

  return (
    <Box>
      <Stack direction="row" spacing={1} alignItems="center">
        <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Processes</Typography>
        <Typography variant="caption" color="text.secondary">Last fetched {procsElapsed}</Typography>
        <Chip label="Reload" aria-label="reload processes" size="small" onClick={() => { onLoadProcessesWithRetry(resolveDevId()); }} clickable sx={chipSx} />
        <FormControlLabel control={<Switch checked={autoAttach} onChange={(e) => setAutoAttach(e.target.checked)} />} label="Auto-attach to package" />
        <FormControlLabel control={<Switch checked={autoReloadProcs} onChange={(e) => setAutoReloadProcs(e.target.checked)} />} label="Auto-reload" />
      </Stack>
      {procError && (
        <Alert severity="warning" sx={{ my: 1 }}
          action={<Stack direction="row" spacing={1}>
            <Button color="inherit" size="small" onClick={() => { onLoadProcessesWithRetry(resolveDevId()); }}>Reload</Button>
            <Button color="inherit" size="small" onClick={onEnsureCorellium}>Ensure</Button>
          </Stack>}>
          {procError}
        </Alert>
      )}
      <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
        <TextField aria-label="process filter" label="Filter" value={procFilter} onChange={e => setProcFilter(e.target.value)} size="small" placeholder="type to filter..." />
      </Stack>
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', maxHeight: 200, overflow: 'auto' }}>
        {procLoading ? (
          Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} variant="rounded" width={180} height={28} sx={{ borderRadius: 1 }} />
          ))
        ) : (
          (() => {
            const filtered = memoProcesses;
            if (processes.length > 0 && filtered.length === 0) {
              return (
                <Stack direction="row" spacing={1} alignItems="center">
                  <Chip label="No matches" size="small" />
                  <Typography variant="caption" color="text.secondary">No results for &apos;{procFilter}&apos;.</Typography>
                  <Button size="small" variant="text" onClick={() => setProcFilter('')}>Clear filter</Button>
                  <Chip label="Reload" size="small" onClick={() => { onLoadProcessesWithRetry(resolveDevId()); }} clickable sx={chipSx} />
                </Stack>
              );
            }
            if (filtered.length > 0) {
              return filtered.map(p => (
                <ProcessRow key={p.pid} p={p} />
              ));
            }
            return (
              <Stack direction="row" spacing={1} alignItems="center">
                <Chip label="No processes" size="small" />
                <Typography variant="caption" color="text.secondary">Tip: Ensure device is attached and app is running. Use Reload.</Typography>
              </Stack>
            );
          })()
        )}
      </Box>
    </Box>
  );
}
