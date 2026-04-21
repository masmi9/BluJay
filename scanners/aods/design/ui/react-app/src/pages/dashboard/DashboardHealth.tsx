import { useState } from 'react';
import { Alert, Box, Button, Chip, Grid, Stack, TextField, Typography } from '@mui/material';
import { secureFetch } from '../../lib/api';
import { DataCard } from '../../components';
import type { FridaDevice, FridaHealthStatus, ToolsStatusResponse, ToolStatus } from '../../types';

interface DashboardHealthProps {
  tools: ToolsStatusResponse | null;
  showFrida: boolean;
}

export function DashboardHealth({ tools, showFrida }: DashboardHealthProps) {
  const [fridaPackage, setFridaPackage] = useState('');
  const [fridaStatus, setFridaStatus] = useState<FridaHealthStatus | null>(null);
  const [fridaLoading, setFridaLoading] = useState(false);
  const [fridaError, setFridaError] = useState<string | null>(null);

  function renderToolChip(name: string, v: ToolStatus | undefined) {
    const ok = Boolean((v && (v.available ?? v.ready)) || false);
    const color: 'success' | 'error' = ok ? 'success' : 'error';
    return <Chip size="small" color={color} label={`${name.toUpperCase()} ${ok ? 'PASS' : 'FAIL'}`} sx={{ mr: 1 }} />;
  }

  async function probeFrida() {
    setFridaError(null);
    setFridaStatus(null);
    setFridaLoading(true);
    try {
      const resp = await secureFetch(`/frida/session/${encodeURIComponent(fridaPackage)}/status`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      setFridaStatus(await resp.json());
    } catch (e: unknown) {
      setFridaError((e as Error)?.message || 'Probe failed');
    } finally {
      setFridaLoading(false);
    }
  }

  return (
    <>
      <Grid item xs={12}>
        <DataCard title="System Health">
          {tools ? (
            <Typography component="div">
              {renderToolChip('adb', tools.adb)}
              {renderToolChip('frida', tools.frida)}
              {renderToolChip('jadx', tools.jadx)}
            </Typography>
          ) : (
            <Typography color="text.secondary">Status unavailable</Typography>
          )}
        </DataCard>
      </Grid>
      {showFrida && (
        <Grid item xs={12}>
          <DataCard title="Frida Device Health">
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems="center">
              <TextField size="small" label="Package" value={fridaPackage} onChange={(e) => setFridaPackage(e.target.value)} sx={{ minWidth: 280 }} />
              <Button size="small" variant="outlined" onClick={probeFrida} disabled={!fridaPackage || fridaLoading}>Probe</Button>
            </Stack>
            {fridaLoading && <Typography sx={{ mt: 1 }} color="text.secondary">Probing...</Typography>}
            {fridaError && <Alert sx={{ mt: 1 }} severity="error">{fridaError}</Alert>}
            {fridaStatus && (
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2">Available: {String(fridaStatus.available)}</Typography>
                {fridaStatus.message && <Typography variant="body2">{fridaStatus.message}</Typography>}
                {(Array.isArray(fridaStatus.devices) && fridaStatus.devices.length > 0) && (
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="body2" color="text.secondary">Devices</Typography>
                    <Stack direction="row" spacing={1} useFlexGap sx={{ mt: 0.5, flexWrap: 'wrap' }}>
                      {fridaStatus.devices.map((d: FridaDevice, idx: number) => (
                        <Chip key={idx} size="small" label={`${d.name || d.id} (${d.type || 'usb'})`} />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Box>
            )}
          </DataCard>
        </Grid>
      )}
    </>
  );
}
