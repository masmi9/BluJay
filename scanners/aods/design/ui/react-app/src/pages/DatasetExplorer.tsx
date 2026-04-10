import { useEffect, useMemo, useState } from 'react';
import { Box, Button, Chip, Divider, Grid, Paper, Stack, TextField, Typography, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import { secureFetch } from '../lib/api';
import { PageHeader, ErrorDisplay, LoadingSkeleton, EmptyState } from '../components';
import { useApiQuery } from '../hooks';

type ArtifactItem = { name: string; relPath: string; isDir: boolean; size: number; mtime: string };

export function DatasetExplorer() {
  const [subdir, setSubdir] = useState<string>('ml_baselines');
  const { data: items, loading, error, refetch } = useApiQuery<ArtifactItem[]>(
    `/artifacts/list?subdir=${encodeURIComponent(subdir)}`,
    { transform: (j: Record<string, unknown>) => Array.isArray(j?.items) ? j.items as ArtifactItem[] : [] },
  );
  const [selected, setSelected] = useState<ArtifactItem | null>(null);
  const [preview, setPreview] = useState<{ contentType: string; content: string } | null>(null);
  const [query, setQuery] = useState<string>('');

  // Clear selection when subdir changes
  useEffect(() => {
    setSelected(null);
    setPreview(null);
  }, [subdir]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        try { setSelected(null); setPreview(null); } catch {}
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  async function loadPreview(item: ArtifactItem) {
    if (selected?.relPath === item.relPath) {
      setSelected(null);
      setPreview(null);
      return;
    }
    setSelected(item);
    setPreview(null);
    if (item.isDir) return;
    try {
      const r = await secureFetch(`/artifacts/read?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(item.relPath)}`);
      if (!r.ok) {
        const txt = await r.text();
        setPreview({ contentType: 'text/plain', content: `Preview unavailable (${r.status}): ${txt}` });
        return;
      }
      const j = await r.json();
      setPreview({ contentType: j?.contentType || 'text/plain', content: String(j?.content || '') });
    } catch (e: any) {
      setPreview({ contentType: 'text/plain', content: e?.message || 'Failed to load preview' });
    }
  }

  const filtered = useMemo(() => {
    const list = items ?? [];
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter(i => i.name.toLowerCase().includes(q) || i.relPath.toLowerCase().includes(q));
  }, [items, query]);

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader title="Dataset Explorer" subtitle="Browse ML baseline artifacts. Preview small JSON/HTML/Markdown files; download any file." />
        <ErrorDisplay error={error} onRetry={refetch} />
        <Stack direction="row" spacing={1} alignItems="center">
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel id="ds-cat-label">Subdir</InputLabel>
            <Select labelId="ds-cat-label" label="Subdir" value={subdir} onChange={e => setSubdir(String(e.target.value))}>
              <MenuItem value="ml_baselines">ML Baselines</MenuItem>
              <MenuItem value="reports">Reports</MenuItem>
              <MenuItem value="ci_gates">CI Gates</MenuItem>
              <MenuItem value="scans">Scans</MenuItem>
              <MenuItem value="plugin_audit">Plugin Audit</MenuItem>
            </Select>
          </FormControl>
          <TextField size="small" label="Filter" value={query} onChange={e => setQuery(e.target.value)} />
        </Stack>
        {loading ? (
          <LoadingSkeleton variant="list" />
        ) : (
          <Grid container spacing={2}>
            <Grid item xs={12} md={5}>
              <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1.5 }}>
                  Files (<Typography component="span" sx={{ fontVariantNumeric: 'tabular-nums' }}>{filtered.length}</Typography>)
                </Typography>
                <Stack spacing={0} divider={<Divider />}>
                  {filtered.length === 0 && <EmptyState message="No items match the current filter" />}
                  {filtered.slice(0, 200).map((it) => {
                    const ext = (it.name.split('.').pop() || '').toLowerCase();
                    const type = it.isDir ? 'dir' : (ext || 'file');
                    const sizeKb = it.size ? Math.round(it.size / 1024) : 0;
                    const isSelected = selected?.relPath === it.relPath;
                    return (
                      <Button key={it.relPath} onClick={() => loadPreview(it)} color="inherit" sx={{ justifyContent: 'flex-start', textTransform: 'none', py: 1, borderRadius: 1, bgcolor: isSelected ? 'action.selected' : 'transparent', '&:hover': { bgcolor: isSelected ? 'action.selected' : 'action.hover' } }}>
                        <Stack spacing={0} alignItems="flex-start" sx={{ width: '100%' }}>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{it.name}{it.isDir ? '/' : ''}</Typography>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Chip size="small" label={type} color={type === 'json' ? 'success' : type === 'html' ? 'primary' : 'default'} />
                            {!it.isDir && <Typography variant="caption" color="text.secondary">{sizeKb} KB</Typography>}
                          </Stack>
                        </Stack>
                      </Button>
                    );
                  })}
                </Stack>
              </Paper>
            </Grid>
            <Grid item xs={12} md={7}>
              <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
                {selected && preview ? (
                  <>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13 }}>{selected.name}</Typography>
                      <Stack direction="row" spacing={0.5}>
                        <Button variant="outlined" size="small" onClick={async () => { try { const r = await secureFetch(`/artifacts/download?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(selected.relPath)}`); if (!r.ok) return; const blob = await r.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = selected.name; a.click(); URL.revokeObjectURL(url); } catch {} }}>Download</Button>
                        <Button variant="text" size="small" onClick={() => { setSelected(null); setPreview(null); }}>Close</Button>
                      </Stack>
                    </Stack>
                    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', maxHeight: 400, overflow: 'auto', bgcolor: 'background.default', p: 1.5, borderRadius: 1, fontFamily: 'monospace', fontSize: 12, m: 0 }}>
                      {preview.content}
                    </Box>
                  </>
                ) : (
                  <Typography variant="body2" color="text.secondary" sx={{ py: 6, textAlign: 'center' }}>
                    Select a file from the list to preview its contents.
                  </Typography>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}
      </Stack>
    </Box>
  );
}

export default DatasetExplorer;


