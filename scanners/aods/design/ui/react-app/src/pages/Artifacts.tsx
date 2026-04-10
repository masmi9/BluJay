import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Box, Button, Chip, FormControl, InputLabel, MenuItem, Select, Stack, Typography, TextField } from '@mui/material';
import FolderOffIcon from '@mui/icons-material/FolderOff';
import { secureFetch } from '../lib/api';
import { StructuredPreview } from '../components/StructuredPreview';
import { PageHeader, ErrorDisplay, EmptyState, AppToast } from '../components';
import { useToast } from '../hooks/useToast';

type ArtifactItem = {
  name: string;
  relPath: string;
  isDir: boolean;
  size: number;
  mtime: string;
};

export function Artifacts() {
  const { toast, showToast, closeToast } = useToast();
  const [subdir, setSubdir] = useState<'ci_gates' | 'ml_baselines' | 'scans' | 'reports' | 'plugin_audit' | 'logs'>(() => { try { return (localStorage.getItem('aodsArtifacts_subdir') as any) || 'ci_gates'; } catch { return 'ci_gates'; } });
  const [items, setItems] = useState<ArtifactItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ relPath: string; content: string; contentType?: string, size?: number, eof?: boolean, nextOffset?: number } | null>(null);
  const [query, setQuery] = useState<string>(() => { try { return localStorage.getItem('aodsArtifacts_query') || ''; } catch { return ''; } });
  const [pathFilter, setPathFilter] = useState<string>(() => { try { return localStorage.getItem('aodsArtifacts_pathFilter') || ''; } catch { return ''; } });
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'DIR' | 'JSON' | 'HTML' | 'OTHER'>(() => { try { return (localStorage.getItem('aodsArtifacts_typeFilter') as any) || 'ALL'; } catch { return 'ALL'; } });
  const pendingPathRef = useRef<string | null>(null);

  const fetchArtifacts = useCallback(async () => {
    try {
      const r = await secureFetch(`/artifacts/list?subdir=${encodeURIComponent(subdir)}`);
      if (!r.ok) throw new Error(String(r.status));
      const data = await r.json();
      setItems(data.items || []);
      setError(null);
      return data.items || [];
    } catch (e: any) {
      setError(e?.message || 'Failed to load artifacts');
      return null;
    }
  }, [subdir]);

  useEffect(() => {
    (async () => {
      const loaded = await fetchArtifacts();
      if (!loaded) return;
      // Prefer URL search (?cat=...&path=...), fall back to hash (#/artifacts?cat=...)
      const searchParams = new URLSearchParams((location.search || '').replace(/^\?/, ''));
      let cat = searchParams.get('cat');
      let path = searchParams.get('path');
      if (!cat || !path) {
        const hashParams = new URLSearchParams((location.hash || '').replace(/^#\/?/, '').split('?')[1] || '');
        cat = cat || hashParams.get('cat');
        path = path || hashParams.get('path');
      }
      if (cat && path) {
        // Ensure files are visible when deep-linking
        try { setTypeFilter('ALL'); } catch {}
        if (cat !== subdir) {
          pendingPathRef.current = path;
          setSubdir(cat as any);
        } else {
          openPreview(path);
        }
      }
    })();
  }, [subdir]);

  useEffect(() => {
    // When subdir changes and items are loaded, open any pending deep-link path
    if (pendingPathRef.current && items && items.length >= 0) {
      const p = pendingPathRef.current;
      pendingPathRef.current = null;
      if (p) openPreview(p);
    }
  }, [items, subdir]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        try { setPreview(null); } catch {}
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { try { localStorage.setItem('aodsArtifacts_subdir', subdir); } catch {} }, [subdir]);
  useEffect(() => { try { localStorage.setItem('aodsArtifacts_query', query); } catch {} }, [query]);
  useEffect(() => { try { localStorage.setItem('aodsArtifacts_pathFilter', pathFilter); } catch {} }, [pathFilter]);
  useEffect(() => { try { localStorage.setItem('aodsArtifacts_typeFilter', typeFilter); } catch {} }, [typeFilter]);

  async function openPreview(relPath: string) {
    if (preview?.relPath === relPath) { setPreview(null); return; }
    setPreview(null);
    try {
      let r = await secureFetch(`/artifacts/read_chunk?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(relPath)}&offset=0&numBytes=131072`);
      if (!r.ok) {
        // Try non-chunk read as a fallback for small files and clearer errors
        const r2 = await secureFetch(`/artifacts/read?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(relPath)}`);
        if (!r2.ok) {
          // Surface server-provided detail when available
          try { const j = await r2.json(); setError(`HTTP ${r2.status}: ${j?.detail || 'preview failed'}`); } catch { setError(`HTTP ${r2.status}`); }
          return;
        }
        const j = await r2.json();
        setPreview({ relPath, content: j.content, size: j.size, eof: true, nextOffset: j.size });
        setError(null);
        return;
      }
      const data = await r.json();
      setPreview({ relPath, content: data.content, size: data.size, eof: data.eof, nextOffset: data.nextOffset });
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to read artifact');
    }
  }

  async function download(relPath: string) {
    try {
      const r = await secureFetch(`/artifacts/download?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(relPath)}`);
      if (!r.ok) { setError('Download failed'); return; }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = relPath.split('/').pop() || 'download';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e?.message || 'Download failed');
    }
  }

  const filteredItems = useMemo(() => {
    const q = (query || '').toLowerCase();
    const pfx = (pathFilter || '').toLowerCase();
    return (items || []).filter((it) => {
      const name = (it.name || '').toLowerCase();
      const rel = (it.relPath || '').toLowerCase();
      if (q && !(name.includes(q) || rel.includes(q))) return false;
      if (pfx && !rel.includes(pfx)) return false;
      if (typeFilter === 'DIR') return it.isDir;
      if (typeFilter === 'JSON') return !it.isDir && (it.name.toLowerCase().endsWith('.json'));
      if (typeFilter === 'HTML') return !it.isDir && (it.name.toLowerCase().endsWith('.html'));
      if (typeFilter === 'OTHER') return !it.isDir && !(it.name.toLowerCase().endsWith('.json') || it.name.toLowerCase().endsWith('.html'));
      return true;
    });
  }, [items, query, pathFilter, typeFilter]);

  const pageSize = 50;
  const pageItems = useMemo(() => filteredItems.slice(0, pageSize), [filteredItems]);
  const previewNotInList = useMemo(() => !!(preview && !pageItems.some(it => it.relPath === preview.relPath)), [preview, pageItems]);

  return (
    <Box>
      <Stack spacing={2}>
        <PageHeader title="Artifacts" subtitle="Browse CI gates, ML baselines, scan outputs, and log files" />
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <FormControl sx={{ minWidth: 180 }} size="small">
            <InputLabel id="cat-label">Category</InputLabel>
            <Select labelId="cat-label" label="Category" value={subdir} onChange={e => setSubdir(e.target.value as any)}>
              <MenuItem value="ci_gates">CI Gates</MenuItem>
              <MenuItem value="ml_baselines">ML Baselines</MenuItem>
              <MenuItem value="scans">Scans</MenuItem>
              <MenuItem value="reports">Reports</MenuItem>
              <MenuItem value="plugin_audit">Plugin Audit</MenuItem>
              <MenuItem value="logs">Logs</MenuItem>
            </Select>
          </FormControl>
          <TextField size="small" label="Search artifacts" placeholder="name or path" value={query} onChange={(e)=>setQuery(e.target.value)} sx={{ minWidth: 220 }} inputProps={{ 'aria-label': 'Search artifacts by name or path' }} />
          <TextField size="small" label="Path filter" placeholder="path contains…" value={pathFilter} onChange={(e)=>setPathFilter(e.target.value)} sx={{ minWidth: 220 }} inputProps={{ 'aria-label': 'Filter artifacts by path' }} />
          <FormControl sx={{ minWidth: 140 }} size="small">
            <InputLabel id="type-label">Type</InputLabel>
            <Select labelId="type-label" label="Type" value={typeFilter} onChange={(e)=>setTypeFilter(e.target.value as any)}>
              {['ALL','DIR','JSON','HTML','OTHER'].map((t)=> (<MenuItem key={t} value={t as any}>{t}</MenuItem>))}
            </Select>
          </FormControl>
          <Typography variant="caption" color="text.secondary" aria-live="polite">{filteredItems.length} items</Typography>
          <Box sx={{ flex: 1 }} />
          <Button size="small" aria-label="Export current page as CSV" onClick={() => {
            try {
              const rows = pageItems.map((it) => ({ name: it.name, relPath: it.relPath, isDir: it.isDir, size: it.size, mtime: it.mtime }));
              const header = ['name','relPath','isDir','size','mtime'];
              const csv = [header.join(',')].concat(rows.map(r => header.map(k => `"${String((r as any)[k] ?? '').replace(/"/g,'""')}"`).join(','))).join('\n');
              const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a'); a.href = url; a.download = 'artifacts_page.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(url), 15000);
              showToast('CSV exported');
            } catch { showToast('Export failed', 'error'); }
          }}>Export Page CSV</Button>
          <Button size="small" aria-label="Export current page as JSON" onClick={() => {
            try {
              const rows = pageItems.map((it) => ({ name: it.name, relPath: it.relPath, isDir: it.isDir, size: it.size, mtime: it.mtime }));
              const blob = new Blob([JSON.stringify({ items: rows }, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a'); a.href = url; a.download = 'artifacts_page.json'; a.click(); setTimeout(()=>URL.revokeObjectURL(url), 15000);
              showToast('JSON exported');
            } catch { showToast('Export failed', 'error'); }
          }}>Export Page JSON</Button>
        </Stack>
        <ErrorDisplay error={error} onRetry={fetchArtifacts} />
        <Stack spacing={1.5}>
          {pageItems.map(it => {
            const ext = (it.name.split('.').pop() || '').toLowerCase();
            const type = it.isDir ? 'dir' : (ext || 'file');
            const sizeKb = it.size ? Math.round(it.size / 1024) : 0;
            return (
              <Box key={it.relPath} sx={{ border: 1, borderColor: 'divider', borderRadius: 2, px: 2, py: 1.5, transition: 'background-color 0.15s', '&:hover': { bgcolor: 'action.hover' } }}>
                <Stack direction="row" alignItems="center" spacing={1.5} flexWrap="wrap" useFlexGap>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Stack direction="row" spacing={1} alignItems="baseline">
                      <Typography variant="body2" sx={{ fontWeight: 600, wordBreak: 'break-all' }}>{it.name}{it.isDir ? '/' : ''}</Typography>
                      <Chip size="small" label={type} color={type === 'json' ? 'success' : type === 'html' ? 'primary' : 'default'} />
                      {!it.isDir && <Chip size="small" label={`${sizeKb} KB`} variant="outlined" sx={{ fontVariantNumeric: 'tabular-nums' }} />}
                    </Stack>
                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 11 }}>{it.relPath}</Typography>
                  </Box>
                  {!it.isDir && (
                    <Stack direction="row" spacing={0.5}>
                      <Button size="small" variant="text" onClick={() => openPreview(it.relPath)} aria-label={`Preview ${it.name}`} aria-expanded={preview?.relPath === it.relPath}>Preview</Button>
                      <Button size="small" variant="text" onClick={() => download(it.relPath)} aria-label={`Download ${it.name}`}>Download</Button>
                    </Stack>
                  )}
                </Stack>
                {preview?.relPath === it.relPath && (
                  <Box sx={{ mt: 1.5, pt: 1.5, borderTop: 1, borderColor: 'divider' }}>
                    <StructuredPreview
                      content={preview.content}
                      fileName={it.name}
                      size={preview.size}
                      maxHeight={400}
                      hasMore={!preview.eof}
                      onLoadMore={async () => {
                        try {
                          const r = await secureFetch(`/artifacts/read_chunk?subdir=${encodeURIComponent(subdir)}&relPath=${encodeURIComponent(preview.relPath)}&offset=${preview.nextOffset || 0}&numBytes=131072`);
                          if (!r.ok) throw new Error(String(r.status));
                          const data = await r.json();
                          setPreview(p => p ? ({ ...p, content: p.content + data.content, eof: data.eof, nextOffset: data.nextOffset }) : p);
                        } catch (e: any) {
                          setError(e?.message || 'Failed to load more');
                        }
                      }}
                    />
                  </Box>
                )}
              </Box>
            );
          })}
          {pageItems.length === 0 && (
            <EmptyState icon={FolderOffIcon} message="No artifacts found" />
          )}
        </Stack>
        {preview && previewNotInList && (
          <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 1.5, p: 2, mt: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Preview: {preview.relPath}</Typography>
            <StructuredPreview
              content={preview.content}
              fileName={preview.relPath.split('/').pop()}
              size={preview.size}
              maxHeight={400}
              hasMore={!preview.eof}
            />
          </Box>
        )}
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}


