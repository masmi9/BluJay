import { useState, useMemo } from 'react';
import { Box, Button, ButtonGroup, Checkbox, Chip, Divider, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { secureFetch } from '../lib/api';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, EmptyState, ErrorDisplay, LoadingSkeleton, StatusChip, ConfirmDialog } from '../components';

type Task = {
  id: string;
  type: string;
  title: string;
  severity?: string;
  category?: string;
  cwe_id?: string;
  file_path?: string;
  location?: string;
  tool?: string;
  aods?: any;
  external?: any;
};

const TASK_TYPES = ['all', 'missing_in_aods', 'missing_in_external', 'severity_mismatch', 'meta_mismatch'];
const SORT_OPTIONS = ['severity', 'type', 'cwe'];

export function Curation() {
  const { data: summary, loading: loadingSummary, error: summaryErr } = useApiQuery<{ counts: Record<string, number> }>('/curation/summary');
  const { data: taskData, loading: loadingTasks, error: tasksErr, refetch } = useApiQuery<{ tasks: Task[] }>('/curation/tasks');
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');
  const [sortBy, setSortBy] = useState('severity');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkDialog, setBulkDialog] = useState<{ open: boolean; action: string }>({ open: false, action: '' });
  const queryError = summaryErr || tasksErr;

  const counts = summary?.counts ?? {};
  const tasks = taskData?.tasks ?? [];
  const loading = loadingSummary || loadingTasks;

  const filtered = useMemo(() => {
    let list = [...tasks];
    if (typeFilter !== 'all') list = list.filter(t => t.type === typeFilter);
    if (sevFilter !== 'all') list = list.filter(t => (t.severity || '').toUpperCase() === sevFilter);
    list.sort((a, b) => {
      if (sortBy === 'severity') {
        const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        return (order[(a.severity || 'INFO').toUpperCase()] ?? 5) - (order[(b.severity || 'INFO').toUpperCase()] ?? 5);
      }
      if (sortBy === 'type') return (a.type || '').localeCompare(b.type || '');
      if (sortBy === 'cwe') return (a.cwe_id || '').localeCompare(b.cwe_id || '');
      return 0;
    });
    return list;
  }, [tasks, typeFilter, sevFilter, sortBy]);

  const act = async (id: string, action: 'verify' | 'fp' | 'skip') => {
    setError(null);
    try {
      const n = notes[id] || '';
      const r = await secureFetch('/curation/review', { method: 'POST', body: JSON.stringify({ id, action, notes: n }) });
      if (!r.ok) throw new Error(`Review failed: ${r.status}`);
      refetch();
    } catch (e: any) {
      setError(e?.message || 'Review action failed');
    }
  };

  const bulkAct = async (action: 'verify' | 'fp' | 'skip') => {
    setError(null);
    for (const id of selected) {
      try {
        const r = await secureFetch('/curation/review', { method: 'POST', body: JSON.stringify({ id, action, notes: '' }) });
        if (!r.ok) throw new Error(`Review failed for ${id}: ${r.status}`);
      } catch (e: any) {
        setError(e?.message || `Bulk action failed`);
        break;
      }
    }
    setSelected(new Set());
    setBulkDialog({ open: false, action: '' });
    refetch();
  };

  function toggleSelect(id: string) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (selected.size === filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map(t => t.id)));
  }

  return (
    <Box>
      <PageHeader title="Curation Queue" subtitle="Review and classify security findings" />
      <ErrorDisplay error={error || queryError} onRetry={refetch} />
      <Stack direction="row" spacing={2} sx={{ mb: 2, mt: error ? 1 : 0 }} flexWrap="wrap" useFlexGap>
        <Chip label={`Missing in AODS: ${counts.missing_in_aods ?? 0}`} color="warning" />
        <Chip label={`Missing in External: ${counts.missing_in_external ?? 0}`} />
        <Chip label={`Severity Mismatch: ${counts.severity_mismatch ?? 0}`} color="secondary" />
        <Chip label={`Meta Mismatch: ${counts.meta_mismatch ?? 0}`} color="info" />
        <Chip label={`Total: ${counts.total ?? 0}`} color="primary" />
      </Stack>

      {/* Filter bar */}
      <Stack direction="row" spacing={2} sx={{ mb: 2 }} alignItems="center" flexWrap="wrap" useFlexGap>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel id="type-filter-label">Type</InputLabel>
          <Select labelId="type-filter-label" label="Type" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            {TASK_TYPES.map(t => <MenuItem key={t} value={t}>{t === 'all' ? 'All Types' : t.replace(/_/g, ' ')}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel id="sev-filter-label">Severity</InputLabel>
          <Select labelId="sev-filter-label" label="Severity" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="CRITICAL">Critical</MenuItem>
            <MenuItem value="HIGH">High</MenuItem>
            <MenuItem value="MEDIUM">Medium</MenuItem>
            <MenuItem value="LOW">Low</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel id="sort-label">Sort by</InputLabel>
          <Select labelId="sort-label" label="Sort by" value={sortBy} onChange={e => setSortBy(e.target.value)}>
            {SORT_OPTIONS.map(s => <MenuItem key={s} value={s}>{s}</MenuItem>)}
          </Select>
        </FormControl>
        <Typography variant="body2" color="text.secondary">{filtered.length} task{filtered.length !== 1 ? 's' : ''}</Typography>
        {selected.size > 0 && (
          <ButtonGroup size="small" variant="outlined">
            <Button onClick={() => setBulkDialog({ open: true, action: 'verify' })}>Verify ({selected.size})</Button>
            <Button onClick={() => setBulkDialog({ open: true, action: 'fp' })}>Mark FP ({selected.size})</Button>
            <Button onClick={() => setBulkDialog({ open: true, action: 'skip' })}>Skip ({selected.size})</Button>
          </ButtonGroup>
        )}
      </Stack>

      {loading ? (
        <LoadingSkeleton variant="table" />
      ) : (
        <Stack spacing={2}>
          {filtered.length > 0 && (
            <Stack direction="row" alignItems="center" spacing={1}>
              <Checkbox checked={selected.size === filtered.length && filtered.length > 0} indeterminate={selected.size > 0 && selected.size < filtered.length} onChange={toggleAll} size="small" />
              <Typography variant="caption" color="text.secondary">Select all</Typography>
            </Stack>
          )}
          {filtered.map((t) => (
            <DataCard key={t.id} title={t.title} variant="outlined" actions={<StatusChip status={t.type === 'missing_in_aods' ? 'WARN' : t.type === 'severity_mismatch' ? 'MEDIUM' : 'INFO'} label={t.type} />}>
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Checkbox checked={selected.has(t.id)} onChange={() => toggleSelect(t.id)} size="small" />
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {t.category && <Chip size="small" label={`category: ${t.category}`} />}
                    {t.cwe_id && <Chip size="small" label={`cwe: ${t.cwe_id}`} />}
                    {t.file_path && <Chip size="small" label={`file: ${t.file_path}`} />}
                    {t.location && <Chip size="small" label={`location: ${t.location}`} />}
                    {t.tool && <Chip size="small" label={`tool: ${t.tool}`} />}
                  </Stack>
                </Stack>
                <Divider />
                <Stack direction="row" spacing={2} alignItems="center">
                  <ButtonGroup size="small">
                    <Button variant="contained" onClick={() => act(t.id, 'verify')}>Verify</Button>
                    <Button variant="outlined" onClick={() => act(t.id, 'fp')}>Mark FP</Button>
                    <Button onClick={() => act(t.id, 'skip')}>Skip</Button>
                  </ButtonGroup>
                  <TextField size="small" fullWidth placeholder="Notes" value={notes[t.id] || ''} onChange={(e) => setNotes((p) => ({ ...p, [t.id]: e.target.value }))} />
                </Stack>
              </Stack>
            </DataCard>
          ))}
          {filtered.length === 0 && tasks.length > 0 && (
            <EmptyState message="No tasks match the current filters." />
          )}
          {tasks.length === 0 && (
            <EmptyState message="No tasks. Import via API to populate queue." />
          )}
        </Stack>
      )}

      <ConfirmDialog
        open={bulkDialog.open}
        title={`Bulk ${bulkDialog.action}?`}
        message={`Apply "${bulkDialog.action}" to ${selected.size} selected task${selected.size !== 1 ? 's' : ''}?`}
        severity="warning"
        confirmLabel={bulkDialog.action || 'Confirm'}
        onConfirm={() => bulkAct(bulkDialog.action as 'verify' | 'fp' | 'skip')}
        onCancel={() => setBulkDialog({ open: false, action: '' })}
      />
    </Box>
  );
}
