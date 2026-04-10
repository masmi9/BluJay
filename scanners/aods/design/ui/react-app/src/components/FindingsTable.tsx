import { useState, useMemo } from 'react';
import { Box, Checkbox, Chip, Collapse, FormControl, IconButton, InputLabel, MenuItem, Select, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TableSortLabel, Tooltip, Typography } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import PsychologyIcon from '@mui/icons-material/Psychology';
import { SeverityChip } from './SeverityChip';

export interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  confidence?: number;
  file_path?: string;
  line_number?: number;
  description?: string;
  recommendation?: string;
  code_snippet?: string;
  cwe_id?: string;
  masvs_category?: string;
  references?: string[];
  category?: string;
  plugin_source?: string;
  evidence?: Record<string, unknown>;
}

export interface FindingsTableProps {
  findings: Finding[];
  compact?: boolean;
  maxRows?: number;
  onFindingClick?: (f: Finding) => void;
  onExplainClick?: (f: Finding) => void;
  selectable?: boolean;
  selected?: Set<number>;
  onSelectionChange?: (selected: Set<number>) => void;
}

type SortKey = 'severity' | 'confidence' | 'file_path' | 'title';
type SortDir = 'asc' | 'desc';

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function sevRank(s?: string): number {
  return SEV_ORDER[(s || '').toUpperCase()] ?? 5;
}

function copyText(text: string) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

export function FindingsTable({ findings, compact = false, maxRows, onFindingClick, onExplainClick, selectable, selected, onSelectionChange }: FindingsTableProps) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [sevFilter, setSevFilter] = useState<string>('ALL');

  const filtered = useMemo(() => {
    if (sevFilter === 'ALL') return findings;
    return findings.filter(f => (f.severity || '').toUpperCase() === sevFilter);
  }, [findings, sevFilter]);

  const sorted = useMemo(() => {
    const list = [...filtered];
    list.sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'severity') cmp = sevRank(a.severity) - sevRank(b.severity);
      else if (sortKey === 'confidence') cmp = (b.confidence ?? 0) - (a.confidence ?? 0);
      else if (sortKey === 'file_path') cmp = (a.file_path || '').localeCompare(b.file_path || '');
      else cmp = (a.title || '').localeCompare(b.title || '');
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return maxRows ? list.slice(0, maxRows) : list;
  }, [filtered, sortKey, sortDir, maxRows]);

  // Map sorted items back to their index in the original findings array
  const sortedOriginalIndices = useMemo(() => {
    return sorted.map(f => findings.indexOf(f));
  }, [sorted, findings]);

  function handleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
  }

  function toggle(idx: number) {
    setExpanded(p => ({ ...p, [idx]: !p[idx] }));
  }

  function handleSelectAll() {
    if (!onSelectionChange) return;
    const allSelected = sortedOriginalIndices.every(i => selected?.has(i));
    if (allSelected) {
      onSelectionChange(new Set());
    } else {
      onSelectionChange(new Set(sortedOriginalIndices));
    }
  }

  function handleSelectOne(origIdx: number) {
    if (!onSelectionChange) return;
    const next = new Set(selected);
    if (next.has(origIdx)) next.delete(origIdx);
    else next.add(origIdx);
    onSelectionChange(next);
  }

  const allChecked = selectable && sortedOriginalIndices.length > 0 && sortedOriginalIndices.every(i => selected?.has(i));
  const someChecked = selectable && sortedOriginalIndices.some(i => selected?.has(i)) && !allChecked;

  // Compute column count for detail row colSpan
  let colCount = compact ? 3 : 5; // severity + title + confidence (compact) or + file + line
  colCount += 1; // expand button column
  if (selectable) colCount += 1;
  if (onExplainClick) colCount += 1;

  return (
    <Box>
      <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="body2" color="text.secondary">{filtered.length} finding{filtered.length !== 1 ? 's' : ''}</Typography>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel id="sev-filter-label">Severity</InputLabel>
          <Select labelId="sev-filter-label" label="Severity" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
            <MenuItem value="ALL">All</MenuItem>
            <MenuItem value="CRITICAL">Critical</MenuItem>
            <MenuItem value="HIGH">High</MenuItem>
            <MenuItem value="MEDIUM">Medium</MenuItem>
            <MenuItem value="LOW">Low</MenuItem>
            <MenuItem value="INFO">Info</MenuItem>
          </Select>
        </FormControl>
      </Stack>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              {selectable && (
                <TableCell padding="checkbox">
                  <Checkbox
                    checked={allChecked}
                    indeterminate={someChecked}
                    onChange={handleSelectAll}
                    inputProps={{ 'aria-label': 'Select all findings' }}
                    data-testid="select-all-checkbox"
                  />
                </TableCell>
              )}
              <TableCell padding="checkbox" />
              <TableCell><TableSortLabel active={sortKey === 'severity'} direction={sortKey === 'severity' ? sortDir : 'asc'} onClick={() => handleSort('severity')}>Severity</TableSortLabel></TableCell>
              <TableCell><TableSortLabel active={sortKey === 'title'} direction={sortKey === 'title' ? sortDir : 'asc'} onClick={() => handleSort('title')}>Title</TableSortLabel></TableCell>
              {!compact && <TableCell><TableSortLabel active={sortKey === 'file_path'} direction={sortKey === 'file_path' ? sortDir : 'asc'} onClick={() => handleSort('file_path')}>File</TableSortLabel></TableCell>}
              {!compact && <TableCell>Line</TableCell>}
              <TableCell><TableSortLabel active={sortKey === 'confidence'} direction={sortKey === 'confidence' ? sortDir : 'asc'} onClick={() => handleSort('confidence')}>Confidence</TableSortLabel></TableCell>
              {onExplainClick && <TableCell>Explain</TableCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {sorted.map((f, idx) => {
              const origIdx = sortedOriginalIndices[idx];
              return (
                <TableRow key={idx} sx={{ cursor: onFindingClick ? 'pointer' : 'default' }} onClick={() => onFindingClick?.(f)} hover>
                  {selectable && (
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={selected?.has(origIdx) ?? false}
                        onChange={() => handleSelectOne(origIdx)}
                        onClick={e => e.stopPropagation()}
                        inputProps={{ 'aria-label': `Select finding ${idx + 1}` }}
                        data-testid="finding-checkbox"
                      />
                    </TableCell>
                  )}
                  <TableCell padding="checkbox">
                    <IconButton size="small" onClick={e => { e.stopPropagation(); toggle(idx); }}>
                      {expanded[idx] ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
                    </IconButton>
                  </TableCell>
                  <TableCell><SeverityChip severity={f.severity || ''} /></TableCell>
                  <TableCell>{f.title || 'Untitled'}</TableCell>
                  {!compact && <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><Tooltip title={f.file_path || ''}><span>{f.file_path || '-'}</span></Tooltip></TableCell>}
                  {!compact && <TableCell>{f.line_number ?? '-'}</TableCell>}
                  <TableCell>{f.confidence != null ? `${Math.round(f.confidence * 100)}%` : '-'}</TableCell>
                  {onExplainClick && (
                    <TableCell>
                      <Tooltip title="Explain this finding">
                        <IconButton size="small" onClick={e => { e.stopPropagation(); onExplainClick(f); }} aria-label="Explain finding" data-testid="explain-btn">
                          <PsychologyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  )}
                </TableRow>
              );
            })}
            {sorted.map((f, idx) => expanded[idx] && (
              <TableRow key={`detail-${idx}`}>
                <TableCell colSpan={colCount} sx={{ py: 0 }}>
                  <Collapse in={expanded[idx]}>
                    <Box sx={{ p: 2 }}>
                      <Stack spacing={1}>
                        {f.description && <Typography variant="body2"><strong>Description:</strong> {f.description}</Typography>}
                        {f.recommendation && <Typography variant="body2"><strong>Recommendation:</strong> {f.recommendation}</Typography>}
                        {f.code_snippet && (
                          <Box>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Typography variant="body2"><strong>Code:</strong></Typography>
                              <IconButton size="small" onClick={() => copyText(f.code_snippet || '')}><ContentCopyIcon fontSize="small" /></IconButton>
                            </Stack>
                            <Box component="pre" sx={{ m: 0, mt: 0.5, p: 1.5, bgcolor: 'background.default', borderRadius: 1, overflow: 'auto', maxHeight: 200, fontFamily: 'monospace', fontSize: '0.8rem', whiteSpace: 'pre-wrap' }}>
                              {f.code_snippet}
                            </Box>
                          </Box>
                        )}
                        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                          {f.cwe_id && <Chip size="small" label={`CWE: ${f.cwe_id}`} />}
                          {f.masvs_category && <Chip size="small" label={`MASVS: ${f.masvs_category}`} />}
                          {f.category && <Chip size="small" label={f.category} />}
                          {f.plugin_source && <Chip size="small" label={`Plugin: ${f.plugin_source}`} variant="outlined" />}
                        </Stack>
                        {f.references && f.references.length > 0 && (
                          <Box>
                            <Typography variant="body2"><strong>References:</strong></Typography>
                            {f.references.map((ref, ri) => (
                              <Typography key={ri} variant="body2" component="a" href={ref} target="_blank" rel="noopener noreferrer" sx={{ display: 'block', fontSize: '0.8rem', color: 'primary.main' }}>{ref}</Typography>
                            ))}
                          </Box>
                        )}
                      </Stack>
                    </Box>
                  </Collapse>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {findings.length === 0 && <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 3 }}>No findings to display</Typography>}
    </Box>
  );
}
