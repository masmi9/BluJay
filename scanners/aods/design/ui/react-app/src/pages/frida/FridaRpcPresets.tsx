import { useMemo } from 'react';
import { Button, MenuItem, Stack, TextField } from '@mui/material';

export interface RpcPresetItem {
  name: string;
  fn: string;
  args: string;
  tags?: string[];
}

interface FridaRpcPresetsProps {
  presets: RpcPresetItem[];
  selectedName: string;
  search: string;
  tagFilter: string;
  onSelect: (name: string) => void;
  onSave: () => void;
  onSearchChange: (value: string) => void;
  onTagFilterChange: (value: string) => void;
  fieldDenseSx: Record<string, any>;
  btnSx: Record<string, any>;
}

/**
 * RPC preset management UI: search, filter by tag, select, and save presets.
 * Extracted from FridaRpcPanel to improve separation of concerns.
 */
export function FridaRpcPresets({
  presets,
  selectedName,
  search,
  tagFilter,
  onSelect,
  onSave,
  onSearchChange,
  onTagFilterChange,
  fieldDenseSx,
  btnSx,
}: FridaRpcPresetsProps) {
  const filteredPresets = useMemo(() => {
    const q = search.trim().toLowerCase();
    const tg = tagFilter.trim().toLowerCase();
    return presets.filter(p => {
      const inName = !q || p.name.toLowerCase().includes(q) || p.fn.toLowerCase().includes(q);
      const inTag = !tg || (Array.isArray(p.tags) && p.tags.some(t => t.toLowerCase().includes(tg)));
      return inName && inTag;
    });
  }, [presets, search, tagFilter]);

  return (
    <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap', rowGap: 1 }}>
      <TextField
        size="small"
        label="Search presets"
        value={search}
        onChange={e => onSearchChange(e.target.value)}
        sx={{ width: 180, ...fieldDenseSx }}
      />
      <TextField
        size="small"
        label="Tag"
        placeholder="tag filter"
        value={tagFilter}
        onChange={e => onTagFilterChange(e.target.value)}
        sx={{ width: 140, ...fieldDenseSx }}
      />
      <TextField
        label="RPC Presets"
        select
        value={selectedName}
        onChange={e => onSelect(e.target.value)}
        size="small"
        sx={{ minWidth: 200, ...fieldDenseSx }}
      >
        {filteredPresets.length === 0 ? (
          <MenuItem value="">(none)</MenuItem>
        ) : (
          filteredPresets.map(p => (
            <MenuItem key={p.name} value={p.name}>
              {p.name}
              {Array.isArray(p.tags) && p.tags.length > 0 ? ` \u2014 [${p.tags.join(', ')}]` : ''}
            </MenuItem>
          ))
        )}
      </TextField>
      <Button size="small" variant="outlined" onClick={onSave} sx={btnSx}>
        Save RPC preset
      </Button>
    </Stack>
  );
}
