import { useRef } from 'react';
import {
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import FilterAltOffIcon from '@mui/icons-material/FilterAltOff';

export interface GateFilterBarProps {
  gateQuery: string;
  setGateQuery: (value: string) => void;
  gateStatus: string;
  setGateStatus: (value: string) => void;
  autoRefresh: boolean;
  setAutoRefresh: (value: boolean | ((prev: boolean) => boolean)) => void;
  totalCount: number;
  filteredCount: number;
  /** Count of items matching text filter (before status filter). Used for ALL chip. */
  textFilteredCount: number;
  statusCounts?: { PASS?: number; WARN?: number; FAIL?: number };
}

const STATUS_OPTIONS = ['ALL', 'PASS', 'WARN', 'FAIL'] as const;

const STATUS_CHIP_COLOR: Record<string, 'primary' | 'success' | 'warning' | 'error'> = {
  ALL: 'primary', PASS: 'success', WARN: 'warning', FAIL: 'error',
};

export function GateFilterBar({
  gateQuery,
  setGateQuery,
  gateStatus,
  setGateStatus,
  autoRefresh,
  setAutoRefresh,
  totalCount,
  filteredCount,
  textFilteredCount,
  statusCounts,
}: GateFilterBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const hasActiveFilters = gateQuery !== '' || gateStatus !== 'ALL';

  return (
    <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ xs: 'stretch', sm: 'center' }}>
        {/* Search */}
        <TextField
          size="small"
          placeholder="Filter by name..."
          value={gateQuery}
          onChange={(e) => setGateQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              setGateQuery('');
              inputRef.current?.blur();
            }
          }}
          inputRef={inputRef}
          inputProps={{ 'aria-label': 'Filter gates by name' }}
          sx={{ minWidth: 200, maxWidth: 300 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon sx={{ fontSize: 18, color: gateQuery ? 'primary.main' : 'text.disabled', transition: 'color 0.15s' }} />
              </InputAdornment>
            ),
            endAdornment: gateQuery ? (
              <InputAdornment position="end">
                <IconButton
                  size="small"
                  onClick={() => { setGateQuery(''); inputRef.current?.focus(); }}
                  edge="end"
                  aria-label="Clear search"
                >
                  <ClearIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </InputAdornment>
            ) : undefined,
          }}
        />

        {/* Status filter chips */}
        <Stack direction="row" spacing={0.75} alignItems="center" role="group" aria-label="Filter gates by status">
          {STATUS_OPTIONS.map((s) => {
            const count = s === 'ALL' ? textFilteredCount : (statusCounts?.[s] ?? 0);
            const isEmpty = s !== 'ALL' && count === 0;
            const isSelected = gateStatus === s;
            return (
              <Chip
                key={s}
                label={`${s} (${count})`}
                onClick={isEmpty ? undefined : () => setGateStatus(isSelected ? 'ALL' : s)}
                color={isSelected ? STATUS_CHIP_COLOR[s] : 'default'}
                variant={isSelected ? 'filled' : 'outlined'}
                disabled={isEmpty}
                size="small"
                aria-label={`${s}, ${count} gate${count !== 1 ? 's' : ''}`}
                sx={{
                  fontWeight: isSelected ? 600 : 500,
                  fontSize: 12,
                  fontVariantNumeric: 'tabular-nums',
                  cursor: isEmpty ? 'default' : 'pointer',
                }}
              />
            );
          })}
        </Stack>

        {/* Clear all filters - always rendered for layout stability, hidden when inactive */}
        <Button
          size="small"
          startIcon={<FilterAltOffIcon sx={{ fontSize: '14px !important' }} />}
          onClick={() => { setGateQuery(''); setGateStatus('ALL'); }}
          disabled={!hasActiveFilters}
          aria-label="Clear all filters"
          sx={{
            textTransform: 'none',
            fontSize: 11,
            minWidth: 'auto',
            px: 1,
            visibility: hasActiveFilters ? 'visible' : 'hidden',
          }}
        >
          Clear
        </Button>

        <Box sx={{ flex: 1 }} />

        <Divider orientation="vertical" flexItem sx={{ display: { xs: 'none', sm: 'block' } }} />

        {/* Right: gate count + auto-refresh toggle */}
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="caption" color="text.disabled" sx={{ fontVariantNumeric: 'tabular-nums', fontSize: 11, whiteSpace: 'nowrap' }}>
            {filteredCount === totalCount
              ? `${totalCount} gate${totalCount !== 1 ? 's' : ''}`
              : `${filteredCount} of ${totalCount}`
            }
          </Typography>
          <Tooltip title={autoRefresh ? 'Disable auto-refresh' : 'Enable 30s auto-refresh'}>
            <Stack direction="row" spacing={0.5} alignItems="center">
              <Switch
                size="small"
                checked={autoRefresh}
                onChange={() => setAutoRefresh((v: boolean) => !v)}
                aria-label={`Auto refresh ${autoRefresh ? 'on' : 'off'}`}
              />
              <Typography
                variant="caption"
                onClick={() => setAutoRefresh((v: boolean) => !v)}
                sx={{
                  fontSize: 11,
                  color: autoRefresh ? 'success.main' : 'text.disabled',
                  fontWeight: 500,
                  userSelect: 'none',
                  cursor: 'pointer',
                }}
              >
                30s
              </Typography>
            </Stack>
          </Tooltip>
        </Stack>
      </Stack>
    </Paper>
  );
}
