import { Alert, Box, Button, Chip, Paper, Stack, Typography } from '@mui/material';
import SearchOffIcon from '@mui/icons-material/SearchOff';
import FilterAltOffIcon from '@mui/icons-material/FilterAltOff';
import { GateCard, GateItem } from '../../components/GateCard';

const STATUS_CHIP_COLOR: Record<string, 'success' | 'warning' | 'error'> = {
  PASS: 'success', WARN: 'warning', FAIL: 'error',
};

export interface GateListProps {
  /** Pre-filtered and sorted items from the parent. */
  items: GateItem[];
  /** Total number of items before any filtering. */
  totalCount: number;
  /** Whether any filter is currently active. */
  hasActiveFilters: boolean;
  /** Current text query (for display in empty state). */
  gateQuery: string;
  /** Current status filter (for display in empty state). */
  gateStatus: string;
  /** Callback to clear all filters. */
  onClearFilters: () => void;
  pluginAudit: boolean;
  unknownFieldsReport: boolean;
  severityReport: boolean;
  severitySummary: any | null;
}

export function GateList({
  items,
  totalCount,
  hasActiveFilters,
  gateQuery,
  gateStatus,
  onClearFilters,
  pluginAudit,
  unknownFieldsReport,
  severityReport,
  severitySummary,
}: GateListProps) {
  const hasReports = pluginAudit || unknownFieldsReport || severityReport;

  return (
    <>
      {/* Auxiliary reports */}
      {hasReports && (
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase', color: 'text.disabled', mr: 0.5 }}>
              Reports
            </Typography>
            {pluginAudit && (
              <Button size="small" variant="outlined" href={`#/artifacts?cat=plugin_audit&path=${encodeURIComponent('index.html')}`} sx={{ textTransform: 'none', fontSize: 12 }}>
                Plugin Audit
              </Button>
            )}
            {unknownFieldsReport && (
              <Button size="small" variant="outlined" href={`#/artifacts?cat=ci_gates&path=${encodeURIComponent('unknown_fields/summary.json')}`} sx={{ textTransform: 'none', fontSize: 12 }}>
                Unknown Fields
              </Button>
            )}
            {severityReport && (
              <Button size="small" variant="outlined" href={`#/artifacts?cat=ci_gates&path=${encodeURIComponent('severity/summary.json')}`} sx={{ textTransform: 'none', fontSize: 12 }}>
                Severity Gate
              </Button>
            )}
          </Stack>
          {severityReport && severitySummary && (
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
              <Chip
                size="small"
                label={String(severitySummary.status || 'UNKNOWN').toUpperCase()}
                color={String(severitySummary.status).toUpperCase() === 'PASS' ? 'success' : String(severitySummary.status).toUpperCase() === 'FAIL' ? 'error' : 'warning'}
                sx={{ height: 22, fontSize: 11, fontWeight: 600 }}
              />
              {severitySummary.details && (
                <Typography variant="caption" color="text.secondary" sx={{ fontSize: 11, fontVariantNumeric: 'tabular-nums' }}>
                  High: {severitySummary.details.high ?? 0}
                  {typeof severitySummary.details.max_high !== 'undefined' && ` / max ${severitySummary.details.max_high}`}
                  {' · '}Critical: {severitySummary.details.critical ?? 0}
                  {typeof severitySummary.details.max_critical !== 'undefined' && ` / max ${severitySummary.details.max_critical}`}
                </Typography>
              )}
            </Stack>
          )}
        </Paper>
      )}

      {/* Active filter indicator - stays visible as user scrolls past filter bar */}
      {hasActiveFilters && items.length > 0 && (
        <Stack direction="row" spacing={0.75} alignItems="center" sx={{ px: 0.5 }}>
          <Typography variant="caption" color="text.disabled" sx={{ fontSize: 11 }}>
            Filtered:
          </Typography>
          {gateQuery && (
            <Chip
              size="small"
              variant="outlined"
              label={`"${gateQuery}"`}
              onDelete={undefined}
              sx={{ height: 20, fontSize: 10, maxWidth: 180 }}
            />
          )}
          {gateStatus !== 'ALL' && (
            <Chip
              size="small"
              variant="outlined"
              color={STATUS_CHIP_COLOR[gateStatus] ?? 'default'}
              label={gateStatus}
              sx={{ height: 20, fontSize: 10, fontWeight: 600 }}
            />
          )}
          <Typography variant="caption" color="text.disabled" sx={{ fontSize: 11, fontVariantNumeric: 'tabular-nums' }}>
            {items.length} result{items.length !== 1 ? 's' : ''}
          </Typography>
        </Stack>
      )}

      {/* Gate list */}
      <Stack spacing={1}>
        {items.map((g) => (
          <GateCard key={g.name} gate={g} />
        ))}

        {/* No gates at all */}
        {totalCount === 0 && (
          <Alert severity="info" sx={{ mt: 1 }}>
            No gate artifacts found. Gate summaries are generated by CI pipelines and stored in <Box component="code" sx={{ fontSize: 'inherit' }}>artifacts/ci_gates/</Box>.
            Run <Box component="code" sx={{ fontSize: 'inherit' }}>make local-gates</Box> or a CI workflow to generate gate artifacts.
          </Alert>
        )}

        {/* No matches for current filter */}
        {totalCount > 0 && items.length === 0 && (
          <Paper variant="outlined" sx={{ py: 5, px: 3, textAlign: 'center' }}>
            <SearchOffIcon sx={{ fontSize: 40, color: 'text.disabled', mb: 1.5 }} />
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontWeight: 500 }}>
              No gates match your filter
            </Typography>
            <Stack direction="row" spacing={0.75} justifyContent="center" alignItems="center" sx={{ mb: 2 }}>
              {gateQuery && (
                <Chip size="small" variant="outlined" label={`Name: "${gateQuery}"`} sx={{ height: 22, fontSize: 11 }} />
              )}
              {gateStatus !== 'ALL' && (
                <Chip
                  size="small"
                  variant="outlined"
                  color={STATUS_CHIP_COLOR[gateStatus] ?? 'default'}
                  label={`Status: ${gateStatus}`}
                  sx={{ height: 22, fontSize: 11, fontWeight: 600 }}
                />
              )}
            </Stack>
            {hasActiveFilters && (
              <Button
                size="small"
                variant="outlined"
                startIcon={<FilterAltOffIcon sx={{ fontSize: '14px !important' }} />}
                onClick={onClearFilters}
                sx={{ textTransform: 'none', fontSize: 12 }}
              >
                Clear filters
              </Button>
            )}
          </Paper>
        )}
      </Stack>
    </>
  );
}
