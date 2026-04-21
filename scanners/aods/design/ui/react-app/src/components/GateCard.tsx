import React, { useState } from 'react';
import { formatRelativeTime } from '../lib/format';
import { Collapse, Paper, Typography, Chip, Box, Stack, Link, Tooltip } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import TrendingFlatIcon from '@mui/icons-material/TrendingFlat';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

export type GateItem = { name: string; status: string; failures?: string[]; mtime?: string; path?: string; relPath?: string; trend?: 'up' | 'down' | 'flat' };

const STATUS_BORDER: Record<string, string> = { PASS: 'success.main', WARN: 'warning.main', FAIL: 'error.main', SKIP: 'text.disabled' };
const STATUS_COLOR: Record<string, 'success' | 'warning' | 'error' | 'default'> = {
  PASS: 'success', WARN: 'warning', FAIL: 'error',
};
const TREND_META: Record<string, { icon: React.ReactNode; label: string }> = {
  up: { icon: <TrendingUpIcon sx={{ fontSize: 14, color: 'error.main' }} />, label: 'Regressed' },
  down: { icon: <TrendingDownIcon sx={{ fontSize: 14, color: 'success.main' }} />, label: 'Improved' },
  flat: { icon: <TrendingFlatIcon sx={{ fontSize: 14, color: 'text.disabled' }} />, label: 'Stable' },
};

/** Words that should always be fully uppercased in gate names. */
const UPPER_WORDS = new Set([
  'ml', 'ci', 'fp', 'ui', 'db', 'api', 'sse', 'rbac', 'cwe', 'apk',
  'ast', 'cli', 'csv', 'dom', 'html', 'json', 'jwt', 'masvs', 'nist',
  'owasp', 'pii', 'sdk', 'shap', 'sql', 'tls', 'url', 'xml',
]);

/** Humanize a gate name: strip paths/extensions, replace separators, title-case with abbreviation handling. */
export function humanizeName(raw: string): string {
  const stripped = raw.replace(/\/summary\.json$/i, '').replace(/\.json$/i, '');
  return stripped
    .replace(/[/_-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map(w => UPPER_WORDS.has(w.toLowerCase()) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ') || raw;
}


export function GateCard({ gate }: { gate: GateItem }) {
  const status = String(gate.status || 'UNKNOWN').toUpperCase();
  const color = STATUS_COLOR[status] ?? 'default';
  const hasFailures = !!(gate.failures && gate.failures.length);
  const [expanded, setExpanded] = useState(false);

  return (
    <Paper
      variant="outlined"
      tabIndex={0}
      onKeyDown={(e) => {
        if (hasFailures && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          setExpanded(p => !p);
        }
      }}
      sx={{
        p: 1.5,
        borderLeft: 3,
        borderColor: STATUS_BORDER[status] || 'divider',
        transition: 'background-color 0.15s, box-shadow 0.15s',
        '&:hover': { bgcolor: 'action.hover' },
        '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 },
        cursor: hasFailures ? 'pointer' : 'default',
      }}
      onClick={hasFailures ? () => setExpanded(p => !p) : undefined}
    >
      <Stack direction="row" spacing={1.5} alignItems="center">
        <Chip size="small" label={status} color={color as any} sx={{ fontWeight: 600, minWidth: 52 }} />
        <Stack sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="body2" sx={{ fontWeight: 600, wordBreak: 'break-word', fontSize: 13, lineHeight: 1.3 }}>
            {humanizeName(gate.name)}
          </Typography>
          {gate.mtime && (
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10, lineHeight: 1.2 }}>
              {formatRelativeTime(gate.mtime)}
            </Typography>
          )}
        </Stack>
        {gate.trend && (
          <Stack direction="row" spacing={0.25} alignItems="center" aria-label={`trend ${gate.trend}`}>
            {TREND_META[gate.trend].icon}
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10 }}>
              {TREND_META[gate.trend].label}
            </Typography>
          </Stack>
        )}
        {gate.relPath && (
          <Link
            component={RouterLink}
            to={`/artifacts?cat=ci_gates&path=${encodeURIComponent(gate.relPath)}`}
            title="Open artifact preview"
            underline="hover"
            color="primary.main"
            variant="body2"
            onClick={(e: React.MouseEvent) => e.stopPropagation()}
            sx={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 0.25, whiteSpace: 'nowrap' }}
          >
            view <OpenInNewIcon sx={{ fontSize: 12 }} />
          </Link>
        )}
        {hasFailures && (
          <Tooltip title={expanded ? 'Collapse failures' : `${gate.failures!.length} failure${gate.failures!.length !== 1 ? 's' : ''}`}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Chip
                size="small"
                variant="outlined"
                color="error"
                label={gate.failures!.length}
                sx={{ height: 20, fontSize: 10, fontWeight: 600, minWidth: 24 }}
              />
              <ExpandMoreIcon sx={{ fontSize: 16, color: 'text.disabled', transition: 'transform 0.2s', transform: expanded ? 'rotate(180deg)' : 'none', ml: 0.25 }} />
            </Box>
          </Tooltip>
        )}
      </Stack>
      {hasFailures && (
        <Collapse in={expanded} unmountOnExit timeout={200}>
          <Box sx={{ mt: 1.5, pt: 1, borderTop: 1, borderColor: 'divider', pl: 1 }}>
            {gate.failures!.map((f, i) => (
              <Typography key={i} variant="caption" color="text.secondary" component="div" sx={{ fontSize: 11, lineHeight: 1.8, fontFamily: 'monospace' }}>
                {f}
              </Typography>
            ))}
          </Box>
        </Collapse>
      )}
    </Paper>
  );
}
