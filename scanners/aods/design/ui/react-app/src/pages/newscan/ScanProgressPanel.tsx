import { useRef, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Accordion, AccordionDetails, AccordionSummary,
  Box, Button, Card, CardContent, Chip, Collapse, IconButton,
  Stack, Tooltip, Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import DescriptionIcon from '@mui/icons-material/Description';
import TerminalIcon from '@mui/icons-material/Terminal';
import { secureFetch } from '../../lib/api';

export type StageEntry = { stage: string; pct: number; timestamp: number };

interface ScanProgressPanelProps {
  status: string | null;
  sessionId: string | null;
  effOpts: { applied?: any; ignored?: any } | null;
  latestReport: { name: string; path: string } | null;
  logLines: string[];
  showLogs: boolean;
  setShowLogs: (v: boolean) => void;
  cliPreview: string;
  onCopyCliPreview: () => void;
  stageHistory?: StageEntry[];
  progressPct?: number;
}

export function ScanProgressPanel({
  status, sessionId, effOpts, latestReport, logLines,
  showLogs, setShowLogs, cliPreview, onCopyCliPreview,
  stageHistory = [], progressPct = 0,
}: ScanProgressPanelProps) {
  const logsBoxRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll logs when new lines arrive
  useEffect(() => {
    try {
      const el = logsBoxRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    } catch { /* ignore */ }
  }, [logLines]);

  const elapsedSec = useMemo(() => {
    if (stageHistory.length === 0) return 0;
    return Math.round((Date.now() - stageHistory[0].timestamp) / 1000);
  }, [stageHistory, logLines]); // logLines as proxy for re-render on tick

  const visible = Boolean(effOpts || latestReport || logLines.length > 0 || sessionId);
  if (!visible) return null;

  const isActive = (s: string) => ['completed', 'failed', 'cancelled'].indexOf(s) === -1;

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack spacing={2}>
          {/* Stage Timeline */}
          {stageHistory.length > 0 && (
            <Box data-testid="stage-timeline">
              <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mb: 0.5 }} flexWrap="wrap" useFlexGap>
                <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>Stages:</Typography>
                {stageHistory.map((entry, i) => {
                  const isLast = i === stageHistory.length - 1;
                  const isCurrent = isLast && isActive(entry.stage);
                  const duration = !isLast && stageHistory[i + 1]
                    ? ((stageHistory[i + 1].timestamp - entry.timestamp) / 1000).toFixed(1) + 's'
                    : null;
                  return (
                    <Chip
                      key={i}
                      label={
                        <span>
                          {entry.stage}
                          {duration && <span style={{ marginLeft: 4, opacity: 0.7 }}>({duration})</span>}
                          {isCurrent && <span style={{ marginLeft: 4 }}>{progressPct}%</span>}
                        </span>
                      }
                      size="small"
                      color={isCurrent ? 'primary' : !isLast ? 'success' : 'default'}
                      variant={isCurrent ? 'filled' : 'outlined'}
                      data-testid="stage-chip"
                    />
                  );
                })}
              </Stack>
              {elapsedSec > 0 && (
                <Typography variant="caption" color="text.secondary" data-testid="elapsed-time">
                  Elapsed: {elapsedSec}s
                </Typography>
              )}
            </Box>
          )}

          {/* Latest Report */}
          {String(status || '').toLowerCase() === 'completed' && latestReport && (
            <Box sx={{ p: 1.5, bgcolor: 'success.light', borderRadius: 1, color: 'success.contrastText' }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <DescriptionIcon />
                <Typography variant="subtitle2">Latest Report: {latestReport.name}</Typography>
                <Button size="small" variant="contained" color="success" component={Link} to="/reports">View Reports</Button>
                <Button size="small" variant="outlined" sx={{ bgcolor: 'background.paper', '&:hover': { bgcolor: 'background.default' } }} onClick={async () => {
                  try {
                    const r = await secureFetch(`/reports/read?path=${encodeURIComponent(latestReport.path)}`);
                    if (!r.ok) return;
                    const j = await r.json();
                    const blob = new Blob([j?.content || ''], { type: j?.contentType || 'application/json' });
                    const url = URL.createObjectURL(blob);
                    window.open(url, '_blank');
                    setTimeout(() => URL.revokeObjectURL(url), 15000);
                  } catch { /* ignore */ }
                }}>Open JSON</Button>
              </Stack>
            </Box>
          )}

          {/* Applied Options Chips */}
          {effOpts?.applied && (
            <Box>
              <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>Applied Options:</Typography>
              <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
                {(() => {
                  const a = effOpts.applied as any;
                  const chips: { k: string; v: any }[] = [];
                  const push = (k: string) => { if (a[k] !== undefined) chips.push({ k, v: a[k] }); };
                  ['profile', 'mode', 'formats', 'staticOnly', 'maxWorkers', 'ciMode', 'failOnCritical', 'failOnHigh', 'frameworks', 'compliance', 'progressiveAnalysis', 'sampleRate', 'dedupStrategy'].forEach(push);
                  return chips.map(({ k, v }) => (
                    <Chip key={k} size="small" color="primary" variant="outlined" label={`${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`} />
                  ));
                })()}
              </Stack>
            </Box>
          )}

          {/* Effective Options Details */}
          {effOpts && (
            <Accordion defaultExpanded={false} disableGutters variant="outlined" sx={{ bgcolor: 'action.hover' }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="caption">Effective Options Details</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack direction="row" spacing={3} alignItems="flex-start">
                  <Box sx={{ minWidth: 200 }}>
                    <Typography variant="caption" color="text.secondary">Applied</Typography>
                    <Box component="pre" sx={{ m: 0, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', color: 'text.primary' }}>{JSON.stringify(effOpts.applied || {}, null, 2)}</Box>
                  </Box>
                  <Box sx={{ minWidth: 200 }}>
                    <Typography variant="caption" color="text.secondary">Ignored</Typography>
                    <Box component="pre" sx={{ m: 0, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', color: 'text.primary' }}>{JSON.stringify(effOpts.ignored || {}, null, 2)}</Box>
                  </Box>
                </Stack>
              </AccordionDetails>
            </Accordion>
          )}

          {/* CLI Preview - always shown when panel is visible */}
          <Accordion defaultExpanded={false} disableGutters variant="outlined" sx={{ bgcolor: 'action.hover' }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Stack direction="row" spacing={1} alignItems="center">
                <TerminalIcon fontSize="small" />
                <Typography variant="caption">CLI Preview</Typography>
              </Stack>
            </AccordionSummary>
            <AccordionDetails>
              <Stack direction="row" spacing={1} alignItems="center">
                <Box id="aods-scan-cli-preview" component="pre" sx={{ flex: 1, m: 0, p: 1, borderRadius: 1, bgcolor: 'background.default', fontFamily: 'monospace', fontSize: 11, overflow: 'auto', border: 1, borderColor: 'divider', color: 'text.primary' }}>
                  {cliPreview}
                </Box>
                <Tooltip title="Copy CLI">
                  <IconButton size="small" onClick={onCopyCliPreview} aria-label="Copy CLI preview">
                    <ContentCopyIcon fontSize="inherit" />
                  </IconButton>
                </Tooltip>
              </Stack>
            </AccordionDetails>
          </Accordion>

          {/* Collapsible Logs */}
          {sessionId && (
            <Box>
              <Button
                onClick={() => setShowLogs(!showLogs)}
                startIcon={<TerminalIcon />}
                endIcon={<ExpandMoreIcon sx={{ transform: showLogs ? 'rotate(180deg)' : 'rotate(0deg)', transition: '0.2s' }} />}
                size="small"
                variant="text"
              >
                {showLogs ? 'Hide Logs' : 'Show Logs'} ({logLines.length} lines)
              </Button>
              <Collapse in={showLogs}>
                <Box
                  ref={logsBoxRef}
                  sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1, maxHeight: 260, overflow: 'auto', fontFamily: 'monospace', fontSize: 11, bgcolor: 'common.black', color: 'common.white', mt: 1 }}
                  aria-label="Scan Logs"
                  id="aods-scan-logs"
                >
                  {logLines.length === 0 ? (
                    <Typography variant="caption" color="text.secondary">Waiting for logs...</Typography>
                  ) : (
                    logLines.map((ln, i) => {
                      const isError = ln.startsWith('[ERROR]');
                      const isWarn = ln.startsWith('[WARN]');
                      return (
                        <div
                          key={i}
                          data-log-level={isError ? 'error' : isWarn ? 'warn' : 'info'}
                          style={{
                            color: isError ? '#f44336' : isWarn ? '#ff9800' : undefined,
                            fontWeight: isError ? 600 : undefined,
                          }}
                        >{ln}</div>
                      );
                    })
                  )}
                </Box>
              </Collapse>
            </Box>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}
