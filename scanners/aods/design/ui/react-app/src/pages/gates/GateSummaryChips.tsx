import { Box, Button, Chip, Divider, IconButton, Paper, Stack, Tooltip, Typography } from '@mui/material';
import { Link } from 'react-router-dom';
import InfoOutlined from '@mui/icons-material/InfoOutlined';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ScienceOutlinedIcon from '@mui/icons-material/ScienceOutlined';
import MonitorHeartOutlinedIcon from '@mui/icons-material/MonitorHeartOutlined';
import SpeedOutlinedIcon from '@mui/icons-material/SpeedOutlined';
import PlaylistAddCheckIcon from '@mui/icons-material/PlaylistAddCheck';

export interface GateSummaryChipsProps {
  totals: { PASS?: number; WARN?: number; FAIL?: number };
  gatesDelta: { WARN?: number; FAIL?: number } | null;
  calibMeta: { family?: string; artifact?: string } | null;
  datasetVintage: { mtime?: string; size?: number } | null;
  accuracySummaryPath: string | null;
  accuracyStrict: boolean;
  uiPerf: { render?: number; jankP95?: number; heapMb?: number; domNodes?: number; toggleAvgMs?: number } | null;
  mlDrift: { chi2?: number; nBaseline?: number; nCurrent?: number } | null;
  baselineStale: any | null;
  calibStale: any | null;
  mlStamps: any | null;
  promotion: any | null;
  curationCounts: any | null;
}

const STATUS_COLORS: Record<string, 'success' | 'warning' | 'error'> = { PASS: 'success', WARN: 'warning', FAIL: 'error' };

function SectionLabel({ children, icon: Icon }: { children: React.ReactNode; icon?: React.ElementType }) {
  return (
    <Stack direction="row" spacing={0.75} alignItems="center">
      {Icon && <Icon sx={{ fontSize: 14, color: 'text.disabled' }} />}
      <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase', color: 'text.disabled', whiteSpace: 'nowrap' }}>
        {children}
      </Typography>
    </Stack>
  );
}

function StaleChip({ label, status, strict }: { label: string; status: string; strict?: boolean }) {
  const upper = String(status).toUpperCase();
  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      <Chip
        size="small"
        aria-label={`${label} ${upper}`}
        color={upper === 'FAIL' ? 'warning' : 'success'}
        variant="outlined"
        label={`${label} ${upper}`}
        sx={{ height: 22, fontSize: 11 }}
      />
      {strict && (
        <Chip size="small" aria-label={`Strict ${label}`} color="info" variant="outlined" label="Strict" sx={{ height: 20, fontSize: 10 }} />
      )}
    </Stack>
  );
}

export function GateSummaryChips({
  totals,
  gatesDelta,
  calibMeta,
  datasetVintage,
  accuracySummaryPath,
  accuracyStrict,
  uiPerf,
  mlDrift,
  baselineStale,
  calibStale,
  mlStamps,
  promotion,
  curationCounts,
}: GateSummaryChipsProps) {
  const pass = totals.PASS || 0;
  const warn = totals.WARN || 0;
  const fail = totals.FAIL || 0;
  const total = pass + warn + fail;
  const passRate = total > 0 ? Math.round((pass / total) * 100) : 0;

  const hasMlSection = !!(calibMeta?.family || calibMeta?.artifact || datasetVintage?.mtime || accuracySummaryPath || mlDrift || mlStamps?.status);
  const hasHealthSection = !!(baselineStale?.status || calibStale?.status || (Array.isArray(promotion?.suggestions) && promotion.suggestions.length > 0));

  return (
    <Stack spacing={2}>
      {/* ---- Gate Totals ---- */}
      <Paper variant="outlined" sx={{ p: 2, overflow: 'hidden' }}>
        <Stack direction="row" spacing={3} alignItems="center" flexWrap="wrap" useFlexGap>
          {/* Pass/Warn/Fail counters */}
          {([['PASS', pass, CheckCircleOutlineIcon], ['WARN', warn, WarningAmberIcon], ['FAIL', fail, ErrorOutlineIcon]] as const).map(([label, count, Icon]) => (
            <Stack key={label} direction="row" spacing={0.75} alignItems="center">
              <Icon sx={{ fontSize: 20, color: `${STATUS_COLORS[label]}.main` }} />
              <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1, fontVariantNumeric: 'tabular-nums', fontSize: 24 }}>
                {count}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500, fontSize: 12 }}>
                {label}
              </Typography>
            </Stack>
          ))}

          {/* Pass rate */}
          {total > 0 && (
            <>
              <Divider orientation="vertical" flexItem />
              <Tooltip title={`${pass} of ${total} gates passing`}>
                <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums', color: passRate === 100 ? 'success.main' : passRate >= 80 ? 'text.primary' : 'error.main' }}>
                  {passRate}% pass rate
                </Typography>
              </Tooltip>
            </>
          )}

          {/* Deltas */}
          {gatesDelta && (
            <>
              <Divider orientation="vertical" flexItem />
              <Stack direction="row" spacing={0.5} alignItems="center">
                <TrendingUpIcon sx={{ fontSize: 14, color: 'text.disabled' }} />
                {typeof gatesDelta.WARN === 'number' && gatesDelta.WARN > 0 && (
                  <Chip size="small" color="warning" variant="outlined" label={`+${gatesDelta.WARN} WARN`} sx={{ height: 22, fontSize: 11, fontWeight: 600 }} />
                )}
                {typeof gatesDelta.FAIL === 'number' && gatesDelta.FAIL > 0 && (
                  <Chip size="small" color="error" variant="outlined" label={`+${gatesDelta.FAIL} FAIL`} sx={{ height: 22, fontSize: 11, fontWeight: 600 }} />
                )}
              </Stack>
            </>
          )}

          <Box sx={{ flex: 1 }} />

          {/* Legend */}
          <Tooltip
            arrow
            title={
              <Box sx={{ p: 0.5 }}>
                <Typography variant="caption" component="div">PASS/WARN/FAIL: gate execution totals</Typography>
                <Typography variant="caption" component="div">+WARN/+FAIL: delta since last load</Typography>
                <Typography variant="caption" component="div">ML section: calibration, drift, version stamps</Typography>
                <Typography variant="caption" component="div">Health: baseline & calibration staleness</Typography>
              </Box>
            }
          >
            <IconButton size="small" aria-label="Gates chips legend">
              <InfoOutlined sx={{ fontSize: 16 }} />
            </IconButton>
          </Tooltip>
        </Stack>

        {/* Segmented pass/warn/fail bar */}
        {total > 0 && (
          <Tooltip title={`${pass} pass · ${warn} warn · ${fail} fail`}>
            <Box sx={{ mt: 1.5, display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', bgcolor: 'action.hover' }}>
              {pass > 0 && (
                <Box sx={{ width: `${(pass / total) * 100}%`, bgcolor: 'success.main', transition: 'width 0.4s ease' }} />
              )}
              {warn > 0 && (
                <Box sx={{ width: `${(warn / total) * 100}%`, bgcolor: 'warning.main', transition: 'width 0.4s ease' }} />
              )}
              {fail > 0 && (
                <Box sx={{ width: `${(fail / total) * 100}%`, bgcolor: 'error.main', transition: 'width 0.4s ease' }} />
              )}
            </Box>
          </Tooltip>
        )}
      </Paper>

      {/* ---- ML & Accuracy Section ---- */}
      {hasMlSection && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            <SectionLabel icon={ScienceOutlinedIcon}>ML &amp; Accuracy</SectionLabel>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              {calibMeta?.family && (
                <Chip size="small" label={`Calib: ${calibMeta.family}`} sx={{ height: 22, fontSize: 11 }} />
              )}
              {calibMeta?.artifact && (
                <Tooltip title={String(calibMeta.artifact)} arrow>
                  <Chip size="small" label={`Artifact: ${String(calibMeta.artifact).split('/').slice(-2).join('/')}`} sx={{ height: 22, fontSize: 11 }} />
                </Tooltip>
              )}
              {datasetVintage?.mtime && (
                <Tooltip title={`Dataset timestamp: ${datasetVintage.mtime}`} arrow>
                  <Chip
                    size="small"
                    aria-label={`Detection dataset generated at ${new Date(datasetVintage.mtime).toISOString()}`}
                    label={`Dataset: ${new Date(datasetVintage.mtime).toISOString().slice(0, 10)}`}
                    sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                  />
                </Tooltip>
              )}
              {typeof datasetVintage?.size === 'number' && (
                <Tooltip title={`Raw size: ${datasetVintage.size.toLocaleString()} bytes`} arrow>
                  <Chip
                    size="small"
                    aria-label={`Detection dataset size ${datasetVintage.size} bytes`}
                    label={`${(datasetVintage.size / 1024 / 1024).toFixed(1)} MB`}
                    sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                  />
                </Tooltip>
              )}
              {accuracyStrict && (
                <Chip size="small" aria-label="Strict Accuracy" color="info" variant="outlined" label="Strict" sx={{ height: 20, fontSize: 10 }} />
              )}
              {accuracySummaryPath && (
                <Button
                  size="small"
                  variant="text"
                  component={Link}
                  to={`/artifacts?cat=ci_gates&path=${encodeURIComponent(accuracySummaryPath)}`}
                  aria-label="Open Detection Accuracy summary"
                  endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                  sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
                >
                  Accuracy Summary
                </Button>
              )}

              {/* ML Drift */}
              {mlDrift && typeof mlDrift.chi2 === 'number' && (
                <>
                  <Divider orientation="vertical" flexItem />
                  <Tooltip title="ML Drift Chi-square (bins=10)" arrow>
                    <Chip
                      size="small"
                      label={`Drift \u03C7\u00B2 ${mlDrift.chi2.toFixed(2)}`}
                      aria-label={`ML drift chi-square ${mlDrift.chi2.toFixed(2)}`}
                      color={mlDrift.chi2 > 20 ? 'error' : mlDrift.chi2 > 10 ? 'warning' : 'default'}
                      variant="outlined"
                      sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                    />
                  </Tooltip>
                  <Tooltip title="Sample sizes (baseline / current)" arrow>
                    <Chip
                      size="small"
                      label={`N ${mlDrift.nBaseline}/${mlDrift.nCurrent}`}
                      aria-label={`ML drift sample sizes baseline ${mlDrift.nBaseline} current ${mlDrift.nCurrent}`}
                      sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                    />
                  </Tooltip>
                  <Button
                    size="small"
                    variant="text"
                    component={Link}
                    to={`/artifacts?cat=ml_datasets/metrics&path=${encodeURIComponent('dashboard.html')}`}
                    aria-label="Open ML Metrics dashboard"
                    endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                    sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
                  >
                    ML Dashboard
                  </Button>
                </>
              )}

              {/* ML Stamps */}
              {mlStamps?.status && (
                <>
                  <Divider orientation="vertical" flexItem />
                  <Chip
                    size="small"
                    aria-label={`ML Stamps ${String(mlStamps.status).toUpperCase()}`}
                    color={String(mlStamps.status).toUpperCase() === 'FAIL' ? 'warning' : 'success'}
                    variant="outlined"
                    label={`ML Stamps ${String(mlStamps.status).toUpperCase()}`}
                    sx={{ height: 22, fontSize: 11 }}
                  />
                  {mlStamps.strict === true && (
                    <Chip size="small" aria-label="Strict ML Stamps" color="info" variant="outlined" label="Strict: ML" sx={{ height: 20, fontSize: 10 }} />
                  )}
                </>
              )}
            </Stack>
          </Stack>
        </Paper>
      )}

      {/* ---- Health & Staleness Section ---- */}
      {hasHealthSection && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            <SectionLabel icon={MonitorHeartOutlinedIcon}>Health &amp; Staleness</SectionLabel>
            <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
              {baselineStale?.status && (
                <>
                  <Tooltip title={`Baseline staleness: age ${baselineStale.age_days?.toFixed ? baselineStale.age_days.toFixed(1) : baselineStale.age_days} days (ttl ${baselineStale.ttl_days})`} arrow>
                    <Box><StaleChip label="Baseline" status={baselineStale.status} strict={baselineStale.strict === true} /></Box>
                  </Tooltip>
                  {baselineStale.latest && (
                    <Button
                      size="small"
                      variant="text"
                      component={Link}
                      to={`/artifacts?cat=ci_gates&path=${encodeURIComponent('baseline_staleness/summary.json')}`}
                      aria-label="Open Baseline Staleness summary"
                      endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                      sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
                    >
                      Baseline Details
                    </Button>
                  )}
                </>
              )}

              {calibStale?.status && (
                <>
                  {baselineStale?.status && <Divider orientation="vertical" flexItem />}
                  <Tooltip title={`Calibration staleness: age ${calibStale.age_days?.toFixed ? calibStale.age_days.toFixed(1) : calibStale.age_days} days (ttl ${calibStale.ttl_days})`} arrow>
                    <Box><StaleChip label="Calibration" status={calibStale.status} strict={calibStale.strict === true} /></Box>
                  </Tooltip>
                  {calibStale.summary && (
                    <Button
                      size="small"
                      variant="text"
                      component={Link}
                      to={`/artifacts?cat=ci_gates&path=${encodeURIComponent('calibration_staleness/summary.json')}`}
                      aria-label="Open Calibration Staleness summary"
                      endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                      sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
                    >
                      Calibration Details
                    </Button>
                  )}
                </>
              )}

              {Array.isArray(promotion?.suggestions) && promotion.suggestions.length > 0 && (
                <>
                  {(baselineStale?.status || calibStale?.status) && <Divider orientation="vertical" flexItem />}
                  <Tooltip title={`${promotion.suggestions.length} promotion suggestion(s)`} arrow>
                    <Chip
                      size="small"
                      aria-label={`Promotion ${promotion.suggestions.length}`}
                      color="info"
                      variant="outlined"
                      label={`${promotion.suggestions.length} Promotion${promotion.suggestions.length !== 1 ? 's' : ''}`}
                      sx={{ height: 22, fontSize: 11 }}
                    />
                  </Tooltip>
                  <Button
                    size="small"
                    variant="text"
                    component={Link}
                    to={`/artifacts?cat=ci_gates&path=${encodeURIComponent('promotion_suggester/summary.json')}`}
                    aria-label="Open Promotion Suggester summary"
                    endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                    sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
                  >
                    Promotion Details
                  </Button>
                </>
              )}
            </Stack>
          </Stack>
        </Paper>
      )}

      {/* ---- UI Performance Section ---- */}
      {uiPerf && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            <SectionLabel icon={SpeedOutlinedIcon}>UI Performance</SectionLabel>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              {([
                ['Render', uiPerf.render, 'ms', `UI render time ${typeof uiPerf.render === 'number' ? uiPerf.render : 'unknown'} milliseconds`],
                ['Jank p95', uiPerf.jankP95, 'ms', `Frame jank p95 ${typeof uiPerf.jankP95 === 'number' ? uiPerf.jankP95 : 'unknown'} milliseconds`],
                ['Heap', uiPerf.heapMb, 'MB', `Heap used ${typeof uiPerf.heapMb === 'number' ? uiPerf.heapMb : 'unknown'} megabytes`],
                ['DOM', uiPerf.domNodes, '', `DOM nodes count ${typeof uiPerf.domNodes === 'number' ? uiPerf.domNodes : 'unknown'}`],
              ] as const).map(([label, value, unit, ariaLabel]) => (
                <Tooltip key={label} title={ariaLabel} arrow>
                  <Chip
                    size="small"
                    label={`${label}: ${value ?? '\u2013'} ${unit}`.trim()}
                    aria-label={ariaLabel}
                    sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                  />
                </Tooltip>
              ))}
              {typeof uiPerf.toggleAvgMs === 'number' && (
                <Tooltip title={`Toggle action avg render: ${uiPerf.toggleAvgMs} ms`} arrow>
                  <Chip
                    size="small"
                    label={`Toggle: ${uiPerf.toggleAvgMs} ms`}
                    aria-label={`UI memoization toggle average ${uiPerf.toggleAvgMs} milliseconds`}
                    sx={{ height: 22, fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                  />
                </Tooltip>
              )}
              <Button
                size="small"
                variant="text"
                component={Link}
                to={`/artifacts?cat=ui_perf&path=${encodeURIComponent('perf_metrics.json')}`}
                aria-label="Open UI Perf metrics JSON"
                endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
              >
                UI Perf JSON
              </Button>
            </Stack>
          </Stack>
        </Paper>
      )}

      {/* ---- Curation Queue ---- */}
      {curationCounts && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            <SectionLabel icon={PlaylistAddCheckIcon}>Curation Queue</SectionLabel>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Chip size="small" label={`Missing in AODS: ${curationCounts.missing_in_aods ?? 0}`} color="warning" sx={{ height: 22, fontSize: 11 }} />
              <Chip size="small" label={`Missing in External: ${curationCounts.missing_in_external ?? 0}`} sx={{ height: 22, fontSize: 11 }} />
              <Chip size="small" label={`Severity Mismatch: ${curationCounts.severity_mismatch ?? 0}`} color="secondary" sx={{ height: 22, fontSize: 11 }} />
              <Chip size="small" label={`Meta Mismatch: ${curationCounts.meta_mismatch ?? 0}`} color="info" sx={{ height: 22, fontSize: 11 }} />
              <Divider orientation="vertical" flexItem />
              <Chip size="small" label={`Total: ${curationCounts.total ?? 0}`} color="primary" sx={{ height: 22, fontSize: 11, fontWeight: 600 }} />
              <Button
                component={Link}
                to="/curation"
                size="small"
                variant="text"
                endIcon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                sx={{ textTransform: 'none', fontSize: 12, px: 1 }}
              >
                Open Curation
              </Button>
            </Stack>
          </Stack>
        </Paper>
      )}
    </Stack>
  );
}
