import {
  Accordion, AccordionDetails, AccordionSummary,
  Box, Button, Checkbox, Chip, Divider,
  FormControl, FormControlLabel, InputLabel, MenuItem, OutlinedInput,
  Select, Stack, Switch, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import TuneIcon from '@mui/icons-material/Tune';
import SettingsIcon from '@mui/icons-material/Settings';

interface ScanOptionsFormProps {
  scanProfile: string; setScanProfile: (v: string) => void;
  scanMode: string; setScanMode: (v: string) => void;
  outputFormats: string[]; setOutputFormats: (v: string[]) => void;
  staticOnly: boolean; setStaticOnly: (v: boolean) => void;
  ciMode: boolean; setCiMode: (v: boolean) => void;
  enableFilter: boolean; setEnableFilter: (v: boolean) => void;
  profile: string; setProfile: (v: string) => void;
  fridaMode: string; setFridaMode: (v: string) => void;
  resourceConstrained: boolean; setResourceConstrained: (v: boolean) => void;
  maxWorkers: string; setMaxWorkers: (v: string) => void;
  timeoutsProfile: string; setTimeoutsProfile: (v: string) => void;
  pluginsIncludeCSV: string; setPluginsIncludeCSV: (v: string) => void;
  pluginsExcludeCSV: string; setPluginsExcludeCSV: (v: string) => void;
  failOnCritical: boolean; setFailOnCritical: (v: boolean) => void;
  failOnHigh: boolean; setFailOnHigh: (v: boolean) => void;
  frameworks: string[]; setFrameworks: (v: string[]) => void;
  compliance: string; setCompliance: (v: string) => void;
  mlConfidence: string; setMlConfidence: (v: string) => void;
  mlModelsPath: string; setMlModelsPath: (v: string) => void;
  dedupStrategy: string; setDedupStrategy: (v: string) => void;
  dedupThreshold: string; setDedupThreshold: (v: string) => void;
  progressiveAnalysis: boolean; setProgressiveAnalysis: (v: boolean) => void;
  sampleRate: string; setSampleRate: (v: string) => void;
  agentEnabled: boolean; setAgentEnabled: (v: boolean) => void;
  agentSteps: string[]; setAgentSteps: (v: string[]) => void;
  isAdmin: boolean;
  policy: any;
  policyBusy: boolean;
  onRefreshPolicy: () => void;
  onCopyPolicy: () => void;
}

export function ScanOptionsForm(props: ScanOptionsFormProps) {
  const {
    scanProfile, setScanProfile, scanMode, setScanMode, outputFormats, setOutputFormats,
    staticOnly, setStaticOnly, ciMode, setCiMode, enableFilter, setEnableFilter,
    profile, setProfile, fridaMode, setFridaMode, resourceConstrained, setResourceConstrained,
    maxWorkers, setMaxWorkers, timeoutsProfile, setTimeoutsProfile,
    pluginsIncludeCSV, setPluginsIncludeCSV, pluginsExcludeCSV, setPluginsExcludeCSV,
    failOnCritical, setFailOnCritical, failOnHigh, setFailOnHigh,
    frameworks, setFrameworks, compliance, setCompliance,
    mlConfidence, setMlConfidence, mlModelsPath, setMlModelsPath,
    dedupStrategy, setDedupStrategy, dedupThreshold, setDedupThreshold,
    progressiveAnalysis, setProgressiveAnalysis, sampleRate, setSampleRate,
    agentEnabled, setAgentEnabled, agentSteps, setAgentSteps,
    isAdmin, policy, policyBusy, onRefreshPolicy, onCopyPolicy,
  } = props;

  return (
    <>
      {/* Scan Options Accordion */}
      <Accordion defaultExpanded={false} variant="outlined">
        <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="scan-options-content" id="scan-options-header">
          <Stack direction="row" spacing={1} alignItems="center">
            <TuneIcon color="action" />
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Scan Options</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={2}>
            {/* Row 1: Profile, Mode, Formats */}
            <Stack direction="row" spacing={2} useFlexGap sx={{ flexWrap: 'wrap' }}>
              <FormControl size="small" sx={{ minWidth: 160 }}>
                <InputLabel id="scan-profile-label">Scan Profile</InputLabel>
                <Select labelId="scan-profile-label" label="Scan Profile" value={scanProfile} onChange={(e) => setScanProfile(String(e.target.value))}>
                  <MenuItem value="lightning">lightning</MenuItem>
                  <MenuItem value="fast">fast</MenuItem>
                  <MenuItem value="standard">standard</MenuItem>
                  <MenuItem value="deep">deep</MenuItem>
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel id="scan-mode-label">Mode</InputLabel>
                <Select labelId="scan-mode-label" label="Mode" value={scanMode} onChange={(e) => setScanMode(String(e.target.value))}>
                  <MenuItem value="safe">safe</MenuItem>
                  <MenuItem value="deep">deep</MenuItem>
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 200 }}>
                <InputLabel id="formats-label">Output Formats</InputLabel>
                <Select multiple labelId="formats-label" label="Output Formats" value={outputFormats} onChange={(e) => setOutputFormats((e.target.value as string[]) || [])} renderValue={(sel) => (sel as string[]).join(', ')}>
                  {['json', 'html', 'txt', 'csv'].map(f => (
                    <MenuItem key={f} value={f}>
                      <Checkbox checked={outputFormats.indexOf(f) > -1} size="small" />
                      <Typography variant="body2">{f}</Typography>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Stack>

            {/* Row 2: Toggles */}
            <Stack direction="row" spacing={2} useFlexGap sx={{ flexWrap: 'wrap' }}>
              <FormControlLabel control={<Switch checked={staticOnly} onChange={e => { setStaticOnly(e.target.checked); if (e.target.checked) setFridaMode(''); }} size="small" />} label="Static Only" />
              <FormControlLabel control={<Switch checked={ciMode} onChange={e => setCiMode(e.target.checked)} size="small" />} label="CI Mode" />
              <FormControlLabel control={<Switch checked={enableFilter} onChange={e => setEnableFilter(e.target.checked)} size="small" />} label="ML Threshold Filter" />
            </Stack>

            {/* Profile selector */}
            <FormControl size="small" sx={{ minWidth: 160 }}>
              <InputLabel id="profile-label">Environment Profile</InputLabel>
              <Select labelId="profile-label" label="Environment Profile" value={profile} onChange={(e) => setProfile(String(e.target.value))}>
                <MenuItem value="dev">dev</MenuItem>
                <MenuItem value="staging">staging</MenuItem>
                <MenuItem value="prod">prod</MenuItem>
              </Select>
            </FormControl>

            {/* Agentic Analysis */}
            <Divider />
            <Box>
              <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 0.5 }}>
                <FormControlLabel
                  control={<Switch checked={agentEnabled} onChange={e => setAgentEnabled(e.target.checked)} size="small" />}
                  label={<Typography variant="subtitle2" color="text.secondary">Agentic Analysis</Typography>}
                />
              </Stack>
              {agentEnabled && (
                <Stack spacing={1.5} sx={{ pl: 0.5 }}>
                  <Typography variant="caption" color="text.secondary">
                    AI-powered post-scan agents: triage, verification, remediation, and narrative generation.
                  </Typography>
                  <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                    {(['triage', 'verify', 'remediate', 'narrate', 'orchestrate', 'pipeline'] as const).map(step => (
                      <Chip
                        key={step}
                        label={step.charAt(0).toUpperCase() + step.slice(1)}
                        size="small"
                        color={agentSteps.includes(step) ? 'primary' : 'default'}
                        variant={agentSteps.includes(step) ? 'filled' : 'outlined'}
                        onClick={() => {
                          setAgentSteps(
                            agentSteps.includes(step)
                              ? agentSteps.filter(s => s !== step)
                              : [...agentSteps, step],
                          );
                        }}
                      />
                    ))}
                    <Typography variant="caption" color="text.secondary" sx={{ alignSelf: 'center' }}>
                      {agentSteps.length === 0 ? '(none selected = all agents)' : `${agentSteps.length} selected`}
                    </Typography>
                  </Stack>
                </Stack>
              )}
            </Box>
          </Stack>
        </AccordionDetails>
      </Accordion>

      {/* Advanced Settings Accordion */}
      <Accordion defaultExpanded={false} variant="outlined">
        <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="advanced-settings-content" id="advanced-settings-header">
          <Stack direction="row" spacing={1} alignItems="center">
            <SettingsIcon color="action" />
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Advanced Settings</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={3}>
            {/* Resource Constraints */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Resource Constraints</Typography>
              <Stack direction="row" spacing={2} useFlexGap sx={{ flexWrap: 'wrap' }}>
                <FormControlLabel control={<Switch checked={resourceConstrained} onChange={e => setResourceConstrained(e.target.checked)} size="small" />} label="Resource Constrained" />
                <FormControl size="small" sx={{ minWidth: 140 }}>
                  <InputLabel htmlFor="aods-workers">Max Workers</InputLabel>
                  <OutlinedInput id="aods-workers" label="Max Workers" placeholder="1-64" value={maxWorkers} onChange={e => setMaxWorkers(e.target.value)} />
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel id="timeouts-label">Timeouts Profile</InputLabel>
                  <Select labelId="timeouts-label" label="Timeouts Profile" value={timeoutsProfile} onChange={(e) => setTimeoutsProfile(String(e.target.value))}>
                    <MenuItem value="">(default)</MenuItem>
                    <MenuItem value="slow">slow</MenuItem>
                    <MenuItem value="fast">fast</MenuItem>
                  </Select>
                </FormControl>
              </Stack>
            </Box>

            <Divider />

            {/* Frida Mode */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Dynamic Analysis</Typography>
              <FormControl size="small" sx={{ minWidth: 180 }}>
                <InputLabel id="frida-mode-label">Frida Mode</InputLabel>
                <Select labelId="frida-mode-label" label="Frida Mode" value={fridaMode} onChange={(e) => setFridaMode(String(e.target.value))} disabled={staticOnly}>
                  <MenuItem value="">(none)</MenuItem>
                  <MenuItem value="standard">standard</MenuItem>
                  <MenuItem value="read_only">read_only</MenuItem>
                  <MenuItem value="advanced">advanced</MenuItem>
                </Select>
              </FormControl>
            </Box>

            <Divider />

            {/* Plugin Include/Exclude */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Plugin Filters</Typography>
              <Stack direction="row" spacing={2}>
                <FormControl size="small" fullWidth>
                  <InputLabel htmlFor="aods-plugins-include">Plugins Include (CSV)</InputLabel>
                  <OutlinedInput id="aods-plugins-include" label="Plugins Include (CSV)" placeholder="plugin_a,plugin_b" value={pluginsIncludeCSV} onChange={e => setPluginsIncludeCSV(e.target.value)} />
                </FormControl>
                <FormControl size="small" fullWidth>
                  <InputLabel htmlFor="aods-plugins-exclude">Plugins Exclude (CSV)</InputLabel>
                  <OutlinedInput id="aods-plugins-exclude" label="Plugins Exclude (CSV)" placeholder="plugin_x,plugin_y" value={pluginsExcludeCSV} onChange={e => setPluginsExcludeCSV(e.target.value)} />
                </FormControl>
              </Stack>
            </Box>

            <Divider />

            {/* Frameworks & Compliance */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Frameworks & Compliance</Typography>
              <Stack direction="row" spacing={2}>
                <FormControl size="small" sx={{ minWidth: 220 }}>
                  <InputLabel id="frameworks-label">Frameworks</InputLabel>
                  <Select multiple labelId="frameworks-label" label="Frameworks" value={frameworks} onChange={(e) => {
                    const vals = (e.target.value as string[]) || [];
                    if (vals.includes('all')) {
                      setFrameworks(['flutter', 'react_native', 'xamarin', 'pwa', 'all']);
                    } else {
                      setFrameworks(vals);
                    }
                  }} renderValue={(sel) => (sel as string[]).join(', ')}>
                    {['flutter', 'react_native', 'xamarin', 'pwa', 'all'].map(f => (
                      <MenuItem key={f} value={f}>
                        <Checkbox checked={frameworks.indexOf(f) > -1} size="small" />
                        <Typography variant="body2">{f}</Typography>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel id="compliance-label">Compliance</InputLabel>
                  <Select labelId="compliance-label" label="Compliance" value={compliance} onChange={(e) => setCompliance(String(e.target.value))}>
                    <MenuItem value="">(none)</MenuItem>
                    <MenuItem value="all">all</MenuItem>
                    <MenuItem value="nist">nist</MenuItem>
                    <MenuItem value="masvs">masvs</MenuItem>
                    <MenuItem value="owasp">owasp</MenuItem>
                    <MenuItem value="iso27001">iso27001</MenuItem>
                  </Select>
                </FormControl>
              </Stack>
            </Box>

            <Divider />

            {/* CI Mode Options */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>CI/CD Options</Typography>
              <Stack direction="row" spacing={2}>
                <FormControlLabel control={<Switch checked={failOnCritical} onChange={e => setFailOnCritical(e.target.checked)} size="small" />} label="Fail on Critical" />
                <FormControlLabel control={<Switch checked={failOnHigh} onChange={e => setFailOnHigh(e.target.checked)} size="small" />} label="Fail on High" />
              </Stack>
            </Box>

            <Divider />

            {/* ML Settings */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>ML Settings</Typography>
              <Stack direction="row" spacing={2}>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel htmlFor="aods-mlconf">ML Confidence</InputLabel>
                  <OutlinedInput id="aods-mlconf" label="ML Confidence" placeholder="0.0-1.0" value={mlConfidence} onChange={e => setMlConfidence(e.target.value)} />
                </FormControl>
                <FormControl size="small" fullWidth>
                  <InputLabel htmlFor="aods-mlmodels">ML Models Path</InputLabel>
                  <OutlinedInput id="aods-mlmodels" label="ML Models Path" placeholder="models/unified_ml" value={mlModelsPath} onChange={e => setMlModelsPath(e.target.value)} />
                </FormControl>
              </Stack>
            </Box>

            <Divider />

            {/* Dedup Settings */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Deduplication</Typography>
              <Stack direction="row" spacing={2}>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel id="dedup-label">Dedup Strategy</InputLabel>
                  <Select labelId="dedup-label" label="Dedup Strategy" value={dedupStrategy} onChange={(e) => setDedupStrategy(String(e.target.value))}>
                    <MenuItem value="">(auto)</MenuItem>
                    <MenuItem value="basic">basic</MenuItem>
                    <MenuItem value="intelligent">intelligent</MenuItem>
                    <MenuItem value="aggressive">aggressive</MenuItem>
                    <MenuItem value="conservative">conservative</MenuItem>
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel htmlFor="aods-dedupthr">Dedup Threshold</InputLabel>
                  <OutlinedInput id="aods-dedupthr" label="Dedup Threshold" placeholder="0.0-1.0" value={dedupThreshold} onChange={e => setDedupThreshold(e.target.value)} />
                </FormControl>
              </Stack>
            </Box>

            <Divider />

            {/* Progressive Analysis */}
            <Box>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Progressive Analysis</Typography>
              <Stack direction="row" spacing={2} alignItems="center">
                <FormControlLabel control={<Switch checked={progressiveAnalysis} onChange={e => setProgressiveAnalysis(e.target.checked)} size="small" />} label="Enable" />
                <FormControl size="small" sx={{ minWidth: 140 }} disabled={!progressiveAnalysis}>
                  <InputLabel htmlFor="aods-samplerate">Sample Rate</InputLabel>
                  <OutlinedInput id="aods-samplerate" label="Sample Rate" placeholder="0.1-1.0" value={sampleRate} onChange={e => setSampleRate(e.target.value)} />
                </FormControl>
              </Stack>
            </Box>

            {/* Admin Policy Info */}
            {isAdmin && policy && (
              <>
                <Divider />
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Policy Info (Admin)</Typography>
                  <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
                    <Chip size="small" label={`Mode: ${policy.mode}`} />
                    <Chip size="small" label={`Threads: ${policy.maxThreads}`} />
                    <Chip size="small" label={`Mem: ${policy.memoryLimitMb}MB`} />
                    <Button size="small" variant="text" onClick={onRefreshPolicy} disabled={policyBusy}>{policyBusy ? 'Refreshing...' : 'Refresh'}</Button>
                    <Button size="small" variant="outlined" onClick={onCopyPolicy}>Copy JSON</Button>
                  </Stack>
                </Box>
              </>
            )}
          </Stack>
        </AccordionDetails>
      </Accordion>
    </>
  );
}
