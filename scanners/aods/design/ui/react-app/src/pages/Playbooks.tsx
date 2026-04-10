import { useState, useMemo } from 'react';
import { Box, Button, Chip, Collapse, FormControl, Grid, InputAdornment, InputLabel, List, ListItem, ListItemText, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SearchIcon from '@mui/icons-material/Search';
import { PageHeader, DataCard, EmptyState, AppToast } from '../components';
import { useToast } from '../hooks/useToast';

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: 'Easy' | 'Moderate' | 'Advanced';
  estimatedTime: string;
  prerequisites: string[];
  steps: { action: string; hint?: string }[];
}

const PLAYBOOKS: Playbook[] = [
  {
    id: 'standard-remediation',
    name: 'Standard Remediation',
    description: 'Step-by-step guide for addressing common security findings after a scan.',
    category: 'Remediation',
    difficulty: 'Easy',
    estimatedTime: '1-2 hours',
    prerequisites: ['Completed scan report'],
    steps: [
      { action: 'Review scan report and prioritize Critical/High findings', hint: 'Use severity filter in Results page' },
      { action: 'Assign findings to responsible developers', hint: 'Export findings CSV for tracking' },
      { action: 'Apply recommended fixes from CWE references', hint: 'Check OWASP MASVS mapping for guidance' },
      { action: 'Re-run targeted scan to verify fixes', hint: 'Use "fast" profile for quick validation' },
      { action: 'Update remediation tracking document' },
    ],
  },
  {
    id: 'weekly-report',
    name: 'Weekly Report',
    description: 'Generate weekly security posture summary for stakeholders.',
    category: 'Reporting',
    difficulty: 'Easy',
    estimatedTime: '30 minutes',
    prerequisites: ['At least one completed scan'],
    steps: [
      { action: 'Aggregate scan results from the past 7 days', hint: 'Check Recent Jobs for scan history' },
      { action: 'Calculate trend metrics (new vs resolved findings)' },
      { action: 'Generate executive summary with severity breakdown', hint: 'Use Executive Dashboard for overview' },
      { action: 'Distribute report to configured recipients' },
    ],
  },
  {
    id: 'incident-response',
    name: 'Incident Response',
    description: 'Procedures for responding to critical vulnerability discoveries.',
    category: 'Incident',
    difficulty: 'Advanced',
    estimatedTime: '4-8 hours',
    prerequisites: ['Security team contact list', 'Incident classification criteria'],
    steps: [
      { action: 'Triage the finding \u2014 confirm severity and exploitability', hint: 'Check ML confidence score and evidence' },
      { action: 'Notify security team and affected app owners' },
      { action: 'Apply immediate mitigations (e.g., disable feature, WAF rule)' },
      { action: 'Develop and test permanent fix' },
      { action: 'Deploy fix and run verification scan', hint: 'Use "deep" profile for thorough verification' },
      { action: 'Conduct post-incident review' },
    ],
  },
  {
    id: 'ci-gate-failure',
    name: 'CI/CD Gate Failure',
    description: 'Troubleshoot and resolve CI pipeline gate failures triggered by security findings.',
    category: 'Remediation',
    difficulty: 'Moderate',
    estimatedTime: '1-3 hours',
    prerequisites: ['CI pipeline access', 'Gates Dashboard review'],
    steps: [
      { action: 'Review Gates Dashboard for failing gates', hint: 'Check severity and baseline staleness gates' },
      { action: 'Identify which findings caused the failure' },
      { action: 'Determine if findings are true positives or false positives', hint: 'Use Curation Queue for FP review' },
      { action: 'Fix true positives or mark false positives via Curation' },
      { action: 'Re-run CI pipeline to verify gate passes' },
    ],
  },
  {
    id: 'vulnerability-triage',
    name: 'Vulnerability Triage',
    description: 'Systematic process for evaluating and prioritizing scan findings.',
    category: 'Compliance',
    difficulty: 'Moderate',
    estimatedTime: '2-4 hours',
    prerequisites: ['Completed deep scan', 'MASVS requirements document'],
    steps: [
      { action: 'Filter findings by severity (Critical first, then High)', hint: 'Use severity filter in findings table' },
      { action: 'Cross-reference findings with MASVS requirements' },
      { action: 'Validate evidence and code snippets for accuracy' },
      { action: 'Assign risk scores based on exploitability and impact' },
      { action: 'Create remediation tickets with priority labels' },
    ],
  },
  {
    id: 'compliance-audit',
    name: 'Compliance Audit',
    description: 'Prepare security documentation for compliance frameworks (MASVS, OWASP).',
    category: 'Compliance',
    difficulty: 'Advanced',
    estimatedTime: '1-2 days',
    prerequisites: ['Deep scan of all target APKs', 'Compliance framework reference'],
    steps: [
      { action: 'Run deep scans on all in-scope applications' },
      { action: 'Export full reports in JSON and HTML formats' },
      { action: 'Map findings to MASVS categories', hint: 'Check Mapping Sources page' },
      { action: 'Document remediation status for each finding' },
      { action: 'Generate compliance summary report' },
      { action: 'Archive scan artifacts for audit trail', hint: 'Use Artifacts page for storage' },
    ],
  },
];

const CATEGORY_COLORS: Record<string, 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success'> = {
  Remediation: 'primary',
  Reporting: 'info',
  Incident: 'error',
  Compliance: 'secondary',
};

const DIFFICULTY_COLORS: Record<string, 'success' | 'warning' | 'error'> = {
  Easy: 'success',
  Moderate: 'warning',
  Advanced: 'error',
};

const CATEGORIES = ['All', ...Array.from(new Set(PLAYBOOKS.map(p => p.category)))];

function copyAsMarkdown(pb: Playbook) {
  const lines = [`# ${pb.name}\n`, `${pb.description}\n`, `**Category:** ${pb.category} | **Difficulty:** ${pb.difficulty} | **Time:** ${pb.estimatedTime}\n`];
  if (pb.prerequisites.length) lines.push(`**Prerequisites:** ${pb.prerequisites.join(', ')}\n`);
  lines.push('## Steps\n');
  pb.steps.forEach((s, i) => {
    lines.push(`- [ ] ${i + 1}. ${s.action}`);
    if (s.hint) lines.push(`  - _Hint: ${s.hint}_`);
  });
  try { navigator.clipboard.writeText(lines.join('\n')); } catch { /* ignore */ }
}

export function Playbooks() {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All');
  const { toast, showToast, closeToast } = useToast();

  const filtered = useMemo(() => {
    return PLAYBOOKS.filter(pb => {
      if (category !== 'All' && pb.category !== category) return false;
      if (search && !pb.name.toLowerCase().includes(search.toLowerCase()) && !pb.description.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [search, category]);

  function toggleExpand(id: string) {
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }));
  }

  return (
    <Box>
      <PageHeader title="Playbooks" subtitle="Step-by-step guides for common security workflows" />
      <Stack spacing={2}>
        <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
          <TextField size="small" placeholder="Search playbooks..." value={search} onChange={e => setSearch(e.target.value)} sx={{ minWidth: 200 }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" color="action" /></InputAdornment> }} />
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel id="cat-label">Category</InputLabel>
            <Select labelId="cat-label" label="Category" value={category} onChange={e => setCategory(e.target.value)}>
              {CATEGORIES.map(c => <MenuItem key={c} value={c}>{c}</MenuItem>)}
            </Select>
          </FormControl>
          <Typography variant="body2" color="text.secondary">{filtered.length} playbook{filtered.length !== 1 ? 's' : ''}</Typography>
        </Stack>

        <Grid container spacing={2}>
          {filtered.map(pb => (
            <Grid item xs={12} md={6} key={pb.id}>
              <DataCard title={pb.name}>
                <Stack spacing={1}>
                  <Typography variant="body2" color="text.secondary">{pb.description}</Typography>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                    <Chip label={pb.category} size="small" color={CATEGORY_COLORS[pb.category] || 'default'} />
                    <Chip label={pb.difficulty} size="small" color={DIFFICULTY_COLORS[pb.difficulty] || 'default'} variant="outlined" />
                    <Typography variant="caption" color="text.secondary">{pb.estimatedTime}</Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums', color: 'text.secondary' }}>{pb.steps.length} steps</Typography>
                  </Stack>
                  {pb.prerequisites.length > 0 && (
                    <Typography variant="caption" color="text.secondary">Prerequisites: {pb.prerequisites.join(', ')}</Typography>
                  )}
                  <Stack direction="row" spacing={1}>
                    <Button size="small" variant="text" onClick={() => toggleExpand(pb.id)} endIcon={expanded[pb.id] ? <ExpandLessIcon /> : <ExpandMoreIcon />}>
                      {expanded[pb.id] ? 'Hide steps' : 'Show steps'}
                    </Button>
                    <Button size="small" variant="text" startIcon={<ContentCopyIcon />} onClick={() => { copyAsMarkdown(pb); showToast('Copied to clipboard'); }}>
                      Copy as Markdown
                    </Button>
                  </Stack>
                  <Collapse in={expanded[pb.id]}>
                    <List dense disablePadding>
                      {pb.steps.map((step, i) => (
                        <ListItem key={i} sx={{ pl: 0, flexDirection: 'column', alignItems: 'flex-start', borderRadius: 1, '&:hover': { bgcolor: 'action.hover' } }}>
                          <ListItemText primary={`${i + 1}. ${step.action}`} primaryTypographyProps={{ variant: 'body2' }} />
                          {step.hint && <Typography variant="caption" color="text.secondary" sx={{ pl: 2.5 }}>Hint: {step.hint}</Typography>}
                        </ListItem>
                      ))}
                    </List>
                  </Collapse>
                </Stack>
              </DataCard>
            </Grid>
          ))}
          {filtered.length === 0 && (
            <Grid item xs={12}>
              <EmptyState icon={SearchIcon} message="No playbooks match the current filters" />
            </Grid>
          )}
        </Grid>

        <DataCard title="Need a Playbook?">
          <Typography variant="body2" color="text.secondary">
            Request a custom playbook for your workflow by contacting the security team or submitting a request via your organization&apos;s ticketing system.
          </Typography>
        </DataCard>
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
