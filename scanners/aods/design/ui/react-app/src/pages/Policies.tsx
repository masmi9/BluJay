import { useMemo } from 'react';
import { Box, Button, Chip, Divider, Stack, Switch, Typography } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useToast } from '../hooks/useToast';
import { PageHeader, DataCard, StatusChip, AppToast } from '../components';

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  action: 'block' | 'warn' | 'require' | 'info';
  category: 'CI' | 'Quality' | 'Compliance' | 'ML';
  enabled: boolean;
}

const DEFAULT_POLICIES: PolicyRule[] = [
  { id: 'block-critical', name: 'Block on Critical findings', description: 'Fail CI gate when any Critical severity finding is detected.', action: 'block', category: 'CI', enabled: true },
  { id: 'warn-high', name: 'Warn on High findings', description: 'Issue warning when High severity findings exceed threshold.', action: 'warn', category: 'CI', enabled: true },
  { id: 'require-scan', name: 'Require scan before merge', description: 'Enforce a security scan must pass before code can be merged.', action: 'require', category: 'CI', enabled: true },
  { id: 'min-coverage', name: 'Minimum plugin coverage (%)', description: 'Require at least 80% of applicable plugins to execute during scan.', action: 'require', category: 'Quality', enabled: false },
  { id: 'max-scan-age', name: 'Maximum scan age (days)', description: 'Warn if the latest scan is older than 14 days.', action: 'warn', category: 'Quality', enabled: false },
  { id: 'mandatory-framework', name: 'Mandatory compliance framework', description: 'Require MASVS compliance mapping for all scan results.', action: 'require', category: 'Compliance', enabled: false },
  { id: 'evidence-high', name: 'Enforce evidence for HIGH+ findings', description: 'Require code snippet or file path evidence for High and Critical findings.', action: 'require', category: 'Compliance', enabled: false },
  { id: 'ml-confidence', name: 'Require ML confidence above threshold', description: 'Filter findings below ML confidence threshold (default 0.5).', action: 'info', category: 'ML', enabled: true },
];

const ACTION_STATUS: Record<string, string> = {
  block: 'FAIL',
  warn: 'WARN',
  require: 'INFO',
  info: 'OK',
};

const CATEGORY_COLORS: Record<string, 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success'> = {
  CI: 'error',
  Quality: 'primary',
  Compliance: 'secondary',
  ML: 'info',
};

const CATEGORIES: Array<PolicyRule['category']> = ['CI', 'Quality', 'Compliance', 'ML'];

function exportAsYaml(policies: PolicyRule[]): string {
  const lines = ['# AODS Policy Configuration', `# Exported: ${new Date().toISOString()}`, '', 'policies:'];
  policies.forEach(p => {
    lines.push(`  - id: ${p.id}`);
    lines.push(`    name: "${p.name}"`);
    lines.push(`    action: ${p.action}`);
    lines.push(`    category: ${p.category}`);
    lines.push(`    enabled: ${p.enabled}`);
  });
  return lines.join('\n');
}

export function Policies() {
  const [policies, setPolicies] = useLocalStorage<PolicyRule[]>('aodsPolicies', DEFAULT_POLICIES);
  const { toast, showToast, closeToast } = useToast();

  // Ensure all 8 policies exist (handles localStorage with old 4-rule format)
  const allPolicies = useMemo(() => {
    const byId = new Map(policies.map(p => [p.id, p]));
    return DEFAULT_POLICIES.map(dp => byId.get(dp.id) || dp);
  }, [policies]);

  const enabledCount = allPolicies.filter(p => p.enabled).length;
  const byCategory = useMemo(() => {
    const groups: Record<string, PolicyRule[]> = {};
    CATEGORIES.forEach(c => { groups[c] = allPolicies.filter(p => p.category === c); });
    return groups;
  }, [allPolicies]);

  function toggle(id: string) {
    const updated = allPolicies.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p);
    setPolicies(updated);
  }

  function handleExport() {
    const yaml = exportAsYaml(allPolicies);
    try { navigator.clipboard.writeText(yaml); showToast('Copied YAML to clipboard'); } catch { showToast('Failed to copy', 'error'); }
  }

  return (
    <Box>
      <PageHeader title="Policies" subtitle="Configure security enforcement rules for CI gates" />
      <Stack spacing={2}>
        <Stack direction="row" spacing={2} alignItems="center">
          <Chip label={`${enabledCount} / ${allPolicies.length} enabled`} color="primary" />
          {CATEGORIES.map(c => {
            const count = byCategory[c]?.filter(p => p.enabled).length ?? 0;
            return <Chip key={c} label={`${c}: ${count}`} size="small" color={CATEGORY_COLORS[c] || 'default'} variant="outlined" />;
          })}
          <Box sx={{ flexGrow: 1 }} />
          <Button size="small" variant="outlined" startIcon={<ContentCopyIcon />} onClick={handleExport}>Export as YAML</Button>
        </Stack>

        {CATEGORIES.map(cat => (
          <DataCard key={cat} title={cat}>
            <Stack spacing={1}>
              {byCategory[cat]?.map(p => (
                <Box key={p.id}>
                  <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between" sx={{ py: 0.75, px: 1, borderRadius: 1, transition: 'background-color 0.15s', '&:hover': { bgcolor: 'action.hover' } }}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ flexGrow: 1 }}>
                      <Switch checked={p.enabled} onChange={() => toggle(p.id)} size="small" />
                      <Box>
                        <Typography sx={{ opacity: p.enabled ? 1 : 0.5 }}>{p.name}</Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ opacity: p.enabled ? 1 : 0.4 }}>{p.description}</Typography>
                      </Box>
                    </Stack>
                    <StatusChip status={ACTION_STATUS[p.action] || 'INFO'} label={p.action} />
                  </Stack>
                  <Divider sx={{ mt: 0.5 }} />
                </Box>
              ))}
            </Stack>
          </DataCard>
        ))}
      </Stack>
      <AppToast toast={toast} onClose={closeToast} />
    </Box>
  );
}
