import { useMemo } from 'react';
import { Button, Divider, Stack, Tooltip, Typography } from '@mui/material';
import BoltIcon from '@mui/icons-material/Bolt';
import SearchIcon from '@mui/icons-material/Search';
import SecurityIcon from '@mui/icons-material/Security';

export interface PresetTarget {
  scanProfile: string;
  scanMode: string;
  staticOnly: boolean;
  fridaMode: string;
  resourceConstrained: boolean;
  outputFormats?: string[];
  ciMode?: boolean;
  failOnCritical?: boolean;
  failOnHigh?: boolean;
}

interface ScanPresetsBarProps {
  scanProfile: string;
  scanMode: string;
  staticOnly: boolean;
  fridaMode: string;
  resourceConstrained: boolean;
  ciMode: boolean;
  failOnCritical: boolean;
  failOnHigh: boolean;
  onSelectPreset: (preset: PresetTarget) => void;
}

export function ScanPresetsBar({
  scanProfile, scanMode, staticOnly, fridaMode, resourceConstrained,
  ciMode, failOnCritical, failOnHigh, onSelectPreset,
}: ScanPresetsBarProps) {
  const quickStaticSelected = useMemo(() => (
    String(scanProfile) === 'lightning' && String(scanMode) === 'safe' && staticOnly === true && (!fridaMode) && !resourceConstrained && !ciMode && !failOnCritical && !failOnHigh
  ), [scanProfile, scanMode, staticOnly, fridaMode, resourceConstrained, ciMode, failOnCritical, failOnHigh]);
  const fullDynamicSelected = useMemo(() => (
    String(scanProfile) === 'standard' && String(scanMode) === 'deep' && staticOnly === false && String(fridaMode) === 'standard'
  ), [scanProfile, scanMode, staticOnly, fridaMode]);
  const deepAnalysisSelected = useMemo(() => (
    String(scanProfile) === 'deep' && String(scanMode) === 'deep' && staticOnly === false && String(fridaMode) === 'advanced'
  ), [scanProfile, scanMode, staticOnly, fridaMode]);

  return (
    <>
      <Divider />
      <Stack spacing={1}>
        <Typography variant="subtitle2" color="text.secondary">Quick Presets</Typography>
        <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
          <Tooltip title="Fast static-only analysis (lightning profile, safe mode)">
            <Button
              variant={quickStaticSelected ? 'contained' : 'outlined'}
              color={quickStaticSelected ? 'primary' : 'inherit'}
              startIcon={<BoltIcon />}
              aria-pressed={quickStaticSelected}
              onClick={() => onSelectPreset({
                scanProfile: 'lightning', scanMode: 'safe', staticOnly: true, fridaMode: '', resourceConstrained: false, outputFormats: ['json','html'], ciMode: false, failOnCritical: false, failOnHigh: false,
              })}
            >
              Quick Static
            </Button>
          </Tooltip>
          <Tooltip title="Standard profile with Frida dynamic analysis (deep mode)">
            <Button
              variant={fullDynamicSelected ? 'contained' : 'outlined'}
              color={fullDynamicSelected ? 'primary' : 'inherit'}
              startIcon={<SearchIcon />}
              aria-pressed={fullDynamicSelected}
              onClick={() => onSelectPreset({
                scanProfile: 'standard', scanMode: 'deep', staticOnly: false, fridaMode: 'standard', resourceConstrained: false,
              })}
            >
              Standard Scan
            </Button>
          </Tooltip>
          <Tooltip title="Deep profile with analysis and advanced Frida">
            <Button
              variant={deepAnalysisSelected ? 'contained' : 'outlined'}
              color={deepAnalysisSelected ? 'primary' : 'inherit'}
              startIcon={<SecurityIcon />}
              aria-pressed={deepAnalysisSelected}
              onClick={() => onSelectPreset({
                scanProfile: 'deep', scanMode: 'deep', staticOnly: false, fridaMode: 'advanced', resourceConstrained: false,
              })}
            >
              Deep Analysis
            </Button>
          </Tooltip>
        </Stack>
      </Stack>
    </>
  );
}
