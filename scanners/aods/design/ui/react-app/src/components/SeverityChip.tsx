import { Chip } from '@mui/material';

export interface SeverityChipProps {
  severity: string;
  size?: 'small' | 'medium';
  variant?: 'filled' | 'outlined';
}

const SEVERITY_COLOR: Record<string, 'error' | 'warning' | 'info' | 'success' | 'default'> = {
  CRITICAL: 'error',
  HIGH: 'warning',
  MEDIUM: 'info',
  LOW: 'success',
  INFO: 'default',
};

export function SeverityChip({ severity, size = 'small', variant = 'filled' }: SeverityChipProps) {
  const upper = (severity || '').toUpperCase();
  return <Chip label={upper || 'UNKNOWN'} size={size} variant={variant} color={SEVERITY_COLOR[upper] || 'default'} />;
}
