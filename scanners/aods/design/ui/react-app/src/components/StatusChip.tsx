import { Chip } from '@mui/material';
import type { ChipProps } from '@mui/material';

const STATUS_COLORS: Record<string, ChipProps['color']> = {
  PASS: 'success',
  FAIL: 'error',
  WARN: 'warning',
  ERROR: 'error',
  OK: 'success',
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'default',
  INFO: 'info',
  RUNNING: 'info',
  COMPLETED: 'success',
  CANCELLED: 'warning',
  PENDING: 'default',
  QUEUED: 'info',
  FAILED: 'error',
};

export interface StatusChipProps {
  status: string;
  label?: string;
  size?: 'small' | 'medium';
}

export function StatusChip({ status, label, size = 'small' }: StatusChipProps) {
  const upper = (status || '').toUpperCase();
  const color = STATUS_COLORS[upper] || 'default';
  return <Chip size={size} label={label || status} color={color} />;
}
