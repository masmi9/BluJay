import React from 'react';
import { Box, Paper, Skeleton, Stack, Typography } from '@mui/material';

export interface DataCardProps {
  title: string;
  children: React.ReactNode;
  /** Optional action buttons in the card header. */
  actions?: React.ReactNode;
  /** Show a loading spinner overlay. */
  loading?: boolean;
  /** Paper variant. Default: 'outlined'. */
  variant?: 'elevation' | 'outlined';
  /** Paper elevation when variant='elevation'. Default: 0. */
  elevation?: number;
}

export function DataCard({ title, children, actions, loading, variant = 'outlined', elevation = 0 }: DataCardProps) {
  return (
    <Paper variant={variant} elevation={variant === 'outlined' ? 0 : elevation} sx={{ p: 2.5, borderRadius: 2, position: 'relative', transition: 'box-shadow 0.2s', '&:hover': variant === 'outlined' ? { boxShadow: 1 } : {} }}>
      {title && (
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{title}</Typography>
          {actions && <Box>{actions}</Box>}
        </Stack>
      )}
      {loading ? (
        <Stack spacing={1} sx={{ py: 1 }}>
          <Skeleton animation="wave" width="80%" height={14} sx={{ borderRadius: 0.5 }} />
          <Skeleton animation="wave" width="60%" height={14} sx={{ borderRadius: 0.5 }} />
          <Skeleton animation="wave" width="70%" height={14} sx={{ borderRadius: 0.5 }} />
        </Stack>
      ) : (
        children
      )}
    </Paper>
  );
}
