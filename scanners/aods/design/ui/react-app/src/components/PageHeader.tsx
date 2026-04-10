import React from 'react';
import { Stack, Typography, Box } from '@mui/material';

export interface PageHeaderProps {
  title: string;
  subtitle?: string;
  /** Action buttons rendered on the right side of the header. */
  actions?: React.ReactNode;
}

export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2} sx={{ mb: 3 }}>
      <Box>
        <Typography variant="h4" component="h2" sx={{ fontWeight: 700 }}>{title}</Typography>
        {subtitle && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {subtitle}
          </Typography>
        )}
      </Box>
      {actions && <Box sx={{ flexShrink: 0, pt: 0.5 }}>{actions}</Box>}
    </Stack>
  );
}
