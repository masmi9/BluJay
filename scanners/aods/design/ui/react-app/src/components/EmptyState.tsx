import { Box, Button, Typography } from '@mui/material';
import type { SvgIconComponent } from '@mui/icons-material';

export interface EmptyStateProps {
  message: string;
  icon?: SvgIconComponent;
  /** Optional action button. */
  action?: { label: string; onClick: () => void };
}

export function EmptyState({ message, icon: Icon, action }: EmptyStateProps) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 8 }}>
      {Icon && <Icon sx={{ fontSize: 56, color: 'text.disabled', mb: 2, opacity: 0.35 }} />}
      <Typography variant="subtitle1" color="text.secondary" sx={{ maxWidth: 360, textAlign: 'center', fontWeight: 500, lineHeight: 1.5 }}>
        {message}
      </Typography>
      {action && (
        <Button size="small" variant="outlined" sx={{ mt: 2.5 }} onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </Box>
  );
}
