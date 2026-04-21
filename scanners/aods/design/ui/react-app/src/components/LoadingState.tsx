import { Box, CircularProgress, Typography } from '@mui/material';

export interface LoadingStateProps {
  label?: string;
  size?: number;
  fullHeight?: boolean;
}

export function LoadingState({ label, size = 32, fullHeight }: LoadingStateProps) {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        py: 4,
        ...(fullHeight ? { minHeight: '60vh' } : {}),
      }}
    >
      <CircularProgress size={size} />
      {label && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          {label}
        </Typography>
      )}
    </Box>
  );
}
