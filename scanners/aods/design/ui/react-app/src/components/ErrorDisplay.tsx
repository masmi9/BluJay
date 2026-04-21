import { Alert, Button } from '@mui/material';

export interface ErrorDisplayProps {
  error: string | null;
  onRetry?: () => void;
  severity?: 'error' | 'warning' | 'info';
}

export function ErrorDisplay({ error, onRetry, severity = 'error' }: ErrorDisplayProps) {
  if (!error) return null;
  return (
    <Alert
      severity={severity}
      role="alert"
      variant="outlined"
      sx={{ borderRadius: 1.5 }}
      action={onRetry ? <Button color="inherit" size="small" onClick={onRetry}>Retry</Button> : undefined}
    >
      {error}
    </Alert>
  );
}
