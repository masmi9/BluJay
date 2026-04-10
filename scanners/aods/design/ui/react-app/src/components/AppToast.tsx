import { Alert, Snackbar } from '@mui/material';
import type { ToastState } from '../hooks/useToast';

export interface AppToastProps {
  toast: ToastState;
  onClose: () => void;
}

/**
 * Reusable toast/snackbar component.
 * Use with `useToast()` hook for consistent notifications across pages.
 */
export function AppToast({ toast, onClose }: AppToastProps) {
  return (
    <Snackbar
      open={toast.open}
      autoHideDuration={3000}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert
        onClose={onClose}
        severity={toast.severity}
        variant="filled"
        sx={{ width: '100%' }}
      >
        {toast.message}
      </Alert>
    </Snackbar>
  );
}
