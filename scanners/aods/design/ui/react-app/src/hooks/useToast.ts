import { useState, useCallback, useRef } from 'react';

export interface ToastState {
  open: boolean;
  message: string;
  severity: 'success' | 'error' | 'warning' | 'info';
}

export interface UseToastReturn {
  toast: ToastState;
  showToast: (message: string, severity?: ToastState['severity']) => void;
  closeToast: () => void;
}

/**
 * Unified toast/snackbar hook with auto-dismiss.
 * Replaces scattered `[toast, setToast] + setTimeout` patterns.
 */
export function useToast(defaultDuration = 3000): UseToastReturn {
  const [toast, setToast] = useState<ToastState>({ open: false, message: '', severity: 'success' });
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  const showToast = useCallback((message: string, severity: ToastState['severity'] = 'success') => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setToast({ open: true, message, severity });
    timerRef.current = setTimeout(() => {
      setToast(prev => ({ ...prev, open: false }));
    }, defaultDuration);
  }, [defaultDuration]);

  const closeToast = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setToast(prev => ({ ...prev, open: false }));
  }, []);

  return { toast, showToast, closeToast };
}
