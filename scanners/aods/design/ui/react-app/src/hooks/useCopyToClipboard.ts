import { useCallback } from 'react';
import type { UseToastReturn } from './useToast';

export interface UseCopyToClipboardOptions {
  /** Toast hook instance for feedback */
  toast?: UseToastReturn;
  /** Custom success message (default: "Copied to clipboard") */
  successMessage?: string;
}

/**
 * Copy text to clipboard with optional toast feedback.
 * Works standalone or integrates with useToast for visual feedback.
 */
export function useCopyToClipboard(options: UseCopyToClipboardOptions = {}) {
  const { toast, successMessage = 'Copied to clipboard' } = options;

  const copy = useCallback(async (text: string, label?: string) => {
    try {
      await navigator.clipboard.writeText(text);
      if (toast) {
        toast.showToast(label ? `${label} copied` : successMessage, 'success');
      }
      return true;
    } catch {
      if (toast) {
        toast.showToast('Failed to copy', 'error');
      }
      return false;
    }
  }, [toast, successMessage]);

  return copy;
}
