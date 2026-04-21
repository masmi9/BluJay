/** Vite environment access - extracted for Jest compatibility (import.meta is ESM-only). */
export function getUiVersion(): string {
  try {
    const env = (import.meta as unknown as Record<string, Record<string, string>>)?.env || {};
    return env.VITE_APP_VERSION || env.VITE_UI_VERSION || 'dev';
  } catch { return 'dev'; }
}
