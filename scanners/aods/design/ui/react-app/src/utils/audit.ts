import { secureFetch } from '../lib/api';

export async function emitAudit(action: string, user: string, resource?: string, details?: any) {
  try {
    await secureFetch(`/audit/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        user,
        action,
        resource,
        details
      })
    });
  } catch {
    // best effort; ignore
  }
}


