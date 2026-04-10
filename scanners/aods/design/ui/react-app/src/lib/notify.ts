/**
 * Browser notification helper that respects Config page notification preferences.
 *
 * Reads `aodsConfig_notifEnabled` and `aodsConfig_notifEvents` from localStorage.
 * Only fires if the user has both enabled notifications in Config and granted
 * the browser permission.
 */

type NotifEvent = 'Scan complete' | 'Scan failed' | 'Gate violations';

function readPref<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw !== null ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export function fireNotification(event: NotifEvent, body: string): void {
  try {
    if (typeof Notification === 'undefined') return;
    if (Notification.permission !== 'granted') return;
    if (!readPref<boolean>('aodsConfig_notifEnabled', false)) return;
    const events = readPref<string[]>('aodsConfig_notifEvents', []);
    if (!events.includes(event)) return;

    new Notification(`AODS - ${event}`, { body, icon: '/favicon.ico' });
  } catch {
    // Best-effort - never break the caller
  }
}
