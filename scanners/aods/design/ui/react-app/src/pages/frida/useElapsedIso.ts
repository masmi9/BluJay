import { useState, useEffect } from 'react';

export function useElapsedIso(iso: string | null | undefined): string {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick(t => t + 1), 1000);
    return () => { try { window.clearInterval(id); } catch {} };
  }, []);
  if (!iso) return ' - ';
  try {
    const t = new Date(iso).getTime();
    const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    return `${h}h ago`;
  } catch { return ' - '; }
}
