/**
 * Shared date/time formatting utilities.
 * Replaces per-page formatDate / toLocaleString / toLocaleTimeString patterns.
 */

/** Full date+time for table cells: "Jan 15, 2026, 02:30 PM" */
export function formatDateTime(dateStr: string | undefined | null): string {
  if (!dateStr) return '\u2014';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return dateStr || '\u2014';
  }
}

/** Time only for compact display: "2:30:15 PM" */
export function formatTime(dateStr: string | undefined | null): string {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleTimeString();
  } catch {
    return dateStr || '';
  }
}

/** Relative time: "3 minutes ago", "2 hours ago", "yesterday" */
export function formatRelativeTime(dateStr: string | undefined | null): string {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const now = Date.now();
    const diffMs = now - d.getTime();
    if (diffMs < 0) return 'just now';
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return 'just now';
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHrs = Math.floor(diffMin / 60);
    if (diffHrs < 24) return `${diffHrs}h ago`;
    const diffDays = Math.floor(diffHrs / 24);
    if (diffDays === 1) return 'yesterday';
    if (diffDays < 30) return `${diffDays}d ago`;
    return formatDateTime(dateStr);
  } catch {
    return dateStr || '';
  }
}

/** Format file size: "4 KB", "1.2 MB" */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Severity summary: "3C/5H/2M" from scan summary object */
export function sevSummary(s?: { critical?: number; high?: number; medium?: number; low?: number; info?: number }): string {
  if (!s) return '';
  const parts: string[] = [];
  if (s.critical) parts.push(`${s.critical}C`);
  if (s.high) parts.push(`${s.high}H`);
  if (s.medium) parts.push(`${s.medium}M`);
  if (s.low) parts.push(`${s.low}L`);
  if (s.info) parts.push(`${s.info}I`);
  return parts.join('/');
}

/** Truncate text in the middle, preserving start/end for readability */
export function truncateMiddle(text: string, maxLen = 40): string {
  if (!text || text.length <= maxLen) return text || '';
  const half = Math.floor((maxLen - 3) / 2);
  return `${text.slice(0, half)}\u2026${text.slice(-half)}`;
}
