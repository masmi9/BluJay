// Shared helpers for reports/result summaries

type SevKey = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

function normalizeSeverity(value: any): SevKey {
  const s = String(value || '').toUpperCase();
  if (s.includes('CRIT')) return 'CRITICAL';
  if (s.includes('HIGH')) return 'HIGH';
  if (s.includes('MED')) return 'MEDIUM';
  if (s.includes('LOW')) return 'LOW';
  return 'INFO';
}

export type ReportStats = {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export function computeReportStats(data: any): ReportStats | null {
  if (!data || typeof data !== 'object') return null;

  // Helper to count severities from an arbitrary list of finding-like objects
  const tallyFromList = (arr: any[]): ReportStats => {
    const counts: Record<SevKey, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of arr) {
      const sev = normalizeSeverity((f && (f.severity ?? f.Severity ?? f.risk ?? f.Risk)) || '');
      counts[sev] += 1;
    }
    const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.INFO;
    return {
      total_findings: total,
      critical: counts.CRITICAL,
      high: counts.HIGH,
      medium: counts.MEDIUM,
      low: counts.LOW,
      info: counts.INFO,
    };
  };

  // 1) Direct summary fields at root
  if (['total_findings','critical','high','medium','low'].some(k => typeof (data as any)[k] !== 'undefined')) {
    return {
      total_findings: Number((data as any).total_findings || 0),
      critical: Number((data as any).critical || 0),
      high: Number((data as any).high || 0),
      medium: Number((data as any).medium || 0),
      low: Number((data as any).low || 0),
      info: Number((data as any).info || 0),
    };
  }

  // 1b) Check summary.severity block (matches API _summarize_result logic)
  try {
    const summary = (data as any)?.summary;
    if (summary && typeof summary === 'object') {
      const sev = summary.severity;
      if (sev && typeof sev === 'object') {
        return {
          total_findings: Number(summary.findings ?? summary.total_findings ?? 0),
          critical: Number(sev.critical ?? 0),
          high: Number(sev.high ?? 0),
          medium: Number(sev.medium ?? 0),
          low: Number(sev.low ?? 0),
          info: Number(sev.info ?? sev.informational ?? 0),
        };
      }
    }
  } catch {}

  // 2) Tally from vulnerabilities array (aods_parallel format)
  try {
    const vulns = (data as any)?.vulnerabilities;
    if (Array.isArray(vulns) && vulns.length) {
      return tallyFromList(vulns);
    }
  } catch {}

  // 3) Known shapes: context.processed_findings (preferred)
  try {
    const processed = (data as any)?.context?.processed_findings;
    if (Array.isArray(processed) && processed.length) {
      return tallyFromList(processed);
    }
  } catch {}

  // 4) Aggregate all sections[*].findings
  try {
    const sections = (data as any)?.sections;
    if (Array.isArray(sections) && sections.length) {
      const all: any[] = [];
      for (const s of sections) {
        if (Array.isArray((s as any)?.findings) && (s as any).findings.length) all.push(...(s as any).findings);
      }
      if (all.length) return tallyFromList(all);
    }
  } catch {}

  // 5) statistics object with severity counts
  try {
    const stats = (data as any)?.statistics;
    if (stats && typeof stats === 'object') {
      const getNum = (o: any, k: string) => Number((o as any)[k] ?? (o as any)[k.toUpperCase()] ?? (o as any)[k.toLowerCase()] ?? 0);
      const candidates = [stats, (stats as any).severity, (stats as any).severity_counts, (stats as any).severity_breakdown, (stats as any).by_severity];
      for (const obj of candidates) {
        if (obj && typeof obj === 'object') {
          const keys = Object.keys(obj).map((x) => String(x).toLowerCase());
          if (keys.some(k => ['critical','high','medium','low'].includes(k))) {
            const critical = getNum(obj, 'critical');
            const high = getNum(obj, 'high');
            const medium = getNum(obj, 'medium');
            const low = getNum(obj, 'low');
            const info = getNum(obj, 'info') || getNum(obj, 'informational');
            const total = Number(getNum(obj, 'total_findings')) || (critical + high + medium + low + info);
            return { total_findings: total, critical, high, medium, low, info };
          }
        }
      }
    }
  } catch {}

  // 6) Fallback: root findings array
  const findings = Array.isArray((data as any).findings) ? (data as any).findings : [];
  if (findings.length) return tallyFromList(findings);

  return null;
}
