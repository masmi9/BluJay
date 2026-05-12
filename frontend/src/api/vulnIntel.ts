import { api } from './client'

export interface CVEResult {
  id: string
  score: number | null
  severity: string
  vector: string | null
  description: string
  published: string | null
  refs: string[]
}

export interface NucleiScan {
  id: string
  target: string
  status: string
  findings: Record<string, unknown>[]
  findings_count?: number
  started_at: string
  completed_at?: string
  error?: string | null
}

export const vulnIntelApi = {
  cveSearch: (keyword: string, cpe_name = '', limit = 20) =>
    api.post('/vuln/cve/search', { keyword, cpe_name, limit }).then((r) => r.data as { total: number; results: CVEResult[] }),

  getCve: (id: string) =>
    api.get(`/vuln/cve/${id}`).then((r) => r.data as CVEResult),

  versionsMatch: (services: { service: string; version: string; port?: number }[]) =>
    api.post('/vuln/versions/match', { services }).then((r) => r.data),

  nucleiStatus: () =>
    api.get('/vuln/nuclei/status').then((r) => r.data as { available: boolean; path: string | null; version: string | null; hint: string | null }),

  nucleiScan: (target: string, tags: string[], severity: string[]) =>
    api.post('/vuln/nuclei/scan', { target, tags, severity }).then((r) => r.data as { id: string; status: string; target: string }),

  nucleiResults: (id: string) =>
    api.get(`/vuln/nuclei/results/${id}`).then((r) => r.data as NucleiScan),

  nucleiScans: () =>
    api.get('/vuln/nuclei/scans').then((r) => r.data as NucleiScan[]),

  exploitdbSearch: (keyword: string, limit = 20) =>
    api.post('/vuln/exploitdb/search', { keyword, limit }).then((r) => r.data),
}
