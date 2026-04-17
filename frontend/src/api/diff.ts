import { api } from './client'

export interface FindingSnap {
  category: string
  severity: string
  title: string
  description: string
  file_path: string | null
  rule_id: string | null
}

export interface DiffOut {
  id: number
  created_at: string
  baseline_id: number | null
  target_id: number | null
  diff_type: string
  added_findings: FindingSnap[]
  removed_findings: FindingSnap[]
  added_permissions: string[]
  removed_permissions: string[]
  severity_delta: Record<string, number>
  summary: string | null
}

export interface DiffSummary {
  id: number
  created_at: string
  baseline_id: number | null
  target_id: number | null
  diff_type: string
  summary: string | null
}

export const diffApi = {
  create: (baseline_id: number, target_id: number, diff_type = 'full') =>
    api.post<DiffOut>('/diff', { baseline_id, target_id, diff_type }).then((r) => r.data),

  list: () => api.get<DiffSummary[]>('/diff').then((r) => r.data),

  get: (id: number) => api.get<DiffOut>(`/diff/${id}`).then((r) => r.data),

  delete: (id: number) => api.delete(`/diff/${id}`),
}
