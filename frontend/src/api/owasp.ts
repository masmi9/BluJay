import { api } from './client'
import type { OwaspFinding, OwaspScanSummary } from '@/types/owasp'

export const owaspApi = {
  start: (apk_path: string, package_name: string, mode = 'safe', analysis_id?: number, device_serial?: string, platform = 'android') =>
    api.post<{ id: number; status: string }>('/owasp', { apk_path, package_name, mode, analysis_id, device_serial, platform }).then((r) => r.data),
  list: () => api.get<OwaspScanSummary[]>('/owasp').then((r) => r.data),
  get: (id: number) => api.get<OwaspScanSummary & { findings: OwaspFinding[]; summary: unknown; has_html: boolean }>(`/owasp/${id}`).then((r) => r.data),
  getFindings: (id: number, params?: { severity?: string; skip?: number; limit?: number }) =>
    api.get<{ total: number; items: OwaspFinding[] }>(`/owasp/${id}/findings`, { params }).then((r) => r.data),
  delete: (id: number) => api.delete(`/owasp/${id}`),
  reportUrl: (id: number) => `/api/v1/owasp/${id}/report`,
}
