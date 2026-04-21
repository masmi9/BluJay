import { api } from './client'
import type { TlsAudit, TlsAuditRequest } from '@/types/tls'

export const tlsApi = {
  audit: (body: TlsAuditRequest) =>
    api.post<TlsAudit[]>('/tls/audit', body).then((r) => r.data),

  list: (params?: { session_id?: number; analysis_id?: number }) =>
    api.get<TlsAudit[]>('/tls/audits', { params }).then((r) => r.data),

  get: (id: number) =>
    api.get<TlsAudit>(`/tls/audits/${id}`).then((r) => r.data),
}
