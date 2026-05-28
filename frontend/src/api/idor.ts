import { api } from './client'
import type { IDORConfig, IDORStats, IDORFinding } from '@/types/idor'

export const idorApi = {
  configure: (sessionId: number, config: Partial<IDORConfig>) =>
    api.post('/idor/configure', config, { params: { session_id: sessionId } }).then((r) => r.data),

  getStats: (sessionId: number) =>
    api.get<IDORStats>('/idor/stats', { params: { session_id: sessionId } }).then((r) => r.data),

  getFindings: (sessionId: number) =>
    api.get<{ findings: IDORFinding[] }>('/idor/findings', { params: { session_id: sessionId } }).then((r) => r.data),

  clear: (sessionId: number) =>
    api.delete('/idor/clear', { params: { session_id: sessionId } }).then((r) => r.data),
}
