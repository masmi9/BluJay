import axios from 'axios'
import type { AIAgentScan, AIAgentScanWithFindings, ProtocolType, ProbeCategory } from '@/types/aiAgent'

const api = axios.create({ baseURL: '/api/v1/ai-agents' })

export const aiAgentApi = {
  startScan: (params: {
    target_url: string
    protocol_type: ProtocolType
    probe_categories: ProbeCategory[]
    session_id?: number | null
  }) => api.post<{ id: number; status: string }>('/scan', params).then((r) => r.data),

  getScanStatus: (id: number) =>
    api.get<{ id: number; status: string; finding_count: number; duration_seconds: number | null; error: string | null }>(`/scan/${id}/status`).then((r) => r.data),

  getScanResults: (id: number) =>
    api.get<AIAgentScanWithFindings>(`/scan/${id}/results`).then((r) => r.data),

  listScans: (sessionId?: number | null) =>
    api.get<AIAgentScan[]>('/scans', { params: sessionId != null ? { session_id: sessionId } : {} }).then((r) => r.data),

  cancelScan: (id: number) =>
    api.post<{ id: number; status: string }>(`/scan/${id}/cancel`).then((r) => r.data),

  deleteScan: (id: number) =>
    api.delete(`/scan/${id}`).then((r) => r.data),
}
