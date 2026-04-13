import { api } from './client'
import type { StrixScan, StrixScanResults, StartScanRequest, StrixStatus } from '@/types/strix'

export const strixApi = {
  status: () =>
    api.get<StrixStatus>('/strix/status').then((r) => r.data),

  startScan: (body: StartScanRequest) =>
    api
      .post<{ id: number; status: string; target: string; scan_mode: string; session_id: number | null; message: string }>(
        '/strix/scan',
        body,
      )
      .then((r) => r.data),

  getScan: (id: number) =>
    api.get<StrixScan & { raw_output: string | null; findings: unknown[] }>(`/strix/scan/${id}`).then((r) => r.data),

  scanStatus: (id: number) =>
    api.get<StrixScan>(`/strix/scan/${id}/status`).then((r) => r.data),

  scanResults: (id: number) =>
    api.get<StrixScanResults>(`/strix/scan/${id}/results`).then((r) => r.data),

  cancelScan: (id: number) =>
    api.post<{ id: number; status: string }>(`/strix/scan/${id}/cancel`).then((r) => r.data),

  listScans: (params?: { session_id?: number; status?: string; skip?: number; limit?: number }) =>
    api.get<StrixScan[]>('/strix/scans', { params }).then((r) => r.data),

  deleteScan: (id: number) =>
    api.delete(`/strix/scan/${id}`),
}
