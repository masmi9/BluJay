import axios from 'axios'
import type { ActiveScanJob, FindingsResponse, ScanFinding } from '@/types/scanner'

const BASE = '/api/v1/scanner'

export const scannerApi = {
  getFindings: (params?: { session_id?: number; scan_type?: string; severity?: string; limit?: number }) =>
    axios.get<FindingsResponse>(`${BASE}/findings`, { params }).then((r) => r.data),

  clearFindings: (session_id?: number) =>
    axios.delete(`${BASE}/findings`, { params: { session_id } }).then((r) => r.data),

  listJobs: (session_id?: number) =>
    axios.get<ActiveScanJob[]>(`${BASE}/jobs`, { params: { session_id } }).then((r) => r.data),

  startScan: (flow_ids: string[], checks: string[], session_id?: number, target_urls?: string[]) =>
    axios.post<ActiveScanJob>(`${BASE}/jobs`, { flow_ids, checks, session_id, target_urls }).then((r) => r.data),

  scanUrl: (url: string, session_id?: number) =>
    axios.post<{ url: string; findings: import('@/types/scanner').ScanFinding[] }>(
      `${BASE}/scan-url`, { url, session_id }
    ).then((r) => r.data),

  getJob: (job_id: number) =>
    axios.get<ActiveScanJob>(`${BASE}/jobs/${job_id}`).then((r) => r.data),

  cancelJob: (job_id: number) =>
    axios.delete(`${BASE}/jobs/${job_id}`).then((r) => r.data),
}
