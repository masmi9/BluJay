import axios from 'axios'
import type { PciFinding, PciScanJob, PaymentFlowResult } from '@/types/pci'

const BASE = '/api/v1/pci'

export interface ScopeValidation {
  valid: boolean
  name?: string
  target_count?: number
  checks?: Record<string, boolean>
  scan_profile?: string
  error?: string
}

export const pciApi = {
  startScan: (target_urls: string[], categories: string[] = [], scan_profile = 'web_only') =>
    axios.post<PciScanJob>(`${BASE}/jobs`, { target_urls, categories, scan_profile }).then((r) => r.data),

  startFullScan: (scope_config: string, scan_profile = 'external_pci') =>
    axios.post<PciScanJob>(`${BASE}/full-scan`, { scope_config, scan_profile }).then((r) => r.data),

  validateScope: (scope_config: string) =>
    axios.post<ScopeValidation>(`${BASE}/scope/validate`, { scope_config }).then((r) => r.data),

  listJobs: () =>
    axios.get<PciScanJob[]>(`${BASE}/jobs`).then((r) => r.data),

  getJob: (job_id: number) =>
    axios.get<PciScanJob>(`${BASE}/jobs/${job_id}`).then((r) => r.data),

  cancelJob: (job_id: number) =>
    axios.delete(`${BASE}/jobs/${job_id}`).then((r) => r.data),

  deleteJob: (job_id: number) =>
    axios.delete(`${BASE}/jobs/${job_id}/delete`).then((r) => r.data),

  getFindings: (job_id: number) =>
    axios.get<PciFinding[]>(`${BASE}/jobs/${job_id}/findings`).then((r) => r.data),

  getFlowSteps: (job_id: number) =>
    axios.get<PaymentFlowResult[]>(`${BASE}/jobs/${job_id}/flow-steps`).then((r) => r.data),

  downloadReport: async (job_id: number, type: 'json' | 'executive' | 'technical') => {
    const r = await axios.get(`${BASE}/jobs/${job_id}/report/${type}`, { responseType: 'blob' })
    return r.data as Blob
  },
}
