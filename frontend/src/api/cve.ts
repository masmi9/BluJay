import { api } from './client'
import type { CveScanResponse, DetectedLibrary, CveMatch } from '@/types/cve'

export const cveApi = {
  triggerScan: (analysisId: number) =>
    api.post<{ status: string }>(`/cve/scan/${analysisId}`).then((r) => r.data),

  getLibraries: (analysisId: number) =>
    api.get<DetectedLibrary[]>(`/cve/${analysisId}/libraries`).then((r) => r.data),

  getMatches: (analysisId: number, severity?: string) =>
    api
      .get<CveMatch[]>(`/cve/${analysisId}/matches`, { params: severity ? { severity } : {} })
      .then((r) => r.data),

  getSummary: (analysisId: number) =>
    api.get<CveScanResponse>(`/cve/${analysisId}/summary`).then((r) => r.data),
}
