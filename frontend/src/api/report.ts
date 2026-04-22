import axios from 'axios'

const BASE = '/api/v1/report'

export const reportApi = {
  downloadHtml: (analysisId: number) =>
    `${BASE}/analysis/${analysisId}`,

  downloadSarif: (analysisId: number) =>
    `${BASE}/analysis/${analysisId}/sarif`,
}
