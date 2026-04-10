import { api } from './client'
import type { RiskScore, RiskGraph } from '@/types/risk'

export const riskApi = {
  getScore: (analysisId: number) =>
    api.get<RiskScore>(`/risk/${analysisId}/score`).then((r) => r.data),

  getGraph: (analysisId: number) =>
    api.get<RiskGraph>(`/risk/${analysisId}/graph`).then((r) => r.data),
}
