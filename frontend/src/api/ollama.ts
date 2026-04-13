import { api } from './client'
import type { OllamaAnalysis, AnalyzeRequest, OllamaStatus } from '@/types/ollama'

export const ollamaApi = {
  status: () =>
    api.get<OllamaStatus>('/ollama/status').then((r) => r.data),

  analyze: (body: AnalyzeRequest) =>
    api
      .post<OllamaAnalysis & { ai_response: string }>('/ollama/analyze', body)
      .then((r) => r.data),

  analyzeSession: (body: { session_id: number; sources?: string[]; model?: string }) =>
    api
      .post<OllamaAnalysis & { sources_included: string[] }>('/ollama/analyze/session', body)
      .then((r) => r.data),

  history: (params?: { session_id?: number; source?: string; skip?: number; limit?: number }) =>
    api.get<OllamaAnalysis[]>('/ollama/history', { params }).then((r) => r.data),

  deleteAnalysis: (id: number) =>
    api.delete(`/ollama/history/${id}`),
}
