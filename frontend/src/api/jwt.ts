import { api } from './client'
import type { JwtDecodeResult, JwtTestOut } from '@/types/jwt'

export const jwtApi = {
  decode: (token: string, sessionId?: number, analysisId?: number) =>
    api
      .post<JwtDecodeResult>('/jwt/decode', {
        token,
        session_id: sessionId ?? null,
        analysis_id: analysisId ?? null,
      })
      .then((r) => r.data),

  startBruteForce: (testId: number, wordlist?: string) =>
    api
      .post<{ status: string; test_id: number }>(`/jwt/brute-force/${testId}`, null, {
        params: wordlist ? { wordlist } : {},
      })
      .then((r) => r.data),

  forge: (token: string) =>
    api
      .post<{ alg_none: string; kid_injection: string[]; role_escalation: string[] }>(
        '/jwt/forge',
        { token }
      )
      .then((r) => r.data),

  listTests: (params?: { session_id?: number; analysis_id?: number }) =>
    api.get<JwtTestOut[]>('/jwt/tests', { params }).then((r) => r.data),

  scanFlows: (sessionId: number) =>
    api.get<string[]>('/jwt/from-flows', { params: { session_id: sessionId } }).then((r) => r.data),
}
