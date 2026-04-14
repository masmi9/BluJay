import { api } from './client'
import type {
  ApiTest,
  ApiTestResult,
  ApiTestSuite,
  ImportFlowsResult,
  SuggestedTest,
} from '@/types/api_testing'

const BASE = '/api-testing'

export const apiTestingApi = {
  // ── Suites ──────────────────────────────────────────────────────────────
  listSuites: (): Promise<ApiTestSuite[]> =>
    api.get(`${BASE}/suites`).then(r => r.data),

  createSuite: (data: {
    name: string
    session_id?: number | null
    analysis_id?: number | null
    target_app?: string | null
    platform?: string
  }): Promise<ApiTestSuite> =>
    api.post(`${BASE}/suites`, data).then(r => r.data),

  getSuite: (id: number): Promise<ApiTestSuite> =>
    api.get(`${BASE}/suites/${id}`).then(r => r.data),

  importFlows: (suiteId: number): Promise<ImportFlowsResult> =>
    api.post(`${BASE}/suites/${suiteId}/import-flows`).then(r => r.data),

  // ── Tests ────────────────────────────────────────────────────────────────
  listTests: (suiteId: number): Promise<ApiTest[]> =>
    api.get(`${BASE}/suites/${suiteId}/tests`).then(r => r.data),

  createTest: (suiteId: number, data: {
    test_type: string
    name: string
    description?: string
    method?: string
    url: string
    headers?: Record<string, string>
    body?: string | null
    config?: Record<string, unknown>
  }): Promise<ApiTest> =>
    api.post(`${BASE}/suites/${suiteId}/tests`, data).then(r => r.data),

  bulkCreateTests: (suiteId: number, tests: SuggestedTest[]): Promise<{ ok: boolean; created: number }> =>
    api.post(`${BASE}/suites/${suiteId}/tests/bulk-create`, tests).then(r => r.data),

  runTest: (suiteId: number, testId: number): Promise<{ ok: boolean; test_id: number }> =>
    api.post(`${BASE}/suites/${suiteId}/tests/${testId}/run`).then(r => r.data),

  getResults: (suiteId: number, testId: number): Promise<ApiTestResult[]> =>
    api.get(`${BASE}/suites/${suiteId}/tests/${testId}/results`).then(r => r.data),

  clearResults: (suiteId: number, testId: number): Promise<{ ok: boolean }> =>
    api.delete(`${BASE}/suites/${suiteId}/tests/${testId}/results`).then(r => r.data),

  exportFinding: (suiteId: number, testId: number): Promise<{ ok: boolean; exported: number }> =>
    api.post(`${BASE}/suites/${suiteId}/tests/${testId}/export`).then(r => r.data),

  // ── Integrated fuzzer ─────────────────────────────────────────────────────
  fuzzSuite: (suiteId: number, data?: {
    session_id?: number | null
    analysis_id?: number | null
    attacks?: string[]
  }): Promise<{ ok: boolean; fuzz_job_id: number; endpoint_count: number }> =>
    api.post(`${BASE}/suites/${suiteId}/fuzz`, data ?? {}).then(r => r.data),
}
