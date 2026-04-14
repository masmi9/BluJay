export interface AuthContext {
  id: number
  label: string
  header_name: string
  header_value: string
  first_seen_url: string
}

export interface ApiTestSuite {
  id: number
  name: string
  target_app: string | null
  platform: string
  status: 'building' | 'ready' | 'running' | 'complete'
  flow_count: number
  session_id: number | null
  analysis_id: number | null
  auth_contexts: AuthContext[]
  collected_ids: Record<string, Record<string, string[]>>
  test_count: number
}

export type TestType = 'idor_sweep' | 'auth_strip' | 'token_replay' | 'cross_user_auth'

export interface ApiTest {
  id: number
  suite_id: number
  test_type: TestType
  name: string
  description: string | null
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  config: Record<string, unknown>
  status: 'pending' | 'running' | 'complete' | 'failed'
  run_count: number
  vulnerable_count: number
  result_count: number
}

export interface ApiTestResult {
  id: number
  test_id: number
  label: string | null
  request_method: string | null
  request_url: string | null
  request_headers: Record<string, string>
  request_body: string | null
  response_status: number | null
  response_headers: Record<string, string>
  response_body: string | null
  duration_ms: number | null
  is_vulnerable: boolean
  finding: string | null
  severity: string | null
  diff_summary: string | null
}

export interface SuggestedTest {
  test_type: TestType
  name: string
  description: string
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  config: Record<string, unknown>
}

export interface ImportFlowsResult {
  ok: boolean
  flow_count: number
  auth_contexts: AuthContext[]
  collected_ids: Record<string, Record<string, string[]>>
  suggested_tests: SuggestedTest[]
}

export interface WsTestEvent {
  type: 'progress' | 'result' | 'waiting' | 'done' | 'error' | 'ping'
  message?: string
  label?: string
  status?: number
  vulnerable?: boolean
  token_valid?: boolean
}
