export interface ProxyFlow {
  id: string
  session_id: number
  timestamp: string
  method: string
  url: string
  host: string
  path: string
  request_headers: string
  response_status: number | null
  response_headers: string | null
  tls: boolean
  content_type: string | null
  duration_ms: number | null
  traffic_type?: 'web' | 'mobile' | 'ai_llm' | 'subsystem' | 'unknown'
}

export interface ProxyFlowDetail extends ProxyFlow {
  request_body: string | null
  response_body: string | null
}

export interface RepeaterResponse {
  status_code: number
  headers: Record<string, string>
  body: string
  duration_ms: number
}

export interface RaceResult {
  idx: number
  status: number
  length: number
  duration_ms: number
  body_snippet: string
  error: string
}

// ── Endpoint Map ─────────────────────────────────────────────────────────────

export type EndpointFlag = 'idor_candidate' | 'auth_required' | 'pii_likely' | 'sensitive_method'
export type ParamType = 'string' | 'integer' | 'uuid' | 'boolean'

export interface EndpointParam {
  name: string
  type: ParamType
  sample: string
}

export interface MappedEndpoint {
  pattern: string
  host: string
  methods: string[]
  sample_url: string
  auth_headers: string[]
  path_params: EndpointParam[]
  query_params: EndpointParam[]
  body_params: EndpointParam[]
  flags: EndpointFlag[]
  response_codes: number[]
  count: number
  feature: string | null
  first_seen: string
  last_seen: string
}

export interface EndpointMapStats {
  hosts: number
  endpoints: number
  idor_candidates: number
}

export interface EndpointMapResponse {
  session_id: number
  stats: EndpointMapStats
  map: Record<string, MappedEndpoint[]>
}

export interface RepeaterTab {
  id: string
  label: string
  method: string
  url: string
  headers: { key: string; value: string }[]
  body: string
  response: RepeaterResponse | null
  loading: boolean
  raceCount: number
  raceResults: RaceResult[]
  raceRunning: boolean
}
