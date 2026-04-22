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
