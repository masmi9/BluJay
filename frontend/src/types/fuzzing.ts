export interface FuzzJob {
  id: number
  created_at: string
  session_id: number | null
  analysis_id: number | null
  status: 'pending' | 'running' | 'complete' | 'error'
  attacks: string | null   // JSON string: string[]
  endpoint_count: number
  result_summary: string | null
  error: string | null
}

export interface FuzzResult {
  id: number
  job_id: number
  attack_type: string
  method: string
  url: string
  response_status: number | null
  response_body: string | null
  duration_ms: number | null
  is_interesting: boolean
  notes: string | null
}

export interface FuzzJobDetail extends FuzzJob {
  results: FuzzResult[]
}

export interface FuzzJobCreate {
  session_id?: number
  analysis_id?: number
  attacks: string[]
  endpoint_filter?: string
  base_url?: string
}
