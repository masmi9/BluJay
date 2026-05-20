export type ProtocolType = 'openai_compat' | 'mcp' | 'a2a' | 'rest'
export type ProbeCategory = 'infra' | 'prompt_injection'
export type ScanStatus = 'pending' | 'running' | 'complete' | 'error' | 'cancelled'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface AIAgentScan {
  id: number
  status: ScanStatus
  target_url: string
  protocol_type: ProtocolType
  probe_categories: ProbeCategory[]
  finding_count: number
  session_id: number | null
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  error: string | null
  created_at: string | null
}

export interface AIAgentFinding {
  id: number
  scan_id: number
  category: string
  severity: Severity
  title: string
  detail: string
  evidence: string | null
  probe_id: string
  request_payload: string | null
  raw_response: string | null
  confirmed: boolean
  timestamp: string | null
}

export interface AIAgentScanWithFindings extends AIAgentScan {
  findings: AIAgentFinding[]
}
