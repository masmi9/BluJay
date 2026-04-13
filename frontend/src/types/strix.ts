export interface StrixScan {
  id: number
  created_at: string
  updated_at: string | null
  session_id: number | null
  target: string
  scan_mode: 'quick' | 'standard' | 'deep'
  instruction: string | null
  llm_model: string
  status: 'pending' | 'running' | 'complete' | 'error' | 'cancelled'
  run_name: string | null
  vuln_count: number | null
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | null
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  error: string | null
}

export interface StrixFinding {
  title?: string
  name?: string
  severity?: string
  description?: string
  remediation?: string
  [key: string]: unknown
}

export interface StrixScanResults extends StrixScan {
  findings: StrixFinding[]
  summary: string
  run_dir: string | null
}

export interface StartScanRequest {
  target: string
  session_id?: number
  scan_mode?: 'quick' | 'standard' | 'deep'
  instruction?: string
  llm_model?: string
  ollama_base?: string
  auto_triage?: boolean
}

export interface StrixStatus {
  strix_installed: boolean
  docker_running: boolean
  ready: boolean
  hints: string[]
}
