export interface OllamaAnalysis {
  id: number
  created_at: string
  session_id: number | null
  source: string
  status: 'pending' | 'running' | 'complete' | 'error'
  model_used: string
  ai_response: string | null
  error: string | null
  duration_ms: number | null
}

export interface AnalyzeRequest {
  scan_data: string
  source?: string
  session_id?: number
  model?: string
  extra_context?: string
}

export interface OllamaStatus {
  ollama_running: boolean
  model_available: boolean
  available_models: string[]
  default_model: string
  error?: string
  hint: string | null
}
