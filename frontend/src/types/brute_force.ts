export interface BruteForceJob {
  id: number
  created_at: string
  target_url: string
  auth_type: string
  username_field: string
  password_field: string
  username: string
  concurrency: number
  rate_limit_rps: number
  status: 'pending' | 'running' | 'paused' | 'complete' | 'error'
  attempts_made: number
  credentials_found: string | null  // JSON: {username, password}[]
  error: string | null
}

export interface BruteForceAttempt {
  id: number
  job_id: number
  username: string
  password: string
  status_code: number | null
  success: boolean
  timestamp: string
}

export interface BruteForceJobCreate {
  target_url: string
  auth_type?: string
  username_field?: string
  password_field?: string
  username: string
  wordlist_path?: string
  concurrency?: number
  rate_limit_rps?: number
}

export interface DetectedEndpoint {
  url: string
  auth_type: string
  username_field: string
  password_field: string
  sample_body: string
  headers: Record<string, string>
}
