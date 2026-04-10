export interface JwtDecodeResult {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  alg_none_token: string
  kid_tokens: string[]
  role_tokens: string[]
}

export interface JwtTestOut {
  id: number
  created_at: string
  session_id: number | null
  analysis_id: number | null
  raw_token: string
  decoded_header: string | null
  decoded_payload: string | null
  alg_none_token: string | null
  hmac_secret_found: string | null
  rs256_hs256_token: string | null
  kid_injection_payloads: string | null
  role_escalation_tokens: string | null
  notes: string | null
}

export interface JwtBruteForceResult {
  found: boolean
  secret: string | null
  tested_count: number
  error?: string
}
