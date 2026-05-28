export type IDORConfidence = 'high' | 'medium' | 'low'
export type IDORMode = 'second_user' | 'unauthenticated'

export interface IDORFinding {
  id: string
  timestamp: string
  url: string
  method: string
  victim_status: number
  attacker_status: number
  confidence: IDORConfidence
  detail: string
  victim_snippet: string
  attacker_snippet: string
  attacker_mode: IDORMode
}

export interface IDORStats {
  enabled: boolean
  queue_depth: number
  tested: number
  findings: number
  has_attacker_auth: boolean
  has_victim_auth: boolean
}

export interface IDORConfig {
  enabled: boolean
  victim_auth: string
  victim_auth_header: string
  attacker_auth: string
  attacker_auth_header: string
  cooldown_seconds: number
  test_unauthenticated: boolean
}
