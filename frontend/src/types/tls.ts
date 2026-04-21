export interface TlsAudit {
  id: number
  host: string
  port: number
  session_id: number | null
  analysis_id: number | null
  audited_at: string
  status: string
  cert_subject: string | null
  cert_issuer: string | null
  cert_expiry: string | null
  cert_self_signed: boolean | null
  tls10_enabled: boolean
  tls11_enabled: boolean
  tls12_enabled: boolean
  tls13_enabled: boolean
  hsts_present: boolean
  weak_ciphers: string | null   // JSON string: string[]
  findings_json: string | null  // JSON string: {severity, title}[]
  error: string | null
}

export interface TlsAuditRequest {
  hosts: string[]
  session_id?: number
  analysis_id?: number
  port?: number
}

export interface TlsFinding {
  severity: string
  title: string
}
