export type AnalysisStatus = 'pending' | 'decompiling' | 'analyzing' | 'complete' | 'failed'

export interface Analysis {
  id: number
  created_at: string
  apk_filename: string
  apk_sha256: string
  package_name: string | null
  version_name: string | null
  version_code: number | null
  min_sdk: number | null
  target_sdk: number | null
  platform: string
  bundle_id: string | null
  min_ios_version: string | null
  status: AnalysisStatus
  error_message: string | null
  decompile_path: string | null
  jadx_path: string | null
}

export interface StaticFinding {
  id: number
  analysis_id: number
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  file_path: string | null
  line_number: number | null
  evidence: string | null
  rule_id: string | null
  impact: string | null
  attack_path: string | null
}

export interface PermissionInfo {
  name: string
  short_name: string
  protection_level: string
  description: string
  risk: 'none' | 'low' | 'medium' | 'high' | 'critical'
}

export interface ComponentInfo {
  name: string
  type: 'activity' | 'service' | 'receiver' | 'provider'
  exported: boolean
  permission: string | null
  intent_filters: Array<{ actions: string[]; categories: string[] }>
}

export interface ParsedManifest {
  package_name: string
  version_name: string | null
  version_code: number | null
  min_sdk: number | null
  target_sdk: number | null
  debuggable: boolean
  allow_backup: boolean
  network_security_config: boolean
  uses_cleartext_traffic: boolean | null
  permissions: string[]
  components: ComponentInfo[]
}

export interface SourceEntry {
  path: string
  is_dir: boolean
  size: number | null
}
