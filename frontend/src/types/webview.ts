export interface WebViewFinding {
  rule_id: string
  severity: string
  title: string
  file: string
  line: number
  evidence: string
}

export interface WebViewFile {
  index: number
  source: string
  path: string
  size_bytes: number
  findings: WebViewFinding[]
  bridge_methods: string[]
}

export interface WebViewScanResult {
  analysis_id: number
  files_found: number
  findings_count: number
  files: WebViewFile[]
}
