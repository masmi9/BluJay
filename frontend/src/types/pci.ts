export type PciSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface NetworkCapture {
  method: string
  url: string
  is_https: boolean
  has_card_pattern: boolean
  post_data_snippet: string
}

export interface FlowStep {
  step: number
  action: string
  url: string
  description: string
  screenshot_b64: string | null
  elements_found: string[]
  notes: string
}

export interface PaymentFlowResult {
  url: string
  processor: string | null
  test_card: { number: string; exp: string; cvv: string; name: string } | null
  reached_payment_form: boolean
  steps: FlowStep[]
  network_captures: NetworkCapture[]
  error: string | null
}

export interface PciFinding {
  id: number
  job_id: number
  url: string
  host: string
  check_name: string
  severity: PciSeverity
  category: string
  phase: string | null
  title: string
  detail: string
  evidence: string | null
  evidence_json: string | null
  remediation: string | null
  pci_req: string | null
  port: number | null
  service: string | null
  cvss_score: number | null
  cve_ids: string | null   // JSON string
  plugin_id: string | null
  created_at: string
}

export interface PciScanJob {
  id: number
  target_urls: string[]
  scope_config: string | null
  categories: string[]
  scan_profile: string
  status: 'pending' | 'running' | 'done' | 'error'
  phase: string | null
  started_at: string | null
  finished_at: string | null
  finding_count: number
  hosts_found: number
  ports_open: number
  pages_crawled: number
  processors_detected: string[]
  flow_steps_count: number
  error: string | null
  created_at: string
}

export const PCI_SEVERITY_COLOR: Record<PciSeverity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low:      'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info:     'text-zinc-400 bg-zinc-500/10 border-zinc-500/20',
}

export const PCI_SEVERITY_ORDER: Record<PciSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export const PCI_CATEGORY_LABEL: Record<string, string> = {
  transport:        'Transport / TLS',
  headers:          'Security Headers',
  cookies:          'Cookies',
  forms:            'Payment Forms',
  'mixed-content':  'Mixed Content',
  data:             'Card Data',
  processor:        'Processors',
  integrity:        'Script Integrity',
  cors:             'CORS',
  ports:            'Open Ports',
  services:         'Services',
  vulnerability:    'Vulnerabilities',
  'brute-exposure': 'Brute Exposure',
  malware:          'Malware / Skimmer',
  network:          'Network',
  payment_flow:     'Payment Flow Test',
}

export const SCAN_PHASES = [
  { id: 'scope_resolution', label: 'Scope' },
  { id: 'host_discovery',   label: 'Discovery' },
  { id: 'port_scan',        label: 'Port Scan' },
  { id: 'vulnerability',    label: 'Vulns' },
  { id: 'brute_exposure',   label: 'Brute Exposure' },
  { id: 'web_crawl',        label: 'Crawl' },
  { id: 'web_checks',       label: 'Web Checks' },
  { id: 'malware',          label: 'Malware' },
  { id: 'payment_flow',     label: 'Pay Flow' },
  { id: 'report',           label: 'Report' },
]

export const TIKTOK_PRESETS = [
  { label: 'TikTok Ads', url: 'https://ads.tiktok.com' },
  { label: 'TikTok Promote', url: 'https://promote.tiktok.com' },
  { label: 'TikTok Live', url: 'https://live.tiktok.com' },
]

export const EXAMPLE_SCOPE_YAML = `scope:
  name: "TikTok CDE Assessment"
  scan_profile: "external_pci"
  targets:
    - type: url
      value: "https://ads.tiktok.com"
    - type: url
      value: "https://promote.tiktok.com"
    - type: url
      value: "https://live.tiktok.com"
  web:
    include_patterns: ["*/payment*","*/billing*","*/checkout*"]
    exclude_patterns: ["*/logout*","*/static/*"]
    max_depth: 3
    max_pages: 50
  ports:
    profile: "pci_standard"
  checks:
    host_discovery: true
    port_scan: true
    vulnerability: true
    web_scan: true
    brute_exposure: true
    malware: true
    tls: true`
