import { api } from './client'

export interface CTFScanRequest {
  target: string
  ports?: string
  scan_speed?: number
  launch_strix?: boolean
  strix_mode?: string
  run_default_scripts?: boolean
  run_vuln_scripts?: boolean
}

export interface PortInfo {
  port: number
  protocol: string
  state: string
  service: string
  version: string
  cpe?: string
}

export interface ServiceScope {
  port: number
  service: string
  severity: string
  version: string
  attacks: string[]
  flag_hints: string[]
  tools: string[]
  strix_scan_id?: number
}

export interface CTFScan {
  id: number
  target: string
  status: string
  ports_found?: number        // list response only
  ai_analysis?: string | null // metatron-qwen CTF analysis
  strix_targets?: string[]    // web targets passed to Strix
  phase: string
  open_ports: PortInfo[]
  scope: ServiceScope[]
  os_guess: string | null
  strix_scan_ids: number[]
  overall_strategy: string[]
  started_at: string | null
  completed_at: string | null
  error: string | null
}

export interface CTFScanStatus {
  id: number
  status: string
  phase: string
  ports_found: number
  strix_scan_ids: number[]
  error: string | null
}

export const ctfApi = {
  nmapStatus: () =>
    api.get('/ctf/nmap-status').then((r) => r.data as { available: boolean; hint: string | null }),

  startScan: (req: CTFScanRequest) =>
    api.post('/ctf/scan', req).then((r) => r.data as { id: number; status: string; target: string }),

  getScan: (id: number) =>
    api.get(`/ctf/scan/${id}`).then((r) => r.data as CTFScan),

  getScanStatus: (id: number) =>
    api.get(`/ctf/scan/${id}/status`).then((r) => r.data as CTFScanStatus),

  listScans: () =>
    api.get('/ctf/scans').then((r) => r.data as CTFScan[]),

  deleteScan: (id: number) =>
    api.delete(`/ctf/scan/${id}`).then((r) => r.data),

  clearAll: () =>
    api.delete('/ctf/scans').then((r) => r.data),
}
