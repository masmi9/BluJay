const BASE = '/api/v1/mobsf'

export interface MobSFStatus {
  reachable: boolean
  url: string
}

export interface MobSFScanResult {
  scan_hash: string
  scan_type: string
  summary: Record<string, unknown>
}

export const mobsfApi = {
  async status(): Promise<MobSFStatus> {
    const r = await fetch(`${BASE}/status`)
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  },

  async scan(analysisId: number): Promise<MobSFScanResult> {
    const r = await fetch(`${BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_id: analysisId }),
    })
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  },

  async report(scanHash: string): Promise<Record<string, unknown>> {
    const r = await fetch(`${BASE}/report/${scanHash}`)
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  },
}
