const BASE = '/api/v1/red-team'

export interface InjectRequest {
  analysis_id: number
  lhost: string
  lport: number
  payload: string
}

export interface InjectResult {
  job_id: string
  filename: string
  download_url: string
  listener_rc_url: string
  lhost: string
  lport: number
  payload: string
}

export interface GhostSession {
  session_id: string
  device_id: string
  status: string
}

export const redTeamApi = {
  async payloads(): Promise<{ payloads: string[] }> {
    const r = await fetch(`${BASE}/payloads`)
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  },

  async ghostConnect(deviceId: string): Promise<GhostSession> {
    const r = await fetch(`${BASE}/ghost/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId }),
    })
    if (!r.ok) {
      const body = await r.json().catch(() => ({ detail: r.statusText }))
      throw new Error(body.detail ?? r.statusText)
    }
    return r.json()
  },

  async ghostCommand(sessionId: string, command: string): Promise<void> {
    const r = await fetch(`${BASE}/ghost/command`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, command }),
    })
    if (!r.ok) throw new Error(await r.text())
  },

  async ghostOutput(sessionId: string): Promise<{ lines: string[] }> {
    const r = await fetch(`${BASE}/ghost/output/${sessionId}`)
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  },

  async ghostDisconnect(sessionId: string): Promise<void> {
    await fetch(`${BASE}/ghost/${sessionId}`, { method: 'DELETE' })
  },

  async inject(req: InjectRequest): Promise<InjectResult> {
    const r = await fetch(`${BASE}/inject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    })
    if (!r.ok) {
      const body = await r.json().catch(() => ({ detail: r.statusText }))
      throw new Error(body.detail ?? r.statusText)
    }
    return r.json()
  },
}
