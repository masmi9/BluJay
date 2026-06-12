const BASE = '/api/v1/playstore'

export interface PlayStoreDownloadRequest {
  package_name: string
  email?: string
  password?: string
}

export const playstoreApi = {
  async download(req: PlayStoreDownloadRequest): Promise<{ id: number }> {
    const r = await fetch(`${BASE}`, {
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
