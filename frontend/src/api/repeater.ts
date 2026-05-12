import { api } from './client'

export interface ReplaceRule {
  find: string
  replace: string
  target: 'url' | 'headers' | 'body' | 'all'
}

export interface RepeaterRequest {
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  follow_redirects: boolean
  verify_ssl: boolean
  timeout: number
  save: boolean
  rules: ReplaceRule[]
}

export interface RepeaterResponse {
  status_code: number
  reason: string
  headers: Record<string, string>
  body: string
  elapsed_ms: number
  size_bytes: number
  url: string
  redirects: string[]
}

export interface RepeaterResult {
  id: number | null
  request: RepeaterRequest
  response: RepeaterResponse
}

export interface HistoryEntry {
  id: number
  saved_at: string
  method: string
  url: string
  status: number
  elapsed_ms: number
  size_bytes: number
}

export interface HistoryEntryFull {
  id: number
  saved_at: string
  request: RepeaterRequest
  response: RepeaterResponse
}

export const repeaterApi = {
  send: (req: RepeaterRequest) =>
    api.post('/repeater/send', req).then((r) => r.data as RepeaterResult),

  sendRaw: (raw: string, base_url?: string, rules?: ReplaceRule[]) =>
    api.post('/repeater/raw', { raw, base_url, rules: rules ?? [], save: true })
      .then((r) => r.data as RepeaterResult),

  listHistory: () =>
    api.get('/repeater/history').then((r) => r.data as HistoryEntry[]),

  getEntry: (id: number) =>
    api.get(`/repeater/history/${id}`).then((r) => r.data as HistoryEntryFull),

  saveEntry: (request: object, response: object) =>
    api.post('/repeater/history', { request, response }).then((r) => r.data),

  deleteEntry: (id: number) =>
    api.delete(`/repeater/history/${id}`).then((r) => r.data),

  clearHistory: () =>
    api.delete('/repeater/history').then((r) => r.data),
}
