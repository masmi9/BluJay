import { api } from './client'

export interface ObjectionSession {
  session_id: string
  gadget: string
  running: boolean
}

export const objectionApi = {
  start: (gadget: string, deviceSerial?: string) =>
    api.post<ObjectionSession>('/objection/sessions', { gadget, device_serial: deviceSerial ?? null })
      .then((r) => r.data),

  stop: (sessionId: string) =>
    api.delete(`/objection/sessions/${sessionId}`).then((r) => r.data),

  sendCommand: (sessionId: string, command: string) =>
    api.post(`/objection/sessions/${sessionId}/command`, { command }).then((r) => r.data),

  listSessions: () =>
    api.get<ObjectionSession[]>('/objection/sessions').then((r) => r.data),
}
