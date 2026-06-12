import { api } from './client'
import type { FridaScriptInfo, FridaEvent, FridaProcess } from '@/types/frida'

export const fridaApi = {
  listScripts: () => api.get<FridaScriptInfo[]>('/frida/scripts').then((r) => r.data),
  attach: (sessionId: number, deviceSerial: string, packageName: string) =>
    api.post('/frida/sessions', { session_id: sessionId, device_serial: deviceSerial, package_name: packageName }).then((r) => r.data),
  detach: (sessionId: number) => api.delete(`/frida/sessions/${sessionId}`).then((r) => r.data),
  loadBuiltin: (sessionId: number, builtinName: string) =>
    api.post(`/frida/sessions/${sessionId}/scripts`, { builtin_name: builtinName }).then((r) => r.data),
  loadCustom: (sessionId: number, source: string) =>
    api.post(`/frida/sessions/${sessionId}/scripts`, { source }).then((r) => r.data),
  unloadScript: (sessionId: number, scriptId: string) =>
    api.delete(`/frida/sessions/${sessionId}/scripts/${scriptId}`).then((r) => r.data),
  getEvents: (sessionId: number, params?: { skip?: number; limit?: number }) =>
    api.get<{ total: number; items: FridaEvent[] }>('/frida/events', { params: { session_id: sessionId, ...params } }).then((r) => r.data),
  processes: (serial: string) =>
    api.get<FridaProcess[]>(`/frida/processes/${serial}`).then((r) => r.data),
  spawnAttach: (sessionId: number, deviceSerial: string, packageName: string, startupScript?: string) =>
    api.post('/frida/sessions/spawn', { session_id: sessionId, device_serial: deviceSerial, package_name: packageName, startup_script: startupScript ?? null }).then((r) => r.data),
  codeshareSearch: (q: string, page = 1) =>
    api.get<{ results: CodeshareProject[]; next: string | null }>('/frida/codeshare/search', { params: { q, page } }).then((r) => r.data),
  codeshareScript: (project: string) =>
    api.get<{ project: string; source: string; title: string }>('/frida/codeshare/script', { params: { project } }).then((r) => r.data),
}

export interface CodeshareProject {
  slug: string
  title: string
  description: string
  author: string
  tag_line?: string
}
