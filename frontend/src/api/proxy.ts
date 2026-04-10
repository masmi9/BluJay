import { api } from './client'
import type { ProxyFlow, ProxyFlowDetail, RepeaterResponse } from '@/types/proxy'

export const proxyApi = {
  start: (sessionId: number = 0, port = 8080) =>
    api.post('/proxy/start', { session_id: sessionId, port }).then((r) => r.data),
  stop: (sessionId: number) => api.post(`/proxy/stop/${sessionId}`).then((r) => r.data),
  getFlows: (sessionId: number, params?: { skip?: number; limit?: number; method?: string; host?: string }) =>
    api.get<{ total: number; items: ProxyFlow[] }>('/proxy/flows', { params: { session_id: sessionId, ...params } }).then((r) => r.data),
  getFlow: (flowId: string) => api.get<ProxyFlowDetail>(`/proxy/flows/${flowId}`).then((r) => r.data),
  replay: (flowId: string) => api.post(`/proxy/flows/${flowId}/replay`).then((r) => r.data),
  clearFlows: (sessionId: number) =>
    api.delete('/proxy/flows', { params: { session_id: sessionId } }).then((r) => r.data),
  certUrl: () => '/api/v1/proxy/cert',
  configureDevice: (serial: string, host: string, port: number, pushCert = true) =>
    api.post('/proxy/configure-device', { serial, host, port, push_cert: pushCert }).then((r) => r.data),
  unconfigureDevice: (serial: string) =>
    api.post('/proxy/unconfigure-device', null, { params: { serial } }).then((r) => r.data),
  repeater: (method: string, url: string, headers: Record<string, string>, body: string) =>
    api.post<RepeaterResponse>('/proxy/repeater', { method, url, headers, body }).then((r) => r.data),
  getLocalIp: () =>
    api.get<{ local_ip: string; all_ips: string[] }>('/proxy/local-ip').then((r) => r.data),
  startCertServer: (port = 8888) =>
    api.post<{ port: number; running: boolean }>('/proxy/cert-server/start', null, { params: { port } }).then((r) => r.data),
  stopCertServer: () =>
    api.post<{ running: boolean }>('/proxy/cert-server/stop').then((r) => r.data),
  certServerStatus: () =>
    api.get<{ running: boolean }>('/proxy/cert-server/status').then((r) => r.data),
  certQrUrl: (url: string) => `/api/v1/proxy/cert-qr?url=${encodeURIComponent(url)}`,
}
