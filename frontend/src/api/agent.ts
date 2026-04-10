import { api } from './client'
import type { AgentCommandResult, AgentStatus, AgentSetupResult, BuildStatus } from '@/types/agent'

export const agentApi = {
  run: (serial: string, command: string, args: Record<string, unknown> = {}, timeout = 60) =>
    api.post('/agent/run', { serial, command, args, timeout }).then((r) => r.data),
  history: (serial: string, params?: { skip?: number; limit?: number }) =>
    api.get<AgentCommandResult[]>('/agent/history', { params: { serial, ...params } }).then((r) => r.data),
  clearHistory: (serial: string) =>
    api.delete('/agent/history', { params: { serial } }).then((r) => r.data),
  commands: () =>
    api.get<{ commands: string[] }>('/agent/commands').then((r) => r.data),
  setup: (serial: string, apk_path?: string, start_service = true) =>
    api.post<AgentSetupResult>('/agent/setup', { serial, apk_path, start_service }).then((r) => r.data),
  startService: (serial: string) =>
    api.post<{ forwarded: boolean; started: boolean; reachable: boolean }>(`/agent/start-service`, null, { params: { serial } }).then((r) => r.data),
  status: (serial: string) =>
    api.get<AgentStatus>(`/agent/status/${serial}`).then((r) => r.data),
  buildApk: () =>
    api.post<{ status: string; message: string }>('/agent/build-apk').then((r) => r.data),
  buildStatus: (lastLine = 0) =>
    api.get<BuildStatus>('/agent/build-status', { params: { last_line: lastLine } }).then((r) => r.data),
}
