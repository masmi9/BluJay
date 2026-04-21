import { api } from './client'
import type { Analysis, StaticFinding, PermissionInfo, ParsedManifest, SourceEntry } from '@/types/analysis'

export const analysisApi = {
  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api.post<Analysis>('/analyses', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then((r) => r.data)
  },
  fromDevice: (serial: string, pkg: string) =>
    api.post<Analysis>('/analyses/from-device', { serial, package: pkg }).then((r) => r.data),
  list: () => api.get<Analysis[]>('/analyses').then((r) => r.data),
  get: (id: number) => api.get<Analysis>(`/analyses/${id}`).then((r) => r.data),
  delete: (id: number) => api.delete(`/analyses/${id}`),
  reanalyze: (id: number) => api.post<Analysis>(`/analyses/${id}/reanalyze`).then((r) => r.data),
  getManifest: (id: number) => api.get<ParsedManifest>(`/analyses/${id}/manifest`).then((r) => r.data),
  getPermissions: (id: number) => api.get<PermissionInfo[]>(`/analyses/${id}/permissions`).then((r) => r.data),
  getFindings: (id: number, params?: { severity?: string; category?: string; skip?: number; limit?: number }) =>
    api.get<{ total: number; items: StaticFinding[] }>(`/analyses/${id}/findings`, { params }).then((r) => r.data),
  listSource: (id: number, path = '') =>
    api.get<SourceEntry[]>(`/analyses/${id}/source`, { params: { path } }).then((r) => r.data),
  readFile: (id: number, path: string) =>
    api.get<{ path: string; content: string }>(`/analyses/${id}/source/file`, { params: { path } }).then((r) => r.data),
}
