import { api } from './client'
import type { IosDeviceInfo } from '@/types/adb'

export interface IosAppInfo {
  bundle_id: string
  version: string
  name: string
}

export const iosApi = {
  listDevices: () => api.get<IosDeviceInfo[]>('/ios-devices').then((r) => r.data),
  listApps: (udid: string) => api.get<IosAppInfo[]>(`/ios-devices/${udid}/apps`).then((r) => r.data),
  pullIpa: (udid: string, bundle_id: string) =>
    api.post<{ ipa_path: string }>('/ios-devices/pull-ipa', { udid, bundle_id }).then((r) => r.data),
  pullAndAnalyze: (udid: string, bundle_id: string) =>
    api.post<{ id: number; status: string; platform: string }>('/ios-devices/pull-and-analyze', { udid, bundle_id }).then((r) => r.data),
  uploadIpa: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api.post<{ id: number; status: string }>('/ipa', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then((r) => r.data)
  },
  startOwaspScan: (params: { udid: string; bundleId: string; ipaPath: string; analysisId?: number }) =>
    api.post<{ id: number; status: string }>('/owasp', {
      apk_path: params.ipaPath,
      package_name: params.bundleId,
      mode: 'deep',
      platform: 'ios',
      analysis_id: params.analysisId,
      device_udid: params.udid,
    }).then((r) => r.data),
  getPlist: (analysisId: number) =>
    api.get<Record<string, unknown>>(`/ipa/${analysisId}/plist`).then((r) => r.data),
}
