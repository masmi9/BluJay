import { api } from './client'
import type { DeviceInfo, DynamicSession } from '@/types/adb'

export const adbApi = {
  listDevices: () => api.get<DeviceInfo[]>('/devices').then((r) => r.data),
  install: (serial: string, apkPath: string) =>
    api.post(`/devices/${serial}/install`, null, { params: { apk_path: apkPath } }).then((r) => r.data),
  launch: (serial: string, packageName: string, activity?: string) =>
    api.post(`/devices/${serial}/launch`, { package_name: packageName, activity }).then((r) => r.data),
  listPackages: (serial: string, thirdPartyOnly = true) =>
    api.get<Array<{ package: string; apk_path: string; third_party: boolean }>>(
      `/devices/${serial}/packages`,
      { params: { third_party_only: thirdPartyOnly } }
    ).then((r) => r.data),
  setProxy: (serial: string, host: string, port: number) =>
    api.post(`/devices/${serial}/proxy/set`, null, { params: { host, port } }).then((r) => r.data),
  clearProxy: (serial: string) => api.post(`/devices/${serial}/proxy/clear`).then((r) => r.data),
}

export const sessionApi = {
  create: (params: {
    analysisId?: number
    deviceSerial: string
    packageName: string
    platform?: 'android' | 'ios'
  }) =>
    api.post<DynamicSession>('/sessions', {
      analysis_id: params.analysisId,
      device_serial: params.deviceSerial,
      package_name: params.packageName,
      platform: params.platform ?? 'android',
    }).then((r) => r.data),
  get: (id: number) => api.get<DynamicSession>(`/sessions/${id}`).then((r) => r.data),
  stop: (id: number) => api.delete(`/sessions/${id}`),
}
