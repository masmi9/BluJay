import { api } from './client'
import type { AccuracyDashboard, TestApp, TestRun } from '@/types/testing'

export const testingApi = {
  // Apps
  listApps: () => api.get<TestApp[]>('/testing/apps').then((r) => r.data),
  getApp: (id: number) => api.get<TestApp & { runs: TestRun[] }>(`/testing/apps/${id}`).then((r) => r.data),
  createApp: (body: { display_name: string; package_name: string; apk_path?: string; category?: string; description?: string; is_vulnerable_app?: boolean }) =>
    api.post<TestApp>('/testing/apps', body).then((r) => r.data),
  deleteApp: (id: number) => api.delete(`/testing/apps/${id}`),

  // Runs
  createRun: (body: {
    test_app_id: number
    analysis_id?: number
    owasp_scan_id?: number
    frida_script_name?: string
    frida_script_source?: string
    findings?: unknown[]
    notes?: string
  }) => api.post<TestRun>('/testing/runs', body).then((r) => r.data),
  getRun: (id: number) => api.get<TestRun>(`/testing/runs/${id}`).then((r) => r.data),
  updateAccuracy: (id: number, tp: number, fp: number, fn: number, notes?: string) =>
    api.patch<TestRun>(`/testing/runs/${id}/accuracy`, { true_positives: tp, false_positives: fp, false_negatives: fn, notes }).then((r) => r.data),
  deleteRun: (id: number) => api.delete(`/testing/runs/${id}`),

  // Accuracy dashboard
  accuracy: () => api.get<AccuracyDashboard>('/testing/accuracy').then((r) => r.data),

  // Reproduction builder
  buildReproduction: (findings: unknown[]) =>
    api.post<{ steps: unknown[] }>('/testing/reproduce', { findings }).then((r) => r.data),
}
