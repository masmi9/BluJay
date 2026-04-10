import { api } from './client'
import type { BruteForceJob, BruteForceAttempt, BruteForceJobCreate, DetectedEndpoint } from '@/types/brute_force'

export const bruteForceApi = {
  detect: (sessionId: number) =>
    api.post<DetectedEndpoint[]>('/brute-force/detect', { session_id: sessionId }).then((r) => r.data),

  createJob: (body: BruteForceJobCreate) =>
    api.post<BruteForceJob>('/brute-force/jobs', body).then((r) => r.data),

  listJobs: () =>
    api.get<BruteForceJob[]>('/brute-force/jobs').then((r) => r.data),

  getJob: (id: number) =>
    api.get<BruteForceJob>(`/brute-force/jobs/${id}`).then((r) => r.data),

  pause: (id: number) =>
    api.post<BruteForceJob>(`/brute-force/jobs/${id}/pause`).then((r) => r.data),

  resume: (id: number) =>
    api.post<BruteForceJob>(`/brute-force/jobs/${id}/resume`).then((r) => r.data),

  getAttempts: (id: number, page = 1, successOnly = false) =>
    api.get<BruteForceAttempt[]>(`/brute-force/jobs/${id}/attempts`, {
      params: { page, success_only: successOnly },
    }).then((r) => r.data),
}
