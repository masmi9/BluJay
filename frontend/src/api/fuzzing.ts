import { api } from './client'
import type { FuzzJob, FuzzJobCreate, FuzzJobDetail } from '@/types/fuzzing'

export const fuzzingApi = {
  createJob: (body: FuzzJobCreate) =>
    api.post<FuzzJob>('/fuzzing/jobs', body).then((r) => r.data),

  listJobs: () =>
    api.get<FuzzJob[]>('/fuzzing/jobs').then((r) => r.data),

  getJob: (id: number) =>
    api.get<FuzzJobDetail>(`/fuzzing/jobs/${id}`).then((r) => r.data),

  deleteJob: (id: number) =>
    api.delete(`/fuzzing/jobs/${id}`),
}
