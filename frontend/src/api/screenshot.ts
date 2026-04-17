import { api } from './client'
import type { Screenshot, CaptureRequest } from '@/types/screenshot'

export const screenshotApi = {
  capture: (body: CaptureRequest & { platform?: string }) =>
    api.post<Screenshot>('/screenshots/capture', body).then((r) => r.data),

  list: (sessionId: number) =>
    api.get<Screenshot[]>('/screenshots', { params: { session_id: sessionId } }).then((r) => r.data),

  imageUrl: (id: number) => `/api/v1/screenshots/${id}/image`,

  delete: (id: number) => api.delete(`/screenshots/${id}`),
}
