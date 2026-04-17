import { api } from './client'

export interface CampaignTarget {
  id: number
  apk_filename: string
  analysis_id: number | null
  status: string
  error: string | null
}

export interface CampaignOut {
  id: number
  created_at: string
  name: string
  description: string | null
  platform: string
  status: string
  targets: CampaignTarget[]
}

export interface CampaignSummary {
  id: number
  created_at: string
  name: string
  platform: string
  status: string
  total: number
  complete: number
  failed: number
}

export const campaignApi = {
  create: (name: string, description?: string, platform = 'android') =>
    api.post<CampaignOut>('/campaigns', { name, description, platform }).then((r) => r.data),

  list: () => api.get<CampaignSummary[]>('/campaigns').then((r) => r.data),

  get: (id: number) => api.get<CampaignOut>(`/campaigns/${id}`).then((r) => r.data),

  addTarget: (campaignId: number, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api.post<CampaignOut>(`/campaigns/${campaignId}/targets`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then((r) => r.data)
  },

  run: (id: number) => api.post<CampaignOut>(`/campaigns/${id}/run`).then((r) => r.data),

  delete: (id: number) => api.delete(`/campaigns/${id}`),
}
