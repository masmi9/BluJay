import { api } from './client'
import type { WebViewScanResult } from '@/types/webview'

export const webviewApi = {
  scan: (analysisId: number) =>
    api.post<WebViewScanResult>(`/webview/scan/${analysisId}`).then((r) => r.data),

  getFiles: (analysisId: number) =>
    api.get<WebViewScanResult>(`/webview/${analysisId}/files`).then((r) => r.data),

  getContent: (analysisId: number, index: number) =>
    api.get<{ content: string }>(`/webview/${analysisId}/files/${index}/content`).then((r) => r.data.content),
}
