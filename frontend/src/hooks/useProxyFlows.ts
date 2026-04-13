import { useCallback } from 'react'
import { useWebSocket } from './useWebSocket'
import { useProxyStore } from '@/store/proxyStore'

export function useProxyFlows(sessionId: number | null) {
  const addFlow = useProxyStore((s) => s.addFlow)

  const onMessage = useCallback((data: unknown) => {
    const d = data as { type: string; data: unknown }
    if (d.type === 'flow_captured' && d.data) {
      addFlow(d.data as Parameters<typeof addFlow>[0])
    }
  }, [addFlow])

  useWebSocket(sessionId != null ? `/ws/proxy/${sessionId}` : null, onMessage)
}
