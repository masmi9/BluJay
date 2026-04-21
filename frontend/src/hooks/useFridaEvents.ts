import { useState, useCallback } from 'react'
import { useWebSocket } from './useWebSocket'
import type { FridaEvent } from '@/types/frida'

const MAX_EVENTS = 2000

export function useFridaEvents(sessionId: number | null) {
  const [events, setEvents] = useState<FridaEvent[]>([])

  const onMessage = useCallback((data: unknown) => {
    const d = data as { type: string; data: FridaEvent }
    if (d.type === 'frida_event' && d.data) {
      setEvents((prev) => {
        const next = [d.data, ...prev]
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next
      })
    }
  }, [])

  useWebSocket(sessionId !== null ? `/ws/frida/${sessionId}` : null, onMessage)

  const clear = useCallback(() => setEvents([]), [])

  return { events, clear }
}
