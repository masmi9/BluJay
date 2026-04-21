import { useState, useCallback } from 'react'
import { useWebSocket } from './useWebSocket'
import type { LogcatLine } from '@/types/adb'

const MAX_LINES = 5000

export function useLogcat(sessionId: number | null) {
  const [lines, setLines] = useState<LogcatLine[]>([])

  const onMessage = useCallback((data: unknown) => {
    const d = data as LogcatLine & { type?: string }
    if (d.level) {
      setLines((prev) => {
        const next = [...prev, d]
        return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next
      })
    }
  }, [])

  useWebSocket(sessionId ? `/ws/logcat/${sessionId}` : null, onMessage)

  const clear = useCallback(() => setLines([]), [])

  return { lines, clear }
}
