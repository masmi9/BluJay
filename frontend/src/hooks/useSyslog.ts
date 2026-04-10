import { useState, useEffect, useRef } from 'react'

export interface SyslogLine {
  ts: string
  message: string
}

const MAX_LINES = 2000

export function useSyslog(sessionId: number | null) {
  const [lines, setLines] = useState<SyslogLine[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!sessionId) return

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/syslog/${sessionId}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'ping') return
        if (msg.ts && msg.message) {
          setLines((prev) => {
            const next = [...prev, msg as SyslogLine]
            return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
          })
        }
      } catch {
        // ignore malformed frames
      }
    }

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [sessionId])

  const clear = () => setLines([])

  return { lines, clear }
}
