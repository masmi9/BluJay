import { useEffect, useRef, useCallback, useState } from 'react'

export function useWebSocket(url: string | null, onMessage?: (data: unknown) => void) {
  const wsRef = useRef<WebSocket | null>(null)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage
  const [lastMessage, setLastMessage] = useState<string | null>(null)

  const connect = useCallback(() => {
    if (!url) return
    const ws = new WebSocket(`ws://${window.location.host}${url}`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type !== 'ping') {
          setLastMessage(event.data)
          onMessageRef.current?.(data)
        }
      } catch {}
    }

    ws.onclose = () => {
      // Reconnect after 2s
      setTimeout(connect, 2000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      wsRef.current?.close()
    }
  }, [connect])

  return { lastMessage }
}
