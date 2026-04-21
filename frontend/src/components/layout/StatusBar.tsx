import { useDeviceStore } from '@/store/deviceStore'
import { useProxyStore } from '@/store/proxyStore'

export function StatusBar() {
  const session = useDeviceStore((s) => s.activeSession)
  const proxySessionId = useProxyStore((s) => s.sessionId)

  return (
    <footer className="h-6 flex items-center gap-4 px-4 bg-bg-surface border-t border-bg-border text-xs text-zinc-500 shrink-0">
      <span>
        Session:{' '}
        <span className={session ? 'text-green-400' : 'text-zinc-600'}>
          {session ? `#${session.id} active` : 'none'}
        </span>
      </span>
      <span>
        Proxy:{' '}
        <span className={proxySessionId ? 'text-accent' : 'text-zinc-600'}>
          {proxySessionId ? `port ${session?.proxy_port ?? '...'}` : 'stopped'}
        </span>
      </span>
      {session?.frida_attached && (
        <span className="text-yellow-400">Frida attached</span>
      )}
    </footer>
  )
}
