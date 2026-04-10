import { useQuery } from '@tanstack/react-query'
import { Smartphone, WifiOff, Zap, X } from 'lucide-react'
import { adbApi } from '@/api/adb'
import { fridaApi } from '@/api/frida'
import { useDeviceStore } from '@/store/deviceStore'
import { useFridaStore } from '@/store/fridaStore'

export function TopBar() {
  const { setDevices, devices } = useDeviceStore()
  const { attached, attachedPackage, attachedSerial, sessionId, detach } = useFridaStore()

  const handleDetach = async () => {
    try {
      await fridaApi.detach(sessionId)
    } catch { /* session may already be gone */ }
    detach()
  }

  useQuery({
    queryKey: ['devices'],
    queryFn: async () => {
      const devs = await adbApi.listDevices()
      setDevices(devs)
      return devs
    },
    refetchInterval: 5000,
  })

  const connected = devices.filter((d) => d.state === 'device')

  return (
    <header className="h-10 flex items-center justify-between px-4 bg-bg-surface border-b border-bg-border shrink-0">
      <span className="text-sm font-semibold tracking-wide text-blue-300">BluJay</span>
      <div className="flex items-center gap-3 text-xs text-zinc-400">
        {/* Persistent Frida session indicator */}
        {attached && attachedPackage && (
          <div className="flex items-center gap-1.5 bg-yellow-500/10 border border-yellow-500/20 rounded px-2 py-1">
            <Zap size={11} className="text-yellow-400" />
            <span className="text-yellow-400 font-mono">{attachedPackage}</span>
            <button
              onClick={handleDetach}
              className="ml-1 text-yellow-600 hover:text-yellow-300 transition-colors"
              title="Detach Frida"
            >
              <X size={11} />
            </button>
          </div>
        )}

        {connected.length > 0 ? (
          connected.map((d) => (
            <span key={d.serial} className="flex items-center gap-1 text-green-400">
              <Smartphone size={12} />
              {d.model || d.serial}
            </span>
          ))
        ) : (
          <span className="flex items-center gap-1 text-zinc-500">
            <WifiOff size={12} />
            No device
          </span>
        )}
      </div>
    </header>
  )
}
