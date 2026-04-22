import { useState } from 'react'
import { clsx } from 'clsx'
import { Lock, Key, Brain } from 'lucide-react'
import TlsAuditPage from '@/pages/TlsAuditPage'
import JwtPage from '@/pages/JwtPage'
import AiTriagePage from '@/pages/AiTriagePage'

const STORAGE_KEY = 'decode-active-tab'

const TABS = [
  { id: 'tls',   label: 'TLS Audit',  icon: Lock },
  { id: 'jwt',   label: 'JWT Testing', icon: Key },
  { id: 'triage',label: 'AI Triage',  icon: Brain },
] as const

type TabId = typeof TABS[number]['id']

export default function DecodePage() {
  const [active, setActive] = useState<TabId>(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    return (stored as TabId) ?? 'tls'
  })

  const switchTab = (id: TabId) => {
    setActive(id)
    localStorage.setItem(STORAGE_KEY, id)
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Tab bar */}
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => switchTab(id)}
            className={clsx(
              'flex items-center gap-1.5 px-5 py-2.5 text-xs font-medium transition-colors border-b-2',
              active === id
                ? 'text-zinc-100 border-accent'
                : 'text-zinc-500 border-transparent hover:text-zinc-300 hover:border-zinc-600'
            )}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </div>

      {/* Keep all mounted so state is preserved */}
      <div className={clsx('flex-1 overflow-hidden', active !== 'tls' && 'hidden')}>
        <TlsAuditPage />
      </div>
      <div className={clsx('flex-1 overflow-hidden', active !== 'jwt' && 'hidden')}>
        <JwtPage />
      </div>
      <div className={clsx('flex-1 overflow-hidden', active !== 'triage' && 'hidden')}>
        <AiTriagePage />
      </div>
    </div>
  )
}
