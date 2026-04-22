import { useState } from 'react'
import { clsx } from 'clsx'
import { ShieldAlert, TestTube2, KeyRound, Radar, Wrench, Globe, Workflow, Search } from 'lucide-react'
import ScannerPage from '@/pages/ScannerPage'
import ApiTesting from '@/pages/ApiTesting'
import BruteForcePage from '@/pages/BruteForcePage'
import StrixPage from '@/pages/StrixPage'
import RepackagePage from '@/pages/RepackagePage'
import WsTestPage from '@/pages/WsTestPage'
import GraphqlPage from '@/pages/GraphqlPage'
import ReconPage from '@/pages/ReconPage'

const STORAGE_KEY = 'api-scanner-active-tab'

const TABS = [
  { id: 'scanner',   label: 'Scanner',      icon: ShieldAlert },
  { id: 'api',       label: 'API Testing',  icon: TestTube2 },
  { id: 'brute',     label: 'Brute Force',  icon: KeyRound },
  { id: 'ws',        label: 'WebSocket',    icon: Workflow },
  { id: 'graphql',   label: 'GraphQL',      icon: Globe },
  { id: 'recon',     label: 'Recon',        icon: Search },
  { id: 'repackage', label: 'Repackage',    icon: Wrench },
  { id: 'strix',     label: 'Strix Pentest',icon: Radar },
] as const

type TabId = typeof TABS[number]['id']

export default function ApiScannerPage() {
  const [active, setActive] = useState<TabId>(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    return (stored as TabId) ?? 'scanner'
  })

  const switchTab = (id: TabId) => {
    setActive(id)
    localStorage.setItem(STORAGE_KEY, id)
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Tab bar */}
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0 overflow-x-auto">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => switchTab(id)}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 whitespace-nowrap shrink-0',
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

      {/* Page content — keep all mounted so state is preserved */}
      <div className={clsx('flex-1 overflow-auto', active !== 'scanner' && 'hidden')}>
        <ScannerPage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'api' && 'hidden')}>
        <ApiTesting />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'brute' && 'hidden')}>
        <BruteForcePage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'ws' && 'hidden')}>
        <WsTestPage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'graphql' && 'hidden')}>
        <GraphqlPage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'recon' && 'hidden')}>
        <ReconPage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'repackage' && 'hidden')}>
        <RepackagePage />
      </div>
      <div className={clsx('flex-1 overflow-auto', active !== 'strix' && 'hidden')}>
        <StrixPage />
      </div>
    </div>
  )
}
