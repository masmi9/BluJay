import { useState } from 'react'
import { Flag, Target } from 'lucide-react'
import { clsx } from 'clsx'
import CTFPage from '@/pages/CTFPage'
import BugBountyPage from '@/pages/BugBountyPage'

const TABS = [
  { id: 'ctf',        label: 'CTF Mode',        icon: Flag,   color: 'border-yellow-400 text-yellow-400' },
  { id: 'bugbounty',  label: 'Bug Bounty Hunt',  icon: Target, color: 'border-orange-400 text-orange-400' },
] as const

type TabId = typeof TABS[number]['id']
const STORAGE_KEY = 'hunt-active-tab'

export default function HuntPage() {
  const [active, setActive] = useState<TabId>(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    return (stored === 'ctf' || stored === 'bugbounty') ? stored : 'ctf'
  })

  const switchTab = (id: TabId) => {
    setActive(id)
    localStorage.setItem(STORAGE_KEY, id)
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        {TABS.map(({ id, label, icon: Icon, color }) => (
          <button
            key={id}
            onClick={() => switchTab(id)}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors',
              active === id ? color : 'border-transparent text-zinc-500 hover:text-zinc-300'
            )}
          >
            <Icon size={12} /> {label}
          </button>
        ))}
      </div>

      <div className={clsx('flex-1 overflow-hidden', active !== 'ctf' && 'hidden')}>
        <CTFPage />
      </div>
      <div className={clsx('flex-1 overflow-hidden', active !== 'bugbounty' && 'hidden')}>
        <BugBountyPage />
      </div>
    </div>
  )
}
