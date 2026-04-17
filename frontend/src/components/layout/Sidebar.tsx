import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Search, Radio, Zap, Terminal, Shield, FlaskConical, Settings, Lock, Key, KeyRound, Radar, Brain, TestTube2, GitCompare, Layers } from 'lucide-react'
import { clsx } from 'clsx'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/proxy', icon: Radio, label: 'Proxy' },
  { to: '/frida', icon: Zap, label: 'Frida' },
  { to: '/owasp', icon: Shield, label: 'OWASP Scanner' },
  { to: '/agent', icon: Terminal, label: 'Agent Console' },
  { to: '/tls', icon: Lock, label: 'TLS Audit' },
  { to: '/jwt', icon: Key, label: 'JWT Testing' },
  { to: '/api-testing', icon: TestTube2, label: 'API Testing' },
  { to: '/brute-force', icon: KeyRound, label: 'Brute Force' },
  { to: '/strix', icon: Radar, label: 'Strix Pentest' },
  { to: '/ai-triage', icon: Brain, label: 'AI Triage' },
  { to: '/diff', icon: GitCompare, label: 'Diff / Change Detection' },
  { to: '/campaigns', icon: Layers, label: 'Multi-APK Campaign' },
  { to: '/testing', icon: FlaskConical, label: 'Testing Lab' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export function Sidebar() {
  return (
    <aside className="w-14 flex flex-col items-center py-4 gap-1 bg-bg-surface border-r border-bg-border shrink-0 overflow-y-auto">
      <div className="mb-4 w-8 h-8 rounded-lg bg-accent flex items-center justify-center shrink-0">
        <Search size={16} className="text-white" />
      </div>
      {NAV.map(({ to, icon: Icon, label }) => (
        <NavLink
          key={to}
          to={to}
          title={label}
          className={({ isActive }) =>
            clsx(
              'w-10 h-10 flex items-center justify-center rounded-lg transition-colors shrink-0',
              isActive
                ? 'bg-accent text-white'
                : 'text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated'
            )
          }
        >
          <Icon size={18} />
        </NavLink>
      ))}
    </aside>
  )
}
