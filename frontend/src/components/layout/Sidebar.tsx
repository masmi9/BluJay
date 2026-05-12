import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Search, Radio, Zap, Terminal, Shield, Settings, ShieldAlert, GitCompare, ClipboardCheck, CreditCard, Flag, ArrowLeftRight, KeyRound, AlertOctagon, Cloud, Network, Brain } from 'lucide-react'
import { clsx } from 'clsx'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/proxy', icon: Radio, label: 'Proxy' },
  { to: '/repeater', icon: ArrowLeftRight, label: 'Repeater' },
  { to: '/api-scanner', icon: ShieldAlert, label: 'API + Scanner' },
  { to: '/ctf', icon: Flag, label: 'CTF Mode' },
  { to: '/auth-tester', icon: KeyRound, label: 'Auth & Session Tester' },
  { to: '/vuln-intel', icon: AlertOctagon, label: 'Vulnerability Intelligence' },
  { to: '/cloud-tester', icon: Cloud, label: 'Cloud Tester' },
  { to: '/protocol-tester', icon: Network, label: 'Protocol Tester' },
  { to: '/ai-triage', icon: Brain, label: 'AI Triage' },
  { to: '/frida', icon: Zap, label: 'Frida' },
  { to: '/owasp', icon: Shield, label: 'OWASP Scanner' },
  { to: '/pci', icon: CreditCard, label: 'PCI DSS Scanner' },
  { to: '/agent', icon: Terminal, label: 'Agent Console' },
  { to: '/diff', icon: GitCompare, label: 'Diff / Change Detection' },
  { to: '/checklist', icon: ClipboardCheck, label: 'Testing Checklist' },
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
