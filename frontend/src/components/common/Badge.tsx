import { clsx } from 'clsx'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD'

const SEVERITY_CLASSES: Record<Severity, string> = {
  critical: 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30',
  high: 'bg-severity-high/20 text-severity-high border border-severity-high/30',
  medium: 'bg-severity-medium/20 text-severity-medium border border-severity-medium/30',
  low: 'bg-severity-low/20 text-severity-low border border-severity-low/30',
  info: 'bg-severity-info/20 text-severity-info border border-severity-info/30',
}

const METHOD_CLASSES: Record<string, string> = {
  GET: 'text-green-400',
  POST: 'text-blue-400',
  PUT: 'text-yellow-400',
  DELETE: 'text-red-400',
  PATCH: 'text-orange-400',
  OPTIONS: 'text-purple-400',
  HEAD: 'text-zinc-400',
}

interface BadgeProps {
  variant: 'severity' | 'method' | 'status'
  value: string
  className?: string
}

export function Badge({ variant, value, className }: BadgeProps) {
  if (variant === 'severity') {
    const sev = value.toLowerCase() as Severity
    return (
      <span className={clsx('text-xs px-1.5 py-0.5 rounded font-mono uppercase tracking-wide', SEVERITY_CLASSES[sev] || SEVERITY_CLASSES.info, className)}>
        {value}
      </span>
    )
  }

  if (variant === 'method') {
    return (
      <span className={clsx('text-xs font-mono font-semibold w-16 inline-block', METHOD_CLASSES[value] || 'text-zinc-400', className)}>
        {value}
      </span>
    )
  }

  if (variant === 'status') {
    const code = parseInt(value)
    const color = code < 300 ? 'text-green-400' : code < 400 ? 'text-blue-400' : code < 500 ? 'text-yellow-400' : 'text-red-400'
    return (
      <span className={clsx('text-xs font-mono', color, className)}>{value}</span>
    )
  }

  return <span className={className}>{value}</span>
}
