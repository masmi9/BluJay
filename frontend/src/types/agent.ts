export interface AgentCommandResult {
  id: number
  created_at: string
  command_type: string
  args: Record<string, unknown>
  result: unknown
  status: 'pending' | 'running' | 'complete' | 'error'
  error: string | null
  duration_ms: number | null
}

export const AGENT_COMMANDS = [
  { value: 'manifest_analysis', label: 'Manifest Analysis', description: 'Parse AndroidManifest.xml, list components, permissions, intent filters', args: ['package'] },
  { value: 'permission_audit', label: 'Permission Audit', description: 'List all requested permissions and classify risk', args: ['package'] },
  { value: 'package_enum', label: 'Package List', description: 'List all installed packages on the device', args: [] },
  { value: 'exploit_provider', label: 'Content Provider', description: 'Enumerate and query exported content providers', args: ['package', 'uri?'] },
  { value: 'exploit_intent', label: 'Intent Exploit', description: 'Test exported component with crafted intents', args: ['package', 'component', 'action?'] },
  { value: 'exploit_ipc', label: 'IPC Analysis', description: 'Analyse inter-process communication attack surface', args: ['package'] },
  { value: 'exploit_webview', label: 'WebView Analysis', description: 'Detect WebView JS interface exposure and insecure settings', args: ['package'] },
  { value: 'shell', label: 'Shell Command', description: 'Run arbitrary ADB shell command on the device', args: ['cmd'] },
] as const

export type AgentCommandType = typeof AGENT_COMMANDS[number]['value']

export interface AgentStatus {
  serial: string
  installed: boolean
  forwarded: boolean
  reachable: boolean
  morph_apk_configured: boolean
}

export interface AgentSetupResult {
  ok: boolean
  steps: Record<string, boolean | string>
}

export interface BuildStatus {
  status: 'idle' | 'building' | 'success' | 'failed'
  total_lines: number
  new_lines: string[]
  apk_path: string | null
  error: string | null
}
