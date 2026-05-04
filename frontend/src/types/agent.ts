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
  // ── Standard Android analysis ──────────────────────────────────────────
  { value: 'manifest_analysis', label: 'Manifest Analysis', description: 'Parse AndroidManifest.xml, list components, permissions, intent filters', args: ['package'] },
  { value: 'permission_audit',  label: 'Permission Audit',  description: 'List all requested permissions and classify risk', args: ['package'] },
  { value: 'package_enum',      label: 'Package List',      description: 'List all installed packages on the device', args: [] },
  { value: 'exploit_provider',  label: 'Content Provider',  description: 'Enumerate and query exported content providers', args: ['package', 'uri?'] },
  { value: 'exploit_intent',    label: 'Intent Exploit',    description: 'Test exported component with crafted intents', args: ['package', 'component', 'action?'] },
  { value: 'exploit_ipc',       label: 'IPC Analysis',      description: 'Analyse inter-process communication attack surface', args: ['package'] },
  { value: 'exploit_webview',   label: 'WebView Analysis',  description: 'Detect WebView JS interface exposure and insecure settings', args: ['package'] },
  { value: 'shell',             label: 'Shell Command',     description: 'Run arbitrary ADB shell command on the device', args: ['cmd'] },
  // ── Unity C2 — engine recon ────────────────────────────────────────────
  { value: 'unity_detect',      label: 'Unity: Detect Engine',    description: 'Detect Unity version, scripting backend (IL2CPP vs Mono), and game metadata', args: ['package'] },
  { value: 'unity_list_scenes', label: 'Unity: List Scenes',      description: 'Enumerate loaded Unity scenes and active GameObjects at runtime', args: ['package'] },
  // ── Unity C2 — memory exploitation ────────────────────────────────────
  { value: 'unity_dump_il2cpp', label: 'Unity: Dump IL2CPP',      description: 'Extract IL2CPP class/method/field metadata from process memory (replaces il2cppdumper)', args: ['package'] },
  { value: 'unity_scan_memory', label: 'Unity: Scan Memory',      description: 'Scan process memory for hardcoded API keys, auth tokens, secrets, and URLs', args: ['package', 'pattern?'] },
  // ── Unity C2 — game state tampering ───────────────────────────────────
  { value: 'unity_read_prefs',  label: 'Unity: Read PlayerPrefs', description: 'Dump all Unity PlayerPrefs — game state, auth tokens, cheat flags, currency values', args: ['package'] },
  { value: 'unity_write_prefs', label: 'Unity: Tamper PlayerPrefs', description: 'Write or modify a Unity PlayerPrefs key-value pair at runtime', args: ['package', 'key', 'value', 'type?'] },
  // ── Unity C2 — runtime hooks & exploits ───────────────────────────────
  { value: 'unity_hook_method', label: 'Unity: Hook Method',      description: 'Install a Frida runtime hook on a Unity class method to intercept or modify calls', args: ['package', 'class_name', 'method_name'] },
  { value: 'unity_bypass_ssl',  label: 'Unity: Bypass SSL',       description: 'Bypass SSL/TLS certificate pinning in Unity HTTPS client calls', args: ['package'] },
  { value: 'unity_exploit_socket', label: 'Unity: Exploit Network', description: 'Analyse and interact with Unity multiplayer sockets — UNET, Mirror, Photon, Netcode', args: ['package'] },
  { value: 'unity_exploit_chain',  label: 'Unity: Full Exploit Chain', description: 'Run a full Unity C2 chain: detect engine → dump IL2CPP → scan memory → hook anti-cheat bypass', args: ['package'] },
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
