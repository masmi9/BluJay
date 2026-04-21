export interface FridaProcess {
  pid: number | null
  name: string
  identifier: string | null
  running: boolean
}

export interface FridaScriptInfo {
  name: string
  filename: string
  description: string
  hooks: string[]
}

export interface FridaEvent {
  id: number
  session_id: number
  timestamp: string
  event_type: 'log' | 'hook_hit' | 'error' | 'send'
  script_name: string | null
  payload: string
}
