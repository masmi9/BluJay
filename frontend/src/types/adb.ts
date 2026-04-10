export interface DeviceInfo {
  serial: string
  state: 'device' | 'offline' | 'unauthorized'
  product: string | null
  model: string | null
  transport_id: string | null
}

export interface IosDeviceInfo {
  udid: string
  name: string | null
  model: string | null
  ios_version: string | null
  jailbroken: boolean
}

export interface DynamicSession {
  id: number
  analysis_id: number
  created_at: string
  device_serial: string
  package_name: string
  status: 'active' | 'stopped'
  proxy_port: number | null
  frida_attached: boolean
}

export interface LogcatLine {
  ts: string
  level: 'V' | 'D' | 'I' | 'W' | 'E' | 'F'
  tag: string
  message: string
  pid?: string
}
