import { create } from 'zustand'
import type { DeviceInfo, DynamicSession } from '@/types/adb'

interface DeviceStore {
  devices: DeviceInfo[]
  selectedSerial: string | null
  activeSession: DynamicSession | null
  setDevices: (devices: DeviceInfo[]) => void
  selectDevice: (serial: string | null) => void
  setActiveSession: (session: DynamicSession | null) => void
}

export const useDeviceStore = create<DeviceStore>((set) => ({
  devices: [],
  selectedSerial: null,
  activeSession: null,
  setDevices: (devices) => set({ devices }),
  selectDevice: (serial) => set({ selectedSerial: serial }),
  setActiveSession: (session) => set({ activeSession: session }),
}))
