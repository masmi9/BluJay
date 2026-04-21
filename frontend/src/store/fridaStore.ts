import { create } from 'zustand'

interface FridaStore {
  attached: boolean
  attachedPackage: string | null
  attachedSerial: string | null
  sessionId: number
  setAttached: (attached: boolean, pkg?: string, serial?: string, sessionId?: number) => void
  detach: () => void
}

export const useFridaStore = create<FridaStore>((set) => ({
  attached: false,
  attachedPackage: null,
  attachedSerial: null,
  sessionId: 0,
  setAttached: (attached, pkg = null, serial = null, sessionId = 0) =>
    set({ attached, attachedPackage: pkg, attachedSerial: serial, sessionId }),
  detach: () =>
    set({ attached: false, attachedPackage: null, attachedSerial: null, sessionId: 0 }),
}))
