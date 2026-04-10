import { create } from 'zustand'
import type { ProxyFlow } from '@/types/proxy'

interface ProxyStore {
  flows: ProxyFlow[]
  selectedFlowId: string | null
  sessionId: number | null
  isRunning: boolean
  addFlow: (flow: ProxyFlow) => void
  setFlows: (flows: ProxyFlow[]) => void
  selectFlow: (id: string | null) => void
  setSessionId: (id: number | null) => void
  setIsRunning: (v: boolean) => void
  clearFlows: () => void
}

export const useProxyStore = create<ProxyStore>((set) => ({
  flows: [],
  selectedFlowId: null,
  sessionId: null,
  isRunning: false,
  addFlow: (flow) => set((s) => ({ flows: [flow, ...s.flows].slice(0, 5000) })),
  setFlows: (flows) => set({ flows }),
  selectFlow: (id) => set({ selectedFlowId: id }),
  setSessionId: (id) => set({ sessionId: id }),
  setIsRunning: (v) => set({ isRunning: v }),
  clearFlows: () => set({ flows: [], selectedFlowId: null }),
}))
