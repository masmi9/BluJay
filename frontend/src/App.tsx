import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopBar } from '@/components/layout/TopBar'
import { StatusBar } from '@/components/layout/StatusBar'
import Dashboard from '@/pages/Dashboard'
import StaticAnalysis from '@/pages/StaticAnalysis'
import DynamicAnalysis from '@/pages/DynamicAnalysis'
import ProxyPage from '@/pages/ProxyPage'
import FridaPage from '@/pages/FridaPage'
import AgentConsole from '@/pages/AgentConsole'
import OwaspScan from '@/pages/OwaspScan'
import TestingLab from '@/pages/TestingLab'
import SettingsPage from '@/pages/Settings'
import CvePage from '@/pages/CvePage'
import WebViewPage from '@/pages/WebViewPage'
import TlsAuditPage from '@/pages/TlsAuditPage'
import JwtPage from '@/pages/JwtPage'
import RiskPage from '@/pages/RiskPage'
import BruteForcePage from '@/pages/BruteForcePage'
import StrixPage from '@/pages/StrixPage'
import AiTriagePage from '@/pages/AiTriagePage'
import ApiTesting from '@/pages/ApiTesting'
import DiffPage from '@/pages/DiffPage'
import CampaignPage from '@/pages/CampaignPage'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-bg-base">
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <TopBar />
          <main className="flex-1 overflow-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/analysis/:id" element={<StaticAnalysis />} />
              <Route path="/dynamic/:sessionId" element={<DynamicAnalysis />} />
              <Route path="/proxy" element={<ProxyPage />} />
              <Route path="/frida" element={<FridaPage />} />
              <Route path="/agent" element={<AgentConsole />} />
              <Route path="/owasp" element={<OwaspScan />} />
              <Route path="/testing" element={<TestingLab />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/cve/:id" element={<CvePage />} />
              <Route path="/webview/:id" element={<WebViewPage />} />
              <Route path="/tls" element={<TlsAuditPage />} />
              <Route path="/jwt" element={<JwtPage />} />
              <Route path="/risk/:id" element={<RiskPage />} />
              <Route path="/fuzzing" element={<Navigate to="/api-testing" replace />} />
              <Route path="/brute-force" element={<BruteForcePage />} />
              <Route path="/strix" element={<StrixPage />} />
              <Route path="/ai-triage" element={<AiTriagePage />} />
              <Route path="/api-testing" element={<ApiTesting />} />
              <Route path="/diff" element={<DiffPage />} />
              <Route path="/campaigns" element={<CampaignPage />} />
              <Route path="/ipa" element={<Navigate to="/owasp" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
          <StatusBar />
        </div>
      </div>
    </BrowserRouter>
  )
}
