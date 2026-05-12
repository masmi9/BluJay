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
import SettingsPage from '@/pages/Settings'
import CvePage from '@/pages/CvePage'
import WebViewPage from '@/pages/WebViewPage'
import RiskPage from '@/pages/RiskPage'
import DiffPage from '@/pages/DiffPage'
import CampaignPage from '@/pages/CampaignPage'
import ChecklistPage from '@/pages/ChecklistPage'
import ApiScannerPage from '@/pages/ApiScannerPage'
import AiTriagePage from '@/pages/AiTriagePage'
import PciTestPage from '@/pages/PciTestPage'
import CTFPage from '@/pages/CTFPage'
import RepeaterPage from '@/pages/RepeaterPage'
import AuthTesterPage from '@/pages/AuthTesterPage'
import VulnIntelPage from '@/pages/VulnIntelPage'
import CloudTesterPage from '@/pages/CloudTesterPage'
import ProtocolTesterPage from '@/pages/ProtocolTesterPage'

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
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/cve/:id" element={<CvePage />} />
              <Route path="/webview/:id" element={<WebViewPage />} />
              <Route path="/risk/:id" element={<RiskPage />} />
              <Route path="/diff" element={<DiffPage />} />
              <Route path="/campaigns" element={<CampaignPage />} />
              <Route path="/checklist" element={<ChecklistPage />} />
              <Route path="/api-scanner" element={<ApiScannerPage />} />
              <Route path="/ai-triage" element={<AiTriagePage />} />
              <Route path="/pci" element={<PciTestPage />} />
              <Route path="/ctf" element={<CTFPage />} />
              <Route path="/repeater" element={<RepeaterPage />} />
              <Route path="/auth-tester" element={<AuthTesterPage />} />
              <Route path="/vuln-intel" element={<VulnIntelPage />} />
              <Route path="/cloud-tester" element={<CloudTesterPage />} />
              <Route path="/protocol-tester" element={<ProtocolTesterPage />} />
              {/* Legacy redirects */}
              <Route path="/scanner" element={<Navigate to="/api-scanner" replace />} />
              <Route path="/api-testing" element={<Navigate to="/api-scanner" replace />} />
              <Route path="/fuzzing" element={<Navigate to="/api-scanner" replace />} />
              <Route path="/brute-force" element={<Navigate to="/api-scanner" replace />} />
              <Route path="/strix" element={<Navigate to="/api-scanner" replace />} />
              <Route path="/tls" element={<Navigate to="/protocol-tester" replace />} />
              <Route path="/jwt" element={<Navigate to="/auth-tester" replace />} />
              <Route path="/decode" element={<Navigate to="/ai-triage" replace />} />
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
