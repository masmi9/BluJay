import React from 'react';
import { Box, Button, Typography } from '@mui/material';
import { Link, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { NewScan } from './pages/NewScan';
import { Results } from './pages/Results';
import { ToolsStatus } from './pages/ToolsStatus';
import { ResultDetail } from './pages/ResultDetail';
import { Artifacts } from './pages/Artifacts';
import { GatesDashboard } from './pages/GatesDashboard';
import { BatchConsole } from './pages/BatchConsole';
import { AuditLog } from './pages/AuditLog';
import FridaConsole from './pages/FridaConsole';
import { Dashboard } from './pages/Dashboard';
import { Config } from './pages/Config';
import { AuthProvider, RequireRoles, useAuth } from './context/AuthContext';
import { Login } from './pages/Login';
import { Reports } from './pages/Reports';
import { Policies } from './pages/Policies';
import { Playbooks } from './pages/Playbooks';
import { MLOverview } from './pages/MLOverview';
import { MLThresholds } from './pages/MLThresholds';
import { MLPRMetrics } from './pages/MLPRMetrics';
import { MLFPBreakdown } from './pages/MLFPBreakdown';
import { MappingSources } from './pages/MappingSources';
import { Curation } from './pages/Curation';
import { MLTraining } from './pages/MLTraining';
import { ErrorBoundary } from './components/ErrorBoundary';
import { DatasetExplorer } from './pages/DatasetExplorer';
import { ExecutiveDashboard } from './pages/ExecutiveDashboard';
import { RecentJobs } from './pages/RecentJobs';
import { VectorSearch } from './pages/VectorSearch';
import { AgentDashboard } from './pages/AgentDashboard';
import { RBACAdmin } from './pages/RBACAdmin';
import { ScanCompare } from './pages/ScanCompare';
import { FeedbackAnalytics } from './pages/FeedbackAnalytics';
import { MalwareFamilies } from './pages/MalwareFamilies';
import { IoCDashboard } from './pages/IoCDashboard';
import { AutoResearch } from './pages/AutoResearch';
import { Layout } from './components/Layout';

function Shell() {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  React.useEffect(() => {
    try { localStorage.setItem('aodsLastPath', location.pathname || '/'); } catch { /* ignore */ }
  }, [location.pathname]);
  React.useEffect(() => {
    if (!auth.token) return;
    try {
      const last = localStorage.getItem('aodsLastPath');
      const p = location.pathname || '/';
      if (last && last !== p && (p === '/' || p === '/ui' || p === '/ui/')) {
        navigate(last, { replace: true });
      }
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => {
    let seq = '';
    const onKey = (e: KeyboardEvent) => {
      if (e.target && (e.target as HTMLElement).tagName && ['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement).tagName)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const k = e.key.toLowerCase();
      seq = (seq + k).slice(-2);
      if (seq === 'gg') { e.preventDefault(); navigate('/gates'); seq = ''; }
      else if (seq === 'gr') { e.preventDefault(); navigate('/runs'); seq = ''; }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate]);
  return (
    <Layout>
      {!auth.token ? (
        <Login onLogin={(t, r, u) => auth.login(t, r, u)} />
      ) : (
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/runs" element={<Results />} />
          <Route path="/runs/:id" element={<ResultDetail />} />
          <Route path="/jobs" element={<RecentJobs />} />
          <Route path="/new-scan" element={<RequireRoles roles={["admin", "analyst"]}><NewScan /></RequireRoles>} />
          <Route path="/tools" element={<ToolsStatus />} />
          <Route path="/artifacts" element={<Artifacts />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/vector-search" element={<RequireRoles roles={["admin", "analyst"]}><VectorSearch /></RequireRoles>} />
          <Route path="/gates" element={<RequireRoles roles={["admin", "analyst"]}><GatesDashboard /></RequireRoles>} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/playbooks" element={<Playbooks />} />
          <Route path="/ml" element={<RequireRoles roles={["admin"]}><MLOverview /></RequireRoles>} />
          <Route path="/ml/training" element={<RequireRoles roles={["admin"]}><MLTraining /></RequireRoles>} />
          <Route path="/ml/thresholds" element={<RequireRoles roles={["admin"]}><MLThresholds /></RequireRoles>} />
          <Route path="/ml/metrics" element={<RequireRoles roles={["admin"]}><MLPRMetrics /></RequireRoles>} />
          <Route path="/ml/fp-breakdown" element={<RequireRoles roles={["admin"]}><MLFPBreakdown /></RequireRoles>} />
          <Route path="/mappings/sources" element={<RequireRoles roles={["admin"]}><MappingSources /></RequireRoles>} />
          <Route path="/datasets" element={<RequireRoles roles={["admin"]}><DatasetExplorer /></RequireRoles>} />
          <Route path="/exec" element={<RequireRoles roles={["admin"]}><ExecutiveDashboard /></RequireRoles>} />
          <Route path="/batch" element={<RequireRoles roles={["admin"]}><BatchConsole /></RequireRoles>} />
          <Route path="/audit" element={<RequireRoles roles={["admin", "auditor"]}><AuditLog /></RequireRoles>} />
          <Route path="/frida" element={<RequireRoles roles={["admin", "analyst"]}><FridaConsole /></RequireRoles>} />
          <Route path="/config" element={<RequireRoles roles={["admin"]}><Config /></RequireRoles>} />
          <Route path="/curation" element={<RequireRoles roles={["admin"]}><Curation /></RequireRoles>} />
          <Route path="/agent" element={<RequireRoles roles={["admin", "analyst"]}><AgentDashboard /></RequireRoles>} />
          <Route path="/compare" element={<RequireRoles roles={["admin", "analyst"]}><ScanCompare /></RequireRoles>} />
          <Route path="/feedback" element={<RequireRoles roles={["admin", "analyst"]}><FeedbackAnalytics /></RequireRoles>} />
          <Route path="/malware-families" element={<RequireRoles roles={["admin", "analyst"]}><MalwareFamilies /></RequireRoles>} />
          <Route path="/ioc-dashboard" element={<RequireRoles roles={["admin", "analyst"]}><IoCDashboard /></RequireRoles>} />
          <Route path="/autoresearch" element={<RequireRoles roles={["admin"]}><AutoResearch /></RequireRoles>} />
          <Route path="/admin/rbac" element={<RequireRoles roles={["admin"]}><RBACAdmin /></RequireRoles>} />
          <Route path="*" element={
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', py: 8 }}>
              <Typography variant="h1" sx={{ fontSize: 72, fontWeight: 700, color: 'text.disabled', lineHeight: 1 }}>404</Typography>
              <Typography variant="h6" color="text.secondary" sx={{ mt: 1, mb: 3 }}>Page not found</Typography>
              <Button variant="contained" component={Link} to="/">Back to Dashboard</Button>
            </Box>
          } />
        </Routes>
      )}
    </Layout>
  );
}

export function App() {
  return (
    <AuthProvider>
      <ErrorBoundary>
        <Shell />
      </ErrorBoundary>
    </AuthProvider>
  );
}
