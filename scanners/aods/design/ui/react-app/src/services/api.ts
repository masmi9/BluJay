import type { ScanResult, ScanProgress, ScanSession, AuditListResponse, StartScanResponse, FindingInput, FindSimilarResponse, VectorIndexStatus, RebuildIndexResponse, AgentTask, AgentTaskInput, AgentConfig, AgentObservation, AgentStats, AdminUser, RolesResponse, ApkInspectResult, TriageFeedbackHistoryResponse, IoCExportResponse, IoCStatsResponse, AutoResearchExperiment, AutoResearchConfig, AttackSurfaceGraph, EnvSummaryResponse } from '../types';
import { getApiBase, secureFetch } from '../lib/api';

export class AODSApiClient {
  private baseUrlPromise: Promise<string>;

  constructor() {
    this.baseUrlPromise = getApiBase();
  }

  async getScanResults(): Promise<ScanResult[]> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/results?limit=100`);
    if (!r.ok) throw new Error(`getScanResults failed: ${r.status}`);
    return r.json();
  }

  async startScan(apkPath: string, opts?: { enableThresholdFiltering?: boolean; packageName?: string } & { scanOptions?: any }): Promise<StartScanResponse> {
    await this.baseUrlPromise;
    const payload: any = { apkPath };
    if (opts && typeof opts.enableThresholdFiltering === 'boolean') {
      payload.enableThresholdFiltering = Boolean(opts.enableThresholdFiltering);
    }
    if (opts && opts.packageName) {
      payload.packageName = opts.packageName;
    }
    if (opts && opts.scanOptions && typeof opts.scanOptions === 'object') {
      payload.scanOptions = opts.scanOptions;
    }
    const ac = new AbortController();
    const timer = window.setTimeout(() => { try { ac.abort(); } catch {} }, 15000);
    let r: Response;
    try {
      r = await secureFetch(`/scans/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: (ac as any).signal,
      } as any);
    } finally {
      try { window.clearTimeout(timer); } catch {}
    }
    if (!r.ok) {
      // Try to surface server error details to the UI for diagnosis
      try {
        const ct = r.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
          const j = await r.json();
          const detail = (j && (j.detail || j.error)) ? ` (${String(j.detail || j.error)})` : '';
          throw new Error(`startScan failed: ${r.status}${detail}`);
        } else {
          const t = await r.text();
          const msg = t ? ` (${t.slice(0, 200)})` : '';
          throw new Error(`startScan failed: ${r.status}${msg}`);
        }
      } catch (e: any) {
        if (e.message?.startsWith('startScan failed')) throw e;
        throw new Error(`startScan failed: ${r.status}`);
      }
    }
    return r.json();
  }

  /**
   * Confirm package name for a scan that is awaiting confirmation.
   * Call this after startScan returns status="awaiting_confirmation".
   */
  async confirmPackage(sessionId: string, packageName: string): Promise<{ sessionId: string; status: string; packageName: string }> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/${encodeURIComponent(sessionId)}/confirm-package`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ packageName }),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || `HTTP ${r.status}`;
        throw new Error(`confirmPackage failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('confirmPackage failed')) throw e;
        throw new Error(`confirmPackage failed: ${r.status}`);
      }
    }
    return r.json();
  }

  /**
   * Retry package detection for a scan awaiting confirmation.
   * May improve detection if AAPT or other tools become available.
   */
  async retryDetection(sessionId: string): Promise<{
    sessionId: string;
    status: string;
    packageDetection: any;
    improved: boolean;
    error?: string;
  }> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/${encodeURIComponent(sessionId)}/retry-detection`, {
      method: 'POST',
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || `HTTP ${r.status}`;
        throw new Error(`retryDetection failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('retryDetection failed')) throw e;
        throw new Error(`retryDetection failed: ${r.status}`);
      }
    }
    return r.json();
  }

  async getScanProgress(sessionId: string): Promise<ScanProgress> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/${encodeURIComponent(sessionId)}/progress`);
    if (!r.ok) throw new Error(`getScanProgress failed: ${r.status}`);
    return r.json();
  }

  async getAuditEvents(params: { user?: string; action?: string; resourceContains?: string; since?: string; until?: string; limit?: number; offset?: number; order?: 'asc' | 'desc' }): Promise<AuditListResponse> {
    await this.baseUrlPromise;
    const usp = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined || v === null) continue;
      usp.set(k, String(v));
    }
    const r = await secureFetch(`/audit/events?${usp.toString()}`);
    if (!r.ok) throw new Error(`getAuditEvents failed: ${r.status}`);
    return r.json();
  }

  async cancelScan(sessionId: string): Promise<{ status: string }> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/${encodeURIComponent(sessionId)}/cancel`, { method: 'POST' });
    if (!r.ok) throw new Error(`cancelScan failed: ${r.status}`);
    return r.json();
  }

  async getRecentScans(opts?: {
    limit?: number;
    offset?: number;
    status?: 'running' | 'completed' | 'failed' | 'cancelled' | 'all';
  }): Promise<{
    items: any[];
    total: number;
    hasMore: boolean;
    limit: number;
    offset: number;
  }> {
    const params = new URLSearchParams();
    if (opts?.limit) params.set('limit', String(opts.limit));
    if (opts?.offset) params.set('offset', String(opts.offset));
    if (opts?.status) params.set('status', opts.status);
    const qs = params.toString();
    const r = await secureFetch(`/scans/recent${qs ? '?' + qs : ''}`);
    if (!r.ok) throw new Error(`getRecentScans failed: ${r.status}`);
    return r.json();
  }

  async cancelBatch(jobId: string): Promise<{ status: string }> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/batch/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
    if (!r.ok) throw new Error(`cancelBatch failed: ${r.status}`);
    return r.json();
  }

  async getScanDetails(sessionId: string): Promise<any> {
    await this.baseUrlPromise;
    const r = await secureFetch(`/scans/${encodeURIComponent(sessionId)}/details`);
    if (!r.ok) throw new Error(`getScanDetails failed: ${r.status}`);
    return r.json();
  }

  async checkConnectivity(): Promise<{ health: boolean; auth: boolean; message?: string }> {
    try {
      const [h, me] = await Promise.all([
        secureFetch(`/health`),
        secureFetch(`/auth/me`)
      ]);
      const healthOk = h.ok;
      const authOk = me.ok;
      let msg = '';
      if (!healthOk) msg += 'health failed; ';
      if (!authOk) {
        try { const j = await me.json(); msg += String(j?.detail || 'unauthorized'); }
        catch { msg += 'unauthorized'; }
      }
      return { health: healthOk, auth: authOk, message: msg.trim() };
    } catch (e:any) {
      return { health: false, auth: false, message: e?.message || 'network error' };
    }
  }

  async findSimilarFindings(finding: FindingInput, nResults?: number, includeSameScan?: boolean): Promise<FindSimilarResponse> {
    const payload: any = { finding };
    if (nResults !== undefined) payload.n_results = nResults;
    if (includeSameScan !== undefined) payload.include_same_scan = includeSameScan;
    const r = await secureFetch(`/vector/findings/similar`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || j?.error || `HTTP ${r.status}`;
        throw new Error(`findSimilarFindings failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('findSimilarFindings failed')) throw e;
        throw new Error(`findSimilarFindings failed: ${r.status}`);
      }
    }
    return r.json();
  }

  async getVectorIndexStatus(): Promise<VectorIndexStatus> {
    const r = await secureFetch(`/vector/index/status`);
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || j?.error || `HTTP ${r.status}`;
        throw new Error(`getVectorIndexStatus failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('getVectorIndexStatus failed')) throw e;
        throw new Error(`getVectorIndexStatus failed: ${r.status}`);
      }
    }
    return r.json();
  }

  async rebuildVectorIndex(reportsDir?: string, clearExisting?: boolean): Promise<RebuildIndexResponse> {
    const payload: any = {};
    if (reportsDir !== undefined) payload.reports_dir = reportsDir;
    if (clearExisting !== undefined) payload.clear_existing = clearExisting;
    const r = await secureFetch(`/vector/index/rebuild`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || j?.error || `HTTP ${r.status}`;
        throw new Error(`rebuildVectorIndex failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('rebuildVectorIndex failed')) throw e;
        throw new Error(`rebuildVectorIndex failed: ${r.status}`);
      }
    }
    return r.json();
  }

  // --- Agent Intelligence ---

  async startAgentTask(input: AgentTaskInput): Promise<{ task_id: string; status: string; agent_type: string }> {
    const r = await secureFetch(`/agent/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        const detail = j?.detail || `HTTP ${r.status}`;
        throw new Error(`startAgentTask failed: ${detail}`);
      } catch (e: any) {
        if (e.message?.startsWith('startAgentTask failed')) throw e;
        throw new Error(`startAgentTask failed: ${r.status}`);
      }
    }
    return r.json();
  }

  async getAgentTasks(opts?: { status?: string; limit?: number }): Promise<{ tasks: AgentTask[]; count: number }> {
    const params = new URLSearchParams();
    if (opts?.status) params.set('status', opts.status);
    if (opts?.limit) params.set('limit', String(opts.limit));
    const qs = params.toString();
    const r = await secureFetch(`/agent/tasks${qs ? '?' + qs : ''}`);
    if (!r.ok) throw new Error(`getAgentTasks failed: ${r.status}`);
    return r.json();
  }

  async getAgentTask(taskId: string): Promise<AgentTask> {
    const r = await secureFetch(`/agent/tasks/${encodeURIComponent(taskId)}`);
    if (!r.ok) throw new Error(`getAgentTask failed: ${r.status}`);
    return r.json();
  }

  async cancelAgentTask(taskId: string): Promise<{ task_id: string; status: string }> {
    const r = await secureFetch(`/agent/tasks/${encodeURIComponent(taskId)}/cancel`, { method: 'POST' });
    if (!r.ok) throw new Error(`cancelAgentTask failed: ${r.status}`);
    return r.json();
  }

  async getAgentConfig(): Promise<AgentConfig> {
    const r = await secureFetch(`/agent/config`);
    if (!r.ok) throw new Error(`getAgentConfig failed: ${r.status}`);
    return r.json();
  }

  async updateAgentConfig(params: {
    enabled?: boolean;
    provider?: string;
    model?: string;
    max_iterations?: number;
    cost_limit_usd?: number;
    max_wall_time_seconds?: number;
  }): Promise<AgentConfig> {
    const r = await secureFetch(`/agent/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        throw new Error(j?.detail || `HTTP ${r.status}`);
      } catch (e: any) {
        if (e.message?.startsWith('HTTP') || e.message?.includes('forbidden')) throw e;
        throw new Error(`updateAgentConfig failed: ${r.status}`);
      }
    }
    return r.json();
  }

  async getAgentTranscript(taskId: string): Promise<{ observations: AgentObservation[] }> {
    const r = await secureFetch(`/agent/tasks/${encodeURIComponent(taskId)}/transcript`);
    if (!r.ok) throw new Error(`getAgentTranscript failed: ${r.status}`);
    return r.json();
  }

  async startPipeline(params: {
    report_file: string;
    steps?: { agent_type: string; enabled: boolean }[];
    total_token_budget?: number;
    stop_on_failure?: boolean;
    scan_id?: string;
  }): Promise<{ task_id: string; status: string; agent_type: string }> {
    const r = await secureFetch(`/agent/pipeline`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!r.ok) throw new Error(`startPipeline failed: ${r.status}`);
    return r.json();
  }

  async getAgentStats(days?: number): Promise<AgentStats> {
    const qs = days ? `?days=${days}` : '';
    const r = await secureFetch(`/agent/stats${qs}`);
    if (!r.ok) throw new Error(`getAgentStats failed: ${r.status}`);
    return r.json();
  }

  async submitTriageFeedback(params: {
    report_file: string;
    finding_title: string;
    action: 'accept' | 'reject';
    new_classification?: string;
    reason?: string;
    agent_type?: string;
  }): Promise<{ status: string; finding_title: string; action: string }> {
    const r = await secureFetch(`/agent/triage/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_type: 'triage', ...params }),
    });
    if (!r.ok) throw new Error(`submitTriageFeedback failed: ${r.status}`);
    return r.json();
  }

  async getTriageFeedbackHistory(findingTitle: string, nResults = 10): Promise<TriageFeedbackHistoryResponse> {
    const params = new URLSearchParams({ finding_title: findingTitle, n_results: String(nResults) });
    const r = await secureFetch(`/agent/triage/feedback/history?${params.toString()}`);
    if (!r.ok) throw new Error(`getTriageFeedbackHistory failed: ${r.status}`);
    return r.json();
  }

  // --- RBAC Admin ---

  async getAdminUsers(): Promise<{ users: AdminUser[] }> {
    const r = await secureFetch(`/admin/users`);
    if (!r.ok) throw new Error(`getAdminUsers failed: ${r.status}`);
    return r.json();
  }

  async getAdminRoles(): Promise<RolesResponse> {
    const r = await secureFetch(`/admin/roles`);
    if (!r.ok) throw new Error(`getAdminRoles failed: ${r.status}`);
    return r.json();
  }

  async updateUserRole(username: string, role: string): Promise<{ ok: boolean }> {
    const r = await secureFetch(`/admin/users/${encodeURIComponent(username)}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        throw new Error(j?.detail || `HTTP ${r.status}`);
      } catch (e: any) {
        if (e.message?.startsWith('HTTP') || e.message?.includes('self')) throw e;
        throw new Error(`updateUserRole failed: ${r.status}`);
      }
    }
    return r.json();
  }

  // --- IoC Correlation (Track 117) ---

  async getIoCCorrelations(value: string): Promise<{ correlations: any[]; total: number }> {
    const params = new URLSearchParams({ value });
    const r = await secureFetch(`/vector/iocs/correlations?${params.toString()}`);
    if (!r.ok) throw new Error(`getIoCCorrelations failed: ${r.status}`);
    return r.json();
  }

  async getScanIoCCorrelations(scanId: string): Promise<{ scan_id: string; correlations: any[]; total: number }> {
    const r = await secureFetch(`/vector/iocs/scan/${encodeURIComponent(scanId)}`);
    if (!r.ok) throw new Error(`getScanIoCCorrelations failed: ${r.status}`);
    return r.json();
  }

  async getIoCClusters(minApks?: number): Promise<{ clusters: any[]; total: number }> {
    const params = new URLSearchParams();
    if (minApks) params.set('min_apks', String(minApks));
    const qs = params.toString();
    const r = await secureFetch(`/vector/iocs/clusters${qs ? '?' + qs : ''}`);
    if (!r.ok) throw new Error(`getIoCClusters failed: ${r.status}`);
    return r.json();
  }

  async getIoCStats(): Promise<{ total_iocs: number; total_scans: number; type_distribution: Record<string, number> }> {
    const r = await secureFetch(`/vector/iocs/stats`);
    if (!r.ok) throw new Error(`getIoCStats failed: ${r.status}`);
    return r.json();
  }

  // --- IoC Export (Track 117.16) ---

  async getScanIoCs(resultId: string, format: 'json' | 'stix' = 'json'): Promise<IoCExportResponse> {
    const params = new URLSearchParams({ format });
    const r = await secureFetch(`/scans/result/${encodeURIComponent(resultId)}/iocs?${params.toString()}`);
    if (!r.ok) throw new Error(`getScanIoCs failed: ${r.status}`);
    return r.json();
  }

  async deleteScanIoCs(scanId: string): Promise<{ deleted: number; scan_id: string }> {
    const r = await secureFetch(`/vector/iocs/scan/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(`deleteScanIoCs failed: ${r.status}`);
    return r.json();
  }

  // --- AutoResearch ---

  async getAutoResearchExperiments(opts?: {
    type?: 'recent' | 'best' | 'accepted';
    n?: number;
    run_id?: string;
  }): Promise<{ experiments: AutoResearchExperiment[]; total: number }> {
    const kind = opts?.type || 'recent';
    const params = new URLSearchParams();
    if (opts?.n) params.set('n', String(opts.n));
    if (opts?.run_id) params.set('run_id', opts.run_id);
    const qs = params.toString();
    const r = await secureFetch(`/autoresearch/experiments/${kind}${qs ? '?' + qs : ''}`);
    if (!r.ok) throw new Error(`getAutoResearchExperiments failed: ${r.status}`);
    return r.json();
  }

  async getAutoResearchConfig(): Promise<AutoResearchConfig> {
    const r = await secureFetch(`/autoresearch/config`);
    if (!r.ok) throw new Error(`getAutoResearchConfig failed: ${r.status}`);
    return r.json();
  }

  async getAutoResearchThresholds(): Promise<{ thresholds: Record<string, any>; exists: boolean }> {
    const r = await secureFetch(`/autoresearch/current-thresholds`);
    if (!r.ok) throw new Error(`getAutoResearchThresholds failed: ${r.status}`);
    return r.json();
  }

  // --- APK Inspect ---

  async inspectApkPath(apkPath: string): Promise<ApkInspectResult> {
    const r = await secureFetch(`/apk/inspect-path`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apk_path: apkPath }),
    });
    if (!r.ok) {
      try {
        const j = await r.json();
        throw new Error(j?.detail || `HTTP ${r.status}`);
      } catch (e: any) {
        if (e.message?.startsWith('HTTP') || e.message?.includes('not found')) throw e;
        throw new Error(`inspectApkPath failed: ${r.status}`);
      }
    }
    return r.json();
  }

  // Validate a local APK path by probing /apk/inspect with a zero-byte stream
  async validateApkPathWithInspect(filePath: string): Promise<{ ok: boolean; detail?: string }> {
    await this.baseUrlPromise;
    try {
      const usp = new URLSearchParams({ path: filePath });
      const r = await secureFetch(`/apk/exists?${usp.toString()}`);
      if (!r.ok) {
        const ct = r.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
          const j = await r.json();
          return { ok: false, detail: String(j?.detail || `HTTP ${r.status}`) };
        }
        return { ok: false, detail: `HTTP ${r.status}` };
      }
      const j = await r.json();
      const ok = Boolean(j?.exists && j?.isFile);
      return ok ? { ok: true } : { ok: false, detail: 'Path not found or not a file' };
    } catch (e: any) {
      return { ok: false, detail: e?.message || 'validation failed' };
    }
  }

  // --- Attack Surface Graph ---

  async getAttackSurface(resultId: string): Promise<AttackSurfaceGraph> {
    const r = await secureFetch(`/scans/result/${encodeURIComponent(resultId)}/attack-surface`);
    if (!r.ok) throw new Error(`getAttackSurface failed: ${r.status}`);
    return r.json();
  }

  // --- Environment Variables ---

  async getEnvSummary(): Promise<EnvSummaryResponse> {
    const r = await secureFetch('/admin/env');
    if (!r.ok) throw new Error(`getEnvSummary failed: ${r.status}`);
    return r.json();
  }

  async updateEnvVar(name: string, value: string): Promise<{ ok: boolean; name: string; value: string }> {
    const r = await secureFetch(`/admin/env/${encodeURIComponent(name)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value }),
    });
    if (!r.ok) {
      try { const j = await r.json(); throw new Error(j?.detail || `HTTP ${r.status}`); }
      catch (e: any) { if (e.message?.includes('HTTP') || e.message?.includes('sensitive')) throw e; throw new Error(`updateEnvVar failed: ${r.status}`); }
    }
    return r.json();
  }
}


