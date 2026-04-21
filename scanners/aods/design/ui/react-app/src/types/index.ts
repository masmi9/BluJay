export type ScanResult = {
  id: string;
  startedAt: string;
  finishedAt?: string;
  profile?: string | null;
  apkName?: string;
  path?: string;
  summary?: { findings: number; critical: number; high: number; medium: number; low: number; info?: number };
};

/**
 * Package detection result with confidence scoring.
 * Returned when /scans/start needs user confirmation for low-confidence detection.
 */
export type PackageDetectionInfo = {
  packageName: string;
  confidence: number; // 0.0-1.0
  method: string; // aapt_badging | aapt_xmltree | manifest_parsing | filename_generation | fallback
  appName?: string;
  versionName?: string;
  needsConfirmation: boolean;
};

export type ScanSession = {
  id: string;
  apkPath: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'awaiting_confirmation' | 'cancelled';
};

/**
 * Response from POST /scans/start
 */
export type StartScanResponse = {
  sessionId: string;
  status: 'queued' | 'awaiting_confirmation';
  startedAt: string;
  packageDetection?: PackageDetectionInfo;
  warning?: string;
};

export type ScanProgress = {
  id: string;
  pct: number;
  stage?: string;
  message?: string;
};

export type AuditEvent = {
  timestamp: string;
  user: string;
  action: string;
  resource?: string;
  details?: any;
};

export type AuditListResponse = {
  total: number;
  items: AuditEvent[];
};

/**
 * Recent scan item from /scans/recent endpoint
 */
export type RecentScanItem = {
  id: string;
  source: 'session' | 'report';
  apkName: string;
  apkPath?: string | null;
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'queued' | 'awaiting_confirmation' | string;
  profile?: string | null;
  mode?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  durationMs?: number | null;
  findingsCount?: number | null;
  reportPath?: string | null;
  createdAt?: string | number | null;
};

export type RecentScansResponse = {
  items: RecentScanItem[];
  total: number;
  hasMore: boolean;
  limit: number;
  offset: number;
};

export type FindingInput = {
  title?: string;
  description?: string;
  vulnerability_type?: string;
  severity?: string;
  cwe_id?: string;
};

export type SimilarFinding = {
  finding_id: string;
  scan_id: string;
  similarity_score: number;
  severity?: string;
  cwe_id?: string;
  title?: string;
  vulnerability_type?: string;
};

export type FindSimilarResponse = {
  results: SimilarFinding[];
  query_time_ms: number;
  total_indexed: number;
};

export type VectorIndexStatus = {
  enabled: boolean;
  available: boolean;
  model: string;
  storage_path: string;
  collection_count: number;
  embedding_dimension?: number;
  cache_stats?: Record<string, number>;
  error?: string;
};

export type RebuildIndexResponse = {
  indexed: number;
  skipped_no_owner: number;
  skipped_pollution: number;
  errors: number;
};

// --- Dashboard & shared API response types ---

export type GatesTotals = {
  PASS: number;
  WARN: number;
  FAIL: number;
};

export type GatesSummary = {
  totals?: GatesTotals;
  items?: Array<{ name: string; status: string; relPath?: string; failures?: string[]; trend?: 'up' | 'down' | 'flat' }>;
  summary?: Record<string, unknown>;
};

export type ToolStatus = {
  available?: boolean;
  ready?: boolean;
  version?: string;
  executable_path?: string;
  default_timeout?: number;
  max_retries?: number;
  last_checked?: string;
  install_hint?: string;
  tool_type?: string;
};

export type ToolsStatusResponse = Record<string, ToolStatus>;

export type MLThresholdsData = {
  fp_threshold?: number;
  confidence_min?: number;
  default?: number;
  severity_weights?: Record<string, number>;
  plugins?: Record<string, number>;
  categories?: Record<string, number>;
};

export type MLAccuracySummary = {
  status?: string;
  precision?: number;
  recall?: number;
  min_precision?: number;
  min_recall?: number;
  pass_rate?: number;
  failed?: number;
};

export type PRPoint = {
  t: number;
  P: number;
  R: number;
  F1: number;
};

export type PRCategoryData = {
  points: PRPoint[];
  count?: number;
};

export type MLPRMetricsData = {
  precision?: number;
  recall?: number;
  f1?: number;
  dataset_size?: number;
  fpr?: number;
  ece?: number;
  global?: { points: PRPoint[] };
  per_category?: Record<string, PRCategoryData>;
  per_plugin?: Record<string, PRCategoryData>;
  generated_at?: string;
};

export type MLFPBreakdownData = {
  fp_by_plugin?: Record<string, number>;
  fp_by_category?: Record<string, number>;
};

export type MLTrainingStatus = {
  status?: string;
  last_run?: string;
  models?: string[];
};

export type MLCalibrationSummary = {
  calibrated?: boolean;
  brier_score?: number;
  ece?: number;
};

export type DecompPolicy = {
  mode?: string;
  maxThreads?: number;
  memoryLimitMb?: number;
  reason?: string;
  outputDir?: string;
  flags?: string[];
};

export type DevServerProcess = {
  pid: number | null;
  running: boolean;
  cmd?: string;
};

export type DevServerStatus = {
  api?: DevServerProcess;
  ui?: DevServerProcess;
  ports?: { api?: boolean; ui?: boolean };
  network?: {
    ips?: string[];
    listeners?: Array<{ local: string }>;
    api?: { url: string };
    ui?: { url: string };
  };
  apiInstances?: DevServerProcess[];
  uiInstances?: DevServerProcess[];
};

export type ActiveScan = {
  id: string;
  status: string;
  pct?: number;
  stage?: string;
};

export type ApiInfo = {
  apiVersion?: string;
  version?: string;
};

export type ReportStats = {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type FridaDevice = {
  name?: string;
  id?: string;
  type?: string;
};

export type FridaHealthStatus = {
  available: boolean;
  message?: string;
  devices?: FridaDevice[];
};

export type BatchStatus = {
  status?: string;
  progress?: number;
  stdout?: string;
  stderr?: string;
};

export type MLSnapshot = {
  thresholds?: MLThresholdsData | null;
  accuracy?: MLAccuracySummary | null;
};

// --- Agent Intelligence types ---

export type AgentTask = {
  id: string;
  agent_type: string;
  scan_id?: string | null;
  user?: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  iterations: number;
  token_usage: { input_tokens: number; output_tokens: number };
  result?: string | null;
  error?: string | null;
  observations_count: number;
};

export type AgentTaskInput = {
  agent_type: 'analyze' | 'narrate' | 'verify' | 'triage' | 'remediate' | 'pipeline';
  scan_id?: string;
  report_file?: string;
  prompt?: string;
  params?: Record<string, unknown>;
};

export type AgentConfig = {
  enabled: boolean;
  provider: string;
  model: string;
  budget: Record<string, unknown>;
  agents: Record<string, unknown>;
};

// --- Narrative / Agentic Analysis types (Track 91) ---

export type NarrativeAttackChain = {
  name: string;
  steps: string[];
  impact: string;
  likelihood: string;
};

export type NarrativePriorityFinding = {
  title: string;
  severity: string;
  exploitability: string;
  context: string;
  cwe_id?: string | null;
};

export type NarrativeRemediationStep = {
  priority: number;
  title: string;
  description: string;
  effort: string;
  findings_addressed: string[];
};

export type AgenticAnalysis = {
  executive_summary: string;
  risk_rating: string;
  risk_rationale: string;
  attack_chains: NarrativeAttackChain[];
  priority_findings: NarrativePriorityFinding[];
  remediation_plan: NarrativeRemediationStep[];
  app_context: string;
  historical_comparison: string;
  method?: string;
  full_narrative: string;
  token_usage: Record<string, number>;
  task_id: string;
};

// --- Verification Agent types (Track 92) ---

export type FindingVerification = {
  finding_title: string;
  original_confidence: number;
  verified_confidence: number;
  status: 'confirmed' | 'likely' | 'unverifiable' | 'likely_fp';
  evidence: string;
  frida_script: string;
  frida_output: string;
  reasoning: string;
};

export type VerificationData = {
  verifications: FindingVerification[];
  summary: string;
  total_verified: number;
  total_confirmed: number;
  total_fp_detected: number;
  frida_available: boolean;
  method?: string;
};

// --- ML Explainability types ---

export type ContributingFactor = {
  factor: string;
  value: unknown;
  contribution: number;
  direction: string;
};

export type UnifiedExplanation = {
  finding_id: string;
  summary: string;
  method: string;
  confidence: number;
  contributing_factors: ContributingFactor[];
  risk_factors: string[];
  mitigating_factors: string[];
  metadata: Record<string, unknown>;
};

// --- Agent Transcript types ---

export type AgentObservation = {
  step: number;
  type: string;
  content: string;
  timestamp: string;
  tool_name?: string;
};

// --- Agent Stats types (Track 107) ---

export type AgentStatsByType = {
  count: number;
  tokens: number;
  avg_elapsed: number;
};

export type AgentStats = {
  total_tasks: number;
  total_tokens: number;
  avg_elapsed_seconds: number;
  by_agent_type: Record<string, AgentStatsByType>;
  by_status: Record<string, number>;
  recent_trend: Array<{ date: string; tokens: number; count: number }>;
};

// --- RBAC Admin types ---

export type AdminUser = {
  username: string;
  roles: string[];
};

export type RoleDetail = {
  description: string;
  permissions: string[];
  resource_permissions: Record<string, string[]>;
};

export type RolesResponse = {
  roles: Record<string, RoleDetail>;
};

// --- Orchestration Agent types (Track 93) ---

export type PluginSelection = {
  plugin_name: string;
  reason: string;
  priority: 1 | 2 | 3;
  time_budget_seconds: number;
};

export type OrchestrationData = {
  selected_plugins: PluginSelection[];
  excluded_plugins: Array<{ name: string; reason: string }>;
  profile_name: string;
  estimated_time: string;
  reasoning: string;
  app_category: string;
  attack_surface: string[];
  token_usage: Record<string, number>;
  task_id: string;
};

// --- Triage Agent types (Track 99) ---

export type ClassifiedFinding = {
  finding_title: string;
  classification: 'confirmed_tp' | 'likely_tp' | 'needs_review' | 'likely_fp' | 'informational';
  severity: string;
  confidence: number;
  reasoning: string;
  group_id?: string;
};

export type FindingGroup = {
  id: string;
  label: string;
  root_cause: string;
  finding_titles: string[];
};

export type TriageData = {
  classified_findings: ClassifiedFinding[];
  groups: FindingGroup[];
  priority_order: string[];
  summary: string;
  triage_notes: Record<string, string>;
  token_usage: Record<string, number>;
  task_id: string;
  method?: string; // "llm" | "heuristic" | "heuristic_fallback"
};

// --- Remediation Agent types (Track 100) ---

export type FindingRemediation = {
  finding_title: string;
  vulnerability_type: string;
  cwe_id?: string;
  current_code: string;
  fixed_code: string;
  explanation: string;
  difficulty: 'easy' | 'moderate' | 'complex';
  breaking_changes: string;
  references: string[];
  test_suggestion: string;
};

export type RemediationData = {
  remediations: FindingRemediation[];
  summary: string;
  total_findings: number;
  total_with_patches: number;
  overall_effort: string;
  token_usage: Record<string, number>;
  task_id: string;
  method?: string;
};

// --- Pipeline types (Track 96) ---

export type PipelineStepResult = {
  agent_type: string;
  status: 'completed' | 'failed' | 'skipped' | 'budget_exceeded' | 'timeout';
  task_id: string;
  token_usage: Record<string, number>;
  elapsed_seconds: number;
  error?: string;
};

export type PipelineResult = {
  steps: PipelineStepResult[];
  total_token_usage: Record<string, number>;
  total_elapsed_seconds: number;
  status: string;
  summary: string;
};

// --- Triage Feedback History types (Track 101) ---

export type TriageFeedbackHistoryItem = {
  finding_title: string;
  action: string;
  new_classification: string;
  reason: string;
  user: string;
  timestamp: string;
  scan_id: string;
  similarity_score: number;
};

export type TriageFeedbackHistoryResponse = {
  results: TriageFeedbackHistoryItem[];
  total: number;
  vector_db_available: boolean;
};

// --- Malware Family types ---

export type MalwareFamily = {
  name: string;
  category: string;
  severity: string;
  description: string;
  package_patterns: string[];
  class_patterns: string[];
  string_signatures: string[];
};

export type MalwareFamiliesResponse = {
  families: MalwareFamily[];
  total: number;
  version: string;
};

// --- IoC Export types (Track 117.16) ---

export type IoCEntry = {
  type: string;
  value: string;
  source: string;
  severity: string;
  confidence: number;
  context?: Record<string, string>;
};

export type IoCExportResponse = {
  scan_id: string;
  apk_name: string;
  iocs: IoCEntry[];
  total: number;
  static_count: number;
  dynamic_count: number;
  exported_at: string;
};

export type IoCCluster = {
  ioc_value: string;
  ioc_type: string;
  apk_names: string[];
  scan_ids: string[];
  count: number;
};

export type IoCStatsResponse = {
  total_iocs: number;
  total_scans: number;
  type_distribution: Record<string, number>;
};

// --- AutoResearch types ---

export type AutoResearchExperiment = {
  id: number;
  run_id: string;
  experiment_num: number;
  params: Record<string, number>;
  aqs: number;
  detection_score: number;
  fp_penalty: number;
  stability_bonus: number;
  accepted: boolean;
  reason: string;
  per_apk: any[];
  elapsed_seconds: number;
  baseline_aqs: number;
  created_at: string;
};

export type AutoResearchParamBounds = {
  name: string;
  json_path: string;
  min_value: number;
  max_value: number;
  default_value: number;
  step: number;
  tier: number;
};

export type AutoResearchConfig = {
  defaults: Record<string, any>;
  parameter_space: {
    tier_1: AutoResearchParamBounds[];
    tier_2: AutoResearchParamBounds[];
    tier_3: AutoResearchParamBounds[];
  };
  total_params: number;
  aqs_formula: string;
};

// --- APK Inspection types ---

export type ApkInspectResult = {
  apk_path: string;
  file_size: number;
  file_name: string;
  packageName?: string;
  warning?: string;
};

// --- Attack Surface Graph ---

export type AttackSurfaceNode = {
  id: string;
  node_type: 'activity' | 'service' | 'receiver' | 'provider' | 'permission' | 'entry_point' | 'deep_link' | 'warning' | 'app_config';
  label: string;
  metadata: Record<string, any>;
  findings: string[];
  severity: string | null;
};

export type AttackSurfaceEdge = {
  source: string;
  target: string;
  relationship: 'exports' | 'requires_permission' | 'intent_filter' | 'ipc_call' | 'attack_chain';
  metadata: Record<string, any>;
};

export type AttackSurfaceGraph = {
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  stats: {
    total_components: number;
    exported: number;
    permissions: number;
    dangerous_permissions?: number;
    permission_combos?: number;
    deep_links: number;
    findings_mapped: number;
    attack_chains: number;
    total_findings: number;
    mitre_techniques_total?: number;
  };
};

// --- Environment Variables ---

export type EnvVarEntry = {
  name: string;
  description: string;
  type: string;
  default: any;
  current: any;
  is_set: boolean;
};

export type EnvSummaryResponse = {
  categories: Record<string, EnvVarEntry[]>;
};

export type DiffStatus = 'added' | 'removed' | 'changed' | 'unchanged';
