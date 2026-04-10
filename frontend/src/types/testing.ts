export interface TestApp {
  id: number
  created_at: string
  display_name: string
  package_name: string
  apk_path: string | null
  category: string | null
  description: string | null
  is_vulnerable_app: boolean
}

export interface ReproductionStep {
  step: number
  title: string
  category: string
  cwe: string
  description: string
  commands: string[]
  expected_output: string
  evidence: string
  file_ref: string
  attack_path: string
}

export interface TestRun {
  id: number
  created_at: string
  test_app_id: number
  analysis_id: number | null
  owasp_scan_id: number | null
  frida_script_name: string | null
  frida_script_source: string | null
  findings: unknown[]
  finding_count: number
  reproduction_steps: ReproductionStep[]
  true_positives: number
  false_positives: number
  false_negatives: number
  precision: number | null
  recall: number | null
  notes: string | null
}

export interface AccuracyDashboard {
  total_runs: number
  total_tp: number
  total_fp: number
  total_fn: number
  precision: number | null
  recall: number | null
  f1: number | null
}
