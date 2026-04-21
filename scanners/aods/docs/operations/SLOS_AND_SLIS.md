# AODS Service Level Objectives & Indicators

**Created:** 2026-01-26
**Scope:** Track 8 - professional Scanner Foundation

---

## Overview

This document defines measurable Service Level Indicators (SLIs) and Service Level Objectives (SLOs) for the AODS scanner. These targets guide development priorities and provide production monitoring criteria.

---

## 1. Scan Performance

### SLI: Scan Completion Latency
**Definition:** Time from scan start to report generation for a single APK.

| Metric | Measurement | Collection Point |
|--------|-------------|-----------------|
| `scan_latency_seconds` | Wall-clock time from scan start to JSON report written | `dyna.py` entry/exit timestamps |
| `plugin_execution_p95_seconds` | 95th percentile individual plugin execution time | `unified_manager.py` plugin timing |
| `batch_processing_seconds` | Time per plugin batch | `unified_manager.py` batch timing |

### SLO: Scan Latency Targets

| APK Size | Static-Only | Full Scan | Measurement |
|----------|-------------|-----------|-------------|
| Small (<10 MB) | < 120s | < 300s | AndroGoat benchmark |
| Medium (10-50 MB) | < 300s | < 600s | Production samples |
| Large (50-100 MB) | < 600s | < 1200s | Production samples |

**Error budget:** 5% of scans may exceed targets (95th percentile).

**Current baseline:** AndroGoat static-only scan completes in ~60s (well within target).

---

## 2. Detection Accuracy

### SLI: Vulnerability Detection Metrics
**Definition:** Precision, recall, and F1 score against ground truth datasets.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `detection_precision` | True positives / (True positives + False positives) | `tools/ci/gates/detection_accuracy_gate.py` |
| `detection_recall` | True positives / (True positives + False negatives) | `tools/ci/gates/detection_accuracy_gate.py` |
| `detection_f1` | Harmonic mean of precision and recall | Computed from above |
| `false_positive_rate` | False positives / Total findings reported | `core/advanced_false_positive_reducer.py` |

### SLO: Detection Accuracy Targets

| Metric | Target | Current | Gate Variable |
|--------|--------|---------|---------------|
| Precision | >= 0.90 | TBD (needs ground truth) | `AODS_ACCURACY_MIN_PRECISION` |
| Recall | >= 0.85 | TBD (needs ground truth) | `AODS_ACCURACY_MIN_RECALL` |
| F1 Score | >= 0.87 | TBD | Computed |
| False Positive Rate | < 5% | < 5% (validated) | `AODS_FP_MAX_RATE` |

**Note:** Ground truth dataset required (Phase 8.2) before accuracy SLOs can be measured.

---

## 3. ML Model Performance

### SLI: Calibration & Prediction Quality
**Definition:** Quality metrics for ML confidence scores and predictions.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `calibration_ece` | Expected Calibration Error | `tools/ci/gates/calibration_quality_gate.py` |
| `calibration_mce` | Maximum Calibration Error | `tools/ci/gates/calibration_quality_gate.py` |
| `fp_reducer_f1` | F1 score of false positive reducer | `core/ai_ml/ml_false_positive_reducer.py` |
| `malware_detection_f1` | F1 score of malware classifier | `models/malware_detection_*/metadata.json` |

### SLO: ML Model Targets

| Metric | Target | Current | Gate Variable |
|--------|--------|---------|---------------|
| ECE | < 0.10 | ~0.05 (validated) | `AODS_ML_MAX_ECE` |
| MCE | < 0.20 | TBD | `AODS_ML_MAX_MCE` |
| FP Reducer F1 | > 0.50 | 0.0 (broken) | - |
| Malware F1 | > 0.80 | 1.0 (hybrid model) | - |
| Calibration Staleness | < 14 days | OK | `AODS_CALIBRATION_TTL_DAYS` |
| F1 Regression Delta | < 0.02 | - | `AODS_MAX_F1_DELTA` |

---

## 4. API Availability

### SLI: Endpoint Responsiveness
**Definition:** HTTP response time and availability for API endpoints.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `api_health_status` | Response from `/api/health` | Health endpoint |
| `api_response_p95_ms` | 95th percentile response time | API middleware |
| `api_error_rate` | 5xx responses / Total requests | API middleware |
| `sse_connection_success_rate` | Successful SSE connections / Attempts | SSE endpoints |

### SLO: API Availability Targets

| Metric | Target | Measurement Window |
|--------|--------|--------------------|
| Health endpoint availability | 99.9% | Rolling 30 days |
| API response time (p95) | < 500ms | Excluding scan start |
| Scan start response time | < 2s | API → background thread launched |
| SSE connection success rate | > 99% | Rolling 24 hours |
| API error rate (5xx) | < 0.1% | Rolling 24 hours |

---

## 5. Plugin Reliability

### SLI: Plugin Execution Success
**Definition:** Plugin execution success rate and discovery completeness.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `plugin_discovery_count` | Number of plugins discovered | `/api/health/plugins` |
| `plugin_execution_success_rate` | Successful executions / Total executions | `unified_manager.py` |
| `plugin_timeout_rate` | Timeouts / Total executions | `unified_manager.py` |
| `plugin_crash_rate` | Unhandled exceptions / Total executions | `unified_manager.py` |

### SLO: Plugin Reliability Targets

| Metric | Target | Current |
|--------|--------|---------|
| Plugins discovered | >= 75 | 75-86 |
| Execution success rate | >= 95% | ~95% |
| Timeout rate | < 5% | < 5% |
| Crash rate | < 1% | < 1% |
| V2 migration rate | >= 75% | 75.6% |

---

## 6. Report Quality

### SLI: Report Completeness & Validity
**Definition:** Structural quality and completeness of generated reports.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `report_valid_json_rate` | Valid JSON reports / Total reports | Report validation |
| `report_findings_count` | Number of findings per report | Report analysis |
| `evidence_completeness` | Fields present / Required fields | `tools/ci/gates/evidence_completeness_gate.py` |
| `evidence_quality_score` | Composite evidence quality | `tools/ci/gates/evidence_quality_gate.py` |

### SLO: Report Quality Targets

| Metric | Target | Gate Variable |
|--------|--------|---------------|
| Valid JSON rate | 100% | - |
| Findings per scan (small APK) | >= 5 | - |
| Evidence completeness (all) | >= 85% | `AODS_EVIDENCE_MIN_ALL` |
| Evidence completeness (per field) | >= 90% | `AODS_EVIDENCE_MIN_FIELD` |
| Evidence quality score | >= 85% | `AODS_EVIDENCE_MIN_QUALITY` |
| Code snippet coverage | >= 85% | `AODS_EVID_Q_MIN_CS` |
| File path coverage | >= 90% | `AODS_EVID_Q_MIN_FP` |
| Line number coverage | >= 80% | `AODS_EVID_Q_MIN_LN` |

---

## 7. Security

### SLI: Authentication & Access Control
**Definition:** Security posture metrics.

| Metric | Definition | Collection Point |
|--------|------------|-----------------|
| `auth_success_rate` | Successful logins / Login attempts | API auth middleware |
| `unauthorized_access_attempts` | 401/403 responses on protected endpoints | API middleware |
| `sse_unauth_connections` | SSE connections without valid token | SSE auth handler |

### SLO: Security Targets

| Metric | Target |
|--------|--------|
| Auth bypass rate | 0% (zero tolerance) |
| SSE unauthenticated access | 0% |
| eval() usage in RBAC | 0 instances |
| Hardcoded credentials | 0 instances |

---

## Monitoring Implementation

### Phase 1 (Current): Health Endpoints
```
GET /api/health       → Overall system health
GET /api/health/ml    → ML subsystem status
GET /api/health/plugins → Plugin discovery status
GET /api/health/scan  → Scan infrastructure status
```

### Phase 2 (Planned): Structured Metrics
- Emit `artifacts/ci_gates/runtime_metrics.json` per scan
- Track scan latency, plugin counts, findings counts
- Compare against SLO thresholds in CI gates

### Phase 3 (Future): Dashboard
- Real-time SLO burn-rate tracking
- Historical trend visualization
- Alerting on SLO budget exhaustion

---

## Measurement Cadence

| Frequency | Metrics |
|-----------|---------|
| Per scan | Latency, plugin success rate, report quality, findings count |
| Per CI run | Quality gate results, accuracy metrics, regression deltas |
| Weekly | ML model staleness, calibration drift |
| Monthly | Overall SLO compliance, error budget consumption |

---

## Error Budget Policy

| SLO Category | Monthly Budget | Action When Exhausted |
|-------------|----------------|----------------------|
| Scan Latency | 5% scans over target | Profile and optimize hot paths |
| Detection Accuracy | 2% below threshold | Retrain models, review FP filter |
| API Availability | 0.1% downtime | Incident review, add redundancy |
| Plugin Reliability | 5% failures | Fix failing plugins, add retries |

---

**Last Updated:** 2026-01-26
