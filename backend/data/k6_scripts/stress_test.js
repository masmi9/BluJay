/**
 * k6 — Stress Test (Timing-Based Vulnerability Confirmation)
 * Triggered by: slow_response finding
 * Goal: graduated load to find the breaking point and confirm whether
 *       response time variance reveals timing-based vulnerabilities
 *       (SQL injection, blind SSRF, timing oracle).
 *
 * Env vars:
 *   TARGET_URL       endpoint to stress (required)
 *   VUS              max virtual users (default 30)
 *   DURATION         test duration (default 120s)
 *   METHOD           HTTP method (default GET)
 *   BODY             request body (default "")
 *   AUTH_HEADER      Authorization header (optional)
 *   BASELINE_P95_MS  expected baseline p95 latency in ms (default 500)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend, Gauge } from "k6/metrics";

const targetUrl    = __ENV.TARGET_URL        || "http://localhost:8000/api/v1/health";
const maxVus       = parseInt(__ENV.VUS      || "30");
const method       = (__ENV.METHOD           || "GET").toUpperCase();
const body         = __ENV.BODY              || null;
const authHeader   = __ENV.AUTH_HEADER       || "";
const baselineP95  = parseInt(__ENV.BASELINE_P95_MS || "500");

const requests     = new Counter("total_requests");
const errorRate    = new Rate("error_rate");
const latency      = new Trend("stress_latency", true);
const timingAnomaly = new Counter("timing_anomaly");   // latency > 3× baseline

export const options = {
  stages: [
    { duration: "20s", target: Math.ceil(maxVus * 0.2) },  // ramp
    { duration: "30s", target: Math.ceil(maxVus * 0.5) },  // medium load
    { duration: "30s", target: maxVus },                    // full stress
    { duration: "20s", target: Math.ceil(maxVus * 0.5) },  // recovery
    { duration: "20s", target: 0 },
  ],
  thresholds: {
    error_rate: ["rate<0.1"],
    // Stress test intentionally relaxed — we're looking for degradation, not enforcing limits
    stress_latency: ["p(99)<30000"],
  },
};

export default function () {
  const params = { headers: {}, timeout: "30s" };
  if (authHeader) params.headers["Authorization"] = authHeader;
  if (body)       params.headers["Content-Type"] = "application/json";

  let res;
  try {
    res = method === "GET"
      ? http.get(targetUrl, params)
      : http.request(method, targetUrl, body, params);
  } catch (_) {
    errorRate.add(1);
    return;
  }

  requests.add(1);
  latency.add(res.timings.duration);

  // Timing anomaly: response 3× slower than expected baseline signals possible
  // timing oracle (blind SQLi, blind SSRF, etc.)
  if (res.timings.duration > baselineP95 * 3) {
    timingAnomaly.add(1);
  }

  check(res, {
    "not server error": (r) => r.status < 500,
  });

  errorRate.add(res.status >= 500);
  sleep(0.05);
}
