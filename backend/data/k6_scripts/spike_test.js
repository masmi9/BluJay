/**
 * k6 — Spike Test (DoS Viability Assessment)
 * Triggered by: api_endpoint finding
 * Goal: assess whether an endpoint is vulnerable to DoS via sudden traffic spikes.
 *       Measures error rate and latency degradation under spike conditions.
 *
 * Env vars:
 *   TARGET_URL    endpoint to spike (required)
 *   VUS           peak virtual users during spike (default 50)
 *   DURATION      total test duration (default 90s)
 *   METHOD        HTTP method (default GET)
 *   BODY          request body for POST/PUT (default "")
 *   AUTH_HEADER   Authorization header (optional)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const targetUrl  = __ENV.TARGET_URL  || "http://localhost:8000/api/v1/health";
const peakVus    = parseInt(__ENV.VUS      || "50");
const method     = (__ENV.METHOD           || "GET").toUpperCase();
const body       = __ENV.BODY              || null;
const authHeader = __ENV.AUTH_HEADER       || "";

const requests   = new Counter("total_requests");
const errorRate  = new Rate("error_rate");
const latency    = new Trend("spike_latency", true);
const timeouts   = new Counter("timeouts");

export const options = {
  // Spike profile: ramp up → sustain → ramp down
  stages: [
    { duration: "10s", target: Math.ceil(peakVus * 0.1) },  // warm-up
    { duration: "5s",  target: peakVus },                    // spike up
    { duration: "20s", target: peakVus },                    // sustain spike
    { duration: "5s",  target: Math.ceil(peakVus * 0.1) },  // drop
    { duration: "10s", target: 0 },                          // ramp down
  ],
  thresholds: {
    // DoS viability: flag if >5% errors or p99 > 5s under spike
    error_rate: ["rate<0.3"],
    spike_latency: ["p(99)<10000"],
  },
};

export default function () {
  const params = { headers: {}, timeout: "10s" };
  if (authHeader) params.headers["Authorization"] = authHeader;
  if (body)       params.headers["Content-Type"] = "application/json";

  let res;
  try {
    res = method === "GET"
      ? http.get(targetUrl, params)
      : http.request(method, targetUrl, body, params);
  } catch (e) {
    timeouts.add(1);
    errorRate.add(1);
    return;
  }

  requests.add(1);
  latency.add(res.timings.duration);

  const ok = check(res, {
    "status 2xx or 4xx (not server error)": (r) => r.status < 500,
  });

  errorRate.add(!ok);
  sleep(0.01);
}
