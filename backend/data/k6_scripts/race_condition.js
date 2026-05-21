/**
 * k6 — Race Condition Test
 * Triggered by: race_condition finding
 * Goal: state mutation under concurrent load — confirms whether the race window
 *       is exploitable at realistic concurrency levels.
 *
 * Env vars (set by BluJay perf runner):
 *   TARGET_URL   full endpoint URL (required)
 *   VUS          virtual users (default 25)
 *   DURATION     test duration (default 30s)
 *   METHOD       HTTP method (default POST)
 *   BODY         JSON body to send (default "{}")
 *   AUTH_HEADER  Authorization header value (optional)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const targetUrl    = __ENV.TARGET_URL   || "http://localhost:8000/api/test";
const vus          = parseInt(__ENV.VUS      || "25");
const duration     = __ENV.DURATION         || "30s";
const method       = (__ENV.METHOD          || "POST").toUpperCase();
const body         = __ENV.BODY             || "{}";
const authHeader   = __ENV.AUTH_HEADER      || "";

const stateChanges = new Counter("state_changes");
const raceFired    = new Counter("race_condition_triggered");
const errorRate    = new Rate("error_rate");
const latency      = new Trend("request_latency", true);

export const options = {
  vus,
  duration,
  thresholds: {
    error_rate: ["rate<0.05"],
    request_latency: ["p(95)<2000"],
  },
};

export default function () {
  const params = { headers: { "Content-Type": "application/json" } };
  if (authHeader) params.headers["Authorization"] = authHeader;

  // Fire requests in a tight burst to maximise race window overlap
  const responses = http.batch(
    Array.from({ length: 5 }, () => [method, targetUrl, body, params])
  );

  let successCount = 0;
  for (const res of responses) {
    const ok = check(res, {
      "status 2xx": (r) => r.status >= 200 && r.status < 300,
    });
    errorRate.add(!ok);
    latency.add(res.timings.duration);
    if (ok) successCount++;
  }

  // Multiple successes in one burst indicates race condition exploitability
  if (successCount > 1) raceFired.add(1);
  stateChanges.add(successCount);

  sleep(0.1);
}
