/**
 * k6 — IDOR Enumeration Load Test
 * Triggered by: idor_found finding
 * Goal: sweep an ID range at scale to confirm IDOR exploitability and
 *       measure how many objects are accessible.
 *
 * Env vars:
 *   TARGET_URL    base URL with {ID} placeholder, e.g. "https://api.example.com/users/{ID}"
 *   VUS           virtual users (default 10)
 *   DURATION      test duration (default 45s)
 *   ID_START      start of ID range (default 1)
 *   ID_END        end of ID range (default 1000)
 *   AUTH_HEADER   Authorization header value (optional, victim token)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const targetTemplate = __ENV.TARGET_URL  || "http://localhost:8000/api/users/{ID}";
const vus            = parseInt(__ENV.VUS      || "10");
const duration       = __ENV.DURATION          || "45s";
const idStart        = parseInt(__ENV.ID_START  || "1");
const idEnd          = parseInt(__ENV.ID_END    || "1000");
const authHeader     = __ENV.AUTH_HEADER        || "";

const totalRequests  = new Counter("total_requests");
const accessGranted  = new Counter("idor_access_granted");  // 200 OK for foreign IDs
const forbidden      = new Counter("access_forbidden");     // 403/401
const notFound       = new Counter("not_found");
const errorRate      = new Rate("error_rate");
const latency        = new Trend("idor_latency", true);

let currentId = idStart;

export const options = {
  vus,
  duration,
  thresholds: {
    error_rate: ["rate<0.1"],
    idor_latency: ["p(95)<2000"],
  },
};

export default function () {
  const id = idStart + (currentId++ % (idEnd - idStart + 1));
  const url = targetTemplate.replace("{ID}", id.toString());

  const params = { headers: {} };
  if (authHeader) params.headers["Authorization"] = authHeader;

  const res = http.get(url, params);
  totalRequests.add(1);
  latency.add(res.timings.duration);

  if (res.status === 200) {
    accessGranted.add(1);
  } else if (res.status === 403 || res.status === 401) {
    forbidden.add(1);
  } else if (res.status === 404) {
    notFound.add(1);
  }

  check(res, {
    "not server error": (r) => r.status < 500,
  });

  errorRate.add(res.status >= 500);
  sleep(0.02);
}
