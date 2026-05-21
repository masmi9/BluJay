/**
 * k6 — Auth Brute-Force / Rate Limit Test
 * Triggered by: auth_endpoint finding
 * Goal: detect lockout threshold and rate limit enforcement on login endpoints.
 *
 * Env vars:
 *   TARGET_URL          login endpoint URL (required)
 *   VUS                 virtual users (default 5)
 *   DURATION            test duration (default 60s)
 *   USERNAME_FIELD      body field for username (default "username")
 *   PASSWORD_FIELD      body field for password (default "password")
 *   TEST_USERNAME       username to brute-force (default "admin")
 *   RATE_LIMIT_EXPECT   expected 429 threshold per minute (default 10)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const targetUrl       = __ENV.TARGET_URL         || "http://localhost:8000/api/login";
const vus             = parseInt(__ENV.VUS        || "5");
const duration        = __ENV.DURATION            || "60s";
const usernameField   = __ENV.USERNAME_FIELD      || "username";
const passwordField   = __ENV.PASSWORD_FIELD      || "password";
const testUsername    = __ENV.TEST_USERNAME        || "admin";
const rateLimitExpect = parseInt(__ENV.RATE_LIMIT_EXPECT || "10");

const attempts        = new Counter("login_attempts");
const lockouts        = new Counter("lockout_responses");     // 423
const rateLimited     = new Counter("rate_limited_responses"); // 429
const successLogins   = new Counter("successful_logins");
const errorRate       = new Rate("error_rate");
const latency         = new Trend("login_latency", true);

// Wordlist of common weak passwords to cycle through
const passwords = [
  "password", "123456", "password1", "admin", "letmein",
  "qwerty", "monkey", "1234567890", "iloveyou", "princess",
  "welcome", "shadow", "sunshine", "master", "dragon",
];

let attemptIndex = 0;

export const options = {
  vus,
  duration,
  thresholds: {
    error_rate: ["rate<0.5"],
    login_latency: ["p(95)<3000"],
  },
};

export default function () {
  const pwd = passwords[attemptIndex % passwords.length];
  attemptIndex++;

  const body = JSON.stringify({ [usernameField]: testUsername, [passwordField]: pwd });
  const params = { headers: { "Content-Type": "application/json" } };

  const res = http.post(targetUrl, body, params);
  attempts.add(1);
  latency.add(res.timings.duration);

  if (res.status === 200 || res.status === 201) {
    successLogins.add(1);
  } else if (res.status === 423) {
    lockouts.add(1);
  } else if (res.status === 429) {
    rateLimited.add(1);
  }

  check(res, {
    "not server error": (r) => r.status < 500,
  });

  errorRate.add(res.status >= 500);

  // Back off slightly after hitting rate limit to measure lockout window
  if (res.status === 429 || res.status === 423) {
    sleep(1);
  } else {
    sleep(0.05);
  }
}
