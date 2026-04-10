# Flake Policy and Retries

- Playwright (prod-shell E2E)
  - Workers: 1
  - Retries: 1
  - Acceptable failure rate: 0% on main; ≤ 2% on PRs (investigate if exceeded)

- Jest
  - Retries: off by default; re-run changed tests if supported by runner
  - Acceptable failure rate: 0% on main; ≤ 1% on PRs (investigate if exceeded)

- SSE/WS Reliability
  - No drops during prod-shell smoke; if flake observed, open triage item
