#!/usr/bin/env bash
# import_n8n_workflows.sh
#
# Imports all BluJay workflow definitions into a running n8n instance via the
# n8n REST API. Run this once after `docker compose up -d n8n` to pre-load all
# Layer 1 workflows.
#
# Usage:
#   ./scripts/import_n8n_workflows.sh [N8N_URL] [USER] [PASSWORD]
#
# Defaults:
#   N8N_URL  = http://localhost:5678
#   USER     = admin
#   PASSWORD = blujay

set -euo pipefail

N8N_URL="${1:-http://localhost:5678}"
N8N_USER="${2:-${N8N_ADMIN_USER:-admin}}"
N8N_PASS="${3:-${N8N_ADMIN_PASSWORD:-blujay}}"

WORKFLOWS_DIR="$(cd "$(dirname "$0")/../workflows" && pwd)"
AUTH_HEADER="$(printf '%s:%s' "$N8N_USER" "$N8N_PASS" | base64)"

echo "→ n8n URL   : $N8N_URL"
echo "→ Workflows : $WORKFLOWS_DIR"
echo ""

# ── Wait for n8n to be ready ─────────────────────────────────────────────────
echo "Waiting for n8n to be ready..."
for i in $(seq 1 30); do
  if curl -sf -o /dev/null "$N8N_URL/healthz"; then
    echo "✓ n8n is up"
    break
  fi
  sleep 2
done

# ── Import each workflow JSON ─────────────────────────────────────────────────
IMPORTED=0
FAILED=0

for f in "$WORKFLOWS_DIR"/*.json; do
  name="$(basename "$f")"
  echo -n "  Importing $name ... "

  HTTP_STATUS=$(curl -s -o /tmp/n8n_import_resp.json -w "%{http_code}" \
    -X POST "$N8N_URL/api/v1/workflows" \
    -H "Authorization: Basic $AUTH_HEADER" \
    -H "Content-Type: application/json" \
    --data-binary "@$f")

  if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
    WF_ID=$(python3 -c "import json,sys; d=json.load(open('/tmp/n8n_import_resp.json')); print(d.get('id','?'))" 2>/dev/null || echo "?")
    echo "✓ (id=$WF_ID)"
    IMPORTED=$((IMPORTED + 1))
  else
    echo "✗ HTTP $HTTP_STATUS"
    cat /tmp/n8n_import_resp.json 2>/dev/null || true
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "Done — imported: $IMPORTED  failed: $FAILED"
echo ""
echo "Open n8n UI: $N8N_URL"
echo "  Add credentials in Settings → Credentials:"
echo "    - BluJay Slack (Slack API token with chat:write, commands scopes)"
echo "    - BluJay SMTP  (SMTP for nightly report emails)"
echo ""
echo "  Set workflow variables (Settings → Variables):"
echo "    BLUJAY_BASE_URL          http://app:8000/api/v1  (or host-gateway:8000)"
echo "    SLACK_SECURITY_CHANNEL   #security-alerts"
echo "    NIGHTLY_SCAN_TARGETS     https://target1.com,https://target2.com"
echo "    TARGET_BASE_URL          https://your-main-target.com"
echo "    REPORT_TO_EMAIL          security@yourdomain.com"
echo "    REPORT_FROM_EMAIL        blujay-noreply@yourdomain.com"
