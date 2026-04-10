# Structured Logging and Triage SLA

- Structured logging
  - Include: component, stream, item_id, file, line, context ids
  - Use JSON where practical for CI ingestion

- Error context
  - Add gate name, run_id, artifact paths, hints

- Triage SLA (local-only dev)
  - Acknowledge within 24h; fix or downgrade within 72h
  - Record status in MASTER_EXECUTION_PLAN "Live Status" notes
