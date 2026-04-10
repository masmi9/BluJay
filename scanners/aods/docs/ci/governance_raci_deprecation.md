## Governance: RACI + Deprecation Lifecycle

This document defines the governance metadata and lifecycle policies enforced by the CI gates for patterns and related components.

### RACI Metadata
- Fields under `governance.raci` within `patterns/registry.yaml`:
  - `responsible`: list of handles responsible for day-to-day maintenance
  - `accountable`: single handle ultimately accountable for outcomes
  - `consulted`: optional list of SMEs engaged for advice
  - `informed`: optional list of channels or groups to notify on changes

Policy toggles:
- `AODS_GOV_REQUIRE_RACI=1` enforces presence of `governance.raci` for each entry.
- `AODS_GOV_MAX_LAST_REVIEWED_DAYS` defines staleness window for `last_reviewed` (default 365 days).

### Deprecation Lifecycle
- Valid statuses: `active`, `experimental`, `deprecated`.
- When `status: deprecated`, entries must provide a `deprecation` block:
  - `stage`: one of `planned`, `deprecated`, `removed`
  - `decision_by`: accountable decision maker handle
  - `decision_date`: ISO date `YYYY-MM-DD`

### CI Gates
- Pattern Registry Validator: baseline schema and field validation for registry entries.
- RACI + Deprecation Validator: enforces governance policy and deprecation lifecycle. Use `--strict` to fail on warnings.

### Acceptance Criteria
- All registry entries have `owner`, `version`, `status`, `tags`, `risk`, `test_links`, `last_reviewed`.
- `last_reviewed` is an ISO date and not stale beyond configured window.
- When `AODS_GOV_REQUIRE_RACI=1`, each entry has `governance.raci.responsible` and `accountable`.
- Deprecated entries include a valid `deprecation` block with `stage`, `decision_by`, and `decision_date`.


