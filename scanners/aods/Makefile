SHELL := /bin/bash

# =============================================================================
# Docker Compose Targets
# =============================================================================
.PHONY: build-dev up-dev up-prod down test-ci test-e2e image-prod pin-digests
.PHONY: clean clean-docker clean-ephemeral logs status secrets-init

# Build images for development profile
build-dev:
	docker compose --profile dev build

# Start development environment (API + UI with hot reload)
up-dev:
	docker compose --profile dev up -d --build
	@echo "Waiting for API to be healthy..."
	@timeout 60 bash -c 'until curl -fsS http://127.0.0.1:8081/api/health >/dev/null 2>&1; do sleep 2; done' || echo "Warning: health check timed out"
	@echo "AODS dev environment ready at http://127.0.0.1:8081"

# Start production environment (security-hardened)
up-prod:
	@if [ ! -f secrets/aods_admin_password ]; then \
		echo "Error: secrets/aods_admin_password not found. Run 'make secrets-init' first."; \
		exit 1; \
	fi
	docker compose --profile prod up -d --build
	@echo "Waiting for API to be healthy..."
	@timeout 60 bash -c 'until curl -fsS http://127.0.0.1:8081/api/health >/dev/null 2>&1; do sleep 2; done' || echo "Warning: health check timed out"
	@echo "AODS production environment ready at http://127.0.0.1:8081"

# Stop all containers and remove orphans
down:
	docker compose --profile dev --profile ci --profile prod --profile e2e down --remove-orphans

# Run pytest in CI container
test-ci:
	docker compose --profile ci run --rm ci-runner pytest -q tests/unit tests/api || true

# Run Playwright E2E tests in container
test-e2e:
	docker compose --profile dev up -d api-ui
	@echo "Waiting for API to be healthy..."
	@timeout 60 bash -c 'until curl -fsS http://127.0.0.1:8081/api/health >/dev/null 2>&1; do sleep 2; done'
	docker compose --profile e2e run --rm playwright || true
	docker compose --profile dev down

# Build multi-arch production images
image-prod:
	docker buildx build --platform linux/amd64,linux/arm64 -f tools/docker/Dockerfile.api-ui -t aods/api-ui:dev .
	docker buildx build --platform linux/amd64,linux/arm64 -f tools/docker/Dockerfile.worker --target runtime -t aods/worker:dev .

# Helper to print current digests for base images
pin-digests:
	@set -e; \
	for img in "$${NODE_BASE:-node:20-alpine}" "$${PY_BASE:-python:3.11-slim}"; do \
	  echo "==> $$img"; \
	  docker pull $$img >/dev/null 2>&1 || true; \
	  docker inspect --format='{{index .RepoDigests 0}}' $$img || true; \
	done

# =============================================================================
# Docker Cleanup Targets
# =============================================================================

# Full cleanup: stop containers, remove volumes, prune system
clean: down
	docker system prune -af --volumes

# Label-based cleanup: remove ephemeral containers and volumes
clean-ephemeral:
	@echo "Removing ephemeral containers..."
	-docker rm -f $$(docker ps -aq --filter "label=com.aods.lifecycle=ephemeral") 2>/dev/null || true
	@echo "Removing ephemeral volumes..."
	-docker volume rm $$(docker volume ls -q --filter "label=com.aods.lifecycle=ephemeral") 2>/dev/null || true

# Docker-specific cleanup (preserves persistent volumes)
clean-docker:
	docker compose --profile dev --profile ci --profile prod --profile e2e down --remove-orphans
	@echo "Removing AODS containers..."
	-docker rm -f $$(docker ps -aq --filter "label=com.aods.service") 2>/dev/null || true
	@echo "Pruning dangling images..."
	-docker image prune -f
	@echo "Pruning old build cache (>7 days)..."
	-docker buildx prune -f --filter until=168h
	@echo "Note: Persistent volumes preserved. Use 'make clean' to remove all volumes."

# View container logs
logs:
	docker compose --profile dev logs -f

# Show container status
status:
	@echo "=== AODS Containers ==="
	@docker ps -a --filter "label=com.aods.service" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@echo "=== AODS Volumes ==="
	@docker volume ls --filter "label=com.aods.persist=true" --format "table {{.Name}}\t{{.Driver}}"

# Initialize secrets directory with placeholder files
secrets-init:
	@mkdir -p secrets
	@if [ ! -f secrets/aods_admin_password ]; then \
		echo "changeme" > secrets/aods_admin_password; \
		echo "Created secrets/aods_admin_password (update with real password)"; \
	fi
	@if [ ! -f secrets/aods_api_token ]; then \
		openssl rand -hex 32 > secrets/aods_api_token 2>/dev/null || echo "generated-token-$$(date +%s)" > secrets/aods_api_token; \
		echo "Created secrets/aods_api_token"; \
	fi
	@chmod 444 secrets/*
	@echo "Secrets initialized in ./secrets/ (add to .gitignore)"

.PHONY: baseline-suite local-gates ml-toggles-test dedup-smoke dedup-effectiveness dedup-perf exec-path-gate external-tools-gate androgoat-dedup local-gates-quick

baseline-suite:
	python tools/ci/run_baseline_suite.py $(REPORT)

local-gates:
	AODS_LOCAL_GATES=1 pytest -q -m integration tests/unit/core/reporting/test_quality_gates_integration.py

ml-toggles-test:
	pytest -q tests/unit/core/reporting/test_ml_pipeline_toggles.py

dedup-smoke:
	python -c "from core.unified_deduplication_framework import deduplicate_findings; r = deduplicate_findings([{'title':'A','severity':'HIGH','category':'X'},{'title':'A','severity':'MEDIUM','category':'X'}]); print(f'dedup: 2 -> {len(r.unique_findings)}')"

dedup-effectiveness:
	python tools/ci/check_dedup_effectiveness.py

dedup-perf:
	python tools/ci/smoke_dedup_performance.py

exec-path-gate:
	python tools/ci/gates/execution_path_gate.py --log scan_results/scan_log

external-tools-gate:
	AODS_STATIC_ONLY_HARD=1 python tools/ci/gates/external_tools_mode_gate.py

androgoat-dedup:
	@if [ ! -f apks/vulnerable_apps/AndroGoat.apk ]; then \
		echo "AndroGoat APK not found at apks/vulnerable_apps/AndroGoat.apk"; \
		echo "Download per CI or place it locally, then re-run."; \
		exit 0; \
	fi
	AODS_DEDUP_AGGREGATE=1 AODS_STATIC_ONLY_HARD=1 python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --formats json --output reports/androgoat_dedup.json || true
	python tools/ci/check_dedup_effectiveness.py --report reports/androgoat_dedup.json || true
	python tools/ci/gates/execution_path_gate.py --log scan_results/scan_log || true
	AODS_STATIC_ONLY_HARD=1 python tools/ci/gates/external_tools_mode_gate.py || true

local-gates-quick:
	bash tools/ci/run_local_gates_quick.sh

.PHONY: precommit
precommit:
	@chmod +x scripts/precommit_local_checks.sh >/dev/null 2>&1 || true
	./scripts/precommit_local_checks.sh

.PHONY: install-precommit-hook
install-precommit-hook:
	@chmod +x scripts/install_precommit_hook.sh >/dev/null 2>&1 || true
	./scripts/install_precommit_hook.sh

.PHONY: dev-gates
dev-gates:
	AODS_SEVERITY_BLOCK=0 AODS_FP_THRESHOLD=0.8 AODS_FP_MAX_RATE=0.05 \
	AODS_EVID_Q_EXCLUDE_GLOB='calib*.json,*calibration*' \
	./aods_venv/bin/python ci_quality_gates.py reports/aods_androgoat_true.json || exit 1

.PHONY: release-gates
release-gates:
	# Example strict run; override MAX_* per release policy
	AODS_SEVERITY_BLOCK=1 AODS_MAX_HIGH=0 AODS_MAX_CRITICAL=0 \
	./aods_venv/bin/python ci_quality_gates.py reports/aods_androgoat_true.json || exit 1

.PHONY: shadow-integrations
shadow-integrations:
	AODS_MSTG_TRACING=1 AODS_USE_MPT=1 AODS_RUN_OSTORLAB_BENCHMARKS=1 \
	python tools/ci/external/mpt_orchestrator.py --dry-run || true
	python tools/ci/benchmarks/generate_ostorlab_summary.py || true
	python tools/ci/gates/generate_pr_summary.py --out artifacts/ci_gates/summary/pr_summary.md || true

# Ultra-conservative WSL run: lowest resource footprint
.PHONY: androgoat-dedup-wsl-ultra
androgoat-dedup-wsl-ultra:
	@if [ ! -f apks/vulnerable_apps/AndroGoat.apk ]; then \
		echo "AndroGoat APK not found at apks/vulnerable_apps/AndroGoat.apk"; \
		echo "Download per CI or place it locally, then re-run."; \
		exit 0; \
	fi
	AODS_STATIC_ONLY_HARD=1 \
	AODS_MAX_WORKERS=1 \
	AODS_DECOMPILATION_MODE=MINIMAL \
	AODS_JADX_THREADS=1 \
	AODS_JADX_MEM_MB=256 \
	AODS_ORCHESTRATOR_TIMEOUT_SEC=1800 \
	AODS_DEDUP_AGGREGATE=1 \
	python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --profile lightning --sequential --disable-ml --disable-enhancements --sample-rate 0.2 --formats json --output reports/androgoat_dedup_ultra.json || true
	PYTHONPATH=. python tools/ci/check_dedup_effectiveness.py --report reports/androgoat_dedup_ultra.json || true
	python tools/ci/gates/execution_path_gate.py --log scan_results/scan_log || true
	AODS_STATIC_ONLY_HARD=1 python tools/ci/gates/external_tools_mode_gate.py || true


# WSL-safe AndroGoat dedup run with static-only hard mode and conservative resources
.PHONY: androgoat-dedup-wsl
androgoat-dedup-wsl:
	@if [ ! -f apks/vulnerable_apps/AndroGoat.apk ]; then \
		echo "AndroGoat APK not found at apks/vulnerable_apps/AndroGoat.apk"; \
		echo "Download per CI or place it locally, then re-run."; \
		exit 0; \
	fi
	AODS_STATIC_ONLY_HARD=1 \
	AODS_MAX_WORKERS=1 \
	AODS_DECOMPILATION_MODE=MINIMAL \
	AODS_JADX_THREADS=1 \
	AODS_JADX_MEM_MB=512 \
	AODS_ORCHESTRATOR_TIMEOUT_SEC=1200 \
	AODS_DEDUP_AGGREGATE=1 \
	python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --formats json --output reports/androgoat_dedup.json || true
	python tools/ci/check_dedup_effectiveness.py --report reports/androgoat_dedup.json || true
	python tools/ci/gates/execution_path_gate.py --log scan_results/scan_log || true
	AODS_STATIC_ONLY_HARD=1 python tools/ci/gates/external_tools_mode_gate.py || true



