# Paths
INPUT_PY=examples/python_project
INPUT_JAVA=examples/java_project
OUTPUT_DIR=output
PY_REPORT=$(OUTPUT_DIR)/python_findings.csv
JAVA_REPORT=$(OUTPUT_DIR)/java_findings.csv

# Setup
install:
	pip install -e .

# Run scans
scan-python:
	blujay scan --input $(INPUT_PY) --lang python --output $(PY_REPORT)

scan-java:
	blujay scan --input $(INPUT_JAVA) --lang java --output $(JAVA_REPORT)

# Tests
test:
	pytest tests/

# Clean outputs
clean:
	rm -rf $(OUTPUT_DIR)/*.csv $(OUTPUT_DIR)/*.json $(OUTPUT_DIR)/*.docx

# Reinstall dependencies (after updating setup.py or requirements)
reinstall:
	pip uninstall -y blujay || true
	pip install -e .

# Format and lint
format:
	black .

lint:
	mypy .

# Full run
all: install test scan-python scan-java
