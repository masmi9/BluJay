# IODS Makefile

.PHONY: setup install install-full lint test clean api help

PYTHON := python3
VENV := iods_venv
VENV_PYTHON := $(VENV)/bin/python

help:
	@echo "IODS – iOS OWASP Dynamic Scan Framework"
	@echo ""
	@echo "Targets:"
	@echo "  setup        Create venv and install base dependencies"
	@echo "  install      Install analysis dependencies (includes ML)"
	@echo "  install-dev  Install dev dependencies (testing + linting)"
	@echo "  lint         Run flake8"
	@echo "  test         Run pytest"
	@echo "  api          Start FastAPI server (port 8089)"
	@echo "  clean        Remove workspace and compiled files"

setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -r requirements/base.txt
	@echo "Setup complete. Activate with: source $(VENV)/bin/activate"

install:
	$(VENV_PYTHON) -m pip install -r requirements/analysis.txt

install-dev:
	$(VENV_PYTHON) -m pip install -r requirements/dev.txt

lint:
	$(VENV_PYTHON) -m flake8 core/ plugins/ ios_scan.py --max-line-length=120

test:
	$(VENV_PYTHON) -m pytest tests/ -v

api:
	$(VENV_PYTHON) -m uvicorn core.api.server:app --host 127.0.0.1 --port 8089 --reload

clean:
	rm -rf workspace/ reports/ uploads/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
