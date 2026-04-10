# AODS Requirements

Modular dependency files for different AODS use cases.

## Quick Selection

| Use Case | File | Install Command |
|----------|------|-----------------|
| Core functionality | `base.txt` | `pip install -r requirements/base.txt` |
| Full analysis | `analysis.txt` | `pip install -r requirements/analysis.txt` |
| Docker deployment | `docker.txt` | `pip install -r requirements/docker.txt` |
| Development | `dev.txt` | `pip install -r requirements/dev.txt` |

## File Descriptions

### `base.txt` - Core Requirements
Essential dependencies: CLI interface, APK analysis, data processing, basic reporting.

Use for: minimal installs, CI/CD, container base images.

### `analysis.txt` - Full Analysis
All base requirements plus Frida, mitmproxy, YARA, ML detection, advanced reporting.

Use for: full AODS functionality (recommended for most users).

### `docker.txt` - Docker Deployment
Base requirements plus FastAPI, uvicorn, database connectivity, monitoring. No dev tools.

Use for: Docker images and production deployments.

### `dev.txt` - Development
Full analysis plus testing (pytest, playwright), code quality (black, flake8), debugging tools.

Use for: contributing to AODS or local development.

## Dependency Hierarchy

```
dev.txt
└── analysis.txt
    └── base.txt

docker.txt
└── base.txt
```

## Installation

```bash
# Create virtual environment (must be named aods_venv)
python -m venv aods_venv
source aods_venv/bin/activate

# Install for your use case
pip install -r requirements/analysis.txt
```

## Adding Dependencies

1. Core functionality -> `base.txt`
2. Analysis features -> `analysis.txt`
3. Docker/API features -> `docker.txt`
4. Development tools -> `dev.txt`
