# AODS Plugin Development Guide

This guide covers developing plugins for AODS (Automated OWASP Dynamic Scan). Plugins extend AODS's analysis capabilities with custom security checks, vulnerability detection, and compliance verification.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Plugin Interface (BasePluginV2)](#plugin-interface-basepluginv2)
3. [PluginFinding Structure](#pluginfinding-structure)
4. [Creating Your First Plugin](#creating-your-first-plugin)
5. [Plugin Discovery Mechanism](#plugin-discovery-mechanism)
6. [Scan Profiles](#scan-profiles)
7. [Best Practices](#best-practices)
8. [Testing Plugins](#testing-plugins)
9. [Legacy Plugin Adaptation](#legacy-plugin-adaptation)
10. [APK Context Reference](#apk-context-reference)

---

## Architecture Overview

AODS uses a modular plugin architecture where each plugin is responsible for a specific type of security analysis.

**Current Status:**
- Plugin counts vary by branch and by discovery configuration.
- `BasePluginV2` is the modern interface; legacy plugins may be wrapped via `LegacyPluginAdapter`.
- To see current counts on your checkout, run: `./aods_venv/bin/python tools/ci/check_baseplugin_v2_compliance.py`

### Key Features

- **Standardized interfaces** via `BasePluginV2`
- **Automatic discovery** of plugins in configured plugin directories (typically `plugins/`)
- **Profile-based selection** for optimized scan performance
- **Lifecycle management** with setup, execute, and cleanup phases
- **Resource monitoring** and timeout protection
- **Finding validation** via `PluginFindingValidator`

### Canonical Import Pattern

Always import plugin components through the unified facade:

```python
# CORRECT: Use the canonical import
from core.plugins import PluginManager, create_plugin_manager
from core.plugins.base_plugin_v2 import BasePluginV2, PluginMetadata, PluginFinding

# NEVER: Do not import from internal modules
# from core.enhanced_plugin_manager import ...  # Wrong!
# from core.robust_plugin_execution_manager import ...  # Wrong!
```

---

## Plugin Interface (BasePluginV2)

All modern plugins must implement the `BasePluginV2` abstract class.

### Required Methods

```python
from core.plugins.base_plugin_v2 import (
    BasePluginV2, PluginMetadata, PluginResult, PluginFinding,
    PluginCapability, PluginStatus, PluginPriority, PluginDependency
)

class MySecurityPlugin(BasePluginV2):

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata (required)."""
        pass

    def execute(self, apk_ctx) -> PluginResult:
        """Execute analysis on the APK context (required)."""
        pass
```

### PluginMetadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | str | Yes | Unique plugin identifier (e.g., "my_security_plugin") |
| `version` | str | Yes | Semantic version (e.g., "1.0.0") |
| `capabilities` | List[PluginCapability] | Yes | Analysis capabilities the plugin provides |
| `dependencies` | List[str \| PluginDependency] | No | External dependencies required |
| `description` | str | No | Human-readable description |
| `author` | str | No | Plugin author |
| `priority` | PluginPriority | No | Execution priority (default: NORMAL) |
| `timeout_seconds` | int | No | Maximum execution time (default: 300) |
| `requires_network` | bool | No | Whether network access is needed |
| `requires_root` | bool | No | Whether root/elevated privileges are needed |
| `tags` | List[str] | No | Searchable tags |
| `decompilation_requirements` | List[str] | No | Required decompilation outputs: `res`, `assets`, `imports`, `debug` |
| `supported_platforms` | List[str] | No | Supported platforms (default: linux, windows, macos) |

### PluginCapability Enum

```python
class PluginCapability(Enum):
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    CRYPTOGRAPHIC_ANALYSIS = "crypto_analysis"
    MANIFEST_ANALYSIS = "manifest_analysis"
    RESOURCE_ANALYSIS = "resource_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    COMPLIANCE_CHECKING = "compliance_checking"
    PERFORMANCE_ANALYSIS = "performance_analysis"
```

### PluginPriority Enum

```python
class PluginPriority(Enum):
    CRITICAL = 1   # Run first
    HIGH = 2
    NORMAL = 3     # Default
    LOW = 4
    BACKGROUND = 5 # Run last
```

### PluginStatus Enum

```python
class PluginStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    PARTIAL_SUCCESS = "partial_success"
    DEPENDENCY_MISSING = "dependency_missing"
    CONFIGURATION_ERROR = "configuration_error"
```

---

## PluginFinding Structure

The `PluginFinding` dataclass is the canonical structure for reporting vulnerabilities.

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `finding_id` | str | **Yes** | Unique identifier (e.g., "hardcoded_key_001") |
| `title` | str | **Yes** | Short, descriptive title |
| `description` | str | **Yes** | Detailed explanation of the finding |
| `severity` | str | **Yes** | One of: `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | float | **Yes** | Confidence score 0.0-1.0 |
| `file_path` | str | No | Source file where issue was found |
| `line_number` | int | No | Line number in source file |
| `code_snippet` | str | No | Relevant code excerpt |
| `vulnerability_type` | str | No | Type classification |
| `cwe_id` | str | No | CWE identifier (e.g., "CWE-798") |
| `owasp_category` | str | No | OWASP Mobile category (e.g., "M2") |
| `masvs_control` | str | No | MASVS control identifier |
| `evidence` | Dict[str, Any] | No | Supporting evidence and context |
| `remediation` | str | No | How to fix the issue |
| `references` | List[str] | No | URLs for additional information |
| `detected_at` | float | No | Unix timestamp (auto-populated) |
| `plugin_version` | str | No | Plugin version that found it |

### Severity Guidelines

| Severity | Score | Description |
|----------|-------|-------------|
| `critical` | 9.0-10.0 | Remote code execution, authentication bypass, data breach |
| `high` | 7.0-8.9 | Sensitive data exposure, privilege escalation |
| `medium` | 4.0-6.9 | Limited data exposure, requires user interaction |
| `low` | 0.1-3.9 | Information disclosure, defense-in-depth issues |
| `info` | 0.0 | Best practice recommendations |

### Confidence Guidelines

| Confidence | Description |
|------------|-------------|
| 0.9-1.0 | Verified finding with concrete evidence |
| 0.7-0.89 | High confidence, pattern match with context |
| 0.5-0.69 | Moderate confidence, may need manual verification |
| 0.3-0.49 | Low confidence, possible false positive |
| 0.0-0.29 | Heuristic match, requires human review |

---

## Creating Your First Plugin

### Directory Structure

```
plugins/
└── my_security_plugin/
    ├── __init__.py          # Empty or exports
    ├── v2_plugin.py         # Main plugin implementation
```

Recommended tests layout (to avoid accidental plugin discovery of test files):

```
tests/
└── unit/
    └── plugins/
        └── my_security_plugin/
            └── test_my_security_plugin.py
```

### Complete Example

```python
#!/usr/bin/env python3
"""
My Security Plugin - Custom vulnerability detection.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import re
import time
from typing import List

from core.plugins.base_plugin_v2 import (
    BasePluginV2, PluginMetadata, PluginResult, PluginFinding,
    PluginCapability, PluginStatus, PluginPriority, PluginDependency
)


class MySecurityPlugin(BasePluginV2):
    """
    Custom security analyzer for detecting specific vulnerabilities.
    """

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="my_security_plugin",
            version="1.0.0",
            description="Detects custom security vulnerabilities",
            author="Your Name",

            capabilities=[
                PluginCapability.STATIC_ANALYSIS,
                PluginCapability.VULNERABILITY_DETECTION
            ],

            dependencies=[
                PluginDependency(
                    name="re",
                    description="Regular expressions",
                    optional=False
                )
            ],

            priority=PluginPriority.NORMAL,
            timeout_seconds=120,

            tags=["security", "custom", "static"],
            # supported_platforms refers to the host OSes this plugin supports
            # (AODS scans Android apps; this is not the target app platform).
            supported_platforms=["linux", "windows", "macos"]
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute the security analysis."""
        findings = []

        try:
            # Perform analysis using APK context
            findings = self._analyze_source_files(apk_ctx)

            return self.create_result(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    # In core/apk_ctx.py, source_files is dict[str, str] (path -> content)
                    "files_scanned": len(getattr(apk_ctx, 'source_files', {}) or {}),
                    "patterns_checked": 5
                }
            )

        except Exception as e:
            self.logger.error("analysis_failed", error=str(e), exc_info=True)
            return self.create_result(
                status=PluginStatus.FAILURE,
                error_message=str(e)
            )

    def _analyze_source_files(self, apk_ctx) -> List[PluginFinding]:
        """Scan source files for vulnerabilities."""
        findings = []

        # Access decompiled source files
        source_dir = getattr(apk_ctx, 'jadx_output_dir', None)
        if not source_dir:
            return findings

        # Example: Search for hardcoded credentials
        pattern = re.compile(r'password\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

        for java_file in Path(source_dir).rglob("*.java"):
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1

                    finding = self.create_finding(
                        finding_id=f"hardcoded_password_{len(findings):03d}",
                        title="Hardcoded Password Detected",
                        description=f"Found hardcoded password in source code at line {line_num}",
                        severity="high",
                        confidence=0.9,
                        file_path=str(java_file.relative_to(source_dir)),
                        line_number=line_num,
                        code_snippet=match.group(0)[:100],
                        cwe_id="CWE-798",
                        owasp_category="M2",
                        remediation="Store credentials securely using Android Keystore or encrypted SharedPreferences."
                    )
                    findings.append(finding)
            except Exception as e:
                self.logger.warning(f"Could not scan {java_file}: {e}")

        return findings


# Plugin factory function (optional but recommended)
def create_plugin() -> MySecurityPlugin:
    """Create plugin instance."""
    return MySecurityPlugin()


# Export the plugin class
__all__ = ['MySecurityPlugin', 'create_plugin']
```

### Using Helper Methods

`BasePluginV2` provides convenience methods:

```python
# Create a finding with auto-populated fields
finding = self.create_finding(
    finding_id="my_finding_001",
    title="Security Issue",
    description="Detailed description",
    severity="medium",
    confidence=0.85,
    cwe_id="CWE-123"
)

# Create a result with timing info
result = self.create_result(
    status=PluginStatus.SUCCESS,
    findings=[finding],
    metadata={"custom_key": "value"}
)
```

### Optional Lifecycle Methods

```python
def validate_dependencies(self) -> Dict[str, bool]:
    """Validate plugin dependencies (auto-implemented)."""
    pass

def can_execute(self, apk_ctx) -> tuple[bool, Optional[str]]:
    """Check if plugin can execute in current context."""
    pass

def setup(self, apk_ctx) -> bool:
    """Optional setup before execution."""
    pass

def cleanup(self, apk_ctx) -> None:
    """Optional cleanup after execution."""
    pass
```

---

## Plugin Discovery Mechanism

AODS discovers plugins through directory scanning (see `core/plugins/unified_manager.py`):

1. **Directory Scan**: configured plugin directories are scanned recursively (default is typically `plugins/`; config may override this)
2. **File Detection**: any `*.py` can be considered (including `__init__.py`)
3. **Heuristic Classification**: a file is treated as "plugin-like" if it matches common plugin patterns (e.g., `run_plugin(...)`, `execute(...)`, `class <Something>Plugin`, `PLUGIN_*`)
4. **Registration**: "plugin-like" files are registered in the discovery registry (this is not the same as being a `BasePluginV2` plugin)
5. **Execution Entry Point Resolution**: at runtime, execution tries module-level entrypoints (`analyze()`, `run()`, `execute()`, `run_plugin()`) and then the v2 factory pattern (`create_plugin() -> instance.execute()`)

### Important: avoid accidental discovery of tests/helpers

Because discovery is heuristic and broad, **do not put unit tests under `plugins/**`** unless they are guaranteed to not match plugin heuristics.

Recommended:
- Put plugin tests under `tests/unit/plugins/<plugin_name>/...` (preferred)
- If you must keep plugin-local tests, avoid names like `*Plugin` in test class names (e.g., use `TestMySecurity` not `TestMySecurityPlugin`) and avoid defining `execute()` / `run_plugin()` helpers in test modules.

### Discovery Requirements

For a **BasePluginV2** plugin to behave as intended, it should:

1. Live under `plugins/<your_plugin>/...`
2. Provide one of these executable entrypoints:
   - **Preferred (v2 factory)**: `create_plugin()` returning an instance with `execute(apk_ctx) -> PluginResult`
   - **Legacy module function**: `run_plugin(apk_ctx)` (or `run(...)`/`execute(...)`/`analyze(...)`)
3. Implement `BasePluginV2` and return a `PluginResult` with `PluginFinding` objects

### Manual Registration

For special cases, use the factory function:

```python
from core.plugins import create_plugin_manager

manager = create_plugin_manager(
    scan_mode="safe",
    plugin_directories=["plugins/", "custom_plugins/"]
)
```

---

## Scan Profiles

Plugins are selected based on scan profiles for performance optimization:

| Profile | Plugins | Use Case | Time |
|---------|---------|----------|------|
| `lightning` | ~12 | Quick CI checks, credential detection | ~60s |
| `fast` | ~18 | Regular testing, common vulnerabilities | 2-3 min |
| `standard` | 43 | Production scans, full security coverage | 5-8 min |
| `deep` | All | Security audits, full compliance | 15+ min |

### Profile Selection Logic

From `core/scan_profiles.py`:

```python
# LIGHTNING: Focus on credentials/secrets
plugins={
    "insecure_data_storage",
    "cryptography_tests",
    "enhanced_data_storage_analyzer",
    "authentication_security_analysis",
    "jadx_static_analysis",
    "enhanced_static_analysis",
    "enhanced_manifest_analysis",
    # ...
}

# DEEP: All available plugins except explicitly excluded
def get_plugins_for_profile(profile, available_plugins):
    if profile == ScanProfile.DEEP:
        return available_plugins - config.excluded_plugins
```

### Adding Your Plugin to Profiles

Edit `core/scan_profiles.py` to include your plugin:

```python
# In ScanProfileManager._initialize_profiles()

profiles[ScanProfile.FAST] = ProfileConfiguration(
    plugins={
        "existing_plugin_1",
        "my_security_plugin",  # Add your plugin here
        # ...
    },
    # ...
)
```

### Profile Selection Criteria

- **LIGHTNING**: fast CI-focused static-first scan (targeted plugin set; implementation documents ~30–60s)
- **FAST**: common security issues (~2–3 min)
- **STANDARD**: full security coverage (~5-8 min)
- **DEEP**: all available plugins (15+ min)

---

## Best Practices

### Performance

```python
def execute(self, apk_ctx) -> PluginResult:
    # 1. Check for required data early
    if not getattr(apk_ctx, 'jadx_output_dir', None):
        return self.create_result(
            status=PluginStatus.SKIPPED,
            error_message="No decompiled source available"
        )

    # 2. Use generators for large file iteration
    def scan_files():
        for java_file in Path(source_dir).rglob("*.java"):
            yield from self._scan_file(java_file)

    # 3. Limit file sizes to prevent memory issues
    for file_path in files:
        if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
            self.logger.warning(f"Skipping large file: {file_path}")
            continue
```

### Error Handling

```python
def execute(self, apk_ctx) -> PluginResult:
    findings = []
    errors = []

    try:
        for check in self.security_checks:
            try:
                findings.extend(check(apk_ctx))
            except Exception as e:
                errors.append(f"{check.__name__}: {e}")
                self.logger.warning(f"Check failed: {check.__name__}", exc_info=True)

        # Return partial success if some checks passed
        if findings and errors:
            return self.create_result(
                status=PluginStatus.PARTIAL_SUCCESS,
                findings=findings,
                warning_messages=errors
            )
        elif errors:
            return self.create_result(
                status=PluginStatus.FAILURE,
                error_message="; ".join(errors)
            )
        else:
            return self.create_result(
                status=PluginStatus.SUCCESS,
                findings=findings
            )
    except Exception as e:
        return self.create_result(
            status=PluginStatus.FAILURE,
            error_message=str(e)
        )
```

### Logging

```python
# Use the built-in logger (structlog-based)
self.logger.debug("scan_file", file_path=str(file_path))
self.logger.info("findings_count", count=len(findings))
self.logger.warning("large_file_skipped", file_path=str(file_path), size_bytes=file_path.stat().st_size)
self.logger.error("analysis_failed", exc_info=True)
```

### Finding Quality

```python
# Good: Specific, actionable finding
finding = self.create_finding(
    finding_id="hardcoded_api_key_aws_001",
    title="AWS API Key Hardcoded in Source",
    description=(
        "An AWS access key ID was found hardcoded in the source code. "
        "This key grants access to AWS services and could be extracted "
        "from the APK by an attacker."
    ),
    severity="critical",
    confidence=0.95,
    file_path="com/example/app/AWSClient.java",
    line_number=42,
    code_snippet='private static final String AWS_KEY = "AKIA..."',
    cwe_id="CWE-798",
    owasp_category="M2",
    masvs_control="MSTG-STORAGE-14",
    remediation=(
        "1. Immediately rotate the exposed AWS key\n"
        "2. Use AWS Secrets Manager or environment variables\n"
        "3. Implement runtime key retrieval from a secure backend"
    ),
    references=[
        "https://owasp.org/www-project-mobile-security-testing-guide/"
    ]
)

# Bad: Vague, non-actionable finding
finding = self.create_finding(
    finding_id="issue_1",
    title="Security Issue",
    description="Found a problem",
    severity="medium",
    confidence=0.5
)
```

---

## Testing Plugins

### Where to place tests (important)

Because plugin discovery is heuristic, **avoid placing tests under `plugins/**`**.

Recommended test layout:

```
tests/unit/plugins/<plugin_name>/test_<plugin_name>.py
```

### Unit Test Example

```python
# tests/unit/plugins/my_security_plugin/test_my_security_plugin.py

import pytest
from unittest.mock import Mock
from pathlib import Path
from plugins.my_security_plugin.v2_plugin import MySecurityPlugin
from core.plugins.base_plugin_v2 import PluginStatus


class TestMySecurityPlugin:
    """Unit tests for MySecurityPlugin."""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance."""
        return MySecurityPlugin()

    @pytest.fixture
    def mock_apk_ctx(self, tmp_path):
        """Create mock APK context."""
        ctx = Mock()
        # In core/apk_ctx.py, these are Path objects; mock accordingly.
        ctx.jadx_output_dir = Path(tmp_path)
        # In core/apk_ctx.py, source_files is dict[str, str] (path -> content).
        ctx.source_files = {}
        return ctx

    def test_metadata_required_fields(self, plugin):
        """Verify all required metadata fields are present."""
        metadata = plugin.get_metadata()

        assert metadata.name == "my_security_plugin"
        assert metadata.version
        assert len(metadata.capabilities) > 0

    def test_execute_success(self, plugin, mock_apk_ctx, tmp_path):
        """Test successful execution."""
        # Create test file with vulnerability
        test_file = tmp_path / "TestClass.java"
        test_file.write_text('String password = "secret123";')

        result = plugin.execute(mock_apk_ctx)

        assert result.status == PluginStatus.SUCCESS
        assert len(result.findings) >= 1

    def test_execute_no_source(self, plugin):
        """Test graceful handling of missing source."""
        ctx = Mock()
        ctx.jadx_output_dir = None

        result = plugin.execute(ctx)

        assert result.status == PluginStatus.SKIPPED

    def test_finding_structure(self, plugin, mock_apk_ctx, tmp_path):
        """Verify finding structure compliance."""
        test_file = tmp_path / "Test.java"
        test_file.write_text('String apiKey = "sk-1234567890";')

        result = plugin.execute(mock_apk_ctx)

        if result.findings:
            finding = result.findings[0]
            # Verify required fields
            assert finding.finding_id
            assert finding.title
            assert finding.description
            assert finding.severity in ('critical', 'high', 'medium', 'low', 'info')
            assert 0.0 <= finding.confidence <= 1.0
```

### Running Tests

```bash
# Run plugin-specific tests
pytest tests/unit/plugins/my_security_plugin/ -v

# Run with the full test suite
pytest tests/unit/ -v -k "my_security_plugin"

# Audit BasePluginV2 conformance across plugins (writes an artifact path to stdout)
./aods_venv/bin/python tools/ci/check_baseplugin_v2_compliance.py

# Validate finding structure
./aods_venv/bin/python -c "
from core.plugins.finding_validator import validate_plugin_findings
from plugins.my_security_plugin.v2_plugin import MySecurityPlugin

plugin = MySecurityPlugin()
# result = plugin.execute(mock_ctx)
# valid, summary = validate_plugin_findings(result.findings)
# print(summary)
"
```

### Finding Validation

Use `PluginFindingValidator` for runtime validation:

```python
from core.plugins import PluginFindingValidator, validate_plugin_findings

# Validate single finding
validator = PluginFindingValidator(strict_mode=True)
result = validator.validate_finding(finding)

if not result.is_valid:
    print(f"Errors: {result.errors}")
    print(f"Missing required: {result.missing_required}")

# Validate batch
all_valid, summary = validate_plugin_findings(findings, strict=False)
print(f"Compliance rate: {summary['compliance_rate']:.1%}")
```

---

## Legacy Plugin Adaptation

For existing plugins using the legacy interface, use `LegacyPluginAdapter`:

### Legacy Plugin Format

```python
# Old format (legacy)
def run_plugin(apk_ctx):
    """Legacy plugin entry point."""
    findings = []
    # ... analysis logic ...
    return ("Plugin Title", findings)
```

### Adapter Usage

```python
from core.plugins.base_plugin_v2 import LegacyPluginAdapter

# Wrap legacy plugin
import importlib
legacy_module = importlib.import_module("plugins.legacy_plugin")
adapter = LegacyPluginAdapter(legacy_module, "legacy_plugin")

# Use like a v2 plugin
metadata = adapter.get_metadata()
result = adapter.execute(apk_ctx)
```

### Migration Checklist

- [ ] Create `v2_plugin.py` in plugin directory
- [ ] Implement `BasePluginV2` subclass
- [ ] Define complete `PluginMetadata`
- [ ] Convert findings to `PluginFinding` dataclass
- [ ] Return `PluginResult` with proper status
- [ ] Add unit tests
- [ ] Update scan profile if needed
- [ ] Add deprecation warning to old entry point

---

## APK Context Reference

The `apk_ctx` object provides access to analysis data:

| Attribute | Type | Description |
|-----------|------|-------------|
| `apk_path_str` | str | Original path string passed to `APKContext(...)` |
| `apk_path` | pathlib.Path | Resolved filesystem path to APK |
| `package_name` | Optional[str] | Android package name (may be auto-extracted best-effort) |
| `jadx_output_dir` | pathlib.Path | Output directory for decompilation artifacts |
| `manifest_path` | pathlib.Path | Filesystem path to `AndroidManifest.xml` (if extracted) |
| `manifest_content` | str | Best-effort manifest content (empty string if unavailable) |
| `source_files` | Dict[str, str] | Decompiled source map (relative path -> file content) |
| `activities` | List[dict] | Activity declarations |
| `services` | List[dict] | Service declarations |
| `receivers` | List[dict] | Broadcast receiver declarations |
| `providers` | List[dict] | Content provider declarations |

### Common Access Patterns

```python
# Basic info
package_name = apk_ctx.package_name
apk_path = apk_ctx.apk_path

# Manifest access (best-effort)
manifest_path = apk_ctx.manifest_path
manifest_xml = apk_ctx.manifest_content  # string (may be empty)

# Decompiled sources (if available)
sources_dir = apk_ctx.jadx_output_dir
java_files = list(Path(sources_dir).rglob("*.java"))

# Components
activities = apk_ctx.get_activities()
services = apk_ctx.get_services()
receivers = apk_ctx.get_receivers()
providers = apk_ctx.get_providers()
```

---

## Secret Detection Plugins

AODS includes specialized plugins for detecting hardcoded secrets, credentials, and cryptographic issues.

### Plugin Locations

| Plugin | Path | Purpose |
|--------|------|---------|
| Enhanced Static Analysis | `plugins/enhanced_static_analysis/secret_detector.py` | Pattern-based secret detection with entropy analysis |
| Insecure Data Storage | `plugins/insecure_data_storage/secret_detector.py` | Hash security and password storage analysis |

### Secret Detection Patterns

The enhanced static analysis secret detector uses pattern matching with entropy analysis:

```python
# Pattern categories and their risk levels
'api_key':      RiskLevel.HIGH      # API keys, client secrets
'private_key':  RiskLevel.CRITICAL  # RSA/EC/DSA private keys
'database_url': RiskLevel.HIGH      # JDBC/MySQL/PostgreSQL URLs
'password':     RiskLevel.HIGH      # Hardcoded passwords
'token':        RiskLevel.HIGH      # Auth tokens, bearer tokens
'certificate':  RiskLevel.MEDIUM    # X509 certs, public keys
```

### Path Exclusions

To prevent false positives from framework/library code, the analyzers exclude certain paths:

**Excluded Path Prefixes** (configured in `config/vulnerability_patterns.yaml`):
- `android/support/` - Android support library
- `androidx/` - AndroidX libraries
- `com/google/` - Google libraries
- `kotlin/` / `kotlinx/` - Kotlin stdlib
- `org/apache/` - Apache libraries
- Test/debug directories

**Configuration:**
```yaml
# In config/vulnerability_patterns.yaml
file_filters:
  exclude_paths:
    - androidx/
    - com/google/
    - org/apache/
    - kotlin/
    - kotlinx/

global_exclusions:
  - .*/android/support/.*
  - .*/androidx/.*
```

### Custom Exclusions

Add custom exclusions via environment variable:
```bash
export AODS_STATIC_EXCLUDE_PATHS="vendor/,third_party/,external/"
```

Or in `config/vulnerability_patterns.yaml`:
```yaml
file_filters:
  exclude_paths:
    - vendor/
    - third_party/
```

### Confidence Calculation

Secret detection confidence is calculated based on:
1. **Entropy** - High entropy strings more likely to be secrets
2. **Pattern match** - Specific patterns (API_KEY=, PASSWORD=) increase confidence
3. **Context** - Location in source (config files vs code)
4. **Value characteristics** - Length, character set, randomness

Example confidence thresholds:
- `>= 0.85`: High confidence (likely real secret)
- `0.65 - 0.85`: Medium confidence (review recommended)
- `< 0.65`: Low confidence (may be false positive)

---

## Additional Resources

| Resource | Location |
|----------|----------|
| BasePluginV2 Source | `core/plugins/base_plugin_v2.py` |
| Plugin Manager Facade | `core/plugins/__init__.py` |
| Finding Validator | `core/plugins/finding_validator.py` |
| Scan Profiles | `core/scan_profiles.py` |
| Example v2 Plugin | `plugins/example_static_analyzer_v2/v2_plugin.py` |
| Secret Detector (Static) | `plugins/enhanced_static_analysis/secret_detector.py` |
| Secret Detector (Storage) | `plugins/insecure_data_storage/secret_detector.py` |
| Vulnerability Patterns | `config/vulnerability_patterns.yaml` |
| Unit Test Examples | `tests/unit/plugins/` |

---

*Last updated: 2026-02-03*
