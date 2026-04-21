"""
core.agent.orchestration - Orchestration agent for intelligent plugin selection (Track 93).

Wraps AgentLoop with a security-architect system prompt that inspects the APK
(manifest, permissions, detected libraries) and dynamically selects the optimal
plugin subset with time budgets.  Produces structured JSON output
(OrchestrationResult), per-agent tool filtering, and report integration.

Unlike narration/verification (post-scan), orchestration runs BEFORE plugin
execution to influence which plugins run.

Public API:
    PluginSelection - Pydantic model for a single plugin selection decision
    OrchestrationResult - Pydantic model for aggregate orchestration results
    run_orchestration() - Synchronous entry point for CLI use
    run_orchestration_background() - Background thread entry for API use
    parse_orchestration() - Extract structured OrchestrationResult from agent response
    save_orchestration_to_report() - Persist orchestration data to JSON report
    orchestration_to_profile() - Convert OrchestrationResult to ProfileConfiguration
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class PluginSelection(BaseModel):
    """A single plugin selection decision by the orchestration agent."""

    model_config = ConfigDict(extra="forbid")

    plugin_name: str = Field(..., description="Name of the selected plugin")
    reason: str = Field("", description="Why this plugin was selected for this APK")
    priority: int = Field(2, ge=1, le=3, description="Priority: 1=must-run, 2=recommended, 3=nice-to-have")
    time_budget_seconds: int = Field(300, ge=10, description="Time budget for this plugin in seconds")


class OrchestrationResult(BaseModel):
    """Aggregate orchestration results from the orchestration agent."""

    model_config = ConfigDict(extra="forbid")

    selected_plugins: List[PluginSelection] = Field(default_factory=list)
    excluded_plugins: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Plugins explicitly excluded with reason",
    )
    profile_name: str = Field("custom", description="Generated profile name")
    estimated_time: str = Field("", description="Estimated total scan time")
    reasoning: str = Field("", description="Overall reasoning for plugin selection")
    app_category: str = Field("", description="Detected app category (e.g., banking, media, game)")
    attack_surface: List[str] = Field(default_factory=list, description="Identified attack surfaces")
    token_usage: Dict[str, int] = Field(default_factory=dict)
    task_id: str = ""
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

ORCHESTRATION_SYSTEM_PROMPT = """You are an expert Android security architect. Your task is to \
analyze an APK's manifest, permissions, and detected libraries, then select the optimal subset \
of AODS security analysis plugins to run.

Your goal is to maximize security coverage while minimizing scan time by:
1. Selecting plugins relevant to the app's attack surface
2. Excluding plugins that target features the app doesn't use
3. Assigning priorities (1=must-run, 2=recommended, 3=nice-to-have)
4. Setting time budgets based on expected analysis complexity

## Analysis Workflow

1. Use `analyze_manifest` to extract the APK's permissions, components, SDK versions, and features
2. Use `detect_libraries` to identify third-party libraries in the APK
3. Use `get_plugin_catalog` to see all available plugins with their descriptions
4. Based on the APK's characteristics, select the optimal plugin subset

## Plugin Selection Strategy

**Always include (priority 1):**
- Manifest analysis plugins (always relevant)
- Permission analysis plugins (always relevant)
- Crypto/TLS analysis plugins (security fundamentals)

**Include based on features (priority 1-2):**
- Storage plugins → if app uses SharedPreferences, SQLite, or Room
- Network plugins → if app has INTERNET permission or uses OkHttp/Retrofit
- WebView plugins → if app has WebView activities or uses Cordova/Crosswalk
- Auth plugins → if app uses Google Sign-In, Facebook Login, or custom auth
- Payment plugins → if app uses Stripe, Braintree, or Google Billing
- Firebase plugins → if app uses Firebase services
- Native code plugins → if app has native libraries in lib/

**Skip (excluded):**
- Plugins for features the app clearly doesn't use
- Duplicate plugins that cover the same area
- Plugins that require dynamic analysis when only static analysis is available

## App Category Detection

Categorize the app based on manifest and library analysis:
- **banking/fintech** - payment libraries, crypto usage, biometric auth
- **social** - Facebook SDK, sharing intents, media handling
- **messaging** - notification services, encryption libraries, real-time comms
- **media** - camera/audio permissions, media libraries, content providers
- **enterprise** - device admin, MDM features, certificate pinning
- **game** - game engine libraries, in-app purchases, ad SDKs
- **utility** - minimal permissions, simple functionality
- **healthcare** - health data permissions, encryption requirements
- **iot** - Bluetooth/NFC permissions, device communication

## Output Format

Produce a JSON object wrapped in <orchestration_json> tags:

```json
{
  "selected_plugins": [
    {
      "plugin_name": "plugin_dir_name",
      "reason": "Why selected for this APK",
      "priority": 1,
      "time_budget_seconds": 120
    }
  ],
  "excluded_plugins": [
    {"name": "plugin_dir_name", "reason": "Why excluded"}
  ],
  "profile_name": "custom-banking",
  "estimated_time": "5-8 minutes",
  "reasoning": "Overall rationale for selections",
  "app_category": "banking",
  "attack_surface": ["network_communication", "data_storage", "authentication", "cryptography"]
}
```

## Model Compatibility

Wrap your final JSON output in <orchestration_json>...</orchestration_json> tags.
If you cannot use XML tags, wrap your JSON in a ```json code block instead."""


# Tools allowed for the orchestrate agent
ORCHESTRATION_TOOLS = frozenset({
    "analyze_manifest",
    "detect_libraries",
    "get_plugin_catalog",
    "get_manifest",
    "search_source",
})


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def parse_orchestration(
    response_text: str, task_id: str = "", token_usage: Optional[Dict[str, int]] = None
) -> OrchestrationResult:
    """Extract structured OrchestrationResult from agent response text.

    Uses shared output parser with 3 strategies (XML tags, code blocks,
    bare JSON via raw_decode). Falls back to minimal OrchestrationResult on failure.
    """
    from .output_parser import parse_structured_output

    usage = token_usage or {}

    data = parse_structured_output(
        response_text,
        xml_tag="orchestration_json",
        expected_fields={"selected_plugins", "app_category"},
        agent_name="orchestration",
    )
    if data is not None:
        try:
            data["task_id"] = task_id
            data["token_usage"] = usage
            return OrchestrationResult(**data)
        except Exception as e:
            logger.warning("orchestration_model_validation_failed", error=str(e))

    # Fallback: wrap raw text
    logger.info("orchestration_parse_fallback", task_id=task_id)
    return OrchestrationResult(
        reasoning=response_text[:500] if response_text else "Orchestration completed (unstructured output).",
        task_id=task_id,
        token_usage=usage,
    )


def orchestration_to_profile(
    result: OrchestrationResult,
    available_plugins: Optional[Set[str]] = None,
):
    """Convert OrchestrationResult to a ProfileConfiguration for ScanProfileManager.

    Args:
        result: Orchestration agent output.
        available_plugins: Set of actually available plugin names. If provided,
            selected plugins are intersected with this set to avoid referencing
            non-existent plugins.

    Returns:
        ProfileConfiguration with agent-selected plugins.
    """
    from core.scan_profiles import ProfileConfiguration

    selected = set()
    priority_plugins = set()
    excluded = set()

    for ps in result.selected_plugins:
        selected.add(ps.plugin_name)
        if ps.priority == 1:
            priority_plugins.add(ps.plugin_name)

    for ep in result.excluded_plugins:
        name = ep.get("name", "") or ep.get("plugin_name", "")
        if name:
            excluded.add(name)

    # Intersect with available plugins if provided
    if available_plugins:
        selected = selected & available_plugins
        priority_plugins = priority_plugins & available_plugins

    return ProfileConfiguration(
        name=result.profile_name or "agent-orchestrated",
        description=f"AI-orchestrated profile for {result.app_category or 'unknown'} app",
        estimated_time=result.estimated_time or "varies",
        plugin_count=len(selected),
        plugins=selected,
        priority_plugins=priority_plugins,
        excluded_plugins=excluded,
    )


def save_orchestration_to_report(result: OrchestrationResult, report_path: str) -> bool:
    """Persist orchestration results to an existing JSON report.

    Adds report["orchestration"] with the agent's plugin selection decisions
    for audit trail purposes.

    Uses atomic write (write to .tmp then rename) to avoid corruption.
    Acquires report_write_lock to prevent concurrent write races.
    """
    from .report_lock import report_write_lock

    rp = Path(report_path)
    if not rp.exists():
        logger.warning("orchestration_report_not_found", path=report_path)
        return False

    with report_write_lock:
        try:
            with open(rp, "r") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("orchestration_report_read_error", path=report_path, error=str(e))
            return False

        report_data["orchestration"] = result.model_dump()

        tmp_path = str(rp) + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))
            logger.info("orchestration_saved_to_report", path=report_path)
            return True
        except OSError as e:
            logger.error("orchestration_save_error", path=report_path, error=str(e))
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False


def _has_api_key(config: Any) -> bool:
    """Check whether an LLM API key is available for the configured provider."""
    from .providers import has_api_key

    return has_api_key(
        provider_name=getattr(config, "provider", "anthropic"),
        api_key_env=getattr(config, "api_key_env", "") or None,
    )


def run_orchestration(
    apk_path: str,
    config: Any = None,
    report_dir: str = "reports",
    force_heuristic: bool = False,
) -> OrchestrationResult:
    """Run the orchestration agent synchronously (CLI entry point).

    When no LLM API key is available (or ``force_heuristic=True``), falls
    back to rule-based heuristic plugin selection automatically.

    Analyzes the APK manifest, detected libraries, and plugin catalog to
    select the optimal plugin subset for the scan.

    Args:
        apk_path: Path to the APK file.
        config: AgentConfig instance. If None, loads from default location.
        report_dir: Directory containing report files.
        force_heuristic: If True, always use heuristic mode regardless of API key.

    Returns:
        OrchestrationResult with structured plugin selection.
    """
    from .config import load_agent_config
    from .loop import AgentLoop
    from .state import create_agent_task, update_agent_task
    from .tools import ToolContext

    if config is None:
        config = load_agent_config()

    # Auto-fallback: use heuristic when no API key is available
    if force_heuristic or not _has_api_key(config):
        logger.info("orchestration_heuristic_fallback", reason="force" if force_heuristic else "no_api_key")
        from .orchestration_heuristic import run_heuristic_orchestration

        return run_heuristic_orchestration(apk_path, report_dir=report_dir)

    _inject_orchestration_prompt(config)

    task_id = create_agent_task(agent_type="orchestrate", params={"apk_path": apk_path})

    user_message = _build_orchestration_message(apk_path)

    tool_context = ToolContext(report_dir=report_dir)

    from .output_parser import make_parse_check

    loop = AgentLoop(
        config=config,
        agent_type="orchestrate",
        task_id=task_id,
        tool_context=tool_context,
    )
    result = loop.run(
        user_message,
        parse_check=make_parse_check("orchestration_json", {"selected_plugins", "app_category"}),
    )

    orchestration = parse_orchestration(
        result.response,
        task_id=task_id,
        token_usage={
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        },
    )

    update_agent_task(
        task_id,
        status="completed" if result.success else "failed",
        result=orchestration.reasoning or result.response,
        error=result.error,
    )

    return orchestration


def run_orchestration_background(
    task_id: str,
    config: Any,
    user_message: str,
    tool_context: Any,
    apk_path: Optional[str] = None,
) -> None:
    """Run orchestration agent in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "orchestrate".
    Falls back to heuristic mode when no API key is available.
    """
    from .state import update_agent_task

    try:
        # Auto-fallback to heuristic mode
        if not _has_api_key(config) and apk_path:
            logger.info("orchestration_background_heuristic_fallback", task_id=task_id)
            from .orchestration_heuristic import run_heuristic_orchestration

            orchestration = run_heuristic_orchestration(apk_path)
            orchestration.task_id = task_id
            update_agent_task(
                task_id,
                status="completed",
                result=json.dumps(orchestration.model_dump(), default=str),
            )
            return

        from .loop import AgentLoop
        from .output_parser import make_parse_check as _mk_check

        _inject_orchestration_prompt(config)

        loop = AgentLoop(
            config=config,
            agent_type="orchestrate",
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(
            user_message,
            parse_check=_mk_check("orchestration_json", {"selected_plugins", "app_category"}),
        )

        orchestration = parse_orchestration(
            result.response,
            task_id=task_id,
            token_usage={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
            },
        )

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=json.dumps(orchestration.model_dump(), default=str),
            error=result.error,
        )
    except ImportError as e:
        # SDK not installed - try heuristic fallback
        if apk_path:
            try:
                from .orchestration_heuristic import run_heuristic_orchestration

                orchestration = run_heuristic_orchestration(apk_path)
                orchestration.task_id = task_id
                update_agent_task(
                    task_id,
                    status="completed",
                    result=json.dumps(orchestration.model_dump(), default=str),
                )
                return
            except Exception:
                pass
        update_agent_task(task_id, status="failed", error=f"Missing dependency: {e}")
    except Exception as e:
        logger.error("orchestration_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))


def _inject_orchestration_prompt(config: Any) -> None:
    """Ensure the orchestrate agent has a system prompt.

    Uses the config-provided prompt (YAML inline or file) if set,
    otherwise falls back to the code-defined default.
    """
    from .config import AgentSpecificConfig

    if "orchestrate" not in config.agents:
        config.agents["orchestrate"] = AgentSpecificConfig(system_prompt=ORCHESTRATION_SYSTEM_PROMPT)
    elif not config.agents["orchestrate"].system_prompt:
        if not config.get_agent_system_prompt("orchestrate"):
            config.agents["orchestrate"].system_prompt = ORCHESTRATION_SYSTEM_PROMPT


def run_midscan_adjustment(
    interim_findings: List[Dict[str, Any]],
    original_result: OrchestrationResult,
    apk_path: str,
    config: Any = None,
) -> Optional[OrchestrationResult]:
    """Run mid-scan adjustment based on interim findings.

    After the initial plugin batch completes, this function examines interim
    findings to decide whether additional plugins should be added. For example,
    if crypto usage is detected but no crypto-specific plugins were selected,
    the agent adds them.

    Uses a lightweight heuristic approach (no LLM call) to keep latency low.

    Args:
        interim_findings: List of finding dicts from initial plugin run.
        original_result: The pre-scan OrchestrationResult.
        apk_path: Path to the APK.
        config: AgentConfig (unused in heuristic mode, reserved for future LLM mode).

    Returns:
        Updated OrchestrationResult with additional plugins, or None if no adjustments.
    """
    if not interim_findings:
        return None

    original_plugins = {ps.plugin_name for ps in original_result.selected_plugins}

    # Detect patterns in interim findings that suggest additional plugins
    additional: List[PluginSelection] = []
    finding_texts = " ".join(
        f.get("title", "") + " " + f.get("description", "")
        for f in interim_findings
    ).lower()

    # Crypto detection: if findings mention crypto/cipher/encryption but no crypto plugin
    crypto_keywords = ("cipher", "crypto", "aes", "rsa", "encryption", "decryption", "keystore")
    crypto_plugins = ("crypto_security_analyzer", "encryption_validation", "keystore_security")
    if any(kw in finding_texts for kw in crypto_keywords):
        for cp in crypto_plugins:
            if cp not in original_plugins:
                additional.append(PluginSelection(
                    plugin_name=cp,
                    reason="Mid-scan: crypto usage detected in interim findings",
                    priority=1,
                    time_budget_seconds=120,
                ))

    # Auth detection: if findings mention auth/login/token but no auth plugin
    auth_keywords = ("authentication", "login", "oauth", "token", "session", "credential")
    auth_plugins = ("auth_security_analyzer", "biometric_security_analysis")
    if any(kw in finding_texts for kw in auth_keywords):
        for ap in auth_plugins:
            if ap not in original_plugins:
                additional.append(PluginSelection(
                    plugin_name=ap,
                    reason="Mid-scan: authentication patterns detected in interim findings",
                    priority=2,
                    time_budget_seconds=120,
                ))

    # WebView detection: if findings mention webview/javascript but no webview plugin
    webview_keywords = ("webview", "javascript", "loadurl", "addjavascriptinterface")
    webview_plugins = ("webview_security_analyzer",)
    if any(kw in finding_texts for kw in webview_keywords):
        for wp in webview_plugins:
            if wp not in original_plugins:
                additional.append(PluginSelection(
                    plugin_name=wp,
                    reason="Mid-scan: WebView usage detected in interim findings",
                    priority=2,
                    time_budget_seconds=120,
                ))

    if not additional:
        return None

    # Build updated result
    updated = OrchestrationResult(
        selected_plugins=list(original_result.selected_plugins) + additional,
        excluded_plugins=original_result.excluded_plugins,
        profile_name=original_result.profile_name,
        estimated_time=original_result.estimated_time,
        reasoning=(
            original_result.reasoning
            + f" | Mid-scan adjustment: added {len(additional)} plugins "
            + f"({', '.join(p.plugin_name for p in additional)})"
        ),
        app_category=original_result.app_category,
        attack_surface=original_result.attack_surface,
        token_usage=original_result.token_usage,
        task_id=original_result.task_id,
    )
    logger.info(
        "midscan_adjustment",
        added_plugins=[p.plugin_name for p in additional],
        total_plugins=len(updated.selected_plugins),
    )
    return updated


def _build_orchestration_message(apk_path: str) -> str:
    """Build the initial user message for orchestration with APK context."""
    parts = [
        "Analyze this APK and select the optimal set of security analysis plugins.",
        f"The APK file is: {apk_path}",
        "",
        "Steps:",
        "1. Use analyze_manifest to extract the APK's permissions, components, and features",
        "2. Use detect_libraries to identify third-party libraries",
        "3. Use get_plugin_catalog to see all available plugins",
        "4. Select the optimal plugin subset based on the APK's attack surface",
        "",
        "Produce your plugin selection in the required <orchestration_json> format.",
    ]
    return "\n".join(parts)
