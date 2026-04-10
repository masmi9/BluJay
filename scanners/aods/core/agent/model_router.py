"""
core.agent.model_router - Intelligent model selection per agent type.

Selects the best model for each agent based on task complexity (finding count)
and agent type. Orchestration (manifest analysis) works fine with Haiku.
Triage with few findings can use Haiku. Narration needs Sonnet for synthesis.

Users can override per-agent in config - routing only applies when
no explicit per-agent model is set.
"""

from __future__ import annotations

from typing import Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


# Default model routing per agent type and complexity tier.
# Complexity tiers: simple (< 15 findings), complex (15-50), large (50+).
_AGENT_MODEL_DEFAULTS = {
    "triage": {
        "simple": "claude-haiku-4-5",
        "complex": "claude-sonnet-4-6",
        "large": "claude-sonnet-4-6",
    },
    "verify": {
        "simple": "claude-sonnet-4-6",
        "complex": "claude-sonnet-4-6",
        "large": "claude-sonnet-4-6",
    },
    "remediate": {
        "simple": "claude-haiku-4-5",
        "complex": "claude-sonnet-4-6",
        "large": "claude-sonnet-4-6",
    },
    "narrate": {
        "simple": "claude-sonnet-4-6",
        "complex": "claude-sonnet-4-6",
        "large": "claude-sonnet-4-6",
    },
    "orchestrate": {
        "simple": "claude-haiku-4-5",
        "complex": "claude-haiku-4-5",
        "large": "claude-haiku-4-5",
    },
}

_SIMPLE_THRESHOLD = 15
_LARGE_THRESHOLD = 50


def get_recommended_model(
    agent_type: str,
    finding_count: int = 0,
    provider: str = "anthropic",
    user_override: Optional[str] = None,
) -> str:
    """Select the best model for an agent type and task complexity.

    Args:
        agent_type: Agent type name (triage, verify, etc.).
        finding_count: Number of findings in the report.
        provider: LLM provider. Only Anthropic has tiered models.
        user_override: User-specified model (absolute priority).

    Returns:
        Model name string, or empty string if routing doesn't apply
        (non-Anthropic providers).
    """
    if user_override:
        return user_override

    if provider != "anthropic":
        return ""  # Let provider default handle it

    defaults = _AGENT_MODEL_DEFAULTS.get(agent_type, {})
    if not defaults:
        return "claude-sonnet-4-6"

    if finding_count < _SIMPLE_THRESHOLD:
        tier = "simple"
    elif finding_count < _LARGE_THRESHOLD:
        tier = "complex"
    else:
        tier = "large"

    model = defaults.get(tier, "claude-sonnet-4-6")

    logger.debug(
        "model_routed",
        agent_type=agent_type,
        finding_count=finding_count,
        tier=tier,
        model=model,
    )

    return model


def apply_model_routing(
    config,
    agent_type: str,
    finding_count: int = 0,
) -> None:
    """Apply model routing to config if no per-agent model override exists.

    Modifies config in-place. Only routes when the agent uses the global
    default model (i.e., no explicit per-agent override in YAML).

    Args:
        config: AgentConfig instance (modified in-place).
        agent_type: Agent type name.
        finding_count: Number of findings for complexity-based routing.
    """
    # Check if user has explicitly set a per-agent model
    agent_cfg = config.agents.get(agent_type)
    if agent_cfg and agent_cfg.model is not None:
        return  # User-specified model takes priority

    recommended = get_recommended_model(
        agent_type, finding_count, config.provider,
    )
    if not recommended or recommended == config.model:
        return  # No change needed

    from .config import AgentSpecificConfig

    if agent_type not in config.agents:
        config.agents[agent_type] = AgentSpecificConfig(model=recommended)
    else:
        config.agents[agent_type].model = recommended

    logger.debug(
        "model_routing_applied",
        agent_type=agent_type,
        model=recommended,
        finding_count=finding_count,
    )
