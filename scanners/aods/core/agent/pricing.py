"""
core.agent.pricing - LLM model pricing for cost tracking.

Provides token-to-cost conversion and cost estimation for agent pipelines.
Pricing data is approximate and should be updated periodically.
"""

from __future__ import annotations

from typing import Dict

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

# Pricing per 1M tokens (USD), as of 2026-03.
# "default" is used for unknown models and Ollama (local/free).
_MODEL_PRICING: Dict[str, Dict[str, float]] = {
    # Anthropic
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 0.80, "output": 4.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1": {"input": 2.0, "output": 8.0},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
    "gpt-4.1-nano": {"input": 0.10, "output": 0.40},
    # Local / unknown
    "default": {"input": 0.0, "output": 0.0},
}

# Average tokens per finding per agent (empirical estimate for cost estimation)
_AVG_TOKENS_PER_FINDING = {
    "triage": {"input": 600, "output": 250},
    "verify": {"input": 800, "output": 300},
    "remediate": {"input": 700, "output": 400},
    "narrate": {"input": 500, "output": 350},
}
_DEFAULT_TOKENS_PER_FINDING = {"input": 600, "output": 300}


def get_model_pricing(model: str, provider: str = "anthropic") -> Dict[str, float]:
    """Get pricing for a model. Returns default (free) for unknown models.

    Args:
        model: Model name/ID.
        provider: LLM provider name. Ollama always returns free pricing.

    Returns:
        Dict with "input" and "output" keys (USD per 1M tokens).
    """
    if provider == "ollama":
        return _MODEL_PRICING["default"]
    return _MODEL_PRICING.get(model, _MODEL_PRICING["default"])


def calculate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str,
    provider: str = "anthropic",
) -> float:
    """Calculate cost in USD for given token usage.

    Args:
        input_tokens: Number of input tokens consumed.
        output_tokens: Number of output tokens generated.
        model: Model name/ID.
        provider: LLM provider name.

    Returns:
        Cost in USD (rounded to 6 decimal places).
    """
    pricing = get_model_pricing(model, provider)
    cost = (input_tokens / 1_000_000) * pricing["input"]
    cost += (output_tokens / 1_000_000) * pricing["output"]
    return round(cost, 6)


def estimate_pipeline_cost(
    finding_count: int,
    agent_types: list,
    model: str,
    provider: str = "anthropic",
) -> float:
    """Estimate pipeline cost before execution.

    Uses empirical averages of tokens per finding per agent type.

    Args:
        finding_count: Number of findings in the report.
        agent_types: List of agent types to run.
        model: Model name/ID.
        provider: LLM provider name.

    Returns:
        Estimated cost in USD.
    """
    total_input = 0
    total_output = 0
    for agent_type in agent_types:
        avg = _AVG_TOKENS_PER_FINDING.get(agent_type, _DEFAULT_TOKENS_PER_FINDING)
        total_input += finding_count * avg["input"]
        total_output += finding_count * avg["output"]
    return calculate_cost(total_input, total_output, model, provider)
