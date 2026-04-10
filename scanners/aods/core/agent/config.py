"""
core.agent.config - Agent configuration loading and validation.

Loads agent config from YAML with environment variable overrides.
All fields have sensible defaults so the system works even without
a config file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


class BudgetConfig(BaseModel):
    """Resource budget limits for a single agent task."""

    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(20, ge=1, le=200)
    max_tokens: int = Field(50000, ge=1000, le=500000)
    max_wall_time_seconds: int = Field(300, ge=10, le=3600)
    cost_limit_usd: float = Field(1.0, ge=0.01, le=100.0)
    max_output_tokens: int = Field(4096, ge=256, le=16384)


class AgentSpecificConfig(BaseModel):
    """Per-agent-type overrides (merged with global defaults)."""

    model_config = ConfigDict(extra="forbid")

    model: Optional[str] = None
    max_iterations: Optional[int] = Field(None, ge=1, le=200)
    max_output_tokens: Optional[int] = Field(None, ge=256, le=16384)
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0, description="LLM sampling temperature")
    system_prompt: Optional[str] = None
    system_prompt_file: Optional[str] = Field(
        None, description="Path to a text file containing the system prompt"
    )


class AgentConfig(BaseModel):
    """Top-level agent configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    model: str = "claude-sonnet-4-6"
    provider: str = Field("anthropic", description="LLM provider: anthropic, openai, ollama")
    api_key_env: str = Field("", description="Env var name for API key (auto-detected if empty)")
    base_url: str = Field("", description="Custom API base URL (e.g. for Ollama)")
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    agents: Dict[str, AgentSpecificConfig] = Field(default_factory=dict)

    def get_agent_model(self, agent_type: str) -> str:
        """Return the model for a specific agent type, falling back to global."""
        agent_cfg = self.agents.get(agent_type)
        if agent_cfg and agent_cfg.model:
            return agent_cfg.model
        return self.model

    def get_agent_max_iterations(self, agent_type: str) -> int:
        """Return max_iterations for a specific agent type, falling back to global."""
        agent_cfg = self.agents.get(agent_type)
        if agent_cfg and agent_cfg.max_iterations is not None:
            return agent_cfg.max_iterations
        return self.budget.max_iterations

    def get_agent_max_output_tokens(self, agent_type: str) -> int:
        """Return max_output_tokens for a specific agent type, falling back to global."""
        agent_cfg = self.agents.get(agent_type)
        if agent_cfg and agent_cfg.max_output_tokens is not None:
            return agent_cfg.max_output_tokens
        return self.budget.max_output_tokens

    # Per-agent temperature defaults - deterministic for classification,
    # slightly creative for narration, precise for code generation.
    _TEMPERATURE_DEFAULTS: Dict[str, float] = {
        "triage": 0.2,
        "verify": 0.1,
        "remediate": 0.2,
        "narrate": 0.6,
        "orchestrate": 0.1,
    }

    def get_agent_temperature(self, agent_type: str) -> Optional[float]:
        """Return temperature for a specific agent type.

        Checks per-agent config first, then built-in defaults.
        Returns None for unknown agent types (provider uses its own default).
        """
        agent_cfg = self.agents.get(agent_type)
        if agent_cfg and agent_cfg.temperature is not None:
            return agent_cfg.temperature
        return self._TEMPERATURE_DEFAULTS.get(agent_type)

    def get_agent_system_prompt(self, agent_type: str) -> Optional[str]:
        """Return system prompt for a specific agent type.

        Checks in order: inline system_prompt, system_prompt_file, None.
        """
        agent_cfg = self.agents.get(agent_type)
        if not agent_cfg:
            return None
        if agent_cfg.system_prompt:
            return agent_cfg.system_prompt
        if agent_cfg.system_prompt_file:
            try:
                prompt_path = Path(agent_cfg.system_prompt_file)
                if not prompt_path.is_absolute():
                    prompt_path = Path(__file__).parent.parent.parent / prompt_path
                if prompt_path.exists():
                    return prompt_path.read_text(encoding="utf-8")
                logger.warning(
                    "agent_prompt_file_not_found",
                    agent_type=agent_type,
                    path=str(prompt_path),
                )
            except Exception as exc:
                logger.warning(
                    "agent_prompt_file_read_failed",
                    agent_type=agent_type,
                    error=str(exc),
                )
        return None


def load_agent_config(path: Optional[str] = None) -> AgentConfig:
    """Load agent config from YAML file with env var overrides.

    Args:
        path: Path to YAML config file. If None, uses default location.

    Returns:
        AgentConfig instance.
    """
    data: dict = {}
    config_path = Path(path) if path else _default_config_path()

    if config_path.exists():
        try:
            import yaml

            with open(config_path, "r") as f:
                raw = yaml.safe_load(f)
            if isinstance(raw, dict):
                data = raw
                logger.debug("agent_config_loaded", path=str(config_path))
        except Exception as exc:
            logger.warning("agent_config_load_failed", path=str(config_path), error=str(exc))
    else:
        logger.debug("agent_config_using_defaults", path=str(config_path))

    # Environment variable overrides
    env_enabled = os.environ.get("AODS_AGENT_ENABLED")
    if env_enabled is not None:
        data["enabled"] = env_enabled.lower() in ("1", "true", "yes")

    env_provider = os.environ.get("AODS_AGENT_PROVIDER")
    if env_provider:
        data["provider"] = env_provider

    env_api_key_env = os.environ.get("AODS_AGENT_API_KEY_ENV")
    if env_api_key_env:
        data["api_key_env"] = env_api_key_env

    env_base_url = os.environ.get("AODS_AGENT_BASE_URL")
    if env_base_url:
        data["base_url"] = env_base_url

    env_model = os.environ.get("AODS_AGENT_MODEL")
    if env_model:
        data["model"] = env_model

    env_max_iter = os.environ.get("AODS_AGENT_MAX_ITERATIONS")
    if env_max_iter:
        try:
            val = int(env_max_iter)
            if not (1 <= val <= 200):
                raise ValueError(f"must be 1-200, got {val}")
            budget = data.get("budget", {})
            if not isinstance(budget, dict):
                budget = {}
            budget["max_iterations"] = val
            data["budget"] = budget
        except ValueError as e:
            logger.warning(
                "agent_config_invalid_env",
                var="AODS_AGENT_MAX_ITERATIONS", value=env_max_iter, error=str(e),
            )

    env_cost = os.environ.get("AODS_AGENT_COST_LIMIT")
    if env_cost:
        try:
            cost_val = float(env_cost)
            if not (0.01 <= cost_val <= 100.0):
                raise ValueError(f"must be 0.01-100.0, got {cost_val}")
            budget = data.get("budget", {})
            if not isinstance(budget, dict):
                budget = {}
            budget["cost_limit_usd"] = cost_val
            data["budget"] = budget
        except ValueError as e:
            logger.warning("agent_config_invalid_env", var="AODS_AGENT_COST_LIMIT", value=env_cost, error=str(e))

    env_wall_time = os.environ.get("AODS_AGENT_MAX_WALL_TIME")
    if env_wall_time:
        try:
            wt_val = int(env_wall_time)
            if not (10 <= wt_val <= 3600):
                raise ValueError(f"must be 10-3600, got {wt_val}")
            budget = data.get("budget", {})
            if not isinstance(budget, dict):
                budget = {}
            budget["max_wall_time_seconds"] = wt_val
            data["budget"] = budget
        except ValueError as e:
            logger.warning(
                "agent_config_invalid_env",
                var="AODS_AGENT_MAX_WALL_TIME", value=env_wall_time, error=str(e),
            )

    return AgentConfig(**data)


def _default_config_path() -> Path:
    """Return the default config file path (repo root / config / agent_config.yaml)."""
    return Path(__file__).parent.parent.parent / "config" / "agent_config.yaml"
