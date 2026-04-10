"""
core.autoresearch.llm_guided - LLM-guided optimization mode.

Uses the agent loop from core.agent.loop to have an LLM propose
parameter adjustments based on experiment history and AQS analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .config import ExperimentConfig, ParameterBounds


PROGRAM_PATH = Path(__file__).parent / "program.md"


def _load_program() -> str:
    """Load the strategy document for the LLM."""
    try:
        return PROGRAM_PATH.read_text(encoding="utf-8")
    except OSError:
        return "You are an optimization agent tuning AODS scan parameters to maximize AQS."


def _register_autoresearch_tools() -> None:
    """Register autoresearch tools in the agent tool registry."""
    from core.agent.tools import get_tool_registry, _AGENT_TOOL_ALLOWLIST
    from .tools import ALL_TOOLS

    registry = get_tool_registry()
    for tool in ALL_TOOLS:
        registry.register(tool)

    # Add allowlist for autoresearch agent type
    _AGENT_TOOL_ALLOWLIST["autoresearch"] = frozenset(t.name for t in ALL_TOOLS)


def create_llm_candidate_generator(
    config: ExperimentConfig,
) -> Callable[[Dict[str, float], List[ParameterBounds], Any], Dict[str, float]]:
    """Create a candidate generator that uses the LLM agent loop.

    Returns:
        A callable (current_best, bounds, history) -> Dict[str, float]
    """
    from core.agent.config import AgentConfig
    from core.agent.loop import AgentLoop
    from core.agent.state import create_agent_task
    from core.agent.tools.base import ToolContext

    _register_autoresearch_tools()
    program = _load_program()

    agent_config = AgentConfig()
    if config.llm_provider:
        agent_config.provider = config.llm_provider
    if config.llm_model:
        agent_config.model = config.llm_model

    def generate(
        current_best: Dict[str, float],
        bounds: List[ParameterBounds],
        history: Any,
    ) -> Dict[str, float]:
        task_id = create_agent_task("autoresearch")
        context = ToolContext()

        loop = AgentLoop(
            config=agent_config,
            agent_type="autoresearch",
            task_id=task_id,
            tool_context=context,
        )

        # Build the user message
        recent = []
        if history is not None:
            try:
                recent = history.get_recent(n=5)
            except Exception:
                pass

        history_text = ""
        if recent:
            history_text = "\n\nRecent experiments:\n"
            for exp in recent:
                history_text += (
                    f"  #{exp.get('experiment_num')}: AQS={exp.get('aqs', 0):.4f} "
                    f"accepted={exp.get('accepted')} reason={exp.get('reason', '')}\n"
                )

        user_msg = (
            f"{program}\n\n"
            f"Current best parameters: {current_best}\n"
            f"{history_text}\n"
            f"Use the tools to inspect current state, then call propose_params "
            f"with your suggested parameter changes. Focus on 1-3 parameters per iteration. "
            f"Respond with DONE when you've proposed your parameters."
        )

        result = loop.run(user_msg)

        # Extract proposed params from the last propose_params tool result
        proposed = dict(current_best)
        for obs in reversed(result.observations):
            if obs.tool_name == "propose_params" and obs.type == "tool_result":
                content = obs.content
                if isinstance(content, dict) and content.get("success"):
                    data = content.get("data_preview", "")
                    # The actual data comes from the tool result
                    break

        # Fallback: look for validated_params in observations
        for obs in reversed(result.observations):
            if obs.tool_name == "propose_params" and obs.type == "tool_result":
                if isinstance(obs.content, dict):
                    data = obs.content.get("data", {})
                    if isinstance(data, dict) and "validated_params" in data:
                        proposed = data["validated_params"]
                        break

        logger.info("llm_candidate_generated", changed_count=sum(
            1 for k in proposed if abs(proposed[k] - current_best.get(k, 0)) > 1e-6
        ))
        return proposed

    return generate
