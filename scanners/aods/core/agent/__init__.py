"""
core.agent - AODS Agent Intelligence System (Track 90).

Optional AI agent subsystem for autonomous scan analysis, narration,
verification, and triage. Disabled by default (AODS_AGENT_ENABLED=0).

Public API:
    AgentConfig, load_agent_config - Configuration
    ToolRegistry, get_tool_registry - Tool management
    create_agent_task, get_agent_task, list_agent_tasks - State management
"""

from __future__ import annotations

from .config import AgentConfig, load_agent_config
from .narration import Narrative, run_narration
from .orchestration import OrchestrationResult, run_orchestration
from .verification import VerificationResult, run_verification
from .state import (
    create_agent_task,
    get_agent_task,
    list_agent_tasks,
    update_agent_task,
    append_observation,
    cancel_agent_task,
)
from .tools import ToolRegistry, get_tool_registry

__all__ = [
    "AgentConfig",
    "load_agent_config",
    "Narrative",
    "run_narration",
    "OrchestrationResult",
    "run_orchestration",
    "VerificationResult",
    "run_verification",
    "ToolRegistry",
    "get_tool_registry",
    "create_agent_task",
    "get_agent_task",
    "list_agent_tasks",
    "update_agent_task",
    "append_observation",
    "cancel_agent_task",
]
