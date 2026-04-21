"""
core.agent.loop - LLM tool-use conversation loop.

Implements the core agent loop that:
1. Sends messages to an LLM (via a pluggable provider) with available tools
2. Processes tool_use responses by executing registered tools
3. Feeds tool results back to the LLM
4. Repeats until the LLM stops using tools or budget is exhausted

The loop is provider-agnostic: callers pass an ``LLMProvider`` instance
(Anthropic, OpenAI, Ollama).  When no provider is given the constructor
falls back to auto-detecting from ``AgentConfig.provider``.
"""

from __future__ import annotations

import json
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .config import AgentConfig
from .state import append_observation, update_agent_task, get_task_elapsed
from .tools import ToolContext, ToolResult, get_tool_registry, is_tool_allowed


@dataclass
class TokenUsage:
    """Tracks cumulative token usage across iterations."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class AgentObservation:
    """A single observation in the agent's reasoning chain."""

    type: str  # "thinking", "tool_call", "tool_result", "response"
    content: Any = None
    tool_name: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_name:
            d["tool_name"] = self.tool_name
        if self.timestamp:
            d["timestamp"] = self.timestamp
        return d


@dataclass
class AgentResult:
    """Final result from an agent loop execution."""

    success: bool = True
    response: str = ""
    observations: List[AgentObservation] = field(default_factory=list)
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    iterations: int = 0
    stop_reason: str = ""  # "end_turn", "budget_exceeded", "error", "cancelled"
    error: Optional[str] = None
    tool_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    cost_usd: float = 0.0


class TranscriptLogger:
    """Logs the full agent conversation for debugging/audit."""

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.entries: List[Dict[str, Any]] = []

    def log(self, role: str, content: Any) -> None:
        self.entries.append({
            "role": role,
            "content": content,
            "timestamp": time.time(),
        })

    def get_transcript(self) -> List[Dict[str, Any]]:
        return list(self.entries)


class AgentLoop:
    """Core agent loop that orchestrates LLM tool-use conversations.

    Args:
        config: Agent configuration.
        agent_type: Type of agent (analyze, narrate, verify, triage).
        task_id: ID of the agent task being executed.
        tool_context: Context for tool execution.
        provider: LLM provider instance. If None, auto-detected from config.
    """

    def __init__(
        self,
        config: AgentConfig,
        agent_type: str,
        task_id: str,
        tool_context: ToolContext,
        provider: Optional[Any] = None,
    ) -> None:
        if provider is not None:
            self.provider = provider
        else:
            # Auto-detect provider from config
            from .providers import get_provider

            self.provider = get_provider(
                provider_name=config.provider,
                api_key_env=config.api_key_env or None,
                base_url=config.base_url or None,
            )

        self.config = config
        self.agent_type = agent_type
        self.task_id = task_id
        self.tool_context = tool_context
        self.transcript = TranscriptLogger(task_id)
        self._cancelled = False
        self._tool_metrics: Dict[str, Dict[str, Any]] = {}
        self._model = config.get_agent_model(agent_type)
        self._provider = config.provider
        self._temperature = config.get_agent_temperature(agent_type)

    def cancel(self) -> None:
        """Signal the loop to stop at the next iteration."""
        self._cancelled = True

    def run(
        self,
        user_message: str,
        parse_check: Optional[Any] = None,
    ) -> AgentResult:
        """Execute the agent loop synchronously.

        Args:
            user_message: The initial user message to send to the LLM.
            parse_check: Optional callable ``(str) -> bool`` that checks if
                the final response contains valid structured output.  When
                the LLM stops tool use but ``parse_check`` returns ``False``,
                the loop appends a nudge message and continues for one more
                iteration to give the LLM a chance to fix its output.

        Returns:
            AgentResult with the final response and observations.
        """
        result = AgentResult()
        usage = TokenUsage()
        model = self.config.get_agent_model(self.agent_type)
        max_iterations = self.config.get_agent_max_iterations(self.agent_type)
        system_prompt = self.config.get_agent_system_prompt(self.agent_type) or ""
        max_output_tokens = self.config.get_agent_max_output_tokens(self.agent_type)
        registry = get_tool_registry()
        tools = registry.get_tools_for_agent(self.agent_type)

        messages: List[Dict[str, Any]] = [{"role": "user", "content": user_message}]

        self.transcript.log("system", system_prompt)
        self.transcript.log("user", user_message)

        update_agent_task(self.task_id, status="running")
        _parse_retry_used = False

        for iteration in range(max_iterations):
            if self._cancelled:
                result.stop_reason = "cancelled"
                break

            # Budget check
            budget_issue = self._check_budget(usage, iteration, max_iterations)
            if budget_issue:
                result.stop_reason = "budget_exceeded"
                result.error = budget_issue
                append_observation(self.task_id, {
                    "type": "budget_exceeded",
                    "content": budget_issue,
                })
                break

            # Trim messages if context is getting too large
            self._trim_messages(messages)

            response = self._call_provider_with_retry(
                model=model,
                system=system_prompt,
                messages=messages,
                tools=tools,
                max_output_tokens=max_output_tokens,
                temperature=self._temperature,
            )
            if response is None:
                result.success = False
                result.stop_reason = "error"
                result.error = f"API error after retries (task {self.task_id})"
                break

            # Track token usage
            usage.input_tokens += response.input_tokens
            usage.output_tokens += response.output_tokens

            # Post-call budget check - stop before executing tools if budget exceeded
            post_budget = self._check_budget(usage, iteration, max_iterations)
            if post_budget:
                result.stop_reason = "budget_exceeded"
                result.error = post_budget
                result.response = "\n".join(response.text_parts)
                break

            self.transcript.log("assistant", self.provider.serialize_content_blocks(response.raw_content))

            # Process response
            for text in response.text_parts:
                obs = AgentObservation(type="thinking", content=text)
                result.observations.append(obs)
                append_observation(self.task_id, obs.to_dict())

            for tc in response.tool_calls:
                obs = AgentObservation(
                    type="tool_call",
                    tool_name=tc.name,
                    content=tc.input,
                )
                result.observations.append(obs)
                append_observation(self.task_id, obs.to_dict())

            # If no tool_use, the agent is done - unless parse_check fails
            if not response.tool_calls:
                final_text = "\n".join(response.text_parts)

                # Parse retry: if the output doesn't parse, nudge once
                if parse_check and not _parse_retry_used and not parse_check(final_text):
                    _parse_retry_used = True
                    logger.info("agent_parse_retry", task_id=self.task_id, iteration=iteration)
                    # Append assistant response + nudge for next iteration
                    messages.append({"role": "assistant", "content": final_text})
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your response could not be parsed. Please produce your "
                            "structured output again, wrapped in the appropriate XML "
                            "tags as specified in the system prompt (e.g., "
                            "<triage_json>, <narrative_json>). Alternatively, wrap "
                            "your JSON in a ```json code block."
                        ),
                    })
                    result.iterations = iteration + 1
                    continue

                if parse_check and _parse_retry_used and not parse_check(final_text):
                    logger.warning(
                        "agent_parse_retry_exhausted",
                        task_id=self.task_id,
                        iteration=iteration,
                    )
                result.response = final_text
                result.stop_reason = "end_turn"
                break

            # Execute tools and build tool_result message
            tool_results_content = []
            for tc in response.tool_calls:
                tool_result = self._execute_tool(tc.name, tc.input)
                content_str = json.dumps(
                    tool_result.data if tool_result.success else {"error": tool_result.error},
                    default=str,
                )
                tool_id = tc.id or str(uuid.uuid4())
                tool_results_content.append(
                    self.provider.format_tool_result(tool_id, content_str)
                )
                obs = AgentObservation(
                    type="tool_result",
                    tool_name=tc.name,
                    content={
                        "success": tool_result.success,
                        "data_preview": _preview(tool_result.data) if tool_result.success else None,
                        "error": tool_result.error,
                    },
                )
                result.observations.append(obs)
                append_observation(self.task_id, obs.to_dict())

            # Append assistant + tool_result messages for next iteration
            assistant_content = self.provider.format_assistant_content(response.raw_content)
            if isinstance(assistant_content, dict) and "role" in assistant_content:
                messages.append(assistant_content)
            else:
                messages.append({"role": "assistant", "content": assistant_content})
            for tr in tool_results_content:
                if isinstance(tr, dict) and tr.get("role") == "tool":
                    messages.append(tr)
                else:
                    messages.append({"role": "user", "content": [tr] if not isinstance(tr, list) else tr})
            self.transcript.log("tool_results", tool_results_content)

            result.iterations = iteration + 1
        else:
            # Loop exhausted max_iterations without breaking
            result.stop_reason = "max_iterations"
            result.error = f"Max iterations ({max_iterations}) exceeded"

        result.token_usage = usage
        result.tool_metrics = dict(self._tool_metrics)
        try:
            from .pricing import calculate_cost
            result.cost_usd = calculate_cost(
                usage.input_tokens, usage.output_tokens,
                self._model, self._provider,
            )
        except Exception:
            pass  # pricing is best-effort
        update_agent_task(
            self.task_id,
            iterations=result.iterations,
            token_usage={"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens},
        )
        return result

    def _execute_tool(self, tool_name: str, tool_input: dict) -> ToolResult:
        """Execute a single tool call with allowlist enforcement and metrics."""
        # Normalize input - providers may produce None (e.g. json.loads("null"))
        if not isinstance(tool_input, dict):
            tool_input = {}
        if not is_tool_allowed(self.agent_type, tool_name):
            logger.warning(
                "agent_tool_blocked",
                task_id=self.task_id,
                agent_type=self.agent_type,
                tool_name=tool_name,
            )
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' is not allowed for agent type '{self.agent_type}'",
            )
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        if not tool:
            available = registry.list_tools()
            return ToolResult(
                success=False,
                error=f"Unknown tool: {tool_name}. Available tools: {', '.join(available)}",
            )
        result = tool.safe_execute(tool_input, self.tool_context)

        # Summarize large results to reduce context usage
        if result.success and result.data and isinstance(result.data, dict):
            try:
                from .result_summarizer import should_summarize, summarize_tool_result
                if should_summarize(tool_name, result.data):
                    result.data = summarize_tool_result(tool_name, result.data)
            except Exception:
                pass

        # Track tool metrics (local + global singleton)
        if tool_name not in self._tool_metrics:
            self._tool_metrics[tool_name] = {
                "call_count": 0,
                "success_count": 0,
                "error_count": 0,
                "total_time_ms": 0.0,
                "truncated_count": 0,
            }
        metrics = self._tool_metrics[tool_name]
        metrics["call_count"] += 1
        if result.success:
            metrics["success_count"] += 1
        else:
            metrics["error_count"] += 1

        try:
            from .tool_metrics import record_tool_invocation
            result_size = len(str(result.data)) if result.data else 0
            record_tool_invocation(
                tool_name=tool_name, success=result.success,
                result_size=result_size, error=result.error if not result.success else None,
            )
        except Exception:
            pass
        metrics["total_time_ms"] += result.execution_time_ms
        # Detect truncation in response data
        if isinstance(result.data, dict) and result.data.get("_truncated"):
            metrics["truncated_count"] += 1

        return result

    def _call_provider_with_retry(
        self,
        model: str,
        system: str,
        messages: list,
        tools: list,
        max_retries: int = 3,
        max_output_tokens: int = 4096,
        temperature: Optional[float] = None,
    ):
        """Call the LLM provider with exponential backoff on transient errors.

        Retries on: 429 (rate limit), 500/502/503 (server errors),
        connection/timeout errors. Fails immediately on auth errors (401/403)
        and content policy errors (400).

        Returns:
            ChatResponse on success, None after all retries exhausted.
        """
        for attempt in range(max_retries + 1):
            try:
                return self.provider.create_message(
                    model=model,
                    system=system,
                    messages=messages,
                    tools=tools,
                    max_tokens=max_output_tokens,
                    temperature=temperature,
                )
            except Exception as e:
                error_str = str(e).lower()

                # Non-retryable errors - fail immediately
                non_retryable = (
                    "401", "403", "authentication", "permission",
                    "400", "content_policy", "content_filter", "invalid_request",
                )
                if any(code in error_str for code in non_retryable):
                    logger.error("agent_api_auth_error", task_id=self.task_id, error=str(e))
                    return None

                if attempt < max_retries:
                    # Exponential backoff with jitter, capped at 5s
                    delay = min(5.0, (2 ** attempt)) + random.uniform(0, 0.5)
                    logger.warning(
                        "agent_api_retry",
                        task_id=self.task_id,
                        attempt=attempt + 1,
                        max_retries=max_retries,
                        delay=round(delay, 2),
                        error=str(e),
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        "agent_api_retries_exhausted",
                        task_id=self.task_id,
                        attempts=max_retries + 1,
                        error=str(e),
                    )
        return None

    # Approximate max context size in characters (char/4 ≈ token).
    # Default 150K chars ≈ ~37K tokens, conservative for most models.
    _MAX_CONTEXT_CHARS = 150_000

    def _trim_messages(self, messages: List[Dict[str, Any]]) -> None:
        """Trim older tool_result messages if context is approaching limits.

        Preserves the first user message (initial task) and the last 4
        messages (current conversation state). Replaces middle tool_result
        content with a truncation marker to free context space.
        """
        total_chars = sum(len(json.dumps(m, default=str)) for m in messages)
        if total_chars <= self._MAX_CONTEXT_CHARS:
            return

        # Keep first message (initial user prompt) and last 4 messages
        protect_head = 1
        protect_tail = 4
        if len(messages) <= protect_head + protect_tail:
            return  # Not enough messages to trim

        trimmed_count = 0
        for i in range(protect_head, len(messages) - protect_tail):
            msg = messages[i]
            role = msg.get("role", "")
            content = msg.get("content", "")

            # Only trim user/tool messages with large content - never touch
            # assistant messages (Anthropic requires typed content blocks).
            if role == "assistant":
                continue

            content_str = json.dumps(content, default=str) if not isinstance(content, str) else content
            if len(content_str) > 500:
                msg["content"] = "[trimmed - earlier tool result removed to save context]"
                trimmed_count += 1

        if trimmed_count:
            logger.debug(
                "agent_context_trimmed",
                task_id=self.task_id,
                trimmed=trimmed_count,
                original_chars=total_chars,
            )

    def _check_budget(self, usage: TokenUsage, iteration: int, max_iterations: int) -> Optional[str]:
        """Check if any budget limit has been exceeded.

        Returns:
            Error message if budget exceeded, None otherwise.
        """
        budget = self.config.budget

        if iteration >= max_iterations:
            return f"Max iterations ({max_iterations}) reached"

        if usage.total >= budget.max_tokens:
            return f"Token budget exceeded ({usage.total} >= {budget.max_tokens})"

        elapsed = get_task_elapsed(self.task_id)
        if elapsed is not None and elapsed >= budget.max_wall_time_seconds:
            return f"Wall time exceeded ({elapsed:.0f}s > {budget.max_wall_time_seconds}s)"

        # Cost limit enforcement
        if budget.cost_limit_usd > 0:
            from .pricing import calculate_cost
            current_cost = calculate_cost(
                usage.input_tokens, usage.output_tokens,
                self._model, self._provider,
            )
            if current_cost >= budget.cost_limit_usd:
                return (
                    f"Cost limit exceeded (${current_cost:.4f} >= "
                    f"${budget.cost_limit_usd:.2f})"
                )

        return None


def _preview(data: Any, max_len: int = 200) -> str:
    """Create a short preview string of data for observation logs."""
    s = json.dumps(data, default=str) if not isinstance(data, str) else data
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s
