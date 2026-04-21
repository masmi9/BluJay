"""
core.agent.providers.openai_provider - OpenAI / Ollama provider.

Wraps the OpenAI Python SDK to implement LLMProvider.  Because Ollama
exposes an OpenAI-compatible ``/v1`` API, this single class serves both
OpenAI and local Ollama backends via the ``base_url`` parameter.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, List, Optional

from .base import ChatResponse, LLMProvider, ToolCall

try:
    from core.logging_config import get_logger
    _logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    _logger = stdlib_logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    """LLM provider backed by the OpenAI SDK (also Ollama-compatible).

    Args:
        api_key: OpenAI API key. Falls back to ``OPENAI_API_KEY`` env var.
            For Ollama, pass ``"ollama"`` (Ollama ignores the key).
        base_url: Custom API base URL. For Ollama: ``http://localhost:11434/v1``.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        try:
            import openai  # noqa: F401

            self._openai = openai
        except ImportError:
            raise ImportError(
                "The 'openai' package is required for the OpenAI/Ollama provider. "
                "Install it with: pip install openai"
            )
        resolved_key = api_key or os.environ.get("OPENAI_API_KEY", "ollama")
        kwargs: Dict[str, Any] = {"api_key": resolved_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = self._openai.OpenAI(**kwargs)

    # ---- LLMProvider interface ----

    def create_message(
        self,
        model: str,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> ChatResponse:
        # Build OpenAI-format messages with system prompt prepended
        oai_messages: List[Dict[str, Any]] = []
        if system:
            oai_messages.append({"role": "system", "content": system})

        for msg in messages:
            converted = self._convert_message(msg)
            if isinstance(converted, list):
                oai_messages.extend(converted)
            else:
                oai_messages.append(converted)

        formatted_tools = self.format_tool_schemas(tools)

        kwargs: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": oai_messages,
        }
        if formatted_tools:
            kwargs["tools"] = formatted_tools
        if temperature is not None:
            kwargs["temperature"] = temperature

        response = self._client.chat.completions.create(**kwargs)

        choice = response.choices[0] if response.choices else None
        if not choice:
            _logger.warning("openai_empty_choices", model=model)
            return ChatResponse(
                text_parts=[],
                tool_calls=[],
                raw_content=[],
                input_tokens=getattr(getattr(response, "usage", None), "prompt_tokens", 0) or 0,
                output_tokens=getattr(getattr(response, "usage", None), "completion_tokens", 0) or 0,
            )

        msg = choice.message
        text_parts: List[str] = []
        tool_calls_out: List[ToolCall] = []

        if msg.content:
            text_parts.append(msg.content)

        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    parsed_args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError) as e:
                    _logger.warning("openai_tool_args_parse_failed", tool=tc.function.name, error=str(e))
                    parsed_args = {}
                # json.loads("null") returns None - normalize to dict
                if not isinstance(parsed_args, dict):
                    parsed_args = {}
                tool_calls_out.append(ToolCall(
                    id=tc.id or str(uuid.uuid4()),
                    name=tc.function.name,
                    input=parsed_args,
                ))

        input_tokens = getattr(response.usage, "prompt_tokens", 0) if response.usage else 0
        output_tokens = getattr(response.usage, "completion_tokens", 0) if response.usage else 0

        return ChatResponse(
            text_parts=text_parts,
            tool_calls=tool_calls_out,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw_content=msg,
        )

    def format_tool_schemas(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert Claude-format tool schemas to OpenAI function-calling format."""
        result = []
        for tool in tools:
            result.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {}),
                },
            })
        return result

    def format_tool_result(self, tool_use_id: str, content: str) -> Dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": tool_use_id,
            "content": content,
        }

    def format_assistant_content(self, raw_content: Any) -> Any:
        """Convert OpenAI message to dict for message accumulation."""
        msg = raw_content
        result: Dict[str, Any] = {"role": "assistant"}

        if msg.content:
            result["content"] = msg.content

        if msg.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]

        return result

    def serialize_content_blocks(self, raw_content: Any) -> List[Dict[str, Any]]:
        result = []
        msg = raw_content
        if msg and getattr(msg, "content", None):
            result.append({"type": "text", "text": msg.content})
        if msg and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                result.append({"type": "tool_use", "name": tc.function.name, "input": args})
        return result

    # ---- helpers ----

    def _convert_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a provider-neutral message to OpenAI format.

        Handles:
        - Plain user/assistant messages → pass through
        - Assistant messages with tool_calls → preserve tool_calls
        - Tool role messages → pass through
        - Anthropic-style tool_result content lists → OpenAI tool messages
        - Assistant messages with raw Anthropic content blocks → OpenAI format
        """
        role = msg.get("role", "user")
        content = msg.get("content")

        # Tool messages - pass through directly
        if role == "tool":
            return msg

        # Assistant message already in OpenAI format (has tool_calls key)
        if role == "assistant" and "tool_calls" in msg:
            result: Dict[str, Any] = {"role": "assistant", "tool_calls": msg["tool_calls"]}
            if content:
                result["content"] = str(content)
            return result

        # Assistant message with raw content from format_assistant_content()
        if role == "assistant":
            if isinstance(content, dict) and "role" in content:
                return content
            if isinstance(content, (list, tuple)):
                # Could be raw content blocks - extract text
                text_parts = []
                tool_calls = []
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            text_parts.append(item.get("text") or "")
                        elif item.get("type") == "tool_use":
                            tool_name = item.get("name", "")
                            if not tool_name:
                                _logger.warning("openai_convert_missing_tool_name", item_keys=list(item.keys()))
                                continue
                            tool_calls.append({
                                "id": item.get("id", str(uuid.uuid4())),
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": json.dumps(item.get("input", {})),
                                },
                            })
                out: Dict[str, Any] = {"role": "assistant"}
                if text_parts:
                    out["content"] = "\n".join(text_parts)
                if tool_calls:
                    out["tool_calls"] = tool_calls
                return out
            return {"role": "assistant", "content": str(content) if content else ""}

        # User message with tool_result list (Anthropic format)
        if role == "user" and isinstance(content, list):
            tool_messages = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_result":
                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": item.get("tool_use_id", ""),
                        "content": item.get("content", ""),
                    })
            if tool_messages:
                return tool_messages[0] if len(tool_messages) == 1 else tool_messages

        return {"role": role, "content": str(content) if content else ""}
