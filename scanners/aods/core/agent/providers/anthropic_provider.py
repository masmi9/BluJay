"""
core.agent.providers.anthropic_provider - Anthropic Claude provider.

Wraps the Anthropic Python SDK to implement LLMProvider. This is the
default provider and mirrors the original AgentLoop behaviour exactly.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .base import ChatResponse, LLMProvider, ToolCall


class AnthropicProvider(LLMProvider):
    """LLM provider backed by the Anthropic SDK.

    Args:
        api_key: Anthropic API key. Falls back to ``ANTHROPIC_API_KEY`` env var.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        try:
            import anthropic  # noqa: F401

            self._anthropic = anthropic
        except ImportError:
            raise ImportError(
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install it with: pip install anthropic"
            )
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if self._api_key:
            self._client = self._anthropic.Anthropic(api_key=self._api_key)
        else:
            self._client = self._anthropic.Anthropic()

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
        # Use cache_control for system prompt - after the first call in a
        # session, the system prompt is served from cache at ~10% input cost.
        system_with_cache = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]

        kwargs: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system_with_cache,
            "tools": tools,
            "messages": messages,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        response = self._client.messages.create(**kwargs)

        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, input=block.input))

        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "output_tokens", 0) if usage else 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) if usage else 0
        cache_read = getattr(usage, "cache_read_input_tokens", 0) if usage else 0

        return ChatResponse(
            text_parts=text_parts,
            tool_calls=tool_calls,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw_content=response.content,
            cache_creation_tokens=cache_creation,
            cache_read_tokens=cache_read,
        )

    def format_tool_schemas(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Claude-native format - passthrough
        return tools

    def format_tool_result(self, tool_use_id: str, content: str) -> Dict[str, Any]:
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content,
        }

    def format_assistant_content(self, raw_content: Any) -> Any:
        # Anthropic SDK returns content block list - pass directly
        return raw_content

    def serialize_content_blocks(self, raw_content: Any) -> List[Dict[str, Any]]:
        result = []
        for block in (raw_content or []):
            if hasattr(block, "text"):
                result.append({"type": "text", "text": block.text})
            elif hasattr(block, "name"):
                result.append({"type": "tool_use", "name": block.name, "input": block.input})
            else:
                result.append({"type": str(getattr(block, "type", "unknown"))})
        return result
