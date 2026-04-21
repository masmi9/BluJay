"""
core.agent.providers.base - Abstract LLM provider interface.

Defines the data types and abstract base class that all LLM providers
implement, allowing AgentLoop to work with any backend (Anthropic,
OpenAI, Ollama) through a uniform interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolCall:
    """A tool invocation requested by the LLM."""

    id: str
    name: str
    input: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChatResponse:
    """Unified response from any LLM provider."""

    text_parts: List[str] = field(default_factory=list)
    tool_calls: List[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    raw_content: Any = None  # provider-specific, for message accumulation
    cache_creation_tokens: int = 0  # tokens used to create cache (Anthropic)
    cache_read_tokens: int = 0  # tokens read from cache (Anthropic)


class LLMProvider(ABC):
    """Abstract LLM provider that AgentLoop uses for all model interaction.

    Each concrete provider wraps a specific SDK (Anthropic, OpenAI/Ollama)
    and translates between the provider's native format and the unified
    ChatResponse / ToolCall types.
    """

    @abstractmethod
    def create_message(
        self,
        model: str,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> ChatResponse:
        """Send a message and return the assistant response.

        Args:
            model: Model identifier (e.g. "claude-sonnet-4-6", "gpt-4o").
            system: System prompt text.
            messages: Conversation history in provider-neutral format.
            tools: Tool schemas (Claude format from BaseTool.to_claude_schema()).
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature (0.0-2.0). None = provider default.

        Returns:
            ChatResponse with text parts, tool calls, and token usage.
        """

    @abstractmethod
    def format_tool_schemas(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert Claude-format tool schemas to the provider's native format.

        Args:
            tools: List of {"name", "description", "input_schema"} dicts.

        Returns:
            Provider-native tool schema list.
        """

    @abstractmethod
    def format_tool_result(self, tool_use_id: str, content: str) -> Dict[str, Any]:
        """Format a tool result for the provider's message format.

        Args:
            tool_use_id: ID of the tool call being responded to.
            content: Serialized tool result content.

        Returns:
            Provider-specific tool result message element.
        """

    @abstractmethod
    def format_assistant_content(self, raw_content: Any) -> Any:
        """Format raw_content from ChatResponse for message accumulation.

        Args:
            raw_content: The raw_content field from ChatResponse.

        Returns:
            Value suitable for appending as assistant message content.
        """

    @abstractmethod
    def serialize_content_blocks(self, raw_content: Any) -> List[Dict[str, Any]]:
        """Serialize provider-specific content blocks to JSON-safe dicts.

        Used for transcript logging.

        Args:
            raw_content: The raw_content field from ChatResponse.

        Returns:
            List of serializable dicts.
        """
