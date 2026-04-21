"""
core.agent.providers - LLM provider abstraction layer.

Factory function ``get_provider()`` instantiates the correct LLM backend
based on a provider name string.  The default is ``"anthropic"`` for
backward compatibility.

Supported providers:
- ``"anthropic"`` - Anthropic Claude API (requires ``anthropic`` package)
- ``"openai"``    - OpenAI API (requires ``openai`` package)
- ``"ollama"``    - Local Ollama server via OpenAI-compatible API
"""

from __future__ import annotations

import os
from typing import Optional

from .base import ChatResponse, LLMProvider, ToolCall

__all__ = [
    "ChatResponse",
    "LLMProvider",
    "ToolCall",
    "get_provider",
    "has_api_key",
]

# Default env var names per provider
_DEFAULT_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "ollama": "",  # Ollama doesn't need an API key
}


def get_provider(
    provider_name: str = "anthropic",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key_env: Optional[str] = None,
) -> LLMProvider:
    """Instantiate an LLM provider by name.

    Args:
        provider_name: One of "anthropic", "openai", "ollama".
        api_key: Explicit API key. If None, resolved from env var.
        base_url: Custom base URL (used for Ollama or proxies).
        api_key_env: Custom env var name for the API key.

    Returns:
        An LLMProvider instance.

    Raises:
        ValueError: If provider_name is unknown.
        ImportError: If the required SDK is not installed.
    """
    name = provider_name.lower().strip()

    # Resolve API key from explicit value, custom env var, or default env var
    resolved_key = api_key
    if not resolved_key and api_key_env:
        resolved_key = os.environ.get(api_key_env, "")
    if not resolved_key:
        default_env = _DEFAULT_KEY_ENVS.get(name, "")
        if default_env:
            resolved_key = os.environ.get(default_env, "")

    if name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=resolved_key or None)

    if name in ("openai", "ollama"):
        from .openai_provider import OpenAIProvider

        if name == "ollama":
            base_url = base_url or "http://localhost:11434/v1"
            resolved_key = resolved_key or "ollama"
        return OpenAIProvider(api_key=resolved_key or None, base_url=base_url)

    raise ValueError(
        f"Unknown LLM provider: {provider_name!r}. "
        f"Supported: anthropic, openai, ollama"
    )


def has_api_key(
    provider_name: str = "anthropic",
    api_key_env: Optional[str] = None,
) -> bool:
    """Check whether an API key is available for the given provider.

    Ollama never needs a key, so always returns True for "ollama".
    """
    name = provider_name.lower().strip()
    if name == "ollama":
        return True

    if api_key_env:
        if os.environ.get(api_key_env):
            return True

    default_env = _DEFAULT_KEY_ENVS.get(name, "")
    if default_env and os.environ.get(default_env):
        return True

    return False
