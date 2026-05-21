"""
LLM factory — dual backend strategy:
  - Routine nodes (recon, report)   → Ollama local (free, no cloud deps)
  - Exploit reasoning / gate summ.  → Claude via Anthropic API (billed)
  - Graceful degradation: if ANTHROPIC_API_KEY absent, all nodes use Ollama
"""
import os

ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")
OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")


def get_exploit_llm():
    """Claude for exploit reasoning and gate summarisation."""
    if ANTHROPIC_KEY:
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model="claude-sonnet-4-6",
            api_key=ANTHROPIC_KEY,
            max_tokens=8096,
        )
    return get_routine_llm()


def get_routine_llm():
    """Ollama for recon and report nodes."""
    from langchain_community.chat_models import ChatOllama
    return ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE, temperature=0)
