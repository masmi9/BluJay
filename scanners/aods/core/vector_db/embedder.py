"""
AODS Vector DB Finding Embedder
===============================

This module provides pure embedding functions for converting findings to
vector representations. It includes secret redaction to ensure sensitive
values are never stored in the vector database.

Key Features:
- Sentence-transformer based embeddings (all-MiniLM-L6-v2 default)
- LRU cache for embedding reuse
- Secret redaction in embedding text
- Cosine similarity computation
- Graceful fallback when sentence-transformers unavailable

Security:
- Secrets are REDACTED before embedding
- Embedding text contains context (api_key=<SECRET>) not values
- Vector DB is safe to query (no raw secrets exposed)
"""

from __future__ import annotations

import os
import re
import math
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

# Logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default embedding model (small, fast, good quality)
DEFAULT_EMBEDDING_MODEL = os.environ.get("AODS_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# Cache size for embeddings
EMBEDDING_CACHE_SIZE = int(os.environ.get("AODS_VECTOR_CACHE_SIZE", "10000"))

# Maximum text length for embedding (longer text is truncated)
MAX_TEXT_LENGTH = int(os.environ.get("AODS_VECTOR_SNIPPET_MAX", "500"))


# ---------------------------------------------------------------------------
# Secret Redaction Patterns
# ---------------------------------------------------------------------------

# Patterns to match and redact secrets
# Format: (pattern, replacement)
SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "<AWS_KEY>"),
    (
        re.compile(r"aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", re.IGNORECASE),
        "aws_secret_access_key=<AWS_SECRET>",
    ),
    # GitHub tokens
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.IGNORECASE), "<GITHUB_TOKEN>"),
    # Google API keys
    (re.compile(r"AIza[0-9A-Za-z_-]{35}", re.IGNORECASE), "<GOOGLE_API_KEY>"),
    # JWTs
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "<JWT>"),
    # Slack tokens
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]+"), "<SLACK_TOKEN>"),
    # Stripe keys
    (re.compile(r"sk_live_[0-9A-Za-z]{24,}"), "<STRIPE_KEY>"),
    (re.compile(r"pk_live_[0-9A-Za-z]{24,}"), "<STRIPE_PK>"),
    # Generic patterns (must come last - more general)
    (re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-/+=]{8,}['\"]?", re.IGNORECASE), r"\1=<API_KEY>"),
    (re.compile(r"(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?", re.IGNORECASE), r"\1=<PASSWORD>"),
    (re.compile(r"(secret|client_secret)\s*[:=]\s*['\"]?[\w\-/+=]{8,}['\"]?", re.IGNORECASE), r"\1=<SECRET>"),
    (
        re.compile(r"(token|access_token|auth_token|bearer)\s*[:=]\s*['\"]?[\w\-/+=._]{16,}['\"]?", re.IGNORECASE),
        r"\1=<TOKEN>",
    ),
    (re.compile(r"bearer\s+[A-Za-z0-9_.-]+", re.IGNORECASE), "bearer <TOKEN>"),
    # Private keys
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "<PRIVATE_KEY>",
    ),
    # Long base64 strings (likely encoded secrets)
    (re.compile(r"[A-Za-z0-9+/]{50,}={0,2}"), "<BASE64>"),
]


# ---------------------------------------------------------------------------
# Sentence Transformer Model Management
# ---------------------------------------------------------------------------

# Lazy-loaded model instance
_embedding_model = None
_model_load_attempted = False


def _get_embedding_model():
    """
    Lazy-load the sentence transformer model.

    Returns:
        SentenceTransformer model instance, or None if unavailable
    """
    global _embedding_model, _model_load_attempted

    if _model_load_attempted:
        return _embedding_model

    _model_load_attempted = True

    try:
        from sentence_transformers import SentenceTransformer

        model_name = DEFAULT_EMBEDDING_MODEL
        logger.info("embedding_model_loading", model=model_name)

        _embedding_model = SentenceTransformer(model_name)

        logger.info(
            "embedding_model_loaded",
            model=model_name,
            embedding_dim=_embedding_model.get_sentence_embedding_dimension(),
        )

    except ImportError:
        logger.warning(
            "sentence_transformers_unavailable",
            message="Install sentence-transformers for embedding support",
        )
    except Exception as e:
        logger.error("embedding_model_load_failed", error=str(e))

    return _embedding_model


def get_embedding_dimension() -> int:
    """
    Get the dimension of embedding vectors.

    Returns:
        Embedding dimension, or 0 if model unavailable
    """
    model = _get_embedding_model()
    if model is None:
        return 0
    return model.get_sentence_embedding_dimension()


def is_embedder_available() -> bool:
    """
    Check if the embedding model is available.

    Returns:
        True if embeddings can be computed
    """
    return _get_embedding_model() is not None


# ---------------------------------------------------------------------------
# Secret Redaction Functions
# ---------------------------------------------------------------------------


def redact_secrets(text: str) -> str:
    """
    Replace secret values with placeholders.

    This preserves the context (e.g., "api_key=") while hiding values,
    allowing semantic search to work on the pattern without exposing secrets.

    Args:
        text: Text potentially containing secrets

    Returns:
        Text with secrets replaced by placeholders

    Examples:
        >>> redact_secrets("api_key = 'sk-1234567890abcdef'")
        "api_key=<API_KEY>"
        >>> redact_secrets("password: hunter2")
        "password=<PASSWORD>"
    """
    if not text:
        return text

    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)

    return result


def _truncate_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Truncate text to maximum length, preferring word boundaries."""
    if len(text) <= max_length:
        return text

    # Try to truncate at word boundary
    truncated = text[:max_length]
    last_space = truncated.rfind(" ")
    if last_space > max_length * 0.8:  # Only use if we don't lose too much
        truncated = truncated[:last_space]

    return truncated + "..."


# ---------------------------------------------------------------------------
# Embedding Functions
# ---------------------------------------------------------------------------


def finding_to_embedding_text(finding: Dict[str, Any]) -> str:
    """
    Convert finding to text for embedding. Secrets are REDACTED.

    The resulting text includes:
    - Title and vulnerability type
    - Description (truncated, redacted)
    - CWE and severity metadata
    - Code snippet (truncated, redacted)
    - Recommendation (truncated, redacted)

    Args:
        finding: Finding dict

    Returns:
        Text suitable for embedding (secrets redacted)
    """
    parts = []

    # Core attributes
    title = finding.get("title") or finding.get("name") or ""
    if title:
        parts.append(redact_secrets(str(title)))

    vuln_type = finding.get("vulnerability_type") or finding.get("type") or ""
    if vuln_type:
        parts.append(redact_secrets(str(vuln_type)))

    # Description (redacted, truncated)
    description = finding.get("description", "")
    if description:
        desc_redacted = redact_secrets(str(description))
        parts.append(_truncate_text(desc_redacted, MAX_TEXT_LENGTH))

    # Safe metadata
    cwe_id = finding.get("cwe_id") or finding.get("cwe")
    if cwe_id:
        parts.append(f"CWE: {cwe_id}")

    severity = finding.get("severity")
    if severity:
        parts.append(f"Severity: {severity}")

    # Recommendation (redacted, truncated)
    recommendation = finding.get("recommendation", "")
    if recommendation:
        rec_redacted = redact_secrets(str(recommendation))
        parts.append(f"Fix: {_truncate_text(rec_redacted, 300)}")

    # Code snippet (redacted, truncated)
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        snippet = evidence.get("code_snippet", "") or evidence.get("snippet", "")
        if snippet:
            snippet_redacted = redact_secrets(str(snippet))
            parts.append(f"Code: {_truncate_text(snippet_redacted, MAX_TEXT_LENGTH)}")

    return " ".join(filter(None, parts))


@lru_cache(maxsize=EMBEDDING_CACHE_SIZE)
def _compute_embedding_cached(text: str) -> Optional[Tuple[float, ...]]:
    """
    Compute embedding with caching (internal).

    Uses a tuple return type for LRU cache hashability.
    """
    model = _get_embedding_model()
    if model is None:
        return None

    try:
        embedding = model.encode(text, convert_to_numpy=True)
        return tuple(float(x) for x in embedding)
    except Exception as e:
        logger.error("embedding_computation_failed", error=str(e), text_length=len(text))
        return None


def compute_embedding(text: str) -> Optional[List[float]]:
    """
    Compute embedding vector for text.

    Args:
        text: Text to embed (should already be redacted)

    Returns:
        Embedding vector as list of floats, or None if unavailable
    """
    if not text or not text.strip():
        return None

    # Truncate very long text
    text = _truncate_text(text, MAX_TEXT_LENGTH * 2)

    result = _compute_embedding_cached(text)
    if result is None:
        return None

    return list(result)


def compute_finding_embedding(finding: Dict[str, Any]) -> Optional[List[float]]:
    """
    Compute embedding for a finding (convenience function).

    Args:
        finding: Finding dict

    Returns:
        Embedding vector, or None if unavailable
    """
    text = finding_to_embedding_text(finding)
    return compute_embedding(text)


def compute_cosine_similarity(emb1: List[float], emb2: List[float]) -> float:
    """
    Compute cosine similarity between two embeddings.

    Args:
        emb1: First embedding vector
        emb2: Second embedding vector

    Returns:
        Cosine similarity score (0.0 to 1.0)

    Raises:
        ValueError: If embeddings have different dimensions
    """
    if len(emb1) != len(emb2):
        raise ValueError(f"Embedding dimension mismatch: {len(emb1)} vs {len(emb2)}")

    if not emb1 or not emb2:
        return 0.0

    # Compute dot product and norms
    dot_product = sum(a * b for a, b in zip(emb1, emb2))
    norm1 = math.sqrt(sum(a * a for a in emb1))
    norm2 = math.sqrt(sum(b * b for b in emb2))

    if norm1 == 0 or norm2 == 0:
        return 0.0

    similarity = dot_product / (norm1 * norm2)

    # Clamp to [0, 1] range (numerical precision can push slightly outside)
    return max(0.0, min(1.0, similarity))


def compute_batch_embeddings(texts: List[str]) -> List[Optional[List[float]]]:
    """
    Compute embeddings for a batch of texts.

    More efficient than computing one at a time when processing many findings.

    Args:
        texts: List of texts to embed

    Returns:
        List of embeddings (None for failed texts)
    """
    model = _get_embedding_model()
    if model is None:
        return [None] * len(texts)

    if not texts:
        return []

    # Truncate and filter
    processed = [_truncate_text(t, MAX_TEXT_LENGTH * 2) if t else "" for t in texts]

    try:
        embeddings = model.encode(processed, convert_to_numpy=True, show_progress_bar=False)
        return [list(float(x) for x in emb) for emb in embeddings]
    except Exception as e:
        logger.error("batch_embedding_failed", error=str(e), batch_size=len(texts))
        # Fall back to individual computation
        return [compute_embedding(t) for t in texts]


def clear_embedding_cache() -> None:
    """Clear the embedding cache."""
    _compute_embedding_cached.cache_clear()
    logger.info("embedding_cache_cleared")


def get_cache_stats() -> Dict[str, int]:
    """Get embedding cache statistics."""
    info = _compute_embedding_cached.cache_info()
    return {
        "hits": info.hits,
        "misses": info.misses,
        "maxsize": info.maxsize,
        "currsize": info.currsize,
    }
