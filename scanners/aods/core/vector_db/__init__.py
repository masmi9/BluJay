"""
AODS Vector Database Package
============================

This package provides semantic similarity and vector search capabilities for
vulnerability findings. It is an optional component that gracefully degrades
when ChromaDB or sentence-transformers are unavailable.

Key Components:
- FindingEmbedder: Pure embedding functions with secret redaction
- PollutionFilter: Filters out example/demo/test findings
- SecretFingerprinter: HMAC fingerprinting for secret deduplication
- ChromaDBBackend: ChromaDB adapter with ownership metadata
- SemanticFindingIndex: High-level index with RBAC enforcement

Environment Variables:
- AODS_VECTOR_DB_ENABLED: Enable vector index (default: 0)
- AODS_VECTOR_DB_PATH: ChromaDB storage path (default: data/vector_index/)
- AODS_EMBEDDING_MODEL: Sentence-transformer model (default: all-MiniLM-L6-v2)
- AODS_DISABLE_EMBEDDINGS: Disable embeddings entirely (default: 0)
- AODS_VECTOR_CACHE_SIZE: Embedding cache entries (default: 10000)
- AODS_VECTOR_SNIPPET_MAX: Max code snippet chars for embedding (default: 500)

IMPORTANT: ChromaDB uses SQLite internally and is NOT safe for multi-worker
deployments. Use single-process uvicorn only:
    uvicorn core.api.server:app --workers 1

For multi-worker deployments, a separate vector store backend (e.g., Qdrant)
should be configured via AODS_VECTOR_BACKEND environment variable.

Usage:
    from core.vector_db import (
        get_semantic_finding_index,
        should_index_finding,
        compute_embedding,
    )

    # Check if finding should be indexed (pollution filter)
    if should_index_finding(finding):
        # Get the singleton index
        index = get_semantic_finding_index()
        if index:
            index.index_finding(finding, scan_context)
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional  # noqa: F401

# Lazy imports to avoid loading heavy dependencies when disabled
_embedder_module = None
_pollution_filter_module = None
_fingerprint_module = None
_index_module = None

# Singleton instance
_semantic_finding_index: Optional[Any] = None


def _is_vector_db_enabled() -> bool:
    """Check if vector DB is enabled via environment variable."""
    return os.environ.get("AODS_VECTOR_DB_ENABLED", "0") == "1"


def _is_embeddings_disabled() -> bool:
    """Check if embeddings are disabled entirely."""
    return os.environ.get("AODS_DISABLE_EMBEDDINGS", "0") == "1"


# ---------------------------------------------------------------------------
# Pollution Filter Exports (always available)
# ---------------------------------------------------------------------------


def should_index_finding(finding: Dict[str, Any]) -> bool:
    """
    Check if a finding should be indexed in the vector database.

    Excludes:
    - Example/demo/test plugins
    - Findings with placeholder/demo content markers
    - Findings without stable identifiers

    Args:
        finding: The finding dict to check

    Returns:
        True if the finding should be indexed, False otherwise
    """
    global _pollution_filter_module
    if _pollution_filter_module is None:
        from core.vector_db import pollution_filter as _pf

        _pollution_filter_module = _pf
    return _pollution_filter_module.should_index_finding(finding)


def get_excluded_plugin_patterns() -> List[str]:
    """Get the list of excluded plugin patterns."""
    global _pollution_filter_module
    if _pollution_filter_module is None:
        from core.vector_db import pollution_filter as _pf

        _pollution_filter_module = _pf
    return _pollution_filter_module.EXCLUDED_PLUGIN_PATTERNS.copy()


def get_excluded_content_markers() -> List[str]:
    """Get the list of excluded content markers."""
    global _pollution_filter_module
    if _pollution_filter_module is None:
        from core.vector_db import pollution_filter as _pf

        _pollution_filter_module = _pf
    return _pollution_filter_module.EXCLUDED_CONTENT_MARKERS.copy()


# ---------------------------------------------------------------------------
# Embedder Exports (available when embeddings enabled)
# ---------------------------------------------------------------------------


def compute_embedding(text: str) -> Optional[List[float]]:
    """
    Compute embedding vector for text.

    Returns None if embeddings are disabled or unavailable.

    Args:
        text: Text to embed

    Returns:
        Embedding vector as list of floats, or None
    """
    if _is_embeddings_disabled():
        return None

    global _embedder_module
    if _embedder_module is None:
        try:
            from core.vector_db import embedder as _emb

            _embedder_module = _emb
        except ImportError:
            return None

    try:
        return _embedder_module.compute_embedding(text)
    except Exception:
        return None


def compute_cosine_similarity(emb1: List[float], emb2: List[float]) -> float:
    """
    Compute cosine similarity between two embeddings.

    Args:
        emb1: First embedding vector
        emb2: Second embedding vector

    Returns:
        Cosine similarity score (0.0 to 1.0)
    """
    global _embedder_module
    if _embedder_module is None:
        try:
            from core.vector_db import embedder as _emb

            _embedder_module = _emb
        except ImportError:
            # Fallback implementation
            import math

            dot_product = sum(a * b for a, b in zip(emb1, emb2))
            norm1 = math.sqrt(sum(a * a for a in emb1))
            norm2 = math.sqrt(sum(b * b for b in emb2))
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return dot_product / (norm1 * norm2)

    return _embedder_module.compute_cosine_similarity(emb1, emb2)


def finding_to_embedding_text(finding: Dict[str, Any]) -> str:
    """
    Convert finding to text for embedding. Secrets are REDACTED.

    Args:
        finding: Finding dict

    Returns:
        Text suitable for embedding (secrets redacted)
    """
    global _embedder_module
    if _embedder_module is None:
        try:
            from core.vector_db import embedder as _emb

            _embedder_module = _emb
        except ImportError:
            # Fallback: simple concatenation
            parts = []
            for field in ["title", "vulnerability_type", "description"]:
                if finding.get(field):
                    parts.append(str(finding[field]))
            return " ".join(parts)

    return _embedder_module.finding_to_embedding_text(finding)


def redact_secrets(text: str) -> str:
    """
    Replace secret values with placeholders.

    Args:
        text: Text potentially containing secrets

    Returns:
        Text with secrets replaced by placeholders
    """
    global _embedder_module
    if _embedder_module is None:
        try:
            from core.vector_db import embedder as _emb

            _embedder_module = _emb
        except ImportError:
            # No redaction available
            return text

    return _embedder_module.redact_secrets(text)


# ---------------------------------------------------------------------------
# Secret Fingerprinting Exports
# ---------------------------------------------------------------------------


def compute_secret_fingerprint(secret_value: str, tenant_id: str = "default") -> str:
    """
    Compute HMAC fingerprint for 'seen before' detection without revealing secret.

    Args:
        secret_value: The secret value to fingerprint
        tenant_id: Tenant ID for per-tenant key isolation

    Returns:
        HMAC fingerprint (truncated to 16 chars)
    """
    global _fingerprint_module
    if _fingerprint_module is None:
        from core.vector_db import secret_fingerprint as _fp

        _fingerprint_module = _fp

    return _fingerprint_module.compute_secret_fingerprint(secret_value, tenant_id)


# ---------------------------------------------------------------------------
# Semantic Finding Index Exports (full index functionality)
# ---------------------------------------------------------------------------


def get_semantic_finding_index() -> Optional[Any]:
    """
    Get the singleton SemanticFindingIndex instance.

    Returns None if vector DB is disabled or unavailable.

    Returns:
        SemanticFindingIndex instance, or None
    """
    if not _is_vector_db_enabled():
        return None

    global _semantic_finding_index, _index_module

    if _semantic_finding_index is not None:
        return _semantic_finding_index

    if _index_module is None:
        try:
            from core.vector_db import semantic_finding_index as _idx

            _index_module = _idx
        except ImportError:
            return None

    try:
        _semantic_finding_index = _index_module.get_semantic_finding_index()
        return _semantic_finding_index
    except Exception:
        return None


def is_vector_db_available() -> bool:
    """
    Check if vector DB is enabled and properly initialized.

    Returns:
        True if vector DB is available for use
    """
    if not _is_vector_db_enabled():
        return False

    index = get_semantic_finding_index()
    return index is not None


def get_vector_db_status() -> Dict[str, Any]:
    """
    Get status information about the vector DB.

    Returns:
        Dict with enabled, available, model, collection_count, etc.
    """
    enabled = _is_vector_db_enabled()
    embeddings_disabled = _is_embeddings_disabled()

    status = {
        "enabled": enabled,
        "embeddings_disabled": embeddings_disabled,
        "available": False,
        "model": os.environ.get("AODS_EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
        "storage_path": os.environ.get("AODS_VECTOR_DB_PATH", "data/vector_index/"),
        "collection_count": 0,
        "error": None,
    }

    if not enabled:
        status["error"] = "Vector DB disabled (set AODS_VECTOR_DB_ENABLED=1)"
        return status

    if embeddings_disabled:
        status["error"] = "Embeddings disabled (AODS_DISABLE_EMBEDDINGS=1)"
        return status

    try:
        index = get_semantic_finding_index()
        if index is None:
            status["error"] = "Failed to initialize index (check dependencies)"
        else:
            status["available"] = index.is_available()
            if status["available"]:
                status["collection_count"] = index.get_collection_count()
            else:
                status["error"] = "Index initialized but embedder or backend unavailable"
    except Exception as e:
        status["error"] = str(e)

    return status


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    # Pollution filter
    "should_index_finding",
    "get_excluded_plugin_patterns",
    "get_excluded_content_markers",
    # Embedder
    "compute_embedding",
    "compute_cosine_similarity",
    "finding_to_embedding_text",
    "redact_secrets",
    # Secret fingerprinting
    "compute_secret_fingerprint",
    # Index
    "get_semantic_finding_index",
    "is_vector_db_available",
    "get_vector_db_status",
]
