"""
AODS ChromaDB Backend
=====================

This module provides the ChromaDB adapter for the vector database.
ChromaDB is used as an embedded vector store for semantic similarity
search across vulnerability findings.

IMPORTANT: ChromaDB uses SQLite internally and is NOT safe for multi-worker
deployments. Use single-process uvicorn only:
    uvicorn core.api.server:app --workers 1

Features:
- Embedded storage (no external service required)
- Ownership metadata for RBAC enforcement
- Index versioning for model compatibility
- Batch indexing with configurable batch size
- Persistence across restarts

Environment Variables:
- AODS_VECTOR_DB_PATH: Storage path (default: data/vector_index/)
- AODS_EMBEDDING_MODEL: Model identifier for versioning
- AODS_VECTOR_BATCH_SIZE: Batch size for indexing (default: 100)
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path
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

DEFAULT_DB_PATH = os.environ.get("AODS_VECTOR_DB_PATH", "data/vector_index/")
DEFAULT_COLLECTION_NAME = "aods_findings"
DEFAULT_BATCH_SIZE = int(os.environ.get("AODS_VECTOR_BATCH_SIZE", "100"))
DEFAULT_EMBEDDING_MODEL = os.environ.get("AODS_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# Query timeout in seconds
QUERY_TIMEOUT = float(os.environ.get("AODS_VECTOR_QUERY_TIMEOUT", "5.0"))


# ---------------------------------------------------------------------------
# Index Metadata Schema
# ---------------------------------------------------------------------------

INDEX_SCHEMA_VERSION = "1.0"


def _get_index_metadata() -> Dict[str, Any]:
    """Get metadata to store with the index collection.

    Sets hnsw:space to cosine so that distances are in [0, 1] and the
    similarity formula ``1.0 - distance`` produces valid [0, 1] scores.
    ChromaDB defaults to L2 (squared Euclidean) where distances can
    exceed 1.0, which would produce negative similarity values.
    """
    return {
        "hnsw:space": "cosine",
        "embedding_model_id": DEFAULT_EMBEDDING_MODEL,
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "aods_version": os.environ.get("AODS_VERSION", "1.0.0"),
    }


# ---------------------------------------------------------------------------
# ChromaDB Backend Class
# ---------------------------------------------------------------------------


class ChromaDBBackend:
    """
    ChromaDB adapter for AODS vector storage.

    This class manages the ChromaDB client and collection, providing
    methods for indexing and querying findings with ownership filtering.

    Thread Safety:
        ChromaDB is thread-safe for reads but NOT for concurrent writes.
        A ``_write_lock`` serialises all write operations (index, delete,
        clear) to prevent data corruption.

    Usage:
        backend = ChromaDBBackend()
        if backend.is_available():
            backend.index(finding_id, embedding, metadata)
            results = backend.query(query_embedding, filters, n_results=10)
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        collection_name: str = DEFAULT_COLLECTION_NAME,
    ):
        """
        Initialize the ChromaDB backend.

        Args:
            db_path: Path to ChromaDB storage directory
            collection_name: Name of the collection to use
        """
        self._db_path = Path(db_path or DEFAULT_DB_PATH)
        self._collection_name = collection_name
        self._client = None
        self._collection = None
        self._available = False
        self._init_attempted = False
        self._model_mismatch_warning_logged = False
        self._write_lock = threading.Lock()

    def _ensure_initialized(self) -> bool:
        """Lazy initialization of ChromaDB client and collection."""
        if self._init_attempted:
            return self._available

        self._init_attempted = True

        try:
            import chromadb
            from chromadb.config import Settings

            # Create storage directory if needed
            self._db_path.mkdir(parents=True, exist_ok=True)

            # Initialize persistent client
            self._client = chromadb.PersistentClient(
                path=str(self._db_path),
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True,
                ),
            )

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata=_get_index_metadata(),
            )

            # Check for model mismatch
            self._check_model_compatibility()

            self._available = True
            logger.info(
                "chromadb_initialized",
                path=str(self._db_path),
                collection=self._collection_name,
                count=self._collection.count(),
            )

        except ImportError:
            logger.warning(
                "chromadb_unavailable",
                message="Install chromadb for vector search support",
            )
        except Exception as e:
            logger.error("chromadb_init_failed", error=str(e))

        return self._available

    def _check_model_compatibility(self) -> None:
        """Check if stored index uses same embedding model."""
        if self._collection is None:
            return

        stored_model = self._collection.metadata.get("embedding_model_id")
        current_model = DEFAULT_EMBEDDING_MODEL

        if stored_model and stored_model != current_model:
            if not self._model_mismatch_warning_logged:
                logger.warning(
                    "chromadb_model_mismatch",
                    stored_model=stored_model,
                    current_model=current_model,
                    message="Index was created with different model. Rebuild recommended.",
                )
                self._model_mismatch_warning_logged = True

    def is_available(self) -> bool:
        """Check if ChromaDB is available and initialized."""
        return self._ensure_initialized()

    def get_collection_count(self) -> int:
        """Get the number of documents in the collection."""
        if not self._ensure_initialized():
            return 0
        return self._collection.count()

    # -----------------------------------------------------------------------
    # Index Operations
    # -----------------------------------------------------------------------

    def index(
        self,
        finding_id: str,
        embedding: List[float],
        metadata: Dict[str, Any],
    ) -> bool:
        """
        Index a single finding.

        Args:
            finding_id: Unique identifier for the finding
            embedding: Embedding vector
            metadata: Metadata dict (must include ownership fields)

        Returns:
            True if indexing succeeded

        Required metadata fields:
            - scan_id: Scan session ID
            - owner_user_id: User who owns this finding
            - tenant_id: Tenant identifier (default: "default")
            - visibility: "private" | "shared" | "public"
        """
        if not self._ensure_initialized():
            return False

        try:
            # Ensure required metadata
            required = ["scan_id", "owner_user_id"]
            for field in required:
                if field not in metadata:
                    logger.warning(
                        "chromadb_index_missing_metadata",
                        finding_id=finding_id,
                        missing_field=field,
                    )
                    return False

            # Add indexing timestamp
            metadata["indexed_at"] = datetime.now(timezone.utc).isoformat()

            # ChromaDB metadata must be string, int, float, or bool
            sanitized_metadata = self._sanitize_metadata(metadata)

            with self._write_lock:
                self._collection.upsert(
                    ids=[finding_id],
                    embeddings=[embedding],
                    metadatas=[sanitized_metadata],
                )

            return True

        except Exception as e:
            logger.error(
                "chromadb_index_failed",
                finding_id=finding_id,
                error=str(e),
            )
            return False

    def index_batch(
        self,
        items: List[Tuple[str, List[float], Dict[str, Any]]],
    ) -> int:
        """
        Index a batch of findings.

        Args:
            items: List of (finding_id, embedding, metadata) tuples

        Returns:
            Number of successfully indexed items
        """
        if not self._ensure_initialized():
            return 0

        if not items:
            return 0

        indexed = 0

        # Process in batches
        for i in range(0, len(items), DEFAULT_BATCH_SIZE):
            batch = items[i : i + DEFAULT_BATCH_SIZE]

            ids = []
            embeddings = []
            metadatas = []

            for finding_id, embedding, metadata in batch:
                # Validate required metadata
                if not metadata.get("scan_id") or not metadata.get("owner_user_id"):
                    continue

                metadata["indexed_at"] = datetime.now(timezone.utc).isoformat()

                ids.append(finding_id)
                embeddings.append(embedding)
                metadatas.append(self._sanitize_metadata(metadata))

            if ids:
                try:
                    with self._write_lock:
                        self._collection.upsert(
                            ids=ids,
                            embeddings=embeddings,
                            metadatas=metadatas,
                        )
                    indexed += len(ids)
                except Exception as e:
                    logger.error(
                        "chromadb_batch_index_failed",
                        batch_size=len(ids),
                        error=str(e),
                    )

        return indexed

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize metadata for ChromaDB (only allows str, int, float, bool)."""
        sanitized = {}

        for key, value in metadata.items():
            if value is None:
                continue
            elif isinstance(value, (str, int, float, bool)):
                sanitized[key] = value
            elif isinstance(value, list):
                # Convert lists to comma-separated strings
                sanitized[key] = ",".join(str(v) for v in value)
            else:
                sanitized[key] = str(value)

        return sanitized

    # -----------------------------------------------------------------------
    # Query Operations
    # -----------------------------------------------------------------------

    def query(
        self,
        query_embedding: List[float],
        ownership_filter: Optional[Dict[str, Any]] = None,
        n_results: int = 10,
        include_embeddings: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Query for similar findings with ownership filtering.

        Args:
            query_embedding: Query embedding vector
            ownership_filter: Filter dict for ownership (ChromaDB where clause)
            n_results: Maximum number of results
            include_embeddings: Whether to include embeddings in results

        Returns:
            List of result dicts with: id, distance, metadata, (embedding)

        Ownership filter example:
            {"owner_user_id": "alice"}  # Only Alice's findings
            {"$or": [{"owner_user_id": "alice"}, {"visibility": "public"}]}
        """
        if not self._ensure_initialized():
            return []

        try:
            # Build query kwargs
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": n_results,
                "include": ["metadatas", "distances"],
            }

            if include_embeddings:
                query_kwargs["include"].append("embeddings")

            if ownership_filter:
                query_kwargs["where"] = ownership_filter

            results = self._collection.query(**query_kwargs)

            # Transform results
            output = []
            ids = results.get("ids", [[]])[0]
            distances = results.get("distances", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]
            embeddings = results.get("embeddings", [[]])[0] if include_embeddings else [None] * len(ids)

            for i, finding_id in enumerate(ids):
                result = {
                    "id": finding_id,
                    "distance": distances[i] if i < len(distances) else None,
                    "similarity": 1.0 - distances[i] if i < len(distances) else 0.0,
                    "metadata": metadatas[i] if i < len(metadatas) else {},
                }
                if include_embeddings and embeddings[i] is not None:
                    result["embedding"] = embeddings[i]
                output.append(result)

            return output

        except Exception as e:
            logger.error("chromadb_query_failed", error=str(e))
            return []

    def get_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get a single finding by ID."""
        if not self._ensure_initialized():
            return None

        try:
            results = self._collection.get(
                ids=[finding_id],
                include=["metadatas", "embeddings"],
            )

            if not results.get("ids"):
                return None

            return {
                "id": results["ids"][0],
                "metadata": results["metadatas"][0] if results.get("metadatas") else {},
                "embedding": results["embeddings"][0] if results.get("embeddings") else None,
            }

        except Exception as e:
            logger.error("chromadb_get_failed", finding_id=finding_id, error=str(e))
            return None

    def get_by_scan_id(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a scan."""
        if not self._ensure_initialized():
            return []

        try:
            results = self._collection.get(
                where={"scan_id": scan_id},
                include=["metadatas"],
            )

            output = []
            ids = results.get("ids", [])
            metadatas = results.get("metadatas", [])

            for i, finding_id in enumerate(ids):
                output.append(
                    {
                        "id": finding_id,
                        "metadata": metadatas[i] if i < len(metadatas) else {},
                    }
                )

            return output

        except Exception as e:
            logger.error("chromadb_get_by_scan_failed", scan_id=scan_id, error=str(e))
            return []

    # -----------------------------------------------------------------------
    # Delete Operations
    # -----------------------------------------------------------------------

    def delete(self, finding_ids: List[str]) -> int:
        """
        Delete findings by ID.

        Args:
            finding_ids: List of finding IDs to delete

        Returns:
            Number of deleted items
        """
        if not self._ensure_initialized():
            return 0

        if not finding_ids:
            return 0

        try:
            with self._write_lock:
                self._collection.delete(ids=finding_ids)
            return len(finding_ids)
        except Exception as e:
            logger.error("chromadb_delete_failed", count=len(finding_ids), error=str(e))
            return 0

    def delete_by_scan_id(self, scan_id: str) -> int:
        """
        Delete all findings for a scan.

        Args:
            scan_id: Scan session ID

        Returns:
            Number of deleted items
        """
        if not self._ensure_initialized():
            return 0

        try:
            # First get IDs
            results = self._collection.get(
                where={"scan_id": scan_id},
                include=[],  # Only need IDs
            )

            ids = results.get("ids", [])
            if ids:
                with self._write_lock:
                    self._collection.delete(ids=ids)

            return len(ids)

        except Exception as e:
            logger.error("chromadb_delete_scan_failed", scan_id=scan_id, error=str(e))
            return 0

    def clear(self) -> bool:
        """
        Clear all data from the collection.

        Returns:
            True if successful
        """
        if not self._ensure_initialized():
            return False

        try:
            with self._write_lock:
                # Delete and recreate collection
                self._client.delete_collection(self._collection_name)
                self._collection = self._client.create_collection(
                    name=self._collection_name,
                    metadata=_get_index_metadata(),
                )
            logger.info("chromadb_cleared", collection=self._collection_name)
            return True
        except Exception as e:
            logger.error("chromadb_clear_failed", error=str(e))
            return False

    # -----------------------------------------------------------------------
    # Utility Methods
    # -----------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the index."""
        if not self._ensure_initialized():
            return {"available": False}

        return {
            "available": True,
            "collection_name": self._collection_name,
            "document_count": self._collection.count(),
            "db_path": str(self._db_path),
            "embedding_model": DEFAULT_EMBEDDING_MODEL,
            "schema_version": INDEX_SCHEMA_VERSION,
        }

    def close(self) -> None:
        """Close the ChromaDB connection (cleanup)."""
        # ChromaDB PersistentClient doesn't require explicit close
        self._client = None
        self._collection = None
        self._available = False
        self._init_attempted = False


# ---------------------------------------------------------------------------
# Singleton Instance
# ---------------------------------------------------------------------------

_backend_instance: Optional[ChromaDBBackend] = None


def get_chromadb_backend() -> ChromaDBBackend:
    """Get the singleton ChromaDB backend instance."""
    global _backend_instance

    if _backend_instance is None:
        _backend_instance = ChromaDBBackend()

    return _backend_instance
