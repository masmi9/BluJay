"""
AODS Semantic Finding Index
===========================

This module provides the high-level interface for semantic similarity search
across vulnerability findings. It orchestrates the embedder, pollution filter,
and ChromaDB backend to provide a unified, RBAC-aware search experience.

Key Features:
- Ownership-aware indexing and querying
- Pollution filtering (excludes example/demo findings)
- Secret redaction in embeddings
- Graceful degradation when dependencies unavailable
- Index versioning and rebuild support

Usage:
    from core.vector_db import get_semantic_finding_index

    index = get_semantic_finding_index()
    if index and index.is_available():
        # Index a finding after scan completion
        index.index_finding(finding, scan_context)

        # Search for similar findings (RBAC-filtered)
        results = index.find_similar(
            finding,
            user_info={"user": "alice", "roles": ["analyst"]},
            n_results=10
        )
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic Finding Index
# ---------------------------------------------------------------------------


class SemanticFindingIndex:
    """
    High-level interface for semantic finding search.

    This class orchestrates:
    - Pollution filtering (skip example/demo findings)
    - Embedding computation (with secret redaction)
    - ChromaDB storage and retrieval
    - RBAC-aware query filtering

    Thread Safety:
        Read operations are thread-safe.
        Write operations should be serialized (single writer).
    """

    def __init__(self):
        """Initialize the semantic finding index."""
        self._embedder_available = False
        self._backend_available = False
        self._init_attempted = False

    def _ensure_initialized(self) -> bool:
        """Lazy initialization of components."""
        if self._init_attempted:
            return self._embedder_available and self._backend_available

        self._init_attempted = True

        # Check embedder availability
        try:
            from core.vector_db.embedder import is_embedder_available

            self._embedder_available = is_embedder_available()
        except ImportError:
            logger.warning("semantic_index_embedder_unavailable")

        # Check backend availability
        try:
            from core.vector_db.chromadb_backend import get_chromadb_backend

            backend = get_chromadb_backend()
            self._backend_available = backend.is_available()
        except ImportError:
            logger.warning("semantic_index_backend_unavailable")

        if self._embedder_available and self._backend_available:
            logger.info("semantic_index_initialized")
        else:
            logger.warning(
                "semantic_index_degraded",
                embedder=self._embedder_available,
                backend=self._backend_available,
            )

        return self._embedder_available and self._backend_available

    def is_available(self) -> bool:
        """Check if the index is fully available."""
        return self._ensure_initialized()

    def get_collection_count(self) -> int:
        """Get the number of indexed findings."""
        if not self._ensure_initialized():
            return 0

        from core.vector_db.chromadb_backend import get_chromadb_backend

        return get_chromadb_backend().get_collection_count()

    # -----------------------------------------------------------------------
    # Indexing Operations
    # -----------------------------------------------------------------------

    def index_finding(
        self,
        finding: Dict[str, Any],
        scan_context: Dict[str, Any],
    ) -> bool:
        """
        Index a single finding with ownership metadata.

        Args:
            finding: The finding dict to index
            scan_context: Context dict containing:
                - scan_id: Session ID
                - owner_user_id: User who initiated the scan
                - tenant_id: (optional) Tenant identifier
                - visibility: (optional) "private" | "shared" | "public"

        Returns:
            True if indexing succeeded, False otherwise

        Note:
            Applies pollution filter - example/demo findings are skipped.
        """
        if not self._ensure_initialized():
            return False

        # Apply pollution filter
        from core.vector_db.pollution_filter import should_index_finding

        if not should_index_finding(finding):
            logger.debug(
                "semantic_index_skipped_pollution",
                title=str(finding.get("title", ""))[:50],
            )
            return False

        # Require owner metadata
        owner_user_id = scan_context.get("owner_user_id")
        if not owner_user_id:
            logger.warning(
                "semantic_index_no_owner",
                scan_id=scan_context.get("scan_id", "unknown"),
            )
            return False

        # Get finding ID
        finding_id = self._get_finding_id(finding)
        if not finding_id:
            logger.warning("semantic_index_no_id")
            return False

        # Compute embedding
        from core.vector_db.embedder import (
            compute_finding_embedding,
        )

        embedding = compute_finding_embedding(finding)
        if embedding is None:
            logger.warning(
                "semantic_index_embedding_failed",
                finding_id=finding_id,
            )
            return False

        # Build metadata
        metadata = self._build_finding_metadata(finding, scan_context)

        # Index
        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()

        return backend.index(finding_id, embedding, metadata)

    def index_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        scan_context: Dict[str, Any],
    ) -> int:
        """
        Index a batch of findings.

        Args:
            findings: List of findings to index
            scan_context: Context dict with ownership metadata

        Returns:
            Number of successfully indexed findings
        """
        if not self._ensure_initialized():
            return 0

        if not findings:
            return 0

        # Require owner metadata
        owner_user_id = scan_context.get("owner_user_id")
        if not owner_user_id:
            logger.warning(
                "semantic_index_batch_no_owner",
                scan_id=scan_context.get("scan_id", "unknown"),
            )
            return 0

        from core.vector_db.pollution_filter import should_index_finding
        from core.vector_db.embedder import compute_batch_embeddings, finding_to_embedding_text
        from core.vector_db.chromadb_backend import get_chromadb_backend

        # Filter and prepare findings
        valid_findings = []
        for finding in findings:
            if should_index_finding(finding):
                finding_id = self._get_finding_id(finding)
                if finding_id:
                    valid_findings.append((finding, finding_id))

        if not valid_findings:
            return 0

        # Compute embeddings in batch
        texts = [finding_to_embedding_text(f) for f, _ in valid_findings]
        embeddings = compute_batch_embeddings(texts)

        # Prepare items for batch indexing
        items = []
        for i, (finding, finding_id) in enumerate(valid_findings):
            if embeddings[i] is not None:
                metadata = self._build_finding_metadata(finding, scan_context)
                items.append((finding_id, embeddings[i], metadata))

        # Batch index
        backend = get_chromadb_backend()
        indexed = backend.index_batch(items)

        logger.info(
            "semantic_index_batch_complete",
            total=len(findings),
            valid=len(valid_findings),
            indexed=indexed,
        )

        return indexed

    def update_finding_metadata(
        self,
        finding_id: str,
        new_metadata: Dict[str, Any],
    ) -> bool:
        """
        Merge new metadata keys into an existing indexed finding.

        Fetches the existing document, merges ``new_metadata`` on top,
        and re-upserts with the original embedding so nothing is lost.

        Args:
            finding_id: The ID of the finding to update.
            new_metadata: Dict of metadata keys to add/overwrite.

        Returns:
            True if the update succeeded, False if the finding was not
            found or the index is unavailable.
        """
        if not self._ensure_initialized():
            return False

        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()
        existing = backend.get_by_id(finding_id)
        if existing is None:
            return False

        # Merge metadata
        merged = dict(existing.get("metadata", {}))
        merged.update(new_metadata)

        # Re-upsert with the same embedding
        embedding = existing.get("embedding")
        if embedding is None:
            return False

        return backend.index(finding_id, embedding, merged)

    def _get_finding_id(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract or generate finding ID."""
        finding_id = finding.get("id") or finding.get("finding_id") or finding.get("unique_id")

        if finding_id:
            return str(finding_id)

        return None

    def _build_finding_metadata(
        self,
        finding: Dict[str, Any],
        scan_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build metadata dict for ChromaDB storage."""
        metadata = {
            # Ownership (REQUIRED)
            "scan_id": scan_context.get("scan_id", ""),
            "owner_user_id": scan_context.get("owner_user_id", ""),
            "tenant_id": scan_context.get("tenant_id", "default"),
            "visibility": scan_context.get("visibility", "private"),
            # Finding attributes
            "severity": finding.get("severity", ""),
            "cwe_id": str(finding.get("cwe_id") or finding.get("cwe") or ""),
            "plugin_source": finding.get("plugin_source", "") or finding.get("source", ""),
            "title": str(finding.get("title", ""))[:200],
            "vulnerability_type": str(finding.get("vulnerability_type", "") or finding.get("type", ""))[:100],
        }

        # Add secret fingerprints if available
        try:
            from core.vector_db.secret_fingerprint import fingerprint_finding_secrets

            secret_meta = fingerprint_finding_secrets(
                finding,
                tenant_id=scan_context.get("tenant_id", "default"),
            )
            if secret_meta.get("secret_count", 0) > 0:
                metadata["secret_types"] = ",".join(secret_meta.get("secret_types", []))
                metadata["secret_fingerprints"] = ",".join(secret_meta.get("secret_fingerprints", []))
                metadata["secret_count"] = secret_meta["secret_count"]
        except Exception as e:
            logger.debug("semantic_index_secret_fingerprint_skipped", error=str(e))

        return metadata

    # -----------------------------------------------------------------------
    # Query Operations
    # -----------------------------------------------------------------------

    def find_similar(
        self,
        finding: Dict[str, Any],
        user_info: Optional[Dict[str, Any]] = None,
        n_results: int = 10,
        include_same_scan: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Find similar findings using semantic search.

        Args:
            finding: The finding to find similar matches for
            user_info: User info for RBAC filtering (from _require_roles)
                If None, returns all results (admin-like access)
            n_results: Maximum number of results
            include_same_scan: If False, excludes findings from same scan

        Returns:
            List of similar findings with similarity scores
        """
        if not self._ensure_initialized():
            return []

        # Compute query embedding
        from core.vector_db.embedder import compute_finding_embedding

        query_embedding = compute_finding_embedding(finding)
        if query_embedding is None:
            return []

        # Build ownership filter
        ownership_filter = self._build_ownership_filter(user_info)

        # Exclude same scan if requested
        scan_id = finding.get("_scan_id") or finding.get("scan_id")
        if not include_same_scan and scan_id:
            if ownership_filter:
                ownership_filter = {
                    "$and": [
                        ownership_filter,
                        {"scan_id": {"$ne": scan_id}},
                    ]
                }
            else:
                ownership_filter = {"scan_id": {"$ne": scan_id}}

        # Query backend
        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()

        results = backend.query(
            query_embedding=query_embedding,
            ownership_filter=ownership_filter,
            n_results=n_results,
        )

        return results

    def find_similar_by_text(
        self,
        query_text: str,
        user_info: Optional[Dict[str, Any]] = None,
        n_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Find similar findings by text query.

        Args:
            query_text: Text to search for
            user_info: User info for RBAC filtering
            n_results: Maximum number of results

        Returns:
            List of similar findings
        """
        if not self._ensure_initialized():
            return []

        from core.vector_db.embedder import compute_embedding

        query_embedding = compute_embedding(query_text)
        if query_embedding is None:
            return []

        ownership_filter = self._build_ownership_filter(user_info)

        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()

        return backend.query(
            query_embedding=query_embedding,
            ownership_filter=ownership_filter,
            n_results=n_results,
        )

    def _build_ownership_filter(
        self,
        user_info: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Build ChromaDB ownership filter from user info.

        Applies both tenant isolation (``tenant_id``) and per-user
        visibility rules.  Admins bypass visibility but still respect
        tenant boundaries.
        """
        if user_info is None:
            # No user info = no filtering (admin-like)
            return None

        roles = user_info.get("roles", [])
        username = user_info.get("user", "")
        tenant_id = user_info.get("tenant_id", "default")

        tenant_clause = {"tenant_id": tenant_id}

        # Admins see everything within their tenant
        if "admin" in roles:
            return tenant_clause

        # Other users: own findings + shared + public, within tenant
        visibility_clause = {
            "$or": [
                {"owner_user_id": username},
                {"visibility": "shared"},
                {"visibility": "public"},
            ]
        }

        return {
            "$and": [
                tenant_clause,
                visibility_clause,
            ]
        }

    # -----------------------------------------------------------------------
    # Admin Operations
    # -----------------------------------------------------------------------

    def delete_scan_findings(self, scan_id: str) -> int:
        """
        Delete all indexed findings for a scan.

        Args:
            scan_id: Scan session ID

        Returns:
            Number of deleted findings
        """
        if not self._ensure_initialized():
            return 0

        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()

        deleted = backend.delete_by_scan_id(scan_id)
        logger.info("semantic_index_scan_deleted", scan_id=scan_id, deleted=deleted)

        return deleted

    def rebuild_from_reports(
        self,
        reports_dir: str,
        owner_metadata_extractor: Optional[callable] = None,
        clear_existing: bool = True,
    ) -> Dict[str, int]:
        """
        Rebuild index from existing report files.

        This is an ADMIN-ONLY operation that reindexes all findings
        from saved reports. Reports without owner metadata are skipped.

        Args:
            reports_dir: Path to reports directory
            owner_metadata_extractor: Optional function to extract owner
                metadata from report. Signature: (report) -> Dict[str, str]
            clear_existing: If True (default), clear the index before rebuild.
                Set to False to append to existing index.

        Returns:
            Stats dict with indexed, skipped_no_owner, skipped_pollution counts
        """
        import json
        from pathlib import Path

        if not self._ensure_initialized():
            return {"error": "Index not available"}

        stats = {
            "indexed": 0,
            "skipped_no_owner": 0,
            "skipped_pollution": 0,
            "errors": 0,
        }

        reports_path = Path(reports_dir)
        if not reports_path.exists():
            return {"error": f"Reports directory not found: {reports_dir}"}

        # Conditionally clear existing index
        from core.vector_db.chromadb_backend import get_chromadb_backend

        backend = get_chromadb_backend()
        if clear_existing:
            backend.clear()

        # Process each report
        # Real report filenames include a timestamp+uuid suffix after "_report",
        # e.g. "com.app_security_report_20260203_165005_059bb3f9.json"
        for report_file in reports_path.glob("**/*_report*.json"):
            try:
                with open(report_file, "r") as f:
                    report = json.load(f)

                # Extract owner metadata
                if owner_metadata_extractor:
                    owner_meta = owner_metadata_extractor(report)
                else:
                    owner_meta = {
                        "owner_user_id": report.get("owner_user_id"),
                        "scan_id": report.get("session_id") or report.get("scan_id"),
                        "tenant_id": report.get("tenant_id", "default"),
                    }

                if not owner_meta.get("owner_user_id"):
                    stats["skipped_no_owner"] += 1
                    continue

                # Index findings - reports may store findings under different keys
                findings = (
                    report.get("findings")
                    or report.get("vulnerability_findings")
                    or report.get("vulnerabilities")
                    or []
                )
                for finding in findings:
                    result = self.index_finding(finding, owner_meta)
                    if result:
                        stats["indexed"] += 1
                    else:
                        stats["skipped_pollution"] += 1

            except Exception as e:
                logger.error("semantic_index_rebuild_error", file=str(report_file), error=str(e))
                stats["errors"] += 1

        logger.info("semantic_index_rebuild_complete", **stats)
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        if not self._ensure_initialized():
            return {
                "available": False,
                "embedder_available": self._embedder_available,
                "backend_available": self._backend_available,
            }

        from core.vector_db.chromadb_backend import get_chromadb_backend
        from core.vector_db.embedder import get_embedding_dimension, get_cache_stats

        backend_stats = get_chromadb_backend().get_stats()
        cache_stats = get_cache_stats()

        return {
            "available": True,
            "embedder_available": self._embedder_available,
            "backend_available": self._backend_available,
            "embedding_dimension": get_embedding_dimension(),
            "embedding_cache": cache_stats,
            **backend_stats,
        }


# ---------------------------------------------------------------------------
# Singleton Instance
# ---------------------------------------------------------------------------

_index_instance: Optional[SemanticFindingIndex] = None


def get_semantic_finding_index() -> SemanticFindingIndex:
    """Get the singleton SemanticFindingIndex instance."""
    global _index_instance

    if _index_instance is None:
        _index_instance = SemanticFindingIndex()

    return _index_instance


def reset_semantic_finding_index() -> None:
    """Reset the singleton instance (for testing)."""
    global _index_instance
    _index_instance = None
