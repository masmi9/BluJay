"""
Evidence Enrichment Pipeline.

Track 7 Phase 3 - Output Validation: Automatically enriches plugin findings
with line numbers and code snippets after execution.

This module bridges the gap between existing evidence infrastructure
(LineNumberExtractor, VulnerabilityCodeExtractor) and the plugin execution
pipeline, improving evidence coverage from ~5% to target 80%+.

Key Features:
1. Post-processing enrichment after plugin execution
2. Automatic line number extraction from file paths and patterns
3. Code snippet extraction with context
4. Evidence structure normalization
5. Coverage metrics tracking
"""

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging

    logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    """Result of evidence enrichment operation."""

    findings_processed: int
    findings_enriched: int
    line_numbers_added: int
    code_snippets_added: int
    elapsed_ms: float
    errors: List[str]


@dataclass
class EnrichmentMetrics:
    """Metrics for evidence quality after enrichment."""

    total_findings: int
    with_line_number: int
    with_code_snippet: int
    with_file_path: int
    with_taxonomy: int
    line_number_pct: float
    code_snippet_pct: float
    file_path_pct: float
    taxonomy_pct: float


class EvidenceEnrichmentPipeline:
    """
    Enriches plugin findings with line numbers and code snippets.

    This pipeline runs after plugin execution to improve evidence
    completeness by leveraging existing extraction infrastructure.
    """

    # Default context lines for code snippets
    DEFAULT_CONTEXT_LINES = 5

    # File extensions to search for source files
    SOURCE_EXTENSIONS = [".java", ".kt", ".xml", ".smali", ".js", ".json", ".gradle"]

    def __init__(self, apk_context: Optional[Any] = None):
        """
        Initialize enrichment pipeline.

        Args:
            apk_context: APK context with decompiled paths (optional)
        """
        self.apk_context = apk_context
        self._line_extractor = None
        self._code_extractor = None
        self._source_file_cache: Dict[str, str] = {}
        self._decompiled_paths: List[Path] = []

        # Initialize decompiled paths from context
        if apk_context:
            self._init_decompiled_paths(apk_context)

    def _init_decompiled_paths(self, apk_context: Any) -> None:
        """Initialize paths to search for decompiled sources."""
        paths = []

        # Standard decompiled directories
        if hasattr(apk_context, "decompiled_apk_dir"):
            paths.append(Path(apk_context.decompiled_apk_dir))
        if hasattr(apk_context, "jadx_output_dir"):
            paths.append(Path(apk_context.jadx_output_dir))
        if hasattr(apk_context, "apktool_output_dir"):
            paths.append(Path(apk_context.apktool_output_dir))

        # Sources subdirectory (JADX standard output)
        for p in list(paths):
            sources_dir = p / "sources"
            if sources_dir.exists():
                paths.insert(0, sources_dir)  # Prioritize sources/

        self._decompiled_paths = [p for p in paths if p.exists()]
        logger.debug(f"Initialized {len(self._decompiled_paths)} decompiled paths")

    @property
    def line_extractor(self):
        """Lazy-load line number extractor."""
        if self._line_extractor is None:
            try:
                from core.line_number_extractor import LineNumberExtractor

                self._line_extractor = LineNumberExtractor()
            except ImportError:
                logger.warning("LineNumberExtractor not available")
        return self._line_extractor

    @property
    def code_extractor(self):
        """Lazy-load code extractor."""
        if self._code_extractor is None:
            try:
                from core.vulnerability_code_extractor import VulnerabilityCodeExtractor

                self._code_extractor = VulnerabilityCodeExtractor(context_lines=self.DEFAULT_CONTEXT_LINES)
            except ImportError:
                logger.warning("VulnerabilityCodeExtractor not available")
        return self._code_extractor

    def enrich_findings(
        self,
        findings: List[Any],
        source_paths: Optional[List[Path]] = None,
    ) -> EnrichmentResult:
        """
        Enrich a list of findings with line numbers and code snippets.

        Args:
            findings: List of PluginFinding objects or dicts
            source_paths: Additional paths to search for source files

        Returns:
            EnrichmentResult with metrics
        """
        start_time = time.time()
        errors = []
        enriched_count = 0
        line_numbers_added = 0
        code_snippets_added = 0

        # Combine search paths
        search_paths = list(self._decompiled_paths)
        if source_paths:
            search_paths.extend(source_paths)

        for finding in findings:
            try:
                result = self._enrich_single_finding(finding, search_paths)
                if result["enriched"]:
                    enriched_count += 1
                if result["line_number_added"]:
                    line_numbers_added += 1
                if result["code_snippet_added"]:
                    code_snippets_added += 1
            except Exception as e:
                errors.append(f"Error enriching finding: {e}")
                logger.debug(f"Enrichment error: {e}", exc_info=True)

        elapsed_ms = (time.time() - start_time) * 1000

        logger.info(
            f"Evidence enrichment: {enriched_count}/{len(findings)} enriched, "
            f"+{line_numbers_added} line numbers, +{code_snippets_added} snippets "
            f"({elapsed_ms:.1f}ms)"
        )

        return EnrichmentResult(
            findings_processed=len(findings),
            findings_enriched=enriched_count,
            line_numbers_added=line_numbers_added,
            code_snippets_added=code_snippets_added,
            elapsed_ms=elapsed_ms,
            errors=errors,
        )

    def _enrich_single_finding(
        self,
        finding: Any,
        search_paths: List[Path],
    ) -> Dict[str, bool]:
        """
        Enrich a single finding with line number and code snippet.

        Args:
            finding: PluginFinding object or dict
            search_paths: Paths to search for source files

        Returns:
            Dict with enrichment status flags
        """
        result = {
            "enriched": False,
            "line_number_added": False,
            "code_snippet_added": False,
        }

        # Extract current values
        file_path = self._get_finding_attr(finding, "file_path")
        line_number = self._get_finding_attr(finding, "line_number")
        code_snippet = self._get_finding_attr(finding, "code_snippet")
        title = self._get_finding_attr(finding, "title", "")
        description = self._get_finding_attr(finding, "description", "")

        # Skip if already fully enriched
        if line_number and code_snippet:
            return result

        # Try to find source file
        source_content = None
        resolved_path = None

        if file_path:
            source_content, resolved_path = self._find_and_read_source(file_path, search_paths)

        # Enrich line number
        if not line_number and source_content:
            extracted_line = self._extract_line_number(
                source_content,
                title,
                description,
                resolved_path,
            )
            if extracted_line:
                self._set_finding_attr(finding, "line_number", extracted_line)
                line_number = extracted_line
                result["line_number_added"] = True
                result["enriched"] = True

        # Enrich code snippet
        final_snippet = code_snippet
        if not code_snippet and source_content and line_number:
            extracted_snippet = self._extract_code_snippet(
                source_content,
                line_number,
                resolved_path,
            )
            if extracted_snippet:
                self._set_finding_attr(finding, "code_snippet", extracted_snippet)
                final_snippet = extracted_snippet
                result["code_snippet_added"] = True
                result["enriched"] = True

        # Update evidence structure
        if result["enriched"]:
            self._update_evidence_structure(finding, line_number, final_snippet)

        return result

    def _get_finding_attr(self, finding: Any, attr: str, default: Any = None) -> Any:
        """Get attribute from finding (dataclass or dict).

        Falls back to finding['evidence'][attr] when the top-level key is absent,
        since enriched evidence is stored in a nested 'evidence' dict.
        """
        if hasattr(finding, attr):
            val = getattr(finding, attr, default)
            if val is not None:
                return val
        if isinstance(finding, dict):
            val = finding.get(attr)
            if val is not None:
                return val
            # Fallback: check nested evidence dict
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                val = evidence.get(attr)
                if val is not None:
                    return val
        return default

    def _set_finding_attr(self, finding: Any, attr: str, value: Any) -> None:
        """Set attribute on finding (dataclass or dict)."""
        if hasattr(finding, attr):
            setattr(finding, attr, value)
        elif isinstance(finding, dict):
            finding[attr] = value

    def _find_and_read_source(
        self,
        file_path: str,
        search_paths: List[Path],
    ) -> Tuple[Optional[str], Optional[Path]]:
        """
        Find and read source file content.

        Args:
            file_path: Relative or absolute file path
            search_paths: Paths to search

        Returns:
            Tuple of (content, resolved_path) or (None, None)
        """
        # Check cache first
        if file_path in self._source_file_cache:
            return self._source_file_cache[file_path], Path(file_path)

        # Normalize path
        file_path = file_path.replace("\\", "/")

        # Try direct path first
        if os.path.isabs(file_path) and os.path.exists(file_path):
            try:
                content = Path(file_path).read_text(errors="ignore")
                self._source_file_cache[file_path] = content
                return content, Path(file_path)
            except Exception:
                pass

        # Extract relative path components
        # Handle paths like "com/example/MainActivity.java"
        relative_parts = file_path.split("/")

        # Search in decompiled paths
        for base_path in search_paths:
            # Try direct join
            candidate = base_path / file_path
            if candidate.exists():
                try:
                    content = candidate.read_text(errors="ignore")
                    self._source_file_cache[file_path] = content
                    return content, candidate
                except Exception:
                    pass

            # Try searching for filename in subdirectories
            if len(relative_parts) > 0:
                filename = relative_parts[-1]
                for source_file in base_path.rglob(filename):
                    # Verify path suffix matches
                    if str(source_file).endswith(file_path):
                        try:
                            content = source_file.read_text(errors="ignore")
                            self._source_file_cache[file_path] = content
                            return content, source_file
                        except Exception:
                            pass

        return None, None

    def _extract_line_number(
        self,
        content: str,
        title: str,
        description: str,
        file_path: Optional[Path],
    ) -> Optional[int]:
        """
        Extract line number from content using various strategies.

        Args:
            content: Source file content
            title: Finding title (may contain pattern hints)
            description: Finding description
            file_path: Source file path

        Returns:
            Extracted line number or None
        """
        _ = file_path  # Reserved for future language-specific extraction
        # Strategy 1: Search for vulnerability pattern in title
        patterns_to_search = []

        # Extract code patterns from title/description
        code_patterns = re.findall(r"`([^`]+)`", title + " " + description)
        patterns_to_search.extend(code_patterns)

        # Common vulnerability indicators
        indicators = [
            r"SecretKeySpec",
            r"Cipher\.getInstance",
            r"MessageDigest",
            r"SharedPreferences",
            r"getSystemService",
            r"WebView",
            r"setJavaScriptEnabled",
            r"addJavascriptInterface",
            r"setAllowFileAccess",
            r"checkServerTrusted",
            r"TrustManager",
            r"SSLContext",
            r"X509TrustManager",
            r"Log\.[dviwe]",
            r"printStackTrace",
            r"MODE_WORLD_",
            r"android:debuggable",
            r"android:allowBackup",
        ]

        # Try each pattern
        for pattern in patterns_to_search + indicators:
            try:
                match = re.search(re.escape(pattern) if pattern in patterns_to_search else pattern, content)
                if match:
                    line_number = content[: match.start()].count("\n") + 1
                    if line_number > 0:
                        return line_number
            except Exception:
                pass

        # Strategy 2: Use LineNumberExtractor if available
        if self.line_extractor:
            try:
                # Use position-based extraction (returns int, not dict)
                extracted = self.line_extractor.extract_line_number_from_content_position(
                    content=content,
                    position=0,
                )
                if extracted and extracted > 1:
                    return extracted
            except Exception:
                pass

        return None

    def _extract_code_snippet(
        self,
        content: str,
        line_number: int,
        file_path: Optional[Path],
    ) -> Optional[str]:
        """
        Extract code snippet around the given line number.

        Args:
            content: Source file content
            line_number: Line number to center snippet on
            file_path: Source file path (used for logging)

        Returns:
            Code snippet string or None
        """
        _ = file_path  # Reserved for future language detection
        try:
            lines = content.split("\n")
            total_lines = len(lines)

            if line_number < 1 or line_number > total_lines:
                return None

            # Calculate context window
            start = max(0, line_number - 1 - self.DEFAULT_CONTEXT_LINES)
            end = min(total_lines, line_number + self.DEFAULT_CONTEXT_LINES)

            # Extract lines with line numbers
            snippet_lines = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if line_num == line_number else "   "
                snippet_lines.append(f"{line_num:4d} {marker} {lines[i]}")

            return "\n".join(snippet_lines)

        except Exception as e:
            logger.debug(f"Code snippet extraction failed: {e}")
            return None

    def _update_evidence_structure(
        self,
        finding: Any,
        line_number: Optional[int],
        code_snippet: Optional[str],
    ) -> None:
        """
        Update evidence dict with enriched data.

        Args:
            finding: Finding to update
            line_number: Extracted line number
            code_snippet: Extracted code snippet
        """
        # Get or create evidence dict
        evidence = self._get_finding_attr(finding, "evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}

        # Update with enriched data
        if line_number:
            evidence["line_number"] = line_number
        if code_snippet:
            evidence["code_snippet"] = code_snippet
            evidence["snippet_lines"] = len(code_snippet.split("\n"))

        # Mark as enriched
        evidence["enriched"] = True
        evidence["enrichment_source"] = "evidence_enrichment_pipeline"

        self._set_finding_attr(finding, "evidence", evidence)

    def calculate_metrics(self, findings: List[Any]) -> EnrichmentMetrics:
        """
        Calculate evidence quality metrics for a list of findings.

        Args:
            findings: List of findings to analyze

        Returns:
            EnrichmentMetrics with coverage percentages
        """
        total = len(findings)
        if total == 0:
            return EnrichmentMetrics(
                total_findings=0,
                with_line_number=0,
                with_code_snippet=0,
                with_file_path=0,
                with_taxonomy=0,
                line_number_pct=0.0,
                code_snippet_pct=0.0,
                file_path_pct=0.0,
                taxonomy_pct=0.0,
            )

        with_line_number = sum(1 for f in findings if self._get_finding_attr(f, "line_number"))
        with_code_snippet = sum(1 for f in findings if self._get_finding_attr(f, "code_snippet"))
        with_file_path = sum(1 for f in findings if self._get_finding_attr(f, "file_path"))
        with_taxonomy = sum(
            1 for f in findings if (self._get_finding_attr(f, "cwe_id") or self._get_finding_attr(f, "owasp_category"))
        )

        return EnrichmentMetrics(
            total_findings=total,
            with_line_number=with_line_number,
            with_code_snippet=with_code_snippet,
            with_file_path=with_file_path,
            with_taxonomy=with_taxonomy,
            line_number_pct=round(with_line_number / total * 100, 1),
            code_snippet_pct=round(with_code_snippet / total * 100, 1),
            file_path_pct=round(with_file_path / total * 100, 1),
            taxonomy_pct=round(with_taxonomy / total * 100, 1),
        )


def enrich_plugin_findings(
    findings: List[Any],
    apk_context: Optional[Any] = None,
    source_paths: Optional[List[Path]] = None,
) -> EnrichmentResult:
    """
    Convenience function to enrich plugin findings.

    Args:
        findings: List of PluginFinding objects or dicts
        apk_context: APK context with decompiled paths
        source_paths: Additional paths to search

    Returns:
        EnrichmentResult with metrics
    """
    pipeline = EvidenceEnrichmentPipeline(apk_context=apk_context)
    return pipeline.enrich_findings(findings, source_paths=source_paths)


def calculate_evidence_metrics(findings: List[Any]) -> EnrichmentMetrics:
    """
    Calculate evidence quality metrics for findings.

    Args:
        findings: List of findings to analyze

    Returns:
        EnrichmentMetrics with coverage percentages
    """
    pipeline = EvidenceEnrichmentPipeline()
    return pipeline.calculate_metrics(findings)
