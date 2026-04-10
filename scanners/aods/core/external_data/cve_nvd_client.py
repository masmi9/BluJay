#!/usr/bin/env python3
"""
AODS CVE/NVD Integration Client
==============================

Full CVE/NVD API client providing real-time vulnerability data
synchronization with intelligent rate limiting and data processing.

Features:
- CVE/NVD API v2.0 integration with full data access
- Intelligent rate limiting and retry mechanisms
- Incremental updates with change detection
- Data validation and quality assurance
- Efficient local caching and storage
- CVSS score calculation and enhancement
"""

import asyncio
import aiohttp
import logging
import time
import json
import hashlib
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3

logger = logging.getLogger(__name__)


@dataclass
class CVEData:
    """Full CVE data structure with metadata."""

    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: datetime
    modified_date: datetime
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[Dict[str, str]] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        """Calculate enhanced risk score with external factors."""
        base_score = self.cvss_score

        # Enhance score based on exploit availability
        if self.exploit_available:
            base_score += 1.5

        # Enhance score based on threat intelligence
        threat_multiplier = self.threat_intelligence.get("activity_score", 0) / 10
        base_score += threat_multiplier

        # Reduce score if patch is available
        if self.patch_available:
            base_score -= 0.5

        return min(10.0, max(0.0, base_score))


@dataclass
class SynchronizationStats:
    """Statistics for CVE/NVD synchronization operations."""

    total_processed: int = 0
    new_cves: int = 0
    updated_cves: int = 0
    errors: int = 0
    processing_time: float = 0.0
    last_sync: Optional[datetime] = None
    data_freshness: float = 0.0  # Hours since last update


class CVENVDClient:
    """
    Advanced CVE/NVD API client with data integration.

    Provides reliable CVE/NVD data synchronization with intelligent
    rate limiting, error handling, and data quality assurance.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize CVE/NVD client with configuration."""
        self.config = config or {}
        self.api_base_url = self.config.get("api_base_url", "https://services.nvd.nist.gov/rest/json")
        self.api_version = self.config.get("api_version", "v2")
        self.rate_limit = self.config.get("rate_limit", 50)  # requests per minute
        self.max_retries = self.config.get("max_retry_attempts", 3)
        self.request_timeout = self.config.get("request_timeout", 30)

        # Rate limiting
        self.request_times = []
        self.rate_limit_window = 60  # seconds

        # Database for local storage
        self.db_path = self.config.get("database_path", "data/cve_nvd.db")
        self.init_database()

        # Statistics tracking
        self.stats = SynchronizationStats()

        logger.info("CVE/NVD Client initialized with data integration")

    def init_database(self) -> None:
        """Initialize local CVE database for caching and querying."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_data (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    [references] TEXT,  -- JSON (escaped reserved keyword)
                    cwe_ids TEXT,     -- JSON
                    affected_products TEXT,  -- JSON
                    exploit_available BOOLEAN DEFAULT 0,
                    patch_available BOOLEAN DEFAULT 0,
                    threat_intelligence TEXT,  -- JSON
                    data_hash TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_data(severity);
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_data(cvss_score);
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cve_modified ON cve_data(modified_date);
            """)

            # Statistics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_stats (
                    id INTEGER PRIMARY KEY,
                    sync_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_processed INTEGER,
                    new_cves INTEGER,
                    updated_cves INTEGER,
                    errors INTEGER,
                    processing_time REAL
                )
            """)

            conn.commit()

        logger.info("CVE/NVD local database initialized")

    async def _rate_limit_check(self) -> None:
        """Ensure API rate limits are respected."""
        current_time = time.time()

        # Remove old requests outside the rate limit window
        self.request_times = [
            req_time for req_time in self.request_times if current_time - req_time < self.rate_limit_window
        ]

        # Check if we need to wait
        if len(self.request_times) >= self.rate_limit:
            wait_time = self.rate_limit_window - (current_time - self.request_times[0])
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        self.request_times.append(current_time)

    async def _make_api_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make rate-limited API request with retry logic."""
        url = f"{self.api_base_url}/{self.api_version}/{endpoint}"

        for attempt in range(self.max_retries):
            try:
                await self._rate_limit_check()

                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, timeout=self.request_timeout) as response:
                        if response.status == 200:
                            return await response.json()
                        elif response.status == 429:  # Rate limited
                            retry_after = int(response.headers.get("Retry-After", 60))
                            logger.warning(f"Rate limited by server, waiting {retry_after}s")
                            await asyncio.sleep(retry_after)
                        else:
                            logger.error(f"API request failed: {response.status}")
                            if attempt < self.max_retries - 1:
                                await asyncio.sleep(2**attempt)  # Exponential backoff

            except asyncio.TimeoutError:
                logger.error(f"API request timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
            except Exception as e:
                logger.error(f"API request error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)

        raise Exception(f"Failed to complete API request after {self.max_retries} attempts")

    def _parse_cve_data(self, cve_item: Dict[str, Any]) -> CVEData:
        """Parse CVE data from NVD API response."""
        cve_data = cve_item.get("cve", {})

        # Basic CVE information
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"), "")

        # CVSS scoring
        metrics = cve_item.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        severity = "UNKNOWN"

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]  # Take first metric
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # Dates
        published_date = datetime.fromisoformat(cve_item.get("published", "").replace("Z", "+00:00"))
        modified_date = datetime.fromisoformat(cve_item.get("lastModified", "").replace("Z", "+00:00"))

        # References
        references = [ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")]

        # Weakness information (CWE)
        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_ids.append(desc.get("value", ""))

        # Affected products (CPE)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        affected_products.append(
                            {
                                "cpe": cpe_match.get("criteria", ""),
                                "version_start": cpe_match.get("versionStartIncluding"),
                                "version_end": cpe_match.get("versionEndExcluding"),
                            }
                        )

        return CVEData(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            cwe_ids=cwe_ids,
            affected_products=affected_products,
        )

    async def fetch_recent_cves(self, days: int = 7) -> List[CVEData]:
        """Fetch CVEs published or modified in the last N days."""
        end_date = datetime.now(UTC)
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "resultsPerPage": 2000,
        }

        cves = []
        start_index = 0

        while True:
            params["startIndex"] = start_index

            try:
                response = await self._make_api_request("cves", params)

                vulnerabilities = response.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln_item in vulnerabilities:
                    try:
                        cve_data = self._parse_cve_data(vuln_item)
                        cves.append(cve_data)
                    except Exception as e:
                        logger.error(f"Failed to parse CVE data: {e}")
                        self.stats.errors += 1

                # Check if there are more results
                total_results = response.get("totalResults", 0)
                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break

            except Exception as e:
                logger.error(f"Failed to fetch CVEs: {e}")
                self.stats.errors += 1
                break

        logger.info(f"Fetched {len(cves)} CVEs from last {days} days")
        return cves

    def store_cve_data(self, cve_data: CVEData) -> bool:
        """Store CVE data in local database with deduplication."""
        try:
            # Calculate data hash for change detection
            data_str = f"{cve_data.cve_id}{cve_data.description}{cve_data.cvss_score}{cve_data.modified_date}"
            data_hash = hashlib.sha256(data_str.encode()).hexdigest()

            with sqlite3.connect(self.db_path) as conn:
                # Check if CVE exists and hash has changed
                cursor = conn.execute("SELECT data_hash FROM cve_data WHERE cve_id = ?", (cve_data.cve_id,))
                existing = cursor.fetchone()

                if existing and existing[0] == data_hash:
                    # No changes detected
                    return False

                # Insert or update CVE data
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_data (
                        cve_id, description, severity, cvss_score, cvss_vector,
                        published_date, modified_date, [references], cwe_ids,
                        affected_products, exploit_available, patch_available,
                        threat_intelligence, data_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cve_data.cve_id,
                        cve_data.description,
                        cve_data.severity,
                        cve_data.cvss_score,
                        cve_data.cvss_vector,
                        cve_data.published_date.isoformat(),
                        cve_data.modified_date.isoformat(),
                        json.dumps(cve_data.references),
                        json.dumps(cve_data.cwe_ids),
                        json.dumps(cve_data.affected_products),
                        cve_data.exploit_available,
                        cve_data.patch_available,
                        json.dumps(cve_data.threat_intelligence),
                        data_hash,
                    ),
                )

                conn.commit()

                if existing:
                    self.stats.updated_cves += 1
                else:
                    self.stats.new_cves += 1

                return True

        except Exception as e:
            logger.error(f"Failed to store CVE data {cve_data.cve_id}: {e}")
            self.stats.errors += 1
            return False

    def query_cves(
        self,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        product: Optional[str] = None,
        limit: int = 100,
    ) -> List[CVEData]:
        """Query CVEs from local database with filtering."""
        try:
            query = "SELECT * FROM cve_data WHERE 1=1"
            params = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if min_score is not None:
                query += " AND cvss_score >= ?"
                params.append(min_score)

            if product:
                query += " AND affected_products LIKE ?"
                params.append(f"%{product}%")

            query += " ORDER BY cvss_score DESC, modified_date DESC LIMIT ?"
            params.append(limit)

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)

                cves = []
                for row in cursor.fetchall():
                    cve_data = CVEData(
                        cve_id=row["cve_id"],
                        description=row["description"],
                        severity=row["severity"],
                        cvss_score=row["cvss_score"],
                        cvss_vector=row["cvss_vector"],
                        published_date=datetime.fromisoformat(row["published_date"]),
                        modified_date=datetime.fromisoformat(row["modified_date"]),
                        references=json.loads(row["references"] or "[]"),
                        cwe_ids=json.loads(row["cwe_ids"] or "[]"),
                        affected_products=json.loads(row["affected_products"] or "[]"),
                        exploit_available=bool(row["exploit_available"]),
                        patch_available=bool(row["patch_available"]),
                        threat_intelligence=json.loads(row["threat_intelligence"] or "{}"),
                    )
                    cves.append(cve_data)

                return cves

        except Exception as e:
            logger.error(f"Failed to query CVEs: {e}")
            return []

    async def sync_cve_database(self, days: int = 30) -> SynchronizationStats:
        """Synchronize local CVE database with NVD data."""
        logger.info(f"Starting CVE database synchronization for last {days} days")
        start_time = time.time()

        # Reset statistics
        self.stats = SynchronizationStats()

        try:
            # Fetch recent CVEs
            cves = await self.fetch_recent_cves(days)

            # Store CVEs in local database
            for cve in cves:
                if self.store_cve_data(cve):
                    self.stats.total_processed += 1

            # Update statistics
            self.stats.processing_time = time.time() - start_time
            self.stats.last_sync = datetime.now(UTC)
            self.stats.data_freshness = 0.0  # Just synchronized

            # Store sync statistics
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO sync_stats (total_processed, new_cves, updated_cves, errors, processing_time)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        self.stats.total_processed,
                        self.stats.new_cves,
                        self.stats.updated_cves,
                        self.stats.errors,
                        self.stats.processing_time,
                    ),
                )
                conn.commit()

            logger.info(
                f"CVE synchronization completed: {self.stats.total_processed} processed, "
                f"{self.stats.new_cves} new, {self.stats.updated_cves} updated, "
                f"{self.stats.errors} errors in {self.stats.processing_time:.1f}s"
            )

        except Exception as e:
            logger.error(f"CVE synchronization failed: {e}")
            self.stats.errors += 1

        return self.stats

    def get_cve_by_id(self, cve_id: str) -> Optional[CVEData]:
        """Get specific CVE by ID from local database."""
        cves = self.query_cves()
        cve_matches = [cve for cve in cves if cve.cve_id == cve_id]
        return cve_matches[0] if cve_matches else None

    def get_database_stats(self) -> Dict[str, Any]:
        """Get statistics about the local CVE database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM cve_data")
                total_cves = cursor.fetchone()[0]

                cursor = conn.execute("SELECT COUNT(*) FROM cve_data WHERE severity = 'CRITICAL'")
                critical_cves = cursor.fetchone()[0]

                cursor = conn.execute("SELECT COUNT(*) FROM cve_data WHERE severity = 'HIGH'")
                high_cves = cursor.fetchone()[0]

                cursor = conn.execute("SELECT AVG(cvss_score) FROM cve_data WHERE cvss_score > 0")
                avg_score = cursor.fetchone()[0] or 0.0

                cursor = conn.execute("SELECT MAX(modified_date) FROM cve_data")
                last_updated = cursor.fetchone()[0]

                return {
                    "total_cves": total_cves,
                    "critical_cves": critical_cves,
                    "high_cves": high_cves,
                    "average_cvss_score": round(avg_score, 2),
                    "last_updated": last_updated,
                    "database_size_mb": (
                        Path(self.db_path).stat().st_size / (1024 * 1024) if Path(self.db_path).exists() else 0
                    ),
                }

        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}
