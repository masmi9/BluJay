#!/usr/bin/env python3
"""
AODS Threat Intelligence Processor
==================================

Full threat intelligence feed processing system providing real-time
threat data ingestion, analysis, and enrichment capabilities.

Features:
- Multi-format threat intelligence feed support (JSON, XML, CSV, STIX)
- Real-time feed processing and parsing
- Intelligence correlation with vulnerability data
- Source reliability scoring and validation
- Threat actor and campaign tracking
- IOC (Indicator of Compromise) processing
- MITRE ATT&CK framework integration
"""

import asyncio
import aiohttp
import logging
import json
import xml.etree.ElementTree as ET
from core.xml_safe import safe_fromstring as _safe_fromstring
import csv
import hashlib
import time
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import re

# Optional dependency - feedparser for RSS/Atom feeds
try:
    import feedparser

    FEEDPARSER_AVAILABLE = True
except ImportError:
    feedparser = None
    FEEDPARSER_AVAILABLE = False

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager, CacheType

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Threat type classification."""

    MALWARE = "malware"
    APT = "apt"
    VULNERABILITY = "vulnerability"
    IOC = "ioc"
    CAMPAIGN = "campaign"
    TECHNIQUE = "technique"
    ACTOR = "actor"
    INFRASTRUCTURE = "infrastructure"


class IOCType(Enum):
    """Indicator of Compromise type classification."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"


class FeedFormat(Enum):
    """Threat intelligence feed format."""

    JSON = "json"
    XML = "xml"
    CSV = "csv"
    RSS = "rss"
    STIX = "stix"
    PLAIN_TEXT = "plain_text"


@dataclass
class ThreatIntelligence:
    """Full threat intelligence record."""

    id: str
    source: str
    threat_type: ThreatType
    title: str
    description: str
    confidence: float  # 0.0 to 1.0
    severity: str
    published_date: datetime
    modified_date: datetime
    tlp_level: str = "WHITE"  # Traffic Light Protocol
    tags: List[str] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    affected_sectors: List[str] = field(default_factory=list)
    geographical_regions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        """Calculate risk score based on intelligence factors."""
        base_score = 5.0  # Neutral baseline

        # Confidence factor
        base_score *= self.confidence

        # Severity factor
        severity_multipliers = {"CRITICAL": 2.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.7, "INFO": 0.5}
        base_score *= severity_multipliers.get(self.severity.upper(), 1.0)

        # Recency factor
        age_days = (datetime.now(UTC) - self.published_date).days
        if age_days <= 7:
            base_score *= 1.3  # Recent threats are more relevant
        elif age_days <= 30:
            base_score *= 1.1
        elif age_days > 365:
            base_score *= 0.8  # Older threats are less relevant

        # IOC availability factor
        if self.iocs:
            base_score *= 1.2

        return min(10.0, max(0.0, base_score))


@dataclass
class FeedConfiguration:
    """Threat intelligence feed configuration."""

    feed_id: str
    name: str
    url: str
    format: FeedFormat
    enabled: bool = True
    update_interval: int = 3600  # seconds
    timeout: int = 60
    max_retry_attempts: int = 3
    authentication: Optional[Dict[str, str]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    filters: Dict[str, Any] = field(default_factory=dict)
    reliability_score: float = 1.0  # 0.0 to 1.0
    last_update: Optional[datetime] = None
    error_count: int = 0


class ThreatIntelligenceProcessor:
    """
    Advanced threat intelligence processing system.

    Provides full threat intelligence feed processing with support
    for multiple formats, real-time updates, and intelligent correlation.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize threat intelligence processor."""
        self.config = config or {}

        # Feed configurations
        self.feeds: Dict[str, FeedConfiguration] = {}

        # MIGRATED: Use unified cache manager; store intelligence via store/retrieve and keep local dict for fast access
        self.cache_manager = get_unified_cache_manager()
        self._cache_namespace = "threat_intel_processor"
        self.intelligence_cache: Dict[str, ThreatIntelligence] = {}

        # IOC database for fast lookups
        self.ioc_database: Dict[IOCType, Dict[str, List[str]]] = {ioc_type: {} for ioc_type in IOCType}

        # Feed processors by format
        self.format_processors = {
            FeedFormat.JSON: self._process_json_feed,
            FeedFormat.XML: self._process_xml_feed,
            FeedFormat.CSV: self._process_csv_feed,
            FeedFormat.RSS: self._process_rss_feed,
            FeedFormat.STIX: self._process_stix_feed,
            FeedFormat.PLAIN_TEXT: self._process_plain_text_feed,
        }

        # MITRE ATT&CK framework data
        self.mitre_techniques = self._load_mitre_techniques()

        # Performance metrics
        self.processing_stats = {
            "feeds_processed": 0,
            "intelligence_records": 0,
            "iocs_extracted": 0,
            "correlation_matches": 0,
            "processing_errors": 0,
        }

        logger.info("Threat Intelligence Processor initialized")

    def _load_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK technique mappings."""
        # This would typically load from a local file or database
        # For demo purposes, returning a subset
        return {
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters",
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion",
                "description": "Adversaries may inject code into processes",
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to dump credentials",
            },
        }

    def add_feed(self, feed_config: FeedConfiguration) -> None:
        """Add threat intelligence feed configuration."""
        self.feeds[feed_config.feed_id] = feed_config
        logger.info(f"Added threat intelligence feed: {feed_config.name}")

    def remove_feed(self, feed_id: str) -> bool:
        """Remove threat intelligence feed."""
        if feed_id in self.feeds:
            del self.feeds[feed_id]
            logger.info(f"Removed threat intelligence feed: {feed_id}")
            return True
        return False

    async def update_feed(self, feed_id: str) -> Dict[str, Any]:
        """Update threat intelligence from a specific feed."""
        if feed_id not in self.feeds:
            raise ValueError(f"Unknown feed: {feed_id}")

        feed_config = self.feeds[feed_id]

        if not feed_config.enabled:
            return {"status": "skipped", "reason": "Feed disabled"}

        logger.info(f"Updating threat intelligence feed: {feed_config.name}")

        result = {
            "feed_id": feed_id,
            "status": "success",
            "records_processed": 0,
            "iocs_extracted": 0,
            "errors": 0,
            "processing_time": 0,
        }

        start_time = time.time()

        try:
            # Fetch feed data
            feed_data = await self._fetch_feed_data(feed_config)

            # Process feed based on format
            processor = self.format_processors.get(feed_config.format)
            if not processor:
                raise ValueError(f"Unsupported feed format: {feed_config.format.value}")

            # Parse and process intelligence records
            intelligence_records = await processor(feed_data, feed_config)

            # Store and index intelligence
            for intel in intelligence_records:
                self._store_intelligence(intel)
                result["records_processed"] += 1
                result["iocs_extracted"] += len(intel.iocs)

            # Update feed status
            feed_config.last_update = datetime.now(UTC)
            feed_config.error_count = 0

            # Update performance stats
            self.processing_stats["feeds_processed"] += 1
            self.processing_stats["intelligence_records"] += result["records_processed"]
            self.processing_stats["iocs_extracted"] += result["iocs_extracted"]

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            result["errors"] = 1

            feed_config.error_count += 1
            self.processing_stats["processing_errors"] += 1

            logger.error(f"Failed to update feed {feed_id}: {e}")

        result["processing_time"] = time.time() - start_time
        return result

    async def _fetch_feed_data(self, feed_config: FeedConfiguration) -> Union[str, bytes]:
        """Fetch data from threat intelligence feed."""
        headers = feed_config.headers.copy()

        # Add authentication if configured
        if feed_config.authentication:
            auth_type = feed_config.authentication.get("type", "basic")
            if auth_type == "basic":
                import base64

                username = feed_config.authentication.get("username", "")
                password = feed_config.authentication.get("password", "")
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
            elif auth_type == "bearer":
                token = feed_config.authentication.get("token", "")
                headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "api_key":
                key_name = feed_config.authentication.get("key_name", "X-API-Key")
                api_key = feed_config.authentication.get("api_key", "")
                headers[key_name] = api_key

        # Add User-Agent if not specified
        if "User-Agent" not in headers:
            headers["User-Agent"] = "AODS-ThreatIntel/1.0"

        # Fetch data with retry logic
        for attempt in range(feed_config.max_retry_attempts):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        feed_config.url, headers=headers, timeout=aiohttp.ClientTimeout(total=feed_config.timeout)
                    ) as response:
                        if response.status == 200:
                            return await response.text()
                        else:
                            raise Exception(f"HTTP {response.status}: {response.reason}")

            except Exception as e:
                if attempt < feed_config.max_retry_attempts - 1:
                    wait_time = 2**attempt  # Exponential backoff
                    await asyncio.sleep(wait_time)
                    continue
                raise e

    async def _process_json_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process JSON format threat intelligence feed."""
        try:
            json_data = json.loads(data)

            intelligence_records = []

            # Handle different JSON structures
            if isinstance(json_data, list):
                items = json_data
            elif isinstance(json_data, dict):
                # Try common field names for data arrays
                items = json_data.get("data", json_data.get("indicators", json_data.get("objects", [json_data])))
            else:
                items = [json_data]

            for item in items:
                intel = self._parse_json_intelligence(item, feed_config)
                if intel:
                    intelligence_records.append(intel)

            return intelligence_records

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON feed {feed_config.feed_id}: {e}")
            return []

    def _parse_json_intelligence(
        self, item: Dict[str, Any], feed_config: FeedConfiguration
    ) -> Optional[ThreatIntelligence]:
        """Parse individual JSON intelligence record."""
        try:
            # Extract basic fields with flexible field mapping
            intel_id = item.get("id", item.get("uuid", str(hash(str(item)))))
            title = item.get("title", item.get("name", item.get("summary", "Unknown Threat")))
            description = item.get("description", item.get("details", ""))

            # Parse threat type
            threat_type_str = item.get("type", item.get("category", "unknown")).lower()
            threat_type = ThreatType.MALWARE  # Default
            for tt in ThreatType:
                if tt.value in threat_type_str:
                    threat_type = tt
                    break

            # Parse dates
            published_date = self._parse_date(item.get("published", item.get("created", item.get("timestamp"))))
            modified_date = self._parse_date(item.get("modified", item.get("updated", published_date)))

            # Parse confidence and severity
            confidence = float(item.get("confidence", item.get("score", 0.5)))
            if confidence > 1.0:
                confidence = confidence / 100.0  # Convert percentage to decimal

            severity = item.get("severity", item.get("priority", "MEDIUM")).upper()

            # Extract IOCs
            iocs = self._extract_iocs_from_json(item)

            # Extract MITRE techniques
            mitre_techniques = item.get("mitre_techniques", item.get("techniques", []))
            if isinstance(mitre_techniques, str):
                mitre_techniques = [mitre_techniques]

            # Extract tags
            tags = item.get("tags", item.get("labels", []))
            if isinstance(tags, str):
                tags = [tags]

            # Extract threat actors and campaigns
            threat_actors = item.get("threat_actors", item.get("actors", []))
            campaigns = item.get("campaigns", item.get("malware_families", []))

            # Extract references
            references = item.get("references", item.get("links", []))
            if isinstance(references, str):
                references = [references]

            return ThreatIntelligence(
                id=intel_id,
                source=feed_config.feed_id,
                threat_type=threat_type,
                title=title,
                description=description,
                confidence=confidence,
                severity=severity,
                published_date=published_date,
                modified_date=modified_date,
                tlp_level=item.get("tlp", "WHITE"),
                tags=tags,
                iocs=iocs,
                mitre_techniques=mitre_techniques,
                threat_actors=threat_actors,
                campaigns=campaigns,
                affected_sectors=item.get("sectors", []),
                geographical_regions=item.get("regions", []),
                references=references,
                raw_data=item,
            )

        except Exception as e:
            logger.error(f"Failed to parse JSON intelligence record: {e}")
            return None

    def _extract_iocs_from_json(self, item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from JSON intelligence record."""
        iocs = []

        # Direct IOC fields
        if "iocs" in item:
            ioc_data = item["iocs"]
            if isinstance(ioc_data, list):
                for ioc in ioc_data:
                    if isinstance(ioc, dict):
                        iocs.append(ioc)
                    else:
                        # Simple string IOC
                        ioc_type = self._detect_ioc_type(str(ioc))
                        if ioc_type:
                            iocs.append({"type": ioc_type.value, "value": str(ioc), "confidence": 0.8})

        # Search for IOCs in common fields
        ioc_fields = ["indicators", "observables", "artifacts"]
        for field in ioc_fields:  # noqa: F402
            if field in item:
                field_data = item[field]
                if isinstance(field_data, list):
                    for indicator in field_data:
                        if isinstance(indicator, dict):
                            ioc_type = indicator.get("type", "").lower()
                            value = indicator.get("value", indicator.get("indicator", ""))
                            if value:
                                iocs.append(
                                    {"type": ioc_type, "value": value, "confidence": indicator.get("confidence", 0.8)}
                                )

        # Extract IOCs from description using pattern matching
        description = item.get("description", "")
        if description:
            extracted_iocs = self._extract_iocs_from_text(description)
            iocs.extend(extracted_iocs)

        return iocs

    def _detect_ioc_type(self, value: str) -> Optional[IOCType]:
        """Detect IOC type from value using pattern matching."""
        value = value.strip()

        # IP Address
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ip_pattern, value):
            return IOCType.IP_ADDRESS

        # Domain
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, value):
            return IOCType.DOMAIN

        # URL
        if value.startswith(("http://", "https://", "ftp://")):
            return IOCType.URL

        # Email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, value):
            return IOCType.EMAIL

        # File Hash (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$", value):  # MD5
            return IOCType.FILE_HASH
        elif re.match(r"^[a-fA-F0-9]{40}$", value):  # SHA1
            return IOCType.FILE_HASH
        elif re.match(r"^[a-fA-F0-9]{64}$", value):  # SHA256
            return IOCType.FILE_HASH

        # Registry Key
        if value.startswith(("HKEY_", "HKLM\\", "HKCU\\", "HKCR\\")):
            return IOCType.REGISTRY_KEY

        # File Path
        if value.startswith(("C:\\", "/", "\\")) and ("." in value or "\\" in value):
            return IOCType.FILE_PATH

        return None

    def _extract_iocs_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract IOCs from text using pattern matching."""
        iocs = []

        # IP addresses
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        for match in re.finditer(ip_pattern, text):
            iocs.append({"type": IOCType.IP_ADDRESS.value, "value": match.group(), "confidence": 0.7})

        # Domains
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        for match in re.finditer(domain_pattern, text):
            domain = match.group()
            # Filter out common false positives
            dl = domain.lower()
            false_pos = {"example.com", "www.example.com", "localhost", "test.com"}
            if dl not in false_pos:
                iocs.append({"type": IOCType.DOMAIN.value, "value": domain, "confidence": 0.6})

        # File hashes
        hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
        for match in re.finditer(hash_pattern, text):
            hash_value = match.group()
            if len(hash_value) in [32, 40, 64]:  # MD5, SHA1, SHA256
                iocs.append({"type": IOCType.FILE_HASH.value, "value": hash_value, "confidence": 0.8})

        return iocs

    async def _process_xml_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process XML format threat intelligence feed."""
        try:
            root = _safe_fromstring(data)
            intelligence_records = []

            # Handle different XML structures
            for item in root.findall(".//item") or root.findall(".//entry") or [root]:
                intel = self._parse_xml_intelligence(item, feed_config)
                if intel:
                    intelligence_records.append(intel)

            return intelligence_records

        except ET.ParseError as e:
            logger.error(f"Failed to parse XML feed {feed_config.feed_id}: {e}")
            return []

    def _parse_xml_intelligence(self, item: ET.Element, feed_config: FeedConfiguration) -> Optional[ThreatIntelligence]:
        """Parse individual XML intelligence record."""
        try:
            # Extract text content with fallbacks
            def get_text(element, *tags):
                for tag in tags:
                    elem = element.find(tag)
                    if elem is not None and elem.text:
                        return elem.text.strip()
                return ""

            intel_id = get_text(item, "id", "guid", "uuid") or str(hash(ET.tostring(item)))
            title = get_text(item, "title", "name", "summary")
            description = get_text(item, "description", "content", "details")

            # Parse dates
            published_str = get_text(item, "published", "pubDate", "created")
            published_date = self._parse_date(published_str)
            modified_date = self._parse_date(get_text(item, "updated", "modified")) or published_date

            # Default values
            threat_type = ThreatType.MALWARE
            confidence = 0.5
            severity = "MEDIUM"

            return ThreatIntelligence(
                id=intel_id,
                source=feed_config.feed_id,
                threat_type=threat_type,
                title=title,
                description=description,
                confidence=confidence,
                severity=severity,
                published_date=published_date,
                modified_date=modified_date,
                iocs=self._extract_iocs_from_text(description),
                raw_data={"xml": ET.tostring(item, encoding="unicode")},
            )

        except Exception as e:
            logger.error(f"Failed to parse XML intelligence record: {e}")
            return None

    async def _process_csv_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process CSV format threat intelligence feed."""
        try:
            intelligence_records = []
            reader = csv.DictReader(data.splitlines())

            for row in reader:
                intel = self._parse_csv_intelligence(row, feed_config)
                if intel:
                    intelligence_records.append(intel)

            return intelligence_records

        except Exception as e:
            logger.error(f"Failed to parse CSV feed {feed_config.feed_id}: {e}")
            return []

    def _parse_csv_intelligence(
        self, row: Dict[str, str], feed_config: FeedConfiguration
    ) -> Optional[ThreatIntelligence]:
        """Parse individual CSV intelligence record."""
        try:
            # Map common CSV field names
            intel_id = row.get("id", row.get("uuid", str(hash(str(row)))))
            title = row.get("title", row.get("name", row.get("indicator", "Unknown Threat")))
            description = row.get("description", row.get("details", ""))

            # Parse dates
            published_date = self._parse_date(row.get("published", row.get("created")))
            modified_date = self._parse_date(row.get("modified", row.get("updated"))) or published_date

            # Parse confidence and severity
            confidence = float(row.get("confidence", "0.5"))
            severity = row.get("severity", "MEDIUM").upper()

            return ThreatIntelligence(
                id=intel_id,
                source=feed_config.feed_id,
                threat_type=ThreatType.IOC,  # CSV feeds typically contain IOCs
                title=title,
                description=description,
                confidence=confidence,
                severity=severity,
                published_date=published_date,
                modified_date=modified_date,
                iocs=self._extract_iocs_from_text(f"{title} {description}"),
                raw_data=row,
            )

        except Exception as e:
            logger.error(f"Failed to parse CSV intelligence record: {e}")
            return None

    async def _process_rss_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process RSS format threat intelligence feed."""
        if not FEEDPARSER_AVAILABLE:
            logger.warning("feedparser not available - RSS feed processing disabled")
            return []

        try:
            feed = feedparser.parse(data)
            intelligence_records = []

            for entry in feed.entries:
                intel = self._parse_rss_intelligence(entry, feed_config)
                if intel:
                    intelligence_records.append(intel)

            return intelligence_records

        except Exception as e:
            logger.error(f"Failed to parse RSS feed {feed_config.feed_id}: {e}")
            return []

    def _parse_rss_intelligence(self, entry: Any, feed_config: FeedConfiguration) -> Optional[ThreatIntelligence]:
        """Parse individual RSS intelligence record."""
        try:
            intel_id = getattr(entry, "id", getattr(entry, "guid", str(hash(str(entry)))))
            title = getattr(entry, "title", "Unknown Threat")
            description = getattr(entry, "description", getattr(entry, "summary", ""))

            # Parse date
            published_date = self._parse_date(getattr(entry, "published", getattr(entry, "updated", None)))

            return ThreatIntelligence(
                id=intel_id,
                source=feed_config.feed_id,
                threat_type=ThreatType.IOC,
                title=title,
                description=description,
                confidence=0.6,  # RSS feeds typically have moderate confidence
                severity="MEDIUM",
                published_date=published_date,
                modified_date=published_date,
                iocs=self._extract_iocs_from_text(f"{title} {description}"),
                references=[getattr(entry, "link", "")],
                raw_data=dict(entry),
            )

        except Exception as e:
            logger.error(f"Failed to parse RSS intelligence record: {e}")
            return None

    async def _process_stix_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process STIX format threat intelligence feed."""
        # STIX processing would require specialized libraries
        # For demo purposes, treating as JSON
        return await self._process_json_feed(data, feed_config)

    async def _process_plain_text_feed(self, data: str, feed_config: FeedConfiguration) -> List[ThreatIntelligence]:
        """Process plain text format threat intelligence feed."""
        try:
            # Extract IOCs from plain text
            iocs = self._extract_iocs_from_text(data)

            if not iocs:
                return []

            # Create intelligence record from extracted IOCs
            intel_id = hashlib.sha256(data.encode()).hexdigest()[:16]

            return [
                ThreatIntelligence(
                    id=intel_id,
                    source=feed_config.feed_id,
                    threat_type=ThreatType.IOC,
                    title=f"IOC Feed from {feed_config.name}",
                    description="IOCs extracted from plain text feed",
                    confidence=0.7,
                    severity="MEDIUM",
                    published_date=datetime.now(UTC),
                    modified_date=datetime.now(UTC),
                    iocs=iocs,
                    raw_data={"text": data},
                )
            ]

        except Exception as e:
            logger.error(f"Failed to parse plain text feed {feed_config.feed_id}: {e}")
            return []

    def _parse_date(self, date_str: Optional[str]) -> datetime:
        """Parse date string with multiple format support."""
        if not date_str:
            return datetime.now(UTC)

        # Common date formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%d-%m-%Y",
            "%Y/%m/%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        # Fallback to current time
        logger.warning(f"Could not parse date: {date_str}")
        return datetime.now(UTC)

    def _store_intelligence(self, intel: ThreatIntelligence) -> None:
        """Store threat intelligence and update IOC database."""
        # Store intelligence record (local + unified)
        self.intelligence_cache[intel.id] = intel
        try:
            self.cache_manager.store(
                f"{self._cache_namespace}:{intel.id}",
                intel,
                CacheType.GENERAL,
                ttl_hours=24,
                tags=[self._cache_namespace],
            )
        except Exception:
            pass

        # Index IOCs for fast lookup
        for ioc in intel.iocs:
            ioc_type_str = ioc.get("type", "").lower()
            ioc_value = ioc.get("value", "")

            if not ioc_value:
                continue

            # Find matching IOC type
            ioc_type = None
            for iot in IOCType:
                if iot.value == ioc_type_str:
                    ioc_type = iot
                    break

            if not ioc_type:
                ioc_type = self._detect_ioc_type(ioc_value)

            if ioc_type:
                if ioc_value not in self.ioc_database[ioc_type]:
                    self.ioc_database[ioc_type][ioc_value] = []
                self.ioc_database[ioc_type][ioc_value].append(intel.id)

    def lookup_ioc(self, ioc_value: str, ioc_type: Optional[IOCType] = None) -> List[ThreatIntelligence]:
        """Lookup threat intelligence by IOC value."""
        matching_intel = []

        if ioc_type:
            ioc_types = [ioc_type]
        else:
            # Auto-detect IOC type
            detected_type = self._detect_ioc_type(ioc_value)
            ioc_types = [detected_type] if detected_type else list(IOCType)

        for iot in ioc_types:
            if ioc_value in self.ioc_database[iot]:
                for intel_id in self.ioc_database[iot][ioc_value]:
                    if intel_id in self.intelligence_cache:
                        matching_intel.append(self.intelligence_cache[intel_id])

        return matching_intel

    def search_intelligence(
        self,
        query: str,
        threat_types: Optional[List[ThreatType]] = None,
        min_confidence: float = 0.0,
        max_age_days: Optional[int] = None,
    ) -> List[ThreatIntelligence]:
        """Search threat intelligence records."""
        matching_intel = []
        cutoff_date = None

        if max_age_days:
            cutoff_date = datetime.now(UTC) - timedelta(days=max_age_days)

        for intel in self.intelligence_cache.values():
            # Check threat type filter
            if threat_types and intel.threat_type not in threat_types:
                continue

            # Check confidence filter
            if intel.confidence < min_confidence:
                continue

            # Check age filter
            if cutoff_date and intel.published_date < cutoff_date:
                continue

            # Check query match
            query_lower = query.lower()
            if (
                query_lower in intel.title.lower()
                or query_lower in intel.description.lower()
                or any(query_lower in tag.lower() for tag in intel.tags)
            ):
                matching_intel.append(intel)

        # Sort by relevance (confidence * recency)
        matching_intel.sort(
            key=lambda x: x.confidence * (1.0 / max(1, (datetime.now(UTC) - x.published_date).days)), reverse=True
        )

        return matching_intel

    async def update_all_feeds(self) -> Dict[str, Any]:
        """Update all enabled threat intelligence feeds."""
        results = {}

        # Get feeds that need updating
        feeds_to_update = []
        current_time = datetime.now(UTC)

        for feed_id, feed_config in self.feeds.items():
            if not feed_config.enabled:
                continue

            if not feed_config.last_update or current_time >= feed_config.last_update + timedelta(
                seconds=feed_config.update_interval
            ):
                feeds_to_update.append(feed_id)

        logger.info(f"Updating {len(feeds_to_update)} threat intelligence feeds")

        # Update feeds concurrently
        update_tasks = [self.update_feed(feed_id) for feed_id in feeds_to_update]

        if update_tasks:
            feed_results = await asyncio.gather(*update_tasks, return_exceptions=True)

            for i, result in enumerate(feed_results):
                feed_id = feeds_to_update[i]
                if isinstance(result, Exception):
                    results[feed_id] = {"status": "error", "error": str(result)}
                else:
                    results[feed_id] = result

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence processing statistics."""
        stats = self.processing_stats.copy()

        # Add current cache statistics
        stats["cached_intelligence"] = len(self.intelligence_cache)
        stats["indexed_iocs"] = sum(len(iocs) for iocs in self.ioc_database.values())

        # Feed statistics
        stats["total_feeds"] = len(self.feeds)
        stats["enabled_feeds"] = sum(1 for feed in self.feeds.values() if feed.enabled)

        # IOC type distribution
        stats["ioc_distribution"] = {ioc_type.value: len(iocs) for ioc_type, iocs in self.ioc_database.items()}

        return stats
