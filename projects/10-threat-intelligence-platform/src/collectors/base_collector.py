#!/usr/bin/env python3
"""
Base Threat Feed Collector
Abstract base class for all threat intelligence collectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import requests
import logging
import time

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IOC, ThreatFeed, IOCType, ThreatLevel, Confidence


class BaseCollector(ABC):
    """Abstract base class for threat feed collectors"""

    def __init__(self, feed: ThreatFeed):
        self.feed = feed
        self.logger = logging.getLogger(f"{__class__.__name__}.{feed.feed_id}")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntelligencePlatform/1.0'
        })

        if feed.api_key:
            self._setup_authentication()

    @abstractmethod
    def _setup_authentication(self):
        """Setup authentication for the feed"""
        pass

    @abstractmethod
    def fetch_iocs(self) -> List[IOC]:
        """Fetch IOCs from the threat feed"""
        pass

    @abstractmethod
    def parse_response(self, response: Any) -> List[IOC]:
        """Parse API response into IOC objects"""
        pass

    def collect(self) -> List[IOC]:
        """Main collection method with error handling"""
        try:
            self.logger.info(f"Starting collection from {self.feed.name}")

            if not self.feed.needs_update():
                self.logger.info(f"Feed {self.feed.name} doesn't need update yet")
                return []

            iocs = self.fetch_iocs()

            # Update feed statistics
            self.feed.last_update = datetime.now()
            self.feed.next_update = datetime.now() + timedelta(seconds=self.feed.update_interval)
            self.feed.iocs_collected += len(iocs)
            self.feed.total_iocs = len(iocs)

            self.logger.info(f"Collected {len(iocs)} IOCs from {self.feed.name}")
            return iocs

        except Exception as e:
            self.logger.error(f"Error collecting from {self.feed.name}: {e}")
            self.feed.errors_count += 1
            self.feed.last_error = str(e)
            return []

    def _make_request(self, url: str, params: Optional[Dict] = None,
                      timeout: int = 30) -> Optional[requests.Response]:
        """Make HTTP request with retry logic"""
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=timeout)
                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                else:
                    raise

        return None

    def normalize_ioc_type(self, ioc_type_str: str) -> IOCType:
        """Normalize IOC type string to IOCType enum"""
        type_mapping = {
            'ip': IOCType.IP_ADDRESS,
            'ipv4': IOCType.IP_ADDRESS,
            'domain': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'url': IOCType.URL,
            'md5': IOCType.FILE_HASH_MD5,
            'sha1': IOCType.FILE_HASH_SHA1,
            'sha256': IOCType.FILE_HASH_SHA256,
            'email': IOCType.EMAIL,
            'cve': IOCType.CVE,
        }
        return type_mapping.get(ioc_type_str.lower(), IOCType.IP_ADDRESS)

    def normalize_threat_level(self, severity: str) -> ThreatLevel:
        """Normalize threat level string to ThreatLevel enum"""
        level_mapping = {
            'critical': ThreatLevel.CRITICAL,
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
            'info': ThreatLevel.INFO,
            'informational': ThreatLevel.INFO,
        }
        return level_mapping.get(severity.lower(), ThreatLevel.UNKNOWN)

    def calculate_confidence(self, sources_count: int, feed_reliability: float) -> Confidence:
        """Calculate confidence level based on multiple factors"""
        score = feed_reliability

        # Boost confidence based on number of sources
        if sources_count > 5:
            score += 0.3
        elif sources_count > 2:
            score += 0.2
        elif sources_count > 1:
            score += 0.1

        # Map to Confidence enum
        if score >= 0.9:
            return Confidence.CONFIRMED
        elif score >= 0.7:
            return Confidence.HIGH
        elif score >= 0.5:
            return Confidence.MEDIUM
        elif score >= 0.3:
            return Confidence.LOW
        else:
            return Confidence.UNCONFIRMED

    def deduplicate_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """Remove duplicate IOCs"""
        seen = set()
        unique_iocs = []

        for ioc in iocs:
            key = f"{ioc.ioc_type.value}:{ioc.value}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def enrich_ioc(self, ioc: IOC) -> IOC:
        """Enrich IOC with additional context"""
        # Add source feed info
        if self.feed.name not in ioc.sources:
            ioc.sources.append(self.feed.name)

        # Add feed tags
        for tag in self.feed.tags:
            if tag not in ioc.tags:
                ioc.tags.append(tag)

        # Update confidence based on feed reliability
        ioc.confidence = self.calculate_confidence(
            len(ioc.sources),
            self.feed.reliability_score
        )

        return ioc
