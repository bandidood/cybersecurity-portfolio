#!/usr/bin/env python3
"""
AlienVault OTX (Open Threat Exchange) Collector
Collects threat intelligence from AlienVault OTX platform
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IOC, IOCType, ThreatLevel, Confidence
from collectors.base_collector import BaseCollector


class OTXCollector(BaseCollector):
    """AlienVault OTX threat intelligence collector"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def _setup_authentication(self):
        """Setup OTX API key authentication"""
        self.session.headers.update({
            'X-OTX-API-KEY': self.feed.api_key
        })

    def fetch_iocs(self) -> List[IOC]:
        """Fetch IOCs from OTX pulses"""
        all_iocs = []

        # Fetch recent pulses
        pulses = self._fetch_pulses()

        for pulse in pulses:
            iocs = self._parse_pulse(pulse)
            all_iocs.extend(iocs)

        return self.deduplicate_iocs(all_iocs)

    def _fetch_pulses(self, limit: int = 50) -> List[Dict]:
        """Fetch recent OTX pulses"""
        url = f"{self.BASE_URL}/pulses/subscribed"
        params = {
            'limit': limit,
            'modified_since': (datetime.now() - timedelta(days=7)).isoformat()
        }

        try:
            response = self._make_request(url, params=params)
            if response:
                data = response.json()
                return data.get('results', [])
        except Exception as e:
            self.logger.error(f"Error fetching OTX pulses: {e}")

        return []

    def _parse_pulse(self, pulse: Dict) -> List[IOC]:
        """Parse a single OTX pulse into IOCs"""
        iocs = []

        pulse_name = pulse.get('name', 'Unknown')
        pulse_tags = pulse.get('tags', [])
        pulse_tlp = pulse.get('TLP', 'white')

        # Extract indicators
        indicators = pulse.get('indicators', [])

        for indicator in indicators:
            try:
                ioc = self._parse_indicator(indicator, pulse_name, pulse_tags, pulse_tlp)
                if ioc:
                    iocs.append(ioc)
            except Exception as e:
                self.logger.warning(f"Error parsing indicator: {e}")

        return iocs

    def _parse_indicator(self, indicator: Dict, pulse_name: str,
                        pulse_tags: List[str], tlp: str) -> IOC:
        """Parse a single indicator into IOC"""
        indicator_type = indicator.get('type', '')
        indicator_value = indicator.get('indicator', '')

        # Map OTX indicator type to IOCType
        ioc_type = self._map_indicator_type(indicator_type)

        # Determine threat level from pulse data
        threat_level = ThreatLevel.MEDIUM  # Default
        if 'critical' in pulse_name.lower() or 'critical' in pulse_tags:
            threat_level = ThreatLevel.CRITICAL
        elif 'high' in pulse_name.lower() or 'malware' in pulse_tags:
            threat_level = ThreatLevel.HIGH

        # Create IOC
        ioc = IOC(
            ioc_type=ioc_type,
            value=indicator_value,
            threat_level=threat_level,
            confidence=Confidence.MEDIUM,
            tags=pulse_tags + [f'tlp:{tlp}', 'otx'],
            description=f"From OTX pulse: {pulse_name}",
            context={
                'pulse_name': pulse_name,
                'pulse_id': indicator.get('pulse_key'),
                'otx_type': indicator_type,
                'tlp': tlp
            }
        )

        return self.enrich_ioc(ioc)

    def _map_indicator_type(self, otx_type: str) -> IOCType:
        """Map OTX indicator type to IOCType"""
        type_mapping = {
            'IPv4': IOCType.IP_ADDRESS,
            'IPv6': IOCType.IP_ADDRESS,
            'domain': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'URL': IOCType.URL,
            'FileHash-MD5': IOCType.FILE_HASH_MD5,
            'FileHash-SHA1': IOCType.FILE_HASH_SHA1,
            'FileHash-SHA256': IOCType.FILE_HASH_SHA256,
            'email': IOCType.EMAIL,
            'CVE': IOCType.CVE,
        }
        return type_mapping.get(otx_type, IOCType.IP_ADDRESS)

    def parse_response(self, response: Any) -> List[IOC]:
        """Parse OTX API response - not used in this implementation"""
        # Method required by base class but not used as we override fetch_iocs
        return []

    def get_pulse_details(self, pulse_id: str) -> Dict:
        """Get detailed information about a specific pulse"""
        url = f"{self.BASE_URL}/pulses/{pulse_id}"

        try:
            response = self._make_request(url)
            if response:
                return response.json()
        except Exception as e:
            self.logger.error(f"Error fetching pulse details: {e}")

        return {}

    def search_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """Search OTX for information about a specific IOC"""
        section_mapping = {
            'IPv4': 'general',
            'domain': 'general',
            'url': 'general',
            'file_hash': 'general',
        }

        section = section_mapping.get(ioc_type, 'general')
        url = f"{self.BASE_URL}/indicators/{ioc_type}/{ioc_value}/{section}"

        try:
            response = self._make_request(url)
            if response:
                return response.json()
        except Exception as e:
            self.logger.error(f"Error searching IOC: {e}")

        return {}
