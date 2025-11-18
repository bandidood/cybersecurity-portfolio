#!/usr/bin/env python3
"""
AbuseIPDB Collector
Collects IP reputation data from AbuseIPDB
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IOC, IOCType, ThreatLevel, Confidence
from collectors.base_collector import BaseCollector


class AbuseIPDBCollector(BaseCollector):
    """AbuseIPDB threat intelligence collector"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def _setup_authentication(self):
        """Setup AbuseIPDB API key authentication"""
        self.session.headers.update({
            'Key': self.feed.api_key,
            'Accept': 'application/json'
        })

    def fetch_iocs(self) -> List[IOC]:
        """Fetch malicious IPs from AbuseIPDB"""
        all_iocs = []

        # Fetch blacklisted IPs
        blacklist = self._fetch_blacklist()
        all_iocs.extend(blacklist)

        return self.deduplicate_iocs(all_iocs)

    def _fetch_blacklist(self, confidence_minimum: int = 90, limit: int = 10000) -> List[IOC]:
        """Fetch blacklisted IPs from AbuseIPDB"""
        url = f"{self.BASE_URL}/blacklist"
        params = {
            'confidenceMinimum': confidence_minimum,
            'limit': limit
        }

        iocs = []

        try:
            response = self._make_request(url, params=params)
            if response:
                data = response.json()
                blacklist_data = data.get('data', [])

                for entry in blacklist_data:
                    ioc = self._parse_blacklist_entry(entry)
                    if ioc:
                        iocs.append(ioc)

        except Exception as e:
            self.logger.error(f"Error fetching AbuseIPDB blacklist: {e}")

        return iocs

    def _parse_blacklist_entry(self, entry: Dict) -> Optional[IOC]:
        """Parse a blacklist entry into IOC"""
        ip_address = entry.get('ipAddress')
        if not ip_address:
            return None

        abuse_confidence_score = entry.get('abuseConfidenceScore', 0)
        country_code = entry.get('countryCode')
        usage_type = entry.get('usageType')
        isp = entry.get('isp')

        # Determine threat level based on abuse score
        if abuse_confidence_score >= 90:
            threat_level = ThreatLevel.CRITICAL
        elif abuse_confidence_score >= 75:
            threat_level = ThreatLevel.HIGH
        elif abuse_confidence_score >= 50:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        # Determine confidence
        if abuse_confidence_score >= 95:
            confidence = Confidence.CONFIRMED
        elif abuse_confidence_score >= 85:
            confidence = Confidence.HIGH
        elif abuse_confidence_score >= 70:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        ioc = IOC(
            ioc_type=IOCType.IP_ADDRESS,
            value=ip_address,
            threat_level=threat_level,
            confidence=confidence,
            tags=['abuseipdb', 'malicious-ip', usage_type or 'unknown'],
            description=f"Malicious IP reported to AbuseIPDB (Score: {abuse_confidence_score})",
            context={
                'abuse_confidence_score': abuse_confidence_score,
                'country': country_code,
                'isp': isp,
                'usage_type': usage_type,
                'source': 'abuseipdb'
            }
        )

        return self.enrich_ioc(ioc)

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict:
        """Check a specific IP address in AbuseIPDB"""
        url = f"{self.BASE_URL}/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days,
            'verbose': True
        }

        try:
            response = self._make_request(url, params=params)
            if response:
                data = response.json()
                return data.get('data', {})
        except Exception as e:
            self.logger.error(f"Error checking IP {ip_address}: {e}")

        return {}

    def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> bool:
        """Report an IP address to AbuseIPDB"""
        url = f"{self.BASE_URL}/report"
        data = {
            'ip': ip_address,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }

        try:
            response = self.session.post(url, data=data)
            response.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Error reporting IP {ip_address}: {e}")
            return False

    def parse_response(self, response) -> List[IOC]:
        """Parse AbuseIPDB API response"""
        # Method required by base class but not used in this implementation
        return []


# AbuseIPDB Report Categories
ABUSEIPDB_CATEGORIES = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}
