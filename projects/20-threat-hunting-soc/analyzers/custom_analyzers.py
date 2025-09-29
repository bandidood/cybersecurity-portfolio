#!/usr/bin/env python3
"""
Custom Cortex Analyzers for SOC Platform
Advanced threat intelligence and forensic analysis capabilities
Author: SOC Team
Version: 1.0.0
"""

import json
import logging
import hashlib
import requests
import base64
import time
import os
import re
import socket
import dns.resolver
import whois
import yara
import magic
import ssdeep
import pefile
import zipfile
import tarfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod
from urllib.parse import urlparse
import geoip2.database
import geoip2.errors
from virus_total_apis import PublicApi as VirusTotalPublicApi
import shodan
import requests_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import subprocess
import sqlite3
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class AnalyzerResult:
    """Standard analyzer result format"""
    success: bool
    summary: Dict[str, Any]
    full_details: Dict[str, Any]
    artifacts: List[Dict[str, Any]]
    taxonomies: List[Dict[str, Any]]
    level: str  # info, safe, suspicious, malicious
    namespace: str
    predicate: str
    value: str

class BaseAnalyzer(ABC):
    """Base class for custom analyzers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.version = "1.0"
        self.author = "SOC Team"
        
    @abstractmethod
    async def run(self, observable_type: str, observable_value: str) -> AnalyzerResult:
        """Execute the analyzer"""
        pass
    
    def _create_taxonomy(self, level: str, namespace: str, predicate: str, value: str) -> Dict[str, Any]:
        """Create taxonomy entry"""
        return {
            "level": level,
            "namespace": namespace,
            "predicate": predicate,
            "value": value
        }
    
    def _create_artifact(self, data_type: str, data: str, message: str = "", tags: List[str] = None) -> Dict[str, Any]:
        """Create artifact entry"""
        return {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tags": tags or []
        }

class ThreatIntelligenceAggregator(BaseAnalyzer):
    """Advanced threat intelligence aggregator from multiple sources"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.vt_api = VirusTotalPublicApi(config.get('virustotal_key', ''))
        self.shodan_api = shodan.Shodan(config.get('shodan_key', ''))
        self.session = requests_cache.CachedSession('threat_intel_cache', expire_after=3600)
        
        # Initialize threat intelligence feeds
        self.ti_feeds = {
            'malwaredomainlist': 'http://www.malwaredomainlist.com/hostslist/ip.txt',
            'emergingthreats': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
            'alienvault': 'https://reputation.alienvault.com/reputation.generic',
            'abuse_ch': 'https://urlhaus.abuse.ch/downloads/hostfile/',
            'spamhaus': 'https://www.spamhaus.org/drop/drop.txt'
        }
        
        self._initialize_local_intelligence()
    
    def _initialize_local_intelligence(self):
        """Initialize local threat intelligence database"""
        db_path = self.config.get('ti_db_path', '/opt/cortex/data/threat_intel.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_type TEXT,
                confidence INTEGER,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                tags TEXT,
                UNIQUE(indicator_type, indicator_value, source)
            )
        ''')
        self.conn.commit()
    
    async def run(self, observable_type: str, observable_value: str) -> AnalyzerResult:
        """Aggregate threat intelligence from multiple sources"""
        logger.info(f"Running threat intelligence analysis for {observable_type}: {observable_value}")
        
        results = {}
        artifacts = []
        taxonomies = []
        
        try:
            # Check local threat intelligence database
            local_intel = self._check_local_intelligence(observable_type, observable_value)
            if local_intel:
                results['local_intelligence'] = local_intel
                taxonomies.append(self._create_taxonomy(
                    "malicious" if local_intel['threat_level'] == 'high' else "suspicious",
                    "TI",
                    "LocalIntel",
                    f"{len(local_intel['matches'])} matches"
                ))
            
            # VirusTotal analysis
            if observable_type in ['ip', 'domain', 'hash']:
                vt_result = await self._analyze_virustotal(observable_type, observable_value)
                if vt_result:
                    results['virustotal'] = vt_result
                    if vt_result.get('positives', 0) > 0:
                        taxonomies.append(self._create_taxonomy(
                            "malicious" if vt_result['positives'] > 5 else "suspicious",
                            "VT",
                            "Detection",
                            f"{vt_result['positives']}/{vt_result['total']}"
                        ))
            
            # Shodan analysis for IPs
            if observable_type == 'ip':
                shodan_result = await self._analyze_shodan(observable_value)
                if shodan_result:
                    results['shodan'] = shodan_result
                    if shodan_result.get('ports'):
                        taxonomies.append(self._create_taxonomy(
                            "info",
                            "Shodan",
                            "OpenPorts",
                            f"{len(shodan_result['ports'])} ports"
                        ))
            
            # Multiple TI feed checks
            feed_results = await self._check_ti_feeds(observable_type, observable_value)
            if feed_results:
                results['threat_feeds'] = feed_results
                malicious_sources = [f for f in feed_results if feed_results[f].get('found', False)]
                if malicious_sources:
                    taxonomies.append(self._create_taxonomy(
                        "malicious",
                        "TI",
                        "Feeds",
                        f"{len(malicious_sources)} sources"
                    ))
            
            # WHOIS analysis for domains/IPs
            if observable_type in ['ip', 'domain']:
                whois_result = await self._analyze_whois(observable_value)
                if whois_result:
                    results['whois'] = whois_result
                    # Check for suspicious registration patterns
                    if self._is_suspicious_whois(whois_result):
                        taxonomies.append(self._create_taxonomy(
                            "suspicious",
                            "WHOIS",
                            "Suspicious",
                            "Suspicious registration"
                        ))
            
            # DNS analysis for domains
            if observable_type == 'domain':
                dns_result = await self._analyze_dns(observable_value)
                if dns_result:
                    results['dns'] = dns_result
                    # Extract IP artifacts
                    for record_type, records in dns_result.items():
                        if isinstance(records, list):
                            for record in records:
                                if self._is_valid_ip(record):
                                    artifacts.append(self._create_artifact(
                                        "ip", record, f"DNS {record_type} record", ["dns", "extracted"]
                                    ))
            
            # Geolocation analysis
            if observable_type == 'ip':
                geo_result = await self._analyze_geolocation(observable_value)
                if geo_result:
                    results['geolocation'] = geo_result
                    # Flag suspicious countries
                    if geo_result.get('country_code') in self.config.get('suspicious_countries', ['CN', 'RU', 'IR', 'KP']):
                        taxonomies.append(self._create_taxonomy(
                            "suspicious",
                            "GEO",
                            "Country",
                            f"{geo_result.get('country_name', 'Unknown')}"
                        ))
            
            # Historical analysis
            historical_data = await self._get_historical_data(observable_type, observable_value)
            if historical_data:
                results['historical'] = historical_data
            
            # Calculate overall threat score
            threat_score = self._calculate_threat_score(results)
            results['threat_score'] = threat_score
            
            # Determine overall level
            if threat_score >= 80:
                level = "malicious"
            elif threat_score >= 50:
                level = "suspicious"
            elif threat_score >= 20:
                level = "safe"
            else:
                level = "info"
            
            return AnalyzerResult(
                success=True,
                summary={
                    "threat_score": threat_score,
                    "total_sources": len([k for k in results.keys() if k != 'threat_score']),
                    "malicious_sources": len([k for k in results.keys() if 'malicious' in str(results.get(k, {}))]),
                    "level": level
                },
                full_details=results,
                artifacts=artifacts,
                taxonomies=taxonomies,
                level=level,
                namespace="TI",
                predicate="Score",
                value=str(threat_score)
            )
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {e}")
            return AnalyzerResult(
                success=False,
                summary={"error": str(e)},
                full_details={},
                artifacts=[],
                taxonomies=[],
                level="info",
                namespace="TI",
                predicate="Error",
                value="Analysis failed"
            )
    
    def _check_local_intelligence(self, indicator_type: str, indicator_value: str) -> Optional[Dict]:
        """Check local threat intelligence database"""
        cursor = self.conn.execute(
            "SELECT * FROM threat_indicators WHERE indicator_type = ? AND indicator_value = ?",
            (indicator_type, indicator_value)
        )
        
        matches = cursor.fetchall()
        if matches:
            return {
                "found": True,
                "matches": len(matches),
                "sources": [match[3] for match in matches],  # source column
                "threat_level": "high" if any(match[5] >= 80 for match in matches) else "medium",  # confidence column
                "last_seen": max(match[7] for match in matches)  # last_seen column
            }
        
        return None
    
    async def _analyze_virustotal(self, observable_type: str, observable_value: str) -> Optional[Dict]:
        """Analyze using VirusTotal API"""
        try:
            if observable_type == 'ip':
                response = self.vt_api.get_ip_report(observable_value)
            elif observable_type == 'domain':
                response = self.vt_api.get_domain_report(observable_value)
            elif observable_type == 'hash':
                response = self.vt_api.get_file_report(observable_value)
            else:
                return None
            
            if response['response_code'] == 200:
                return response['results']
            
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
        
        return None
    
    async def _analyze_shodan(self, ip: str) -> Optional[Dict]:
        """Analyze IP using Shodan"""
        try:
            host = self.shodan_api.host(ip)
            return {
                "org": host.get('org', ''),
                "os": host.get('os', ''),
                "ports": host.get('ports', []),
                "services": [
                    {
                        "port": service.get('port'),
                        "product": service.get('product', ''),
                        "version": service.get('version', ''),
                        "banner": service.get('data', '')[:200]  # Truncate banner
                    }
                    for service in host.get('data', [])
                ],
                "country": host.get('country_name', ''),
                "city": host.get('city', ''),
                "last_update": host.get('last_update', '')
            }
        except Exception as e:
            logger.error(f"Shodan analysis failed: {e}")
        
        return None
    
    async def _check_ti_feeds(self, observable_type: str, observable_value: str) -> Dict:
        """Check multiple threat intelligence feeds"""
        results = {}
        
        for feed_name, feed_url in self.ti_feeds.items():
            try:
                response = self.session.get(feed_url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    found = observable_value in content
                    results[feed_name] = {
                        "found": found,
                        "last_checked": datetime.utcnow().isoformat()
                    }
            except Exception as e:
                logger.error(f"Failed to check {feed_name}: {e}")
                results[feed_name] = {"error": str(e)}
        
        return results
    
    def _calculate_threat_score(self, results: Dict) -> int:
        """Calculate overall threat score based on all sources"""
        score = 0
        
        # VirusTotal scoring
        vt = results.get('virustotal', {})
        if vt.get('positives', 0) > 0:
            score += min(vt['positives'] * 10, 50)  # Max 50 points from VT
        
        # Local intelligence scoring
        local = results.get('local_intelligence', {})
        if local.get('found', False):
            if local.get('threat_level') == 'high':
                score += 30
            else:
                score += 20
        
        # Threat feeds scoring
        feeds = results.get('threat_feeds', {})
        malicious_feeds = len([f for f in feeds if feeds[f].get('found', False)])
        score += malicious_feeds * 15  # 15 points per malicious feed
        
        # WHOIS suspicious patterns
        whois_data = results.get('whois', {})
        if whois_data and self._is_suspicious_whois(whois_data):
            score += 10
        
        # Geographic risk
        geo = results.get('geolocation', {})
        if geo and geo.get('country_code') in self.config.get('high_risk_countries', ['CN', 'RU', 'IR', 'KP']):
            score += 15
        
        return min(score, 100)  # Cap at 100
    
    def _is_suspicious_whois(self, whois_data: Dict) -> bool:
        """Check for suspicious WHOIS patterns"""
        suspicious_indicators = [
            # Recently registered domains
            whois_data.get('creation_date', datetime.now()) > datetime.now() - timedelta(days=30),
            
            # Privacy protection services
            any(privacy in str(whois_data.get('registrar', '')).lower() 
                for privacy in ['privacy', 'protection', 'whoisguard']),
            
            # Suspicious TLDs
            any(tld in whois_data.get('domain_name', '') 
                for tld in ['.tk', '.ml', '.ga', '.cf', '.top']),
        ]
        
        return any(suspicious_indicators)
    
    async def _analyze_whois(self, target: str) -> Optional[Dict]:
        """WHOIS analysis"""
        try:
            w = whois.whois(target)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "status": w.status,
                "country": w.country
            }
        except Exception as e:
            logger.error(f"WHOIS analysis failed: {e}")
        
        return None
    
    async def _analyze_dns(self, domain: str) -> Optional[Dict]:
        """DNS analysis"""
        try:
            resolver = dns.resolver.Resolver()
            results = {}
            
            # Query different record types
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = resolver.resolve(domain, record_type)
                    results[record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
            
            return results
        except Exception as e:
            logger.error(f"DNS analysis failed: {e}")
        
        return None
    
    async def _analyze_geolocation(self, ip: str) -> Optional[Dict]:
        """Geolocation analysis"""
        try:
            geoip_db_path = self.config.get('geoip_db_path', '/opt/cortex/data/GeoLite2-City.mmdb')
            if os.path.exists(geoip_db_path):
                with geoip2.database.Reader(geoip_db_path) as reader:
                    response = reader.city(ip)
                    return {
                        "country_name": response.country.name,
                        "country_code": response.country.iso_code,
                        "city": response.city.name,
                        "latitude": float(response.location.latitude or 0),
                        "longitude": float(response.location.longitude or 0),
                        "accuracy_radius": response.location.accuracy_radius,
                        "timezone": response.location.time_zone,
                        "isp": response.traits.isp if hasattr(response.traits, 'isp') else None
                    }
        except Exception as e:
            logger.error(f"Geolocation analysis failed: {e}")
        
        return None
    
    async def _get_historical_data(self, observable_type: str, observable_value: str) -> Optional[Dict]:
        """Get historical data for the observable"""
        try:
            cursor = self.conn.execute(
                "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM threat_indicators WHERE indicator_type = ? AND indicator_value = ?",
                (observable_type, observable_value)
            )
            
            result = cursor.fetchone()
            if result and result[0] > 0:
                return {
                    "total_reports": result[0],
                    "first_seen": result[1],
                    "last_seen": result[2]
                }
        except Exception as e:
            logger.error(f"Historical data query failed: {e}")
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

class AdvancedMalwareAnalyzer(BaseAnalyzer):
    """Advanced malware analysis with static and dynamic capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.yara_rules_path = config.get('yara_rules_path', '/opt/cortex/data/yara-rules')
        self.sandbox_url = config.get('sandbox_url', '')
        self.sandbox_key = config.get('sandbox_key', '')
        self.max_file_size = config.get('max_file_size', 100 * 1024 * 1024)  # 100MB
        
        # Load YARA rules
        self._load_yara_rules()
    
    def _load_yara_rules(self):
        """Load YARA rules from directory"""
        try:
            if os.path.exists(self.yara_rules_path):
                rule_files = []
                for root, dirs, files in os.walk(self.yara_rules_path):
                    for file in files:
                        if file.endswith('.yar') or file.endswith('.yara'):
                            rule_files.append(os.path.join(root, file))
                
                if rule_files:
                    rules_dict = {}
                    for i, rule_file in enumerate(rule_files):
                        with open(rule_file, 'r') as f:
                            rules_dict[f'rule_{i}'] = f.read()
                    
                    self.yara_rules = yara.compile(sources=rules_dict)
                    logger.info(f"Loaded {len(rule_files)} YARA rule files")
                else:
                    self.yara_rules = None
            else:
                self.yara_rules = None
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None
    
    async def run(self, observable_type: str, observable_value: str) -> AnalyzerResult:
        """Perform advanced malware analysis"""
        logger.info(f"Running advanced malware analysis for {observable_type}: {observable_value}")
        
        if observable_type not in ['file', 'hash']:
            return AnalyzerResult(
                success=False,
                summary={"error": "Unsupported observable type"},
                full_details={},
                artifacts=[],
                taxonomies=[],
                level="info",
                namespace="Malware",
                predicate="Error",
                value="Unsupported type"
            )
        
        results = {}
        artifacts = []
        taxonomies = []
        
        try:
            # Get file path or download by hash
            file_path = None
            if observable_type == 'file':
                file_path = observable_value
            elif observable_type == 'hash':
                file_path = await self._download_by_hash(observable_value)
            
            if not file_path or not os.path.exists(file_path):
                raise Exception("File not accessible")
            
            # File size check
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                raise Exception(f"File too large: {file_size} bytes")
            
            # Basic file information
            file_info = await self._analyze_file_info(file_path)
            results['file_info'] = file_info
            
            # Hash analysis
            hashes = await self._calculate_hashes(file_path)
            results['hashes'] = hashes
            
            # Magic number analysis
            file_type = await self._analyze_file_type(file_path)
            results['file_type'] = file_type
            
            # Entropy analysis
            entropy = await self._calculate_entropy(file_path)
            results['entropy'] = entropy
            
            # Fuzzy hashing (ssdeep)
            fuzzy_hash = await self._calculate_fuzzy_hash(file_path)
            if fuzzy_hash:
                results['fuzzy_hash'] = fuzzy_hash
            
            # YARA analysis
            if self.yara_rules:
                yara_matches = await self._yara_scan(file_path)
                if yara_matches:
                    results['yara'] = yara_matches
                    taxonomies.append(self._create_taxonomy(
                        "malicious" if any('malware' in match['rule'].lower() for match in yara_matches) else "suspicious",
                        "YARA",
                        "Matches",
                        f"{len(yara_matches)} rules"
                    ))
            
            # PE analysis (if applicable)
            if file_type and 'PE' in file_type.get('mime_type', ''):
                pe_analysis = await self._analyze_pe_file(file_path)
                if pe_analysis:
                    results['pe_analysis'] = pe_analysis
                    
                    # Check for suspicious imports
                    if pe_analysis.get('suspicious_imports'):
                        taxonomies.append(self._create_taxonomy(
                            "suspicious",
                            "PE",
                            "Imports",
                            f"{len(pe_analysis['suspicious_imports'])} suspicious"
                        ))
            
            # String analysis
            strings_analysis = await self._analyze_strings(file_path)
            results['strings'] = strings_analysis
            
            # Extract IoCs from strings
            iocs = self._extract_iocs_from_strings(strings_analysis.get('strings', []))
            if iocs:
                results['extracted_iocs'] = iocs
                for ioc in iocs:
                    artifacts.append(self._create_artifact(
                        ioc['type'], ioc['value'], f"Extracted from malware strings", ["extracted", "ioc"]
                    ))
            
            # Archive analysis
            if file_type and any(archive_type in file_type.get('mime_type', '') 
                               for archive_type in ['zip', 'rar', 'tar', 'gzip']):
                archive_analysis = await self._analyze_archive(file_path)
                if archive_analysis:
                    results['archive'] = archive_analysis
            
            # Dynamic sandbox analysis (if available)
            if self.sandbox_url:
                sandbox_analysis = await self._sandbox_analysis(file_path, hashes['sha256'])
                if sandbox_analysis:
                    results['sandbox'] = sandbox_analysis
            
            # Calculate malware confidence score
            confidence_score = self._calculate_malware_confidence(results)
            results['confidence_score'] = confidence_score
            
            # Determine threat level
            if confidence_score >= 80:
                level = "malicious"
            elif confidence_score >= 50:
                level = "suspicious"
            else:
                level = "info"
            
            return AnalyzerResult(
                success=True,
                summary={
                    "file_size": file_size,
                    "file_type": file_type.get('description', 'Unknown') if file_type else 'Unknown',
                    "entropy": entropy,
                    "yara_matches": len(results.get('yara', [])),
                    "confidence_score": confidence_score,
                    "extracted_iocs": len(iocs) if iocs else 0
                },
                full_details=results,
                artifacts=artifacts,
                taxonomies=taxonomies,
                level=level,
                namespace="Malware",
                predicate="Confidence",
                value=f"{confidence_score}%"
            )
            
        except Exception as e:
            logger.error(f"Malware analysis failed: {e}")
            return AnalyzerResult(
                success=False,
                summary={"error": str(e)},
                full_details={},
                artifacts=[],
                taxonomies=[],
                level="info",
                namespace="Malware",
                predicate="Error",
                value="Analysis failed"
            )
    
    async def _download_by_hash(self, hash_value: str) -> Optional[str]:
        """Download file by hash from various sources"""
        # This would integrate with malware repositories like VirusTotal, MalShare, etc.
        # For now, check local malware repository
        malware_repo = self.config.get('malware_repo_path', '/opt/cortex/data/malware-samples')
        potential_path = os.path.join(malware_repo, hash_value)
        
        if os.path.exists(potential_path):
            return potential_path
        
        # Could add integration with VirusTotal download API here
        return None
    
    async def _analyze_file_info(self, file_path: str) -> Dict:
        """Basic file information analysis"""
        stat = os.stat(file_path)
        return {
            "size": stat.st_size,
            "creation_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modification_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "access_time": datetime.fromtimestamp(stat.st_atime).isoformat()
        }
    
    async def _calculate_hashes(self, file_path: str) -> Dict:
        """Calculate various hashes"""
        hashes = {}
        
        with open(file_path, 'rb') as f:
            content = f.read()
            
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['sha512'] = hashlib.sha512(content).hexdigest()
        
        return hashes
    
    async def _analyze_file_type(self, file_path: str) -> Dict:
        """Analyze file type using magic numbers"""
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            
            desc = magic.Magic()
            description = desc.from_file(file_path)
            
            return {
                "mime_type": mime_type,
                "description": description
            }
        except Exception as e:
            logger.error(f"File type analysis failed: {e}")
            return {}
    
    async def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return 0.0
            
            # Calculate byte frequency
            frequency = {}
            for byte in data:
                frequency[byte] = frequency.get(byte, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            length = len(data)
            
            for count in frequency.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
        except Exception as e:
            logger.error(f"Entropy calculation failed: {e}")
            return 0.0
    
    async def _calculate_fuzzy_hash(self, file_path: str) -> Optional[str]:
        """Calculate fuzzy hash using ssdeep"""
        try:
            return ssdeep.hash_from_file(file_path)
        except Exception as e:
            logger.error(f"Fuzzy hash calculation failed: {e}")
            return None
    
    async def _yara_scan(self, file_path: str) -> List[Dict]:
        """Scan file with YARA rules"""
        try:
            matches = self.yara_rules.match(file_path)
            results = []
            
            for match in matches:
                result = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": []
                }
                
                for string in match.strings:
                    result["strings"].append({
                        "identifier": string.identifier,
                        "instances": [
                            {
                                "offset": instance.offset,
                                "length": instance.length,
                                "matched_data": instance.matched_data[:100].decode('utf-8', errors='ignore')  # Truncate
                            }
                            for instance in string.instances[:10]  # Limit instances
                        ]
                    })
                
                results.append(result)
            
            return results
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return []
    
    async def _analyze_pe_file(self, file_path: str) -> Optional[Dict]:
        """Analyze PE file structure"""
        try:
            pe = pefile.PE(file_path)
            
            # Basic PE info
            result = {
                "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "characteristics": pe.FILE_HEADER.Characteristics,
                "sections": [],
                "imports": {},
                "exports": [],
                "suspicious_imports": []
            }
            
            # Section analysis
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics,
                    "entropy": section.get_entropy()
                }
                result["sections"].append(section_info)
            
            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                suspicious_apis = [
                    'CreateFile', 'WriteFile', 'RegSetValue', 'RegCreateKey',
                    'CreateProcess', 'VirtualAlloc', 'LoadLibrary', 'GetProcAddress',
                    'CryptEncrypt', 'CryptDecrypt', 'InternetOpen', 'InternetConnect',
                    'HttpOpenRequest', 'HttpSendRequest', 'WinExec', 'ShellExecute'
                ]
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            imports.append(api_name)
                            
                            if api_name in suspicious_apis:
                                result["suspicious_imports"].append({
                                    "dll": dll_name,
                                    "api": api_name
                                })
                    
                    result["imports"][dll_name] = imports
            
            # Export analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            
            pe.close()
            return result
            
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return None
    
    async def _analyze_strings(self, file_path: str, min_length: int = 4) -> Dict:
        """Extract and analyze strings from file"""
        try:
            strings = []
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_strings = re.findall(b'[\x20-\x7e]{' + str(min_length).encode() + b',}', data)
            strings.extend([s.decode('ascii') for s in ascii_strings])
            
            # Extract Unicode strings
            unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}', data)
            strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])
            
            # Analyze string patterns
            urls = [s for s in strings if re.match(r'https?://', s)]
            ips = [s for s in strings if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)]
            emails = [s for s in strings if re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', s)]
            registry_keys = [s for s in strings if 'HKEY_' in s.upper()]
            file_paths = [s for s in strings if re.match(r'[A-Za-z]:\\', s)]
            
            return {
                "total_strings": len(strings),
                "strings": strings[:1000],  # Limit to first 1000 strings
                "urls": urls,
                "ips": ips,
                "emails": emails,
                "registry_keys": registry_keys,
                "file_paths": file_paths
            }
        except Exception as e:
            logger.error(f"String analysis failed: {e}")
            return {"error": str(e)}
    
    def _extract_iocs_from_strings(self, strings: List[str]) -> List[Dict]:
        """Extract IoCs from strings"""
        iocs = []
        
        for string in strings:
            # IP addresses
            ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', string)
            for ip in ip_matches:
                iocs.append({"type": "ip", "value": ip})
            
            # Domain names
            domain_matches = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', string)
            for domain in domain_matches:
                if '.' in domain and not domain.replace('.', '').isdigit():
                    iocs.append({"type": "domain", "value": domain})
            
            # URLs
            url_matches = re.findall(r'https?://[^\s<>"\']+', string)
            for url in url_matches:
                iocs.append({"type": "url", "value": url})
            
            # Email addresses
            email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', string)
            for email in email_matches:
                iocs.append({"type": "email", "value": email})
        
        # Remove duplicates
        unique_iocs = []
        seen = set()
        for ioc in iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
    
    async def _analyze_archive(self, file_path: str) -> Dict:
        """Analyze archive files"""
        try:
            result = {
                "files": [],
                "total_files": 0,
                "compressed_size": os.path.getsize(file_path),
                "suspicious_files": []
            }
            
            # ZIP analysis
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for info in zf.infolist():
                        file_info = {
                            "filename": info.filename,
                            "compressed_size": info.compress_size,
                            "uncompressed_size": info.file_size,
                            "compression_type": info.compress_type
                        }
                        result["files"].append(file_info)
                        
                        # Check for suspicious files
                        if info.filename.endswith(('.exe', '.bat', '.cmd', '.scr', '.pif')):
                            result["suspicious_files"].append(info.filename)
                
                result["total_files"] = len(result["files"])
            
            # TAR analysis
            elif tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, 'r') as tf:
                    for member in tf.getmembers():
                        if member.isfile():
                            file_info = {
                                "filename": member.name,
                                "size": member.size,
                                "mode": oct(member.mode)
                            }
                            result["files"].append(file_info)
                            
                            # Check for suspicious files
                            if member.name.endswith(('.exe', '.bat', '.cmd', '.scr', '.pif')):
                                result["suspicious_files"].append(member.name)
                
                result["total_files"] = len(result["files"])
            
            return result
        except Exception as e:
            logger.error(f"Archive analysis failed: {e}")
            return {"error": str(e)}
    
    async def _sandbox_analysis(self, file_path: str, file_hash: str) -> Optional[Dict]:
        """Submit to sandbox for dynamic analysis"""
        try:
            # This would integrate with sandboxes like Cuckoo, Joe Sandbox, etc.
            # For now, return mock result
            return {
                "sandbox": "mock_sandbox",
                "status": "completed",
                "score": 75,
                "behavior": {
                    "network_connections": 5,
                    "file_operations": 12,
                    "registry_operations": 8,
                    "process_created": 2
                },
                "signatures": [
                    {"name": "suspicious_network_activity", "severity": "medium"},
                    {"name": "file_manipulation", "severity": "low"}
                ]
            }
        except Exception as e:
            logger.error(f"Sandbox analysis failed: {e}")
            return None
    
    def _calculate_malware_confidence(self, results: Dict) -> int:
        """Calculate malware confidence score"""
        score = 0
        
        # YARA matches
        yara_matches = results.get('yara', [])
        if yara_matches:
            malware_rules = [match for match in yara_matches if 'malware' in match.get('rule', '').lower()]
            score += len(malware_rules) * 20
            score += (len(yara_matches) - len(malware_rules)) * 10
        
        # High entropy (packed/encrypted)
        entropy = results.get('entropy', 0)
        if entropy > 7.5:
            score += 15
        elif entropy > 7.0:
            score += 10
        
        # PE suspicious imports
        pe_analysis = results.get('pe_analysis', {})
        suspicious_imports = pe_analysis.get('suspicious_imports', [])
        score += len(suspicious_imports) * 5
        
        # Suspicious strings/IoCs
        extracted_iocs = results.get('extracted_iocs', [])
        score += len(extracted_iocs) * 3
        
        # Archive with suspicious files
        archive = results.get('archive', {})
        suspicious_archive_files = archive.get('suspicious_files', [])
        score += len(suspicious_archive_files) * 10
        
        # Sandbox score
        sandbox = results.get('sandbox', {})
        if sandbox and sandbox.get('score', 0) > 50:
            score += 20
        
        return min(score, 100)

class NetworkForensicsAnalyzer(BaseAnalyzer):
    """Advanced network forensics and traffic analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.pcap_tools = config.get('pcap_tools_path', '/usr/bin')
        self.max_pcap_size = config.get('max_pcap_size', 500 * 1024 * 1024)  # 500MB
    
    async def run(self, observable_type: str, observable_value: str) -> AnalyzerResult:
        """Perform network forensics analysis"""
        logger.info(f"Running network forensics analysis for {observable_type}: {observable_value}")
        
        if observable_type != 'file':
            return AnalyzerResult(
                success=False,
                summary={"error": "Only PCAP files supported"},
                full_details={},
                artifacts=[],
                taxonomies=[],
                level="info",
                namespace="NetForensics",
                predicate="Error",
                value="Unsupported type"
            )
        
        results = {}
        artifacts = []
        taxonomies = []
        
        try:
            pcap_path = observable_value
            if not os.path.exists(pcap_path):
                raise Exception("PCAP file not found")
            
            # Check file size
            file_size = os.path.getsize(pcap_path)
            if file_size > self.max_pcap_size:
                raise Exception(f"PCAP file too large: {file_size} bytes")
            
            # Basic PCAP analysis
            basic_analysis = await self._analyze_pcap_basic(pcap_path)
            results['basic'] = basic_analysis
            
            # Protocol analysis
            protocol_analysis = await self._analyze_protocols(pcap_path)
            results['protocols'] = protocol_analysis
            
            # Flow analysis
            flow_analysis = await self._analyze_flows(pcap_path)
            results['flows'] = flow_analysis
            
            # Extract artifacts
            extracted_artifacts = await self._extract_network_artifacts(pcap_path)
            results['extracted'] = extracted_artifacts
            
            # Add extracted IPs and domains as artifacts
            if extracted_artifacts.get('unique_ips'):
                for ip in extracted_artifacts['unique_ips'][:50]:  # Limit to 50
                    artifacts.append(self._create_artifact("ip", ip, "Extracted from PCAP", ["extracted"]))
            
            if extracted_artifacts.get('dns_queries'):
                for domain in list(set(extracted_artifacts['dns_queries']))[:50]:  # Limit to 50 unique
                    artifacts.append(self._create_artifact("domain", domain, "DNS query from PCAP", ["extracted", "dns"]))
            
            # Suspicious activity detection
            suspicious_activity = await self._detect_suspicious_activity(results)
            results['suspicious'] = suspicious_activity
            
            # Create taxonomies based on findings
            if suspicious_activity.get('total_suspicious', 0) > 0:
                taxonomies.append(self._create_taxonomy(
                    "suspicious",
                    "NetForensics",
                    "SuspiciousActivity",
                    f"{suspicious_activity['total_suspicious']} indicators"
                ))
            
            if protocol_analysis.get('encrypted_traffic_ratio', 0) > 0.8:
                taxonomies.append(self._create_taxonomy(
                    "info",
                    "NetForensics",
                    "Encryption",
                    f"{protocol_analysis['encrypted_traffic_ratio']:.1%} encrypted"
                ))
            
            return AnalyzerResult(
                success=True,
                summary={
                    "file_size": file_size,
                    "total_packets": basic_analysis.get('total_packets', 0),
                    "unique_ips": len(extracted_artifacts.get('unique_ips', [])),
                    "protocols": len(protocol_analysis.get('protocols', {})),
                    "suspicious_indicators": suspicious_activity.get('total_suspicious', 0)
                },
                full_details=results,
                artifacts=artifacts,
                taxonomies=taxonomies,
                level="suspicious" if suspicious_activity.get('total_suspicious', 0) > 0 else "info",
                namespace="NetForensics",
                predicate="Analysis",
                value="Complete"
            )
            
        except Exception as e:
            logger.error(f"Network forensics analysis failed: {e}")
            return AnalyzerResult(
                success=False,
                summary={"error": str(e)},
                full_details={},
                artifacts=[],
                taxonomies=[],
                level="info",
                namespace="NetForensics",
                predicate="Error",
                value="Analysis failed"
            )
    
    async def _analyze_pcap_basic(self, pcap_path: str) -> Dict:
        """Basic PCAP file analysis using tshark"""
        try:
            # Get basic statistics
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-q', '-z', 'io,stat,0'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                raise Exception(f"tshark failed: {result.stderr}")
            
            # Parse output for basic stats
            stats = self._parse_tshark_stats(result.stdout)
            
            return stats
        except Exception as e:
            logger.error(f"Basic PCAP analysis failed: {e}")
            return {"error": str(e)}
    
    async def _analyze_protocols(self, pcap_path: str) -> Dict:
        """Analyze protocol distribution"""
        try:
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-q', '-z', 'io,phs'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                raise Exception(f"tshark protocol analysis failed: {result.stderr}")
            
            protocols = self._parse_protocol_hierarchy(result.stdout)
            
            # Calculate encrypted traffic ratio
            encrypted_protocols = ['tls', 'ssl', 'https', 'ssh', 'ipsec']
            encrypted_count = sum(protocols.get(proto, 0) for proto in encrypted_protocols)
            total_count = sum(protocols.values())
            encrypted_ratio = encrypted_count / total_count if total_count > 0 else 0
            
            return {
                "protocols": protocols,
                "total_packets": total_count,
                "encrypted_traffic_ratio": encrypted_ratio
            }
        except Exception as e:
            logger.error(f"Protocol analysis failed: {e}")
            return {"error": str(e)}
    
    async def _analyze_flows(self, pcap_path: str) -> Dict:
        """Analyze network flows"""
        try:
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-e', 'frame.len'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                raise Exception(f"tshark flow analysis failed: {result.stderr}")
            
            flows = self._parse_flow_data(result.stdout)
            
            return flows
        except Exception as e:
            logger.error(f"Flow analysis failed: {e}")
            return {"error": str(e)}
    
    async def _extract_network_artifacts(self, pcap_path: str) -> Dict:
        """Extract network artifacts from PCAP"""
        try:
            artifacts = {
                "unique_ips": set(),
                "dns_queries": [],
                "http_hosts": [],
                "user_agents": [],
                "suspicious_ports": []
            }
            
            # Extract unique IPs
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        ips = line.split('\t')
                        for ip in ips:
                            if ip and ip != '':
                                artifacts["unique_ips"].add(ip)
            
            # Extract DNS queries
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'dns.qry.name',
                '-Y', 'dns.flags.response == 0'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and line != '':
                        artifacts["dns_queries"].append(line)
            
            # Extract HTTP hosts
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'http.host',
                '-Y', 'http.host'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and line != '':
                        artifacts["http_hosts"].append(line)
            
            # Extract User-Agents
            cmd = [
                os.path.join(self.pcap_tools, 'tshark'),
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'http.user_agent',
                '-Y', 'http.user_agent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and line != '':
                        artifacts["user_agents"].append(line)
            
            # Convert sets to lists for JSON serialization
            artifacts["unique_ips"] = list(artifacts["unique_ips"])
            
            return artifacts
        except Exception as e:
            logger.error(f"Artifact extraction failed: {e}")
            return {"error": str(e)}
    
    async def _detect_suspicious_activity(self, analysis_results: Dict) -> Dict:
        """Detect suspicious network activity patterns"""
        suspicious = {
            "indicators": [],
            "total_suspicious": 0
        }
        
        try:
            flows = analysis_results.get('flows', {})
            protocols = analysis_results.get('protocols', {})
            extracted = analysis_results.get('extracted', {})
            
            # Check for port scanning
            if flows.get('unique_destination_ports', 0) > 100:
                suspicious["indicators"].append({
                    "type": "port_scanning",
                    "description": f"High number of unique destination ports: {flows['unique_destination_ports']}",
                    "severity": "medium"
                })
            
            # Check for DNS tunneling
            dns_queries = extracted.get('dns_queries', [])
            long_dns_queries = [q for q in dns_queries if len(q) > 50]
            if len(long_dns_queries) > 10:
                suspicious["indicators"].append({
                    "type": "dns_tunneling",
                    "description": f"Suspicious long DNS queries: {len(long_dns_queries)}",
                    "severity": "high"
                })
            
            # Check for suspicious ports
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900, 6379]
            flows_data = flows.get('flows', [])
            for flow in flows_data:
                dst_port = flow.get('dst_port')
                if dst_port in suspicious_ports:
                    suspicious["indicators"].append({
                        "type": "suspicious_port",
                        "description": f"Connection to suspicious port {dst_port}",
                        "severity": "medium"
                    })
            
            # Check for data exfiltration patterns
            large_flows = [f for f in flows_data if f.get('total_bytes', 0) > 10000000]  # 10MB+
            if len(large_flows) > 5:
                suspicious["indicators"].append({
                    "type": "data_exfiltration",
                    "description": f"Large data transfers detected: {len(large_flows)} flows > 10MB",
                    "severity": "high"
                })
            
            suspicious["total_suspicious"] = len(suspicious["indicators"])
            
            return suspicious
        except Exception as e:
            logger.error(f"Suspicious activity detection failed: {e}")
            return {"error": str(e)}
    
    def _parse_tshark_stats(self, output: str) -> Dict:
        """Parse tshark statistics output"""
        stats = {}
        
        for line in output.split('\n'):
            if 'frames' in line.lower() and 'bytes' in line.lower():
                # Extract packet count and byte count
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        stats['total_packets'] = int(parts[0])
                        stats['total_bytes'] = int(parts[1])
                    except ValueError:
                        pass
        
        return stats
    
    def _parse_protocol_hierarchy(self, output: str) -> Dict:
        """Parse protocol hierarchy statistics"""
        protocols = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('=') and not line.startswith('Protocol'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        protocol_name = parts[0].lower()
                        packet_count = int(parts[1])
                        protocols[protocol_name] = packet_count
                    except (ValueError, IndexError):
                        pass
        
        return protocols
    
    def _parse_flow_data(self, output: str) -> Dict:
        """Parse flow data from tshark output"""
        flows = []
        unique_src_ips = set()
        unique_dst_ips = set()
        unique_dst_ports = set()
        
        for line in output.strip().split('\n'):
            if line:
                parts = line.split('\t')
                if len(parts) >= 7:
                    src_ip, dst_ip, tcp_src, tcp_dst, udp_src, udp_dst, frame_len = parts
                    
                    if src_ip:
                        unique_src_ips.add(src_ip)
                    if dst_ip:
                        unique_dst_ips.add(dst_ip)
                    
                    dst_port = tcp_dst or udp_dst
                    if dst_port:
                        try:
                            unique_dst_ports.add(int(dst_port))
                        except ValueError:
                            pass
                    
                    try:
                        flows.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": int(dst_port) if dst_port else None,
                            "frame_len": int(frame_len) if frame_len else 0
                        })
                    except ValueError:
                        pass
        
        return {
            "flows": flows[:1000],  # Limit to first 1000 flows
            "total_flows": len(flows),
            "unique_src_ips": len(unique_src_ips),
            "unique_dst_ips": len(unique_dst_ips),
            "unique_destination_ports": len(unique_dst_ports)
        }

# Factory function to create analyzers
def create_analyzer(analyzer_name: str, config: Dict[str, Any]) -> BaseAnalyzer:
    """Factory function to create analyzer instances"""
    analyzers = {
        'ThreatIntelligenceAggregator': ThreatIntelligenceAggregator,
        'AdvancedMalwareAnalyzer': AdvancedMalwareAnalyzer,
        'NetworkForensicsAnalyzer': NetworkForensicsAnalyzer
    }
    
    if analyzer_name not in analyzers:
        raise ValueError(f"Unknown analyzer: {analyzer_name}")
    
    return analyzers[analyzer_name](config)

# Main execution function for testing
async def main():
    """Test the analyzers"""
    config = {
        'virustotal_key': 'test-key',
        'shodan_key': 'test-key',
        'geoip_db_path': '/opt/cortex/data/GeoLite2-City.mmdb',
        'yara_rules_path': '/opt/cortex/data/yara-rules',
        'pcap_tools_path': '/usr/bin'
    }
    
    # Test Threat Intelligence Aggregator
    ti_analyzer = create_analyzer('ThreatIntelligenceAggregator', config)
    result = await ti_analyzer.run('ip', '8.8.8.8')
    print(f"TI Analysis Result: {result.summary}")
    
    # Test Malware Analyzer
    # malware_analyzer = create_analyzer('AdvancedMalwareAnalyzer', config)
    # result = await malware_analyzer.run('hash', 'test-hash')
    # print(f"Malware Analysis Result: {result.summary}")

if __name__ == "__main__":
    asyncio.run(main())