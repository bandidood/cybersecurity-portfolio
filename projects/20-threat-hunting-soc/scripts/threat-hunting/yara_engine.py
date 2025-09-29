#!/usr/bin/env python3
"""
YARA Pattern Matching Engine
Advanced malware detection and analysis using YARA rules.

Author: SOC Team
Version: 1.0.0
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import yara
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import magic

logger = logging.getLogger(__name__)

class YaraRuleManager:
    """Advanced YARA rule manager with categorization and compilation."""
    
    def __init__(self, rules_directory: str = "rules/yara"):
        """Initialize YARA rule manager."""
        self.rules_directory = Path(rules_directory)
        self.compiled_rules = None
        self.rule_categories = {}
        self.rule_metadata = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Initialize rule categories
        self._init_rule_categories()
        
    def _init_rule_categories(self):
        """Initialize rule categories for organized detection."""
        self.rule_categories = {
            'apt': {
                'description': 'Advanced Persistent Threat indicators',
                'severity': 'high',
                'families': ['apt1', 'apt28', 'apt29', 'lazarus', 'carbanak']
            },
            'ransomware': {
                'description': 'Ransomware family detection',
                'severity': 'critical',
                'families': ['wannacry', 'petya', 'ryuk', 'maze', 'sodinokibi']
            },
            'banking': {
                'description': 'Banking trojans and financial malware',
                'severity': 'high',
                'families': ['emotet', 'trickbot', 'qakbot', 'zeus', 'dridex']
            },
            'backdoor': {
                'description': 'Backdoor and remote access tools',
                'severity': 'high',
                'families': ['cobalt_strike', 'meterpreter', 'poison_ivy', 'njrat']
            },
            'exploit': {
                'description': 'Exploit kits and vulnerability exploitation',
                'severity': 'high',
                'families': ['metasploit', 'exploit_kit', 'cve_exploit']
            },
            'webshell': {
                'description': 'Web shells and web-based backdoors',
                'severity': 'medium',
                'families': ['c99', 'r57', 'weevely', 'china_chopper']
            },
            'cryptominer': {
                'description': 'Cryptocurrency mining malware',
                'severity': 'medium',
                'families': ['monero_miner', 'coinhive', 'xmrig']
            },
            'pua': {
                'description': 'Potentially unwanted applications',
                'severity': 'low',
                'families': ['adware', 'spyware', 'riskware']
            },
            'tools': {
                'description': 'Hacking tools and utilities',
                'severity': 'medium',
                'families': ['mimikatz', 'psexec', 'winrar_sfx', 'password_dump']
            }
        }
    
    async def compile_rules(self, force_recompile: bool = False) -> bool:
        """Compile all YARA rules from directory."""
        if self.compiled_rules and not force_recompile:
            return True
        
        if not self.rules_directory.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_directory}")
            return False
        
        try:
            # Find all YARA rule files
            rule_files = list(self.rules_directory.rglob("*.yar")) + \
                        list(self.rules_directory.rglob("*.yara"))
            
            if not rule_files:
                logger.warning("No YARA rule files found")
                return False
            
            # Prepare filepaths dictionary
            filepaths = {}
            rule_count = 0
            
            for rule_file in rule_files:
                try:
                    # Validate rule file
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract metadata from rule file
                    metadata = self._extract_rule_metadata(content)
                    category = self._categorize_rule(rule_file, metadata)
                    
                    rule_key = f"rule_{rule_count}"
                    filepaths[rule_key] = str(rule_file)
                    
                    self.rule_metadata[rule_key] = {
                        'file_path': str(rule_file),
                        'category': category,
                        'metadata': metadata,
                        'rule_names': self._extract_rule_names(content)
                    }
                    
                    rule_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to process YARA rule {rule_file}: {e}")
                    continue
            
            # Compile rules
            logger.info(f"Compiling {len(filepaths)} YARA rule files...")
            self.compiled_rules = yara.compile(filepaths=filepaths)
            
            logger.info(f"Successfully compiled {rule_count} YARA rule files")
            return True
            
        except Exception as e:
            logger.error(f"YARA rule compilation failed: {e}")
            return False
    
    def _extract_rule_metadata(self, content: str) -> Dict[str, Any]:
        """Extract metadata from YARA rule content."""
        metadata = {
            'author': 'Unknown',
            'description': '',
            'date': '',
            'version': '',
            'reference': [],
            'hash': [],
            'mitre_attack': []
        }
        
        lines = content.split('\n')
        in_meta = False
        
        for line in lines:
            line = line.strip()
            
            if 'meta:' in line:
                in_meta = True
                continue
            elif in_meta and (line.startswith('strings:') or line.startswith('condition:')):
                in_meta = False
                continue
            elif in_meta and '=' in line:
                try:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    if key in metadata:
                        if isinstance(metadata[key], list):
                            metadata[key].append(value)
                        else:
                            metadata[key] = value
                except:
                    continue
        
        return metadata
    
    def _extract_rule_names(self, content: str) -> List[str]:
        """Extract rule names from YARA content."""
        rule_names = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('rule '):
                try:
                    rule_name = line.split()[1]
                    if rule_name.endswith(':'):
                        rule_name = rule_name[:-1]
                    rule_names.append(rule_name)
                except:
                    continue
        
        return rule_names
    
    def _categorize_rule(self, rule_file: Path, metadata: Dict) -> str:
        """Categorize rule based on file path and metadata."""
        file_path = str(rule_file).lower()
        description = metadata.get('description', '').lower()
        
        # Check file path for category indicators
        for category in self.rule_categories:
            if category in file_path:
                return category
            
            # Check families
            families = self.rule_categories[category]['families']
            for family in families:
                if family in file_path or family in description:
                    return category
        
        # Default categorization
        if 'malware' in file_path or 'trojan' in file_path:
            return 'banking'
        elif 'hack' in file_path or 'tool' in file_path:
            return 'tools'
        else:
            return 'pua'
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about compiled rules."""
        if not self.rule_metadata:
            return {}
        
        stats = {
            'total_files': len(self.rule_metadata),
            'total_rules': sum(len(meta['rule_names']) for meta in self.rule_metadata.values()),
            'by_category': {},
            'authors': set(),
            'dates': []
        }
        
        for rule_info in self.rule_metadata.values():
            category = rule_info['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + len(rule_info['rule_names'])
            
            metadata = rule_info['metadata']
            if metadata.get('author') and metadata['author'] != 'Unknown':
                stats['authors'].add(metadata['author'])
            if metadata.get('date'):
                stats['dates'].append(metadata['date'])
        
        stats['authors'] = list(stats['authors'])
        
        return stats

class YaraScanner:
    """Advanced YARA scanner with multi-threading and analysis features."""
    
    def __init__(self, rule_manager: YaraRuleManager):
        """Initialize YARA scanner."""
        self.rule_manager = rule_manager
        self.scan_results = []
        self.executor = ThreadPoolExecutor(max_workers=8)
    
    async def scan_file(self, file_path: str, timeout: int = 60) -> Dict[str, Any]:
        """Scan individual file with YARA rules."""
        if not self.rule_manager.compiled_rules:
            return {'error': 'YARA rules not compiled'}
        
        file_path_obj = Path(file_path)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            return {'error': 'File not found'}
        
        try:
            # Get file information
            file_info = await self._get_file_info(file_path_obj)
            
            # Skip large files (>100MB by default)
            if file_info['size'] > 100 * 1024 * 1024:
                return {
                    'file_path': str(file_path_obj),
                    'file_info': file_info,
                    'matches': [],
                    'skipped': True,
                    'reason': 'File too large'
                }
            
            # Perform YARA scan
            loop = asyncio.get_event_loop()
            matches = await loop.run_in_executor(
                self.executor,
                self._scan_file_sync,
                str(file_path_obj),
                timeout
            )
            
            # Process matches
            processed_matches = []
            for match in matches:
                match_info = self._process_yara_match(match, file_info)
                processed_matches.append(match_info)
            
            result = {
                'file_path': str(file_path_obj),
                'file_info': file_info,
                'matches': processed_matches,
                'match_count': len(processed_matches),
                'scan_time': datetime.utcnow().isoformat(),
                'threat_level': self._assess_threat_level(processed_matches)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"YARA scan failed for {file_path}: {e}")
            return {
                'file_path': str(file_path_obj),
                'error': str(e)
            }
    
    async def scan_directory(self, directory_path: str, recursive: bool = True, 
                           extensions: List[str] = None, max_files: int = 1000) -> List[Dict]:
        """Scan directory with YARA rules."""
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            logger.error(f"Directory not found: {directory_path}")
            return []
        
        # Find files to scan
        files_to_scan = []
        
        if recursive:
            file_pattern = "**/*"
        else:
            file_pattern = "*"
        
        for file_path in directory.glob(file_pattern):
            if not file_path.is_file():
                continue
            
            # Filter by extensions if specified
            if extensions and file_path.suffix.lower() not in extensions:
                continue
            
            files_to_scan.append(file_path)
            
            if len(files_to_scan) >= max_files:
                break
        
        logger.info(f"Scanning {len(files_to_scan)} files in {directory_path}")
        
        # Scan files concurrently
        tasks = []
        for file_path in files_to_scan:
            task = asyncio.create_task(self.scan_file(str(file_path)))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and empty results
        valid_results = []
        for result in results:
            if isinstance(result, dict) and not result.get('error'):
                valid_results.append(result)
        
        logger.info(f"Directory scan completed: {len(valid_results)} files scanned")
        return valid_results
    
    async def scan_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Scan memory dump with YARA rules."""
        return await self.scan_file(dump_path)
    
    async def scan_network_capture(self, pcap_path: str) -> Dict[str, Any]:
        """Scan network capture file for malicious patterns."""
        # For now, treat as regular file scan
        # Could be enhanced to extract specific network artifacts
        return await self.scan_file(pcap_path)
    
    def _scan_file_sync(self, file_path: str, timeout: int) -> List:
        """Synchronous YARA file scan for thread executor."""
        try:
            matches = self.rule_manager.compiled_rules.match(
                file_path,
                timeout=timeout
            )
            return matches
        except Exception as e:
            logger.error(f"Sync YARA scan failed for {file_path}: {e}")
            return []
    
    async def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get comprehensive file information."""
        try:
            stat = file_path.stat()
            
            # Calculate file hashes
            loop = asyncio.get_event_loop()
            hashes = await loop.run_in_executor(
                self.executor,
                self._calculate_hashes,
                str(file_path)
            )
            
            # Get file type
            try:
                mime_type = magic.from_file(str(file_path), mime=True)
                file_type = magic.from_file(str(file_path))
            except:
                mime_type = 'unknown'
                file_type = 'unknown'
            
            info = {
                'name': file_path.name,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'mime_type': mime_type,
                'file_type': file_type,
                'extension': file_path.suffix.lower(),
                **hashes
            }
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get file info for {file_path}: {e}")
            return {'error': str(e)}
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes (MD5, SHA1, SHA256)."""
        try:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                while chunk := f.read(8192):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return {
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest()
            }
            
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
            return {
                'md5': 'error',
                'sha1': 'error',
                'sha256': 'error'
            }
    
    def _process_yara_match(self, match, file_info: Dict) -> Dict[str, Any]:
        """Process individual YARA match result."""
        try:
            # Find rule metadata
            rule_meta = None
            for rule_key, meta in self.rule_manager.rule_metadata.items():
                if match.rule in meta['rule_names']:
                    rule_meta = meta
                    break
            
            match_info = {
                'rule_name': match.rule,
                'tags': list(match.tags),
                'namespace': match.namespace,
                'category': rule_meta['category'] if rule_meta else 'unknown',
                'metadata': rule_meta['metadata'] if rule_meta else {},
                'strings': []
            }
            
            # Process matched strings
            for string in match.strings:
                string_info = {
                    'identifier': string.identifier,
                    'instances': []
                }
                
                for instance in string.instances:
                    # Limit matched data length and sanitize
                    matched_data = instance.matched_data
                    if len(matched_data) > 100:
                        matched_data = matched_data[:100]
                    
                    try:
                        matched_str = matched_data.decode('utf-8', errors='replace')
                    except:
                        matched_str = str(matched_data)
                    
                    instance_info = {
                        'offset': instance.offset,
                        'matched_data': matched_str,
                        'matched_length': instance.matched_length
                    }
                    string_info['instances'].append(instance_info)
                
                match_info['strings'].append(string_info)
            
            return match_info
            
        except Exception as e:
            logger.error(f"Failed to process YARA match: {e}")
            return {
                'rule_name': match.rule if hasattr(match, 'rule') else 'unknown',
                'error': str(e)
            }
    
    def _assess_threat_level(self, matches: List[Dict]) -> str:
        """Assess threat level based on YARA matches."""
        if not matches:
            return 'clean'
        
        # Count matches by category
        category_counts = {}
        for match in matches:
            category = match.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Assess threat level
        critical_categories = ['ransomware', 'apt']
        high_categories = ['banking', 'backdoor', 'exploit']
        medium_categories = ['webshell', 'tools']
        
        for category in critical_categories:
            if category in category_counts:
                return 'critical'
        
        for category in high_categories:
            if category in category_counts:
                return 'high'
        
        for category in medium_categories:
            if category in category_counts:
                return 'medium'
        
        return 'low'
    
    async def generate_scan_report(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive scan report."""
        if not scan_results:
            return {'message': 'No scan results to report'}
        
        report = {
            'scan_summary': {
                'total_files': len(scan_results),
                'clean_files': 0,
                'infected_files': 0,
                'suspicious_files': 0,
                'errors': 0
            },
            'threat_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'clean': 0
            },
            'top_threats': [],
            'file_types': {},
            'scan_timestamp': datetime.utcnow().isoformat()
        }
        
        threat_details = {}
        
        for result in scan_results:
            if result.get('error'):
                report['scan_summary']['errors'] += 1
                continue
            
            threat_level = result.get('threat_level', 'clean')
            report['threat_breakdown'][threat_level] += 1
            
            if threat_level == 'clean':
                report['scan_summary']['clean_files'] += 1
            elif threat_level in ['critical', 'high']:
                report['scan_summary']['infected_files'] += 1
            else:
                report['scan_summary']['suspicious_files'] += 1
            
            # Count file types
            file_info = result.get('file_info', {})
            file_type = file_info.get('mime_type', 'unknown')
            report['file_types'][file_type] = report['file_types'].get(file_type, 0) + 1
            
            # Collect threat details
            for match in result.get('matches', []):
                rule_name = match.get('rule_name', 'unknown')
                category = match.get('category', 'unknown')
                
                if rule_name not in threat_details:
                    threat_details[rule_name] = {
                        'count': 0,
                        'category': category,
                        'files': []
                    }
                
                threat_details[rule_name]['count'] += 1
                threat_details[rule_name]['files'].append(result['file_path'])
        
        # Get top threats
        top_threats = sorted(
            threat_details.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]
        
        report['top_threats'] = [
            {
                'rule_name': rule_name,
                'detection_count': details['count'],
                'category': details['category'],
                'affected_files': details['files'][:5]  # Limit to first 5 files
            }
            for rule_name, details in top_threats
        ]
        
        # Add recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate recommendations based on scan results."""
        recommendations = []
        
        threat_breakdown = report['threat_breakdown']
        
        if threat_breakdown['critical'] > 0:
            recommendations.append(f"CRITICAL: {threat_breakdown['critical']} files with critical threats detected. Immediate isolation required.")
        
        if threat_breakdown['high'] > 0:
            recommendations.append(f"HIGH: {threat_breakdown['high']} files with high-risk malware. Quarantine and investigate immediately.")
        
        if threat_breakdown['medium'] > 0:
            recommendations.append(f"MEDIUM: {threat_breakdown['medium']} files with suspicious patterns. Review and analyze.")
        
        if threat_breakdown['low'] > 0:
            recommendations.append(f"LOW: {threat_breakdown['low']} files with low-risk indicators. Monitor for additional context.")
        
        infected_percentage = (report['scan_summary']['infected_files'] / report['scan_summary']['total_files']) * 100
        if infected_percentage > 10:
            recommendations.append("High infection rate detected. Consider full system scan and forensic analysis.")
        
        return recommendations

# Sample YARA rules for common threats
SAMPLE_YARA_RULES = {
    'mimikatz': """
rule Mimikatz_Generic {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "SOC Team"
        date = "2025-01-29"
        version = "1.0"
        mitre_attack = "T1003"
        
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "privilege::debug" ascii wide
        $s3 = "mimikatz.exe" ascii wide
        $s4 = "gentilkiwi" ascii wide
        $s5 = "wdigest.dll" ascii wide
        
    condition:
        2 of ($s*)
}
""",
    
    'cobalt_strike': """
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon"
        author = "SOC Team"
        date = "2025-01-29"
        version = "1.0"
        mitre_attack = "T1071"
        
    strings:
        $s1 = "beacon.dll" ascii wide
        $s2 = "beacon.x64.dll" ascii wide
        $s3 = "/admin/get.php" ascii wide
        $s4 = "cobaltstrike" ascii wide nocase
        $s5 = "teamserver" ascii wide
        
    condition:
        any of ($s*)
}
""",
    
    'ransomware_generic': """
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware detection"
        author = "SOC Team"
        date = "2025-01-29"
        version = "1.0"
        
    strings:
        $ext1 = ".encrypted" ascii wide
        $ext2 = ".locked" ascii wide
        $ext3 = ".crypto" ascii wide
        $msg1 = "your files have been encrypted" ascii wide nocase
        $msg2 = "pay the ransom" ascii wide nocase
        $msg3 = "bitcoin" ascii wide nocase
        $msg4 = "decrypt" ascii wide nocase
        
    condition:
        (any of ($ext*)) or (2 of ($msg*))
}
"""
}

async def main():
    """Main function for testing YARA engine."""
    # Initialize rule manager
    rule_manager = YaraRuleManager("rules/yara")
    
    # Compile rules
    success = await rule_manager.compile_rules()
    if not success:
        print("Failed to compile YARA rules")
        return
    
    # Get statistics
    stats = rule_manager.get_rule_statistics()
    print(f"YARA rule statistics: {json.dumps(stats, indent=2)}")
    
    # Initialize scanner
    scanner = YaraScanner(rule_manager)
    
    print("YARA engine ready for malware detection!")

if __name__ == "__main__":
    asyncio.run(main())