#!/usr/bin/env python3
"""
SIGMA Detection Engine
Advanced SIGMA rule management and execution for threat hunting.

Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

from sigma.rule import SigmaRule
from sigma.backends.elasticsearch import ElasticsearchBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.common import logsource_windows, windows_logsources
from sigma.pipelines.elasticsearch import ecs_windows
import elasticsearch

logger = logging.getLogger(__name__)

class SigmaRuleManager:
    """Advanced SIGMA rule manager with categorization and optimization."""
    
    def __init__(self, rules_directory: str = "rules/sigma"):
        """Initialize SIGMA rule manager."""
        self.rules_directory = Path(rules_directory)
        self.rules_cache = {}
        self.rule_categories = {}
        self.elasticsearch_backend = ElasticsearchBackend()
        self.splunk_backend = SplunkBackend()
        
        # Initialize rule categories
        self._init_rule_categories()
        
    def _init_rule_categories(self):
        """Initialize rule categories for organized hunting."""
        self.rule_categories = {
            'process_creation': {
                'description': 'Process creation and execution monitoring',
                'mitre_tactics': ['execution', 'defense-evasion'],
                'log_sources': ['windows', 'linux', 'macos']
            },
            'network_connection': {
                'description': 'Network connections and communications',
                'mitre_tactics': ['command-and-control', 'exfiltration'],
                'log_sources': ['firewall', 'proxy', 'dns']
            },
            'credential_access': {
                'description': 'Credential dumping and access attempts',
                'mitre_tactics': ['credential-access'],
                'log_sources': ['windows', 'linux', 'authentication']
            },
            'privilege_escalation': {
                'description': 'Privilege escalation techniques',
                'mitre_tactics': ['privilege-escalation'],
                'log_sources': ['windows', 'linux', 'macos']
            },
            'lateral_movement': {
                'description': 'Lateral movement and remote access',
                'mitre_tactics': ['lateral-movement'],
                'log_sources': ['windows', 'network', 'authentication']
            },
            'persistence': {
                'description': 'Persistence mechanisms',
                'mitre_tactics': ['persistence'],
                'log_sources': ['windows', 'linux', 'registry']
            },
            'discovery': {
                'description': 'System and network discovery',
                'mitre_tactics': ['discovery'],
                'log_sources': ['windows', 'linux', 'network']
            },
            'defense_evasion': {
                'description': 'Defense evasion techniques',
                'mitre_tactics': ['defense-evasion'],
                'log_sources': ['windows', 'linux', 'antivirus']
            }
        }
    
    async def load_rules(self, force_reload: bool = False) -> int:
        """Load all SIGMA rules from directory."""
        if not force_reload and self.rules_cache:
            return len(self.rules_cache)
        
        self.rules_cache.clear()
        rules_loaded = 0
        
        if not self.rules_directory.exists():
            logger.warning(f"SIGMA rules directory not found: {self.rules_directory}")
            return 0
        
        try:
            # Recursively find all YAML rule files
            rule_files = list(self.rules_directory.rglob("*.yml")) + \
                        list(self.rules_directory.rglob("*.yaml"))
            
            for rule_file in rule_files:
                try:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rule_content = yaml.safe_load(f)
                    
                    # Create SigmaRule object
                    sigma_rule = SigmaRule.from_dict(rule_content)
                    
                    # Categorize rule
                    category = self._categorize_rule(rule_content)
                    
                    rule_info = {
                        'rule': sigma_rule,
                        'file_path': str(rule_file),
                        'category': category,
                        'title': rule_content.get('title', 'Unknown'),
                        'level': rule_content.get('level', 'medium'),
                        'tags': rule_content.get('tags', []),
                        'author': rule_content.get('author', 'Unknown'),
                        'description': rule_content.get('description', ''),
                        'references': rule_content.get('references', []),
                        'mitre_techniques': self._extract_mitre_techniques(rule_content.get('tags', []))
                    }
                    
                    rule_id = rule_content.get('id', str(rule_file.stem))
                    self.rules_cache[rule_id] = rule_info
                    rules_loaded += 1
                    
                except Exception as e:
                    logger.error(f"Failed to load SIGMA rule {rule_file}: {e}")
                    continue
            
            logger.info(f"Loaded {rules_loaded} SIGMA rules")
            return rules_loaded
            
        except Exception as e:
            logger.error(f"Failed to load SIGMA rules: {e}")
            return 0
    
    def _categorize_rule(self, rule_content: Dict) -> str:
        """Categorize rule based on log source and tags."""
        logsource = rule_content.get('logsource', {})
        category = logsource.get('category', '').lower()
        service = logsource.get('service', '').lower()
        tags = [tag.lower() for tag in rule_content.get('tags', [])]
        
        # Process creation rules
        if category in ['process_creation', 'process'] or \
           service in ['sysmon', 'security'] or \
           any('process' in tag for tag in tags):
            return 'process_creation'
        
        # Network rules
        elif category in ['network_connection', 'network'] or \
             service in ['firewall', 'proxy', 'dns'] or \
             any('network' in tag for tag in tags):
            return 'network_connection'
        
        # Authentication rules
        elif category in ['authentication', 'logon'] or \
             service in ['security', 'auth'] or \
             any('logon' in tag or 'credential' in tag for tag in tags):
            return 'credential_access'
        
        # Registry rules
        elif category in ['registry_event', 'registry'] or \
             'registry' in service or \
             any('registry' in tag for tag in tags):
            return 'persistence'
        
        # File system rules
        elif category in ['file_event', 'file'] or \
             any('file' in tag for tag in tags):
            return 'defense_evasion'
        
        # Default categorization
        else:
            return 'discovery'
    
    def _extract_mitre_techniques(self, tags: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from tags."""
        techniques = []
        for tag in tags:
            if tag.lower().startswith('attack.t'):
                technique = tag.upper().replace('ATTACK.T', 'T')
                techniques.append(technique)
        return techniques
    
    def get_rules_by_category(self, category: str) -> List[Dict]:
        """Get rules filtered by category."""
        return [rule_info for rule_info in self.rules_cache.values() 
                if rule_info['category'] == category]
    
    def get_rules_by_technique(self, technique: str) -> List[Dict]:
        """Get rules filtered by MITRE ATT&CK technique."""
        return [rule_info for rule_info in self.rules_cache.values() 
                if technique in rule_info['mitre_techniques']]
    
    def get_rules_by_level(self, level: str) -> List[Dict]:
        """Get rules filtered by severity level."""
        return [rule_info for rule_info in self.rules_cache.values() 
                if rule_info['level'] == level]
    
    async def convert_to_elasticsearch(self, rule_id: str) -> Optional[Dict]:
        """Convert SIGMA rule to Elasticsearch query."""
        if rule_id not in self.rules_cache:
            return None
        
        try:
            rule_info = self.rules_cache[rule_id]
            sigma_rule = rule_info['rule']
            
            # Convert to Elasticsearch query
            es_query = self.elasticsearch_backend.convert(sigma_rule)
            
            return {
                'rule_id': rule_id,
                'title': rule_info['title'],
                'query': es_query,
                'category': rule_info['category'],
                'level': rule_info['level'],
                'mitre_techniques': rule_info['mitre_techniques']
            }
            
        except Exception as e:
            logger.error(f"Failed to convert rule {rule_id} to Elasticsearch: {e}")
            return None
    
    async def convert_to_splunk(self, rule_id: str) -> Optional[Dict]:
        """Convert SIGMA rule to Splunk query."""
        if rule_id not in self.rules_cache:
            return None
        
        try:
            rule_info = self.rules_cache[rule_id]
            sigma_rule = rule_info['rule']
            
            # Convert to Splunk query
            splunk_query = self.splunk_backend.convert(sigma_rule)
            
            return {
                'rule_id': rule_id,
                'title': rule_info['title'],
                'query': splunk_query,
                'category': rule_info['category'],
                'level': rule_info['level'],
                'mitre_techniques': rule_info['mitre_techniques']
            }
            
        except Exception as e:
            logger.error(f"Failed to convert rule {rule_id} to Splunk: {e}")
            return None
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded rules."""
        if not self.rules_cache:
            return {}
        
        stats = {
            'total_rules': len(self.rules_cache),
            'by_category': {},
            'by_level': {},
            'by_technique': {},
            'authors': set(),
            'top_techniques': []
        }
        
        for rule_info in self.rules_cache.values():
            # Count by category
            category = rule_info['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # Count by level
            level = rule_info['level']
            stats['by_level'][level] = stats['by_level'].get(level, 0) + 1
            
            # Count by technique
            for technique in rule_info['mitre_techniques']:
                stats['by_technique'][technique] = stats['by_technique'].get(technique, 0) + 1
            
            # Collect authors
            if rule_info['author'] != 'Unknown':
                stats['authors'].add(rule_info['author'])
        
        # Get top techniques
        stats['top_techniques'] = sorted(
            stats['by_technique'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        stats['authors'] = list(stats['authors'])
        
        return stats

class SigmaHuntingEngine:
    """SIGMA-based hunting engine with advanced query capabilities."""
    
    def __init__(self, es_client, rule_manager: SigmaRuleManager):
        """Initialize SIGMA hunting engine."""
        self.es_client = es_client
        self.rule_manager = rule_manager
        self.hunt_results = {}
    
    async def execute_hunt_by_category(self, category: str, time_range: str = "24h", 
                                     index_pattern: str = "*") -> List[Dict]:
        """Execute hunt using all rules in a category."""
        results = []
        rules = self.rule_manager.get_rules_by_category(category)
        
        logger.info(f"Executing hunt with {len(rules)} rules in category: {category}")
        
        for rule_info in rules:
            try:
                # Convert to Elasticsearch query
                converted_rule = await self.rule_manager.convert_to_elasticsearch(
                    list(self.rule_manager.rules_cache.keys())[
                        list(self.rule_manager.rules_cache.values()).index(rule_info)
                    ]
                )
                
                if not converted_rule:
                    continue
                
                # Execute query
                hunt_result = await self._execute_hunt_query(
                    converted_rule, time_range, index_pattern
                )
                
                if hunt_result['hit_count'] > 0:
                    results.append(hunt_result)
                
            except Exception as e:
                logger.error(f"Failed to execute hunt for rule {rule_info['title']}: {e}")
                continue
        
        logger.info(f"Hunt completed: {len(results)} rules with detections")
        return results
    
    async def execute_hunt_by_technique(self, technique: str, time_range: str = "24h", 
                                      index_pattern: str = "*") -> List[Dict]:
        """Execute hunt using all rules for a MITRE ATT&CK technique."""
        results = []
        rules = self.rule_manager.get_rules_by_technique(technique)
        
        logger.info(f"Executing hunt with {len(rules)} rules for technique: {technique}")
        
        for rule_info in rules:
            try:
                # Convert to Elasticsearch query
                converted_rule = await self.rule_manager.convert_to_elasticsearch(
                    list(self.rule_manager.rules_cache.keys())[
                        list(self.rule_manager.rules_cache.values()).index(rule_info)
                    ]
                )
                
                if not converted_rule:
                    continue
                
                # Execute query
                hunt_result = await self._execute_hunt_query(
                    converted_rule, time_range, index_pattern
                )
                
                if hunt_result['hit_count'] > 0:
                    results.append(hunt_result)
                
            except Exception as e:
                logger.error(f"Failed to execute hunt for rule {rule_info['title']}: {e}")
                continue
        
        return results
    
    async def execute_custom_hunt(self, rule_ids: List[str], time_range: str = "24h", 
                                index_pattern: str = "*") -> List[Dict]:
        """Execute hunt using specific rule IDs."""
        results = []
        
        for rule_id in rule_ids:
            try:
                converted_rule = await self.rule_manager.convert_to_elasticsearch(rule_id)
                
                if not converted_rule:
                    logger.warning(f"Could not convert rule {rule_id}")
                    continue
                
                hunt_result = await self._execute_hunt_query(
                    converted_rule, time_range, index_pattern
                )
                
                results.append(hunt_result)
                
            except Exception as e:
                logger.error(f"Failed to execute hunt for rule {rule_id}: {e}")
                continue
        
        return results
    
    async def _execute_hunt_query(self, converted_rule: Dict, time_range: str, 
                                index_pattern: str) -> Dict:
        """Execute individual hunt query against Elasticsearch."""
        try:
            # Build Elasticsearch query
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"query_string": {"query": converted_rule['query']}}
                        ],
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": f"now-{time_range}"
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [
                    {"@timestamp": {"order": "desc"}}
                ],
                "size": 100
            }
            
            # Execute query
            response = self.es_client.search(index=index_pattern, body=query)
            
            # Process results
            hit_count = response['hits']['total']['value']
            events = response['hits']['hits']
            
            # Analyze event patterns
            event_analysis = self._analyze_events(events)
            
            result = {
                'rule_id': converted_rule['rule_id'],
                'title': converted_rule['title'],
                'category': converted_rule['category'],
                'level': converted_rule['level'],
                'mitre_techniques': converted_rule['mitre_techniques'],
                'hit_count': hit_count,
                'events': events[:10],  # Limit to first 10 events
                'event_analysis': event_analysis,
                'query': converted_rule['query'],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Hunt query execution failed: {e}")
            return {
                'rule_id': converted_rule.get('rule_id', 'unknown'),
                'title': converted_rule.get('title', 'Unknown'),
                'hit_count': 0,
                'events': [],
                'error': str(e)
            }
    
    def _analyze_events(self, events: List[Dict]) -> Dict:
        """Analyze events for patterns and anomalies."""
        if not events:
            return {}
        
        analysis = {
            'unique_hosts': set(),
            'unique_users': set(),
            'unique_processes': set(),
            'time_distribution': {},
            'source_ips': set(),
            'destination_ips': set()
        }
        
        for event in events:
            source = event.get('_source', {})
            
            # Extract host information
            host = source.get('host', {}).get('hostname') or source.get('computer_name')
            if host:
                analysis['unique_hosts'].add(host)
            
            # Extract user information
            user = source.get('user', {}).get('name') or source.get('user_name')
            if user:
                analysis['unique_users'].add(user)
            
            # Extract process information
            process = source.get('process', {}).get('name') or source.get('process_name')
            if process:
                analysis['unique_processes'].add(process)
            
            # Extract network information
            src_ip = source.get('source', {}).get('ip') or source.get('src_ip')
            if src_ip:
                analysis['source_ips'].add(src_ip)
            
            dst_ip = source.get('destination', {}).get('ip') or source.get('dst_ip')
            if dst_ip:
                analysis['destination_ips'].add(dst_ip)
            
            # Time distribution analysis
            timestamp = source.get('@timestamp')
            if timestamp:
                hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
                analysis['time_distribution'][hour] = analysis['time_distribution'].get(hour, 0) + 1
        
        # Convert sets to lists for JSON serialization
        for key in ['unique_hosts', 'unique_users', 'unique_processes', 'source_ips', 'destination_ips']:
            analysis[key] = list(analysis[key])
        
        # Add summary statistics
        analysis['summary'] = {
            'total_events': len(events),
            'unique_host_count': len(analysis['unique_hosts']),
            'unique_user_count': len(analysis['unique_users']),
            'unique_process_count': len(analysis['unique_processes']),
            'peak_hour': max(analysis['time_distribution'].items(), 
                           key=lambda x: x[1])[0] if analysis['time_distribution'] else None
        }
        
        return analysis
    
    async def generate_hunt_summary(self, hunt_results: List[Dict]) -> Dict:
        """Generate summary of hunt results."""
        if not hunt_results:
            return {'message': 'No hunt results to summarize'}
        
        summary = {
            'total_rules_executed': len(hunt_results),
            'rules_with_hits': len([r for r in hunt_results if r.get('hit_count', 0) > 0]),
            'total_events': sum(r.get('hit_count', 0) for r in hunt_results),
            'by_category': {},
            'by_level': {},
            'by_technique': {},
            'top_detections': [],
            'affected_hosts': set(),
            'affected_users': set()
        }
        
        # Analyze results
        for result in hunt_results:
            if result.get('hit_count', 0) == 0:
                continue
            
            # Count by category
            category = result.get('category', 'unknown')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
            
            # Count by level
            level = result.get('level', 'unknown')
            summary['by_level'][level] = summary['by_level'].get(level, 0) + 1
            
            # Count by technique
            for technique in result.get('mitre_techniques', []):
                summary['by_technique'][technique] = summary['by_technique'].get(technique, 0) + 1
            
            # Collect affected entities
            event_analysis = result.get('event_analysis', {})
            summary['affected_hosts'].update(event_analysis.get('unique_hosts', []))
            summary['affected_users'].update(event_analysis.get('unique_users', []))
            
            # Top detections
            summary['top_detections'].append({
                'title': result.get('title', 'Unknown'),
                'hit_count': result.get('hit_count', 0),
                'level': result.get('level', 'unknown'),
                'techniques': result.get('mitre_techniques', [])
            })
        
        # Sort top detections by hit count
        summary['top_detections'] = sorted(
            summary['top_detections'],
            key=lambda x: x['hit_count'],
            reverse=True
        )[:10]
        
        # Convert sets to lists
        summary['affected_hosts'] = list(summary['affected_hosts'])
        summary['affected_users'] = list(summary['affected_users'])
        
        # Add risk assessment
        summary['risk_assessment'] = self._assess_hunt_risk(hunt_results)
        
        return summary
    
    def _assess_hunt_risk(self, hunt_results: List[Dict]) -> Dict:
        """Assess overall risk based on hunt results."""
        risk_score = 0
        risk_factors = []
        
        level_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        
        for result in hunt_results:
            if result.get('hit_count', 0) == 0:
                continue
            
            level = result.get('level', 'low')
            weight = level_weights.get(level, 1)
            hit_count = result.get('hit_count', 0)
            
            rule_risk = min(weight * (hit_count ** 0.5), 50)  # Square root to dampen large numbers
            risk_score += rule_risk
            
            if level in ['critical', 'high'] and hit_count > 5:
                risk_factors.append(f"High-severity rule '{result.get('title', 'Unknown')}' triggered {hit_count} times")
        
        # Normalize risk score to 0-100 scale
        normalized_risk = min(risk_score / 10, 100)
        
        risk_level = 'low'
        if normalized_risk > 70:
            risk_level = 'critical'
        elif normalized_risk > 50:
            risk_level = 'high'
        elif normalized_risk > 25:
            risk_level = 'medium'
        
        return {
            'risk_score': round(normalized_risk, 2),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            'low': 'Continue monitoring. No immediate action required.',
            'medium': 'Review detections and investigate suspicious activities.',
            'high': 'Immediate investigation required. Consider incident response procedures.',
            'critical': 'URGENT: Activate incident response team and implement containment measures.'
        }
        return recommendations.get(risk_level, 'Unknown risk level')

# Pre-built SIGMA rules for common threats
SAMPLE_SIGMA_RULES = {
    'mimikatz_detection': """
title: Mimikatz Detection
id: mimikatz-detection-001
status: experimental
description: Detects Mimikatz credential dumping tool
author: SOC Team
date: 2025/01/29
references:
    - https://attack.mitre.org/techniques/T1003/
tags:
    - attack.credential_access
    - attack.t1003
    - mimikatz
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: 
            - '\\mimikatz.exe'
            - '\\mimilib.dll'
        - CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::pth'
            - 'sekurlsa::tickets'
            - 'privilege::debug'
    condition: selection
falsepositives:
    - Administrative tools
    - Security testing
level: high
""",
    
    'powershell_execution': """
title: Suspicious PowerShell Execution
id: powershell-suspicious-001
status: stable
description: Detects suspicious PowerShell command execution
author: SOC Team
date: 2025/01/29
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
    - powershell
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\\powershell.exe'
        - CommandLine|contains:
            - '-encodedcommand'
            - '-enc '
            - 'downloadstring'
            - 'invoke-expression'
            - 'iex '
            - 'bypass'
            - '-windowstyle hidden'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
    - Software deployment
level: medium
""",
    
    'lateral_movement_wmi': """
title: Lateral Movement via WMI
id: wmi-lateral-movement-001
status: experimental
description: Detects lateral movement using WMI
author: SOC Team
date: 2025/01/29
references:
    - https://attack.mitre.org/techniques/T1047/
tags:
    - attack.lateral_movement
    - attack.t1047
    - wmi
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\\wmic.exe'
        - CommandLine|contains:
            - '/node:'
            - 'process call create'
            - 'shadowcopy'
    condition: selection
falsepositives:
    - System administration
    - Remote management tools
level: high
"""
}

async def main():
    """Main function for testing SIGMA engine."""
    # Initialize rule manager
    rule_manager = SigmaRuleManager("rules/sigma")
    
    # Load rules
    rules_loaded = await rule_manager.load_rules()
    print(f"Loaded {rules_loaded} SIGMA rules")
    
    # Get statistics
    stats = rule_manager.get_rule_statistics()
    print(f"Rule statistics: {json.dumps(stats, indent=2)}")
    
    # Example hunt execution would go here with actual Elasticsearch client
    print("SIGMA engine ready for threat hunting!")

if __name__ == "__main__":
    asyncio.run(main())