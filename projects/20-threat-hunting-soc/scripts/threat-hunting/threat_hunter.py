#!/usr/bin/env python3
"""
Advanced Threat Hunting Engine
Integrates SIGMA rules, YARA patterns, and behavioral analytics for proactive threat detection.

Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import yaml

import elasticsearch
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import yara
import sigma
from sigma.backends.elasticsearch import ElasticsearchBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/threat_hunter.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ThreatHuntingEngine:
    """Advanced threat hunting engine with SIGMA and YARA integration."""
    
    def __init__(self, config_path: str = "configs/threat_hunting.yml"):
        """Initialize the threat hunting engine."""
        self.config = self._load_config(config_path)
        self.es_client = None
        self.sigma_backend = None
        self.yara_rules = None
        self.detection_results = []
        self.hunting_sessions = {}
        
        # MITRE ATT&CK framework mapping
        self.attack_techniques = self._load_attack_techniques()
        
        # Initialize components
        self._init_elasticsearch()
        self._init_sigma_engine()
        self._init_yara_engine()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            # Return default configuration
            return {
                'elasticsearch': {
                    'hosts': ['localhost:9200'],
                    'timeout': 30
                },
                'sigma': {
                    'rules_path': 'rules/sigma/',
                    'backend': 'elasticsearch'
                },
                'yara': {
                    'rules_path': 'rules/yara/',
                    'scan_paths': ['/var/log/', '/tmp/']
                },
                'hunting': {
                    'time_window': '24h',
                    'max_results': 10000,
                    'confidence_threshold': 0.7
                }
            }
    
    def _load_attack_techniques(self) -> Dict[str, Dict[str, str]]:
        """Load MITRE ATT&CK techniques mapping."""
        techniques = {
            'T1003': {
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to dump credentials from system memory'
            },
            'T1055': {
                'name': 'Process Injection',
                'tactic': 'Defense Evasion',
                'description': 'Process injection is used to run code in the address space of another process'
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using application layer protocols'
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may enumerate files and directories'
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'description': 'Adversaries may transfer tools or files from external systems'
            },
            'T1135': {
                'name': 'Network Share Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may look for folders and drives shared on remote systems'
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to exploit a weakness in an Internet-facing host'
            }
        }
        return techniques
    
    def _init_elasticsearch(self):
        """Initialize Elasticsearch client."""
        try:
            self.es_client = elasticsearch.Elasticsearch(
                hosts=self.config['elasticsearch']['hosts'],
                timeout=self.config['elasticsearch']['timeout'],
                verify_certs=False,
                ssl_show_warn=False
            )
            
            # Test connection
            if self.es_client.ping():
                logger.info("Successfully connected to Elasticsearch")
            else:
                logger.error("Failed to connect to Elasticsearch")
                
        except Exception as e:
            logger.error(f"Elasticsearch initialization failed: {e}")
    
    def _init_sigma_engine(self):
        """Initialize SIGMA detection engine."""
        try:
            self.sigma_backend = ElasticsearchBackend()
            logger.info("SIGMA backend initialized successfully")
        except Exception as e:
            logger.error(f"SIGMA initialization failed: {e}")
    
    def _init_yara_engine(self):
        """Initialize YARA pattern matching engine."""
        try:
            rules_path = Path(self.config['yara']['rules_path'])
            if rules_path.exists():
                # Compile YARA rules
                yara_files = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
                if yara_files:
                    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(yara_files)}
                    self.yara_rules = yara.compile(filepaths=filepaths)
                    logger.info(f"Loaded {len(yara_files)} YARA rule files")
                else:
                    logger.warning("No YARA rules found")
            else:
                logger.warning(f"YARA rules path not found: {rules_path}")
        except Exception as e:
            logger.error(f"YARA initialization failed: {e}")
    
    async def start_hunting_session(self, hunt_name: str, hypothesis: str, 
                                  time_range: str = "24h") -> str:
        """Start a new threat hunting session."""
        session_id = f"hunt_{int(time.time())}"
        
        session = {
            'id': session_id,
            'name': hunt_name,
            'hypothesis': hypothesis,
            'start_time': datetime.utcnow(),
            'time_range': time_range,
            'status': 'active',
            'findings': [],
            'techniques_detected': []
        }
        
        self.hunting_sessions[session_id] = session
        logger.info(f"Started hunting session: {hunt_name} ({session_id})")
        
        return session_id
    
    async def execute_sigma_hunt(self, session_id: str, rule_categories: List[str] = None) -> List[Dict]:
        """Execute SIGMA rule-based hunting."""
        results = []
        rules_path = Path(self.config['sigma']['rules_path'])
        
        if not rules_path.exists():
            logger.warning(f"SIGMA rules path not found: {rules_path}")
            return results
        
        try:
            # Load SIGMA rules
            rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
            
            for rule_file in rule_files:
                try:
                    # Parse SIGMA rule
                    with open(rule_file, 'r') as f:
                        rule_content = yaml.safe_load(f)
                    
                    # Filter by category if specified
                    if rule_categories and rule_content.get('logsource', {}).get('category') not in rule_categories:
                        continue
                    
                    # Convert SIGMA rule to Elasticsearch query
                    sigma_rule = SigmaRule.from_dict(rule_content)
                    es_query = self.sigma_backend.convert(sigma_rule)
                    
                    # Execute query against Elasticsearch
                    search_results = await self._execute_es_query(es_query, session_id)
                    
                    if search_results['hits']['total']['value'] > 0:
                        detection = {
                            'rule_id': rule_content.get('id', str(rule_file)),
                            'title': rule_content.get('title', 'Unknown'),
                            'level': rule_content.get('level', 'medium'),
                            'tags': rule_content.get('tags', []),
                            'hit_count': search_results['hits']['total']['value'],
                            'events': search_results['hits']['hits'][:10],  # Limit to 10 events
                            'query': es_query,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        
                        # Map to MITRE ATT&CK techniques
                        techniques = self._extract_attack_techniques(rule_content.get('tags', []))
                        detection['mitre_techniques'] = techniques
                        
                        results.append(detection)
                        
                        # Update hunting session
                        if session_id in self.hunting_sessions:
                            self.hunting_sessions[session_id]['findings'].append(detection)
                            self.hunting_sessions[session_id]['techniques_detected'].extend(techniques)
                        
                        logger.info(f"SIGMA detection: {detection['title']} ({detection['hit_count']} hits)")
                    
                except Exception as e:
                    logger.error(f"Failed to process SIGMA rule {rule_file}: {e}")
                    continue
            
            logger.info(f"SIGMA hunt completed: {len(results)} detections")
            
        except Exception as e:
            logger.error(f"SIGMA hunt execution failed: {e}")
        
        return results
    
    async def execute_yara_hunt(self, session_id: str, target_paths: List[str] = None) -> List[Dict]:
        """Execute YARA pattern matching hunt."""
        results = []
        
        if not self.yara_rules:
            logger.warning("YARA rules not loaded")
            return results
        
        scan_paths = target_paths or self.config['yara']['scan_paths']
        
        try:
            for path in scan_paths:
                path_obj = Path(path)
                if not path_obj.exists():
                    continue
                
                # Scan files in path
                if path_obj.is_file():
                    matches = await self._scan_file_with_yara(path_obj)
                    results.extend(matches)
                elif path_obj.is_dir():
                    # Recursively scan directory
                    for file_path in path_obj.rglob("*"):
                        if file_path.is_file() and file_path.stat().st_size < 100 * 1024 * 1024:  # Limit to 100MB
                            matches = await self._scan_file_with_yara(file_path)
                            results.extend(matches)
            
            # Update hunting session
            if session_id in self.hunting_sessions:
                self.hunting_sessions[session_id]['findings'].extend(results)
            
            logger.info(f"YARA hunt completed: {len(results)} matches")
            
        except Exception as e:
            logger.error(f"YARA hunt execution failed: {e}")
        
        return results
    
    async def execute_behavioral_hunt(self, session_id: str, anomaly_threshold: float = 0.1) -> List[Dict]:
        """Execute behavioral analytics hunting using machine learning."""
        results = []
        
        try:
            # Query recent activity data
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{self.config['hunting']['time_window']}"
                        }
                    }
                },
                "aggs": {
                    "user_activity": {
                        "terms": {
                            "field": "user.name.keyword",
                            "size": 1000
                        },
                        "aggs": {
                            "login_count": {
                                "cardinality": {
                                    "field": "event.id"
                                }
                            },
                            "unique_hosts": {
                                "cardinality": {
                                    "field": "host.hostname.keyword"
                                }
                            },
                            "process_count": {
                                "cardinality": {
                                    "field": "process.name.keyword"
                                }
                            }
                        }
                    }
                }
            }
            
            response = self.es_client.search(index="winlogbeat-*,syslog-*", body=query)
            
            # Extract behavioral features
            user_features = []
            user_names = []
            
            for bucket in response['aggregations']['user_activity']['buckets']:
                user_names.append(bucket['key'])
                features = [
                    bucket['doc_count'],  # Total events
                    bucket['login_count']['value'],  # Login attempts
                    bucket['unique_hosts']['value'],  # Unique hosts accessed
                    bucket['process_count']['value']  # Unique processes
                ]
                user_features.append(features)
            
            if len(user_features) > 10:  # Need sufficient data for ML
                # Apply anomaly detection
                scaler = StandardScaler()
                features_scaled = scaler.fit_transform(user_features)
                
                # Use Isolation Forest for anomaly detection
                iso_forest = IsolationForest(contamination=anomaly_threshold, random_state=42)
                anomalies = iso_forest.fit_predict(features_scaled)
                
                # Extract anomalous users
                for i, is_anomaly in enumerate(anomalies):
                    if is_anomaly == -1:  # Anomaly detected
                        anomaly_score = iso_forest.score_samples([features_scaled[i]])[0]
                        
                        detection = {
                            'type': 'behavioral_anomaly',
                            'user': user_names[i],
                            'anomaly_score': float(anomaly_score),
                            'features': {
                                'total_events': user_features[i][0],
                                'login_count': user_features[i][1],
                                'unique_hosts': user_features[i][2],
                                'process_count': user_features[i][3]
                            },
                            'timestamp': datetime.utcnow().isoformat(),
                            'confidence': abs(anomaly_score)
                        }
                        
                        results.append(detection)
                        logger.info(f"Behavioral anomaly detected for user: {user_names[i]}")
            
            # Update hunting session
            if session_id in self.hunting_sessions:
                self.hunting_sessions[session_id]['findings'].extend(results)
            
            logger.info(f"Behavioral hunt completed: {len(results)} anomalies")
            
        except Exception as e:
            logger.error(f"Behavioral hunt execution failed: {e}")
        
        return results
    
    async def execute_timeline_analysis(self, session_id: str, pivot_entity: str, 
                                      entity_value: str) -> Dict[str, Any]:
        """Execute timeline analysis for specific entity (user, host, IP)."""
        timeline = {
            'entity_type': pivot_entity,
            'entity_value': entity_value,
            'events': [],
            'attack_chain': [],
            'risk_score': 0
        }
        
        try:
            # Build query for entity
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": f"now-{self.config['hunting']['time_window']}"
                                    }
                                }
                            },
                            {
                                "multi_match": {
                                    "query": entity_value,
                                    "fields": [
                                        "user.name",
                                        "host.hostname",
                                        "source.ip",
                                        "destination.ip",
                                        "process.name"
                                    ]
                                }
                            }
                        ]
                    }
                },
                "sort": [
                    {"@timestamp": {"order": "asc"}}
                ],
                "size": 1000
            }
            
            response = self.es_client.search(index="*", body=query)
            
            # Process events chronologically
            events = []
            attack_stages = {
                'initial_access': [],
                'execution': [],
                'persistence': [],
                'privilege_escalation': [],
                'defense_evasion': [],
                'credential_access': [],
                'discovery': [],
                'lateral_movement': [],
                'collection': [],
                'command_and_control': [],
                'exfiltration': [],
                'impact': []
            }
            
            for hit in response['hits']['hits']:
                event = hit['_source']
                event['_id'] = hit['_id']
                events.append(event)
                
                # Categorize event by MITRE ATT&CK tactic
                tactic = self._categorize_event_tactic(event)
                if tactic in attack_stages:
                    attack_stages[tactic].append(event)
            
            timeline['events'] = events
            timeline['attack_chain'] = [
                {'stage': stage, 'events': stage_events}
                for stage, stage_events in attack_stages.items()
                if stage_events
            ]
            
            # Calculate risk score based on attack chain progression
            timeline['risk_score'] = self._calculate_risk_score(attack_stages)
            
            # Update hunting session
            if session_id in self.hunting_sessions:
                self.hunting_sessions[session_id]['findings'].append({
                    'type': 'timeline_analysis',
                    'timeline': timeline
                })
            
            logger.info(f"Timeline analysis completed for {pivot_entity}: {entity_value}")
            
        except Exception as e:
            logger.error(f"Timeline analysis failed: {e}")
        
        return timeline
    
    async def _execute_es_query(self, query: str, session_id: str) -> Dict:
        """Execute Elasticsearch query."""
        try:
            # Convert query string to dict if needed
            if isinstance(query, str):
                query_dict = {"query": {"query_string": {"query": query}}}
            else:
                query_dict = query
            
            # Add time range filter
            if "query" in query_dict and "bool" not in query_dict["query"]:
                query_dict = {
                    "query": {
                        "bool": {
                            "must": [query_dict["query"]],
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": f"now-{self.config['hunting']['time_window']}"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            
            response = self.es_client.search(
                index="*",
                body=query_dict,
                size=self.config['hunting']['max_results']
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Elasticsearch query execution failed: {e}")
            return {"hits": {"total": {"value": 0}, "hits": []}}
    
    async def _scan_file_with_yara(self, file_path: Path) -> List[Dict]:
        """Scan file with YARA rules."""
        matches = []
        
        try:
            yara_matches = self.yara_rules.match(str(file_path))
            
            for match in yara_matches:
                detection = {
                    'type': 'yara_match',
                    'rule': match.rule,
                    'file_path': str(file_path),
                    'tags': list(match.tags),
                    'strings': [
                        {
                            'identifier': s.identifier,
                            'instances': [
                                {
                                    'offset': instance.offset,
                                    'matched_data': instance.matched_data.decode('utf-8', errors='replace')[:100]
                                }
                                for instance in s.instances
                            ]
                        }
                        for s in match.strings
                    ],
                    'timestamp': datetime.utcnow().isoformat()
                }
                matches.append(detection)
                
        except Exception as e:
            logger.error(f"YARA scan failed for {file_path}: {e}")
        
        return matches
    
    def _extract_attack_techniques(self, tags: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from tags."""
        techniques = []
        for tag in tags:
            if tag.startswith('attack.t'):
                technique_id = tag.replace('attack.t', 'T').upper()
                if technique_id in self.attack_techniques:
                    techniques.append(technique_id)
        return techniques
    
    def _categorize_event_tactic(self, event: Dict) -> str:
        """Categorize event by MITRE ATT&CK tactic."""
        # Simple heuristic-based categorization
        # In production, this would be more sophisticated
        
        if 'winlog' in event.get('agent', {}).get('type', ''):
            event_id = event.get('winlog', {}).get('event_id')
            
            # Windows Event ID mapping to tactics
            if event_id in [4624, 4625]:  # Logon events
                return 'initial_access'
            elif event_id in [4688]:  # Process creation
                return 'execution'
            elif event_id in [4648]:  # Explicit credential logon
                return 'credential_access'
            elif event_id in [5156]:  # Network connection
                return 'command_and_control'
        
        # Default categorization based on log source
        log_source = event.get('log', {}).get('file', {}).get('path', '')
        if 'auth' in log_source:
            return 'initial_access'
        elif 'process' in log_source:
            return 'execution'
        elif 'network' in log_source:
            return 'command_and_control'
        
        return 'discovery'  # Default
    
    def _calculate_risk_score(self, attack_stages: Dict) -> float:
        """Calculate risk score based on attack chain progression."""
        stage_weights = {
            'initial_access': 0.8,
            'execution': 0.6,
            'persistence': 0.9,
            'privilege_escalation': 0.9,
            'defense_evasion': 0.7,
            'credential_access': 0.9,
            'discovery': 0.4,
            'lateral_movement': 1.0,
            'collection': 0.8,
            'command_and_control': 0.8,
            'exfiltration': 1.0,
            'impact': 1.0
        }
        
        score = 0
        for stage, events in attack_stages.items():
            if events:
                stage_score = len(events) * stage_weights.get(stage, 0.5)
                score += min(stage_score, 10)  # Cap individual stage contribution
        
        return min(score / 10, 10)  # Normalize to 0-10 scale
    
    async def generate_hunt_report(self, session_id: str) -> Dict:
        """Generate comprehensive hunting report."""
        if session_id not in self.hunting_sessions:
            return {"error": "Session not found"}
        
        session = self.hunting_sessions[session_id]
        session['status'] = 'completed'
        session['end_time'] = datetime.utcnow()
        
        report = {
            'session_info': {
                'id': session_id,
                'name': session['name'],
                'hypothesis': session['hypothesis'],
                'duration': str(session['end_time'] - session['start_time']),
                'status': session['status']
            },
            'summary': {
                'total_findings': len(session['findings']),
                'techniques_detected': list(set(session['techniques_detected'])),
                'high_risk_findings': len([f for f in session['findings'] 
                                         if f.get('level') == 'high' or f.get('risk_score', 0) > 7])
            },
            'findings': session['findings'],
            'recommendations': self._generate_recommendations(session['findings']),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return report
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate hunting recommendations based on findings."""
        recommendations = []
        
        high_risk_count = len([f for f in findings if f.get('level') == 'high'])
        if high_risk_count > 0:
            recommendations.append(f"Investigate {high_risk_count} high-risk findings immediately")
        
        techniques = []
        for finding in findings:
            techniques.extend(finding.get('mitre_techniques', []))
        
        unique_techniques = list(set(techniques))
        if unique_techniques:
            recommendations.append(f"Review MITRE ATT&CK techniques: {', '.join(unique_techniques[:5])}")
        
        behavioral_anomalies = [f for f in findings if f.get('type') == 'behavioral_anomaly']
        if behavioral_anomalies:
            recommendations.append(f"Investigate behavioral anomalies for {len(behavioral_anomalies)} users")
        
        return recommendations

async def main():
    """Main hunting execution function."""
    # Initialize hunting engine
    hunter = ThreatHuntingEngine()
    
    # Start hunting session
    session_id = await hunter.start_hunting_session(
        hunt_name="Advanced Persistent Threat Hunt",
        hypothesis="APT actors may be using living-off-the-land techniques for persistence",
        time_range="7d"
    )
    
    print(f"Started hunting session: {session_id}")
    
    # Execute different hunting techniques
    print("Executing SIGMA rule hunt...")
    sigma_results = await hunter.execute_sigma_hunt(session_id, ['process_creation', 'network'])
    
    print("Executing behavioral analysis...")
    behavioral_results = await hunter.execute_behavioral_hunt(session_id)
    
    print("Executing timeline analysis...")
    timeline = await hunter.execute_timeline_analysis(session_id, 'user', 'administrator')
    
    # Generate final report
    print("Generating hunt report...")
    report = await hunter.generate_hunt_report(session_id)
    
    print(f"Hunt completed with {len(sigma_results + behavioral_results)} findings")
    print(json.dumps(report['summary'], indent=2))

if __name__ == "__main__":
    asyncio.run(main())