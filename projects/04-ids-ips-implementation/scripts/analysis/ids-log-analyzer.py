#!/usr/bin/env python3
"""
IDS/IPS Log Analyzer - Analyse Avancée et Corrélation
Projet 04 - Cybersecurity Portfolio

Fonctionnalités:
- Analyse temps réel des logs Suricata/Snort
- Corrélation d'événements multi-sources
- Détection de patterns d'attaque complexes
- Classification automatique des menaces
- Génération d'alertes intelligentes
- Intégration Threat Intelligence
"""

import json
import re
import time
import logging
import argparse
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Any, Optional
import threading
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    import elasticsearch
    from elasticsearch import Elasticsearch
    import geoip2.database
    import pandas as pd
    ADVANCED_FEATURES = True
except ImportError:
    print("⚠️ Certaines fonctionnalités avancées non disponibles")
    print("Installation: pip3 install requests elasticsearch geoip2 pandas")
    ADVANCED_FEATURES = False

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ids-analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AttackCategory(Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    signature: str
    severity: int
    category: str
    raw_log: str
    threat_level: ThreatLevel
    attack_category: Optional[AttackCategory] = None
    confidence: float = 0.0
    context: Dict[str, Any] = None

class IDSLogAnalyzer:
    def __init__(self, config_file: str = None):
        """Initialisation de l'analyseur IDS/IPS"""
        self.config = self._load_config(config_file)
        self.event_buffer = []
        self.correlation_rules = []
        self.threat_intel = {}
        self.attack_patterns = defaultdict(list)
        self.session_tracker = defaultdict(dict)
        self.alert_cache = {}
        self.running = False
        
        # Statistiques temps réel
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'threats_detected': 0,
            'false_positives_filtered': 0,
            'start_time': datetime.now()
        }
        
        # Initialisation composants
        self._init_elasticsearch()
        self._init_threat_intelligence()
        self._load_correlation_rules()
        self._init_geoip()
        
        logger.info("🔍 IDS Log Analyzer initialisé")

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Chargement configuration"""
        default_config = {
            'elasticsearch': {
                'host': 'localhost',
                'port': 9200,
                'indices': ['suricata-*', 'snort-*']
            },
            'analysis': {
                'correlation_window': 300,  # 5 minutes
                'min_confidence': 0.6,
                'max_events_buffer': 10000,
                'enable_geoip': True,
                'enable_threat_intel': True
            },
            'alerting': {
                'min_severity': 2,
                'rate_limit': 100,  # alerts per hour
                'deduplicate_window': 3600  # 1 hour
            },
            'patterns': {
                'brute_force': {
                    'threshold': 10,
                    'window': 300
                },
                'port_scan': {
                    'threshold': 20,
                    'window': 60
                },
                'data_exfiltration': {
                    'size_threshold': 100000000,  # 100MB
                    'connection_threshold': 5
                }
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    logger.info(f"✅ Configuration chargée: {config_file}")
            except Exception as e:
                logger.warning(f"⚠️ Erreur chargement config: {e}. Utilisation config par défaut.")
        
        return default_config

    def _init_elasticsearch(self):
        """Initialisation connexion Elasticsearch"""
        if not ADVANCED_FEATURES:
            self.es = None
            return
            
        try:
            es_config = self.config['elasticsearch']
            self.es = Elasticsearch([
                f"http://{es_config['host']}:{es_config['port']}"
            ])
            
            # Test connexion
            if self.es.ping():
                logger.info("✅ Connexion Elasticsearch établie")
            else:
                logger.warning("⚠️ Elasticsearch non accessible")
                self.es = None
        except Exception as e:
            logger.error(f"❌ Erreur connexion Elasticsearch: {e}")
            self.es = None

    def _init_threat_intelligence(self):
        """Initialisation feeds de Threat Intelligence"""
        self.threat_intel = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'known_signatures': {},
            'iocs': []
        }
        
        if not self.config['analysis']['enable_threat_intel']:
            return
            
        try:
            # Chargement IOCs depuis sources publiques
            self._load_abuse_ch_feeds()
            self._load_local_iocs()
            logger.info(f"✅ Threat Intelligence chargée: {len(self.threat_intel['malicious_ips'])} IPs malveillantes")
        except Exception as e:
            logger.warning(f"⚠️ Erreur chargement Threat Intel: {e}")

    def _load_abuse_ch_feeds(self):
        """Chargement feeds abuse.ch"""
        try:
            # SSL Abuse List
            response = requests.get('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            try:
                                ipaddress.ip_address(ip)
                                self.threat_intel['malicious_ips'].add(ip)
                            except:
                                pass
                                
        except Exception as e:
            logger.debug(f"Erreur chargement abuse.ch: {e}")

    def _load_local_iocs(self):
        """Chargement IOCs locaux"""
        ioc_file = Path(__file__).parent.parent / 'configs' / 'threat_iocs.json'
        if ioc_file.exists():
            try:
                with open(ioc_file, 'r') as f:
                    local_iocs = json.load(f)
                    self.threat_intel['malicious_ips'].update(local_iocs.get('ips', []))
                    self.threat_intel['malicious_domains'].update(local_iocs.get('domains', []))
                    self.threat_intel['known_signatures'].update(local_iocs.get('signatures', {}))
            except Exception as e:
                logger.warning(f"Erreur chargement IOCs locaux: {e}")

    def _init_geoip(self):
        """Initialisation GeoIP"""
        self.geoip_reader = None
        if not self.config['analysis']['enable_geoip']:
            return
            
        geoip_db = '/usr/share/GeoIP/GeoLite2-City.mmdb'
        if Path(geoip_db).exists():
            try:
                import geoip2.database
                self.geoip_reader = geoip2.database.Reader(geoip_db)
                logger.info("✅ GeoIP database chargée")
            except Exception as e:
                logger.warning(f"⚠️ Erreur GeoIP: {e}")

    def _load_correlation_rules(self):
        """Chargement règles de corrélation"""
        self.correlation_rules = [
            {
                'name': 'brute_force_detection',
                'description': 'Détection attaque brute force',
                'conditions': [
                    {'field': 'dest_port', 'operator': 'in', 'value': [22, 80, 443, 3389]},
                    {'field': 'source_ip', 'operator': 'same'},
                    {'field': 'signature', 'operator': 'contains', 'value': ['brute', 'login', 'auth']}
                ],
                'threshold': self.config['patterns']['brute_force']['threshold'],
                'window': self.config['patterns']['brute_force']['window'],
                'severity': ThreatLevel.HIGH
            },
            {
                'name': 'port_scan_detection', 
                'description': 'Détection scan de ports',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'same'},
                    {'field': 'dest_ip', 'operator': 'same'},
                    {'field': 'dest_port', 'operator': 'different'}
                ],
                'threshold': self.config['patterns']['port_scan']['threshold'],
                'window': self.config['patterns']['port_scan']['window'],
                'severity': ThreatLevel.MEDIUM
            },
            {
                'name': 'lateral_movement',
                'description': 'Détection mouvement latéral',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'internal'},
                    {'field': 'dest_ip', 'operator': 'internal'}, 
                    {'field': 'signature', 'operator': 'contains', 'value': ['smb', 'rdp', 'wmi', 'psexec']}
                ],
                'threshold': 3,
                'window': 600,
                'severity': ThreatLevel.HIGH
            },
            {
                'name': 'data_exfiltration',
                'description': 'Détection exfiltration de données',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'internal'},
                    {'field': 'dest_ip', 'operator': 'external'},
                    {'field': 'protocol', 'operator': 'in', 'value': ['TCP', 'HTTP', 'HTTPS', 'FTP']}
                ],
                'threshold': self.config['patterns']['data_exfiltration']['connection_threshold'],
                'window': 300,
                'severity': ThreatLevel.CRITICAL
            }
        ]
        logger.info(f"✅ {len(self.correlation_rules)} règles de corrélation chargées")

    def parse_suricata_event(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse événement Suricata EVE JSON"""
        try:
            event_data = json.loads(log_line.strip())
            
            if event_data.get('event_type') != 'alert':
                return None
                
            alert = event_data.get('alert', {})
            
            # Extraction des informations
            timestamp = datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00'))
            source_ip = event_data.get('src_ip', '0.0.0.0')
            dest_ip = event_data.get('dest_ip', '0.0.0.0') 
            source_port = event_data.get('src_port', 0)
            dest_port = event_data.get('dest_port', 0)
            protocol = event_data.get('proto', 'unknown')
            
            signature = alert.get('signature', 'Unknown Alert')
            severity = alert.get('severity', 3)
            category = alert.get('category', 'unknown')
            
            # Classification threat level
            threat_level = self._classify_threat_level(severity, signature, category)
            
            # Classification attack category
            attack_category = self._classify_attack_category(signature, category)
            
            # Création événement
            event = SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                signature=signature,
                severity=severity,
                category=category,
                raw_log=log_line,
                threat_level=threat_level,
                attack_category=attack_category,
                confidence=self._calculate_confidence(alert, source_ip, dest_ip),
                context=self._extract_context(event_data)
            )
            
            return event
            
        except Exception as e:
            logger.debug(f"Erreur parsing Suricata: {e}")
            return None

    def parse_snort_event(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse événement Snort Fast Alert"""
        try:
            # Format: timestamp [gid:sid:rev] signature [Classification: class] [Priority: prio] {proto} src:port -> dst:port
            pattern = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(.+?)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
            
            match = re.match(pattern, log_line.strip())
            if not match:
                return None
            
            timestamp_str, gid, sid, rev, signature, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port = match.groups()
            
            # Parsing timestamp
            timestamp = datetime.strptime(f"2025/{timestamp_str}", "%Y/%m/%d-%H:%M:%S.%f")
            
            # Classification
            threat_level = self._classify_threat_level(int(priority), signature, classification)
            attack_category = self._classify_attack_category(signature, classification)
            
            event = SecurityEvent(
                timestamp=timestamp,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=int(src_port),
                dest_port=int(dst_port),
                protocol=protocol.upper(),
                signature=signature.strip(),
                severity=int(priority),
                category=classification,
                raw_log=log_line,
                threat_level=threat_level,
                attack_category=attack_category,
                confidence=self._calculate_confidence({'signature': signature}, src_ip, dst_ip)
            )
            
            return event
            
        except Exception as e:
            logger.debug(f"Erreur parsing Snort: {e}")
            return None

    def _classify_threat_level(self, severity: int, signature: str, category: str) -> ThreatLevel:
        """Classification niveau de menace"""
        signature_lower = signature.lower()
        category_lower = category.lower()
        
        # Mots-clés critiques
        critical_keywords = ['exploit', 'backdoor', 'trojan', 'botnet', 'ransomware', 'apt']
        high_keywords = ['malware', 'brute', 'injection', 'overflow', 'shellcode']
        medium_keywords = ['scan', 'probe', 'reconnaissance', 'suspicious']
        
        # Vérification threat intelligence
        if any(keyword in signature_lower for keyword in critical_keywords):
            return ThreatLevel.CRITICAL
        elif severity <= 1:
            return ThreatLevel.CRITICAL
        elif any(keyword in signature_lower for keyword in high_keywords) or severity <= 2:
            return ThreatLevel.HIGH
        elif any(keyword in signature_lower for keyword in medium_keywords) or severity <= 3:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _classify_attack_category(self, signature: str, category: str) -> Optional[AttackCategory]:
        """Classification catégorie d'attaque selon MITRE ATT&CK"""
        sig_lower = signature.lower()
        cat_lower = category.lower()
        
        # Mapping patterns -> catégories MITRE ATT&CK
        mappings = {
            AttackCategory.RECONNAISSANCE: ['scan', 'probe', 'reconnaissance', 'enumeration'],
            AttackCategory.INITIAL_ACCESS: ['exploit', 'phishing', 'spearphishing', 'watering'],
            AttackCategory.EXECUTION: ['shell', 'command', 'powershell', 'script'],
            AttackCategory.PERSISTENCE: ['backdoor', 'implant', 'startup', 'service'],
            AttackCategory.PRIVILEGE_ESCALATION: ['escalation', 'privilege', 'elevation', 'admin'],
            AttackCategory.DEFENSE_EVASION: ['evasion', 'obfuscation', 'packing', 'encoding'],
            AttackCategory.CREDENTIAL_ACCESS: ['brute', 'credential', 'password', 'hash', 'kerberos'],
            AttackCategory.DISCOVERY: ['discovery', 'enumeration', 'network', 'system'],
            AttackCategory.LATERAL_MOVEMENT: ['lateral', 'movement', 'smb', 'rdp', 'wmi'],
            AttackCategory.COLLECTION: ['collection', 'keylog', 'screenshot', 'audio'],
            AttackCategory.COMMAND_CONTROL: ['c2', 'command', 'control', 'beacon', 'tunnel'],
            AttackCategory.EXFILTRATION: ['exfiltration', 'data', 'transfer', 'upload'],
            AttackCategory.IMPACT: ['impact', 'destruction', 'defacement', 'dos', 'ddos']
        }
        
        for category, keywords in mappings.items():
            if any(keyword in sig_lower or keyword in cat_lower for keyword in keywords):
                return category
                
        return None

    def _calculate_confidence(self, alert_data: Dict, src_ip: str, dest_ip: str) -> float:
        """Calcul score de confiance"""
        confidence = 0.5  # Base confidence
        
        # Boost si IP dans threat intel
        if src_ip in self.threat_intel['malicious_ips']:
            confidence += 0.3
            
        # Boost si signature connue
        signature = alert_data.get('signature', '')
        if signature in self.threat_intel['known_signatures']:
            confidence += 0.2
            
        # Boost si communication interne -> externe
        if self._is_internal_ip(src_ip) and not self._is_internal_ip(dest_ip):
            confidence += 0.1
            
        # Boost si métadonnées riches
        if alert_data.get('payload') or alert_data.get('http'):
            confidence += 0.1
            
        return min(confidence, 1.0)

    def _extract_context(self, event_data: Dict) -> Dict[str, Any]:
        """Extraction contexte enrichi"""
        context = {}
        
        # Informations HTTP
        if 'http' in event_data:
            http = event_data['http']
            context['http'] = {
                'hostname': http.get('hostname'),
                'uri': http.get('uri'),
                'user_agent': http.get('http_user_agent'),
                'method': http.get('http_method'),
                'status': http.get('status')
            }
        
        # Informations DNS
        if 'dns' in event_data:
            dns = event_data['dns']
            context['dns'] = {
                'query': dns.get('query'),
                'type': dns.get('type'),
                'answer': dns.get('answer')
            }
            
        # Informations TLS
        if 'tls' in event_data:
            tls = event_data['tls']
            context['tls'] = {
                'sni': tls.get('sni'),
                'version': tls.get('version'),
                'ja3': tls.get('ja3', {}).get('hash')
            }
            
        # GeoIP enrichment
        if self.geoip_reader:
            try:
                src_geo = self.geoip_reader.city(event_data.get('src_ip', ''))
                context['src_geo'] = {
                    'country': src_geo.country.name,
                    'city': src_geo.city.name,
                    'lat': float(src_geo.location.latitude) if src_geo.location.latitude else None,
                    'lon': float(src_geo.location.longitude) if src_geo.location.longitude else None
                }
            except:
                pass
                
        return context

    def _is_internal_ip(self, ip: str) -> bool:
        """Vérification IP interne"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    def correlate_events(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Corrélation d'événements"""
        correlated_incidents = []
        
        for rule in self.correlation_rules:
            incidents = self._apply_correlation_rule(events, rule)
            correlated_incidents.extend(incidents)
            
        return correlated_incidents

    def _apply_correlation_rule(self, events: List[SecurityEvent], rule: Dict) -> List[Dict[str, Any]]:
        """Application règle de corrélation"""
        incidents = []
        grouped_events = defaultdict(list)
        
        # Groupement des événements selon les conditions
        for event in events:
            if self._event_matches_conditions(event, rule['conditions']):
                # Groupement par source IP (ou autre critère)
                key = event.source_ip
                grouped_events[key].append(event)
        
        # Vérification seuils
        for group_key, group_events in grouped_events.items():
            if len(group_events) >= rule['threshold']:
                # Vérification fenêtre temporelle
                time_window = timedelta(seconds=rule['window'])
                recent_events = [
                    e for e in group_events
                    if datetime.now() - e.timestamp <= time_window
                ]
                
                if len(recent_events) >= rule['threshold']:
                    incident = {
                        'rule_name': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'events_count': len(recent_events),
                        'timespan': {
                            'start': min(e.timestamp for e in recent_events),
                            'end': max(e.timestamp for e in recent_events)
                        },
                        'source_ips': list(set(e.source_ip for e in recent_events)),
                        'dest_ips': list(set(e.dest_ip for e in recent_events)),
                        'signatures': list(set(e.signature for e in recent_events)),
                        'confidence': np.mean([e.confidence for e in recent_events]),
                        'events': [self._serialize_event(e) for e in recent_events]
                    }
                    incidents.append(incident)
        
        return incidents

    def _event_matches_conditions(self, event: SecurityEvent, conditions: List[Dict]) -> bool:
        """Vérification si événement correspond aux conditions"""
        for condition in conditions:
            field = condition['field']
            operator = condition['operator']
            value = condition.get('value')
            
            event_value = getattr(event, field, None)
            if event_value is None:
                continue
                
            if operator == 'in' and event_value not in value:
                return False
            elif operator == 'contains' and not any(v in str(event_value).lower() for v in value):
                return False
            elif operator == 'internal' and not self._is_internal_ip(event_value):
                return False
            elif operator == 'external' and self._is_internal_ip(event_value):
                return False
                
        return True

    def _serialize_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Sérialisation événement pour JSON"""
        return {
            'timestamp': event.timestamp.isoformat(),
            'source_ip': event.source_ip,
            'dest_ip': event.dest_ip,
            'source_port': event.source_port,
            'dest_port': event.dest_port,
            'protocol': event.protocol,
            'signature': event.signature,
            'severity': event.severity,
            'category': event.category,
            'threat_level': event.threat_level.value,
            'attack_category': event.attack_category.value if event.attack_category else None,
            'confidence': event.confidence,
            'context': event.context
        }

    def generate_alert(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Génération alerte formatée"""
        alert_id = f"IDS_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(incident)) % 10000:04d}"
        
        alert = {
            'id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'title': f"{incident['rule_name']}: {incident['description']}",
            'severity': incident['severity'].value,
            'confidence': incident['confidence'],
            'source': 'IDS/IPS Analyzer',
            'details': {
                'rule': incident['rule_name'],
                'events_count': incident['events_count'],
                'timespan_minutes': (incident['timespan']['end'] - incident['timespan']['start']).total_seconds() / 60,
                'affected_ips': {
                    'sources': incident['source_ips'],
                    'destinations': incident['dest_ips']
                },
                'signatures': incident['signatures']
            },
            'mitre_tactics': self._map_mitre_tactics(incident),
            'recommended_actions': self._generate_recommendations(incident),
            'raw_incident': incident
        }
        
        return alert

    def _map_mitre_tactics(self, incident: Dict) -> List[str]:
        """Mapping tactiques MITRE ATT&CK"""
        tactics = set()
        
        rule_name = incident['rule_name'].lower()
        signatures = [sig.lower() for sig in incident['signatures']]
        
        # Mapping basique
        if 'brute_force' in rule_name or any('brute' in sig for sig in signatures):
            tactics.add('TA0006')  # Credential Access
            
        if 'port_scan' in rule_name or any('scan' in sig for sig in signatures):
            tactics.add('TA0007')  # Discovery
            
        if 'lateral_movement' in rule_name or any('lateral' in sig for sig in signatures):
            tactics.add('TA0008')  # Lateral Movement
            
        if 'exfiltration' in rule_name or any('exfil' in sig for sig in signatures):
            tactics.add('TA0010')  # Exfiltration
            
        return list(tactics)

    def _generate_recommendations(self, incident: Dict) -> List[str]:
        """Génération recommandations"""
        recommendations = []
        
        rule_name = incident['rule_name']
        severity = incident['severity']
        
        if rule_name == 'brute_force_detection':
            recommendations.extend([
                "Bloquer temporairement les IPs sources",
                "Vérifier l'intégrité des comptes ciblés",
                "Renforcer les politiques de mots de passe",
                "Activer l'authentification multi-facteurs"
            ])
            
        elif rule_name == 'port_scan_detection':
            recommendations.extend([
                "Analyser les services exposés sur les ports scannés",
                "Vérifier les logs firewall pour le blocage",
                "Considérer le blocage de l'IP source",
                "Surveiller les tentatives de connexion ultérieures"
            ])
            
        elif rule_name == 'lateral_movement':
            recommendations.extend([
                "URGENT: Isoler les machines compromises",
                "Réinitialiser les mots de passe des comptes de service",
                "Auditer les connexions administratives récentes",
                "Déployer des sondes de détection supplémentaires"
            ])
            
        elif rule_name == 'data_exfiltration':
            recommendations.extend([
                "CRITIQUE: Bloquer immédiatement les communications externes",
                "Identifier les données potentiellement compromises", 
                "Notifier l'équipe de réponse aux incidents",
                "Préserver les preuves forensiques"
            ])
        
        # Recommandations générales selon sévérité
        if severity == ThreatLevel.CRITICAL:
            recommendations.append("🚨 ACTIVAR PLAN DE RÉPONSE AUX INCIDENTS")
            
        return recommendations

    def run_analysis(self, log_files: List[str], real_time: bool = False):
        """Exécution analyse principale"""
        logger.info(f"🚀 Démarrage analyse - Mode: {'temps réel' if real_time else 'batch'}")
        
        self.running = True
        
        try:
            if real_time:
                self._run_realtime_analysis(log_files)
            else:
                self._run_batch_analysis(log_files)
        except KeyboardInterrupt:
            logger.info("⚠️ Analyse interrompue par l'utilisateur")
        except Exception as e:
            logger.error(f"❌ Erreur analyse: {e}")
        finally:
            self.running = False
            self._print_final_stats()

    def _run_batch_analysis(self, log_files: List[str]):
        """Analyse batch des fichiers de logs"""
        all_events = []
        
        for log_file in log_files:
            logger.info(f"📂 Traitement fichier: {log_file}")
            events = self._process_log_file(log_file)
            all_events.extend(events)
            
        logger.info(f"📊 {len(all_events)} événements collectés")
        
        # Corrélation
        incidents = self.correlate_events(all_events)
        logger.info(f"🔍 {len(incidents)} incidents corrélés")
        
        # Génération alertes
        alerts = []
        for incident in incidents:
            if incident['confidence'] >= self.config['analysis']['min_confidence']:
                alert = self.generate_alert(incident)
                alerts.append(alert)
                self._output_alert(alert)
                
        self.stats['alerts_generated'] = len(alerts)
        self.stats['threats_detected'] = len([a for a in alerts if a['severity'] in ['critical', 'high']])

    def _run_realtime_analysis(self, log_files: List[str]):
        """Analyse temps réel avec tail -f"""
        import subprocess
        import select
        
        processes = []
        
        # Lancement tail -f pour chaque fichier
        for log_file in log_files:
            if Path(log_file).exists():
                proc = subprocess.Popen(
                    ['tail', '-F', log_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                processes.append((proc, log_file))
                logger.info(f"👀 Surveillance temps réel: {log_file}")
        
        if not processes:
            logger.error("❌ Aucun fichier de log accessible")
            return
            
        buffer_events = []
        last_correlation = time.time()
        
        try:
            while self.running:
                # Lecture non-bloquante
                ready_procs = []
                for proc, filename in processes:
                    if select.select([proc.stdout], [], [], 0.1)[0]:
                        ready_procs.append((proc, filename))
                
                # Traitement nouvelles lignes
                for proc, filename in ready_procs:
                    line = proc.stdout.readline()
                    if line:
                        event = self._parse_log_line(line.strip(), filename)
                        if event and event.confidence >= self.config['analysis']['min_confidence']:
                            buffer_events.append(event)
                            self.stats['events_processed'] += 1
                
                # Corrélation périodique
                if time.time() - last_correlation >= 30:  # Toutes les 30 secondes
                    if buffer_events:
                        incidents = self.correlate_events(buffer_events)
                        
                        for incident in incidents:
                            alert = self.generate_alert(incident)
                            self._output_alert(alert)
                            self.stats['alerts_generated'] += 1
                            
                            if alert['severity'] in ['critical', 'high']:
                                self.stats['threats_detected'] += 1
                        
                        # Nettoyage buffer (garder seulement événements récents)
                        cutoff = datetime.now() - timedelta(seconds=self.config['analysis']['correlation_window'])
                        buffer_events = [e for e in buffer_events if e.timestamp >= cutoff]
                        
                    last_correlation = time.time()
                    self._print_realtime_stats()
                    
        finally:
            # Nettoyage processus
            for proc, _ in processes:
                proc.terminate()

    def _process_log_file(self, log_file: str) -> List[SecurityEvent]:
        """Traitement fichier de log"""
        events = []
        
        try:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        event = self._parse_log_line(line.strip(), log_file)
                        if event:
                            events.append(event)
                            self.stats['events_processed'] += 1
                            
                        if line_num % 10000 == 0:
                            logger.info(f"📄 {line_num} lignes traitées")
                            
        except Exception as e:
            logger.error(f"❌ Erreur lecture fichier {log_file}: {e}")
            
        return events

    def _parse_log_line(self, line: str, filename: str) -> Optional[SecurityEvent]:
        """Parse ligne de log selon le type"""
        try:
            # Détection type de log
            if 'suricata' in filename.lower() or line.startswith('{'):
                return self.parse_suricata_event(line)
            elif 'snort' in filename.lower():
                return self.parse_snort_event(line)
            else:
                # Auto-detection
                if line.startswith('{'):
                    return self.parse_suricata_event(line)
                else:
                    return self.parse_snort_event(line)
        except Exception as e:
            logger.debug(f"Erreur parsing ligne: {e}")
            return None

    def _output_alert(self, alert: Dict[str, Any]):
        """Sortie alerte"""
        # Affichage console
        print("\n" + "="*80)
        print(f"🚨 ALERTE IDS/IPS - {alert['severity'].upper()}")
        print("="*80)
        print(f"ID: {alert['id']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Title: {alert['title']}")
        print(f"Confidence: {alert['confidence']:.2f}")
        print(f"Events: {alert['details']['events_count']}")
        print(f"Duration: {alert['details']['timespan_minutes']:.1f} minutes")
        print(f"Sources: {', '.join(alert['details']['affected_ips']['sources'][:5])}")
        print(f"Destinations: {', '.join(alert['details']['affected_ips']['destinations'][:5])}")
        
        print("\n📋 RECOMMANDATIONS:")
        for i, rec in enumerate(alert['recommended_actions'], 1):
            print(f"  {i}. {rec}")
            
        # Sauvegarde JSON
        alert_file = f"/var/log/ids-alerts-{datetime.now().strftime('%Y%m%d')}.json"
        with open(alert_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
            
        # Envoi vers Elasticsearch si disponible
        if self.es:
            try:
                self.es.index(index='ids-alerts', body=alert)
            except Exception as e:
                logger.debug(f"Erreur envoi ES: {e}")

    def _print_realtime_stats(self):
        """Affichage statistiques temps réel"""
        uptime = datetime.now() - self.stats['start_time']
        events_per_min = self.stats['events_processed'] / max(uptime.total_seconds() / 60, 1)
        
        print(f"\n📊 STATS TEMPS RÉEL (Uptime: {uptime})")
        print(f"   Events: {self.stats['events_processed']:,} ({events_per_min:.1f}/min)")
        print(f"   Alerts: {self.stats['alerts_generated']:,}")
        print(f"   Threats: {self.stats['threats_detected']:,}")

    def _print_final_stats(self):
        """Affichage statistiques finales"""
        uptime = datetime.now() - self.stats['start_time']
        
        print("\n" + "="*60)
        print("📊 STATISTIQUES FINALES D'ANALYSE")
        print("="*60)
        print(f"⏱️  Durée d'analyse       : {uptime}")
        print(f"📄 Événements traités    : {self.stats['events_processed']:,}")
        print(f"🚨 Alertes générées      : {self.stats['alerts_generated']:,}")
        print(f"⚠️  Menaces détectées     : {self.stats['threats_detected']:,}")
        print(f"✅ False positives filtr.: {self.stats['false_positives_filtered']:,}")
        
        if self.stats['events_processed'] > 0:
            alert_rate = (self.stats['alerts_generated'] / self.stats['events_processed']) * 100
            print(f"📊 Taux d'alerte         : {alert_rate:.2f}%")


def main():
    parser = argparse.ArgumentParser(
        description="Analyseur IDS/IPS avec corrélation d'événements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Analyse batch
  python3 ids-log-analyzer.py /var/log/suricata/eve.json /var/log/snort/alert.fast
  
  # Analyse temps réel
  python3 ids-log-analyzer.py --real-time /var/log/suricata/eve.json
  
  # Configuration personnalisée
  python3 ids-log-analyzer.py --config analyzer.json --real-time /var/log/suricata/eve.json
        """
    )
    
    parser.add_argument('log_files', nargs='+', help='Fichiers de logs IDS/IPS à analyser')
    parser.add_argument('--config', '-c', help='Fichier de configuration JSON')
    parser.add_argument('--real-time', '-r', action='store_true', help='Mode temps réel')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Vérification fichiers
    for log_file in args.log_files:
        if not Path(log_file).exists():
            logger.error(f"❌ Fichier non trouvé: {log_file}")
            return 1
    
    # Analyse
    analyzer = IDSLogAnalyzer(args.config)
    analyzer.run_analysis(args.log_files, args.real_time)
    
    return 0

if __name__ == "__main__":
    import sys
    try:
        import numpy as np
    except ImportError:
        print("Installation requise: pip3 install numpy")
        sys.exit(1)
        
    sys.exit(main())