#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Timeline Analyzer - Forensic Analysis Toolkit
============================================================================
Moteur de corrélation temporelle des événements forensiques :
- Agrégation des timelines de tous les analyseurs (Disk, Memory, Network, Mobile)
- Corrélation temporelle et détection de patterns
- Visualisations chronologiques avancées
- Détection d'anomalies temporelles et clustering
- Export de rapports de chronologie forensique
- Analyse de causalité et reconstruction des incidents

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import pandas as pd
import numpy as np
from collections import defaultdict
import re

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types d'événements forensiques supportés"""
    FILE_SYSTEM = "File System"
    PROCESS = "Process"
    NETWORK = "Network"
    REGISTRY = "Registry"
    MEMORY = "Memory"
    SMS = "SMS"
    CALL = "Call"
    LOCATION = "Location"
    BROWSER = "Browser"
    APPLICATION = "Application"
    SYSTEM_LOG = "System Log"
    SECURITY = "Security"
    USER_ACTION = "User Action"
    MALWARE = "Malware"
    DELETED_FILE = "Deleted File"


class EventSeverity(Enum):
    """Niveaux de sévérité des événements"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class CorrelationType(Enum):
    """Types de corrélations temporelles"""
    SEQUENTIAL = "Sequential"  # Événements consécutifs
    SIMULTANEOUS = "Simultaneous"  # Événements simultanés
    PERIODIC = "Periodic"  # Événements répétitifs
    CAUSAL = "Causal"  # Relation de cause à effet
    ANOMALOUS = "Anomalous"  # Comportement anormal


@dataclass
class TimelineEvent:
    """Événement dans la timeline forensique"""
    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str  # Disk, Memory, Network, Mobile
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: EventSeverity = EventSeverity.INFORMATIONAL
    confidence: float = 1.0  # Confiance dans l'événement (0.0-1.0)
    tags: List[str] = field(default_factory=list)
    case_id: str = ""
    hash_value: Optional[str] = None
    file_path: Optional[str] = None
    process_id: Optional[int] = None
    user_account: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None


@dataclass
class CorrelationCluster:
    """Cluster d'événements corrélés"""
    cluster_id: str
    events: List[TimelineEvent]
    correlation_type: CorrelationType
    time_window: Tuple[datetime, datetime]
    confidence_score: float
    description: str
    tags: List[str] = field(default_factory=list)
    severity: EventSeverity = EventSeverity.INFORMATIONAL


@dataclass
class TemporalAnomaly:
    """Anomalie temporelle détectée"""
    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    description: str
    baseline_pattern: str
    deviation_score: float
    affected_events: List[str]  # IDs des événements affectés
    recommendations: List[str] = field(default_factory=list)


class TimelineAggregator:
    """
    Agrégateur de timelines depuis différents analyseurs forensiques
    """
    
    def __init__(self, evidence_dir: str = "./evidence"):
        """
        Initialise l'agrégateur de timelines
        
        Args:
            evidence_dir: Répertoire contenant les bases de données des analyseurs
        """
        self.evidence_dir = Path(evidence_dir)
        self.events = []
        self.case_id = None
        
        # Mappings des bases de données des analyseurs
        self.db_mappings = {
            "disk": "disk_analysis.db",
            "memory": "memory_analysis.db", 
            "network": "network_analysis.db",
            "mobile": "mobile_analysis.db"
        }
    
    def load_timeline_from_disk_analyzer(self, case_id: str) -> List[TimelineEvent]:
        """Charge la timeline depuis l'analyseur disque"""
        events = []
        
        try:
            db_path = self.evidence_dir / self.db_mappings["disk"]
            if not db_path.exists():
                return events
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Événements du système de fichiers
            cursor.execute("""
                SELECT timestamp, file_path, action, hash_md5, file_size
                FROM file_timeline 
                WHERE case_id = ?
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                if row[0]:  # Si timestamp existe
                    event = TimelineEvent(
                        event_id=f"disk_fs_{len(events)}",
                        timestamp=datetime.fromisoformat(row[0]),
                        event_type=EventType.FILE_SYSTEM,
                        source="Disk Analyzer",
                        description=f"File {row[2]}: {row[1]}",
                        details={
                            "action": row[2],
                            "file_size": row[4],
                            "hash_md5": row[3]
                        },
                        file_path=row[1],
                        hash_value=row[3],
                        case_id=case_id
                    )
                    events.append(event)
            
            # Événements des fichiers supprimés
            cursor.execute("""
                SELECT deleted_time, original_path, recovery_status
                FROM deleted_files 
                WHERE case_id = ? AND deleted_time IS NOT NULL
                ORDER BY deleted_time
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"disk_del_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.DELETED_FILE,
                    source="Disk Analyzer",
                    description=f"File deleted: {row[1]}",
                    details={"recovery_status": row[2]},
                    severity=EventSeverity.MEDIUM,
                    file_path=row[1],
                    case_id=case_id
                )
                events.append(event)
            
            conn.close()
            logger.info(f"Chargé {len(events)} événements depuis Disk Analyzer")
            
        except Exception as e:
            logger.error(f"Erreur chargement timeline disk: {e}")
        
        return events
    
    def load_timeline_from_memory_analyzer(self, case_id: str) -> List[TimelineEvent]:
        """Charge la timeline depuis l'analyseur mémoire"""
        events = []
        
        try:
            db_path = self.evidence_dir / self.db_mappings["memory"]
            if not db_path.exists():
                return events
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Événements des processus
            cursor.execute("""
                SELECT start_time, process_name, pid, command_line, exit_time
                FROM memory_processes 
                WHERE case_id = ? AND start_time IS NOT NULL
                ORDER BY start_time
            """, (case_id,))
            
            for row in cursor.fetchall():
                # Événement de démarrage du processus
                start_event = TimelineEvent(
                    event_id=f"mem_proc_start_{row[2]}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.PROCESS,
                    source="Memory Analyzer",
                    description=f"Process started: {row[1]} (PID: {row[2]})",
                    details={
                        "command_line": row[3],
                        "action": "started"
                    },
                    process_id=row[2],
                    case_id=case_id
                )
                events.append(start_event)
                
                # Événement de fin du processus si disponible
                if row[4]:
                    end_event = TimelineEvent(
                        event_id=f"mem_proc_end_{row[2]}",
                        timestamp=datetime.fromisoformat(row[4]),
                        event_type=EventType.PROCESS,
                        source="Memory Analyzer",
                        description=f"Process ended: {row[1]} (PID: {row[2]})",
                        details={
                            "command_line": row[3],
                            "action": "ended"
                        },
                        process_id=row[2],
                        case_id=case_id
                    )
                    events.append(end_event)
            
            # Événements des connexions réseau
            cursor.execute("""
                SELECT timestamp, local_addr, remote_addr, process_name, state
                FROM memory_network_connections 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"mem_net_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.NETWORK,
                    source="Memory Analyzer",
                    description=f"Network connection: {row[1]} -> {row[2]} ({row[4]})",
                    details={
                        "process": row[3],
                        "state": row[4]
                    },
                    case_id=case_id
                )
                events.append(event)
            
            conn.close()
            logger.info(f"Chargé {len(events)} événements depuis Memory Analyzer")
            
        except Exception as e:
            logger.error(f"Erreur chargement timeline memory: {e}")
        
        return events
    
    def load_timeline_from_network_analyzer(self, case_id: str) -> List[TimelineEvent]:
        """Charge la timeline depuis l'analyseur réseau"""
        events = []
        
        try:
            db_path = self.evidence_dir / self.db_mappings["network"]
            if not db_path.exists():
                return events
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Événements des connexions réseau
            cursor.execute("""
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, bytes_transferred
                FROM network_flows 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"net_flow_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.NETWORK,
                    source="Network Analyzer",
                    description=f"Network flow: {row[1]}:{row[4]} -> {row[2]}:{row[5]} ({row[3]})",
                    details={
                        "protocol": row[3],
                        "bytes_transferred": row[6]
                    },
                    ip_address=row[1],
                    port=row[4],
                    case_id=case_id
                )
                events.append(event)
            
            # Événements des requêtes DNS
            cursor.execute("""
                SELECT timestamp, query_name, query_type, response_ip, is_suspicious
                FROM dns_queries 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                severity = EventSeverity.HIGH if row[4] else EventSeverity.LOW
                event = TimelineEvent(
                    event_id=f"net_dns_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.NETWORK,
                    source="Network Analyzer",
                    description=f"DNS query: {row[1]} ({row[2]}) -> {row[3]}",
                    details={
                        "query_type": row[2],
                        "response_ip": row[3],
                        "suspicious": row[4]
                    },
                    severity=severity,
                    tags=["suspicious", "dns"] if row[4] else ["dns"],
                    case_id=case_id
                )
                events.append(event)
            
            conn.close()
            logger.info(f"Chargé {len(events)} événements depuis Network Analyzer")
            
        except Exception as e:
            logger.error(f"Erreur chargement timeline network: {e}")
        
        return events
    
    def load_timeline_from_mobile_analyzer(self, case_id: str) -> List[TimelineEvent]:
        """Charge la timeline depuis l'analyseur mobile"""
        events = []
        
        try:
            db_path = self.evidence_dir / self.db_mappings["mobile"]
            if not db_path.exists():
                return events
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Événements SMS
            cursor.execute("""
                SELECT timestamp, address, body, message_type
                FROM sms_messages 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"mobile_sms_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.SMS,
                    source="Mobile Analyzer",
                    description=f"SMS {row[3]}: {row[1]}",
                    details={
                        "body": row[2][:100] + "..." if len(row[2]) > 100 else row[2],
                        "type": row[3]
                    },
                    case_id=case_id
                )
                events.append(event)
            
            # Événements d'appels
            cursor.execute("""
                SELECT timestamp, phone_number, call_type, duration
                FROM call_records 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"mobile_call_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.CALL,
                    source="Mobile Analyzer",
                    description=f"Call {row[2]}: {row[1]} ({row[3]}s)",
                    details={
                        "call_type": row[2],
                        "duration": row[3]
                    },
                    case_id=case_id
                )
                events.append(event)
            
            # Événements de géolocalisation
            cursor.execute("""
                SELECT timestamp, latitude, longitude, provider, source_app
                FROM location_points 
                WHERE case_id = ? AND timestamp IS NOT NULL
                ORDER BY timestamp
            """, (case_id,))
            
            for row in cursor.fetchall():
                event = TimelineEvent(
                    event_id=f"mobile_loc_{len(events)}",
                    timestamp=datetime.fromisoformat(row[0]),
                    event_type=EventType.LOCATION,
                    source="Mobile Analyzer",
                    description=f"Location: {row[1]:.6f}, {row[2]:.6f} ({row[3]})",
                    details={
                        "latitude": row[1],
                        "longitude": row[2],
                        "provider": row[3],
                        "source_app": row[4]
                    },
                    case_id=case_id
                )
                events.append(event)
            
            conn.close()
            logger.info(f"Chargé {len(events)} événements depuis Mobile Analyzer")
            
        except Exception as e:
            logger.error(f"Erreur chargement timeline mobile: {e}")
        
        return events
    
    def aggregate_all_timelines(self, case_id: str) -> List[TimelineEvent]:
        """
        Agrège toutes les timelines des analyseurs
        
        Args:
            case_id: Identifiant du cas
            
        Returns:
            Liste d'événements fusionnés et triés
        """
        self.case_id = case_id
        all_events = []
        
        # Chargement depuis tous les analyseurs
        logger.info("Agrégation des timelines depuis tous les analyseurs...")
        
        all_events.extend(self.load_timeline_from_disk_analyzer(case_id))
        all_events.extend(self.load_timeline_from_memory_analyzer(case_id))
        all_events.extend(self.load_timeline_from_network_analyzer(case_id))
        all_events.extend(self.load_timeline_from_mobile_analyzer(case_id))
        
        # Tri par timestamp
        all_events.sort(key=lambda x: x.timestamp)
        
        # Suppression des doublons basée sur contenu
        unique_events = self._remove_duplicate_events(all_events)
        
        self.events = unique_events
        logger.info(f"Timeline agrégée: {len(unique_events)} événements uniques")
        
        return unique_events
    
    def _remove_duplicate_events(self, events: List[TimelineEvent]) -> List[TimelineEvent]:
        """Supprime les événements en double"""
        unique_events = []
        seen_hashes = set()
        
        for event in events:
            # Hash basé sur timestamp + description + source
            event_hash = f"{event.timestamp.isoformat()}_{event.description}_{event.source}"
            
            if event_hash not in seen_hashes:
                unique_events.append(event)
                seen_hashes.add(event_hash)
        
        return unique_events


class TemporalCorrelator:
    """
    Moteur de corrélation temporelle des événements
    """
    
    def __init__(self, time_window_seconds: int = 300):
        """
        Initialise le corrélateur temporel
        
        Args:
            time_window_seconds: Fenêtre temporelle pour corrélations (défaut: 5 minutes)
        """
        self.time_window = timedelta(seconds=time_window_seconds)
        self.correlation_rules = self._initialize_correlation_rules()
    
    def _initialize_correlation_rules(self) -> Dict[str, Dict]:
        """Initialise les règles de corrélation prédéfinies"""
        return {
            "process_network_correlation": {
                "types": [EventType.PROCESS, EventType.NETWORK],
                "correlation_type": CorrelationType.CAUSAL,
                "description": "Process launching network connections",
                "confidence_boost": 0.2
            },
            "file_modification_process": {
                "types": [EventType.FILE_SYSTEM, EventType.PROCESS],
                "correlation_type": CorrelationType.CAUSAL,
                "description": "Process modifying files",
                "confidence_boost": 0.15
            },
            "malware_activity_cluster": {
                "types": [EventType.PROCESS, EventType.NETWORK, EventType.FILE_SYSTEM],
                "correlation_type": CorrelationType.SIMULTANEOUS,
                "description": "Potential malware activity pattern",
                "confidence_boost": 0.3,
                "tags": ["malware", "suspicious"]
            },
            "mobile_location_communication": {
                "types": [EventType.LOCATION, EventType.SMS, EventType.CALL],
                "correlation_type": CorrelationType.SEQUENTIAL,
                "description": "Communication activities at specific location",
                "confidence_boost": 0.1
            },
            "data_exfiltration_pattern": {
                "types": [EventType.FILE_SYSTEM, EventType.NETWORK],
                "correlation_type": CorrelationType.SEQUENTIAL,
                "description": "File access followed by network transmission",
                "confidence_boost": 0.25,
                "tags": ["exfiltration", "data-loss"]
            }
        }
    
    def find_temporal_correlations(self, events: List[TimelineEvent]) -> List[CorrelationCluster]:
        """
        Trouve les corrélations temporelles entre événements
        
        Args:
            events: Liste des événements à analyser
            
        Returns:
            Liste des clusters de corrélation
        """
        clusters = []
        
        logger.info(f"Recherche corrélations temporelles sur {len(events)} événements...")
        
        # Corrélations basées sur les règles prédéfinies
        for rule_name, rule in self.correlation_rules.items():
            rule_clusters = self._apply_correlation_rule(events, rule_name, rule)
            clusters.extend(rule_clusters)
        
        # Corrélations par similarité temporelle
        similarity_clusters = self._find_similarity_clusters(events)
        clusters.extend(similarity_clusters)
        
        # Corrélations périodiques
        periodic_clusters = self._find_periodic_patterns(events)
        clusters.extend(periodic_clusters)
        
        logger.info(f"Trouvé {len(clusters)} clusters de corrélation")
        return clusters
    
    def _apply_correlation_rule(self, events: List[TimelineEvent], rule_name: str, 
                              rule: Dict) -> List[CorrelationCluster]:
        """Applique une règle de corrélation spécifique"""
        clusters = []
        target_types = rule["types"]
        
        # Grouper les événements par fenêtres temporelles
        for i, base_event in enumerate(events):
            if base_event.event_type not in target_types:
                continue
            
            # Chercher les événements corrélés dans la fenêtre temporelle
            correlated_events = [base_event]
            window_end = base_event.timestamp + self.time_window
            
            for j in range(i + 1, len(events)):
                candidate_event = events[j]
                
                # Sortir si on dépasse la fenêtre temporelle
                if candidate_event.timestamp > window_end:
                    break
                
                # Vérifier si le type d'événement correspond à la règle
                if candidate_event.event_type in target_types:
                    correlated_events.append(candidate_event)
            
            # Créer un cluster si assez d'événements corrélés
            if len(correlated_events) >= len(target_types):
                cluster_id = f"{rule_name}_{base_event.timestamp.strftime('%Y%m%d_%H%M%S')}"
                
                confidence = rule.get("confidence_boost", 0.1) + (len(correlated_events) * 0.05)
                confidence = min(confidence, 1.0)
                
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    events=correlated_events,
                    correlation_type=rule["correlation_type"],
                    time_window=(correlated_events[0].timestamp, correlated_events[-1].timestamp),
                    confidence_score=confidence,
                    description=rule["description"],
                    tags=rule.get("tags", [])
                )
                
                clusters.append(cluster)
        
        return clusters
    
    def _find_similarity_clusters(self, events: List[TimelineEvent]) -> List[CorrelationCluster]:
        """Trouve les clusters basés sur la similarité des événements"""
        clusters = []
        processed_events = set()
        
        for i, base_event in enumerate(events):
            if base_event.event_id in processed_events:
                continue
            
            similar_events = [base_event]
            processed_events.add(base_event.event_id)
            
            # Chercher les événements similaires
            for j in range(i + 1, len(events)):
                candidate_event = events[j]
                
                if candidate_event.event_id in processed_events:
                    continue
                
                # Vérifier la similarité
                if self._are_events_similar(base_event, candidate_event):
                    similar_events.append(candidate_event)
                    processed_events.add(candidate_event.event_id)
            
            # Créer un cluster si plusieurs événements similaires
            if len(similar_events) >= 3:
                cluster_id = f"similarity_{base_event.timestamp.strftime('%Y%m%d_%H%M%S')}"
                
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    events=similar_events,
                    correlation_type=CorrelationType.SIMULTANEOUS,
                    time_window=(similar_events[0].timestamp, similar_events[-1].timestamp),
                    confidence_score=len(similar_events) * 0.1,
                    description=f"Similar {base_event.event_type.value} events pattern",
                    tags=["pattern", "similarity"]
                )
                
                clusters.append(cluster)
        
        return clusters
    
    def _are_events_similar(self, event1: TimelineEvent, event2: TimelineEvent) -> bool:
        """Détermine si deux événements sont similaires"""
        # Même type d'événement
        if event1.event_type != event2.event_type:
            return False
        
        # Fenêtre temporelle
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        if time_diff > self.time_window.total_seconds():
            return False
        
        # Similarité textuelle dans la description
        desc1_words = set(event1.description.lower().split())
        desc2_words = set(event2.description.lower().split())
        
        if len(desc1_words) == 0 or len(desc2_words) == 0:
            return False
        
        intersection = desc1_words.intersection(desc2_words)
        union = desc1_words.union(desc2_words)
        similarity = len(intersection) / len(union)
        
        return similarity > 0.3  # Seuil de similarité 30%
    
    def _find_periodic_patterns(self, events: List[TimelineEvent]) -> List[CorrelationCluster]:
        """Détecte les patterns périodiques dans les événements"""
        clusters = []
        
        # Grouper les événements par type
        events_by_type = defaultdict(list)
        for event in events:
            events_by_type[event.event_type].append(event)
        
        # Analyser chaque type d'événement pour des patterns périodiques
        for event_type, type_events in events_by_type.items():
            if len(type_events) < 5:  # Minimum requis pour pattern périodique
                continue
            
            # Calculer les intervalles entre événements
            intervals = []
            for i in range(len(type_events) - 1):
                interval = (type_events[i + 1].timestamp - type_events[i].timestamp).total_seconds()
                intervals.append(interval)
            
            # Détecter la périodicité
            if self._is_periodic_pattern(intervals):
                cluster_id = f"periodic_{event_type.value}_{type_events[0].timestamp.strftime('%Y%m%d')}"
                
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    events=type_events,
                    correlation_type=CorrelationType.PERIODIC,
                    time_window=(type_events[0].timestamp, type_events[-1].timestamp),
                    confidence_score=0.7,  # Haute confiance pour patterns périodiques
                    description=f"Periodic {event_type.value} pattern detected",
                    tags=["periodic", "pattern", "recurring"]
                )
                
                clusters.append(cluster)
        
        return clusters
    
    def _is_periodic_pattern(self, intervals: List[float]) -> bool:
        """Détermine si une série d'intervalles forme un pattern périodique"""
        if len(intervals) < 4:
            return False
        
        # Calculer la médiane et l'écart-type des intervalles
        intervals_array = np.array(intervals)
        median_interval = np.median(intervals_array)
        std_interval = np.std(intervals_array)
        
        # Seuil de variabilité pour considérer comme périodique
        variability_threshold = 0.3  # 30% de variabilité max
        
        if median_interval == 0:
            return False
        
        coefficient_variation = std_interval / median_interval
        return coefficient_variation < variability_threshold


class AnomalyDetector:
    """
    Détecteur d'anomalies temporelles dans les timelines
    """
    
    def __init__(self):
        """Initialise le détecteur d'anomalies"""
        self.baseline_patterns = {}
        
    def detect_temporal_anomalies(self, events: List[TimelineEvent]) -> List[TemporalAnomaly]:
        """
        Détecte les anomalies temporelles dans les événements
        
        Args:
            events: Liste des événements à analyser
            
        Returns:
            Liste des anomalies détectées
        """
        anomalies = []
        
        logger.info(f"Détection anomalies temporelles sur {len(events)} événements...")
        
        # Détection d'anomalies par type d'événement
        anomalies.extend(self._detect_frequency_anomalies(events))
        anomalies.extend(self._detect_time_gaps(events))
        anomalies.extend(self._detect_burst_activities(events))
        anomalies.extend(self._detect_unusual_sequences(events))
        
        logger.info(f"Détecté {len(anomalies)} anomalies temporelles")
        return anomalies
    
    def _detect_frequency_anomalies(self, events: List[TimelineEvent]) -> List[TemporalAnomaly]:
        """Détecte les anomalies de fréquence d'événements"""
        anomalies = []
        
        # Analyser la fréquence par heure pour chaque type d'événement
        events_by_type_hour = defaultdict(lambda: defaultdict(int))
        
        for event in events:
            hour_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
            events_by_type_hour[event.event_type][hour_key] += 1
        
        # Détecter les anomalies de fréquence
        for event_type, hourly_counts in events_by_type_hour.items():
            if len(hourly_counts) < 5:  # Données insuffisantes
                continue
            
            counts = list(hourly_counts.values())
            mean_count = np.mean(counts)
            std_count = np.std(counts)
            
            # Seuil d'anomalie: 3 écarts-types
            threshold = mean_count + 3 * std_count
            
            for hour, count in hourly_counts.items():
                if count > threshold and count > 10:  # Minimum absolu aussi
                    anomaly_id = f"freq_{event_type.value}_{hour.strftime('%Y%m%d_%H')}"
                    
                    anomaly = TemporalAnomaly(
                        anomaly_id=anomaly_id,
                        timestamp=hour,
                        anomaly_type="Frequency Spike",
                        description=f"Unusual spike in {event_type.value} events: {count} vs normal {mean_count:.1f}",
                        baseline_pattern=f"Normal: {mean_count:.1f} ± {std_count:.1f} events/hour",
                        deviation_score=(count - mean_count) / std_count,
                        affected_events=[],
                        recommendations=[
                            "Investigate the root cause of increased activity",
                            "Check for automated scripts or malware activity",
                            "Verify system load and performance metrics"
                        ]
                    )
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_time_gaps(self, events: List[TimelineEvent]) -> List[TemporalAnomaly]:
        """Détecte les lacunes temporelles suspectes"""
        anomalies = []
        
        if len(events) < 2:
            return anomalies
        
        # Calculer les intervalles entre événements consécutifs
        intervals = []
        for i in range(len(events) - 1):
            interval = (events[i + 1].timestamp - events[i].timestamp).total_seconds()
            intervals.append((interval, events[i], events[i + 1]))
        
        # Statistiques des intervalles
        interval_values = [interval[0] for interval in intervals]
        mean_interval = np.mean(interval_values)
        std_interval = np.std(interval_values)
        
        # Détecter les lacunes anormalement longues
        gap_threshold = mean_interval + 4 * std_interval  # 4 écarts-types
        
        for interval, event1, event2 in intervals:
            if interval > gap_threshold and interval > 3600:  # Plus d'1 heure
                anomaly_id = f"gap_{event1.timestamp.strftime('%Y%m%d_%H%M%S')}"
                
                anomaly = TemporalAnomaly(
                    anomaly_id=anomaly_id,
                    timestamp=event1.timestamp,
                    anomaly_type="Time Gap",
                    description=f"Unusual time gap: {interval/3600:.1f} hours between events",
                    baseline_pattern=f"Normal interval: {mean_interval/60:.1f} minutes",
                    deviation_score=(interval - mean_interval) / std_interval,
                    affected_events=[event1.event_id, event2.event_id],
                    recommendations=[
                        "Verify if system was powered off or disconnected",
                        "Check for log tampering or deletion",
                        "Investigate potential anti-forensic activities"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_burst_activities(self, events: List[TimelineEvent]) -> List[TemporalAnomaly]:
        """Détecte les rafales d'activité suspecte"""
        anomalies = []
        
        # Analyser les événements par fenêtres de 5 minutes
        window_size = timedelta(minutes=5)
        window_events = defaultdict(list)
        
        for event in events:
            window_start = event.timestamp.replace(minute=(event.timestamp.minute // 5) * 5, second=0, microsecond=0)
            window_events[window_start].append(event)
        
        # Détecter les rafales
        event_counts = [len(events_in_window) for events_in_window in window_events.values()]
        
        if len(event_counts) < 5:
            return anomalies
        
        mean_count = np.mean(event_counts)
        std_count = np.std(event_counts)
        burst_threshold = mean_count + 3 * std_count
        
        for window_start, events_in_window in window_events.items():
            if len(events_in_window) > burst_threshold and len(events_in_window) > 20:
                anomaly_id = f"burst_{window_start.strftime('%Y%m%d_%H%M')}"
                
                anomaly = TemporalAnomaly(
                    anomaly_id=anomaly_id,
                    timestamp=window_start,
                    anomaly_type="Activity Burst",
                    description=f"Burst of {len(events_in_window)} events in 5-minute window",
                    baseline_pattern=f"Normal: {mean_count:.1f} events per 5-minute window",
                    deviation_score=(len(events_in_window) - mean_count) / std_count,
                    affected_events=[e.event_id for e in events_in_window],
                    recommendations=[
                        "Investigate rapid succession of activities",
                        "Check for automated attacks or scripts",
                        "Verify system performance during burst period"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_sequences(self, events: List[TimelineEvent]) -> List[TemporalAnomaly]:
        """Détecte les séquences d'événements inhabituelles"""
        anomalies = []
        
        # Analyser les séquences de 3 événements consécutifs
        for i in range(len(events) - 2):
            sequence = events[i:i+3]
            
            # Vérifier si la séquence est suspecte
            if self._is_suspicious_sequence(sequence):
                anomaly_id = f"seq_{sequence[0].timestamp.strftime('%Y%m%d_%H%M%S')}"
                
                types_str = " -> ".join([e.event_type.value for e in sequence])
                
                anomaly = TemporalAnomaly(
                    anomaly_id=anomaly_id,
                    timestamp=sequence[0].timestamp,
                    anomaly_type="Unusual Sequence",
                    description=f"Suspicious event sequence: {types_str}",
                    baseline_pattern="Normal event sequences",
                    deviation_score=0.8,  # Score élevé pour séquences suspectes
                    affected_events=[e.event_id for e in sequence],
                    recommendations=[
                        "Analyze the causal relationship between events",
                        "Check for malicious activity indicators",
                        "Validate the legitimacy of the event sequence"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _is_suspicious_sequence(self, sequence: List[TimelineEvent]) -> bool:
        """Détermine si une séquence d'événements est suspecte"""
        # Patterns suspects connus
        suspicious_patterns = [
            # Suppression de fichier suivie immédiatement de connexion réseau
            [EventType.DELETED_FILE, EventType.NETWORK],
            # Processus -> Modification fichier système -> Connexion réseau
            [EventType.PROCESS, EventType.FILE_SYSTEM, EventType.NETWORK],
            # Activité nocturne inhabituelle
            # (à implémenter selon le contexte)
        ]
        
        sequence_types = [e.event_type for e in sequence]
        
        # Vérifier contre les patterns connus
        for pattern in suspicious_patterns:
            if len(pattern) <= len(sequence_types):
                if sequence_types[:len(pattern)] == pattern:
                    return True
        
        # Vérifier activité nocturne (entre 2h et 6h du matin)
        night_hours = [2, 3, 4, 5]
        if all(e.timestamp.hour in night_hours for e in sequence):
            # Activité nocturne avec certains types d'événements
            suspicious_night_types = [EventType.PROCESS, EventType.NETWORK, EventType.DELETED_FILE]
            if any(e.event_type in suspicious_night_types for e in sequence):
                return True
        
        return False


class TimelineAnalyzer:
    """
    Analyseur principal de timeline forensique avec corrélation et détection d'anomalies
    """
    
    def __init__(self, evidence_dir: str = "./evidence", output_dir: str = "./timeline_analysis"):
        """
        Initialise l'analyseur de timeline
        
        Args:
            evidence_dir: Répertoire contenant les données des analyseurs
            output_dir: Répertoire de sortie pour les résultats
        """
        self.evidence_dir = Path(evidence_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Composants d'analyse
        self.aggregator = TimelineAggregator(evidence_dir)
        self.correlator = TemporalCorrelator()
        self.anomaly_detector = AnomalyDetector()
        
        # Base de données pour sauvegarder les résultats
        self.db_path = self.output_dir / "timeline_analysis.db"
        self._init_database()
    
    def _init_database(self):
        """Initialise la base de données de timeline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des événements de timeline
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                event_id TEXT PRIMARY KEY,
                case_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                source TEXT,
                description TEXT,
                details TEXT,
                severity TEXT,
                confidence REAL,
                tags TEXT,
                file_path TEXT,
                process_id INTEGER,
                ip_address TEXT,
                port INTEGER,
                hash_value TEXT
            )
        ''')
        
        # Table des clusters de corrélation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_clusters (
                cluster_id TEXT PRIMARY KEY,
                case_id TEXT,
                correlation_type TEXT,
                time_window_start TEXT,
                time_window_end TEXT,
                confidence_score REAL,
                description TEXT,
                tags TEXT,
                event_count INTEGER
            )
        ''')
        
        # Table des anomalies temporelles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS temporal_anomalies (
                anomaly_id TEXT PRIMARY KEY,
                case_id TEXT,
                timestamp TEXT,
                anomaly_type TEXT,
                description TEXT,
                baseline_pattern TEXT,
                deviation_score REAL,
                affected_events TEXT,
                recommendations TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_timeline(self, case_id: str) -> Dict[str, Any]:
        """
        Analyse complète de la timeline pour un cas
        
        Args:
            case_id: Identifiant du cas à analyser
            
        Returns:
            Dictionnaire avec tous les résultats d'analyse
        """
        logger.info(f"🕒 Début analyse timeline pour cas: {case_id}")
        
        # 1. Agrégation des timelines
        logger.info("📊 Agrégation des événements depuis tous les analyseurs...")
        events = self.aggregator.aggregate_all_timelines(case_id)
        
        if not events:
            logger.warning("Aucun événement trouvé pour l'analyse")
            return {"events": [], "clusters": [], "anomalies": []}
        
        # 2. Corrélation temporelle
        logger.info("🔗 Recherche de corrélations temporelles...")
        clusters = self.correlator.find_temporal_correlations(events)
        
        # 3. Détection d'anomalies
        logger.info("🚨 Détection d'anomalies temporelles...")
        anomalies = self.anomaly_detector.detect_temporal_anomalies(events)
        
        # 4. Sauvegarde en base de données
        logger.info("💾 Sauvegarde des résultats...")
        self._save_analysis_results(case_id, events, clusters, anomalies)
        
        # 5. Compilation des statistiques
        statistics = self._generate_statistics(events, clusters, anomalies)
        
        results = {
            "case_id": case_id,
            "events": events,
            "clusters": clusters,
            "anomalies": anomalies,
            "statistics": statistics,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"✅ Analyse timeline terminée:")
        logger.info(f"  📅 Événements: {len(events)}")
        logger.info(f"  🔗 Clusters: {len(clusters)}")
        logger.info(f"  🚨 Anomalies: {len(anomalies)}")
        
        return results
    
    def _save_analysis_results(self, case_id: str, events: List[TimelineEvent], 
                             clusters: List[CorrelationCluster], anomalies: List[TemporalAnomaly]):
        """Sauvegarde les résultats d'analyse en base de données"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sauvegarde des événements
        for event in events:
            cursor.execute('''
                INSERT OR REPLACE INTO timeline_events 
                (event_id, case_id, timestamp, event_type, source, description, details,
                 severity, confidence, tags, file_path, process_id, ip_address, port, hash_value)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id, case_id, event.timestamp.isoformat(), event.event_type.value,
                event.source, event.description, json.dumps(event.details, default=str),
                event.severity.value, event.confidence, json.dumps(event.tags),
                event.file_path, event.process_id, event.ip_address, event.port, event.hash_value
            ))
        
        # Sauvegarde des clusters
        for cluster in clusters:
            cursor.execute('''
                INSERT OR REPLACE INTO correlation_clusters 
                (cluster_id, case_id, correlation_type, time_window_start, time_window_end,
                 confidence_score, description, tags, event_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cluster.cluster_id, case_id, cluster.correlation_type.value,
                cluster.time_window[0].isoformat(), cluster.time_window[1].isoformat(),
                cluster.confidence_score, cluster.description, json.dumps(cluster.tags),
                len(cluster.events)
            ))
        
        # Sauvegarde des anomalies
        for anomaly in anomalies:
            cursor.execute('''
                INSERT OR REPLACE INTO temporal_anomalies 
                (anomaly_id, case_id, timestamp, anomaly_type, description, baseline_pattern,
                 deviation_score, affected_events, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                anomaly.anomaly_id, case_id, anomaly.timestamp.isoformat(),
                anomaly.anomaly_type, anomaly.description, anomaly.baseline_pattern,
                anomaly.deviation_score, json.dumps(anomaly.affected_events),
                json.dumps(anomaly.recommendations)
            ))
        
        conn.commit()
        conn.close()
    
    def _generate_statistics(self, events: List[TimelineEvent], 
                           clusters: List[CorrelationCluster], 
                           anomalies: List[TemporalAnomaly]) -> Dict[str, Any]:
        """Génère les statistiques d'analyse"""
        stats = {
            "total_events": len(events),
            "total_clusters": len(clusters),
            "total_anomalies": len(anomalies),
            "time_span": {},
            "events_by_type": {},
            "events_by_source": {},
            "severity_distribution": {},
            "cluster_types": {},
            "anomaly_types": {}
        }
        
        if events:
            # Période d'analyse
            start_time = min(e.timestamp for e in events)
            end_time = max(e.timestamp for e in events)
            stats["time_span"] = {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_hours": (end_time - start_time).total_seconds() / 3600
            }
            
            # Distribution par type d'événement
            type_counts = defaultdict(int)
            for event in events:
                type_counts[event.event_type.value] += 1
            stats["events_by_type"] = dict(type_counts)
            
            # Distribution par source
            source_counts = defaultdict(int)
            for event in events:
                source_counts[event.source] += 1
            stats["events_by_source"] = dict(source_counts)
            
            # Distribution par sévérité
            severity_counts = defaultdict(int)
            for event in events:
                severity_counts[event.severity.value] += 1
            stats["severity_distribution"] = dict(severity_counts)
        
        # Types de clusters
        cluster_type_counts = defaultdict(int)
        for cluster in clusters:
            cluster_type_counts[cluster.correlation_type.value] += 1
        stats["cluster_types"] = dict(cluster_type_counts)
        
        # Types d'anomalies
        anomaly_type_counts = defaultdict(int)
        for anomaly in anomalies:
            anomaly_type_counts[anomaly.anomaly_type] += 1
        stats["anomaly_types"] = dict(anomaly_type_counts)
        
        return stats
    
    def generate_timeline_report(self, case_id: str, format_type: str = 'html') -> str:
        """
        Génère un rapport de timeline
        
        Args:
            case_id: Identifiant du cas
            format_type: Format du rapport (html, json, csv)
            
        Returns:
            Chemin vers le fichier de rapport généré
        """
        logger.info(f"📄 Génération rapport timeline format {format_type}")
        
        # Charger les résultats depuis la base
        conn = sqlite3.connect(self.db_path)
        
        events_df = pd.read_sql_query(
            "SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp",
            conn, params=(case_id,)
        )
        
        clusters_df = pd.read_sql_query(
            "SELECT * FROM correlation_clusters WHERE case_id = ?",
            conn, params=(case_id,)
        )
        
        anomalies_df = pd.read_sql_query(
            "SELECT * FROM temporal_anomalies WHERE case_id = ?",
            conn, params=(case_id,)
        )
        
        conn.close()
        
        # Génération selon le format
        if format_type.lower() == 'html':
            report_path = self._generate_html_report(case_id, events_df, clusters_df, anomalies_df)
        elif format_type.lower() == 'json':
            report_path = self._generate_json_report(case_id, events_df, clusters_df, anomalies_df)
        elif format_type.lower() == 'csv':
            report_path = self._generate_csv_report(case_id, events_df, clusters_df, anomalies_df)
        else:
            raise ValueError(f"Format non supporté: {format_type}")
        
        logger.info(f"📄 Rapport généré: {report_path}")
        return str(report_path)
    
    def _generate_html_report(self, case_id: str, events_df: pd.DataFrame, 
                            clusters_df: pd.DataFrame, anomalies_df: pd.DataFrame) -> Path:
        """Génère un rapport HTML"""
        report_path = self.output_dir / f"timeline_report_{case_id}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Timeline Analysis Report - {case_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .critical {{ background-color: #ffebee; }}
                .high {{ background-color: #fff3e0; }}
                .medium {{ background-color: #f3e5f5; }}
                .low {{ background-color: #e8f5e8; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🕒 Timeline Analysis Report</h1>
                <p>Case ID: {case_id}</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>📊 Summary</h2>
                <p>Total Events: {len(events_df)}</p>
                <p>Correlation Clusters: {len(clusters_df)}</p>
                <p>Temporal Anomalies: {len(anomalies_df)}</p>
            </div>
            
            <div class="section">
                <h2>📅 Timeline Events</h2>
                {events_df.to_html(classes='timeline-table', escape=False) if not events_df.empty else '<p>No events found</p>'}
            </div>
            
            <div class="section">
                <h2>🔗 Correlation Clusters</h2>
                {clusters_df.to_html(classes='clusters-table', escape=False) if not clusters_df.empty else '<p>No clusters found</p>'}
            </div>
            
            <div class="section">
                <h2>🚨 Temporal Anomalies</h2>
                {anomalies_df.to_html(classes='anomalies-table', escape=False) if not anomalies_df.empty else '<p>No anomalies found</p>'}
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_json_report(self, case_id: str, events_df: pd.DataFrame,
                            clusters_df: pd.DataFrame, anomalies_df: pd.DataFrame) -> Path:
        """Génère un rapport JSON"""
        report_path = self.output_dir / f"timeline_report_{case_id}.json"
        
        report_data = {
            "case_id": case_id,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_events": len(events_df),
                "total_clusters": len(clusters_df),
                "total_anomalies": len(anomalies_df)
            },
            "events": events_df.to_dict('records') if not events_df.empty else [],
            "clusters": clusters_df.to_dict('records') if not clusters_df.empty else [],
            "anomalies": anomalies_df.to_dict('records') if not anomalies_df.empty else []
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return report_path
    
    def _generate_csv_report(self, case_id: str, events_df: pd.DataFrame,
                           clusters_df: pd.DataFrame, anomalies_df: pd.DataFrame) -> Path:
        """Génère des rapports CSV"""
        base_path = self.output_dir / f"timeline_report_{case_id}"
        
        # Sauvegarde séparée pour chaque type de données
        if not events_df.empty:
            events_path = f"{base_path}_events.csv"
            events_df.to_csv(events_path, index=False, encoding='utf-8')
        
        if not clusters_df.empty:
            clusters_path = f"{base_path}_clusters.csv"
            clusters_df.to_csv(clusters_path, index=False, encoding='utf-8')
        
        if not anomalies_df.empty:
            anomalies_path = f"{base_path}_anomalies.csv"
            anomalies_df.to_csv(anomalies_path, index=False, encoding='utf-8')
        
        return Path(f"{base_path}_events.csv")
    
    def close(self):
        """Ferme l'analyseur et nettoie les ressources"""
        logger.info("Timeline analyzer fermé")


def main():
    """Fonction de démonstration"""
    print("🕒 Forensic Analysis Toolkit - Timeline Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = TimelineAnalyzer(
        evidence_dir="./evidence",
        output_dir="./timeline_analysis"
    )
    
    case_id = f"TIMELINE_CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Analyse du cas: {case_id}")
    
    try:
        # Analyse complète de la timeline
        print("🔍 Début de l'analyse timeline...")
        results = analyzer.analyze_timeline(case_id)
        
        # Affichage des statistiques
        stats = results["statistics"]
        print("\n📊 Statistiques d'analyse:")
        print(f"  📅 Événements totaux: {stats['total_events']}")
        print(f"  🔗 Clusters de corrélation: {stats['total_clusters']}")
        print(f"  🚨 Anomalies détectées: {stats['total_anomalies']}")
        
        if stats.get("time_span"):
            print(f"  ⏱️  Période analysée: {stats['time_span']['duration_hours']:.1f} heures")
        
        # Distribution par type d'événement
        if stats.get("events_by_type"):
            print("\n📈 Répartition par type d'événement:")
            for event_type, count in stats["events_by_type"].items():
                print(f"  📄 {event_type}: {count}")
        
        # Types de corrélations
        if stats.get("cluster_types"):
            print("\n🔗 Types de corrélations:")
            for cluster_type, count in stats["cluster_types"].items():
                print(f"  🔍 {cluster_type}: {count}")
        
        # Types d'anomalies
        if stats.get("anomaly_types"):
            print("\n🚨 Types d'anomalies:")
            for anomaly_type, count in stats["anomaly_types"].items():
                print(f"  ⚠️  {anomaly_type}: {count}")
        
        # Génération des rapports
        print("\n📄 Génération des rapports...")
        html_report = analyzer.generate_timeline_report(case_id, 'html')
        json_report = analyzer.generate_timeline_report(case_id, 'json')
        
        print(f"📄 Rapport HTML: {html_report}")
        print(f"📄 Rapport JSON: {json_report}")
        
        analyzer.close()
        
    except Exception as e:
        print(f"❌ Erreur durant l'analyse: {e}")
        logger.error(f"Erreur analyse timeline: {e}")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()