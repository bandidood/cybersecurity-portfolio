#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Reporting Engine - Forensic Analysis Toolkit
============================================================================
Moteur de génération de rapports forensiques professionnels :
- Rapports HTML interactifs avec graphiques et tableaux
- Exports PDF avec mise en page professionnelle
- Rapports exécutifs et techniques personnalisés
- Timeline visuelle et graphiques d'analyse
- Templates modulaires et personnalisables
- Intégration de tous les analyseurs (Disk, Memory, Network, Mobile, Crypto, Timeline)
- Métriques de performance et statistiques avancées
- Conformité aux standards forensiques (ACPO, RFC 3227)

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import json
import sqlite3
import logging
import base64
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import jinja2
from jinja2 import Template
import hashlib

# Bibliothèques pour génération de graphiques
try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Rectangle
    import seaborn as sns
    import pandas as pd
    import numpy as np
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

# Bibliothèques pour PDF
try:
    import weasyprint
    from weasyprint import HTML, CSS
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types de rapports forensiques"""
    EXECUTIVE_SUMMARY = "Executive Summary"
    TECHNICAL_DETAILED = "Technical Detailed"
    INVESTIGATION_SUMMARY = "Investigation Summary"
    TIMELINE_ANALYSIS = "Timeline Analysis"
    EVIDENCE_CATALOG = "Evidence Catalog"
    COMPLIANCE_REPORT = "Compliance Report"
    INCIDENT_RESPONSE = "Incident Response"


class ReportFormat(Enum):
    """Formats de sortie des rapports"""
    HTML = "HTML"
    PDF = "PDF"
    JSON = "JSON"
    CSV = "CSV"
    MARKDOWN = "Markdown"


class EvidenceType(Enum):
    """Types de preuves forensiques"""
    DISK_IMAGE = "Disk Image"
    MEMORY_DUMP = "Memory Dump"
    NETWORK_CAPTURE = "Network Capture"
    MOBILE_BACKUP = "Mobile Backup"
    LOG_FILES = "Log Files"
    REGISTRY_HIVE = "Registry Hive"
    BROWSER_ARTIFACTS = "Browser Artifacts"
    EMAIL_ARCHIVES = "Email Archives"


@dataclass
class EvidenceItem:
    """Élément de preuve forensique"""
    evidence_id: str
    name: str
    type: EvidenceType
    file_path: str
    size: int
    hash_md5: str
    hash_sha256: str
    acquisition_date: datetime
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CaseInformation:
    """Informations du cas forensique"""
    case_id: str
    case_name: str
    investigator: str
    organization: str
    case_date: datetime
    incident_type: str
    description: str
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    legal_authorization: Optional[str] = None
    case_status: str = "Active"
    priority_level: str = "Medium"
    contact_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisResults:
    """Résultats d'analyse consolidés"""
    case_id: str
    analysis_date: datetime
    disk_analysis: Dict[str, Any] = field(default_factory=dict)
    memory_analysis: Dict[str, Any] = field(default_factory=dict)
    network_analysis: Dict[str, Any] = field(default_factory=dict)
    mobile_analysis: Dict[str, Any] = field(default_factory=dict)
    crypto_analysis: Dict[str, Any] = field(default_factory=dict)
    timeline_analysis: Dict[str, Any] = field(default_factory=dict)
    correlation_results: Dict[str, Any] = field(default_factory=dict)
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)


class DataAggregator:
    """
    Agrégateur de données depuis tous les analyseurs forensiques
    """
    
    def __init__(self, evidence_dir: str = "./evidence"):
        """
        Initialise l'agrégateur de données
        
        Args:
            evidence_dir: Répertoire contenant les bases de données des analyseurs
        """
        self.evidence_dir = Path(evidence_dir)
        self.db_mappings = {
            "disk": "disk_analysis.db",
            "memory": "memory_analysis.db",
            "network": "network_analysis.db", 
            "mobile": "mobile_analysis.db",
            "crypto": "crypto_analysis.db",
            "timeline": "timeline_analysis.db"
        }
    
    def aggregate_analysis_results(self, case_id: str) -> AnalysisResults:
        """
        Agrège tous les résultats d'analyse pour un cas
        
        Args:
            case_id: Identifiant du cas
            
        Returns:
            Résultats d'analyse consolidés
        """
        results = AnalysisResults(
            case_id=case_id,
            analysis_date=datetime.now(timezone.utc)
        )
        
        # Agrégation des résultats de chaque analyseur
        results.disk_analysis = self._get_disk_analysis(case_id)
        results.memory_analysis = self._get_memory_analysis(case_id)
        results.network_analysis = self._get_network_analysis(case_id)
        results.mobile_analysis = self._get_mobile_analysis(case_id)
        results.crypto_analysis = self._get_crypto_analysis(case_id)
        results.timeline_analysis = self._get_timeline_analysis(case_id)
        
        # Génération des conclusions et recommandations
        results.key_findings = self._generate_key_findings(results)
        results.recommendations = self._generate_recommendations(results)
        results.risk_assessment = self._assess_risk_level(results)
        
        return results
    
    def _get_disk_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse disque"""
        results = {
            "files_analyzed": 0,
            "deleted_files": 0,
            "suspicious_files": 0,
            "malware_detected": 0,
            "timeline_events": 0,
            "total_size": 0,
            "file_types": {},
            "suspicious_activities": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["disk"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques générales
            cursor.execute("SELECT COUNT(*) FROM file_analysis WHERE case_id = ?", (case_id,))
            results["files_analyzed"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM deleted_files WHERE case_id = ?", (case_id,))
            results["deleted_files"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM malware_detections WHERE case_id = ?", (case_id,))
            results["malware_detected"] = cursor.fetchone()[0]
            
            # Activités suspectes
            cursor.execute("""
                SELECT file_path, malware_type, confidence 
                FROM malware_detections 
                WHERE case_id = ? AND confidence > 0.7
                ORDER BY confidence DESC LIMIT 10
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["suspicious_activities"].append({
                    "type": "Malware Detection",
                    "file": row[0],
                    "details": f"{row[1]} (confidence: {row[2]:.1%})"
                })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation disk analysis: {e}")
        
        return results
    
    def _get_memory_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse mémoire"""
        results = {
            "processes_analyzed": 0,
            "network_connections": 0,
            "injected_processes": 0,
            "suspicious_processes": 0,
            "memory_artifacts": 0,
            "credential_artifacts": [],
            "process_anomalies": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["memory"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques des processus
            cursor.execute("SELECT COUNT(*) FROM memory_processes WHERE case_id = ?", (case_id,))
            results["processes_analyzed"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM memory_network_connections WHERE case_id = ?", (case_id,))
            results["network_connections"] = cursor.fetchone()[0]
            
            # Processus suspects
            cursor.execute("""
                SELECT process_name, pid, command_line, suspicious_score
                FROM memory_processes 
                WHERE case_id = ? AND suspicious_score > 0.5
                ORDER BY suspicious_score DESC LIMIT 10
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["process_anomalies"].append({
                    "process": row[0],
                    "pid": row[1],
                    "command": row[2][:100],
                    "score": row[3]
                })
            
            # Artefacts de credentials
            cursor.execute("""
                SELECT artifact_type, username, domain 
                FROM memory_artifacts 
                WHERE case_id = ? AND artifact_type LIKE '%credential%'
                LIMIT 20
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["credential_artifacts"].append({
                    "type": row[0],
                    "username": row[1],
                    "domain": row[2] or "N/A"
                })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation memory analysis: {e}")
        
        return results
    
    def _get_network_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse réseau"""
        results = {
            "total_flows": 0,
            "suspicious_domains": 0,
            "malicious_ips": 0,
            "dns_queries": 0,
            "http_transactions": 0,
            "port_scans_detected": 0,
            "data_exfiltration": [],
            "threat_indicators": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["network"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques réseau
            cursor.execute("SELECT COUNT(*) FROM network_flows WHERE case_id = ?", (case_id,))
            results["total_flows"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM dns_queries WHERE case_id = ?", (case_id,))
            results["dns_queries"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM dns_queries WHERE case_id = ? AND is_suspicious = 1", (case_id,))
            results["suspicious_domains"] = cursor.fetchone()[0]
            
            # Indicateurs de menace
            cursor.execute("""
                SELECT query_name, threat_type, reputation_score 
                FROM dns_queries 
                WHERE case_id = ? AND is_suspicious = 1
                ORDER BY reputation_score DESC LIMIT 10
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["threat_indicators"].append({
                    "type": "Suspicious Domain",
                    "indicator": row[0],
                    "threat_type": row[1],
                    "score": row[2]
                })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation network analysis: {e}")
        
        return results
    
    def _get_mobile_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse mobile"""
        results = {
            "sms_messages": 0,
            "call_records": 0,
            "location_points": 0,
            "installed_apps": 0,
            "browser_history": 0,
            "device_info": {},
            "communication_patterns": [],
            "location_timeline": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["mobile"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques mobile
            cursor.execute("SELECT COUNT(*) FROM sms_messages WHERE case_id = ?", (case_id,))
            results["sms_messages"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM call_records WHERE case_id = ?", (case_id,))
            results["call_records"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM location_points WHERE case_id = ?", (case_id,))
            results["location_points"] = cursor.fetchone()[0]
            
            # Informations du dispositif
            cursor.execute("""
                SELECT device_type, device_model, os_version 
                FROM mobile_analysis 
                WHERE case_id = ? LIMIT 1
            """, (case_id,))
            
            device_row = cursor.fetchone()
            if device_row:
                results["device_info"] = {
                    "type": device_row[0],
                    "model": device_row[1],
                    "os_version": device_row[2]
                }
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation mobile analysis: {e}")
        
        return results
    
    def _get_crypto_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse cryptographique"""
        results = {
            "crypto_artifacts": 0,
            "stegano_artifacts": 0,
            "password_cracks": 0,
            "certificates_analyzed": 0,
            "algorithms_detected": [],
            "successful_cracks": [],
            "high_entropy_files": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["crypto"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques crypto
            cursor.execute("SELECT COUNT(*) FROM crypto_artifacts WHERE case_id = ?", (case_id,))
            results["crypto_artifacts"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM stegano_artifacts WHERE case_id = ?", (case_id,))
            results["stegano_artifacts"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM password_cracks WHERE case_id = ? AND success = 1", (case_id,))
            results["password_cracks"] = cursor.fetchone()[0]
            
            # Algorithmes détectés
            cursor.execute("""
                SELECT DISTINCT algorithm 
                FROM crypto_artifacts 
                WHERE case_id = ?
            """, (case_id,))
            
            results["algorithms_detected"] = [row[0] for row in cursor.fetchall()]
            
            # Mots de passe craqués
            cursor.execute("""
                SELECT hash_value, plaintext, hash_type 
                FROM password_cracks 
                WHERE case_id = ? AND success = 1
                LIMIT 10
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["successful_cracks"].append({
                    "hash": row[0][:20] + "...",
                    "plaintext": row[1],
                    "type": row[2]
                })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation crypto analysis: {e}")
        
        return results
    
    def _get_timeline_analysis(self, case_id: str) -> Dict[str, Any]:
        """Récupère les résultats d'analyse timeline"""
        results = {
            "total_events": 0,
            "correlation_clusters": 0,
            "temporal_anomalies": 0,
            "time_span": {},
            "event_distribution": {},
            "key_correlations": [],
            "anomaly_summary": []
        }
        
        try:
            db_path = self.evidence_dir / self.db_mappings["timeline"]
            if not db_path.exists():
                return results
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Statistiques timeline
            cursor.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?", (case_id,))
            results["total_events"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM correlation_clusters WHERE case_id = ?", (case_id,))
            results["correlation_clusters"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM temporal_anomalies WHERE case_id = ?", (case_id,))
            results["temporal_anomalies"] = cursor.fetchone()[0]
            
            # Période d'analyse
            cursor.execute("""
                SELECT MIN(timestamp), MAX(timestamp) 
                FROM timeline_events 
                WHERE case_id = ?
            """, (case_id,))
            
            time_range = cursor.fetchone()
            if time_range[0] and time_range[1]:
                results["time_span"] = {
                    "start": time_range[0],
                    "end": time_range[1]
                }
            
            # Corrélations clés
            cursor.execute("""
                SELECT correlation_type, description, confidence_score 
                FROM correlation_clusters 
                WHERE case_id = ? AND confidence_score > 0.7
                ORDER BY confidence_score DESC LIMIT 5
            """, (case_id,))
            
            for row in cursor.fetchall():
                results["key_correlations"].append({
                    "type": row[0],
                    "description": row[1],
                    "confidence": row[2]
                })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur agrégation timeline analysis: {e}")
        
        return results
    
    def _generate_key_findings(self, results: AnalysisResults) -> List[str]:
        """Génère les conclusions clés basées sur les résultats"""
        findings = []
        
        # Analyse des malwares
        malware_count = results.disk_analysis.get("malware_detected", 0)
        if malware_count > 0:
            findings.append(f"Détection de {malware_count} échantillons de malware sur le système")
        
        # Analyse des processus suspects
        suspicious_processes = len(results.memory_analysis.get("process_anomalies", []))
        if suspicious_processes > 0:
            findings.append(f"Identification de {suspicious_processes} processus suspects en mémoire")
        
        # Analyse réseau
        suspicious_domains = results.network_analysis.get("suspicious_domains", 0)
        if suspicious_domains > 0:
            findings.append(f"Communication avec {suspicious_domains} domaines suspects détectée")
        
        # Analyse mobile
        sms_count = results.mobile_analysis.get("sms_messages", 0)
        if sms_count > 1000:
            findings.append(f"Volume élevé de communications mobiles: {sms_count} messages SMS")
        
        # Analyse cryptographique
        crypto_artifacts = results.crypto_analysis.get("crypto_artifacts", 0)
        if crypto_artifacts > 0:
            findings.append(f"Découverte de {crypto_artifacts} artefacts cryptographiques")
        
        # Timeline
        anomalies = results.timeline_analysis.get("temporal_anomalies", 0)
        if anomalies > 0:
            findings.append(f"Détection de {anomalies} anomalies temporelles dans l'activité")
        
        if not findings:
            findings.append("Aucune activité suspecte majeure détectée lors de l'analyse")
        
        return findings
    
    def _generate_recommendations(self, results: AnalysisResults) -> List[str]:
        """Génère les recommandations basées sur les résultats"""
        recommendations = []
        
        # Recommandations sécurité
        malware_count = results.disk_analysis.get("malware_detected", 0)
        if malware_count > 0:
            recommendations.append("Effectuer une désinfection complète du système avec un antivirus à jour")
            recommendations.append("Isoler le système infecté du réseau pour éviter la propagation")
        
        # Recommandations processus
        suspicious_processes = len(results.memory_analysis.get("process_anomalies", []))
        if suspicious_processes > 0:
            recommendations.append("Analyser en détail les processus suspects identifiés")
            recommendations.append("Vérifier l'intégrité des fichiers exécutables système")
        
        # Recommandations réseau
        suspicious_domains = results.network_analysis.get("suspicious_domains", 0)
        if suspicious_domains > 0:
            recommendations.append("Bloquer les domaines malveillants au niveau du firewall/DNS")
            recommendations.append("Surveiller les communications réseau pour des connexions similaires")
        
        # Recommandations cryptographiques
        password_cracks = results.crypto_analysis.get("password_cracks", 0)
        if password_cracks > 0:
            recommendations.append("Changer immédiatement tous les mots de passe compromis")
            recommendations.append("Implémenter une politique de mots de passe robuste")
        
        # Recommandations générales
        recommendations.append("Mettre en place une surveillance continue des activités suspectes")
        recommendations.append("Effectuer des sauvegardes régulières et tester les procédures de restauration")
        recommendations.append("Former les utilisateurs aux bonnes pratiques de cybersécurité")
        
        return recommendations
    
    def _assess_risk_level(self, results: AnalysisResults) -> Dict[str, Any]:
        """Évalue le niveau de risque basé sur les résultats"""
        risk_score = 0
        risk_factors = []
        
        # Facteurs de risque
        malware_count = results.disk_analysis.get("malware_detected", 0)
        if malware_count > 0:
            risk_score += malware_count * 20
            risk_factors.append(f"Présence de malware ({malware_count})")
        
        suspicious_processes = len(results.memory_analysis.get("process_anomalies", []))
        if suspicious_processes > 0:
            risk_score += suspicious_processes * 10
            risk_factors.append(f"Processus suspects ({suspicious_processes})")
        
        suspicious_domains = results.network_analysis.get("suspicious_domains", 0)
        if suspicious_domains > 0:
            risk_score += suspicious_domains * 5
            risk_factors.append(f"Communications suspectes ({suspicious_domains})")
        
        compromised_passwords = results.crypto_analysis.get("password_cracks", 0)
        if compromised_passwords > 0:
            risk_score += compromised_passwords * 15
            risk_factors.append(f"Mots de passe compromis ({compromised_passwords})")
        
        # Détermination du niveau de risque
        if risk_score >= 100:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
        elif risk_score >= 50:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
        else:
            risk_level = "LOW"
            risk_color = "#28a745"
        
        return {
            "level": risk_level,
            "score": min(risk_score, 100),  # Plafonner à 100
            "color": risk_color,
            "factors": risk_factors,
            "description": self._get_risk_description(risk_level)
        }
    
    def _get_risk_description(self, risk_level: str) -> str:
        """Retourne une description du niveau de risque"""
        descriptions = {
            "CRITICAL": "Risque critique nécessitant une intervention immédiate. Le système est compromis.",
            "HIGH": "Risque élevé avec des indicateurs de compromise. Action urgente requise.",
            "MEDIUM": "Risque modéré avec des activités suspectes. Surveillance renforcée recommandée.",
            "LOW": "Risque faible. Activité normale avec quelques éléments à surveiller."
        }
        return descriptions.get(risk_level, "Niveau de risque indéterminé")


class ChartGenerator:
    """
    Générateur de graphiques pour les rapports forensiques
    """
    
    def __init__(self, output_dir: str = "./reports/charts"):
        """
        Initialise le générateur de graphiques
        
        Args:
            output_dir: Répertoire de sortie pour les graphiques
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if PLOTTING_AVAILABLE:
            # Configuration du style matplotlib
            plt.style.use('seaborn-v0_8')
            sns.set_palette("husl")
    
    def generate_timeline_chart(self, timeline_data: List[Dict], case_id: str) -> Optional[str]:
        """Génère un graphique de timeline des événements"""
        if not PLOTTING_AVAILABLE or not timeline_data:
            return None
        
        try:
            # Préparation des données
            df = pd.DataFrame(timeline_data)
            if 'timestamp' not in df.columns:
                return None
            
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
            
            # Création du graphique
            fig, ax = plt.subplots(figsize=(15, 8))
            
            # Grouper les événements par type
            event_types = df['event_type'].unique()[:10]  # Limiter à 10 types max
            colors = sns.color_palette("husl", len(event_types))
            
            y_pos = 0
            for i, event_type in enumerate(event_types):
                type_events = df[df['event_type'] == event_type]
                ax.scatter(type_events['timestamp'], [y_pos] * len(type_events), 
                          c=[colors[i]], label=event_type, alpha=0.7, s=50)
                y_pos += 1
            
            # Configuration du graphique
            ax.set_xlabel('Temps')
            ax.set_ylabel('Types d\'événements')
            ax.set_title(f'Timeline des événements - Cas {case_id}', fontsize=16, fontweight='bold')
            ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            
            # Format des dates
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=6))
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            
            # Sauvegarde
            chart_path = self.output_dir / f"timeline_{case_id}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Erreur génération timeline chart: {e}")
            return None
    
    def generate_risk_assessment_chart(self, risk_data: Dict[str, Any], case_id: str) -> Optional[str]:
        """Génère un graphique d'évaluation des risques"""
        if not PLOTTING_AVAILABLE:
            return None
        
        try:
            risk_score = risk_data.get("score", 0)
            risk_level = risk_data.get("level", "LOW")
            risk_factors = risk_data.get("factors", [])
            
            # Création du graphique en gauge
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
            
            # Gauge de risque
            colors = ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
            levels = [25, 50, 75, 100]
            
            # Création des segments de la gauge
            for i, (level, color) in enumerate(zip(levels, colors)):
                start_angle = 180 - (i * 45)
                end_angle = 180 - ((i + 1) * 45)
                
                wedge = plt.matplotlib.patches.Wedge(
                    (0, 0), 1, start_angle, end_angle,
                    facecolor=color, alpha=0.7, edgecolor='white', linewidth=2
                )
                ax1.add_patch(wedge)
            
            # Aiguille du risque
            angle = 180 - (risk_score * 1.8)  # 180° pour score 0, 0° pour score 100
            x_needle = 0.8 * np.cos(np.radians(angle))
            y_needle = 0.8 * np.sin(np.radians(angle))
            ax1.arrow(0, 0, x_needle, y_needle, head_width=0.05, head_length=0.05, fc='black', ec='black')
            
            ax1.set_xlim(-1.2, 1.2)
            ax1.set_ylim(-0.2, 1.2)
            ax1.set_aspect('equal')
            ax1.axis('off')
            ax1.set_title(f'Niveau de Risque: {risk_level}\nScore: {risk_score}/100', 
                         fontsize=14, fontweight='bold')
            
            # Graphique des facteurs de risque
            if risk_factors:
                factor_names = [f.split(' (')[0] for f in risk_factors[:5]]  # Top 5
                factor_counts = []
                for f in risk_factors[:5]:
                    try:
                        count = int(f.split('(')[-1].split(')')[0])
                        factor_counts.append(count)
                    except:
                        factor_counts.append(1)
                
                bars = ax2.barh(factor_names, factor_counts, color=sns.color_palette("Reds_r", len(factor_names)))
                ax2.set_xlabel('Nombre d\'occurrences')
                ax2.set_title('Facteurs de Risque Identifiés', fontweight='bold')
                
                # Ajouter les valeurs sur les barres
                for i, (bar, count) in enumerate(zip(bars, factor_counts)):
                    ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                            str(count), va='center')
            
            plt.tight_layout()
            
            # Sauvegarde
            chart_path = self.output_dir / f"risk_assessment_{case_id}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Erreur génération risk chart: {e}")
            return None
    
    def generate_analysis_summary_chart(self, analysis_results: AnalysisResults, case_id: str) -> Optional[str]:
        """Génère un graphique de résumé des analyses"""
        if not PLOTTING_AVAILABLE:
            return None
        
        try:
            # Données pour le graphique
            modules = ['Disk', 'Memory', 'Network', 'Mobile', 'Crypto', 'Timeline']
            artifacts_found = [
                analysis_results.disk_analysis.get('files_analyzed', 0),
                analysis_results.memory_analysis.get('processes_analyzed', 0),
                analysis_results.network_analysis.get('total_flows', 0) // 100,  # Réduire pour l'échelle
                analysis_results.mobile_analysis.get('sms_messages', 0) // 10,   # Réduire pour l'échelle
                analysis_results.crypto_analysis.get('crypto_artifacts', 0),
                analysis_results.timeline_analysis.get('total_events', 0) // 100  # Réduire pour l'échelle
            ]
            
            suspicious_items = [
                analysis_results.disk_analysis.get('malware_detected', 0),
                len(analysis_results.memory_analysis.get('process_anomalies', [])),
                analysis_results.network_analysis.get('suspicious_domains', 0),
                0,  # Mobile suspicious items (à implémenter)
                analysis_results.crypto_analysis.get('stegano_artifacts', 0),
                analysis_results.timeline_analysis.get('temporal_anomalies', 0)
            ]
            
            # Création du graphique
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Graphique des artefacts trouvés
            x = np.arange(len(modules))
            width = 0.35
            
            bars1 = ax1.bar(x - width/2, artifacts_found, width, label='Artefacts Analysés', alpha=0.8)
            bars2 = ax1.bar(x + width/2, suspicious_items, width, label='Éléments Suspects', alpha=0.8, color='red')
            
            ax1.set_xlabel('Modules d\'Analyse')
            ax1.set_ylabel('Nombre d\'Éléments')
            ax1.set_title('Résumé des Analyses par Module', fontweight='bold')
            ax1.set_xticks(x)
            ax1.set_xticklabels(modules)
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Ajouter les valeurs sur les barres
            for bars in [bars1, bars2]:
                for bar in bars:
                    height = bar.get_height()
                    if height > 0:
                        ax1.text(bar.get_x() + bar.get_width()/2., height,
                                f'{int(height)}', ha='center', va='bottom')
            
            # Graphique en secteurs des types d'analyse
            analysis_types = []
            analysis_counts = []
            
            if analysis_results.disk_analysis.get('files_analyzed', 0) > 0:
                analysis_types.append('Disk Analysis')
                analysis_counts.append(analysis_results.disk_analysis.get('files_analyzed', 0))
            
            if analysis_results.memory_analysis.get('processes_analyzed', 0) > 0:
                analysis_types.append('Memory Analysis')
                analysis_counts.append(analysis_results.memory_analysis.get('processes_analyzed', 0))
            
            if analysis_results.network_analysis.get('total_flows', 0) > 0:
                analysis_types.append('Network Analysis')
                analysis_counts.append(analysis_results.network_analysis.get('total_flows', 0))
            
            if analysis_results.mobile_analysis.get('sms_messages', 0) > 0:
                analysis_types.append('Mobile Analysis')
                analysis_counts.append(analysis_results.mobile_analysis.get('sms_messages', 0))
            
            if analysis_counts:
                ax2.pie(analysis_counts, labels=analysis_types, autopct='%1.1f%%', startangle=90)
                ax2.set_title('Distribution des Analyses', fontweight='bold')
            
            plt.tight_layout()
            
            # Sauvegarde
            chart_path = self.output_dir / f"analysis_summary_{case_id}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Erreur génération analysis summary chart: {e}")
            return None
    
    def encode_chart_as_base64(self, chart_path: str) -> Optional[str]:
        """Encode un graphique en base64 pour intégration HTML"""
        try:
            if not Path(chart_path).exists():
                return None
            
            with open(chart_path, 'rb') as f:
                chart_data = f.read()
            
            return base64.b64encode(chart_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Erreur encodage base64: {e}")
            return None


class TemplateManager:
    """
    Gestionnaire de templates pour les rapports
    """
    
    def __init__(self, template_dir: str = None):
        """
        Initialise le gestionnaire de templates
        
        Args:
            template_dir: Répertoire des templates personnalisés
        """
        if template_dir:
            self.template_dir = Path(template_dir)
        else:
            self.template_dir = Path(__file__).parent / "templates"
        
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Créer les templates par défaut s'ils n'existent pas
        self._create_default_templates()
        
        # Configurer Jinja2
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Ajouter des filtres personnalisés
        self._add_custom_filters()
    
    def _create_default_templates(self):
        """Crée les templates par défaut"""
        
        # Template HTML exécutif
        executive_template = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport Forensique Exécutif - {{ case_info.case_name }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #6c757d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .section {
            margin: 30px 0;
        }
        .section h2 {
            color: #495057;
            border-left: 4px solid #007bff;
            padding-left: 15px;
            margin-bottom: 20px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }
        .info-card h3 {
            margin-top: 0;
            color: #495057;
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
        }
        .risk-critical { background-color: #dc3545; }
        .risk-high { background-color: #fd7e14; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #28a745; }
        .findings-list {
            list-style: none;
            padding: 0;
        }
        .findings-list li {
            background: #fff3cd;
            margin: 10px 0;
            padding: 15px;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }
        .recommendations-list {
            list-style: none;
            padding: 0;
        }
        .recommendations-list li {
            background: #d1ecf1;
            margin: 10px 0;
            padding: 15px;
            border-left: 4px solid #17a2b8;
            border-radius: 4px;
        }
        .chart-container {
            text-align: center;
            margin: 30px 0;
        }
        .chart-container img {
            max-width: 100%;
            height: auto;
            border: 1px solid #dee2e6;
            border-radius: 8px;
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
            text-align: center;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Rapport Forensique Exécutif</h1>
            <div class="subtitle">{{ case_info.case_name }} - {{ case_info.case_id }}</div>
            <div style="margin-top: 15px;">
                <strong>Enquêteur:</strong> {{ case_info.investigator }} | 
                <strong>Organisation:</strong> {{ case_info.organization }} |
                <strong>Date:</strong> {{ case_info.case_date.strftime('%d/%m/%Y') }}
            </div>
        </div>

        <div class="section">
            <h2>📊 Résumé Exécutif</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Niveau de Risque</h3>
                    <div class="risk-badge risk-{{ analysis_results.risk_assessment.level.lower() }}">
                        {{ analysis_results.risk_assessment.level }}
                    </div>
                    <p style="margin-top: 10px;">{{ analysis_results.risk_assessment.description }}</p>
                </div>
                <div class="info-card">
                    <h3>Période d'Analyse</h3>
                    {% if analysis_results.timeline_analysis.time_span %}
                    <p><strong>Début:</strong> {{ analysis_results.timeline_analysis.time_span.start }}</p>
                    <p><strong>Fin:</strong> {{ analysis_results.timeline_analysis.time_span.end }}</p>
                    {% else %}
                    <p>Période d'analyse non déterminée</p>
                    {% endif %}
                </div>
            </div>
        </div>

        {% if risk_chart %}
        <div class="section">
            <h2>📈 Évaluation des Risques</h2>
            <div class="chart-container">
                <img src="data:image/png;base64,{{ risk_chart }}" alt="Graphique d'évaluation des risques">
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>🔍 Conclusions Clés</h2>
            <ul class="findings-list">
                {% for finding in analysis_results.key_findings %}
                <li>{{ finding }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="section">
            <h2>💡 Recommandations</h2>
            <ul class="recommendations-list">
                {% for recommendation in analysis_results.recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="section">
            <h2>📈 Statistiques d'Analyse</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Analyse Disque</h3>
                    <p><strong>Fichiers analysés:</strong> {{ analysis_results.disk_analysis.files_analyzed }}</p>
                    <p><strong>Malware détecté:</strong> {{ analysis_results.disk_analysis.malware_detected }}</p>
                    <p><strong>Fichiers supprimés:</strong> {{ analysis_results.disk_analysis.deleted_files }}</p>
                </div>
                <div class="info-card">
                    <h3>Analyse Mémoire</h3>
                    <p><strong>Processus analysés:</strong> {{ analysis_results.memory_analysis.processes_analyzed }}</p>
                    <p><strong>Processus suspects:</strong> {{ analysis_results.memory_analysis.process_anomalies|length }}</p>
                    <p><strong>Connexions réseau:</strong> {{ analysis_results.memory_analysis.network_connections }}</p>
                </div>
                <div class="info-card">
                    <h3>Analyse Réseau</h3>
                    <p><strong>Flux analysés:</strong> {{ analysis_results.network_analysis.total_flows }}</p>
                    <p><strong>Domaines suspects:</strong> {{ analysis_results.network_analysis.suspicious_domains }}</p>
                    <p><strong>Requêtes DNS:</strong> {{ analysis_results.network_analysis.dns_queries }}</p>
                </div>
                <div class="info-card">
                    <h3>Analyse Mobile</h3>
                    <p><strong>Messages SMS:</strong> {{ analysis_results.mobile_analysis.sms_messages }}</p>
                    <p><strong>Appels:</strong> {{ analysis_results.mobile_analysis.call_records }}</p>
                    <p><strong>Points GPS:</strong> {{ analysis_results.mobile_analysis.location_points }}</p>
                </div>
            </div>
        </div>

        {% if summary_chart %}
        <div class="section">
            <h2>📊 Résumé des Analyses</h2>
            <div class="chart-container">
                <img src="data:image/png;base64,{{ summary_chart }}" alt="Graphique de résumé des analyses">
            </div>
        </div>
        {% endif %}

        <div class="footer">
            <p><strong>Rapport généré le:</strong> {{ analysis_results.analysis_date.strftime('%d/%m/%Y à %H:%M') }}</p>
            <p><strong>Forensic Analysis Toolkit v2.1.0</strong></p>
            <p>Ce rapport est confidentiel et destiné uniquement à l'usage interne de {{ case_info.organization }}</p>
        </div>
    </div>
</body>
</html>
        '''
        
        executive_path = self.template_dir / "executive_summary.html"
        if not executive_path.exists():
            with open(executive_path, 'w', encoding='utf-8') as f:
                f.write(executive_template)
        
        # Template technique détaillé (version simplifiée)
        technical_template = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Technique - {{ case_info.case_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .section h2 { color: #333; border-left: 4px solid #007bff; padding-left: 15px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 Rapport Technique Détaillé</h1>
        <p>{{ case_info.case_name }} - {{ case_info.case_id }}</p>
        <p><strong>Enquêteur:</strong> {{ case_info.investigator }} | <strong>Date:</strong> {{ case_info.case_date.strftime('%d/%m/%Y') }}</p>
    </div>

    <div class="section">
        <h2>🔍 Méthodologie d'Investigation</h2>
        <p>Cette investigation forensique a été menée conformément aux standards ACPO et RFC 3227.</p>
        <ul>
            <li>Acquisition des preuves avec préservation de l'intégrité</li>
            <li>Analyse multi-modules (Disk, Memory, Network, Mobile, Crypto)</li>
            <li>Corrélation temporelle et détection d'anomalies</li>
            <li>Documentation complète de la chaîne de preuves</li>
        </ul>
    </div>

    <div class="section">
        <h2>💾 Analyse Disque</h2>
        <table>
            <tr><th>Métrique</th><th>Valeur</th></tr>
            <tr><td>Fichiers analysés</td><td>{{ analysis_results.disk_analysis.files_analyzed }}</td></tr>
            <tr><td>Fichiers supprimés</td><td>{{ analysis_results.disk_analysis.deleted_files }}</td></tr>
            <tr><td>Malware détecté</td><td>{{ analysis_results.disk_analysis.malware_detected }}</td></tr>
            <tr><td>Activités suspectes</td><td>{{ analysis_results.disk_analysis.suspicious_activities|length }}</td></tr>
        </table>

        {% if analysis_results.disk_analysis.suspicious_activities %}
        <h3>Activités Suspectes Détectées</h3>
        <ul>
            {% for activity in analysis_results.disk_analysis.suspicious_activities %}
            <li><strong>{{ activity.type }}:</strong> {{ activity.file }} - {{ activity.details }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <div class="section">
        <h2>🧠 Analyse Mémoire</h2>
        <table>
            <tr><th>Métrique</th><th>Valeur</th></tr>
            <tr><td>Processus analysés</td><td>{{ analysis_results.memory_analysis.processes_analyzed }}</td></tr>
            <tr><td>Connexions réseau</td><td>{{ analysis_results.memory_analysis.network_connections }}</td></tr>
            <tr><td>Processus suspects</td><td>{{ analysis_results.memory_analysis.process_anomalies|length }}</td></tr>
        </table>

        {% if analysis_results.memory_analysis.process_anomalies %}
        <h3>Processus Suspects</h3>
        <table>
            <tr><th>Processus</th><th>PID</th><th>Commande</th><th>Score</th></tr>
            {% for proc in analysis_results.memory_analysis.process_anomalies %}
            <tr><td>{{ proc.process }}</td><td>{{ proc.pid }}</td><td class="code">{{ proc.command }}</td><td>{{ "%.2f"|format(proc.score) }}</td></tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>

    <div class="section">
        <h2>🌐 Analyse Réseau</h2>
        <table>
            <tr><th>Métrique</th><th>Valeur</th></tr>
            <tr><td>Flux analysés</td><td>{{ analysis_results.network_analysis.total_flows }}</td></tr>
            <tr><td>Requêtes DNS</td><td>{{ analysis_results.network_analysis.dns_queries }}</td></tr>
            <tr><td>Domaines suspects</td><td>{{ analysis_results.network_analysis.suspicious_domains }}</td></tr>
        </table>

        {% if analysis_results.network_analysis.threat_indicators %}
        <h3>Indicateurs de Menace</h3>
        <table>
            <tr><th>Type</th><th>Indicateur</th><th>Menace</th><th>Score</th></tr>
            {% for indicator in analysis_results.network_analysis.threat_indicators %}
            <tr><td>{{ indicator.type }}</td><td>{{ indicator.indicator }}</td><td>{{ indicator.threat_type }}</td><td>{{ indicator.score }}</td></tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>

    <div class="section">
        <h2>🔒 Analyse Cryptographique</h2>
        <table>
            <tr><th>Métrique</th><th>Valeur</th></tr>
            <tr><td>Artefacts cryptographiques</td><td>{{ analysis_results.crypto_analysis.crypto_artifacts }}</td></tr>
            <tr><td>Artefacts stéganographiques</td><td>{{ analysis_results.crypto_analysis.stegano_artifacts }}</td></tr>
            <tr><td>Mots de passe craqués</td><td>{{ analysis_results.crypto_analysis.password_cracks }}</td></tr>
        </table>

        {% if analysis_results.crypto_analysis.algorithms_detected %}
        <h3>Algorithmes Détectés</h3>
        <ul>
            {% for algo in analysis_results.crypto_analysis.algorithms_detected %}
            <li>{{ algo }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    {% if timeline_chart %}
    <div class="section">
        <h2>🕒 Timeline des Événements</h2>
        <div style="text-align: center;">
            <img src="data:image/png;base64,{{ timeline_chart }}" alt="Timeline des événements" style="max-width: 100%;">
        </div>
    </div>
    {% endif %}

    <div class="section">
        <h2>📋 Conclusions</h2>
        <h3>Résultats Clés</h3>
        <ul>
            {% for finding in analysis_results.key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>

        <h3>Recommandations Techniques</h3>
        <ol>
            {% for recommendation in analysis_results.recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ol>
    </div>

    <div style="margin-top: 50px; border-top: 1px solid #ddd; padding-top: 20px; text-align: center; color: #666;">
        <p><strong>Rapport généré le:</strong> {{ analysis_results.analysis_date.strftime('%d/%m/%Y à %H:%M') }}</p>
        <p>Forensic Analysis Toolkit v2.1.0</p>
    </div>
</body>
</html>
        '''
        
        technical_path = self.template_dir / "technical_detailed.html"
        if not technical_path.exists():
            with open(technical_path, 'w', encoding='utf-8') as f:
                f.write(technical_template)
    
    def _add_custom_filters(self):
        """Ajoute des filtres personnalisés à Jinja2"""
        
        def format_bytes(bytes_value):
            """Formate les octets en unités lisibles"""
            if bytes_value == 0:
                return "0 B"
            
            units = ['B', 'KB', 'MB', 'GB', 'TB']
            i = 0
            while bytes_value >= 1024 and i < len(units) - 1:
                bytes_value /= 1024
                i += 1
            
            return f"{bytes_value:.1f} {units[i]}"
        
        def format_datetime(dt):
            """Formate une date/heure"""
            if isinstance(dt, str):
                try:
                    dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
                except:
                    return dt
            
            return dt.strftime('%d/%m/%Y %H:%M:%S')
        
        def truncate_string(s, length=100):
            """Tronque une chaîne de caractères"""
            if len(s) <= length:
                return s
            return s[:length] + "..."
        
        self.env.filters['format_bytes'] = format_bytes
        self.env.filters['format_datetime'] = format_datetime
        self.env.filters['truncate'] = truncate_string
    
    def get_template(self, template_name: str) -> Template:
        """Récupère un template par nom"""
        try:
            return self.env.get_template(template_name)
        except jinja2.TemplateNotFound:
            logger.error(f"Template non trouvé: {template_name}")
            raise
    
    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Rend un template avec le contexte donné"""
        template = self.get_template(template_name)
        return template.render(**context)


class ReportingEngine:
    """
    Moteur principal de génération de rapports forensiques
    """
    
    def __init__(self, evidence_dir: str = "./evidence", output_dir: str = "./reports"):
        """
        Initialise le moteur de rapports
        
        Args:
            evidence_dir: Répertoire contenant les données d'analyse
            output_dir: Répertoire de sortie pour les rapports
        """
        self.evidence_dir = Path(evidence_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Composants du moteur
        self.data_aggregator = DataAggregator(evidence_dir)
        self.chart_generator = ChartGenerator(output_dir / "charts")
        self.template_manager = TemplateManager()
        
        # Base de données pour les rapports
        self.reports_db = self.output_dir / "reports.db"
        self._init_reports_database()
    
    def _init_reports_database(self):
        """Initialise la base de données des rapports"""
        conn = sqlite3.connect(self.reports_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS generated_reports (
                report_id TEXT PRIMARY KEY,
                case_id TEXT,
                report_type TEXT,
                report_format TEXT,
                file_path TEXT,
                generated_date TIMESTAMP,
                file_size INTEGER,
                file_hash TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_report(self, case_id: str, case_info: CaseInformation, 
                       report_type: ReportType = ReportType.EXECUTIVE_SUMMARY,
                       report_format: ReportFormat = ReportFormat.HTML) -> str:
        """
        Génère un rapport forensique
        
        Args:
            case_id: Identifiant du cas
            case_info: Informations du cas
            report_type: Type de rapport à générer
            report_format: Format de sortie
            
        Returns:
            Chemin vers le rapport généré
        """
        logger.info(f"Génération rapport {report_type.value} pour cas {case_id}")
        
        try:
            # 1. Agrégation des données
            analysis_results = self.data_aggregator.aggregate_analysis_results(case_id)
            
            # 2. Génération des graphiques
            charts = self._generate_charts(analysis_results)
            
            # 3. Préparation du contexte pour le template
            context = {
                'case_info': case_info,
                'analysis_results': analysis_results,
                'generation_date': datetime.now(timezone.utc),
                'report_type': report_type.value,
                'case_id': case_id
            }
            
            # Ajouter les graphiques au contexte
            context.update(charts)
            
            # 4. Génération du rapport selon le format
            if report_format == ReportFormat.HTML:
                report_path = self._generate_html_report(case_id, report_type, context)
            elif report_format == ReportFormat.PDF:
                report_path = self._generate_pdf_report(case_id, report_type, context)
            elif report_format == ReportFormat.JSON:
                report_path = self._generate_json_report(case_id, context)
            else:
                raise ValueError(f"Format de rapport non supporté: {report_format}")
            
            # 5. Enregistrement du rapport dans la base
            self._record_generated_report(case_id, report_type, report_format, report_path)
            
            logger.info(f"Rapport généré avec succès: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Erreur génération rapport: {e}")
            raise
    
    def _generate_charts(self, analysis_results: AnalysisResults) -> Dict[str, str]:
        """Génère les graphiques pour le rapport"""
        charts = {}
        
        try:
            case_id = analysis_results.case_id
            
            # Graphique d'évaluation des risques
            risk_chart_path = self.chart_generator.generate_risk_assessment_chart(
                analysis_results.risk_assessment, case_id
            )
            if risk_chart_path:
                charts['risk_chart'] = self.chart_generator.encode_chart_as_base64(risk_chart_path)
            
            # Graphique de résumé des analyses
            summary_chart_path = self.chart_generator.generate_analysis_summary_chart(
                analysis_results, case_id
            )
            if summary_chart_path:
                charts['summary_chart'] = self.chart_generator.encode_chart_as_base64(summary_chart_path)
            
            # Graphique de timeline (si données disponibles)
            timeline_events = analysis_results.timeline_analysis.get('events', [])
            if timeline_events:
                timeline_chart_path = self.chart_generator.generate_timeline_chart(
                    timeline_events, case_id
                )
                if timeline_chart_path:
                    charts['timeline_chart'] = self.chart_generator.encode_chart_as_base64(timeline_chart_path)
            
        except Exception as e:
            logger.error(f"Erreur génération graphiques: {e}")
        
        return charts
    
    def _generate_html_report(self, case_id: str, report_type: ReportType, context: Dict[str, Any]) -> str:
        """Génère un rapport HTML"""
        
        # Sélection du template selon le type de rapport
        if report_type == ReportType.EXECUTIVE_SUMMARY:
            template_name = "executive_summary.html"
        elif report_type == ReportType.TECHNICAL_DETAILED:
            template_name = "technical_detailed.html"
        else:
            template_name = "executive_summary.html"  # Par défaut
        
        # Rendu du template
        html_content = self.template_manager.render_template(template_name, context)
        
        # Sauvegarde du fichier
        report_filename = f"{report_type.value.lower().replace(' ', '_')}_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = self.output_dir / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _generate_pdf_report(self, case_id: str, report_type: ReportType, context: Dict[str, Any]) -> str:
        """Génère un rapport PDF"""
        if not PDF_AVAILABLE:
            logger.warning("WeasyPrint non disponible, génération PDF impossible")
            # Fallback vers HTML
            return self._generate_html_report(case_id, report_type, context)
        
        try:
            # Générer d'abord le HTML
            html_content = self._generate_html_report(case_id, report_type, context)
            
            # CSS spécifique pour PDF
            pdf_css = CSS(string='''
                @page {
                    size: A4;
                    margin: 2cm;
                }
                body {
                    font-size: 12pt;
                    line-height: 1.4;
                }
                .container {
                    box-shadow: none;
                    border-radius: 0;
                }
            ''')
            
            # Conversion en PDF
            pdf_filename = f"{report_type.value.lower().replace(' ', '_')}_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = self.output_dir / pdf_filename
            
            HTML(html_content).write_pdf(str(pdf_path), stylesheets=[pdf_css])
            
            return str(pdf_path)
            
        except Exception as e:
            logger.error(f"Erreur génération PDF: {e}")
            # Fallback vers HTML
            return html_content
    
    def _generate_json_report(self, case_id: str, context: Dict[str, Any]) -> str:
        """Génère un rapport JSON"""
        
        # Convertir le contexte en JSON serializable
        json_data = {
            'case_id': case_id,
            'generation_date': context['generation_date'].isoformat(),
            'report_type': context['report_type'],
            'case_info': {
                'case_id': context['case_info'].case_id,
                'case_name': context['case_info'].case_name,
                'investigator': context['case_info'].investigator,
                'organization': context['case_info'].organization,
                'case_date': context['case_info'].case_date.isoformat(),
                'incident_type': context['case_info'].incident_type,
                'description': context['case_info'].description
            },
            'analysis_results': {
                'key_findings': context['analysis_results'].key_findings,
                'recommendations': context['analysis_results'].recommendations,
                'risk_assessment': context['analysis_results'].risk_assessment,
                'disk_analysis': context['analysis_results'].disk_analysis,
                'memory_analysis': context['analysis_results'].memory_analysis,
                'network_analysis': context['analysis_results'].network_analysis,
                'mobile_analysis': context['analysis_results'].mobile_analysis,
                'crypto_analysis': context['analysis_results'].crypto_analysis,
                'timeline_analysis': context['analysis_results'].timeline_analysis
            }
        }
        
        # Sauvegarde du fichier JSON
        json_filename = f"report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path = self.output_dir / json_filename
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
        
        return str(json_path)
    
    def _record_generated_report(self, case_id: str, report_type: ReportType, 
                                report_format: ReportFormat, file_path: str):
        """Enregistre un rapport généré dans la base de données"""
        try:
            file_path_obj = Path(file_path)
            file_size = file_path_obj.stat().st_size
            
            # Calcul du hash du fichier
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            report_id = f"{case_id}_{report_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            conn = sqlite3.connect(self.reports_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO generated_reports 
                (report_id, case_id, report_type, report_format, file_path, 
                 generated_date, file_size, file_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_id, case_id, report_type.value, report_format.value,
                str(file_path), datetime.now().isoformat(), file_size, file_hash
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur enregistrement rapport: {e}")
    
    def list_generated_reports(self, case_id: str = None) -> List[Dict[str, Any]]:
        """Liste les rapports générés"""
        conn = sqlite3.connect(self.reports_db)
        cursor = conn.cursor()
        
        if case_id:
            cursor.execute('SELECT * FROM generated_reports WHERE case_id = ? ORDER BY generated_date DESC', (case_id,))
        else:
            cursor.execute('SELECT * FROM generated_reports ORDER BY generated_date DESC')
        
        columns = [desc[0] for desc in cursor.description]
        reports = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return reports
    
    def generate_case_summary(self, case_id: str) -> Dict[str, Any]:
        """Génère un résumé du cas pour aperçu rapide"""
        analysis_results = self.data_aggregator.aggregate_analysis_results(case_id)
        
        summary = {
            'case_id': case_id,
            'analysis_date': analysis_results.analysis_date.isoformat(),
            'risk_level': analysis_results.risk_assessment['level'],
            'risk_score': analysis_results.risk_assessment['score'],
            'key_metrics': {
                'files_analyzed': analysis_results.disk_analysis.get('files_analyzed', 0),
                'malware_detected': analysis_results.disk_analysis.get('malware_detected', 0),
                'processes_analyzed': analysis_results.memory_analysis.get('processes_analyzed', 0),
                'network_flows': analysis_results.network_analysis.get('total_flows', 0),
                'suspicious_domains': analysis_results.network_analysis.get('suspicious_domains', 0),
                'crypto_artifacts': analysis_results.crypto_analysis.get('crypto_artifacts', 0)
            },
            'top_findings': analysis_results.key_findings[:3],
            'priority_recommendations': analysis_results.recommendations[:3]
        }
        
        return summary


def main():
    """Fonction de démonstration"""
    print("📊 Forensic Analysis Toolkit - Reporting Engine")
    print("=" * 50)
    
    # Exemple d'utilisation
    reporting_engine = ReportingEngine(
        evidence_dir="./evidence",
        output_dir="./reports"
    )
    
    # Informations de cas exemple
    case_info = CaseInformation(
        case_id="DEMO_CASE_2024",
        case_name="Démonstration Forensic Analysis",
        investigator="Agent Forensique",
        organization="Cybersecurity Portfolio",
        case_date=datetime.now(),
        incident_type="Malware Investigation",
        description="Analyse forensique de démonstration du toolkit"
    )
    
    print(f"📋 Cas d'exemple: {case_info.case_name}")
    print(f"🔍 Enquêteur: {case_info.investigator}")
    
    try:
        # Génération d'un rapport exécutif
        print("\n📊 Génération du rapport exécutif...")
        executive_report = reporting_engine.generate_report(
            case_id=case_info.case_id,
            case_info=case_info,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.HTML
        )
        
        print(f"✅ Rapport exécutif généré: {executive_report}")
        
        # Génération d'un rapport technique
        print("\n📋 Génération du rapport technique...")
        technical_report = reporting_engine.generate_report(
            case_id=case_info.case_id,
            case_info=case_info,
            report_type=ReportType.TECHNICAL_DETAILED,
            report_format=ReportFormat.HTML
        )
        
        print(f"✅ Rapport technique généré: {technical_report}")
        
        # Génération d'un rapport JSON
        print("\n💾 Génération du rapport JSON...")
        json_report = reporting_engine.generate_report(
            case_id=case_info.case_id,
            case_info=case_info,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.JSON
        )
        
        print(f"✅ Rapport JSON généré: {json_report}")
        
        # Liste des rapports générés
        print("\n📄 Rapports générés:")
        reports = reporting_engine.list_generated_reports(case_info.case_id)
        for report in reports:
            print(f"  - {report['report_type']} ({report['report_format']}) - {report['file_path']}")
        
        # Résumé du cas
        print("\n📈 Résumé du cas:")
        summary = reporting_engine.generate_case_summary(case_info.case_id)
        print(f"  🎯 Niveau de risque: {summary['risk_level']} ({summary['risk_score']}/100)")
        print(f"  📊 Fichiers analysés: {summary['key_metrics']['files_analyzed']}")
        print(f"  🦠 Malware détecté: {summary['key_metrics']['malware_detected']}")
        
        print(f"\n📝 Conclusions principales:")
        for finding in summary['top_findings']:
            print(f"  • {finding}")
        
    except Exception as e:
        print(f"❌ Erreur durant la génération: {e}")
        logger.error(f"Erreur démonstration reporting: {e}")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()