#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Network Analyzer - Forensic Analysis Toolkit
============================================================================
Analyseur réseau forensique utilisant tshark et pyshark pour :
- Analyse de captures réseau (PCAP, PCAPNG)
- Extraction des communications et protocoles
- Détection d'anomalies et de trafic suspect
- Reconstruction des sessions et flux
- Analyse de malware et exfiltration de données
- Géolocalisation des adresses IP

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import hashlib
import logging
import subprocess
import json
import sqlite3
import socket
import struct
import gzip
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import requests
import base64
import re
from urllib.parse import unquote

# Imports conditionnels pour les outils réseau
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.warning("pyshark non disponible, fonctionnalités limitées")

try:
    import scapy.all as scapy
    from scapy.layers import http
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("scapy non disponible, analyse avancée limitée")

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Types de protocoles réseau supportés"""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    FTP = "FTP"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    DNS = "DNS"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    SSH = "SSH"
    TELNET = "TELNET"
    SMB = "SMB"
    RDP = "RDP"
    IRC = "IRC"
    UNKNOWN = "UNKNOWN"


class ThreatLevel(Enum):
    """Niveaux de menace détectés"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class NetworkFlow:
    """Flux réseau entre deux endpoints"""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: ProtocolType
    start_time: datetime
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration: Optional[float] = None
    flags: List[str] = field(default_factory=list)
    country_src: Optional[str] = None
    country_dst: Optional[str] = None
    suspicious: bool = False
    threat_level: ThreatLevel = ThreatLevel.LOW
    indicators: List[str] = field(default_factory=list)


@dataclass
class DNSQuery:
    """Requête DNS extraite"""
    timestamp: datetime
    src_ip: str
    query_name: str
    query_type: str
    response_code: Optional[str] = None
    resolved_ip: Optional[str] = None
    ttl: Optional[int] = None
    suspicious: bool = False
    domain_reputation: Optional[str] = None


@dataclass
class HTTPTransaction:
    """Transaction HTTP extraite"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    method: str
    url: str
    host: str
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    referrer: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    files_transferred: List[str] = field(default_factory=list)
    suspicious: bool = False
    malware_indicators: List[str] = field(default_factory=list)


@dataclass
class EmailCommunication:
    """Communication email extraite (SMTP/POP3/IMAP)"""
    timestamp: datetime
    protocol: ProtocolType
    src_ip: str
    dst_ip: str
    sender: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    message_id: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    body_preview: Optional[str] = None
    suspicious: bool = False
    indicators: List[str] = field(default_factory=list)


@dataclass
class SuspiciousActivity:
    """Activité suspecte détectée"""
    timestamp: datetime
    activity_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    protocol: ProtocolType
    description: str
    severity: ThreatLevel
    indicators: List[str] = field(default_factory=list)
    raw_data: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class FileTransfer:
    """Transfert de fichier détecté"""
    timestamp: datetime
    protocol: ProtocolType
    src_ip: str
    dst_ip: str
    filename: str
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    file_type: Optional[str] = None
    direction: str  # "upload" ou "download"
    reconstructed_path: Optional[str] = None
    suspicious: bool = False
    malware_score: Optional[float] = None


class TsharkWrapper:
    """Wrapper pour interagir avec tshark"""
    
    def __init__(self, tshark_path: str = None):
        """
        Initialise le wrapper tshark
        
        Args:
            tshark_path: Chemin vers tshark (None = auto-détection)
        """
        self.tshark_path = self._find_tshark_path(tshark_path)
    
    def _find_tshark_path(self, provided_path: str = None) -> Optional[str]:
        """Trouve le chemin vers tshark"""
        if provided_path and Path(provided_path).exists():
            return provided_path
        
        # Recherche dans les emplacements communs
        common_paths = [
            "tshark",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "C:\\Program Files (x86)\\Wireshark\\tshark.exe"
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Test avec which/where
        try:
            cmd = "where" if os.name == "nt" else "which"
            result = subprocess.run([cmd, "tshark"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        
        logger.warning("tshark non trouvé, certaines fonctionnalités seront limitées")
        return None
    
    def analyze_capture(self, pcap_file: str, filter_exp: str = None, 
                       fields: List[str] = None) -> Tuple[bool, str, str]:
        """
        Analyse une capture avec tshark
        
        Args:
            pcap_file: Fichier PCAP à analyser
            filter_exp: Filtre d'affichage
            fields: Champs à extraire
            
        Returns:
            Tuple (success, output, error)
        """
        if not self.tshark_path:
            return False, "", "tshark non disponible"
        
        cmd = [self.tshark_path, "-r", pcap_file]
        
        if filter_exp:
            cmd.extend(["-Y", filter_exp])
        
        if fields:
            cmd.extend(["-T", "fields"])
            for field in fields:
                cmd.extend(["-e", field])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Timeout"
        except Exception as e:
            return False, "", str(e)
    
    def get_capture_info(self, pcap_file: str) -> Dict[str, Any]:
        """Obtient des informations sur la capture"""
        if not self.tshark_path:
            return {}
        
        cmd = [self.tshark_path, "-r", pcap_file, "-q", "-z", "io,stat,0"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return self._parse_capture_stats(result.stdout)
        except:
            pass
        
        return {}
    
    def _parse_capture_stats(self, output: str) -> Dict[str, Any]:
        """Parse les statistiques de capture"""
        stats = {}
        
        for line in output.split('\n'):
            if "packets" in line.lower():
                try:
                    # Parse approximatif des statistiques
                    if "captured" in line:
                        stats['total_packets'] = int(line.split()[0])
                except:
                    pass
        
        return stats


class GeolocationResolver:
    """Résolveur de géolocalisation pour adresses IP"""
    
    def __init__(self, use_free_apis: bool = True):
        """
        Initialise le résolveur de géolocalisation
        
        Args:
            use_free_apis: Utiliser les APIs gratuites (limitées)
        """
        self.use_free_apis = use_free_apis
        self.cache = {}
        self.free_api_calls = 0
        self.max_free_calls = 1000  # Limite quotidienne approximative
    
    def resolve_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Résout la géolocalisation d'une adresse IP
        
        Args:
            ip_address: Adresse IP à résoudre
            
        Returns:
            Informations de géolocalisation ou None
        """
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        # Vérification IP privée
        if self._is_private_ip(ip_address):
            result = {
                'country': 'Private',
                'city': 'Local Network',
                'latitude': None,
                'longitude': None,
                'isp': 'Private Network'
            }
            self.cache[ip_address] = result
            return result
        
        if self.use_free_apis and self.free_api_calls < self.max_free_calls:
            result = self._resolve_with_free_api(ip_address)
            if result:
                self.cache[ip_address] = result
                self.free_api_calls += 1
                return result
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si l'IP est privée"""
        try:
            parts = [int(x) for x in ip.split('.')]
            
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            # Localhost
            if parts[0] == 127:
                return True
                
        except:
            pass
        
        return False
    
    def _resolve_with_free_api(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Utilise une API gratuite pour la géolocalisation"""
        try:
            # Utilisation de ip-api.com (gratuit, limité)
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'timezone': data.get('timezone')
                    }
        except Exception as e:
            logger.debug(f"Erreur géolocalisation {ip_address}: {e}")
        
        return None


class NetworkAnalyzer:
    """
    Analyseur réseau forensique principal
    """
    
    def __init__(self, evidence_dir: str = "./evidence", temp_dir: str = "./temp"):
        """
        Initialise l'analyseur réseau
        
        Args:
            evidence_dir: Répertoire pour stocker les preuves
            temp_dir: Répertoire temporaire pour les analyses
        """
        self.evidence_dir = Path(evidence_dir)
        self.temp_dir = Path(temp_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.tshark = TsharkWrapper()
        self.geolocation = GeolocationResolver()
        self.pcap_file = None
        self.case_id = None
        
        # Base de données SQLite pour stocker les résultats
        self.db_path = self.evidence_dir / "network_analysis.db"
        self._init_database()
        
        # Patterns pour détection d'anomalies
        self.suspicious_patterns = self._init_suspicious_patterns()
        
        # Dictionnaire des ports connus
        self.well_known_ports = self._init_well_known_ports()
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des analyses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_analysis (
                case_id TEXT PRIMARY KEY,
                pcap_file TEXT NOT NULL,
                file_size INTEGER,
                file_md5 TEXT,
                file_sha256 TEXT,
                total_packets INTEGER,
                analysis_start TIMESTAMP,
                analysis_end TIMESTAMP,
                capture_duration REAL,
                investigator TEXT
            )
        ''')
        
        # Table des flux réseau
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                flow_id TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                packets_sent INTEGER,
                packets_received INTEGER,
                duration REAL,
                country_src TEXT,
                country_dst TEXT,
                suspicious BOOLEAN,
                threat_level TEXT,
                indicators TEXT,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        # Table des requêtes DNS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                src_ip TEXT,
                query_name TEXT,
                query_type TEXT,
                response_code TEXT,
                resolved_ip TEXT,
                ttl INTEGER,
                suspicious BOOLEAN,
                domain_reputation TEXT,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        # Table des transactions HTTP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS http_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                method TEXT,
                url TEXT,
                host TEXT,
                user_agent TEXT,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                suspicious BOOLEAN,
                malware_indicators TEXT,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        # Table des communications email
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_communications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                sender TEXT,
                recipients TEXT,
                subject TEXT,
                message_id TEXT,
                suspicious BOOLEAN,
                indicators TEXT,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        # Table des activités suspectes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                activity_type TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                description TEXT,
                severity TEXT,
                indicators TEXT,
                raw_data TEXT,
                recommendations TEXT,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        # Table des transferts de fichiers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                filename TEXT,
                file_size INTEGER,
                file_hash TEXT,
                file_type TEXT,
                direction TEXT,
                reconstructed_path TEXT,
                suspicious BOOLEAN,
                malware_score REAL,
                FOREIGN KEY (case_id) REFERENCES network_analysis (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _init_suspicious_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Initialise les patterns de détection d'activités suspectes"""
        return {
            'malware_c2': [
                re.compile(r'\/[a-f0-9]{32}\.php', re.IGNORECASE),  # Hash-based C&C
                re.compile(r'\/gate\.php', re.IGNORECASE),
                re.compile(r'\/panel\/.*\.php', re.IGNORECASE),
                re.compile(r'\/admin\/gate\.php', re.IGNORECASE)
            ],
            'data_exfiltration': [
                re.compile(r'data=[a-zA-Z0-9+/]{100,}={0,2}', re.IGNORECASE),  # Base64 data
                re.compile(r'file_contents=[a-zA-Z0-9+/]{50,}', re.IGNORECASE),
                re.compile(r'backup\.zip|db_dump\.sql', re.IGNORECASE)
            ],
            'suspicious_domains': [
                re.compile(r'[a-f0-9]{20,}\.(?:tk|ml|ga|cf|ru)', re.IGNORECASE),  # Suspicious TLDs
                re.compile(r'\d+\-\d+\-\d+\-\d+\.', re.IGNORECASE),  # IP-like domains
                re.compile(r'[a-z]{1,3}\d{3,}\.', re.IGNORECASE)  # Short name + numbers
            ],
            'credential_theft': [
                re.compile(r'username=[^&]+&password=[^&]+', re.IGNORECASE),
                re.compile(r'user=[^&]+&pass=[^&]+', re.IGNORECASE),
                re.compile(r'email=[^&]+.*pass[wd]?=[^&]+', re.IGNORECASE)
            ],
            'webshell_activity': [
                re.compile(r'cmd=|command=|exec=', re.IGNORECASE),
                re.compile(r'eval\(|system\(|shell_exec\(', re.IGNORECASE),
                re.compile(r'\/uploads?\/.*\.php', re.IGNORECASE)
            ]
        }
    
    def _init_well_known_ports(self) -> Dict[int, str]:
        """Initialise le dictionnaire des ports bien connus"""
        return {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT", 80: "HTTP",
            110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 587: "SMTP-SUBMISSION", 465: "SMTPS",
            389: "LDAP", 636: "LDAPS", 1433: "SQL-SERVER", 3306: "MYSQL",
            5432: "POSTGRESQL", 6379: "REDIS", 27017: "MONGODB",
            3389: "RDP", 5900: "VNC", 22: "SSH", 445: "SMB", 135: "RPC",
            1723: "PPTP", 1194: "OPENVPN", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT"
        }
    
    def open_capture(self, pcap_file: str, case_id: str) -> bool:
        """
        Ouvre une capture réseau pour analyse
        
        Args:
            pcap_file: Chemin vers le fichier PCAP
            case_id: Identifiant du cas
            
        Returns:
            True si succès, False sinon
        """
        try:
            pcap_path = Path(pcap_file)
            
            if not pcap_path.exists():
                logger.error(f"Le fichier PCAP {pcap_path} n'existe pas")
                return False
            
            self.pcap_file = str(pcap_path)
            self.case_id = case_id
            
            # Calcul des hashs du fichier
            file_size = pcap_path.stat().st_size
            md5_hash, sha256_hash = self._calculate_file_hashes(pcap_path)
            
            # Obtention des informations de capture
            capture_info = self.tshark.get_capture_info(self.pcap_file)
            total_packets = capture_info.get('total_packets', 0)
            
            # Sauvegarde des informations d'analyse
            self._save_analysis_info(
                case_id=case_id,
                pcap_file=str(pcap_path),
                file_size=file_size,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                total_packets=total_packets
            )
            
            logger.info(f"Capture {pcap_path.name} ouverte avec succès")
            logger.info(f"Taille: {file_size:,} bytes")
            logger.info(f"Paquets: {total_packets:,}")
            logger.info(f"MD5: {md5_hash}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ouverture de la capture: {e}")
            return False
    
    def _calculate_file_hashes(self, file_path: Path) -> Tuple[str, str]:
        """Calcule les hashs MD5 et SHA-256 du fichier"""
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)
            
            return md5_hasher.hexdigest(), sha256_hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Erreur calcul hashs: {e}")
            return "", ""
    
    def analyze_network_flows(self) -> List[NetworkFlow]:
        """
        Analyse les flux réseau de la capture
        
        Returns:
            Liste des flux réseau
        """
        if not self.pcap_file:
            logger.error("Aucune capture ouverte")
            return []
        
        flows = []
        
        try:
            if PYSHARK_AVAILABLE:
                flows = self._analyze_flows_with_pyshark()
            else:
                flows = self._analyze_flows_with_tshark()
            
            # Enrichissement avec géolocalisation
            for flow in flows:
                flow.country_src = self._get_country(flow.src_ip)
                flow.country_dst = self._get_country(flow.dst_ip)
                
                # Détection d'activités suspectes
                flow.suspicious, flow.threat_level, flow.indicators = self._analyze_flow_suspicion(flow)
            
            # Sauvegarde en base
            self._save_flows_to_db(flows)
            
            logger.info(f"Analyse terminée: {len(flows)} flux réseau")
            suspicious_count = sum(1 for f in flows if f.suspicious)
            if suspicious_count > 0:
                logger.warning(f"{suspicious_count} flux suspects détectés")
            
        except Exception as e:
            logger.error(f"Erreur analyse des flux: {e}")
        
        return flows
    
    def _analyze_flows_with_pyshark(self) -> List[NetworkFlow]:
        """Analyse les flux avec pyshark"""
        flows_dict = {}
        
        try:
            cap = pyshark.FileCapture(self.pcap_file)
            
            for packet in cap:
                try:
                    if hasattr(packet, 'ip'):
                        flow_id = self._generate_flow_id(packet)
                        
                        if flow_id not in flows_dict:
                            flow = self._create_flow_from_packet(packet)
                            if flow:
                                flows_dict[flow_id] = flow
                        else:
                            self._update_flow_with_packet(flows_dict[flow_id], packet)
                            
                except Exception as e:
                    logger.debug(f"Erreur traitement paquet: {e}")
                    continue
            
            cap.close()
            
        except Exception as e:
            logger.error(f"Erreur analyse pyshark: {e}")
        
        return list(flows_dict.values())
    
    def _analyze_flows_with_tshark(self) -> List[NetworkFlow]:
        """Analyse les flux avec tshark (fallback)"""
        flows = []
        
        # Extraction des statistiques de conversation
        success, output, error = self.tshark.analyze_capture(
            self.pcap_file,
            None,
            ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.len", "frame.time"]
        )
        
        if success and output:
            flows = self._parse_tshark_flows(output)
        
        return flows
    
    def _generate_flow_id(self, packet) -> str:
        """Génère un ID unique pour un flux"""
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            if hasattr(packet, 'tcp'):
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                protocol = "TCP"
            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                protocol = "UDP"
            else:
                src_port = dst_port = 0
                protocol = "OTHER"
            
            # Normalisation pour bidirectionnalité
            if src_ip < dst_ip or (src_ip == dst_ip and int(src_port) < int(dst_port)):
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
                
            return flow_id
            
        except Exception:
            return f"unknown-{hash(str(packet))}"
    
    def _create_flow_from_packet(self, packet) -> Optional[NetworkFlow]:
        """Crée un nouveau flux à partir d'un paquet"""
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
            
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                protocol = ProtocolType.TCP
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                protocol = ProtocolType.UDP
            else:
                src_port = dst_port = 0
                protocol = ProtocolType.UNKNOWN
            
            # Détection du protocole applicatif
            app_protocol = self._detect_application_protocol(packet, src_port, dst_port)
            if app_protocol != ProtocolType.UNKNOWN:
                protocol = app_protocol
            
            flow_id = self._generate_flow_id(packet)
            
            return NetworkFlow(
                flow_id=flow_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                start_time=timestamp,
                bytes_sent=int(packet.length) if hasattr(packet, 'length') else 0,
                packets_sent=1
            )
            
        except Exception as e:
            logger.debug(f"Erreur création flux: {e}")
            return None
    
    def _update_flow_with_packet(self, flow: NetworkFlow, packet):
        """Met à jour un flux avec un nouveau paquet"""
        try:
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
            packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            
            # Mise à jour de la fin du flux
            if flow.end_time is None or timestamp > flow.end_time:
                flow.end_time = timestamp
            
            # Détermination de la direction
            if packet.ip.src == flow.src_ip:
                flow.bytes_sent += packet_size
                flow.packets_sent += 1
            else:
                flow.bytes_received += packet_size
                flow.packets_received += 1
            
            # Calcul de la durée
            if flow.end_time and flow.start_time:
                flow.duration = (flow.end_time - flow.start_time).total_seconds()
            
        except Exception as e:
            logger.debug(f"Erreur mise à jour flux: {e}")
    
    def _detect_application_protocol(self, packet, src_port: int, dst_port: int) -> ProtocolType:
        """Détecte le protocole applicatif"""
        # Vérification par port
        for port in [src_port, dst_port]:
            if port == 80:
                return ProtocolType.HTTP
            elif port == 443:
                return ProtocolType.HTTPS
            elif port == 21:
                return ProtocolType.FTP
            elif port == 22:
                return ProtocolType.SSH
            elif port == 23:
                return ProtocolType.TELNET
            elif port == 25:
                return ProtocolType.SMTP
            elif port == 53:
                return ProtocolType.DNS
            elif port == 110:
                return ProtocolType.POP3
            elif port == 143:
                return ProtocolType.IMAP
            elif port == 445:
                return ProtocolType.SMB
            elif port == 3389:
                return ProtocolType.RDP
        
        # Détection par contenu (pour HTTP sur ports non-standard)
        if hasattr(packet, 'tcp') and hasattr(packet, 'http'):
            return ProtocolType.HTTP
        
        # Protocole de base
        if hasattr(packet, 'tcp'):
            return ProtocolType.TCP
        elif hasattr(packet, 'udp'):
            return ProtocolType.UDP
        elif hasattr(packet, 'icmp'):
            return ProtocolType.ICMP
        
        return ProtocolType.UNKNOWN
    
    def _parse_tshark_flows(self, output: str) -> List[NetworkFlow]:
        """Parse la sortie tshark pour créer des flux"""
        flows = []
        flows_dict = {}
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) >= 6:
                try:
                    src_ip = parts[0]
                    src_port = int(parts[1]) if parts[1].isdigit() else 0
                    dst_ip = parts[2]
                    dst_port = int(parts[3]) if parts[3].isdigit() else 0
                    length = int(parts[4]) if parts[4].isdigit() else 0
                    timestamp_str = parts[5]
                    
                    # Parse du timestamp
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    
                    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"
                    
                    if flow_id not in flows_dict:
                        flow = NetworkFlow(
                            flow_id=flow_id,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol=ProtocolType.TCP,
                            start_time=timestamp,
                            bytes_sent=length,
                            packets_sent=1
                        )
                        flows_dict[flow_id] = flow
                    else:
                        flow = flows_dict[flow_id]
                        flow.bytes_sent += length
                        flow.packets_sent += 1
                        flow.end_time = timestamp
                        
                except Exception as e:
                    logger.debug(f"Erreur parse ligne tshark: {e}")
                    continue
        
        return list(flows_dict.values())
    
    def _get_country(self, ip_address: str) -> Optional[str]:
        """Obtient le pays d'une adresse IP"""
        geo_info = self.geolocation.resolve_ip(ip_address)
        return geo_info.get('country') if geo_info else None
    
    def _analyze_flow_suspicion(self, flow: NetworkFlow) -> Tuple[bool, ThreatLevel, List[str]]:
        """Analyse la suspicion d'un flux"""
        suspicious = False
        threat_level = ThreatLevel.LOW
        indicators = []
        
        # Ports suspects
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 8888, 9999]
        if flow.src_port in suspicious_ports or flow.dst_port in suspicious_ports:
            suspicious = True
            indicators.append(f"Suspicious port: {flow.src_port}/{flow.dst_port}")
            threat_level = ThreatLevel.MEDIUM
        
        # Trafic vers des pays à risque
        risky_countries = ['Unknown', 'CN', 'RU', 'KP', 'IR']
        if flow.country_dst in risky_countries:
            indicators.append(f"Communication to risky country: {flow.country_dst}")
            threat_level = max(threat_level, ThreatLevel.LOW)
        
        # Volumes de données anormaux
        if flow.bytes_sent > 100 * 1024 * 1024:  # 100MB
            suspicious = True
            indicators.append("Large data transfer (possible exfiltration)")
            threat_level = max(threat_level, ThreatLevel.HIGH)
        
        # Durée anormalement longue
        if flow.duration and flow.duration > 3600:  # 1 heure
            indicators.append("Long-duration connection")
            threat_level = max(threat_level, ThreatLevel.LOW)
        
        # Communications sur ports non-standard pour protocoles connus
        if flow.protocol == ProtocolType.HTTP and flow.dst_port not in [80, 8080, 8000]:
            indicators.append(f"HTTP on non-standard port {flow.dst_port}")
            threat_level = max(threat_level, ThreatLevel.LOW)
        
        return suspicious, threat_level, indicators
    
    def extract_dns_queries(self) -> List[DNSQuery]:
        """
        Extrait les requêtes DNS de la capture
        
        Returns:
            Liste des requêtes DNS
        """
        if not self.pcap_file:
            logger.error("Aucune capture ouverte")
            return []
        
        queries = []
        
        try:
            if PYSHARK_AVAILABLE:
                queries = self._extract_dns_with_pyshark()
            else:
                queries = self._extract_dns_with_tshark()
            
            # Analyse de réputation des domaines
            for query in queries:
                query.suspicious, query.domain_reputation = self._analyze_domain_reputation(query.query_name)
            
            # Sauvegarde en base
            self._save_dns_to_db(queries)
            
            logger.info(f"Extraction terminée: {len(queries)} requêtes DNS")
            suspicious_count = sum(1 for q in queries if q.suspicious)
            if suspicious_count > 0:
                logger.warning(f"{suspicious_count} requêtes DNS suspectes")
            
        except Exception as e:
            logger.error(f"Erreur extraction DNS: {e}")
        
        return queries
    
    def _extract_dns_with_pyshark(self) -> List[DNSQuery]:
        """Extrait les requêtes DNS avec pyshark"""
        queries = []
        
        try:
            cap = pyshark.FileCapture(self.pcap_file, display_filter='dns')
            
            for packet in cap:
                try:
                    if hasattr(packet, 'dns'):
                        timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
                        
                        # Requête DNS
                        if hasattr(packet.dns, 'qry_name'):
                            query = DNSQuery(
                                timestamp=timestamp,
                                src_ip=packet.ip.src,
                                query_name=packet.dns.qry_name,
                                query_type=packet.dns.qry_type_name if hasattr(packet.dns, 'qry_type_name') else 'A'
                            )
                            
                            # Réponse DNS si présente
                            if hasattr(packet.dns, 'resp_code'):
                                query.response_code = packet.dns.resp_code
                            
                            if hasattr(packet.dns, 'a') and packet.dns.a:
                                query.resolved_ip = packet.dns.a
                            
                            if hasattr(packet.dns, 'resp_ttl'):
                                query.ttl = int(packet.dns.resp_ttl)
                            
                            queries.append(query)
                            
                except Exception as e:
                    logger.debug(f"Erreur traitement DNS: {e}")
                    continue
            
            cap.close()
            
        except Exception as e:
            logger.error(f"Erreur extraction DNS pyshark: {e}")
        
        return queries
    
    def _extract_dns_with_tshark(self) -> List[DNSQuery]:
        """Extrait les requêtes DNS avec tshark"""
        queries = []
        
        fields = [
            "frame.time", "ip.src", "dns.qry.name", "dns.qry.type", 
            "dns.resp.code", "dns.a", "dns.resp.ttl"
        ]
        
        success, output, error = self.tshark.analyze_capture(
            self.pcap_file, "dns", fields
        )
        
        if success and output:
            for line in output.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 3:
                    try:
                        timestamp_str = parts[0]
                        src_ip = parts[1]
                        query_name = parts[2]
                        
                        # Parse du timestamp
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        
                        query = DNSQuery(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            query_name=query_name,
                            query_type=parts[3] if len(parts) > 3 else 'A'
                        )
                        
                        if len(parts) > 4 and parts[4]:
                            query.response_code = parts[4]
                        
                        if len(parts) > 5 and parts[5]:
                            query.resolved_ip = parts[5]
                        
                        if len(parts) > 6 and parts[6].isdigit():
                            query.ttl = int(parts[6])
                        
                        queries.append(query)
                        
                    except Exception as e:
                        logger.debug(f"Erreur parse DNS tshark: {e}")
                        continue
        
        return queries
    
    def _analyze_domain_reputation(self, domain: str) -> Tuple[bool, str]:
        """Analyse la réputation d'un domaine"""
        suspicious = False
        reputation = "Unknown"
        
        # Domaines suspects par patterns
        for pattern_type, patterns in self.suspicious_patterns['suspicious_domains'].items():
            for pattern in patterns:
                if pattern.search(domain):
                    suspicious = True
                    reputation = f"Suspicious ({pattern_type})"
                    break
            if suspicious:
                break
        
        # TLD suspects
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            suspicious = True
            reputation = "Suspicious TLD"
        
        # Domaines DGA (Domain Generation Algorithm)
        if self._is_dga_domain(domain):
            suspicious = True
            reputation = "Possible DGA"
        
        return suspicious, reputation
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Détecte si un domaine ressemble à un DGA"""
        # Heuristiques simples pour détecter les DGA
        base_domain = domain.split('.')[0]
        
        # Longueur anormale
        if len(base_domain) > 20 or len(base_domain) < 3:
            return True
        
        # Ratio consonnes/voyelles anormal
        vowels = 'aeiou'
        vowel_count = sum(1 for c in base_domain.lower() if c in vowels)
        consonant_count = sum(1 for c in base_domain.lower() if c.isalpha() and c not in vowels)
        
        if consonant_count > 0:
            ratio = vowel_count / consonant_count
            if ratio < 0.1 or ratio > 2.0:  # Ratios anormaux
                return True
        
        # Caractères consécutifs identiques
        for i in range(len(base_domain) - 2):
            if base_domain[i] == base_domain[i+1] == base_domain[i+2]:
                return True
        
        # Motifs numériques suspects
        if re.search(r'\d{5,}', base_domain):
            return True
        
        return False
    
    def extract_http_transactions(self) -> List[HTTPTransaction]:
        """
        Extrait les transactions HTTP de la capture
        
        Returns:
            Liste des transactions HTTP
        """
        if not self.pcap_file:
            logger.error("Aucune capture ouverte")
            return []
        
        transactions = []
        
        try:
            if PYSHARK_AVAILABLE:
                transactions = self._extract_http_with_pyshark()
            else:
                transactions = self._extract_http_with_tshark()
            
            # Analyse de suspicion
            for transaction in transactions:
                transaction.suspicious, transaction.malware_indicators = self._analyze_http_suspicion(transaction)
            
            # Sauvegarde en base
            self._save_http_to_db(transactions)
            
            logger.info(f"Extraction terminée: {len(transactions)} transactions HTTP")
            suspicious_count = sum(1 for t in transactions if t.suspicious)
            if suspicious_count > 0:
                logger.warning(f"{suspicious_count} transactions HTTP suspectes")
            
        except Exception as e:
            logger.error(f"Erreur extraction HTTP: {e}")
        
        return transactions
    
    def _extract_http_with_pyshark(self) -> List[HTTPTransaction]:
        """Extrait les transactions HTTP avec pyshark"""
        transactions = []
        
        try:
            cap = pyshark.FileCapture(self.pcap_file, display_filter='http')
            
            for packet in cap:
                try:
                    if hasattr(packet, 'http'):
                        timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
                        
                        # Requête HTTP
                        if hasattr(packet.http, 'request_method'):
                            transaction = HTTPTransaction(
                                timestamp=timestamp,
                                src_ip=packet.ip.src,
                                dst_ip=packet.ip.dst,
                                method=packet.http.request_method,
                                url=getattr(packet.http, 'request_full_uri', ''),
                                host=getattr(packet.http, 'host', '')
                            )
                            
                            # Headers et autres informations
                            if hasattr(packet.http, 'user_agent'):
                                transaction.user_agent = packet.http.user_agent
                            
                            if hasattr(packet.http, 'referer'):
                                transaction.referrer = packet.http.referer
                            
                            if hasattr(packet.http, 'cookie'):
                                transaction.cookies = self._parse_cookies(packet.http.cookie)
                            
                            # Corps de la requête si présent
                            if hasattr(packet, 'data'):
                                transaction.request_body = packet.data.data
                            
                            transactions.append(transaction)
                        
                        # Réponse HTTP
                        elif hasattr(packet.http, 'response_code'):
                            # Associer à la dernière requête (simplification)
                            if transactions:
                                last_transaction = transactions[-1]
                                last_transaction.status_code = int(packet.http.response_code)
                                
                                if hasattr(packet.http, 'content_type'):
                                    last_transaction.content_type = packet.http.content_type
                                
                                if hasattr(packet.http, 'content_length'):
                                    last_transaction.content_length = int(packet.http.content_length)
                                
                                if hasattr(packet, 'data'):
                                    last_transaction.response_body = packet.data.data[:1000]  # Limité
                            
                except Exception as e:
                    logger.debug(f"Erreur traitement HTTP: {e}")
                    continue
            
            cap.close()
            
        except Exception as e:
            logger.error(f"Erreur extraction HTTP pyshark: {e}")
        
        return transactions
    
    def _extract_http_with_tshark(self) -> List[HTTPTransaction]:
        """Extrait les transactions HTTP avec tshark"""
        transactions = []
        
        fields = [
            "frame.time", "ip.src", "ip.dst", "http.request.method",
            "http.request.full_uri", "http.host", "http.user_agent",
            "http.response.code", "http.content_type", "http.content_length"
        ]
        
        success, output, error = self.tshark.analyze_capture(
            self.pcap_file, "http", fields
        )
        
        if success and output:
            for line in output.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 6:
                    try:
                        timestamp_str = parts[0]
                        src_ip = parts[1]
                        dst_ip = parts[2]
                        method = parts[3]
                        url = parts[4]
                        host = parts[5]
                        
                        if method:  # Requête HTTP
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            
                            transaction = HTTPTransaction(
                                timestamp=timestamp,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                method=method,
                                url=url,
                                host=host
                            )
                            
                            if len(parts) > 6 and parts[6]:
                                transaction.user_agent = parts[6]
                            
                            if len(parts) > 7 and parts[7].isdigit():
                                transaction.status_code = int(parts[7])
                            
                            if len(parts) > 8 and parts[8]:
                                transaction.content_type = parts[8]
                            
                            if len(parts) > 9 and parts[9].isdigit():
                                transaction.content_length = int(parts[9])
                            
                            transactions.append(transaction)
                            
                    except Exception as e:
                        logger.debug(f"Erreur parse HTTP tshark: {e}")
                        continue
        
        return transactions
    
    def _parse_cookies(self, cookie_string: str) -> Dict[str, str]:
        """Parse une chaîne de cookies"""
        cookies = {}
        
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        
        return cookies
    
    def _analyze_http_suspicion(self, transaction: HTTPTransaction) -> Tuple[bool, List[str]]:
        """Analyse la suspicion d'une transaction HTTP"""
        suspicious = False
        indicators = []
        
        # URL suspecte
        url_lower = transaction.url.lower()
        
        # Patterns de malware C&C
        for pattern in self.suspicious_patterns['malware_c2']:
            if pattern.search(url_lower):
                suspicious = True
                indicators.append("Malware C&C pattern detected")
                break
        
        # Patterns d'exfiltration de données
        for pattern in self.suspicious_patterns['data_exfiltration']:
            if pattern.search(url_lower) or (transaction.request_body and pattern.search(transaction.request_body)):
                suspicious = True
                indicators.append("Data exfiltration pattern detected")
                break
        
        # Patterns de vol de credentials
        for pattern in self.suspicious_patterns['credential_theft']:
            if transaction.request_body and pattern.search(transaction.request_body):
                suspicious = True
                indicators.append("Credential theft pattern detected")
                break
        
        # Patterns de webshell
        for pattern in self.suspicious_patterns['webshell_activity']:
            if pattern.search(url_lower):
                suspicious = True
                indicators.append("Webshell activity detected")
                break
        
        # User-Agent suspects
        suspicious_uas = ['wget', 'curl', 'powershell', 'python-requests', 'bot']
        if transaction.user_agent:
            ua_lower = transaction.user_agent.lower()
            if any(sus_ua in ua_lower for sus_ua in suspicious_uas):
                indicators.append(f"Suspicious User-Agent: {transaction.user_agent}")
        
        # Fichiers suspects transférés
        if transaction.url:
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
            if any(transaction.url.endswith(ext) for ext in suspicious_extensions):
                suspicious = True
                indicators.append("Suspicious file extension")
        
        # Taille anormalement grande
        if transaction.content_length and transaction.content_length > 50 * 1024 * 1024:  # 50MB
            suspicious = True
            indicators.append("Large file transfer")
        
        # Codes de statut suspects
        if transaction.status_code in [401, 403, 404, 500]:
            indicators.append(f"HTTP error status: {transaction.status_code}")
        
        return suspicious, indicators
    
    def detect_suspicious_activities(self) -> List[SuspiciousActivity]:
        """
        Détecte les activités suspectes dans la capture
        
        Returns:
            Liste des activités suspectes
        """
        if not self.pcap_file:
            logger.error("Aucune capture ouverte")
            return []
        
        activities = []
        
        try:
            # Détection de port scanning
            port_scan_activities = self._detect_port_scanning()
            activities.extend(port_scan_activities)
            
            # Détection de brute force
            brute_force_activities = self._detect_brute_force()
            activities.extend(brute_force_activities)
            
            # Détection de beaconing
            beaconing_activities = self._detect_beaconing()
            activities.extend(beaconing_activities)
            
            # Détection d'exfiltration DNS
            dns_exfil_activities = self._detect_dns_exfiltration()
            activities.extend(dns_exfil_activities)
            
            # Sauvegarde en base
            self._save_suspicious_activities_to_db(activities)
            
            logger.info(f"Détection terminée: {len(activities)} activités suspectes")
            
            # Répartition par sévérité
            severity_counts = {}
            for activity in activities:
                severity_counts[activity.severity.value] = severity_counts.get(activity.severity.value, 0) + 1
            
            for severity, count in severity_counts.items():
                logger.info(f"  {severity}: {count}")
            
        except Exception as e:
            logger.error(f"Erreur détection activités suspectes: {e}")
        
        return activities
    
    def _detect_port_scanning(self) -> List[SuspiciousActivity]:
        """Détecte les tentatives de port scanning"""
        activities = []
        
        # Analyse des connexions par IP source
        ip_port_counts = {}
        
        if PYSHARK_AVAILABLE:
            try:
                cap = pyshark.FileCapture(self.pcap_file, display_filter='tcp.flags.syn==1 and tcp.flags.ack==0')
                
                for packet in cap:
                    try:
                        if hasattr(packet, 'tcp'):
                            src_ip = packet.ip.src
                            dst_port = int(packet.tcp.dstport)
                            
                            if src_ip not in ip_port_counts:
                                ip_port_counts[src_ip] = set()
                            ip_port_counts[src_ip].add(dst_port)
                            
                    except Exception as e:
                        continue
                
                cap.close()
                
            except Exception as e:
                logger.debug(f"Erreur détection port scan: {e}")
        
        # Analyse des résultats
        for src_ip, ports in ip_port_counts.items():
            if len(ports) > 50:  # Seuil de détection
                activity = SuspiciousActivity(
                    timestamp=datetime.now(timezone.utc),
                    activity_type="Port Scanning",
                    source_ip=src_ip,
                    protocol=ProtocolType.TCP,
                    description=f"Port scanning detected from {src_ip} targeting {len(ports)} ports",
                    severity=ThreatLevel.HIGH if len(ports) > 100 else ThreatLevel.MEDIUM,
                    indicators=[f"Scanned {len(ports)} ports"],
                    recommendations=["Block source IP", "Investigate source host", "Check for successful connections"]
                )
                activities.append(activity)
        
        return activities
    
    def _detect_brute_force(self) -> List[SuspiciousActivity]:
        """Détecte les tentatives de brute force"""
        activities = []
        
        # Analyse des connexions SSH/RDP/FTP échouées
        connection_attempts = {}
        
        if PYSHARK_AVAILABLE:
            try:
                # SSH (port 22), RDP (port 3389), FTP (port 21)
                cap = pyshark.FileCapture(self.pcap_file, 
                    display_filter='tcp.dstport==22 or tcp.dstport==3389 or tcp.dstport==21')
                
                for packet in cap:
                    try:
                        if hasattr(packet, 'tcp'):
                            src_ip = packet.ip.src
                            dst_port = int(packet.tcp.dstport)
                            
                            key = f"{src_ip}:{dst_port}"
                            if key not in connection_attempts:
                                connection_attempts[key] = 0
                            connection_attempts[key] += 1
                            
                    except Exception:
                        continue
                
                cap.close()
                
            except Exception as e:
                logger.debug(f"Erreur détection brute force: {e}")
        
        # Analyse des résultats
        for key, count in connection_attempts.items():
            if count > 20:  # Seuil de détection
                src_ip, port = key.split(':')
                service = {22: "SSH", 3389: "RDP", 21: "FTP"}.get(int(port), "Unknown")
                
                activity = SuspiciousActivity(
                    timestamp=datetime.now(timezone.utc),
                    activity_type="Brute Force Attack",
                    source_ip=src_ip,
                    protocol=ProtocolType.TCP,
                    description=f"Brute force attack detected against {service} service ({count} attempts)",
                    severity=ThreatLevel.HIGH if count > 100 else ThreatLevel.MEDIUM,
                    indicators=[f"{count} connection attempts to {service}"],
                    recommendations=["Block source IP", "Enable account lockout", "Monitor authentication logs"]
                )
                activities.append(activity)
        
        return activities
    
    def _detect_beaconing(self) -> List[SuspiciousActivity]:
        """Détecte les communications de beaconing (malware C&C)"""
        activities = []
        
        # Analyse des intervalles de communication réguliers
        # Cette détection nécessiterait une analyse statistique plus poussée
        # Implémentation simplifiée ici
        
        return activities
    
    def _detect_dns_exfiltration(self) -> List[SuspiciousActivity]:
        """Détecte l'exfiltration de données via DNS"""
        activities = []
        
        # Analyse des requêtes DNS avec des sous-domaines suspects
        if PYSHARK_AVAILABLE:
            try:
                cap = pyshark.FileCapture(self.pcap_file, display_filter='dns')
                
                dns_queries = {}
                
                for packet in cap:
                    try:
                        if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                            query_name = packet.dns.qry_name
                            src_ip = packet.ip.src
                            
                            if src_ip not in dns_queries:
                                dns_queries[src_ip] = []
                            dns_queries[src_ip].append(query_name)
                            
                    except Exception:
                        continue
                
                cap.close()
                
                # Analyse des patterns suspects
                for src_ip, queries in dns_queries.items():
                    # Détection de sous-domaines longs (possibles données encodées)
                    long_subdomains = [q for q in queries if '.' in q and len(q.split('.')[0]) > 30]
                    
                    if len(long_subdomains) > 10:
                        activity = SuspiciousActivity(
                            timestamp=datetime.now(timezone.utc),
                            activity_type="DNS Data Exfiltration",
                            source_ip=src_ip,
                            protocol=ProtocolType.DNS,
                            description=f"Possible DNS exfiltration detected from {src_ip} ({len(long_subdomains)} suspicious queries)",
                            severity=ThreatLevel.HIGH,
                            indicators=["Long subdomain names", "High query frequency"],
                            recommendations=["Analyze DNS queries", "Block suspicious domains", "Monitor for encoded data"]
                        )
                        activities.append(activity)
                        
            except Exception as e:
                logger.debug(f"Erreur détection exfiltration DNS: {e}")
        
        return activities
    
    def reconstruct_files(self) -> List[FileTransfer]:
        """
        Reconstruit les fichiers transférés via HTTP/FTP
        
        Returns:
            Liste des transferts de fichiers
        """
        if not self.pcap_file:
            logger.error("Aucune capture ouverte")
            return []
        
        file_transfers = []
        
        try:
            # Reconstruction des fichiers HTTP
            http_files = self._reconstruct_http_files()
            file_transfers.extend(http_files)
            
            # Reconstruction des fichiers FTP
            ftp_files = self._reconstruct_ftp_files()
            file_transfers.extend(ftp_files)
            
            # Sauvegarde en base
            self._save_file_transfers_to_db(file_transfers)
            
            logger.info(f"Reconstruction terminée: {len(file_transfers)} fichiers")
            
        except Exception as e:
            logger.error(f"Erreur reconstruction fichiers: {e}")
        
        return file_transfers
    
    def _reconstruct_http_files(self) -> List[FileTransfer]:
        """Reconstruit les fichiers transférés via HTTP"""
        file_transfers = []
        
        if PYSHARK_AVAILABLE:
            try:
                cap = pyshark.FileCapture(self.pcap_file, display_filter='http')
                
                for packet in cap:
                    try:
                        if hasattr(packet, 'http'):
                            # Recherche de téléchargements de fichiers
                            if hasattr(packet.http, 'content_disposition'):
                                filename = self._extract_filename_from_http(packet.http.content_disposition)
                                if filename:
                                    timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
                                    
                                    transfer = FileTransfer(
                                        timestamp=timestamp,
                                        protocol=ProtocolType.HTTP,
                                        src_ip=packet.ip.dst,  # Serveur
                                        dst_ip=packet.ip.src,  # Client
                                        filename=filename,
                                        direction="download"
                                    )
                                    
                                    if hasattr(packet.http, 'content_length'):
                                        transfer.file_size = int(packet.http.content_length)
                                    
                                    if hasattr(packet.http, 'content_type'):
                                        transfer.file_type = packet.http.content_type
                                    
                                    file_transfers.append(transfer)
                                    
                    except Exception:
                        continue
                
                cap.close()
                
            except Exception as e:
                logger.debug(f"Erreur reconstruction HTTP: {e}")
        
        return file_transfers
    
    def _reconstruct_ftp_files(self) -> List[FileTransfer]:
        """Reconstruit les fichiers transférés via FTP"""
        file_transfers = []
        
        # Implémentation simplifiée - nécessiterait une analyse plus poussée des commandes FTP
        
        return file_transfers
    
    def _extract_filename_from_http(self, content_disposition: str) -> Optional[str]:
        """Extrait le nom de fichier de l'en-tête Content-Disposition"""
        try:
            # Format: attachment; filename="file.exe"
            if 'filename=' in content_disposition:
                filename_part = content_disposition.split('filename=')[1]
                filename = filename_part.strip().strip('"\'')
                return filename
        except:
            pass
        
        return None
    
    def _save_analysis_info(self, case_id: str, pcap_file: str, file_size: int,
                          md5_hash: str, sha256_hash: str, total_packets: int):
        """Sauvegarde les informations d'analyse en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO network_analysis 
            (case_id, pcap_file, file_size, file_md5, file_sha256, total_packets, analysis_start)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (case_id, pcap_file, file_size, md5_hash, sha256_hash, total_packets, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def _save_flows_to_db(self, flows: List[NetworkFlow]):
        """Sauvegarde les flux réseau en base"""
        if not flows:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for flow in flows:
            cursor.execute('''
                INSERT INTO network_flows 
                (case_id, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, start_time, 
                 end_time, bytes_sent, bytes_received, packets_sent, packets_received, duration,
                 country_src, country_dst, suspicious, threat_level, indicators)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, flow.flow_id, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                flow.protocol.value, flow.start_time, flow.end_time, flow.bytes_sent, flow.bytes_received,
                flow.packets_sent, flow.packets_received, flow.duration, flow.country_src, flow.country_dst,
                flow.suspicious, flow.threat_level.value, json.dumps(flow.indicators)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_dns_to_db(self, queries: List[DNSQuery]):
        """Sauvegarde les requêtes DNS en base"""
        if not queries:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for query in queries:
            cursor.execute('''
                INSERT INTO dns_queries 
                (case_id, timestamp, src_ip, query_name, query_type, response_code, 
                 resolved_ip, ttl, suspicious, domain_reputation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, query.timestamp, query.src_ip, query.query_name, query.query_type,
                query.response_code, query.resolved_ip, query.ttl, query.suspicious, query.domain_reputation
            ))
        
        conn.commit()
        conn.close()
    
    def _save_http_to_db(self, transactions: List[HTTPTransaction]):
        """Sauvegarde les transactions HTTP en base"""
        if not transactions:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for transaction in transactions:
            cursor.execute('''
                INSERT INTO http_transactions 
                (case_id, timestamp, src_ip, dst_ip, method, url, host, user_agent, 
                 status_code, content_type, content_length, suspicious, malware_indicators)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, transaction.timestamp, transaction.src_ip, transaction.dst_ip,
                transaction.method, transaction.url, transaction.host, transaction.user_agent,
                transaction.status_code, transaction.content_type, transaction.content_length,
                transaction.suspicious, json.dumps(transaction.malware_indicators)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_suspicious_activities_to_db(self, activities: List[SuspiciousActivity]):
        """Sauvegarde les activités suspectes en base"""
        if not activities:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for activity in activities:
            cursor.execute('''
                INSERT INTO suspicious_activities 
                (case_id, timestamp, activity_type, source_ip, destination_ip, protocol,
                 description, severity, indicators, raw_data, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, activity.timestamp, activity.activity_type, activity.source_ip,
                activity.destination_ip, activity.protocol.value, activity.description,
                activity.severity.value, json.dumps(activity.indicators), activity.raw_data,
                json.dumps(activity.recommendations)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_file_transfers_to_db(self, transfers: List[FileTransfer]):
        """Sauvegarde les transferts de fichiers en base"""
        if not transfers:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for transfer in transfers:
            cursor.execute('''
                INSERT INTO file_transfers 
                (case_id, timestamp, protocol, src_ip, dst_ip, filename, file_size, 
                 file_hash, file_type, direction, reconstructed_path, suspicious, malware_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, transfer.timestamp, transfer.protocol.value, transfer.src_ip, transfer.dst_ip,
                transfer.filename, transfer.file_size, transfer.file_hash, transfer.file_type,
                transfer.direction, transfer.reconstructed_path, transfer.suspicious, transfer.malware_score
            ))
        
        conn.commit()
        conn.close()
    
    def export_results(self, output_file: str, format_type: str = 'json') -> bool:
        """
        Export des résultats d'analyse réseau
        
        Args:
            output_file: Fichier de sortie
            format_type: Format (json, csv, xml)
            
        Returns:
            True si succès
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            if format_type.lower() == 'json':
                # Export JSON complet
                data = {
                    'analysis_info': self._get_analysis_info_from_db(conn),
                    'network_flows': self._get_flows_from_db(conn),
                    'dns_queries': self._get_dns_from_db(conn),
                    'http_transactions': self._get_http_from_db(conn),
                    'suspicious_activities': self._get_suspicious_from_db(conn),
                    'file_transfers': self._get_transfers_from_db(conn)
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                # Export CSV des flux réseau
                import csv
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM network_flows WHERE case_id = ?', (self.case_id,))
                
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([desc[0] for desc in cursor.description])
                    writer.writerows(cursor.fetchall())
            
            conn.close()
            logger.info(f"Résultats exportés vers {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export: {e}")
            return False
    
    def _get_analysis_info_from_db(self, conn) -> Dict:
        """Récupère les informations d'analyse depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_analysis WHERE case_id = ?', (self.case_id,))
        row = cursor.fetchone()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return {}
    
    def _get_flows_from_db(self, conn) -> List[Dict]:
        """Récupère les flux depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_flows WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_dns_from_db(self, conn) -> List[Dict]:
        """Récupère les DNS depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dns_queries WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_http_from_db(self, conn) -> List[Dict]:
        """Récupère les HTTP depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM http_transactions WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_suspicious_from_db(self, conn) -> List[Dict]:
        """Récupère les activités suspectes depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM suspicious_activities WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_transfers_from_db(self, conn) -> List[Dict]:
        """Récupère les transferts depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM file_transfers WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def close(self):
        """Ferme l'analyseur et nettoie les ressources"""
        self.pcap_file = None
        self.case_id = None
        logger.info("Analyseur réseau fermé")


def main():
    """Fonction de démonstration"""
    print("🌐 Forensic Analysis Toolkit - Network Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = NetworkAnalyzer(evidence_dir="./evidence", temp_dir="./temp")
    
    # Simulation avec une capture de test (remplacer par une vraie capture)
    test_pcap = "./test_captures/sample.pcap"
    case_id = f"NETWORK_CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Cas d'analyse: {case_id}")
    
    # Si la capture de test existe
    if Path(test_pcap).exists():
        print(f"🌐 Ouverture de la capture: {test_pcap}")
        
        if analyzer.open_capture(test_pcap, case_id):
            # Analyse des flux réseau
            print("🔄 Analyse des flux réseau...")
            flows = analyzer.analyze_network_flows()
            
            print(f"📊 {len(flows)} flux réseau analysés")
            suspicious_count = sum(1 for f in flows if f.suspicious)
            if suspicious_count > 0:
                print(f"⚠️  {suspicious_count} flux suspects détectés")
            
            # Extraction des requêtes DNS
            print("🔍 Extraction des requêtes DNS...")
            dns_queries = analyzer.extract_dns_queries()
            print(f"📡 {len(dns_queries)} requêtes DNS extraites")
            
            # Extraction des transactions HTTP
            print("🌐 Extraction des transactions HTTP...")
            http_transactions = analyzer.extract_http_transactions()
            print(f"📄 {len(http_transactions)} transactions HTTP extraites")
            
            # Détection d'activités suspectes
            print("🚨 Détection d'activités suspectes...")
            suspicious_activities = analyzer.detect_suspicious_activities()
            print(f"🔴 {len(suspicious_activities)} activités suspectes détectées")
            
            # Reconstruction de fichiers
            print("📁 Reconstruction des fichiers...")
            file_transfers = analyzer.reconstruct_files()
            print(f"💾 {len(file_transfers)} fichiers reconstruits")
            
            # Export des résultats
            output_file = f"./network_analysis_{case_id}.json"
            if analyzer.export_results(output_file, 'json'):
                print(f"📄 Résultats exportés: {output_file}")
            
        analyzer.close()
    else:
        print("⚠️  Aucune capture réseau de test trouvée")
        print(f"   Créez un fichier {test_pcap} ou modifiez le chemin")
        print("   Exemple: tcpdump -i eth0 -w sample.pcap")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()