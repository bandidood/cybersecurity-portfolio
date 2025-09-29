#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Memory Analyzer - Forensic Analysis Toolkit
============================================================================
Analyseur de mémoire forensique utilisant Volatility Framework pour :
- Analyse des dumps mémoire RAM (Windows, Linux, macOS)
- Extraction des processus, DLLs, et artefacts système
- Détection de malware et rootkits en mémoire
- Récupération de mots de passe et clés de chiffrement
- Analyse des connexions réseau et handles système
- Timeline des activités en mémoire

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
import struct
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import psutil
import yara

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OSType(Enum):
    """Types de systèmes d'exploitation supportés"""
    WINDOWS_XP = "Windows XP"
    WINDOWS_VISTA = "Windows Vista"  
    WINDOWS_7 = "Windows 7"
    WINDOWS_8 = "Windows 8"
    WINDOWS_10 = "Windows 10"
    WINDOWS_11 = "Windows 11"
    LINUX = "Linux"
    MACOS = "macOS"
    UNKNOWN = "Unknown"


class MemoryDumpFormat(Enum):
    """Formats de dumps mémoire supportés"""
    RAW = "raw"
    CRASH_DUMP = "crashdump"  
    HIBERNATION = "hiberfil"
    VMM = "vmware"
    HYPER_V = "hyperv"
    LIME = "lime"
    QEMU = "qemu"


@dataclass
class SystemInfo:
    """Informations système extraites de la mémoire"""
    os_type: OSType
    build_number: Optional[str] = None
    service_pack: Optional[str] = None
    architecture: Optional[str] = None
    kernel_version: Optional[str] = None
    total_memory: Optional[int] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    timezone: Optional[str] = None
    boot_time: Optional[datetime] = None


@dataclass
class MemoryProcess:
    """Processus extrait de la mémoire"""
    pid: int
    ppid: int
    name: str
    image_path: str
    command_line: Optional[str] = None
    create_time: Optional[datetime] = None
    exit_time: Optional[datetime] = None
    session_id: Optional[int] = None
    threads: Optional[int] = None
    handles: Optional[int] = None
    wow64: bool = False
    token: Optional[Dict[str, Any]] = None
    privileges: List[str] = field(default_factory=list)
    dlls: List[Dict[str, Any]] = field(default_factory=list)
    vad_info: List[Dict[str, Any]] = field(default_factory=list)
    suspicious: bool = False
    yara_matches: List[str] = field(default_factory=list)


@dataclass
class NetworkConnection:
    """Connexion réseau extraite de la mémoire"""
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    create_time: Optional[datetime] = None
    owner: Optional[str] = None


@dataclass
class RegistryEntry:
    """Entrée de registre extraite de la mémoire"""
    hive_name: str
    key_path: str
    value_name: Optional[str] = None
    value_type: Optional[str] = None
    value_data: Optional[str] = None
    last_write_time: Optional[datetime] = None


@dataclass
class FileHandle:
    """Handle de fichier extrait de la mémoire"""
    pid: int
    process_name: str
    handle_value: int
    handle_type: str
    file_path: Optional[str] = None
    access_mask: Optional[str] = None
    granted_access: Optional[str] = None


@dataclass
class MemoryArtifact:
    """Artefact extrait de la mémoire"""
    artifact_type: str  # password, key, url, email, etc.
    value: str
    confidence: float
    source_process: Optional[str] = None
    source_address: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class VolatilityWrapper:
    """Wrapper pour interagir avec Volatility Framework"""
    
    def __init__(self, volatility_path: str = None):
        """
        Initialise le wrapper Volatility
        
        Args:
            volatility_path: Chemin vers l'exécutable Volatility (None = auto-détection)
        """
        self.volatility_path = self._find_volatility_path(volatility_path)
        self.profile_cache = {}
    
    def _find_volatility_path(self, provided_path: str = None) -> Optional[str]:
        """Trouve le chemin vers Volatility"""
        if provided_path and Path(provided_path).exists():
            return provided_path
        
        # Recherche dans les emplacements communs
        common_paths = [
            "vol.py",
            "volatility",
            "/usr/bin/vol.py",
            "/usr/local/bin/vol.py",
            "C:\\Tools\\Volatility\\vol.py",
            "./volatility/vol.py"
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
            
            # Test avec `which` ou `where`
            try:
                result = subprocess.run(
                    ["which", path] if os.name != 'nt' else ["where", path],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except:
                continue
        
        logger.warning("Volatility non trouvé, certaines fonctionnalités seront limitées")
        return None
    
    def run_plugin(self, memory_file: str, plugin: str, profile: str = None, 
                  extra_args: List[str] = None) -> Tuple[bool, str, str]:
        """
        Exécute un plugin Volatility
        
        Args:
            memory_file: Fichier dump mémoire
            plugin: Nom du plugin
            profile: Profile à utiliser
            extra_args: Arguments supplémentaires
            
        Returns:
            Tuple (success, stdout, stderr)
        """
        if not self.volatility_path:
            return False, "", "Volatility non disponible"
        
        cmd = ["python", self.volatility_path, "-f", memory_file]
        
        if profile:
            cmd.extend(["--profile", profile])
        
        cmd.append(plugin)
        
        if extra_args:
            cmd.extend(extra_args)
        
        try:
            logger.debug(f"Exécution Volatility: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution du plugin {plugin}")
            return False, "", "Timeout"
        except Exception as e:
            logger.error(f"Erreur exécution Volatility: {e}")
            return False, "", str(e)
    
    def detect_profile(self, memory_file: str) -> Optional[str]:
        """Détecte automatiquement le profil approprié"""
        if memory_file in self.profile_cache:
            return self.profile_cache[memory_file]
        
        success, output, error = self.run_plugin(memory_file, "imageinfo")
        
        if success and output:
            # Parse de la sortie pour extraire les profils suggérés
            lines = output.split('\n')
            for line in lines:
                if "Suggested Profile(s)" in line:
                    # Extrait le premier profil suggéré
                    profiles = line.split(':')[1].strip()
                    if profiles:
                        first_profile = profiles.split(',')[0].strip()
                        self.profile_cache[memory_file] = first_profile
                        return first_profile
        
        logger.warning("Impossible de détecter automatiquement le profil")
        return None


class MemoryAnalyzer:
    """
    Analyseur de mémoire forensique principal
    """
    
    def __init__(self, evidence_dir: str = "./evidence", temp_dir: str = "./temp"):
        """
        Initialise l'analyseur de mémoire
        
        Args:
            evidence_dir: Répertoire pour stocker les preuves
            temp_dir: Répertoire temporaire pour les analyses
        """
        self.evidence_dir = Path(evidence_dir)
        self.temp_dir = Path(temp_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.volatility = VolatilityWrapper()
        self.memory_file = None
        self.profile = None
        self.case_id = None
        self.system_info = None
        
        # Base de données SQLite pour stocker les résultats
        self.db_path = self.evidence_dir / "memory_analysis.db"
        self._init_database()
        
        # Chargement des règles YARA pour malware
        self.yara_rules = self._load_yara_rules()
        
        # Patterns pour extraction d'artefacts
        self.artifact_patterns = self._init_artifact_patterns()
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des analyses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memory_analysis (
                case_id TEXT PRIMARY KEY,
                memory_file TEXT NOT NULL,
                file_size INTEGER,
                file_md5 TEXT,
                file_sha256 TEXT,
                os_type TEXT,
                profile TEXT,
                analysis_start TIMESTAMP,
                analysis_end TIMESTAMP,
                system_info TEXT,
                investigator TEXT
            )
        ''')
        
        # Table des processus
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                pid INTEGER,
                ppid INTEGER,
                name TEXT,
                image_path TEXT,
                command_line TEXT,
                create_time TIMESTAMP,
                exit_time TIMESTAMP,
                session_id INTEGER,
                threads INTEGER,
                handles INTEGER,
                wow64 BOOLEAN,
                suspicious BOOLEAN,
                yara_matches TEXT,
                FOREIGN KEY (case_id) REFERENCES memory_analysis (case_id)
            )
        ''')
        
        # Table des connexions réseau
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                protocol TEXT,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                state TEXT,
                pid INTEGER,
                process_name TEXT,
                create_time TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES memory_analysis (case_id)
            )
        ''')
        
        # Table des entrées registre
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registry_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                hive_name TEXT,
                key_path TEXT,
                value_name TEXT,
                value_type TEXT,
                value_data TEXT,
                last_write_time TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES memory_analysis (case_id)
            )
        ''')
        
        # Table des handles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_handles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                pid INTEGER,
                process_name TEXT,
                handle_value INTEGER,
                handle_type TEXT,
                file_path TEXT,
                access_mask TEXT,
                FOREIGN KEY (case_id) REFERENCES memory_analysis (case_id)
            )
        ''')
        
        # Table des artefacts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memory_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                artifact_type TEXT,
                value TEXT,
                confidence REAL,
                source_process TEXT,
                source_address TEXT,
                metadata TEXT,
                FOREIGN KEY (case_id) REFERENCES memory_analysis (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Charge les règles YARA pour détection malware"""
        try:
            # Règles YARA spécifiques à l'analyse mémoire
            yara_source = '''
            rule Memory_Injected_Code
            {
                meta:
                    description = "Détecte du code injecté en mémoire"
                    author = "Forensic Analysis Toolkit"
                    
                strings:
                    $mz = { 4D 5A }
                    $pe = "PE"
                    $exec_heap = { 48 83 EC ?? 48 89 ?? ?? }
                    
                condition:
                    ($mz at 0 and $pe) or $exec_heap
            }
            
            rule Memory_Shellcode_Pattern
            {
                meta:
                    description = "Détecte des patterns de shellcode"
                    
                strings:
                    $call_pop = { E8 00 00 00 00 58 }
                    $nop_sled = { 90 90 90 90 90 90 90 90 }
                    $xor_decoder = { 31 ?? 83 ?? ?? 74 ?? }
                    
                condition:
                    any of them
            }
            
            rule Memory_Credential_Dump
            {
                meta:
                    description = "Détecte des outils de dump de credentials"
                    
                strings:
                    $mimikatz1 = "sekurlsa::logonpasswords" ascii wide
                    $mimikatz2 = "privilege::debug" ascii wide
                    $lsass = "lsass.exe" ascii wide nocase
                    $wdigest = "wdigest" ascii wide nocase
                    
                condition:
                    any of them
            }
            
            rule Memory_Process_Hollowing
            {
                meta:
                    description = "Détecte les techniques de process hollowing"
                    
                strings:
                    $nt_unmap = "NtUnmapViewOfSection" ascii
                    $nt_write = "NtWriteVirtualMemory" ascii
                    $nt_resume = "NtResumeThread" ascii
                    
                condition:
                    2 of them
            }
            '''
            
            return yara.compile(source=yara_source)
            
        except Exception as e:
            logger.warning(f"Impossible de charger les règles YARA: {e}")
            return None
    
    def _init_artifact_patterns(self) -> Dict[str, re.Pattern]:
        """Initialise les patterns pour extraction d'artefacts"""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'url_http': re.compile(r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'file_path_windows': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\n\r]+\\?)*'),
            'file_path_unix': re.compile(r'/(?:[^/\0]+/)*[^/\0]*'),
            'registry_key': re.compile(r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CURRENT_CONFIG|CLASSES_ROOT)\\[^\n\r]*'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }
    
    def open_memory_dump(self, memory_file: str, case_id: str, profile: str = None) -> bool:
        """
        Ouvre un dump mémoire pour analyse
        
        Args:
            memory_file: Chemin vers le dump mémoire
            case_id: Identifiant du cas
            profile: Profile Volatility (détecté automatiquement si None)
            
        Returns:
            True si succès, False sinon
        """
        try:
            memory_path = Path(memory_file)
            
            if not memory_path.exists():
                logger.error(f"Le dump mémoire {memory_path} n'existe pas")
                return False
            
            self.memory_file = str(memory_path)
            self.case_id = case_id
            
            # Calcul des hashs du fichier
            file_size = memory_path.stat().st_size
            md5_hash, sha256_hash = self._calculate_file_hashes(memory_path)
            
            # Détection automatique du profil si non spécifié
            if profile is None:
                profile = self.volatility.detect_profile(self.memory_file)
            
            self.profile = profile
            
            if not self.profile:
                logger.warning("Profil non détecté, certaines analyses peuvent échouer")
            
            # Extraction des informations système de base
            self.system_info = self._extract_system_info()
            
            # Sauvegarde des informations d'analyse
            self._save_analysis_info(
                case_id=case_id,
                memory_file=str(memory_path),
                file_size=file_size,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                profile=self.profile
            )
            
            logger.info(f"Dump mémoire {memory_path.name} ouvert avec succès")
            logger.info(f"Taille: {file_size:,} bytes")
            logger.info(f"Profil: {self.profile}")
            logger.info(f"MD5: {md5_hash}")
            
            if self.system_info:
                logger.info(f"OS: {self.system_info.os_type.value}")
                if self.system_info.hostname:
                    logger.info(f"Hostname: {self.system_info.hostname}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ouverture du dump mémoire: {e}")
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
    
    def _extract_system_info(self) -> Optional[SystemInfo]:
        """Extrait les informations système du dump mémoire"""
        if not self.memory_file or not self.profile:
            return None
        
        try:
            # Utilisation du plugin imageinfo pour les infos système
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "imageinfo", self.profile
            )
            
            if not success:
                logger.warning("Impossible d'extraire les informations système")
                return None
            
            system_info = SystemInfo(os_type=OSType.UNKNOWN)
            
            # Parse des informations système
            lines = output.split('\n')
            for line in lines:
                if "Image Type" in line:
                    if "Windows" in line:
                        if "XP" in line:
                            system_info.os_type = OSType.WINDOWS_XP
                        elif "Vista" in line:
                            system_info.os_type = OSType.WINDOWS_VISTA
                        elif "Win7" in line or "Windows 7" in line:
                            system_info.os_type = OSType.WINDOWS_7
                        elif "Win8" in line or "Windows 8" in line:
                            system_info.os_type = OSType.WINDOWS_8
                        elif "Win10" in line or "Windows 10" in line:
                            system_info.os_type = OSType.WINDOWS_10
                        elif "Win11" in line or "Windows 11" in line:
                            system_info.os_type = OSType.WINDOWS_11
                    elif "Linux" in line:
                        system_info.os_type = OSType.LINUX
                    elif "Mac" in line:
                        system_info.os_type = OSType.MACOS
                
                elif "Image local date and time" in line:
                    # Parse de la date/heure
                    try:
                        date_str = line.split(':', 1)[1].strip()
                        # Format approximatif: "2024-01-15 14:30:25 UTC+0000"
                        # Adaptation nécessaire selon le format exact
                        pass
                    except:
                        pass
            
            # Tentative d'extraction du hostname via plugin hivelist/printkey
            hostname = self._extract_hostname()
            if hostname:
                system_info.hostname = hostname
            
            return system_info
            
        except Exception as e:
            logger.debug(f"Erreur extraction infos système: {e}")
            return SystemInfo(os_type=OSType.UNKNOWN)
    
    def _extract_hostname(self) -> Optional[str]:
        """Extrait le hostname depuis le registre"""
        try:
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "printkey",
                self.profile,
                ["-K", "ControlSet001\\Control\\ComputerName\\ComputerName"]
            )
            
            if success and output:
                for line in output.split('\n'):
                    if "ComputerName" in line and "REG_SZ" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[-1]
                        
        except Exception:
            pass
        
        return None
    
    def extract_processes(self) -> List[MemoryProcess]:
        """
        Extrait la liste des processus de la mémoire
        
        Returns:
            Liste des processus
        """
        if not self.memory_file or not self.profile:
            logger.error("Dump mémoire non ouvert")
            return []
        
        processes = []
        
        try:
            # Utilisation du plugin pslist
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "pslist", self.profile
            )
            
            if not success:
                logger.error(f"Erreur extraction processus: {error}")
                return []
            
            # Parse de la sortie pslist
            lines = output.split('\n')
            header_found = False
            
            for line in lines:
                if "Offset" in line and "Name" in line and "PID" in line:
                    header_found = True
                    continue
                
                if not header_found or not line.strip():
                    continue
                
                # Parse d'une ligne de processus
                process = self._parse_process_line(line)
                if process:
                    processes.append(process)
            
            # Enrichissement avec informations détaillées
            for process in processes:
                self._enrich_process_info(process)
            
            # Sauvegarde en base de données
            self._save_processes_to_db(processes)
            
            logger.info(f"Extraction terminée: {len(processes)} processus")
            
        except Exception as e:
            logger.error(f"Erreur extraction processus: {e}")
        
        return processes
    
    def _parse_process_line(self, line: str) -> Optional[MemoryProcess]:
        """Parse une ligne de sortie pslist"""
        try:
            parts = line.split()
            if len(parts) < 6:
                return None
            
            # Format approximatif: Offset Name PID PPID Thds Hnds Sess Wow64 Start Exit
            offset = parts[0]
            name = parts[1]
            pid = int(parts[2])
            ppid = int(parts[3])
            threads = int(parts[4]) if parts[4].isdigit() else None
            handles = int(parts[5]) if parts[5].isdigit() else None
            
            # Session ID et autres champs optionnels
            session_id = None
            wow64 = False
            
            if len(parts) > 6:
                session_id = int(parts[6]) if parts[6].isdigit() else None
            if len(parts) > 7:
                wow64 = parts[7].lower() == "true"
            
            process = MemoryProcess(
                pid=pid,
                ppid=ppid,
                name=name,
                image_path="",  # Sera rempli par cmdline
                threads=threads,
                handles=handles,
                session_id=session_id,
                wow64=wow64
            )
            
            return process
            
        except Exception as e:
            logger.debug(f"Erreur parse ligne processus: {e}")
            return None
    
    def _enrich_process_info(self, process: MemoryProcess):
        """Enrichit les informations d'un processus"""
        try:
            # Extraction de la ligne de commande
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "cmdline", self.profile,
                ["-p", str(process.pid)]
            )
            
            if success and output:
                for line in output.split('\n'):
                    if f"{process.name} pid: {process.pid}" in line:
                        # La ligne suivante contient généralement la commande
                        cmd_line = line.split(':', 2)[-1].strip() if ':' in line else ""
                        if cmd_line:
                            process.command_line = cmd_line
                            # Premier élément comme image_path
                            process.image_path = cmd_line.split()[0] if cmd_line else process.name
                        break
            
            # Détection de processus suspects
            process.suspicious = self._is_process_suspicious(process)
            
            # Analyse YARA si disponible
            if self.yara_rules:
                process.yara_matches = self._scan_process_memory(process)
                if process.yara_matches:
                    process.suspicious = True
                    
        except Exception as e:
            logger.debug(f"Erreur enrichissement processus {process.pid}: {e}")
    
    def _is_process_suspicious(self, process: MemoryProcess) -> bool:
        """Détermine si un processus est suspect"""
        suspicious_indicators = []
        
        # Processus sans parent (PPID 0 sauf pour System)
        if process.ppid == 0 and process.name.lower() not in ['system', '[system process]']:
            suspicious_indicators.append("Orphan process")
        
        # Processus avec des noms suspects
        suspicious_names = [
            'svchost.exe', 'winlogon.exe', 'explorer.exe', 'lsass.exe', 'csrss.exe'
        ]
        
        if process.name.lower() in [n.lower() for n in suspicious_names]:
            # Vérification des chemins légitimes
            legitimate_paths = {
                'svchost.exe': ['\\system32\\', '\\syswow64\\'],
                'winlogon.exe': ['\\system32\\'],
                'explorer.exe': ['\\windows\\'],
                'lsass.exe': ['\\system32\\'],
                'csrss.exe': ['\\system32\\']
            }
            
            process_name_lower = process.name.lower()
            if process_name_lower in legitimate_paths:
                expected_paths = legitimate_paths[process_name_lower]
                if not any(path.lower() in process.image_path.lower() for path in expected_paths):
                    suspicious_indicators.append(f"Suspicious location for {process.name}")
        
        # Processus avec des caractères inhabituels
        if any(ord(c) > 127 for c in process.name):
            suspicious_indicators.append("Non-ASCII characters in name")
        
        # Processus sans threads
        if process.threads == 0:
            suspicious_indicators.append("No threads")
        
        # Nombre anormal de handles
        if process.handles and process.handles > 10000:
            suspicious_indicators.append("Excessive handles")
        
        if suspicious_indicators:
            process.metadata = {'suspicious_reasons': suspicious_indicators}
            return True
        
        return False
    
    def _scan_process_memory(self, process: MemoryProcess) -> List[str]:
        """Scanne la mémoire d'un processus avec YARA"""
        try:
            # Utilisation du plugin malfind pour extraire du code suspect
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "malfind", self.profile,
                ["-p", str(process.pid)]
            )
            
            if success and output and self.yara_rules:
                # Extraction des données hexadécimales de la sortie
                hex_data = self._extract_hex_from_output(output)
                if hex_data:
                    matches = self.yara_rules.match(data=hex_data)
                    return [match.rule for match in matches]
                    
        except Exception as e:
            logger.debug(f"Erreur scan YARA processus {process.pid}: {e}")
        
        return []
    
    def _extract_hex_from_output(self, output: str) -> Optional[bytes]:
        """Extrait les données hexadécimales d'une sortie Volatility"""
        try:
            hex_pattern = re.compile(r'([0-9a-fA-F]{2}\s+)+')
            hex_matches = hex_pattern.findall(output)
            
            if hex_matches:
                # Combine toutes les données hex trouvées
                hex_string = ''.join(hex_matches).replace(' ', '')
                return bytes.fromhex(hex_string)
                
        except Exception as e:
            logger.debug(f"Erreur extraction hex: {e}")
        
        return None
    
    def extract_network_connections(self) -> List[NetworkConnection]:
        """
        Extrait les connexions réseau de la mémoire
        
        Returns:
            Liste des connexions réseau
        """
        if not self.memory_file or not self.profile:
            logger.error("Dump mémoire non ouvert")
            return []
        
        connections = []
        
        try:
            # Utilisation des plugins netscan ou connscan selon la version Windows
            plugins_to_try = ["netscan", "connscan", "sockets", "sockscan"]
            
            for plugin in plugins_to_try:
                success, output, error = self.volatility.run_plugin(
                    self.memory_file, plugin, self.profile
                )
                
                if success and output:
                    parsed_connections = self._parse_network_output(output, plugin)
                    connections.extend(parsed_connections)
                    break
                    
            # Suppression des doublons
            unique_connections = []
            seen = set()
            
            for conn in connections:
                key = (conn.protocol, conn.local_addr, conn.local_port, 
                      conn.remote_addr, conn.remote_port, conn.pid)
                if key not in seen:
                    seen.add(key)
                    unique_connections.append(conn)
            
            # Sauvegarde en base
            self._save_connections_to_db(unique_connections)
            
            logger.info(f"Extraction terminée: {len(unique_connections)} connexions réseau")
            
        except Exception as e:
            logger.error(f"Erreur extraction connexions réseau: {e}")
        
        return unique_connections
    
    def _parse_network_output(self, output: str, plugin: str) -> List[NetworkConnection]:
        """Parse la sortie des plugins réseau"""
        connections = []
        
        try:
            lines = output.split('\n')
            header_found = False
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Recherche de l'en-tête
                if ("Protocol" in line and "Local Address" in line) or \
                   ("Offset" in line and "Proto" in line):
                    header_found = True
                    continue
                
                if not header_found:
                    continue
                
                # Parse selon le plugin
                conn = self._parse_connection_line(line, plugin)
                if conn:
                    connections.append(conn)
                    
        except Exception as e:
            logger.debug(f"Erreur parse sortie réseau: {e}")
        
        return connections
    
    def _parse_connection_line(self, line: str, plugin: str) -> Optional[NetworkConnection]:
        """Parse une ligne de connexion réseau"""
        try:
            parts = line.split()
            if len(parts) < 5:
                return None
            
            if plugin == "netscan":
                # Format: Offset Proto Local Address Foreign Address State PID Owner Created
                offset = parts[0]
                protocol = parts[1]
                local_addr_port = parts[2]
                remote_addr_port = parts[3]
                state = parts[4] if len(parts) > 4 else None
                pid = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None
                
            else:  # connscan, sockets, etc.
                # Format peut varier, adaptation nécessaire
                protocol = parts[1] if len(parts) > 1 else "TCP"
                local_addr_port = parts[2] if len(parts) > 2 else ""
                remote_addr_port = parts[3] if len(parts) > 3 else ""
                pid = None
                state = None
                
                # Recherche du PID dans les parties suivantes
                for part in parts[4:]:
                    if part.isdigit():
                        pid = int(part)
                        break
            
            # Parse des adresses IP:port
            local_parts = local_addr_port.rsplit(':', 1)
            remote_parts = remote_addr_port.rsplit(':', 1)
            
            if len(local_parts) == 2 and len(remote_parts) == 2:
                local_addr, local_port_str = local_parts
                remote_addr, remote_port_str = remote_parts
                
                try:
                    local_port = int(local_port_str)
                    remote_port = int(remote_port_str)
                except ValueError:
                    return None
                
                return NetworkConnection(
                    protocol=protocol,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid
                )
                
        except Exception as e:
            logger.debug(f"Erreur parse ligne connexion: {e}")
        
        return None
    
    def extract_registry_entries(self, hive_name: str = None, key_path: str = None) -> List[RegistryEntry]:
        """
        Extrait les entrées de registre de la mémoire
        
        Args:
            hive_name: Nom de la ruche (None = toutes)
            key_path: Chemin de clé spécifique (None = toutes)
            
        Returns:
            Liste des entrées de registre
        """
        if not self.memory_file or not self.profile:
            logger.error("Dump mémoire non ouvert")
            return []
        
        entries = []
        
        try:
            # Liste des ruches disponibles
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "hivelist", self.profile
            )
            
            if not success:
                logger.error("Impossible de lister les ruches de registre")
                return []
            
            # Parse des ruches disponibles
            hives = self._parse_hive_list(output)
            
            # Extraction des clés pour chaque ruche
            for hive in hives:
                if hive_name and hive_name.lower() not in hive['name'].lower():
                    continue
                
                hive_entries = self._extract_hive_entries(hive, key_path)
                entries.extend(hive_entries)
            
            # Sauvegarde en base
            self._save_registry_to_db(entries)
            
            logger.info(f"Extraction terminée: {len(entries)} entrées de registre")
            
        except Exception as e:
            logger.error(f"Erreur extraction registre: {e}")
        
        return entries
    
    def _parse_hive_list(self, output: str) -> List[Dict[str, str]]:
        """Parse la liste des ruches de registre"""
        hives = []
        
        try:
            lines = output.split('\n')
            header_found = False
            
            for line in lines:
                if "Virtual" in line and "Physical" in line and "Name" in line:
                    header_found = True
                    continue
                
                if not header_found or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    virtual_addr = parts[0]
                    physical_addr = parts[1]
                    name = ' '.join(parts[2:])
                    
                    hives.append({
                        'virtual_addr': virtual_addr,
                        'physical_addr': physical_addr,
                        'name': name
                    })
                    
        except Exception as e:
            logger.debug(f"Erreur parse liste ruches: {e}")
        
        return hives
    
    def _extract_hive_entries(self, hive: Dict[str, str], key_path: str = None) -> List[RegistryEntry]:
        """Extrait les entrées d'une ruche spécifique"""
        entries = []
        
        try:
            # Utilisation du plugin printkey
            args = ["-o", hive['virtual_addr']]
            if key_path:
                args.extend(["-K", key_path])
            
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "printkey", self.profile, args
            )
            
            if success and output:
                parsed_entries = self._parse_registry_output(output, hive['name'])
                entries.extend(parsed_entries)
                
        except Exception as e:
            logger.debug(f"Erreur extraction ruche {hive['name']}: {e}")
        
        return entries
    
    def _parse_registry_output(self, output: str, hive_name: str) -> List[RegistryEntry]:
        """Parse la sortie du plugin printkey"""
        entries = []
        
        try:
            lines = output.split('\n')
            current_key = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Détection d'une nouvelle clé
                if line.startswith('Key name:'):
                    current_key = line.split(':', 1)[1].strip()
                    continue
                
                # Détection d'une valeur
                if 'REG_' in line and current_key:
                    parts = line.split()
                    if len(parts) >= 3:
                        value_name = parts[0] if parts[0] != '(Default)' else None
                        value_type = None
                        value_data = None
                        
                        # Recherche du type REG_*
                        for i, part in enumerate(parts):
                            if part.startswith('REG_'):
                                value_type = part
                                if i + 1 < len(parts):
                                    value_data = ' '.join(parts[i + 1:])
                                break
                        
                        if value_type:
                            entry = RegistryEntry(
                                hive_name=hive_name,
                                key_path=current_key,
                                value_name=value_name,
                                value_type=value_type,
                                value_data=value_data
                            )
                            entries.append(entry)
                            
        except Exception as e:
            logger.debug(f"Erreur parse sortie registre: {e}")
        
        return entries
    
    def extract_file_handles(self, pid: int = None) -> List[FileHandle]:
        """
        Extrait les handles de fichiers de la mémoire
        
        Args:
            pid: PID du processus (None = tous)
            
        Returns:
            Liste des handles de fichiers
        """
        if not self.memory_file or not self.profile:
            logger.error("Dump mémoire non ouvert")
            return []
        
        handles = []
        
        try:
            args = []
            if pid:
                args.extend(["-p", str(pid)])
            
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "handles", self.profile, args
            )
            
            if success and output:
                handles = self._parse_handles_output(output)
            
            # Sauvegarde en base
            self._save_handles_to_db(handles)
            
            logger.info(f"Extraction terminée: {len(handles)} handles de fichiers")
            
        except Exception as e:
            logger.error(f"Erreur extraction handles: {e}")
        
        return handles
    
    def _parse_handles_output(self, output: str) -> List[FileHandle]:
        """Parse la sortie du plugin handles"""
        handles = []
        
        try:
            lines = output.split('\n')
            header_found = False
            
            for line in lines:
                if "Offset" in line and "Pid" in line and "Handle" in line:
                    header_found = True
                    continue
                
                if not header_found or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    offset = parts[0]
                    pid = int(parts[1]) if parts[1].isdigit() else None
                    handle_val = parts[2]
                    access = parts[3]
                    handle_type = parts[4]
                    details = ' '.join(parts[5:])
                    
                    # Focus sur les handles de fichiers
                    if handle_type == "File" and pid:
                        # Extraction du nom de processus (à améliorer)
                        process_name = "Unknown"
                        
                        # Extraction du chemin de fichier depuis les détails
                        file_path = None
                        if '\\' in details or '/' in details:
                            file_path = details
                        
                        handle = FileHandle(
                            pid=pid,
                            process_name=process_name,
                            handle_value=int(handle_val, 16) if handle_val.startswith('0x') else int(handle_val),
                            handle_type=handle_type,
                            file_path=file_path,
                            access_mask=access
                        )
                        
                        handles.append(handle)
                        
        except Exception as e:
            logger.debug(f"Erreur parse handles: {e}")
        
        return handles
    
    def extract_memory_artifacts(self, artifact_types: List[str] = None) -> List[MemoryArtifact]:
        """
        Extrait divers artefacts de la mémoire (mots de passe, URLs, etc.)
        
        Args:
            artifact_types: Types d'artefacts à extraire (None = tous)
            
        Returns:
            Liste des artefacts trouvés
        """
        if not self.memory_file:
            logger.error("Dump mémoire non ouvert")
            return []
        
        artifacts = []
        
        try:
            # Utilisation du plugin strings pour extraire des chaînes
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "strings", self.profile,
                ["-s", self.memory_file]
            )
            
            if success and output:
                artifacts = self._extract_artifacts_from_strings(output, artifact_types)
            
            # Tentative d'extraction de mots de passe avec hashdump
            password_artifacts = self._extract_password_hashes()
            artifacts.extend(password_artifacts)
            
            # Sauvegarde en base
            self._save_artifacts_to_db(artifacts)
            
            logger.info(f"Extraction terminée: {len(artifacts)} artefacts")
            
        except Exception as e:
            logger.error(f"Erreur extraction artefacts: {e}")
        
        return artifacts
    
    def _extract_artifacts_from_strings(self, strings_output: str, 
                                      artifact_types: List[str] = None) -> List[MemoryArtifact]:
        """Extrait des artefacts depuis la sortie du plugin strings"""
        artifacts = []
        
        try:
            lines = strings_output.split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Test de chaque pattern
                for artifact_type, pattern in self.artifact_patterns.items():
                    if artifact_types and artifact_type not in artifact_types:
                        continue
                    
                    matches = pattern.findall(line)
                    for match in matches:
                        # Calcul de la confiance basé sur le contexte
                        confidence = self._calculate_artifact_confidence(artifact_type, match, line)
                        
                        if confidence >= 0.5:  # Seuil minimum
                            artifact = MemoryArtifact(
                                artifact_type=artifact_type,
                                value=match,
                                confidence=confidence,
                                metadata={'context': line[:100]}  # Contexte limité
                            )
                            artifacts.append(artifact)
            
        except Exception as e:
            logger.debug(f"Erreur extraction artefacts depuis strings: {e}")
        
        return artifacts
    
    def _calculate_artifact_confidence(self, artifact_type: str, value: str, context: str) -> float:
        """Calcule la confiance d'un artefact basé sur le contexte"""
        base_confidence = 0.6
        
        # Ajustements par type
        if artifact_type == 'email':
            if '@gmail.com' in value or '@outlook.com' in value:
                base_confidence += 0.2
        
        elif artifact_type == 'url_http':
            if value.startswith('https://'):
                base_confidence += 0.1
            if any(domain in value for domain in ['.com', '.org', '.net']):
                base_confidence += 0.1
        
        elif artifact_type == 'ip_address':
            # Vérification de plages privées
            parts = value.split('.')
            if len(parts) == 4:
                try:
                    first_octet = int(parts[0])
                    if first_octet in [10, 172, 192]:  # Plages privées
                        base_confidence += 0.1
                except ValueError:
                    base_confidence -= 0.2
        
        elif artifact_type == 'bitcoin_address':
            # Les adresses Bitcoin ont une checksum, confiance élevée
            base_confidence = 0.9
        
        # Réduction si valeur très courte ou suspecte
        if len(value) < 3:
            base_confidence -= 0.3
        
        return min(1.0, max(0.0, base_confidence))
    
    def _extract_password_hashes(self) -> List[MemoryArtifact]:
        """Extrait les hashs de mots de passe avec hashdump"""
        artifacts = []
        
        try:
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "hashdump", self.profile
            )
            
            if success and output:
                lines = output.split('\n')
                for line in lines:
                    if ':' in line and len(line.split(':')) >= 4:
                        # Format: username:rid:lm_hash:ntlm_hash:::
                        parts = line.split(':')
                        if len(parts) >= 4:
                            username = parts[0]
                            lm_hash = parts[2]
                            ntlm_hash = parts[3]
                            
                            if lm_hash and lm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                                artifact = MemoryArtifact(
                                    artifact_type='password_hash',
                                    value=f"{username}:LM:{lm_hash}",
                                    confidence=0.95,
                                    metadata={'hash_type': 'LM', 'username': username}
                                )
                                artifacts.append(artifact)
                            
                            if ntlm_hash and ntlm_hash != '31d6cfe0d16ae931b73c59d7e0c089c0':
                                artifact = MemoryArtifact(
                                    artifact_type='password_hash',
                                    value=f"{username}:NTLM:{ntlm_hash}",
                                    confidence=0.95,
                                    metadata={'hash_type': 'NTLM', 'username': username}
                                )
                                artifacts.append(artifact)
                                
        except Exception as e:
            logger.debug(f"Erreur extraction hashs mots de passe: {e}")
        
        return artifacts
    
    def generate_memory_timeline(self) -> List[Dict[str, Any]]:
        """
        Génère une timeline des événements mémoire
        
        Returns:
            Liste des événements triés par timestamp
        """
        timeline_events = []
        
        try:
            # Utilisation du plugin timeliner
            success, output, error = self.volatility.run_plugin(
                self.memory_file, "timeliner", self.profile
            )
            
            if success and output:
                events = self._parse_timeline_output(output)
                timeline_events.extend(events)
            
            # Tri par timestamp
            timeline_events.sort(key=lambda x: x.get('timestamp', datetime.min.replace(tzinfo=timezone.utc)))
            
            logger.info(f"Timeline générée: {len(timeline_events)} événements")
            
        except Exception as e:
            logger.error(f"Erreur génération timeline: {e}")
        
        return timeline_events
    
    def _parse_timeline_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse la sortie du plugin timeliner"""
        events = []
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                if not line.strip() or line.startswith('Volatility'):
                    continue
                
                # Parse approximatif - le format exact dépend de la version
                parts = line.split('|')
                if len(parts) >= 4:
                    timestamp_str = parts[0].strip()
                    source = parts[1].strip()
                    event_type = parts[2].strip()
                    description = '|'.join(parts[3:]).strip()
                    
                    try:
                        # Parse du timestamp (format à adapter)
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    except:
                        timestamp = datetime.now(timezone.utc)
                    
                    event = {
                        'timestamp': timestamp,
                        'source': source,
                        'event_type': event_type,
                        'description': description
                    }
                    events.append(event)
                    
        except Exception as e:
            logger.debug(f"Erreur parse timeline: {e}")
        
        return events
    
    def _save_analysis_info(self, case_id: str, memory_file: str, file_size: int,
                          md5_hash: str, sha256_hash: str, profile: str = None):
        """Sauvegarde les informations d'analyse en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        os_type = self.system_info.os_type.value if self.system_info else "Unknown"
        system_info_json = json.dumps(self.system_info.__dict__, default=str) if self.system_info else "{}"
        
        cursor.execute('''
            INSERT OR REPLACE INTO memory_analysis 
            (case_id, memory_file, file_size, file_md5, file_sha256, os_type, profile, 
             analysis_start, system_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (case_id, memory_file, file_size, md5_hash, sha256_hash, os_type, 
              profile, datetime.now(), system_info_json))
        
        conn.commit()
        conn.close()
    
    def _save_processes_to_db(self, processes: List[MemoryProcess]):
        """Sauvegarde les processus en base"""
        if not processes:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for process in processes:
            cursor.execute('''
                INSERT OR REPLACE INTO processes 
                (case_id, pid, ppid, name, image_path, command_line, create_time, 
                 exit_time, session_id, threads, handles, wow64, suspicious, yara_matches)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, process.pid, process.ppid, process.name, process.image_path,
                process.command_line, process.create_time, process.exit_time,
                process.session_id, process.threads, process.handles, process.wow64,
                process.suspicious, json.dumps(process.yara_matches)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_connections_to_db(self, connections: List[NetworkConnection]):
        """Sauvegarde les connexions réseau en base"""
        if not connections:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for conn_obj in connections:
            cursor.execute('''
                INSERT INTO network_connections 
                (case_id, protocol, local_addr, local_port, remote_addr, remote_port, 
                 state, pid, process_name, create_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, conn_obj.protocol, conn_obj.local_addr, conn_obj.local_port,
                conn_obj.remote_addr, conn_obj.remote_port, conn_obj.state,
                conn_obj.pid, conn_obj.process_name, conn_obj.create_time
            ))
        
        conn.commit()
        conn.close()
    
    def _save_registry_to_db(self, entries: List[RegistryEntry]):
        """Sauvegarde les entrées de registre en base"""
        if not entries:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for entry in entries:
            cursor.execute('''
                INSERT INTO registry_entries 
                (case_id, hive_name, key_path, value_name, value_type, value_data, last_write_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, entry.hive_name, entry.key_path, entry.value_name,
                entry.value_type, entry.value_data, entry.last_write_time
            ))
        
        conn.commit()
        conn.close()
    
    def _save_handles_to_db(self, handles: List[FileHandle]):
        """Sauvegarde les handles de fichiers en base"""
        if not handles:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for handle in handles:
            cursor.execute('''
                INSERT INTO file_handles 
                (case_id, pid, process_name, handle_value, handle_type, file_path, access_mask)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, handle.pid, handle.process_name, handle.handle_value,
                handle.handle_type, handle.file_path, handle.access_mask
            ))
        
        conn.commit()
        conn.close()
    
    def _save_artifacts_to_db(self, artifacts: List[MemoryArtifact]):
        """Sauvegarde les artefacts en base"""
        if not artifacts:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for artifact in artifacts:
            cursor.execute('''
                INSERT INTO memory_artifacts 
                (case_id, artifact_type, value, confidence, source_process, source_address, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, artifact.artifact_type, artifact.value, artifact.confidence,
                artifact.source_process, artifact.source_address, json.dumps(artifact.metadata)
            ))
        
        conn.commit()
        conn.close()
    
    def export_results(self, output_file: str, format_type: str = 'json') -> bool:
        """
        Export des résultats d'analyse mémoire
        
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
                    'processes': self._get_processes_from_db(conn),
                    'network_connections': self._get_connections_from_db(conn),
                    'registry_entries': self._get_registry_from_db(conn),
                    'file_handles': self._get_handles_from_db(conn),
                    'artifacts': self._get_artifacts_from_db(conn)
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                # Export CSV des processus
                import csv
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM processes WHERE case_id = ?', (self.case_id,))
                
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
        cursor.execute('SELECT * FROM memory_analysis WHERE case_id = ?', (self.case_id,))
        row = cursor.fetchone()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return {}
    
    def _get_processes_from_db(self, conn) -> List[Dict]:
        """Récupère les processus depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM processes WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_connections_from_db(self, conn) -> List[Dict]:
        """Récupère les connexions depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_connections WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_registry_from_db(self, conn) -> List[Dict]:
        """Récupère les entrées registre depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM registry_entries WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_handles_from_db(self, conn) -> List[Dict]:
        """Récupère les handles depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM file_handles WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_artifacts_from_db(self, conn) -> List[Dict]:
        """Récupère les artefacts depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM memory_artifacts WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def close(self):
        """Ferme l'analyseur et nettoie les ressources"""
        self.memory_file = None
        self.profile = None
        self.case_id = None
        logger.info("Analyseur mémoire fermé")


def main():
    """Fonction de démonstration"""
    print("🧠 Forensic Analysis Toolkit - Memory Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = MemoryAnalyzer(evidence_dir="./evidence", temp_dir="./temp")
    
    # Simulation avec un dump de test (remplacer par un vrai dump)
    test_dump = "./test_dumps/memory.raw"
    case_id = f"MEMORY_CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Cas d'analyse: {case_id}")
    
    # Si le dump de test existe
    if Path(test_dump).exists():
        print(f"🧠 Ouverture du dump mémoire: {test_dump}")
        
        if analyzer.open_memory_dump(test_dump, case_id):
            # Extraction des processus
            print("⚙️  Extraction des processus...")
            processes = analyzer.extract_processes()
            
            print(f"📊 {len(processes)} processus extraits")
            suspicious_count = sum(1 for p in processes if p.suspicious)
            if suspicious_count > 0:
                print(f"⚠️  {suspicious_count} processus suspects détectés")
            
            # Extraction des connexions réseau
            print("🌐 Extraction des connexions réseau...")
            connections = analyzer.extract_network_connections()
            print(f"🔗 {len(connections)} connexions réseau extraites")
            
            # Extraction des artefacts
            print("🔍 Extraction des artefacts...")
            artifacts = analyzer.extract_memory_artifacts()
            print(f"💎 {len(artifacts)} artefacts extraits")
            
            # Extraction des handles de fichiers
            print("📁 Extraction des handles de fichiers...")
            handles = analyzer.extract_file_handles()
            print(f"🔧 {len(handles)} handles extraits")
            
            # Export des résultats
            output_file = f"./memory_analysis_{case_id}.json"
            if analyzer.export_results(output_file, 'json'):
                print(f"📄 Résultats exportés: {output_file}")
            
        analyzer.close()
    else:
        print("⚠️  Aucun dump mémoire de test trouvé")
        print(f"   Créez un fichier {test_dump} ou modifiez le chemin")
        print("   Exemple: dd if=/dev/mem of=memory.raw (nécessite root)")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()