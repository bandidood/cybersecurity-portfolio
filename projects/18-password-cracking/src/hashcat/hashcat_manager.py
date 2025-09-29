#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Hashcat Manager - Advanced Password Cracking Tool
============================================================================
Gestionnaire complet pour Hashcat avec toutes les fonctionnalités avancées :
- Attaques par dictionnaire, brute-force, hybrides
- Optimisations GPU/CPU
- Monitoring en temps réel
- Gestion des sessions et reprise
- Benchmarking et statistiques

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import subprocess
import json
import time
import threading
import psutil
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hashcat_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AttackMode(Enum):
    """Modes d'attaque Hashcat"""
    DICTIONARY = 0        # Attaque par dictionnaire
    COMBINATION = 1       # Combinaison de mots
    BRUTE_FORCE = 3      # Force brute
    HYBRID_DICT_MASK = 6 # Hybride dictionnaire + masque
    HYBRID_MASK_DICT = 7 # Hybride masque + dictionnaire


class HashType(Enum):
    """Types de hash supportés"""
    MD5 = 0
    SHA1 = 100
    SHA224 = 1300
    SHA256 = 1400
    SHA384 = 10800
    SHA512 = 1700
    NTLM = 1000
    LM = 3000
    BCRYPT = 3200
    SCRYPT = 8900
    PBKDF2_SHA1 = 12000
    PBKDF2_SHA256 = 10900
    WORDPRESS = 400
    MYSQL = 300
    POSTGRES = 12
    LINUX_SHA512 = 1800


@dataclass
class HashcatResult:
    """Résultat d'une session Hashcat"""
    session_name: str
    attack_mode: AttackMode
    hash_type: HashType
    total_hashes: int
    cracked_hashes: int
    success_rate: float
    start_time: datetime
    end_time: Optional[datetime]
    runtime_seconds: int
    hash_rate: str
    gpu_utilization: float
    cracked_passwords: List[str]
    status: str
    error_message: Optional[str] = None


@dataclass
class AttackConfig:
    """Configuration d'attaque"""
    hash_file: str
    hash_type: HashType
    attack_mode: AttackMode
    wordlists: List[str] = None
    rules: List[str] = None
    masks: List[str] = None
    session_name: str = None
    workload_profile: int = 3  # High performance
    optimized_kernel: bool = True
    force: bool = False
    increment: bool = False
    increment_min: int = 1
    increment_max: int = 8
    custom_charset_1: str = None
    custom_charset_2: str = None
    custom_charset_3: str = None
    custom_charset_4: str = None
    runtime_limit: int = 0  # 0 = unlimited
    restore: bool = False
    show_cracked: bool = False
    left_rule: str = None
    right_rule: str = None


class HashcatManager:
    """
    Gestionnaire principal pour Hashcat
    """
    
    def __init__(self, 
                 hashcat_binary: str = "hashcat",
                 potfile: str = None,
                 outfile_dir: str = "results/cracked",
                 session_dir: str = "results/sessions"):
        """
        Initialisation du gestionnaire
        
        Args:
            hashcat_binary: Chemin vers l'exécutable hashcat
            potfile: Fichier potfile pour les mots de passe crackés
            outfile_dir: Répertoire de sortie des résultats
            session_dir: Répertoire des sessions
        """
        self.hashcat_binary = hashcat_binary
        self.potfile = potfile or "hashcat.potfile"
        self.outfile_dir = Path(outfile_dir)
        self.session_dir = Path(session_dir)
        
        # Création des répertoires
        self.outfile_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # État du manager
        self.current_session = None
        self.monitoring_thread = None
        self.stop_monitoring = False
        self.callbacks = {}
        
        # Validation de l'installation
        self._validate_installation()
        
    def _validate_installation(self):
        """Valide l'installation de Hashcat"""
        try:
            result = subprocess.run([self.hashcat_binary, "--version"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError("Hashcat not found or not working")
                
            version_info = result.stdout.strip()
            logger.info(f"Hashcat detected: {version_info}")
            
        except FileNotFoundError:
            raise RuntimeError(f"Hashcat binary not found: {self.hashcat_binary}")
    
    def benchmark(self, hash_types: List[HashType] = None) -> Dict[str, Any]:
        """
        Lance un benchmark des performances
        
        Args:
            hash_types: Types de hash à tester (None = tous)
            
        Returns:
            Résultats du benchmark
        """
        logger.info("Starting Hashcat benchmark...")
        
        cmd = [self.hashcat_binary, "-b"]
        
        if hash_types:
            cmd.extend(["-m", ",".join(str(ht.value) for ht in hash_types)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                raise RuntimeError(f"Benchmark failed: {result.stderr}")
            
            # Parse des résultats
            benchmark_data = self._parse_benchmark_output(result.stdout)
            
            logger.info("Benchmark completed successfully")
            return benchmark_data
            
        except subprocess.TimeoutExpired:
            logger.error("Benchmark timeout")
            raise RuntimeError("Benchmark timeout")
        except Exception as e:
            logger.error(f"Benchmark error: {e}")
            raise
    
    def _parse_benchmark_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie du benchmark"""
        lines = output.strip().split('\n')
        benchmark_data = {
            'timestamp': datetime.now().isoformat(),
            'device_info': [],
            'hash_types': {}
        }
        
        current_device = None
        
        for line in lines:
            line = line.strip()
            
            # Information des devices
            if 'Device' in line and 'Type' in line:
                device_info = line.split(':')[1].strip() if ':' in line else line
                benchmark_data['device_info'].append(device_info)
                current_device = len(benchmark_data['device_info']) - 1
            
            # Résultats de hash types
            elif 'H/s' in line and '(' in line:
                parts = line.split()
                hash_type = None
                hash_rate = None
                
                for i, part in enumerate(parts):
                    if part.startswith('(') and part.endswith(')'):
                        hash_type = part[1:-1]
                    elif 'H/s' in part:
                        hash_rate = parts[i-1] + ' ' + part
                
                if hash_type and hash_rate:
                    benchmark_data['hash_types'][hash_type] = hash_rate
        
        return benchmark_data
    
    def dictionary_attack(self, config: AttackConfig) -> HashcatResult:
        """
        Lance une attaque par dictionnaire
        
        Args:
            config: Configuration d'attaque
            
        Returns:
            Résultat de l'attaque
        """
        config.attack_mode = AttackMode.DICTIONARY
        return self._execute_attack(config)
    
    def brute_force_attack(self, config: AttackConfig) -> HashcatResult:
        """
        Lance une attaque par force brute
        
        Args:
            config: Configuration d'attaque
            
        Returns:
            Résultat de l'attaque
        """
        config.attack_mode = AttackMode.BRUTE_FORCE
        return self._execute_attack(config)
    
    def hybrid_attack(self, config: AttackConfig) -> HashcatResult:
        """
        Lance une attaque hybride
        
        Args:
            config: Configuration d'attaque
            
        Returns:
            Résultat de l'attaque
        """
        if not config.wordlists or not config.masks:
            raise ValueError("Hybrid attack requires both wordlists and masks")
        
        config.attack_mode = AttackMode.HYBRID_DICT_MASK
        return self._execute_attack(config)
    
    def combination_attack(self, config: AttackConfig) -> HashcatResult:
        """
        Lance une attaque par combinaison
        
        Args:
            config: Configuration d'attaque
            
        Returns:
            Résultat de l'attaque
        """
        if not config.wordlists or len(config.wordlists) < 2:
            raise ValueError("Combination attack requires at least 2 wordlists")
        
        config.attack_mode = AttackMode.COMBINATION
        return self._execute_attack(config)
    
    def _execute_attack(self, config: AttackConfig) -> HashcatResult:
        """
        Exécute une attaque avec la configuration donnée
        
        Args:
            config: Configuration d'attaque
            
        Returns:
            Résultat de l'attaque
        """
        # Génération du nom de session
        if not config.session_name:
            config.session_name = f"session_{int(time.time())}"
        
        # Construction de la commande
        cmd = self._build_command(config)
        
        logger.info(f"Starting attack: {config.session_name}")
        logger.info(f"Command: {' '.join(cmd)}")
        
        # Initialisation du résultat
        result = HashcatResult(
            session_name=config.session_name,
            attack_mode=config.attack_mode,
            hash_type=config.hash_type,
            total_hashes=0,
            cracked_hashes=0,
            success_rate=0.0,
            start_time=datetime.now(),
            end_time=None,
            runtime_seconds=0,
            hash_rate="0 H/s",
            gpu_utilization=0.0,
            cracked_passwords=[],
            status="running"
        )
        
        self.current_session = result
        
        # Démarrage du monitoring
        self.stop_monitoring = False
        self.monitoring_thread = threading.Thread(
            target=self._monitor_session,
            args=(config, result)
        )
        self.monitoring_thread.start()
        
        try:
            # Exécution de l'attaque
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Lecture de la sortie en temps réel
            for line in iter(process.stdout.readline, ''):
                if line:
                    self._process_output_line(line.strip(), result)
            
            # Attendre la fin du processus
            process.wait()
            
            # Finalisation
            result.end_time = datetime.now()
            result.runtime_seconds = int((result.end_time - result.start_time).total_seconds())
            
            if process.returncode == 0:
                result.status = "completed"
                logger.info(f"Attack completed successfully: {config.session_name}")
            else:
                result.status = "failed"
                result.error_message = process.stderr.read()
                logger.error(f"Attack failed: {result.error_message}")
            
        except Exception as e:
            result.status = "error"
            result.error_message = str(e)
            result.end_time = datetime.now()
            result.runtime_seconds = int((result.end_time - result.start_time).total_seconds())
            logger.error(f"Attack error: {e}")
        
        finally:
            # Arrêt du monitoring
            self.stop_monitoring = True
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join()
            
            # Récupération des mots de passe crackés
            result.cracked_passwords = self._get_cracked_passwords(config)
            result.cracked_hashes = len(result.cracked_passwords)
            
            if result.total_hashes > 0:
                result.success_rate = result.cracked_hashes / result.total_hashes
            
            self.current_session = None
        
        return result
    
    def _build_command(self, config: AttackConfig) -> List[str]:
        """Construit la commande Hashcat"""
        cmd = [
            self.hashcat_binary,
            "-m", str(config.hash_type.value),
            "-a", str(config.attack_mode.value),
            "--potfile-path", self.potfile,
            "--session", config.session_name
        ]
        
        # Profil de charge de travail
        cmd.extend(["-w", str(config.workload_profile)])
        
        # Noyau optimisé
        if config.optimized_kernel:
            cmd.append("-O")
        
        # Force
        if config.force:
            cmd.append("--force")
        
        # Increment (pour brute force)
        if config.increment:
            cmd.extend(["--increment", "--increment-min", str(config.increment_min),
                       "--increment-max", str(config.increment_max)])
        
        # Charsets personnalisés
        if config.custom_charset_1:
            cmd.extend(["-1", config.custom_charset_1])
        if config.custom_charset_2:
            cmd.extend(["-2", config.custom_charset_2])
        if config.custom_charset_3:
            cmd.extend(["-3", config.custom_charset_3])
        if config.custom_charset_4:
            cmd.extend(["-4", config.custom_charset_4])
        
        # Limite de temps
        if config.runtime_limit > 0:
            cmd.extend(["--runtime", str(config.runtime_limit)])
        
        # Restauration
        if config.restore:
            cmd.append("--restore")
        
        # Affichage des crackés
        if config.show_cracked:
            cmd.append("--show")
        
        # Fichier de sortie
        outfile = self.outfile_dir / f"{config.session_name}.txt"
        cmd.extend(["--outfile", str(outfile)])
        
        # Règles
        if config.rules:
            for rule in config.rules:
                cmd.extend(["-r", rule])
        
        # Règles left/right pour hybride
        if config.left_rule:
            cmd.extend(["-j", config.left_rule])
        if config.right_rule:
            cmd.extend(["-k", config.right_rule])
        
        # Fichier de hash
        cmd.append(config.hash_file)
        
        # Arguments spécifiques au mode d'attaque
        if config.attack_mode == AttackMode.DICTIONARY:
            if config.wordlists:
                cmd.extend(config.wordlists)
        
        elif config.attack_mode == AttackMode.COMBINATION:
            if len(config.wordlists) >= 2:
                cmd.extend(config.wordlists[:2])
        
        elif config.attack_mode == AttackMode.BRUTE_FORCE:
            if config.masks:
                cmd.extend(config.masks)
            else:
                cmd.append("?a?a?a?a?a?a?a?a")  # Masque par défaut
        
        elif config.attack_mode in [AttackMode.HYBRID_DICT_MASK, AttackMode.HYBRID_MASK_DICT]:
            if config.wordlists and config.masks:
                cmd.extend(config.wordlists[:1])
                cmd.extend(config.masks[:1])
        
        return cmd
    
    def _process_output_line(self, line: str, result: HashcatResult):
        """Traite une ligne de sortie Hashcat"""
        try:
            # Status line format parsing
            if "Recovered" in line and "Hashes" in line:
                # Example: Recovered......: 150/1000 (15.00%) Hashes
                parts = line.split()
                for i, part in enumerate(parts):
                    if "/" in part and "(" in parts[i+1]:
                        cracked, total = part.split("/")
                        result.cracked_hashes = int(cracked)
                        result.total_hashes = int(total)
                        break
            
            elif "Speed" in line and "H/s" in line:
                # Example: Speed.#1........: 1234.5 MH/s
                parts = line.split()
                for i, part in enumerate(parts):
                    if "H/s" in part and i > 0:
                        result.hash_rate = f"{parts[i-1]} {part}"
                        break
            
            elif "Progress" in line and "%" in line:
                # Progress line - peut être utilisé pour callbacks
                if 'progress_callback' in self.callbacks:
                    self.callbacks['progress_callback'](line)
            
            # Log de debug pour les lignes importantes
            if any(keyword in line for keyword in ["Recovered", "Speed", "Progress", "Status"]):
                logger.debug(f"Hashcat output: {line}")
                
        except Exception as e:
            logger.debug(f"Error parsing output line: {e}")
    
    def _monitor_session(self, config: AttackConfig, result: HashcatResult):
        """Thread de monitoring de session"""
        while not self.stop_monitoring:
            try:
                # Monitoring GPU
                gpu_util = self._get_gpu_utilization()
                result.gpu_utilization = gpu_util
                
                # Monitoring système
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                
                # Callbacks
                if 'monitor_callback' in self.callbacks:
                    monitor_data = {
                        'gpu_utilization': gpu_util,
                        'cpu_percent': cpu_percent,
                        'memory_percent': memory_percent,
                        'runtime': int((datetime.now() - result.start_time).total_seconds())
                    }
                    self.callbacks['monitor_callback'](monitor_data)
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                logger.debug(f"Monitoring error: {e}")
                time.sleep(5)
    
    def _get_gpu_utilization(self) -> float:
        """Obtient l'utilisation GPU"""
        try:
            # Tentative avec nvidia-smi
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=utilization.gpu", 
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                utilizations = [float(x.strip()) for x in result.stdout.strip().split('\n') if x.strip()]
                return max(utilizations) if utilizations else 0.0
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Fallback
        return 0.0
    
    def _get_cracked_passwords(self, config: AttackConfig) -> List[str]:
        """Récupère les mots de passe crackés"""
        passwords = []
        
        try:
            # Depuis le fichier de sortie
            outfile = self.outfile_dir / f"{config.session_name}.txt"
            if outfile.exists():
                with open(outfile, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            
            # Depuis le potfile si pas de fichier de sortie
            if not passwords and os.path.exists(self.potfile):
                with open(self.potfile, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if ':' in line:
                            passwords.append(line.split(':', 1)[1].strip())
            
        except Exception as e:
            logger.error(f"Error reading cracked passwords: {e}")
        
        return passwords
    
    def restore_session(self, session_name: str) -> HashcatResult:
        """
        Restore une session interrompue
        
        Args:
            session_name: Nom de la session à restaurer
            
        Returns:
            Résultat de la session restaurée
        """
        logger.info(f"Restoring session: {session_name}")
        
        cmd = [
            self.hashcat_binary,
            "--session", session_name,
            "--restore"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Session restored successfully: {session_name}")
                # Créer un résultat basique pour la session restaurée
                return HashcatResult(
                    session_name=session_name,
                    attack_mode=AttackMode.DICTIONARY,  # Default
                    hash_type=HashType.MD5,  # Default
                    total_hashes=0,
                    cracked_hashes=0,
                    success_rate=0.0,
                    start_time=datetime.now(),
                    end_time=None,
                    runtime_seconds=0,
                    hash_rate="Unknown",
                    gpu_utilization=0.0,
                    cracked_passwords=[],
                    status="restored"
                )
            else:
                logger.error(f"Failed to restore session: {result.stderr}")
                raise RuntimeError(f"Session restore failed: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Error restoring session: {e}")
            raise
    
    def pause_session(self, session_name: str = None):
        """
        Met en pause la session courante ou spécifiée
        
        Args:
            session_name: Nom de la session (None = session courante)
        """
        if not session_name and self.current_session:
            session_name = self.current_session.session_name
        
        if not session_name:
            raise ValueError("No session to pause")
        
        logger.info(f"Pausing session: {session_name}")
        
        # Envoi du signal de pause (Ctrl+C simulation)
        try:
            # Trouver le processus hashcat
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if (proc.info['name'] == 'hashcat' or 
                    (proc.info['cmdline'] and 'hashcat' in proc.info['cmdline'][0])):
                    if any(session_name in arg for arg in proc.info['cmdline']):
                        proc.send_signal(psutil.signal.SIGTERM)
                        logger.info(f"Pause signal sent to session: {session_name}")
                        return
            
            logger.warning(f"Session process not found: {session_name}")
            
        except Exception as e:
            logger.error(f"Error pausing session: {e}")
            raise
    
    def get_session_status(self, session_name: str) -> Dict[str, Any]:
        """
        Obtient le statut d'une session
        
        Args:
            session_name: Nom de la session
            
        Returns:
            Statut de la session
        """
        try:
            # Vérifier si la session est en cours
            running = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if (proc.info['name'] == 'hashcat' or 
                    (proc.info['cmdline'] and 'hashcat' in proc.info['cmdline'][0])):
                    if any(session_name in arg for arg in proc.info['cmdline']):
                        running = True
                        break
            
            # Informations de la session
            session_info = {
                'session_name': session_name,
                'running': running,
                'timestamp': datetime.now().isoformat()
            }
            
            # Fichiers de session
            session_files = []
            for file_path in Path('.').glob(f"{session_name}.*"):
                session_files.append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size,
                    'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                })
            
            session_info['files'] = session_files
            
            # Résultats de sortie
            outfile = self.outfile_dir / f"{session_name}.txt"
            if outfile.exists():
                with open(outfile, 'r') as f:
                    cracked_count = len(f.readlines())
                session_info['cracked_passwords'] = cracked_count
            
            return session_info
            
        except Exception as e:
            logger.error(f"Error getting session status: {e}")
            return {'error': str(e)}
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        Liste toutes les sessions
        
        Returns:
            Liste des sessions avec leur statut
        """
        sessions = []
        
        try:
            # Sessions depuis les fichiers .restore
            for restore_file in Path('.').glob("*.restore"):
                session_name = restore_file.stem
                status = self.get_session_status(session_name)
                sessions.append(status)
            
            # Session courante
            if self.current_session:
                current_status = {
                    'session_name': self.current_session.session_name,
                    'running': True,
                    'current': True,
                    'start_time': self.current_session.start_time.isoformat(),
                    'cracked_hashes': self.current_session.cracked_hashes,
                    'total_hashes': self.current_session.total_hashes
                }
                
                # Vérifier si déjà dans la liste
                existing = next((s for s in sessions 
                               if s['session_name'] == self.current_session.session_name), None)
                if existing:
                    existing.update(current_status)
                else:
                    sessions.append(current_status)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
            return []
    
    def set_callback(self, callback_type: str, callback_func: Callable):
        """
        Définit une fonction de callback
        
        Args:
            callback_type: Type de callback ('progress', 'monitor', 'completion')
            callback_func: Fonction de callback
        """
        self.callbacks[f"{callback_type}_callback"] = callback_func
        logger.info(f"Callback set: {callback_type}")
    
    def cleanup_sessions(self, older_than_days: int = 7):
        """
        Nettoie les sessions anciennes
        
        Args:
            older_than_days: Supprimer les sessions plus anciennes que N jours
        """
        logger.info(f"Cleaning up sessions older than {older_than_days} days")
        
        cutoff_date = datetime.now() - timedelta(days=older_than_days)
        cleaned_count = 0
        
        try:
            # Fichiers de session
            for pattern in ["*.restore", "*.log", "*.out"]:
                for file_path in Path('.').glob(pattern):
                    if datetime.fromtimestamp(file_path.stat().st_mtime) < cutoff_date:
                        file_path.unlink()
                        cleaned_count += 1
            
            # Fichiers de résultats
            for file_path in self.outfile_dir.glob("*.txt"):
                if datetime.fromtimestamp(file_path.stat().st_mtime) < cutoff_date:
                    file_path.unlink()
                    cleaned_count += 1
            
            logger.info(f"Cleaned up {cleaned_count} old session files")
            
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
    
    def export_result(self, result: HashcatResult, output_file: str, format_type: str = "json"):
        """
        Exporte les résultats dans différents formats
        
        Args:
            result: Résultat à exporter
            output_file: Fichier de sortie
            format_type: Format d'export ('json', 'csv', 'html')
        """
        try:
            if format_type.lower() == "json":
                with open(output_file, 'w') as f:
                    json.dump(asdict(result), f, indent=2, default=str)
            
            elif format_type.lower() == "csv":
                import csv
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Metric', 'Value'])
                    
                    # Métriques principales
                    metrics = [
                        ('Session Name', result.session_name),
                        ('Attack Mode', result.attack_mode.name),
                        ('Hash Type', result.hash_type.name),
                        ('Total Hashes', result.total_hashes),
                        ('Cracked Hashes', result.cracked_hashes),
                        ('Success Rate', f"{result.success_rate:.2%}"),
                        ('Runtime (seconds)', result.runtime_seconds),
                        ('Hash Rate', result.hash_rate),
                        ('GPU Utilization', f"{result.gpu_utilization:.1f}%"),
                        ('Status', result.status)
                    ]
                    
                    writer.writerows(metrics)
                    
                    # Mots de passe crackés
                    writer.writerow(['', ''])
                    writer.writerow(['Cracked Passwords', ''])
                    for password in result.cracked_passwords:
                        writer.writerow(['', password])
            
            elif format_type.lower() == "html":
                html_content = self._generate_html_report(result)
                with open(output_file, 'w') as f:
                    f.write(html_content)
            
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            logger.info(f"Results exported to {output_file} ({format_type})")
            
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            raise
    
    def _generate_html_report(self, result: HashcatResult) -> str:
        """Génère un rapport HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Hashcat Report - {session_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .metrics {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }}
        .metric {{ background: #ecf0f1; padding: 15px; border-radius: 5px; flex: 1; min-width: 200px; }}
        .metric h3 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .metric .value {{ font-size: 24px; font-weight: bold; color: #e74c3c; }}
        .passwords {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .password-list {{ max-height: 300px; overflow-y: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Hashcat Attack Report</h1>
        <h2>{session_name}</h2>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>Success Rate</h3>
            <div class="value">{success_rate:.2%}</div>
        </div>
        <div class="metric">
            <h3>Cracked Hashes</h3>
            <div class="value">{cracked_hashes}</div>
        </div>
        <div class="metric">
            <h3>Total Hashes</h3>
            <div class="value">{total_hashes}</div>
        </div>
        <div class="metric">
            <h3>Runtime</h3>
            <div class="value">{runtime_hours:.1f}h</div>
        </div>
        <div class="metric">
            <h3>Hash Rate</h3>
            <div class="value">{hash_rate}</div>
        </div>
        <div class="metric">
            <h3>GPU Utilization</h3>
            <div class="value">{gpu_utilization:.1f}%</div>
        </div>
    </div>
    
    <div class="passwords">
        <h2>Cracked Passwords ({password_count})</h2>
        <div class="password-list">
            {password_list}
        </div>
    </div>
</body>
</html>
        """
        
        password_list = "<br>".join(f"{i+1}. {pwd}" for i, pwd in enumerate(result.cracked_passwords))
        
        return html_template.format(
            session_name=result.session_name,
            success_rate=result.success_rate,
            cracked_hashes=result.cracked_hashes,
            total_hashes=result.total_hashes,
            runtime_hours=result.runtime_seconds / 3600,
            hash_rate=result.hash_rate,
            gpu_utilization=result.gpu_utilization,
            password_count=len(result.cracked_passwords),
            password_list=password_list
        )


# Exemple d'utilisation
if __name__ == "__main__":
    # Initialisation du manager
    hm = HashcatManager()
    
    # Configuration d'attaque
    config = AttackConfig(
        hash_file="hashes/test_md5.txt",
        hash_type=HashType.MD5,
        attack_mode=AttackMode.DICTIONARY,
        wordlists=["wordlists/rockyou.txt"],
        session_name="test_attack"
    )
    
    # Callbacks pour monitoring
    def progress_callback(progress_line):
        print(f"Progress: {progress_line}")
    
    def monitor_callback(monitor_data):
        print(f"GPU: {monitor_data['gpu_utilization']}%, "
              f"Runtime: {monitor_data['runtime']}s")
    
    hm.set_callback("progress", progress_callback)
    hm.set_callback("monitor", monitor_callback)
    
    try:
        # Lancement de l'attaque
        result = hm.dictionary_attack(config)
        
        # Affichage des résultats
        print(f"\nAttack completed!")
        print(f"Success rate: {result.success_rate:.2%}")
        print(f"Cracked passwords: {len(result.cracked_passwords)}")
        
        # Export des résultats
        hm.export_result(result, "attack_report.html", "html")
        
    except Exception as e:
        logger.error(f"Attack failed: {e}")