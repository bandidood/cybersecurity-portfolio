#!/usr/bin/env python3
"""
Industrial Edge Computing Gateway
Gateway de traitement IoT industriel en temps réel avec latence ultra-faible
"""

import asyncio
import json
import time
import logging
import ssl
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
import queue
import socket
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EdgeSensorReading:
    """Lecture de capteur optimisée pour l'edge"""
    timestamp: float  # Unix timestamp pour performance
    sensor_id: str
    value: float
    quality: float
    anomaly_score: float
    processed: bool = False
    cached: bool = False

@dataclass
class EdgeRule:
    """Règle métier à exécuter sur l'edge"""
    rule_id: str
    sensor_id: str
    condition: str  # Expression Python évaluable
    action: str     # Action à déclencher
    priority: int   # 1=critique, 5=info
    enabled: bool = True
    last_triggered: Optional[float] = None
    trigger_count: int = 0

@dataclass
class ConnectivityStatus:
    """État de connectivité réseau"""
    connection_type: str  # wifi, 4g, 5g, ethernet
    signal_strength: float  # 0-100
    latency_ms: float
    bandwidth_mbps: float
    is_primary: bool
    last_check: float
    errors_count: int = 0

class DataCompressor:
    """Compression intelligente des données IoT"""
    
    def __init__(self, compression_level: int = 6):
        self.compression_level = compression_level
        self.stats = {
            'total_compressed': 0,
            'total_uncompressed': 0,
            'compression_ratio': 0.0
        }
    
    def compress_readings(self, readings: List[EdgeSensorReading]) -> bytes:
        """Compresse une liste de lectures avec optimisations spécifiques IoT"""
        
        # Conversion vers format compact
        data = {
            'timestamps': [r.timestamp for r in readings],
            'sensor_ids': [r.sensor_id for r in readings],
            'values': [r.value for r in readings],
            'qualities': [r.quality for r in readings],
            'anomaly_scores': [r.anomaly_score for r in readings]
        }
        
        # Sérialisation JSON compacte
        json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        
        # Compression zlib
        compressed = zlib.compress(json_data, self.compression_level)
        
        # Mise à jour des statistiques
        self.stats['total_uncompressed'] += len(json_data)
        self.stats['total_compressed'] += len(compressed)
        self.stats['compression_ratio'] = (
            1.0 - self.stats['total_compressed'] / self.stats['total_uncompressed']
        ) * 100
        
        return compressed
    
    def decompress_readings(self, compressed_data: bytes) -> List[EdgeSensorReading]:
        """Décompresse les lectures"""
        
        # Décompression
        json_data = zlib.decompress(compressed_data)
        data = json.loads(json_data.decode('utf-8'))
        
        # Reconstruction des objets
        readings = []
        for i in range(len(data['timestamps'])):
            reading = EdgeSensorReading(
                timestamp=data['timestamps'][i],
                sensor_id=data['sensor_ids'][i],
                value=data['values'][i],
                quality=data['qualities'][i],
                anomaly_score=data['anomaly_scores'][i]
            )
            readings.append(reading)
        
        return readings

class LocalCache:
    """Cache local haute performance avec persistance"""
    
    def __init__(self, max_size_mb: int = 1024, retention_hours: int = 168):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.retention_seconds = retention_hours * 3600
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.access_times: Dict[str, float] = {}
        self.size_bytes = 0
        self.lock = threading.RLock()
        
        # Démarrer le nettoyage périodique
        self.cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self.cleanup_thread.start()
    
    def store(self, key: str, data: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Stocke des données dans le cache"""
        with self.lock:
            # Sérialisation pour calcul de taille
            serialized = json.dumps(data, default=str).encode('utf-8')
            data_size = len(serialized)
            
            # Vérification de l'espace disponible
            if self.size_bytes + data_size > self.max_size_bytes:
                self._evict_lru(data_size)
            
            # Stockage
            now = time.time()
            expires_at = now + (ttl_seconds if ttl_seconds else self.retention_seconds)
            
            self.cache[key] = {
                'data': data,
                'size': data_size,
                'created_at': now,
                'expires_at': expires_at,
                'access_count': 1
            }
            
            self.access_times[key] = now
            self.size_bytes += data_size
            
            return True
    
    def get(self, key: str) -> Optional[Any]:
        """Récupère des données du cache"""
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            now = time.time()
            
            # Vérification de l'expiration
            if now > entry['expires_at']:
                self._remove_entry(key)
                return None
            
            # Mise à jour des statistiques d'accès
            entry['access_count'] += 1
            self.access_times[key] = now
            
            return entry['data']
    
    def _evict_lru(self, needed_space: int):
        """Éviction LRU pour libérer de l'espace"""
        # Trier par temps d'accès (plus ancien en premier)
        sorted_keys = sorted(self.access_times.keys(), 
                           key=lambda k: self.access_times[k])
        
        freed_space = 0
        for key in sorted_keys:
            if freed_space >= needed_space:
                break
            
            freed_space += self.cache[key]['size']
            self._remove_entry(key)
    
    def _remove_entry(self, key: str):
        """Supprime une entrée du cache"""
        if key in self.cache:
            self.size_bytes -= self.cache[key]['size']
            del self.cache[key]
            del self.access_times[key]
    
    def _periodic_cleanup(self):
        """Nettoyage périodique des entrées expirées"""
        while True:
            try:
                time.sleep(300)  # Toutes les 5 minutes
                now = time.time()
                
                with self.lock:
                    expired_keys = [
                        key for key, entry in self.cache.items()
                        if now > entry['expires_at']
                    ]
                    
                    for key in expired_keys:
                        self._remove_entry(key)
                    
                    if expired_keys:
                        logger.info(f"Nettoyé {len(expired_keys)} entrées expirées du cache")
                        
            except Exception as e:
                logger.error(f"Erreur lors du nettoyage du cache: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques du cache"""
        with self.lock:
            return {
                'entries_count': len(self.cache),
                'size_bytes': self.size_bytes,
                'size_mb': self.size_bytes / (1024 * 1024),
                'utilization_pct': (self.size_bytes / self.max_size_bytes) * 100,
                'hit_ratio': self._calculate_hit_ratio()
            }
    
    def _calculate_hit_ratio(self) -> float:
        """Calcule le taux de succès du cache"""
        total_access = sum(entry['access_count'] for entry in self.cache.values())
        return (total_access / max(1, len(self.cache))) if self.cache else 0.0

class ConnectivityManager:
    """Gestionnaire de connectivité réseau avec failover"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.connections: Dict[str, ConnectivityStatus] = {}
        self.primary_connection: Optional[str] = None
        self.monitoring_active = False
        
        self._initialize_connections()
    
    def _initialize_connections(self):
        """Initialise les connexions configurées"""
        for conn_name, conn_config in self.config.get('connections', {}).items():
            status = ConnectivityStatus(
                connection_type=conn_config['type'],
                signal_strength=0.0,
                latency_ms=999.0,
                bandwidth_mbps=0.0,
                is_primary=conn_config.get('is_primary', False),
                last_check=0.0
            )
            self.connections[conn_name] = status
            
            if status.is_primary:
                self.primary_connection = conn_name
    
    async def start_monitoring(self):
        """Démarre le monitoring de connectivité"""
        self.monitoring_active = True
        
        # Démarrer les tâches de monitoring
        tasks = [
            asyncio.create_task(self._monitor_connection(name, status))
            for name, status in self.connections.items()
        ]
        
        # Tâche de basculement automatique
        tasks.append(asyncio.create_task(self._auto_failover()))
        
        await asyncio.gather(*tasks)
    
    async def _monitor_connection(self, name: str, status: ConnectivityStatus):
        """Monitore une connexion spécifique"""
        while self.monitoring_active:
            try:
                # Test de latence
                latency = await self._test_latency(name)
                status.latency_ms = latency
                
                # Test de bande passante (approximatif)
                bandwidth = await self._test_bandwidth(name)
                status.bandwidth_mbps = bandwidth
                
                # Force du signal (simulé pour la démo)
                status.signal_strength = max(0, min(100, 
                    status.signal_strength + np.random.normal(0, 5)))
                
                status.last_check = time.time()
                status.errors_count = 0
                
                logger.debug(f"Connexion {name}: {latency:.1f}ms, {bandwidth:.1f}Mbps")
                
            except Exception as e:
                status.errors_count += 1
                logger.warning(f"Erreur monitoring {name}: {e}")
            
            await asyncio.sleep(10)  # Check toutes les 10 secondes
    
    async def _test_latency(self, connection_name: str) -> float:
        """Test de latence réseau"""
        try:
            # Test ping vers serveurs de référence
            test_hosts = ['8.8.8.8', '1.1.1.1', 'google.com']
            latencies = []
            
            for host in test_hosts[:1]:  # Test rapide sur un seul host
                start_time = time.time()
                
                # Résolution DNS + connexion TCP (simulé)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    result = sock.connect_ex((host if not host.count('.') == 3 else host, 53))
                    sock.close()
                    
                    if result == 0:
                        latency = (time.time() - start_time) * 1000
                        latencies.append(latency)
                except:
                    continue
            
            return np.mean(latencies) if latencies else 999.0
            
        except Exception:
            return 999.0
    
    async def _test_bandwidth(self, connection_name: str) -> float:
        """Test approximatif de bande passante"""
        # Simulation basée sur le type de connexion
        conn_type = self.connections[connection_name].connection_type
        
        base_bandwidth = {
            'ethernet': 100.0,
            'wifi': 50.0,
            '5g': 150.0,
            '4g': 25.0,
            'satellite': 10.0
        }.get(conn_type, 1.0)
        
        # Variation réaliste
        variation = np.random.uniform(0.7, 1.2)
        return base_bandwidth * variation
    
    async def _auto_failover(self):
        """Basculement automatique en cas de problème"""
        while self.monitoring_active:
            try:
                current_primary = self.primary_connection
                if current_primary and current_primary in self.connections:
                    primary_status = self.connections[current_primary]
                    
                    # Critères de basculement
                    should_failover = (
                        primary_status.latency_ms > 500 or
                        primary_status.errors_count > 3 or
                        primary_status.signal_strength < 20
                    )
                    
                    if should_failover:
                        # Chercher la meilleure connexion alternative
                        best_alternative = self._find_best_connection(exclude=current_primary)
                        
                        if best_alternative:
                            logger.warning(f"Basculement: {current_primary} → {best_alternative}")
                            self.primary_connection = best_alternative
                            
                            # Marquer la nouvelle connexion comme primaire
                            for name, status in self.connections.items():
                                status.is_primary = (name == best_alternative)
                
            except Exception as e:
                logger.error(f"Erreur dans le failover automatique: {e}")
            
            await asyncio.sleep(30)  # Vérification toutes les 30 secondes
    
    def _find_best_connection(self, exclude: Optional[str] = None) -> Optional[str]:
        """Trouve la meilleure connexion disponible"""
        candidates = {
            name: status for name, status in self.connections.items()
            if name != exclude and status.errors_count < 5
        }
        
        if not candidates:
            return None
        
        # Score basé sur latence, bande passante et fiabilité
        best_name = None
        best_score = -1
        
        for name, status in candidates.items():
            score = (
                (100 - min(status.latency_ms / 10, 100)) * 0.4 +  # Latence
                (status.bandwidth_mbps / 100) * 0.3 +              # Bande passante
                (status.signal_strength / 100) * 0.2 +             # Signal
                (max(0, 10 - status.errors_count) / 10) * 0.1      # Fiabilité
            )
            
            if score > best_score:
                best_score = score
                best_name = name
        
        return best_name
    
    def get_active_connection(self) -> Optional[ConnectivityStatus]:
        """Récupère la connexion active"""
        if self.primary_connection and self.primary_connection in self.connections:
            return self.connections[self.primary_connection]
        return None
    
    def get_all_connections(self) -> Dict[str, ConnectivityStatus]:
        """Récupère toutes les connexions"""
        return self.connections.copy()

class EdgeRulesEngine:
    """Moteur de règles métier pour traitement edge"""
    
    def __init__(self):
        self.rules: Dict[str, EdgeRule] = {}
        self.stats = {
            'rules_executed': 0,
            'rules_triggered': 0,
            'execution_time_ms': 0.0
        }
        self.variables = {}  # Variables globales pour les règles
    
    def add_rule(self, rule: EdgeRule):
        """Ajoute une règle au moteur"""
        self.rules[rule.rule_id] = rule
        logger.info(f"Règle ajoutée: {rule.rule_id} pour capteur {rule.sensor_id}")
    
    def remove_rule(self, rule_id: str):
        """Supprime une règle"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Règle supprimée: {rule_id}")
    
    async def evaluate_reading(self, reading: EdgeSensorReading) -> List[str]:
        """Évalue une lecture contre toutes les règles applicables"""
        triggered_actions = []
        
        # Filtrer les règles applicables
        applicable_rules = [
            rule for rule in self.rules.values()
            if rule.enabled and (rule.sensor_id == reading.sensor_id or rule.sensor_id == '*')
        ]
        
        # Trier par priorité
        applicable_rules.sort(key=lambda r: r.priority)
        
        for rule in applicable_rules:
            try:
                start_time = time.time()
                
                # Préparer le contexte d'évaluation
                context = {
                    'value': reading.value,
                    'quality': reading.quality,
                    'anomaly_score': reading.anomaly_score,
                    'timestamp': reading.timestamp,
                    'sensor_id': reading.sensor_id,
                    **self.variables  # Variables globales
                }
                
                # Évaluer la condition
                if self._evaluate_condition(rule.condition, context):
                    # Vérifier les throttling (éviter les déclenchements trop fréquents)
                    now = time.time()
                    if (rule.last_triggered is None or 
                        now - rule.last_triggered > 60):  # Minimum 1 minute entre déclenchements
                        
                        triggered_actions.append(rule.action)
                        rule.last_triggered = now
                        rule.trigger_count += 1
                        
                        self.stats['rules_triggered'] += 1
                        
                        logger.info(f"Règle déclenchée: {rule.rule_id} -> {rule.action}")
                
                execution_time = (time.time() - start_time) * 1000
                self.stats['execution_time_ms'] += execution_time
                self.stats['rules_executed'] += 1
                
            except Exception as e:
                logger.error(f"Erreur évaluation règle {rule.rule_id}: {e}")
        
        return triggered_actions
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Évalue une condition de manière sécurisée"""
        try:
            # Liste blanche des fonctions autorisées
            safe_functions = {
                'abs': abs,
                'min': min,
                'max': max,
                'round': round,
                'len': len,
                'sum': sum,
                'avg': lambda x: sum(x) / len(x) if x else 0,
                'and': lambda a, b: a and b,
                'or': lambda a, b: a or b,
                'not': lambda a: not a
            }
            
            # Contexte sécurisé
            safe_context = {
                **context,
                **safe_functions,
                '__builtins__': {}  # Désactiver les builtins dangereux
            }
            
            # Évaluation
            return bool(eval(condition, safe_context))
            
        except Exception as e:
            logger.warning(f"Erreur évaluation condition '{condition}': {e}")
            return False
    
    def set_variable(self, name: str, value: Any):
        """Définit une variable globale pour les règles"""
        self.variables[name] = value
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques du moteur de règles"""
        avg_execution_time = (
            self.stats['execution_time_ms'] / max(1, self.stats['rules_executed'])
        )
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rules_executed': self.stats['rules_executed'],
            'rules_triggered': self.stats['rules_triggered'],
            'avg_execution_time_ms': avg_execution_time,
            'trigger_rate_pct': (
                (self.stats['rules_triggered'] / max(1, self.stats['rules_executed'])) * 100
            )
        }

class IndustrialEdgeGateway:
    """Gateway Edge Computing industriel principal"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        
        # Composants principaux
        self.cache = LocalCache(
            max_size_mb=self.config['cache']['max_size_mb'],
            retention_hours=self.config['cache']['retention_hours']
        )
        self.compressor = DataCompressor(
            compression_level=self.config['compression']['level']
        )
        self.connectivity = ConnectivityManager(self.config['connectivity'])
        self.rules_engine = EdgeRulesEngine()
        
        # Files de traitement
        self.input_queue = asyncio.Queue(maxsize=10000)
        self.output_queue = asyncio.Queue(maxsize=5000)
        self.priority_queue = asyncio.Queue(maxsize=1000)
        
        # État et statistiques
        self.running = False
        self.stats = {
            'readings_processed': 0,
            'readings_cached': 0,
            'readings_forwarded': 0,
            'rules_triggered': 0,
            'avg_processing_time_ms': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Chiffrement
        self.cipher = self._init_encryption()
        
        # Pool de threads pour traitement intensif
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        self._setup_default_rules()
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Charge la configuration du gateway"""
        default_config = {
            'gateway': {
                'name': 'Industrial-Edge-Gateway-01',
                'location': 'Factory-Floor-A',
                'batch_size': 100,
                'max_latency_ms': 5,
                'buffer_size': 10000
            },
            'cache': {
                'max_size_mb': 512,
                'retention_hours': 168  # 7 jours
            },
            'compression': {
                'enabled': True,
                'level': 6,
                'min_batch_size': 10
            },
            'connectivity': {
                'connections': {
                    'primary_wifi': {
                        'type': 'wifi',
                        'is_primary': True,
                        'ssid': 'Factory-WiFi-5G',
                        'priority': 1
                    },
                    'backup_4g': {
                        'type': '4g',
                        'is_primary': False,
                        'apn': 'industrial.iot',
                        'priority': 2
                    },
                    'emergency_satellite': {
                        'type': 'satellite',
                        'is_primary': False,
                        'priority': 3
                    }
                },
                'failover': {
                    'enabled': True,
                    'latency_threshold_ms': 500,
                    'error_threshold': 3
                }
            },
            'security': {
                'encryption_enabled': True,
                'tls_version': '1.3',
                'certificate_validation': True,
                'api_key_rotation_hours': 24
            },
            'cloud': {
                'endpoint': 'https://industrial-iot-hub.azure.com',
                'batch_upload_interval_s': 30,
                'max_retry_attempts': 3,
                'timeout_s': 10
            }
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                # Merge récursif
                self._deep_merge(default_config, user_config)
        
        return default_config
    
    def _deep_merge(self, base: Dict, override: Dict):
        """Merge récursif des dictionnaires"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _init_encryption(self) -> Optional[Fernet]:
        """Initialise le chiffrement"""
        if not self.config['security']['encryption_enabled']:
            return None
        
        # Génération/chargement de clé
        key_file = Path('./edge_gateway.key')
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            # Générer nouvelle clé
            password = b"industrial-edge-gateway-secret"
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            logger.info("Nouvelle clé de chiffrement générée")
        
        return Fernet(key)
    
    def _setup_default_rules(self):
        """Configure les règles par défaut"""
        
        # Règle température critique
        temp_rule = EdgeRule(
            rule_id="temp_critical",
            sensor_id="TEMP_*",
            condition="value > 1000 or value < 500",
            action="alert_critical_temperature",
            priority=1
        )
        self.rules_engine.add_rule(temp_rule)
        
        # Règle vibration anormale
        vib_rule = EdgeRule(
            rule_id="vibration_anomaly",
            sensor_id="VIB_*",
            condition="anomaly_score > 0.8 and quality > 0.8",
            action="alert_vibration_anomaly",
            priority=2
        )
        self.rules_engine.add_rule(vib_rule)
        
        # Règle qualité dégradée
        qual_rule = EdgeRule(
            rule_id="quality_degraded",
            sensor_id="QUAL_*",
            condition="value < 90 and quality > 0.9",
            action="alert_quality_degradation",
            priority=3
        )
        self.rules_engine.add_rule(qual_rule)
        
        # Règle maintenance préventive
        maint_rule = EdgeRule(
            rule_id="maintenance_due",
            sensor_id="*",
            condition="anomaly_score > 0.5 and quality < 0.7",
            action="schedule_maintenance",
            priority=4
        )
        self.rules_engine.add_rule(maint_rule)
        
        logger.info(f"Configuré {len(self.rules_engine.rules)} règles par défaut")
    
    async def start(self):
        """Démarre le gateway edge"""
        self.running = True
        
        logger.info(f"Démarrage Edge Gateway: {self.config['gateway']['name']}")
        logger.info(f"Location: {self.config['gateway']['location']}")
        
        # Démarrer les tâches principales
        tasks = [
            asyncio.create_task(self._input_processor()),
            asyncio.create_task(self._data_processor()),
            asyncio.create_task(self._output_processor()),
            asyncio.create_task(self._cloud_uploader()),
            asyncio.create_task(self._stats_reporter()),
            asyncio.create_task(self.connectivity.start_monitoring())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Arrêt du gateway par l'utilisateur")
        finally:
            self.running = False
    
    async def _input_processor(self):
        """Processeur d'entrée pour les données capteurs"""
        while self.running:
            try:
                # Simulation de réception de données
                # En production, ceci recevrait des données via MQTT, HTTP, TCP, etc.
                await asyncio.sleep(0.001)  # Simulation 1000 lectures/sec
                
                # Générer lecture simulée
                reading = EdgeSensorReading(
                    timestamp=time.time(),
                    sensor_id=f"TEMP_FURNACE_{np.random.randint(1, 6):02d}",
                    value=np.random.uniform(800, 950),
                    quality=np.random.uniform(0.8, 1.0),
                    anomaly_score=np.random.uniform(0.0, 0.3)
                )
                
                await self.input_queue.put(reading)
                
            except Exception as e:
                logger.error(f"Erreur dans input_processor: {e}")
    
    async def _data_processor(self):
        """Processeur principal des données"""
        batch = []
        last_batch_time = time.time()
        batch_size = self.config['gateway']['batch_size']
        max_latency = self.config['gateway']['max_latency_ms'] / 1000
        
        while self.running:
            try:
                # Récupération avec timeout
                try:
                    reading = await asyncio.wait_for(
                        self.input_queue.get(), timeout=0.1
                    )
                    batch.append(reading)
                except asyncio.TimeoutError:
                    pass
                
                current_time = time.time()
                
                # Traitement par batch ou par timeout
                should_process = (
                    len(batch) >= batch_size or
                    (batch and current_time - last_batch_time > max_latency)
                )
                
                if should_process and batch:
                    await self._process_batch(batch)
                    batch = []
                    last_batch_time = current_time
                
            except Exception as e:
                logger.error(f"Erreur dans data_processor: {e}")
    
    async def _process_batch(self, readings: List[EdgeSensorReading]):
        """Traite un lot de lectures"""
        start_time = time.time()
        
        try:
            # Traitement en parallèle
            tasks = [self._process_single_reading(reading) for reading in readings]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Traitement des résultats
            processed_readings = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Erreur traitement lecture {i}: {result}")
                else:
                    processed_readings.append(result)
            
            # Mise en cache et forward
            if processed_readings:
                await self._cache_and_forward(processed_readings)
            
            # Mise à jour des statistiques
            processing_time = (time.time() - start_time) * 1000
            self.stats['readings_processed'] += len(readings)
            self.stats['avg_processing_time_ms'] = (
                self.stats['avg_processing_time_ms'] * 0.9 + processing_time * 0.1
            )
            
        except Exception as e:
            logger.error(f"Erreur traitement batch: {e}")
    
    async def _process_single_reading(self, reading: EdgeSensorReading) -> EdgeSensorReading:
        """Traite une lecture individuelle"""
        
        # Vérification cache
        cache_key = f"{reading.sensor_id}_{int(reading.timestamp)}"
        cached_result = self.cache.get(cache_key)
        
        if cached_result:
            self.stats['cache_hits'] += 1
            reading.cached = True
            return reading
        
        self.stats['cache_misses'] += 1
        
        # Évaluation des règles métier
        triggered_actions = await self.rules_engine.evaluate_reading(reading)
        
        if triggered_actions:
            self.stats['rules_triggered'] += len(triggered_actions)
            
            # Traitement des actions critiques en priorité
            critical_actions = [a for a in triggered_actions if 'critical' in a.lower()]
            if critical_actions:
                await self.priority_queue.put({
                    'reading': reading,
                    'actions': critical_actions,
                    'timestamp': time.time()
                })
        
        # Filtrage et enrichissement
        reading = await self._enrich_reading(reading)
        
        # Mise en cache
        self.cache.store(cache_key, asdict(reading), ttl_seconds=3600)
        
        reading.processed = True
        return reading
    
    async def _enrich_reading(self, reading: EdgeSensorReading) -> EdgeSensorReading:
        """Enrichit une lecture avec des données contextuelles"""
        
        # Calculs statistiques rapides (moyennes mobiles, tendances)
        # Correlation avec d'autres capteurs
        # Ajout de métadonnées contextuelles
        
        # Simulation d'enrichissement
        if reading.sensor_id.startswith('TEMP_'):
            # Ajustement température ambiante
            ambient_temp = 22.0  # Température ambiante simulée
            reading.value = reading.value - ambient_temp + 20.0
        
        return reading
    
    async def _cache_and_forward(self, readings: List[EdgeSensorReading]):
        """Met en cache et forward vers le cloud"""
        
        # Cache local
        for reading in readings:
            self.stats['readings_cached'] += 1
        
        # Forward vers le cloud
        await self.output_queue.put(readings)
    
    async def _output_processor(self):
        """Processeur de sortie vers le cloud"""
        while self.running:
            try:
                readings = await self.output_queue.get()
                
                # Compression avant envoi
                if self.config['compression']['enabled']:
                    compressed_data = self.compressor.compress_readings(readings)
                else:
                    compressed_data = json.dumps([asdict(r) for r in readings]).encode()
                
                # Chiffrement si activé
                if self.cipher:
                    compressed_data = self.cipher.encrypt(compressed_data)
                
                # Stockage temporaire pour upload
                upload_key = f"upload_{int(time.time())}_{len(readings)}"
                self.cache.store(upload_key, compressed_data, ttl_seconds=3600)
                
                self.stats['readings_forwarded'] += len(readings)
                
            except Exception as e:
                logger.error(f"Erreur dans output_processor: {e}")
    
    async def _cloud_uploader(self):
        """Upload périodique vers le cloud"""
        upload_interval = self.config['cloud']['batch_upload_interval_s']
        
        while self.running:
            try:
                await asyncio.sleep(upload_interval)
                
                # Récupérer les données en attente d'upload
                upload_keys = [k for k in self.cache.cache.keys() if k.startswith('upload_')]
                
                if upload_keys:
                    success_count = 0
                    for key in upload_keys:
                        data = self.cache.get(key)
                        if data and await self._upload_to_cloud(data):
                            # Supprimer après upload réussi
                            self.cache._remove_entry(key)
                            success_count += 1
                    
                    if success_count > 0:
                        logger.info(f"Uploadé {success_count} batches vers le cloud")
                
            except Exception as e:
                logger.error(f"Erreur dans cloud_uploader: {e}")
    
    async def _upload_to_cloud(self, data: bytes) -> bool:
        """Upload des données vers le cloud"""
        try:
            # Simulation d'upload HTTP
            # En production: requête HTTP POST vers l'endpoint cloud
            
            connection = self.connectivity.get_active_connection()
            if not connection or connection.latency_ms > 1000:
                return False
            
            # Simulation délai réseau
            await asyncio.sleep(connection.latency_ms / 1000)
            
            # Simulation succès/échec basé sur qualité connexion
            success_probability = max(0.7, 1.0 - connection.errors_count * 0.1)
            success = np.random.random() < success_probability
            
            if not success:
                logger.warning("Échec upload vers le cloud")
            
            return success
            
        except Exception as e:
            logger.error(f"Erreur upload cloud: {e}")
            return False
    
    async def _stats_reporter(self):
        """Reporter de statistiques périodique"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Toutes les minutes
                
                # Statistiques complètes
                stats = {
                    'gateway': self.config['gateway'],
                    'timestamp': datetime.now().isoformat(),
                    'performance': self.stats,
                    'cache': self.cache.get_stats(),
                    'compression': self.compressor.stats,
                    'rules_engine': self.rules_engine.get_stats(),
                    'connectivity': {
                        name: asdict(status) 
                        for name, status in self.connectivity.get_all_connections().items()
                    }
                }
                
                # Log des métriques clés
                logger.info(f"📊 Edge Gateway Stats:")
                logger.info(f"  Readings processed: {self.stats['readings_processed']:,}")
                logger.info(f"  Avg processing time: {self.stats['avg_processing_time_ms']:.2f}ms")
                logger.info(f"  Cache utilization: {self.cache.get_stats()['utilization_pct']:.1f}%")
                logger.info(f"  Compression ratio: {self.compressor.stats['compression_ratio']:.1f}%")
                logger.info(f"  Rules triggered: {self.stats['rules_triggered']}")
                
                # Sauvegarder stats détaillées
                with open(f"edge_stats_{datetime.now().strftime('%Y%m%d_%H%M')}.json", 'w') as f:
                    json.dump(stats, f, indent=2, default=str)
                
            except Exception as e:
                logger.error(f"Erreur dans stats_reporter: {e}")
    
    def add_sensor_reading(self, reading: EdgeSensorReading):
        """Ajoute une lecture de capteur (API externe)"""
        try:
            self.input_queue.put_nowait(reading)
        except asyncio.QueueFull:
            logger.warning("Queue d'entrée pleine, lecture ignorée")
    
    def get_stats(self) -> Dict[str, Any]:
        """Récupère les statistiques actuelles"""
        return {
            'gateway': self.config['gateway'],
            'timestamp': datetime.now().isoformat(),
            'performance': self.stats,
            'cache': self.cache.get_stats(),
            'compression': self.compressor.stats,
            'rules_engine': self.rules_engine.get_stats(),
            'connectivity': {
                name: asdict(status) 
                for name, status in self.connectivity.get_all_connections().items()
            }
        }

async def main():
    """Point d'entrée principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Industrial Edge Computing Gateway")
    parser.add_argument('--config', help='Fichier de configuration')
    parser.add_argument('--duration', type=int, default=300, help='Durée test (secondes)')
    
    args = parser.parse_args()
    
    # Créer et démarrer le gateway
    gateway = IndustrialEdgeGateway(args.config)
    
    try:
        # Démarrer avec timeout pour les tests
        await asyncio.wait_for(gateway.start(), timeout=args.duration)
    except asyncio.TimeoutError:
        logger.info(f"Test terminé après {args.duration} secondes")
    except KeyboardInterrupt:
        logger.info("Arrêt par l'utilisateur")
    finally:
        # Statistiques finales
        stats = gateway.get_stats()
        print("\n" + "="*60)
        print("📊 STATISTIQUES FINALES EDGE GATEWAY")
        print("="*60)
        print(f"🏭 Gateway: {stats['gateway']['name']}")
        print(f"📈 Lectures traitées: {stats['performance']['readings_processed']:,}")
        print(f"⚡ Latence moyenne: {stats['performance']['avg_processing_time_ms']:.2f}ms")
        print(f"💾 Cache utilisation: {stats['cache']['utilization_pct']:.1f}%")
        print(f"🗜️  Compression: {stats['compression']['compression_ratio']:.1f}%")
        print(f"🔧 Règles déclenchées: {stats['performance']['rules_triggered']}")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())