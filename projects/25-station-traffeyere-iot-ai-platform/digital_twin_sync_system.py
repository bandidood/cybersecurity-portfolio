#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 5B: Système de Synchronisation Temps Réel du Jumeau Numérique

Système de synchronisation bidirectionnelle entre les capteurs IoT physiques 
et le modèle virtuel avec compensation de latence, fusion de données et 
adaptation dynamique des paramètres.

Auteur: Spécialiste Sécurité IoT Industriel
Date: 2024
"""

import os
import json
import asyncio
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field, asdict
import numpy as np
import pandas as pd
from pathlib import Path
import uuid
import hashlib

# Communication et réseau
import aiohttp
import websockets
import paho.mqtt.client as mqtt
from aiohttp import web, WSMsgType
import socket
import struct

# Traitement des données et filtrage
from scipy.signal import butter, filtfilt, savgol_filter
from scipy.interpolate import interp1d
from scipy.stats import zscore
import kalman_filter as kf
from collections import deque, defaultdict

# Sérialisation et compression
import pickle
import gzip
import msgpack
import cbor2

# Bases de données temps réel
import redis
import asyncio_redis
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Machine Learning pour la prédiction
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
import tensorflow as tf

warnings.filterwarnings('ignore')

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SensorReading:
    """Lecture de capteur IoT avec métadonnées."""
    sensor_id: str
    timestamp: datetime
    value: float
    unit: str
    quality: float = 1.0  # Qualité de la mesure (0-1)
    latency_ms: float = 0.0  # Latence de transmission
    source: str = "physical"  # physical, virtual, predicted
    confidence: float = 1.0  # Confiance dans la mesure
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SynchronizationState:
    """État de synchronisation entre physique et virtuel."""
    equipment_id: str
    last_sync: datetime
    sync_quality: float = 1.0  # Qualité de la synchronisation (0-1)
    drift_rate: float = 0.0  # Taux de dérive temporelle (ms/s)
    latency_avg: float = 0.0  # Latence moyenne (ms)
    latency_jitter: float = 0.0  # Variation de latence (ms)
    data_loss_rate: float = 0.0  # Taux de perte de données (0-1)
    prediction_accuracy: float = 1.0  # Précision des prédictions
    calibration_offset: Dict[str, float] = field(default_factory=dict)

class LatencyCompensator:
    """Compensateur de latence pour synchronisation temporelle."""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.latency_history = deque(maxlen=max_history)
        self.drift_detector = deque(maxlen=100)
        self.kalman_filter = None
        self._initialize_kalman_filter()
    
    def _initialize_kalman_filter(self):
        """Initialise le filtre de Kalman pour l'estimation de latence."""
        try:
            # État: [latence, dérivée_latence]
            # Mesure: latence observée
            self.kalman_filter = kf.KalmanFilter(
                transition_matrices=np.array([[1, 1], [0, 1]]),  # Modèle constant + dérive
                observation_matrices=np.array([[1, 0]]),  # On observe seulement la latence
                initial_state_mean=[50, 0],  # Latence initiale 50ms, dérive 0
                n_dim_state=2,
                n_dim_obs=1
            )
        except Exception as e:
            logger.warning(f"Erreur initialisation Kalman: {e}")
            self.kalman_filter = None
    
    def add_latency_measurement(self, latency_ms: float, timestamp: datetime):
        """Ajoute une mesure de latence."""
        self.latency_history.append({
            'latency': latency_ms,
            'timestamp': timestamp
        })
        
        # Détection de dérive
        if len(self.latency_history) >= 2:
            drift = latency_ms - self.latency_history[-2]['latency']
            self.drift_detector.append(drift)
    
    def estimate_current_latency(self) -> float:
        """Estime la latence actuelle avec prédiction."""
        if not self.latency_history:
            return 50.0  # Valeur par défaut
        
        if self.kalman_filter and len(self.latency_history) > 5:
            try:
                # Utilisation du filtre de Kalman
                recent_latencies = [point['latency'] for point in list(self.latency_history)[-10:]]
                state_means, _ = self.kalman_filter.em(recent_latencies)
                return max(0, state_means[-1][0])  # État estimé de la latence
            except Exception as e:
                logger.warning(f"Erreur Kalman: {e}")
        
        # Fallback: moyenne mobile avec pondération temporelle
        if len(self.latency_history) >= 5:
            recent_latencies = [point['latency'] for point in list(self.latency_history)[-5:]]
            weights = np.exp(np.linspace(-1, 0, len(recent_latencies)))  # Pondération exponentielle
            return np.average(recent_latencies, weights=weights)
        
        return self.latency_history[-1]['latency']
    
    def get_compensation_time(self) -> float:
        """Calcule le temps de compensation à appliquer."""
        estimated_latency = self.estimate_current_latency()
        
        # Ajout d'une marge pour la variation de latence
        if len(self.latency_history) >= 10:
            recent_latencies = [point['latency'] for point in list(self.latency_history)[-10:]]
            jitter = np.std(recent_latencies)
            return estimated_latency + jitter * 0.5  # Marge de sécurité
        
        return estimated_latency
    
    def get_statistics(self) -> Dict[str, float]:
        """Retourne les statistiques de latence."""
        if not self.latency_history:
            return {}
        
        latencies = [point['latency'] for point in self.latency_history]
        
        stats = {
            'avg_latency': np.mean(latencies),
            'min_latency': np.min(latencies),
            'max_latency': np.max(latencies),
            'std_latency': np.std(latencies),
            'measurements_count': len(latencies)
        }
        
        # Détection de dérive
        if len(self.drift_detector) >= 10:
            drifts = list(self.drift_detector)
            stats['drift_rate'] = np.mean(drifts)
            stats['drift_stability'] = 1.0 / (1.0 + abs(stats['drift_rate']))
        
        return stats

class DataFusionEngine:
    """Moteur de fusion de données physiques et virtuelles."""
    
    def __init__(self, fusion_window: int = 10):
        self.fusion_window = fusion_window
        self.sensor_data = defaultdict(lambda: deque(maxlen=fusion_window))
        self.virtual_data = defaultdict(lambda: deque(maxlen=fusion_window))
        self.fusion_weights = {}  # Poids dynamiques pour chaque capteur
        self.anomaly_detectors = {}
        
    def add_physical_reading(self, reading: SensorReading):
        """Ajoute une lecture de capteur physique."""
        self.sensor_data[reading.sensor_id].append(reading)
        self._update_fusion_weights(reading.sensor_id)
    
    def add_virtual_reading(self, reading: SensorReading):
        """Ajoute une lecture du jumeau virtuel."""
        reading.source = "virtual"
        self.virtual_data[reading.sensor_id].append(reading)
    
    def _update_fusion_weights(self, sensor_id: str):
        """Met à jour les poids de fusion basés sur la qualité des données."""
        physical_data = list(self.sensor_data[sensor_id])
        virtual_data = list(self.virtual_data[sensor_id])
        
        if not physical_data or not virtual_data:
            return
        
        # Calcul de la qualité basée sur la cohérence temporelle
        physical_quality = np.mean([reading.quality for reading in physical_data])
        
        # Calcul de l'erreur entre physique et virtuel
        if len(physical_data) >= 3 and len(virtual_data) >= 3:
            phys_values = [r.value for r in physical_data[-3:]]
            virt_values = [r.value for r in virtual_data[-3:]]
            
            # Aligner temporellement
            error = np.mean(np.abs(np.array(phys_values) - np.array(virt_values)))
            virtual_accuracy = 1.0 / (1.0 + error)
            
            # Pondération dynamique
            total_quality = physical_quality + virtual_accuracy
            if total_quality > 0:
                self.fusion_weights[sensor_id] = {
                    'physical': physical_quality / total_quality,
                    'virtual': virtual_accuracy / total_quality
                }
        else:
            # Poids par défaut
            self.fusion_weights[sensor_id] = {
                'physical': 0.8,  # Préférence pour les données réelles
                'virtual': 0.2
            }
    
    def get_fused_value(self, sensor_id: str, timestamp: datetime) -> Optional[SensorReading]:
        """Obtient une valeur fusionnée à un instant donné."""
        physical_data = list(self.sensor_data[sensor_id])
        virtual_data = list(self.virtual_data[sensor_id])
        
        if not physical_data and not virtual_data:
            return None
        
        # Recherche des lectures les plus proches temporellement
        def find_closest_reading(data_list, target_time):
            if not data_list:
                return None
            
            min_diff = float('inf')
            closest = None
            
            for reading in data_list:
                diff = abs((reading.timestamp - target_time).total_seconds())
                if diff < min_diff:
                    min_diff = diff
                    closest = reading
            
            return closest if min_diff < 10.0 else None  # Max 10s de décalage
        
        physical_reading = find_closest_reading(physical_data, timestamp)
        virtual_reading = find_closest_reading(virtual_data, timestamp)
        
        # Fusion des données
        weights = self.fusion_weights.get(sensor_id, {'physical': 0.8, 'virtual': 0.2})
        
        if physical_reading and virtual_reading:
            # Fusion pondérée
            fused_value = (weights['physical'] * physical_reading.value + 
                          weights['virtual'] * virtual_reading.value)
            
            # Métadonnées combinées
            fused_reading = SensorReading(
                sensor_id=sensor_id,
                timestamp=timestamp,
                value=fused_value,
                unit=physical_reading.unit,
                quality=min(physical_reading.quality, virtual_reading.confidence),
                source="fused",
                confidence=(weights['physical'] * physical_reading.quality + 
                           weights['virtual'] * virtual_reading.confidence),
                metadata={
                    'fusion_weights': weights,
                    'physical_value': physical_reading.value,
                    'virtual_value': virtual_reading.value,
                    'time_offset_ms': abs((physical_reading.timestamp - virtual_reading.timestamp).total_seconds() * 1000)
                }
            )
            
            return fused_reading
            
        elif physical_reading:
            # Seulement données physiques
            physical_reading.source = "physical_only"
            return physical_reading
            
        elif virtual_reading:
            # Seulement données virtuelles
            virtual_reading.source = "virtual_only"
            return virtual_reading
            
        return None
    
    def detect_anomalies(self, sensor_id: str) -> List[Dict[str, Any]]:
        """Détecte les anomalies dans les données fusionnées."""
        physical_data = list(self.sensor_data[sensor_id])
        virtual_data = list(self.virtual_data[sensor_id])
        
        anomalies = []
        
        if len(physical_data) >= 5 and len(virtual_data) >= 5:
            # Comparaison des tendances
            phys_values = [r.value for r in physical_data[-5:]]
            virt_values = [r.value for r in virtual_data[-5:]]
            
            # Détection d'écart significatif
            correlation = np.corrcoef(phys_values, virt_values)[0, 1]
            
            if abs(correlation) < 0.7:  # Faible corrélation
                anomalies.append({
                    'type': 'low_correlation',
                    'correlation': correlation,
                    'severity': 'medium',
                    'timestamp': datetime.now()
                })
            
            # Détection de valeurs aberrantes
            combined_values = phys_values + virt_values
            z_scores = np.abs(zscore(combined_values))
            
            if np.any(z_scores > 3):  # Z-score > 3 = aberrant
                anomalies.append({
                    'type': 'outlier_detected',
                    'max_zscore': np.max(z_scores),
                    'severity': 'high' if np.max(z_scores) > 4 else 'medium',
                    'timestamp': datetime.now()
                })
        
        return anomalies
    
    def get_fusion_statistics(self, sensor_id: str) -> Dict[str, Any]:
        """Retourne les statistiques de fusion pour un capteur."""
        physical_count = len(self.sensor_data[sensor_id])
        virtual_count = len(self.virtual_data[sensor_id])
        weights = self.fusion_weights.get(sensor_id, {})
        
        stats = {
            'sensor_id': sensor_id,
            'physical_samples': physical_count,
            'virtual_samples': virtual_count,
            'fusion_weights': weights,
            'last_updated': datetime.now()
        }
        
        # Qualité de fusion
        if physical_count > 0 and virtual_count > 0:
            physical_data = list(self.sensor_data[sensor_id])
            virtual_data = list(self.virtual_data[sensor_id])
            
            avg_physical_quality = np.mean([r.quality for r in physical_data])
            avg_virtual_confidence = np.mean([r.confidence for r in virtual_data])
            
            stats.update({
                'avg_physical_quality': avg_physical_quality,
                'avg_virtual_confidence': avg_virtual_confidence,
                'fusion_quality': (avg_physical_quality + avg_virtual_confidence) / 2
            })
        
        return stats

class RealTimeSyncSystem:
    """Système de synchronisation temps réel principal."""
    
    def __init__(self, config_path: str = "sync_config.json"):
        """Initialise le système de synchronisation."""
        self.config = self.load_config(config_path)
        
        # Composants principaux
        self.latency_compensator = LatencyCompensator()
        self.data_fusion = DataFusionEngine()
        
        # État de synchronisation
        self.sync_states = {}  # equipment_id -> SynchronizationState
        self.active_connections = {}  # Connection tracking
        
        # Communication
        self.mqtt_client = None
        self.websocket_server = None
        self.redis_client = None
        self.influxdb_client = None
        
        # Prédicteurs temps réel
        self.predictors = {}
        
        # Threads et tâches
        self.sync_thread = None
        self.running = False
        
        # Métriques
        self.metrics = {
            'total_messages': 0,
            'successful_syncs': 0,
            'failed_syncs': 0,
            'average_sync_time': 0.0,
            'data_fusion_rate': 0.0
        }
        
        logger.info("Système de synchronisation temps réel initialisé")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration du système."""
        default_config = {
            'mqtt': {
                'broker': 'localhost',
                'port': 1883,
                'topics': {
                    'sensor_data': 'iot/sensors/+/data',
                    'commands': 'iot/commands/+',
                    'status': 'iot/status/+'
                },
                'qos': 2
            },
            'websocket': {
                'host': '0.0.0.0',
                'port': 8765,
                'max_connections': 100
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'expire_seconds': 3600
            },
            'influxdb': {
                'url': 'http://localhost:8086',
                'token': 'your-token',
                'org': 'station-traffeyere',
                'bucket': 'iot-data'
            },
            'sync': {
                'max_latency_ms': 1000,
                'sync_interval_ms': 100,
                'prediction_horizon_s': 30,
                'drift_threshold_ms': 50
            },
            'quality': {
                'min_sensor_quality': 0.7,
                'max_data_age_s': 10,
                'outlier_threshold': 3.0
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                    elif isinstance(value, dict) and isinstance(config[key], dict):
                        for subkey, subvalue in value.items():
                            if subkey not in config[key]:
                                config[key][subkey] = subvalue
            else:
                config = default_config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur chargement config: {e}")
            config = default_config
        
        return config
    
    async def initialize_connections(self):
        """Initialise toutes les connexions réseau."""
        # MQTT
        await self._initialize_mqtt()
        
        # WebSocket
        await self._initialize_websocket()
        
        # Redis
        await self._initialize_redis()
        
        # InfluxDB
        await self._initialize_influxdb()
        
        logger.info("Toutes les connexions initialisées")
    
    async def _initialize_mqtt(self):
        """Initialise la connexion MQTT."""
        try:
            self.mqtt_client = mqtt.Client()
            self.mqtt_client.on_connect = self._on_mqtt_connect
            self.mqtt_client.on_message = self._on_mqtt_message
            self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
            
            mqtt_config = self.config['mqtt']
            self.mqtt_client.connect(mqtt_config['broker'], mqtt_config['port'], 60)
            self.mqtt_client.loop_start()
            
            logger.info("MQTT client initialisé")
            
        except Exception as e:
            logger.error(f"Erreur initialisation MQTT: {e}")
    
    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback de connexion MQTT."""
        if rc == 0:
            logger.info("Connecté au broker MQTT")
            # Souscription aux topics
            topics = self.config['mqtt']['topics']
            qos = self.config['mqtt']['qos']
            
            for topic_name, topic_pattern in topics.items():
                client.subscribe(topic_pattern, qos)
                logger.info(f"Souscrit à {topic_pattern}")
        else:
            logger.error(f"Erreur connexion MQTT: {rc}")
    
    def _on_mqtt_message(self, client, userdata, msg):
        """Callback de réception de message MQTT."""
        try:
            # Décodage du message
            topic = msg.topic
            payload = msg.payload.decode('utf-8')
            
            # Parse JSON
            data = json.loads(payload)
            
            # Traitement asynchrone
            asyncio.create_task(self._process_mqtt_message(topic, data))
            
        except Exception as e:
            logger.error(f"Erreur traitement message MQTT: {e}")
    
    async def _process_mqtt_message(self, topic: str, data: Dict[str, Any]):
        """Traite un message MQTT reçu."""
        try:
            # Extraction de l'ID du capteur depuis le topic
            topic_parts = topic.split('/')
            if len(topic_parts) >= 3:
                sensor_id = topic_parts[2]
                
                # Création d'une lecture de capteur
                reading = SensorReading(
                    sensor_id=sensor_id,
                    timestamp=datetime.now(),
                    value=float(data.get('value', 0)),
                    unit=data.get('unit', ''),
                    quality=float(data.get('quality', 1.0)),
                    source="physical",
                    metadata=data.get('metadata', {})
                )
                
                # Ajout à la fusion de données
                self.data_fusion.add_physical_reading(reading)
                
                # Mise à jour des métriques de latence
                if 'timestamp' in data:
                    msg_timestamp = datetime.fromisoformat(data['timestamp'])
                    latency = (datetime.now() - msg_timestamp).total_seconds() * 1000
                    self.latency_compensator.add_latency_measurement(latency, datetime.now())
                
                # Stockage en base
                await self._store_sensor_data(reading)
                
                self.metrics['total_messages'] += 1
                
        except Exception as e:
            logger.error(f"Erreur traitement message: {e}")
    
    def _on_mqtt_disconnect(self, client, userdata, rc):
        """Callback de déconnexion MQTT."""
        logger.warning(f"Déconnecté du broker MQTT: {rc}")
    
    async def _initialize_websocket(self):
        """Initialise le serveur WebSocket."""
        try:
            ws_config = self.config['websocket']
            
            async def websocket_handler(websocket, path):
                await self._handle_websocket_connection(websocket, path)
            
            self.websocket_server = await websockets.serve(
                websocket_handler,
                ws_config['host'],
                ws_config['port']
            )
            
            logger.info(f"Serveur WebSocket démarré sur {ws_config['host']}:{ws_config['port']}")
            
        except Exception as e:
            logger.error(f"Erreur initialisation WebSocket: {e}")
    
    async def _handle_websocket_connection(self, websocket, path):
        """Gère une connexion WebSocket."""
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = {
            'websocket': websocket,
            'connected_at': datetime.now(),
            'path': path
        }
        
        try:
            logger.info(f"Nouvelle connexion WebSocket: {connection_id}")
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._process_websocket_message(connection_id, data)
                    
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        'error': 'Invalid JSON format'
                    }))
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connexion WebSocket fermée: {connection_id}")
        finally:
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
    
    async def _process_websocket_message(self, connection_id: str, data: Dict[str, Any]):
        """Traite un message WebSocket."""
        message_type = data.get('type')
        websocket = self.active_connections[connection_id]['websocket']
        
        try:
            if message_type == 'sensor_data':
                # Données de capteur via WebSocket
                reading = SensorReading(
                    sensor_id=data['sensor_id'],
                    timestamp=datetime.fromisoformat(data['timestamp']),
                    value=float(data['value']),
                    unit=data.get('unit', ''),
                    quality=float(data.get('quality', 1.0)),
                    source="physical"
                )
                
                self.data_fusion.add_physical_reading(reading)
                await self._store_sensor_data(reading)
                
                # Réponse de confirmation
                await websocket.send(json.dumps({
                    'type': 'ack',
                    'message_id': data.get('message_id'),
                    'status': 'received'
                }))
                
            elif message_type == 'get_sync_status':
                # Demande de statut de synchronisation
                equipment_id = data.get('equipment_id')
                if equipment_id in self.sync_states:
                    sync_state = self.sync_states[equipment_id]
                    await websocket.send(json.dumps({
                        'type': 'sync_status',
                        'equipment_id': equipment_id,
                        'sync_quality': sync_state.sync_quality,
                        'latency_avg': sync_state.latency_avg,
                        'last_sync': sync_state.last_sync.isoformat()
                    }))
                else:
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': f'Equipment {equipment_id} not found'
                    }))
                    
            elif message_type == 'subscribe':
                # Souscription aux mises à jour
                sensor_ids = data.get('sensor_ids', [])
                # Implémentation de la souscription en temps réel
                # ... (logique de souscription)
                
        except Exception as e:
            await websocket.send(json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def _initialize_redis(self):
        """Initialise la connexion Redis."""
        try:
            redis_config = self.config['redis']
            self.redis_client = await asyncio_redis.Connection.create(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config['db']
            )
            
            logger.info("Connexion Redis établie")
            
        except Exception as e:
            logger.error(f"Erreur connexion Redis: {e}")
    
    async def _initialize_influxdb(self):
        """Initialise la connexion InfluxDB."""
        try:
            influx_config = self.config['influxdb']
            self.influxdb_client = InfluxDBClient(
                url=influx_config['url'],
                token=influx_config['token'],
                org=influx_config['org']
            )
            
            logger.info("Connexion InfluxDB établie")
            
        except Exception as e:
            logger.error(f"Erreur connexion InfluxDB: {e}")
    
    async def _store_sensor_data(self, reading: SensorReading):
        """Stocke les données de capteur dans les bases de données."""
        # Redis (cache temps réel)
        if self.redis_client:
            try:
                key = f"sensor:{reading.sensor_id}:latest"
                value = json.dumps({
                    'value': reading.value,
                    'timestamp': reading.timestamp.isoformat(),
                    'quality': reading.quality,
                    'source': reading.source
                })
                
                await self.redis_client.setex(
                    key, 
                    self.config['redis']['expire_seconds'], 
                    value
                )
                
            except Exception as e:
                logger.error(f"Erreur stockage Redis: {e}")
        
        # InfluxDB (historique)
        if self.influxdb_client:
            try:
                point = Point("sensor_data") \
                    .tag("sensor_id", reading.sensor_id) \
                    .tag("source", reading.source) \
                    .field("value", reading.value) \
                    .field("quality", reading.quality) \
                    .time(reading.timestamp)
                
                write_api = self.influxdb_client.write_api(write_options=SYNCHRONOUS)
                write_api.write(
                    bucket=self.config['influxdb']['bucket'],
                    record=point
                )
                
            except Exception as e:
                logger.error(f"Erreur stockage InfluxDB: {e}")
    
    def add_equipment_sync(self, equipment_id: str, sensor_ids: List[str]):
        """Ajoute un équipement à synchroniser."""
        self.sync_states[equipment_id] = SynchronizationState(
            equipment_id=equipment_id,
            last_sync=datetime.now()
        )
        
        logger.info(f"Équipement {equipment_id} ajouté à la synchronisation")
    
    async def synchronize_equipment(self, equipment_id: str, 
                                   digital_twin_engine) -> bool:
        """Synchronise un équipement avec son jumeau numérique."""
        try:
            if equipment_id not in self.sync_states:
                logger.warning(f"Équipement {equipment_id} non configuré pour sync")
                return False
            
            sync_state = self.sync_states[equipment_id]
            sync_start = time.time()
            
            # 1. Collecte des données fusionnées récentes
            fused_readings = {}
            current_time = datetime.now()
            
            # Compensation de latence
            compensation_ms = self.latency_compensator.get_compensation_time()
            compensated_time = current_time - timedelta(milliseconds=compensation_ms)
            
            # Récupération des données fusionnées pour tous les capteurs
            for sensor_id in self._get_equipment_sensors(equipment_id):
                fused_reading = self.data_fusion.get_fused_value(sensor_id, compensated_time)
                if fused_reading:
                    fused_readings[sensor_id] = fused_reading
            
            if not fused_readings:
                logger.warning(f"Aucune donnée pour synchroniser {equipment_id}")
                return False
            
            # 2. Mise à jour du jumeau numérique
            # Construction des conditions opérationnelles
            from digital_twin_simulation_engine import OperatingConditions
            
            conditions = OperatingConditions()
            
            # Mapping des capteurs vers les conditions
            sensor_mapping = {
                'temperature': 'temperature',
                'pressure': 'pressure', 
                'voltage': 'electrical_voltage',
                'current': 'electrical_current',
                'speed': 'rotational_speed',
                'vibration': 'vibration_amplitude'
            }
            
            for sensor_id, reading in fused_readings.items():
                # Extraction du type de capteur depuis l'ID
                sensor_type = self._extract_sensor_type(sensor_id)
                
                if sensor_type in sensor_mapping:
                    condition_attr = sensor_mapping[sensor_type]
                    setattr(conditions, condition_attr, reading.value)
            
            # Mise à jour du jumeau numérique
            success = digital_twin_engine.update_equipment_conditions(equipment_id, conditions)
            
            if success:
                # 3. Mise à jour de l'état de synchronisation
                sync_time = (time.time() - sync_start) * 1000  # ms
                
                sync_state.last_sync = datetime.now()
                sync_state.latency_avg = self.latency_compensator.get_statistics().get('avg_latency', 0)
                
                # Calcul de la qualité de synchronisation
                data_quality = np.mean([r.quality for r in fused_readings.values()])
                sync_state.sync_quality = data_quality * (1.0 - min(sync_time / 1000, 0.5))
                
                # Mise à jour des métriques globales
                self.metrics['successful_syncs'] += 1
                self.metrics['average_sync_time'] = (
                    self.metrics['average_sync_time'] * 0.9 + sync_time * 0.1
                )
                
                # 4. Détection d'anomalies
                for sensor_id in fused_readings.keys():
                    anomalies = self.data_fusion.detect_anomalies(sensor_id)
                    if anomalies:
                        logger.warning(f"Anomalies détectées sur {sensor_id}: {len(anomalies)}")
                        # Notification des anomalies (WebSocket, MQTT, etc.)
                        await self._notify_anomalies(equipment_id, sensor_id, anomalies)
                
                return True
            else:
                self.metrics['failed_syncs'] += 1
                return False
                
        except Exception as e:
            logger.error(f"Erreur synchronisation {equipment_id}: {e}")
            self.metrics['failed_syncs'] += 1
            return False
    
    def _get_equipment_sensors(self, equipment_id: str) -> List[str]:
        """Retourne la liste des capteurs d'un équipement."""
        # Configuration ou découverte automatique
        # Pour la démo, on utilise des capteurs standards
        return [
            f"{equipment_id}_temperature",
            f"{equipment_id}_pressure", 
            f"{equipment_id}_voltage",
            f"{equipment_id}_current",
            f"{equipment_id}_speed",
            f"{equipment_id}_vibration"
        ]
    
    def _extract_sensor_type(self, sensor_id: str) -> str:
        """Extrait le type de capteur depuis son ID."""
        # Extraction basique - peut être améliorée
        if 'temperature' in sensor_id.lower():
            return 'temperature'
        elif 'pressure' in sensor_id.lower():
            return 'pressure'
        elif 'voltage' in sensor_id.lower():
            return 'voltage'
        elif 'current' in sensor_id.lower():
            return 'current'
        elif 'speed' in sensor_id.lower() or 'rpm' in sensor_id.lower():
            return 'speed'
        elif 'vibration' in sensor_id.lower():
            return 'vibration'
        else:
            return 'unknown'
    
    async def _notify_anomalies(self, equipment_id: str, sensor_id: str, 
                               anomalies: List[Dict[str, Any]]):
        """Notifie les anomalies détectées."""
        notification = {
            'type': 'anomaly_detected',
            'equipment_id': equipment_id,
            'sensor_id': sensor_id,
            'anomalies': anomalies,
            'timestamp': datetime.now().isoformat()
        }
        
        # Notification via MQTT
        if self.mqtt_client:
            topic = f"iot/alerts/{equipment_id}"
            self.mqtt_client.publish(topic, json.dumps(notification))
        
        # Notification via WebSocket actives
        ws_message = json.dumps(notification)
        for connection_id, conn_info in self.active_connections.items():
            try:
                await conn_info['websocket'].send(ws_message)
            except Exception as e:
                logger.error(f"Erreur notification WebSocket {connection_id}: {e}")
    
    def start_real_time_sync(self, digital_twin_engine):
        """Démarre la synchronisation temps réel."""
        if self.running:
            logger.warning("Synchronisation déjà en cours")
            return
        
        self.running = True
        
        async def sync_loop():
            while self.running:
                try:
                    # Synchronisation de tous les équipements
                    sync_tasks = []
                    for equipment_id in self.sync_states.keys():
                        task = self.synchronize_equipment(equipment_id, digital_twin_engine)
                        sync_tasks.append(task)
                    
                    if sync_tasks:
                        results = await asyncio.gather(*sync_tasks, return_exceptions=True)
                        successful = sum(1 for r in results if r is True)
                        logger.debug(f"Sync batch: {successful}/{len(results)} succès")
                    
                    # Intervalle de synchronisation
                    interval_ms = self.config['sync']['sync_interval_ms']
                    await asyncio.sleep(interval_ms / 1000.0)
                    
                except Exception as e:
                    logger.error(f"Erreur dans la boucle de sync: {e}")
                    await asyncio.sleep(1.0)
        
        # Lancement de la tâche asynchrone
        asyncio.create_task(sync_loop())
        logger.info("Synchronisation temps réel démarrée")
    
    def stop_real_time_sync(self):
        """Arrête la synchronisation temps réel."""
        self.running = False
        logger.info("Synchronisation temps réel arrêtée")
    
    def get_sync_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques de synchronisation."""
        latency_stats = self.latency_compensator.get_statistics()
        
        stats = {
            **self.metrics,
            'latency_compensation': latency_stats,
            'active_equipment': len(self.sync_states),
            'active_connections': len(self.active_connections),
            'running': self.running
        }
        
        # Statistiques par équipement
        equipment_stats = {}
        for equipment_id, sync_state in self.sync_states.items():
            equipment_stats[equipment_id] = {
                'sync_quality': sync_state.sync_quality,
                'last_sync': sync_state.last_sync.isoformat(),
                'latency_avg': sync_state.latency_avg,
                'data_loss_rate': sync_state.data_loss_rate
            }
        
        stats['equipment_stats'] = equipment_stats
        
        # Statistiques de fusion de données
        fusion_stats = {}
        for sensor_id in self.data_fusion.sensor_data.keys():
            fusion_stats[sensor_id] = self.data_fusion.get_fusion_statistics(sensor_id)
        
        stats['data_fusion_stats'] = fusion_stats
        
        return stats
    
    async def cleanup(self):
        """Nettoie les ressources."""
        self.stop_real_time_sync()
        
        # Fermeture des connexions
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        
        if self.redis_client:
            self.redis_client.close()
        
        if self.influxdb_client:
            self.influxdb_client.close()
        
        logger.info("Ressources de synchronisation libérées")

# Fonction de test et démonstration
async def main():
    """Démonstration du système de synchronisation."""
    
    # Initialisation du système
    sync_system = RealTimeSyncSystem()
    
    try:
        print("=== Initialisation du Système de Synchronisation ===")
        await sync_system.initialize_connections()
        
        # Ajout d'équipements pour test
        equipment_list = ['PUMP_001', 'MOTOR_001', 'HEAT_EXCHANGER_001']
        
        for equipment_id in equipment_list:
            sync_system.add_equipment_sync(equipment_id, [])
            print(f"Équipement {equipment_id} ajouté ✓")
        
        # Simulation de données de capteurs
        print("\n=== Simulation de Données de Capteurs ===")
        
        for i in range(20):
            # Génération de données simulées
            for equipment_id in equipment_list:
                sensors = sync_system._get_equipment_sensors(equipment_id)
                
                for sensor_id in sensors[:3]:  # Premiers 3 capteurs seulement
                    # Lecture physique simulée
                    physical_reading = SensorReading(
                        sensor_id=sensor_id,
                        timestamp=datetime.now(),
                        value=np.random.normal(50, 5),  # Valeur normale
                        unit="°C" if "temperature" in sensor_id else "bar",
                        quality=np.random.uniform(0.8, 1.0),
                        source="physical"
                    )
                    
                    # Lecture virtuelle simulée (avec petit offset)
                    virtual_reading = SensorReading(
                        sensor_id=sensor_id,
                        timestamp=datetime.now(),
                        value=physical_reading.value + np.random.normal(0, 1),
                        unit=physical_reading.unit,
                        quality=1.0,
                        source="virtual",
                        confidence=np.random.uniform(0.7, 0.9)
                    )
                    
                    # Ajout aux données de fusion
                    sync_system.data_fusion.add_physical_reading(physical_reading)
                    sync_system.data_fusion.add_virtual_reading(virtual_reading)
                    
                    # Simulation de latence
                    latency = np.random.normal(100, 20)  # 100ms ± 20ms
                    sync_system.latency_compensator.add_latency_measurement(latency, datetime.now())
            
            # Affichage périodique
            if i % 5 == 0:
                print(f"Cycle {i+1}/20: Données générées pour {len(equipment_list)} équipements")
                
                # Test de fusion pour un capteur
                test_sensor = f"{equipment_list[0]}_temperature"
                fused_reading = sync_system.data_fusion.get_fused_value(test_sensor, datetime.now())
                
                if fused_reading:
                    print(f"  Fusion {test_sensor}: {fused_reading.value:.2f} (qualité: {fused_reading.quality:.2f})")
            
            await asyncio.sleep(0.5)  # 500ms entre les cycles
        
        print("\n=== Analyse des Statistiques ===")
        stats = sync_system.get_sync_statistics()
        
        print(f"Messages total: {stats['total_messages']}")
        print(f"Équipements actifs: {stats['active_equipment']}")
        
        # Statistiques de latence
        if 'latency_compensation' in stats and stats['latency_compensation']:
            latency_stats = stats['latency_compensation']
            print(f"Latence moyenne: {latency_stats.get('avg_latency', 0):.1f}ms")
            print(f"Latence min/max: {latency_stats.get('min_latency', 0):.1f}/{latency_stats.get('max_latency', 0):.1f}ms")
        
        # Statistiques de fusion
        if 'data_fusion_stats' in stats:
            fusion_count = len(stats['data_fusion_stats'])
            print(f"Capteurs avec fusion: {fusion_count}")
            
            # Exemple d'une statistique de fusion
            if fusion_count > 0:
                first_sensor = list(stats['data_fusion_stats'].keys())[0]
                sensor_stats = stats['data_fusion_stats'][first_sensor]
                print(f"  Exemple {first_sensor}: {sensor_stats['physical_samples']} phys., {sensor_stats['virtual_samples']} virt.")
        
        print("\n=== Test de Détection d'Anomalies ===")
        
        # Injection d'une anomalie
        anomaly_sensor = f"{equipment_list[0]}_temperature"
        
        # Valeur aberrante physique
        anomaly_reading = SensorReading(
            sensor_id=anomaly_sensor,
            timestamp=datetime.now(),
            value=150.0,  # Température anormalement élevée
            unit="°C",
            quality=1.0,
            source="physical"
        )
        
        sync_system.data_fusion.add_physical_reading(anomaly_reading)
        
        # Détection d'anomalies
        anomalies = sync_system.data_fusion.detect_anomalies(anomaly_sensor)
        
        if anomalies:
            print(f"Anomalies détectées sur {anomaly_sensor}:")
            for anomaly in anomalies:
                print(f"  - Type: {anomaly['type']}, Sévérité: {anomaly['severity']}")
        else:
            print("Aucune anomalie détectée (données insuffisantes)")
        
        print("\n=== Compensation de Latence ===")
        compensation_time = sync_system.latency_compensator.get_compensation_time()
        print(f"Temps de compensation estimé: {compensation_time:.1f}ms")
        
        estimated_latency = sync_system.latency_compensator.estimate_current_latency()
        print(f"Latence estimée actuelle: {estimated_latency:.1f}ms")
        
    except Exception as e:
        print(f"Erreur durant la démonstration: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Nettoyage
        print("\n=== Nettoyage ===")
        await sync_system.cleanup()
        print("Démonstration terminée ✓")

if __name__ == "__main__":
    asyncio.run(main())