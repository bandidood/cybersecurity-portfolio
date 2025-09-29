#!/usr/bin/env python3
"""
Industrial IoT Cloud Infrastructure
Infrastructure cloud complète pour la plateforme IoT industrielle avec auto-scaling
"""

import asyncio
import json
import time
import logging
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
import uuid
import aiohttp
import aioboto3
from azure.iot.hub import IoTHubRegistryManager
from azure.iot.hub.models import Device, DeviceStatus
from azure.storage.blob.aio import BlobServiceClient
from azure.cosmos.aio import CosmosClient
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import redis.asyncio as redis
import motor.motor_asyncio
from prometheus_client import start_http_server, Counter, Histogram, Gauge
import boto3
from botocore.exceptions import ClientError
import kafka
from kafka import KafkaProducer, KafkaConsumer
import pymongo
from elasticsearch import AsyncElasticsearch

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CloudConfig:
    """Configuration de l'infrastructure cloud"""
    provider: str  # azure, aws, gcp, hybrid
    region: str
    environment: str  # dev, staging, prod
    project_id: str
    resource_group: str
    scaling_enabled: bool = True
    monitoring_enabled: bool = True
    backup_enabled: bool = True

@dataclass
class IoTDevice:
    """Représentation d'un device IoT"""
    device_id: str
    device_name: str
    device_type: str
    location: str
    status: str
    last_activity: datetime
    metadata: Dict[str, Any]
    twin_properties: Dict[str, Any]

@dataclass
class ScalingMetrics:
    """Métriques pour l'auto-scaling"""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_throughput: float
    request_count: int
    response_time: float
    error_rate: float
    queue_depth: int

@dataclass
class CloudResource:
    """Ressource cloud générique"""
    resource_id: str
    resource_type: str
    provider: str
    region: str
    status: str
    configuration: Dict[str, Any]
    created_at: datetime
    last_updated: datetime

class PrometheusMetrics:
    """Métriques Prometheus pour monitoring"""
    
    def __init__(self):
        # Compteurs
        self.messages_processed = Counter('iot_messages_processed_total', 
                                        'Total processed IoT messages', ['device_type', 'status'])
        self.api_requests = Counter('api_requests_total', 
                                  'Total API requests', ['method', 'endpoint', 'status'])
        self.errors = Counter('errors_total', 
                            'Total errors', ['component', 'error_type'])
        
        # Histogrammes
        self.processing_duration = Histogram('processing_duration_seconds', 
                                           'Processing duration in seconds', ['operation'])
        self.response_time = Histogram('http_response_time_seconds', 
                                     'HTTP response time', ['endpoint'])
        
        # Gauges
        self.active_devices = Gauge('active_devices', 'Number of active devices')
        self.queue_size = Gauge('queue_size', 'Size of processing queue', ['queue_name'])
        self.resource_usage = Gauge('resource_usage_ratio', 
                                  'Resource usage ratio', ['resource_type', 'component'])

class IoTHubManager:
    """Gestionnaire IoT Hub Azure/AWS"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.devices: Dict[str, IoTDevice] = {}
        self.connection_string = os.getenv('IOT_HUB_CONNECTION_STRING')
        
        # Clients cloud
        self.azure_registry = None
        self.aws_iot_client = None
        
        self._initialize_clients()
        
    def _initialize_clients(self):
        """Initialise les clients des fournisseurs cloud"""
        try:
            if self.config.provider == 'azure':
                if self.connection_string:
                    self.azure_registry = IoTHubRegistryManager(self.connection_string)
                    logger.info("Azure IoT Hub client initialisé")
            
            elif self.config.provider == 'aws':
                session = boto3.Session()
                self.aws_iot_client = session.client('iot', region_name=self.config.region)
                logger.info("AWS IoT Core client initialisé")
                
        except Exception as e:
            logger.warning(f"Clients cloud non initialisés: {e}")
    
    async def register_device(self, device_id: str, device_config: Dict[str, Any]) -> bool:
        """Enregistre un nouveau device IoT"""
        try:
            device = IoTDevice(
                device_id=device_id,
                device_name=device_config.get('name', device_id),
                device_type=device_config.get('type', 'sensor'),
                location=device_config.get('location', 'unknown'),
                status='offline',
                last_activity=datetime.now(),
                metadata=device_config.get('metadata', {}),
                twin_properties=device_config.get('twin_properties', {})
            )
            
            # Enregistrement selon le provider
            if self.config.provider == 'azure' and self.azure_registry:
                azure_device = Device(device_id=device_id, status=DeviceStatus.enabled)
                await self.azure_registry.create_device_identity(azure_device)
            
            elif self.config.provider == 'aws' and self.aws_iot_client:
                thing_attributes = {
                    'deviceType': device.device_type,
                    'location': device.location
                }
                self.aws_iot_client.create_thing(
                    thingName=device_id,
                    attributePayload={'attributes': thing_attributes}
                )
            
            self.devices[device_id] = device
            logger.info(f"Device {device_id} enregistré avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur enregistrement device {device_id}: {e}")
            return False
    
    async def update_device_status(self, device_id: str, status: str, 
                                 telemetry_data: Optional[Dict] = None):
        """Met à jour le statut d'un device"""
        if device_id in self.devices:
            device = self.devices[device_id]
            device.status = status
            device.last_activity = datetime.now()
            
            if telemetry_data:
                device.metadata.update(telemetry_data)
    
    async def get_devices_by_status(self, status: str) -> List[IoTDevice]:
        """Récupère les devices par statut"""
        return [device for device in self.devices.values() if device.status == status]
    
    async def get_inactive_devices(self, threshold_minutes: int = 30) -> List[IoTDevice]:
        """Récupère les devices inactifs"""
        threshold = datetime.now() - timedelta(minutes=threshold_minutes)
        return [device for device in self.devices.values() 
                if device.last_activity < threshold]
    
    def get_device_count_by_type(self) -> Dict[str, int]:
        """Statistiques devices par type"""
        stats = {}
        for device in self.devices.values():
            stats[device.device_type] = stats.get(device.device_type, 0) + 1
        return stats

class TimeSeriesDB:
    """Gestionnaire base de données time-series (InfluxDB)"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.client = None
        self.write_api = None
        self.query_api = None
        
        # Configuration InfluxDB
        self.url = os.getenv('INFLUXDB_URL', 'http://localhost:8086')
        self.token = os.getenv('INFLUXDB_TOKEN', '')
        self.org = os.getenv('INFLUXDB_ORG', 'industrial')
        self.bucket = f"iot-{config.environment}"
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialise le client InfluxDB"""
        try:
            self.client = influxdb_client.InfluxDBClient(
                url=self.url,
                token=self.token,
                org=self.org
            )
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            self.query_api = self.client.query_api()
            logger.info("Client InfluxDB initialisé")
            
        except Exception as e:
            logger.error(f"Erreur initialisation InfluxDB: {e}")
    
    async def write_sensor_data(self, sensor_data: List[Dict[str, Any]]) -> bool:
        """Écrit des données de capteurs"""
        try:
            points = []
            for data in sensor_data:
                point = influxdb_client.Point("sensor_reading") \
                    .tag("device_id", data['device_id']) \
                    .tag("sensor_type", data['sensor_type']) \
                    .tag("location", data.get('location', '')) \
                    .field("value", float(data['value'])) \
                    .field("quality", float(data.get('quality', 1.0))) \
                    .field("anomaly_score", float(data.get('anomaly_score', 0.0))) \
                    .time(data['timestamp'])
                
                points.append(point)
            
            if points:
                self.write_api.write(bucket=self.bucket, record=points)
                return True
                
        except Exception as e:
            logger.error(f"Erreur écriture InfluxDB: {e}")
            return False
    
    async def query_sensor_data(self, device_id: str, start_time: str, 
                              end_time: str) -> List[Dict[str, Any]]:
        """Requête données capteur"""
        try:
            query = f'''
            from(bucket: "{self.bucket}")
              |> range(start: {start_time}, stop: {end_time})
              |> filter(fn: (r) => r["_measurement"] == "sensor_reading")
              |> filter(fn: (r) => r["device_id"] == "{device_id}")
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            '''
            
            result = self.query_api.query(query)
            data = []
            
            for table in result:
                for record in table.records:
                    data.append({
                        'timestamp': record.get_time(),
                        'device_id': record.values.get('device_id'),
                        'sensor_type': record.values.get('sensor_type'),
                        'value': record.values.get('value'),
                        'quality': record.values.get('quality'),
                        'anomaly_score': record.values.get('anomaly_score')
                    })
            
            return data
            
        except Exception as e:
            logger.error(f"Erreur requête InfluxDB: {e}")
            return []
    
    async def get_aggregated_data(self, measurement: str, aggregation: str, 
                                window: str, filters: Dict[str, str]) -> pd.DataFrame:
        """Récupère des données agrégées"""
        try:
            filter_clauses = []
            for key, value in filters.items():
                filter_clauses.append(f'|> filter(fn: (r) => r["{key}"] == "{value}")')
            
            query = f'''
            from(bucket: "{self.bucket}")
              |> range(start: -24h)
              |> filter(fn: (r) => r["_measurement"] == "{measurement}")
              {''.join(filter_clauses)}
              |> aggregateWindow(every: {window}, fn: {aggregation}, createEmpty: false)
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            '''
            
            result = self.query_api.query_data_frame(query)
            return result
            
        except Exception as e:
            logger.error(f"Erreur agrégation InfluxDB: {e}")
            return pd.DataFrame()

class MLPipeline:
    """Pipeline ML pour l'IA prédictive"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.models: Dict[str, Any] = {}
        self.model_versions: Dict[str, str] = {}
        self.prediction_cache = {}
        
        # Configuration GPU/TPU
        self.compute_type = os.getenv('ML_COMPUTE_TYPE', 'cpu')
        self.auto_scaling = config.scaling_enabled
        
    async def load_model(self, model_name: str, model_path: str) -> bool:
        """Charge un modèle ML"""
        try:
            # Simulation du chargement de modèle
            # En production: TensorFlow, PyTorch, scikit-learn, etc.
            
            model_info = {
                'name': model_name,
                'path': model_path,
                'loaded_at': datetime.now(),
                'version': f"v{hash(model_path) % 1000}",
                'type': 'simulation',
                'accuracy': np.random.uniform(0.85, 0.98),
                'latency_ms': np.random.uniform(50, 150)
            }
            
            self.models[model_name] = model_info
            self.model_versions[model_name] = model_info['version']
            
            logger.info(f"Modèle {model_name} chargé: {model_info['version']}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur chargement modèle {model_name}: {e}")
            return False
    
    async def predict(self, model_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute une prédiction"""
        if model_name not in self.models:
            raise ValueError(f"Modèle {model_name} non trouvé")
        
        try:
            # Simulation prédiction ML
            model = self.models[model_name]
            
            # Cache check
            cache_key = f"{model_name}_{hash(str(input_data))}"
            if cache_key in self.prediction_cache:
                cached_result = self.prediction_cache[cache_key]
                if (datetime.now() - cached_result['timestamp']).seconds < 300:
                    return cached_result['result']
            
            # Simulation latence
            await asyncio.sleep(model['latency_ms'] / 1000)
            
            # Prédiction simulée
            if 'anomaly' in model_name.lower():
                prediction = {
                    'anomaly_score': np.random.beta(2, 8),  # Score d'anomalie
                    'is_anomaly': np.random.random() < 0.1,
                    'confidence': np.random.uniform(0.7, 0.95)
                }
            elif 'maintenance' in model_name.lower():
                prediction = {
                    'maintenance_needed': np.random.random() < 0.2,
                    'days_until_failure': int(np.random.exponential(30)),
                    'failure_probability': np.random.beta(3, 20),
                    'recommended_action': ['inspect', 'lubricate', 'replace'][np.random.randint(3)]
                }
            else:
                prediction = {
                    'value': np.random.uniform(0, 100),
                    'confidence': np.random.uniform(0.6, 0.9)
                }
            
            # Métadonnées
            result = {
                'prediction': prediction,
                'model_name': model_name,
                'model_version': self.model_versions[model_name],
                'timestamp': datetime.now().isoformat(),
                'processing_time_ms': model['latency_ms'],
                'input_features': list(input_data.keys())
            }
            
            # Mise en cache
            self.prediction_cache[cache_key] = {
                'result': result,
                'timestamp': datetime.now()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur prédiction {model_name}: {e}")
            raise
    
    async def batch_predict(self, model_name: str, 
                          batch_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prédictions par batch pour optimiser performance"""
        try:
            tasks = [self.predict(model_name, data) for data in batch_data]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Traitement des résultats
            valid_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Erreur prédiction batch {i}: {result}")
                else:
                    valid_results.append(result)
            
            return valid_results
            
        except Exception as e:
            logger.error(f"Erreur batch prédiction: {e}")
            return []
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Statistiques des modèles"""
        return {
            'loaded_models': len(self.models),
            'model_info': {name: {
                'version': info['version'],
                'accuracy': info['accuracy'],
                'latency_ms': info['latency_ms'],
                'loaded_at': info['loaded_at'].isoformat()
            } for name, info in self.models.items()},
            'cache_size': len(self.prediction_cache),
            'compute_type': self.compute_type
        }

class APIGateway:
    """API Gateway avec rate limiting et authentification"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.rate_limits: Dict[str, Dict] = {}
        self.api_keys: Dict[str, Dict] = {}
        self.request_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited_requests': 0
        }
        
        # Configuration rate limiting
        self.default_rate_limit = 1000  # req/min par défaut
        self.burst_limit = 100  # requêtes en burst
        
    def register_api_key(self, key_id: str, permissions: List[str], 
                        rate_limit: Optional[int] = None) -> str:
        """Enregistre une nouvelle clé API"""
        api_key = f"ak_{uuid.uuid4().hex[:16]}"
        
        self.api_keys[api_key] = {
            'key_id': key_id,
            'permissions': permissions,
            'rate_limit': rate_limit or self.default_rate_limit,
            'created_at': datetime.now(),
            'last_used': None,
            'usage_count': 0
        }
        
        return api_key
    
    async def authenticate_request(self, api_key: str) -> Tuple[bool, Dict[str, Any]]:
        """Authentifie une requête"""
        if api_key not in self.api_keys:
            return False, {'error': 'Invalid API key'}
        
        key_info = self.api_keys[api_key]
        key_info['last_used'] = datetime.now()
        key_info['usage_count'] += 1
        
        return True, key_info
    
    async def check_rate_limit(self, api_key: str, endpoint: str) -> Tuple[bool, Dict[str, Any]]:
        """Vérifie les limites de taux"""
        if api_key not in self.api_keys:
            return False, {'error': 'Invalid API key'}
        
        key_info = self.api_keys[api_key]
        rate_limit = key_info['rate_limit']
        
        # Initialisation rate limiting pour cette clé+endpoint
        limit_key = f"{api_key}:{endpoint}"
        now = datetime.now()
        
        if limit_key not in self.rate_limits:
            self.rate_limits[limit_key] = {
                'requests': [],
                'window_start': now
            }
        
        rate_info = self.rate_limits[limit_key]
        
        # Nettoyage fenêtre glissante (1 minute)
        cutoff_time = now - timedelta(minutes=1)
        rate_info['requests'] = [req_time for req_time in rate_info['requests'] 
                               if req_time > cutoff_time]
        
        # Vérification limite
        if len(rate_info['requests']) >= rate_limit:
            self.request_stats['rate_limited_requests'] += 1
            return False, {
                'error': 'Rate limit exceeded',
                'limit': rate_limit,
                'window': '1 minute',
                'retry_after': 60
            }
        
        # Enregistrement requête
        rate_info['requests'].append(now)
        return True, {'requests_remaining': rate_limit - len(rate_info['requests'])}
    
    async def process_request(self, method: str, endpoint: str, api_key: str, 
                            data: Dict[str, Any]) -> Dict[str, Any]:
        """Traite une requête API"""
        start_time = time.time()
        self.request_stats['total_requests'] += 1
        
        try:
            # Authentification
            auth_valid, auth_info = await self.authenticate_request(api_key)
            if not auth_valid:
                self.request_stats['failed_requests'] += 1
                return {'error': auth_info['error'], 'status_code': 401}
            
            # Rate limiting
            rate_ok, rate_info = await self.check_rate_limit(api_key, endpoint)
            if not rate_ok:
                return {'error': rate_info['error'], 'status_code': 429}
            
            # Traitement de la requête (simulation)
            await asyncio.sleep(0.01)  # Simulation latence
            
            response = {
                'status': 'success',
                'data': {'processed': True, 'timestamp': datetime.now().isoformat()},
                'metadata': {
                    'api_version': 'v1.0',
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'rate_limit_info': rate_info
                }
            }
            
            self.request_stats['successful_requests'] += 1
            return response
            
        except Exception as e:
            self.request_stats['failed_requests'] += 1
            logger.error(f"Erreur traitement requête: {e}")
            return {'error': str(e), 'status_code': 500}
    
    def get_api_stats(self) -> Dict[str, Any]:
        """Statistiques API"""
        total = self.request_stats['total_requests']
        success_rate = (self.request_stats['successful_requests'] / max(1, total)) * 100
        
        return {
            'request_stats': self.request_stats,
            'success_rate_pct': success_rate,
            'registered_keys': len(self.api_keys),
            'active_rate_limits': len(self.rate_limits)
        }

class AutoScaler:
    """Auto-scaling intelligent des ressources cloud"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.scaling_enabled = config.scaling_enabled
        self.current_capacity = {
            'compute_nodes': 2,
            'storage_gb': 1000,
            'network_bandwidth': 100,
            'ml_instances': 1
        }
        
        self.target_metrics = {
            'cpu_threshold': 70.0,
            'memory_threshold': 80.0,
            'response_time_threshold': 200.0,
            'queue_depth_threshold': 1000
        }
        
        self.scaling_history = []
    
    async def evaluate_scaling(self, metrics: ScalingMetrics) -> Dict[str, Any]:
        """Évalue si un scaling est nécessaire"""
        if not self.scaling_enabled:
            return {'action': 'none', 'reason': 'scaling disabled'}
        
        scaling_decisions = []
        
        # Évaluation CPU
        if metrics.cpu_usage > self.target_metrics['cpu_threshold']:
            scaling_decisions.append({
                'resource': 'compute',
                'action': 'scale_up',
                'reason': f"CPU usage {metrics.cpu_usage}% > {self.target_metrics['cpu_threshold']}%",
                'severity': 'medium' if metrics.cpu_usage < 85 else 'high'
            })
        elif metrics.cpu_usage < 30 and self.current_capacity['compute_nodes'] > 1:
            scaling_decisions.append({
                'resource': 'compute',
                'action': 'scale_down',
                'reason': f"CPU usage {metrics.cpu_usage}% < 30%",
                'severity': 'low'
            })
        
        # Évaluation mémoire
        if metrics.memory_usage > self.target_metrics['memory_threshold']:
            scaling_decisions.append({
                'resource': 'memory',
                'action': 'scale_up',
                'reason': f"Memory usage {metrics.memory_usage}% > {self.target_metrics['memory_threshold']}%",
                'severity': 'high' if metrics.memory_usage > 90 else 'medium'
            })
        
        # Évaluation temps de réponse
        if metrics.response_time > self.target_metrics['response_time_threshold']:
            scaling_decisions.append({
                'resource': 'compute',
                'action': 'scale_up',
                'reason': f"Response time {metrics.response_time}ms > {self.target_metrics['response_time_threshold']}ms",
                'severity': 'medium'
            })
        
        # Évaluation queue
        if metrics.queue_depth > self.target_metrics['queue_depth_threshold']:
            scaling_decisions.append({
                'resource': 'processing',
                'action': 'scale_up',
                'reason': f"Queue depth {metrics.queue_depth} > {self.target_metrics['queue_depth_threshold']}",
                'severity': 'high'
            })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'current_metrics': asdict(metrics),
            'scaling_decisions': scaling_decisions,
            'current_capacity': self.current_capacity,
            'action_required': len(scaling_decisions) > 0
        }
    
    async def execute_scaling(self, scaling_decision: Dict[str, Any]) -> bool:
        """Exécute une action de scaling"""
        try:
            resource = scaling_decision['resource']
            action = scaling_decision['action']
            
            # Simulation des actions de scaling
            if resource == 'compute' and action == 'scale_up':
                new_capacity = min(self.current_capacity['compute_nodes'] + 1, 10)
                self.current_capacity['compute_nodes'] = new_capacity
                logger.info(f"Scaled up compute to {new_capacity} nodes")
                
            elif resource == 'compute' and action == 'scale_down':
                new_capacity = max(self.current_capacity['compute_nodes'] - 1, 1)
                self.current_capacity['compute_nodes'] = new_capacity
                logger.info(f"Scaled down compute to {new_capacity} nodes")
            
            # Enregistrement historique
            self.scaling_history.append({
                'timestamp': datetime.now(),
                'decision': scaling_decision,
                'previous_capacity': self.current_capacity.copy(),
                'success': True
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur scaling: {e}")
            return False
    
    def get_scaling_stats(self) -> Dict[str, Any]:
        """Statistiques de scaling"""
        recent_actions = [h for h in self.scaling_history 
                         if (datetime.now() - h['timestamp']).hours < 24]
        
        return {
            'current_capacity': self.current_capacity,
            'target_metrics': self.target_metrics,
            'scaling_enabled': self.scaling_enabled,
            'recent_actions': len(recent_actions),
            'total_scaling_events': len(self.scaling_history)
        }

class CloudInfrastructureManager:
    """Gestionnaire principal de l'infrastructure cloud"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        
        # Composants principaux
        self.iot_hub = IoTHubManager(self.config)
        self.timeseries_db = TimeSeriesDB(self.config)
        self.ml_pipeline = MLPipeline(self.config)
        self.api_gateway = APIGateway(self.config)
        self.auto_scaler = AutoScaler(self.config)
        
        # Monitoring
        self.metrics = PrometheusMetrics()
        self.monitoring_enabled = self.config.monitoring_enabled
        
        # État du système
        self.running = False
        self.system_stats = {
            'uptime_start': datetime.now(),
            'total_messages_processed': 0,
            'total_api_requests': 0,
            'system_health_score': 100.0
        }
        
        # Initialisation
        self._setup_default_models()
        self._setup_api_keys()
    
    def _load_config(self, config_file: str) -> CloudConfig:
        """Charge la configuration"""
        default_config = {
            'provider': 'azure',
            'region': 'westeurope',
            'environment': 'production',
            'project_id': 'industrial-iot-platform',
            'resource_group': 'rg-industrial-iot-prod',
            'scaling_enabled': True,
            'monitoring_enabled': True,
            'backup_enabled': True
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return CloudConfig(**default_config)
    
    def _setup_default_models(self):
        """Configure les modèles ML par défaut"""
        asyncio.create_task(self.ml_pipeline.load_model('anomaly_detector', 'models/anomaly_v1.pkl'))
        asyncio.create_task(self.ml_pipeline.load_model('predictive_maintenance', 'models/maintenance_v2.pkl'))
        asyncio.create_task(self.ml_pipeline.load_model('quality_predictor', 'models/quality_v1.pkl'))
    
    def _setup_api_keys(self):
        """Configure les clés API par défaut"""
        # Clé admin
        admin_key = self.api_gateway.register_api_key(
            'admin', ['read', 'write', 'admin'], rate_limit=5000
        )
        
        # Clé edge gateways
        edge_key = self.api_gateway.register_api_key(
            'edge_gateways', ['write', 'read'], rate_limit=2000
        )
        
        # Clé read-only pour dashboards
        readonly_key = self.api_gateway.register_api_key(
            'dashboards', ['read'], rate_limit=1000
        )
        
        logger.info(f"API keys configurées: admin={admin_key[:8]}...")
    
    async def start(self):
        """Démarre l'infrastructure cloud"""
        self.running = True
        
        logger.info("🚀 Démarrage Infrastructure Cloud IoT Industrielle")
        logger.info(f"Provider: {self.config.provider}")
        logger.info(f"Region: {self.config.region}")
        logger.info(f"Environment: {self.config.environment}")
        
        # Démarrer monitoring Prometheus
        if self.monitoring_enabled:
            start_http_server(9090)
            logger.info("Serveur Prometheus démarré sur :9090")
        
        # Tâches principales
        tasks = [
            asyncio.create_task(self._message_processor()),
            asyncio.create_task(self._health_monitor()),
            asyncio.create_task(self._auto_scaling_loop()),
            asyncio.create_task(self._metrics_collector()),
            asyncio.create_task(self._cleanup_tasks())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Arrêt de l'infrastructure par l'utilisateur")
        finally:
            self.running = False
    
    async def _message_processor(self):
        """Processeur principal de messages IoT"""
        while self.running:
            try:
                # Simulation traitement messages IoT
                batch_size = np.random.randint(50, 200)
                
                for _ in range(batch_size):
                    # Générer message IoT simulé
                    device_id = f"device_{np.random.randint(1, 1000):04d}"
                    message = {
                        'device_id': device_id,
                        'timestamp': datetime.now(),
                        'sensor_type': np.random.choice(['temperature', 'pressure', 'vibration']),
                        'value': np.random.uniform(0, 100),
                        'quality': np.random.uniform(0.8, 1.0),
                        'location': f'zone_{np.random.randint(1, 10)}'
                    }
                    
                    # Traitement du message
                    await self._process_iot_message(message)
                
                self.system_stats['total_messages_processed'] += batch_size
                await asyncio.sleep(1)  # 1 seconde entre batches
                
            except Exception as e:
                logger.error(f"Erreur dans message_processor: {e}")
    
    async def _process_iot_message(self, message: Dict[str, Any]):
        """Traite un message IoT individuel"""
        try:
            device_id = message['device_id']
            
            # Mise à jour statut device
            await self.iot_hub.update_device_status(
                device_id, 'active', message
            )
            
            # Stockage time-series
            await self.timeseries_db.write_sensor_data([message])
            
            # Analyse ML si besoin
            if np.random.random() < 0.1:  # 10% des messages
                prediction = await self.ml_pipeline.predict(
                    'anomaly_detector', message
                )
                
                if prediction['prediction'].get('is_anomaly', False):
                    logger.warning(f"Anomalie détectée: {device_id}")
            
            # Métriques
            self.metrics.messages_processed.labels(
                device_type=message.get('sensor_type', 'unknown'),
                status='success'
            ).inc()
            
        except Exception as e:
            logger.error(f"Erreur traitement message: {e}")
            self.metrics.errors.labels(
                component='message_processor',
                error_type=type(e).__name__
            ).inc()
    
    async def _health_monitor(self):
        """Monitoring de santé des composants"""
        while self.running:
            try:
                health_score = 100.0
                
                # Vérification composants
                components_status = {
                    'iot_hub': len(self.iot_hub.devices) > 0,
                    'timeseries_db': self.timeseries_db.client is not None,
                    'ml_pipeline': len(self.ml_pipeline.models) > 0,
                    'api_gateway': len(self.api_gateway.api_keys) > 0
                }
                
                for component, status in components_status.items():
                    if not status:
                        health_score -= 25.0
                        logger.warning(f"Composant {component} en défaut")
                
                self.system_stats['system_health_score'] = health_score
                
                # Métriques Prometheus
                self.metrics.active_devices.set(len(self.iot_hub.devices))
                
                await asyncio.sleep(30)  # Check toutes les 30 secondes
                
            except Exception as e:
                logger.error(f"Erreur health monitor: {e}")
    
    async def _auto_scaling_loop(self):
        """Boucle d'auto-scaling"""
        while self.running:
            try:
                # Collecte métriques pour scaling
                current_metrics = ScalingMetrics(
                    cpu_usage=np.random.uniform(40, 85),
                    memory_usage=np.random.uniform(50, 80),
                    disk_usage=np.random.uniform(30, 70),
                    network_throughput=np.random.uniform(10, 90),
                    request_count=self.system_stats['total_api_requests'],
                    response_time=np.random.uniform(50, 250),
                    error_rate=np.random.uniform(0, 5),
                    queue_depth=np.random.randint(0, 1500)
                )
                
                # Évaluation scaling
                scaling_eval = await self.auto_scaler.evaluate_scaling(current_metrics)
                
                if scaling_eval['action_required']:
                    for decision in scaling_eval['scaling_decisions']:
                        if decision['severity'] in ['medium', 'high']:
                            await self.auto_scaler.execute_scaling(decision)
                
                await asyncio.sleep(60)  # Évaluation toutes les minutes
                
            except Exception as e:
                logger.error(f"Erreur auto-scaling: {e}")
    
    async def _metrics_collector(self):
        """Collecteur de métriques personnalisées"""
        while self.running:
            try:
                # Collecte métriques business
                device_stats = self.iot_hub.get_device_count_by_type()
                api_stats = self.api_gateway.get_api_stats()
                ml_stats = self.ml_pipeline.get_model_stats()
                
                # Export métriques (simulation)
                metrics_data = {
                    'timestamp': datetime.now().isoformat(),
                    'system_stats': self.system_stats,
                    'device_stats': device_stats,
                    'api_stats': api_stats,
                    'ml_stats': ml_stats,
                    'scaling_stats': self.auto_scaler.get_scaling_stats()
                }
                
                # Sauvegarde périodique
                with open(f'cloud_metrics_{datetime.now().strftime("%Y%m%d_%H%M")}.json', 'w') as f:
                    json.dump(metrics_data, f, indent=2, default=str)
                
                await asyncio.sleep(300)  # Toutes les 5 minutes
                
            except Exception as e:
                logger.error(f"Erreur metrics collector: {e}")
    
    async def _cleanup_tasks(self):
        """Tâches de nettoyage périodique"""
        while self.running:
            try:
                # Nettoyage cache ML
                cache_size_before = len(self.ml_pipeline.prediction_cache)
                cutoff_time = datetime.now() - timedelta(hours=1)
                
                expired_keys = [
                    key for key, value in self.ml_pipeline.prediction_cache.items()
                    if value['timestamp'] < cutoff_time
                ]
                
                for key in expired_keys:
                    del self.ml_pipeline.prediction_cache[key]
                
                if expired_keys:
                    logger.info(f"Nettoyé {len(expired_keys)} entrées cache ML")
                
                # Nettoyage devices inactifs
                inactive_devices = await self.iot_hub.get_inactive_devices(threshold_minutes=60)
                for device in inactive_devices:
                    device.status = 'inactive'
                
                await asyncio.sleep(1800)  # Toutes les 30 minutes
                
            except Exception as e:
                logger.error(f"Erreur cleanup tasks: {e}")
    
    async def process_api_request(self, method: str, endpoint: str, 
                                api_key: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Traite une requête API externe"""
        self.system_stats['total_api_requests'] += 1
        
        return await self.api_gateway.process_request(method, endpoint, api_key, data)
    
    async def register_device(self, device_config: Dict[str, Any]) -> Dict[str, Any]:
        """Enregistre un nouveau device"""
        device_id = device_config.get('device_id') or f"device_{uuid.uuid4().hex[:8]}"
        
        success = await self.iot_hub.register_device(device_id, device_config)
        
        return {
            'success': success,
            'device_id': device_id,
            'message': 'Device registered successfully' if success else 'Registration failed'
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Statut complet du système"""
        uptime = datetime.now() - self.system_stats['uptime_start']
        
        return {
            'status': 'healthy' if self.system_stats['system_health_score'] > 80 else 'degraded',
            'uptime_seconds': uptime.total_seconds(),
            'system_stats': self.system_stats,
            'infrastructure': {
                'provider': self.config.provider,
                'region': self.config.region,
                'environment': self.config.environment,
                'scaling_enabled': self.config.scaling_enabled
            },
            'components': {
                'iot_hub': {
                    'devices_count': len(self.iot_hub.devices),
                    'device_types': self.iot_hub.get_device_count_by_type()
                },
                'ml_pipeline': self.ml_pipeline.get_model_stats(),
                'api_gateway': self.api_gateway.get_api_stats(),
                'auto_scaler': self.auto_scaler.get_scaling_stats()
            }
        }

async def main():
    """Point d'entrée principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Industrial IoT Cloud Infrastructure")
    parser.add_argument('--config', help='Fichier de configuration')
    parser.add_argument('--duration', type=int, default=600, help='Durée test (secondes)')
    
    args = parser.parse_args()
    
    # Créer et démarrer l'infrastructure
    infrastructure = CloudInfrastructureManager(args.config)
    
    try:
        # Démarrer avec timeout pour les tests
        await asyncio.wait_for(infrastructure.start(), timeout=args.duration)
    except asyncio.TimeoutError:
        logger.info(f"Test terminé après {args.duration} secondes")
    except KeyboardInterrupt:
        logger.info("Arrêt par l'utilisateur")
    finally:
        # Statistiques finales
        status = infrastructure.get_system_status()
        print("\n" + "="*60)
        print("☁️  STATISTIQUES FINALES CLOUD INFRASTRUCTURE")
        print("="*60)
        print(f"🏗️  Provider: {status['infrastructure']['provider']}")
        print(f"📍 Region: {status['infrastructure']['region']}")
        print(f"⏱️  Uptime: {status['uptime_seconds']:.1f}s")
        print(f"📊 Messages traités: {status['system_stats']['total_messages_processed']:,}")
        print(f"🔌 Devices actifs: {status['components']['iot_hub']['devices_count']}")
        print(f"🧠 Modèles ML: {status['components']['ml_pipeline']['loaded_models']}")
        print(f"🔑 Requêtes API: {status['system_stats']['total_api_requests']:,}")
        print(f"💚 Santé système: {status['system_stats']['system_health_score']:.1f}%")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())