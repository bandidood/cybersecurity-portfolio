#!/usr/bin/env python3
"""
Industrial IoT Data Generator
Générateur de données IoT industrielles réalistes pour la simulation
"""

import numpy as np
import pandas as pd
import json
import time
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import threading
import uuid
import redis
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import random
import math

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SensorConfig:
    """Configuration d'un capteur industriel"""
    sensor_id: str
    sensor_type: str
    location: str
    unit: str
    min_value: float
    max_value: float
    normal_range: Tuple[float, float]
    sampling_rate: int  # Hz
    noise_level: float
    drift_rate: float  # par heure
    failure_probability: float  # par jour
    maintenance_cycle: int  # jours

@dataclass
class SensorReading:
    """Lecture d'un capteur"""
    timestamp: datetime
    sensor_id: str
    sensor_type: str
    location: str
    value: float
    unit: str
    quality: float  # 0-1
    anomaly_score: float  # 0-1
    maintenance_due: bool
    raw_value: float
    processed_value: float

class IndustrialEnvironment:
    """Simulation d'environnement industriel complet"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.sensors: Dict[str, SensorConfig] = {}
        self.current_state: Dict[str, Any] = {}
        self.historical_data: List[SensorReading] = []
        self.anomalies: List[Dict[str, Any]] = []
        
        # Patterns temporels
        self.shift_patterns = {
            'morning': (6, 14),    # 6h-14h
            'afternoon': (14, 22), # 14h-22h  
            'night': (22, 6)       # 22h-6h
        }
        
        # Profils de production
        self.production_profiles = {
            'weekday': {'base_load': 0.8, 'peak_hours': [9, 14, 20]},
            'weekend': {'base_load': 0.3, 'peak_hours': [10, 15]},
            'maintenance': {'base_load': 0.1, 'peak_hours': []}
        }
        
        self._setup_sensors()
        self._initialize_state()
    
    def _setup_sensors(self):
        """Configure les capteurs selon l'environnement industriel"""
        
        # Capteurs de température (fours, moteurs, ambiante)
        temp_sensors = [
            SensorConfig(
                sensor_id=f"TEMP_FURNACE_{i:02d}",
                sensor_type="temperature",
                location=f"Furnace_{i}",
                unit="°C",
                min_value=20.0,
                max_value=1200.0,
                normal_range=(800.0, 950.0),
                sampling_rate=1,  # 1Hz
                noise_level=2.5,
                drift_rate=0.5,
                failure_probability=0.01,
                maintenance_cycle=30
            ) for i in range(1, 6)
        ]
        
        # Capteurs de vibration (moteurs, compresseurs)
        vibration_sensors = [
            SensorConfig(
                sensor_id=f"VIB_MOTOR_{i:02d}",
                sensor_type="vibration",
                location=f"Motor_{i}",
                unit="mm/s",
                min_value=0.0,
                max_value=50.0,
                normal_range=(0.5, 8.0),
                sampling_rate=10,  # 10Hz
                noise_level=0.1,
                drift_rate=0.02,
                failure_probability=0.005,
                maintenance_cycle=90
            ) for i in range(1, 11)
        ]
        
        # Capteurs de pression (circuits hydrauliques, pneumatiques)
        pressure_sensors = [
            SensorConfig(
                sensor_id=f"PRESS_HYD_{i:02d}",
                sensor_type="pressure",
                location=f"Hydraulic_Circuit_{i}",
                unit="bar",
                min_value=0.0,
                max_value=200.0,
                normal_range=(45.0, 55.0),
                sampling_rate=5,  # 5Hz
                noise_level=0.5,
                drift_rate=0.1,
                failure_probability=0.008,
                maintenance_cycle=60
            ) for i in range(1, 8)
        ]
        
        # Capteurs de qualité (défauts, contamination)
        quality_sensors = [
            SensorConfig(
                sensor_id=f"QUAL_INSPECT_{i:02d}",
                sensor_type="quality",
                location=f"Inspection_Station_{i}",
                unit="%",
                min_value=0.0,
                max_value=100.0,
                normal_range=(95.0, 99.5),
                sampling_rate=0.1,  # 1 mesure toutes les 10s
                noise_level=1.0,
                drift_rate=0.05,
                failure_probability=0.003,
                maintenance_cycle=15
            ) for i in range(1, 5)
        ]
        
        # Capteurs de débit (fluides, matières premières)
        flow_sensors = [
            SensorConfig(
                sensor_id=f"FLOW_PIPE_{i:02d}",
                sensor_type="flow",
                location=f"Pipeline_{i}",
                unit="L/min",
                min_value=0.0,
                max_value=1000.0,
                normal_range=(100.0, 800.0),
                sampling_rate=2,  # 2Hz
                noise_level=5.0,
                drift_rate=0.3,
                failure_probability=0.006,
                maintenance_cycle=45
            ) for i in range(1, 6)
        ]
        
        # Regrouper tous les capteurs
        all_sensors = (temp_sensors + vibration_sensors + 
                      pressure_sensors + quality_sensors + flow_sensors)
        
        for sensor in all_sensors:
            self.sensors[sensor.sensor_id] = sensor
        
        logger.info(f"Configuré {len(self.sensors)} capteurs industriels")
    
    def _initialize_state(self):
        """Initialise l'état des capteurs"""
        for sensor_id, sensor in self.sensors.items():
            self.current_state[sensor_id] = {
                'value': np.random.uniform(*sensor.normal_range),
                'last_maintenance': datetime.now() - timedelta(days=np.random.randint(0, sensor.maintenance_cycle)),
                'cumulative_drift': 0.0,
                'failure_countdown': np.random.exponential(1.0 / sensor.failure_probability),
                'calibration_offset': np.random.normal(0, sensor.noise_level * 0.1),
                'health_score': 1.0
            }
    
    def _get_time_factors(self, timestamp: datetime) -> Dict[str, float]:
        """Calcule les facteurs temporels affectant la production"""
        
        # Facteur jour de la semaine
        weekday_factor = 1.0 if timestamp.weekday() < 5 else 0.4
        
        # Facteur heure de la journée
        hour = timestamp.hour
        if 6 <= hour < 14:  # Équipe du matin
            hour_factor = 1.0
        elif 14 <= hour < 22:  # Équipe d'après-midi
            hour_factor = 0.9
        else:  # Équipe de nuit
            hour_factor = 0.6
        
        # Facteur saisonnier (simulation)
        day_of_year = timestamp.timetuple().tm_yday
        seasonal_factor = 0.9 + 0.2 * math.sin(2 * math.pi * day_of_year / 365)
        
        # Facteur de charge production
        base_profile = self.production_profiles['weekday' if weekday_factor > 0.8 else 'weekend']
        load_factor = base_profile['base_load']
        
        # Pics de production
        if hour in base_profile['peak_hours']:
            load_factor *= 1.3
        
        return {
            'weekday_factor': weekday_factor,
            'hour_factor': hour_factor,
            'seasonal_factor': seasonal_factor,
            'load_factor': load_factor,
            'combined_factor': weekday_factor * hour_factor * seasonal_factor * load_factor
        }
    
    def _simulate_sensor_value(self, sensor: SensorConfig, timestamp: datetime) -> Tuple[float, Dict[str, Any]]:
        """Simule la valeur d'un capteur avec tous les facteurs réalistes"""
        
        current_state = self.current_state[sensor.sensor_id]
        time_factors = self._get_time_factors(timestamp)
        
        # Valeur de base selon le type de capteur
        base_value = current_state['value']
        
        # Influence des facteurs temporels selon le type de capteur
        if sensor.sensor_type == "temperature":
            # Température influence par charge production et cycles thermiques
            thermal_cycle = 10 * math.sin(2 * math.pi * timestamp.hour / 24)
            load_influence = (time_factors['load_factor'] - 0.5) * 100
            base_value += thermal_cycle + load_influence
            
        elif sensor.sensor_type == "vibration":
            # Vibration corrélée à la charge et à l'usure
            health_influence = (1.0 - current_state['health_score']) * 5
            load_influence = time_factors['load_factor'] * 2
            base_value += health_influence + load_influence
            
        elif sensor.sensor_type == "pressure":
            # Pression liée à la demande système
            demand_influence = time_factors['load_factor'] * 10
            base_value += demand_influence
            
        elif sensor.sensor_type == "quality":
            # Qualité dégradée par fatigue opérateurs et maintenance
            hours_since_maintenance = (timestamp - current_state['last_maintenance']).total_seconds() / 3600
            maintenance_factor = max(0, 1.0 - hours_since_maintenance / (sensor.maintenance_cycle * 24))
            fatigue_factor = 1.0 - (timestamp.hour - 6) / 20 if 6 <= timestamp.hour <= 22 else 0.9
            base_value *= maintenance_factor * fatigue_factor * time_factors['combined_factor']
            
        elif sensor.sensor_type == "flow":
            # Débit proportionnel à la charge de production
            base_value *= time_factors['load_factor']
        
        # Ajout du bruit de mesure
        noise = np.random.normal(0, sensor.noise_level)
        
        # Dérive progressive du capteur
        time_since_calibration = (timestamp - current_state['last_maintenance']).total_seconds() / 3600
        drift = sensor.drift_rate * time_since_calibration + current_state['calibration_offset']
        
        # Valeur finale
        final_value = base_value + noise + drift
        
        # Contraindre dans les limites physiques
        final_value = max(sensor.min_value, min(sensor.max_value, final_value))
        
        # Calcul de la qualité de mesure
        quality_score = current_state['health_score'] * (1.0 - abs(drift) / (sensor.max_value - sensor.min_value))
        quality_score = max(0.1, min(1.0, quality_score))
        
        # Détection d'anomalies
        normal_center = (sensor.normal_range[0] + sensor.normal_range[1]) / 2
        normal_width = sensor.normal_range[1] - sensor.normal_range[0]
        anomaly_score = abs(final_value - normal_center) / (normal_width / 2)
        anomaly_score = min(1.0, max(0.0, anomaly_score - 0.5) * 2)  # 0 si dans la normale, 1 si très anormal
        
        # Mise à jour de l'état
        self.current_state[sensor.sensor_id]['value'] = final_value
        self.current_state[sensor.sensor_id]['health_score'] *= 0.99999  # Dégradation lente
        
        # Vérification maintenance
        maintenance_due = (timestamp - current_state['last_maintenance']).days >= sensor.maintenance_cycle
        
        metadata = {
            'time_factors': time_factors,
            'drift': drift,
            'noise': noise,
            'quality_score': quality_score,
            'anomaly_score': anomaly_score,
            'maintenance_due': maintenance_due,
            'health_score': current_state['health_score']
        }
        
        return final_value, metadata
    
    def generate_reading(self, sensor_id: str, timestamp: datetime) -> SensorReading:
        """Génère une lecture pour un capteur spécifique"""
        
        if sensor_id not in self.sensors:
            raise ValueError(f"Capteur {sensor_id} non trouvé")
        
        sensor = self.sensors[sensor_id]
        value, metadata = self._simulate_sensor_value(sensor, timestamp)
        
        reading = SensorReading(
            timestamp=timestamp,
            sensor_id=sensor_id,
            sensor_type=sensor.sensor_type,
            location=sensor.location,
            value=value,
            unit=sensor.unit,
            quality=metadata['quality_score'],
            anomaly_score=metadata['anomaly_score'],
            maintenance_due=metadata['maintenance_due'],
            raw_value=value - metadata['noise'],
            processed_value=value
        )
        
        return reading
    
    def generate_batch_readings(self, start_time: datetime, duration_hours: int, 
                              target_points_per_hour: int = 10000) -> List[SensorReading]:
        """Génère un lot de lectures pour la période spécifiée"""
        
        readings = []
        current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        # Calcul des intervalles d'échantillonnage par capteur
        total_sensors = len(self.sensors)
        points_per_sensor_per_hour = target_points_per_hour // total_sensors
        
        logger.info(f"Génération de {target_points_per_hour} points/heure pour {total_sensors} capteurs")
        logger.info(f"Soit {points_per_sensor_per_hour} points/heure/capteur")
        
        while current_time < end_time:
            for sensor_id, sensor in self.sensors.items():
                # Respecter la fréquence d'échantillonnage du capteur
                if sensor.sampling_rate == 0:
                    continue
                
                # Calculer si ce capteur doit générer une mesure maintenant
                interval_seconds = 3600 // points_per_sensor_per_hour
                if int(current_time.timestamp()) % interval_seconds == 0:
                    reading = self.generate_reading(sensor_id, current_time)
                    readings.append(reading)
            
            current_time += timedelta(seconds=1)
            
            # Progress log
            if len(readings) % 10000 == 0:
                logger.info(f"Généré {len(readings)} lectures...")
        
        logger.info(f"Génération terminée: {len(readings)} lectures totales")
        return readings

class DataExporter:
    """Export des données vers différents formats et systèmes"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.redis_client = None
        self.mqtt_client = None
        self.influxdb_client = None
        
        self._setup_connections()
    
    def _setup_connections(self):
        """Configure les connexions aux systèmes externes"""
        
        # Redis pour cache temps réel
        if self.config.get('redis', {}).get('enabled', False):
            try:
                self.redis_client = redis.Redis(
                    host=self.config['redis']['host'],
                    port=self.config['redis']['port'],
                    decode_responses=True
                )
                logger.info("Connexion Redis établie")
            except Exception as e:
                logger.warning(f"Impossible de connecter à Redis: {e}")
        
        # MQTT pour streaming temps réel
        if self.config.get('mqtt', {}).get('enabled', False):
            try:
                self.mqtt_client = mqtt.Client()
                self.mqtt_client.connect(
                    self.config['mqtt']['broker'],
                    self.config['mqtt']['port'],
                    60
                )
                logger.info("Connexion MQTT établie")
            except Exception as e:
                logger.warning(f"Impossible de connecter à MQTT: {e}")
        
        # InfluxDB pour stockage time-series
        if self.config.get('influxdb', {}).get('enabled', False):
            try:
                self.influxdb_client = InfluxDBClient(
                    url=self.config['influxdb']['url'],
                    token=self.config['influxdb']['token'],
                    org=self.config['influxdb']['org']
                )
                logger.info("Connexion InfluxDB établie")
            except Exception as e:
                logger.warning(f"Impossible de connecter à InfluxDB: {e}")
    
    def export_to_csv(self, readings: List[SensorReading], filename: str):
        """Exporte vers CSV"""
        df = pd.DataFrame([{
            'timestamp': reading.timestamp.isoformat(),
            'sensor_id': reading.sensor_id,
            'sensor_type': reading.sensor_type,
            'location': reading.location,
            'value': reading.value,
            'unit': reading.unit,
            'quality': reading.quality,
            'anomaly_score': reading.anomaly_score,
            'maintenance_due': reading.maintenance_due
        } for reading in readings])
        
        df.to_csv(filename, index=False)
        logger.info(f"Exporté {len(readings)} lectures vers {filename}")
    
    def export_to_json(self, readings: List[SensorReading], filename: str):
        """Exporte vers JSON"""
        data = [{
            'timestamp': reading.timestamp.isoformat(),
            'sensor_id': reading.sensor_id,
            'sensor_type': reading.sensor_type,
            'location': reading.location,
            'value': reading.value,
            'unit': reading.unit,
            'quality': reading.quality,
            'anomaly_score': reading.anomaly_score,
            'maintenance_due': reading.maintenance_due,
            'raw_value': reading.raw_value,
            'processed_value': reading.processed_value
        } for reading in readings]
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exporté {len(readings)} lectures vers {filename}")
    
    def stream_to_mqtt(self, reading: SensorReading):
        """Stream une lecture vers MQTT"""
        if not self.mqtt_client:
            return
        
        topic = f"industrial/{reading.location}/{reading.sensor_type}/{reading.sensor_id}"
        payload = {
            'timestamp': reading.timestamp.isoformat(),
            'value': reading.value,
            'unit': reading.unit,
            'quality': reading.quality,
            'anomaly_score': reading.anomaly_score
        }
        
        self.mqtt_client.publish(topic, json.dumps(payload))
    
    def store_to_influxdb(self, readings: List[SensorReading]):
        """Stocke vers InfluxDB"""
        if not self.influxdb_client:
            return
        
        write_api = self.influxdb_client.write_api(write_options=SYNCHRONOUS)
        
        points = []
        for reading in readings:
            point = Point("sensor_reading") \
                .tag("sensor_id", reading.sensor_id) \
                .tag("sensor_type", reading.sensor_type) \
                .tag("location", reading.location) \
                .tag("unit", reading.unit) \
                .field("value", reading.value) \
                .field("quality", reading.quality) \
                .field("anomaly_score", reading.anomaly_score) \
                .field("maintenance_due", reading.maintenance_due) \
                .time(reading.timestamp)
            
            points.append(point)
        
        write_api.write(bucket=self.config['influxdb']['bucket'], record=points)
        logger.info(f"Stocké {len(readings)} lectures vers InfluxDB")

class IndustrialIoTSimulator:
    """Simulateur IoT industriel complet"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.environment = IndustrialEnvironment(self.config)
        self.exporter = DataExporter(self.config)
        self.running = False
        self.stats = {
            'total_readings': 0,
            'readings_per_second': 0,
            'anomalies_detected': 0,
            'maintenance_alerts': 0
        }
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Charge la configuration"""
        default_config = {
            'simulation': {
                'real_time': False,
                'speed_multiplier': 1.0,
                'target_points_per_hour': 100000,
                'export_batch_size': 10000
            },
            'export': {
                'formats': ['csv', 'json'],
                'directory': './data'
            },
            'redis': {
                'enabled': False,
                'host': 'localhost',
                'port': 6379
            },
            'mqtt': {
                'enabled': False,
                'broker': 'localhost',
                'port': 1883
            },
            'influxdb': {
                'enabled': False,
                'url': 'http://localhost:8086',
                'token': '',
                'org': 'industrial',
                'bucket': 'sensors'
            }
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                # Merge configurations
                default_config.update(user_config)
        
        return default_config
    
    async def start_simulation(self, duration_hours: int = 24):
        """Démarre la simulation"""
        self.running = True
        start_time = datetime.now()
        
        logger.info(f"Démarrage simulation industrielle - {duration_hours}h")
        logger.info(f"Capteurs configurés: {len(self.environment.sensors)}")
        
        try:
            # Simulation par batch si pas temps réel
            if not self.config['simulation']['real_time']:
                await self._run_batch_simulation(start_time, duration_hours)
            else:
                await self._run_realtime_simulation(duration_hours)
                
        except KeyboardInterrupt:
            logger.info("Arrêt de la simulation par l'utilisateur")
        finally:
            self.running = False
    
    async def _run_batch_simulation(self, start_time: datetime, duration_hours: int):
        """Simulation par lots (plus rapide)"""
        target_points = self.config['simulation']['target_points_per_hour']
        batch_size = self.config['simulation']['export_batch_size']
        
        # Génération par chunks pour éviter la surcharge mémoire
        current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        batch_readings = []
        
        while current_time < end_time and self.running:
            # Générer 1 heure de données
            hour_readings = self.environment.generate_batch_readings(
                current_time, 1, target_points
            )
            
            batch_readings.extend(hour_readings)
            self.stats['total_readings'] += len(hour_readings)
            
            # Compter anomalies et alertes maintenance
            for reading in hour_readings:
                if reading.anomaly_score > 0.7:
                    self.stats['anomalies_detected'] += 1
                if reading.maintenance_due:
                    self.stats['maintenance_alerts'] += 1
            
            # Export par batch
            if len(batch_readings) >= batch_size:
                await self._export_batch(batch_readings)
                batch_readings = []
            
            current_time += timedelta(hours=1)
            
            # Progress
            progress = (current_time - start_time).total_seconds() / (duration_hours * 3600) * 100
            logger.info(f"Progrès simulation: {progress:.1f}%")
        
        # Export final batch
        if batch_readings:
            await self._export_batch(batch_readings)
        
        logger.info("Simulation batch terminée")
        self._print_stats()
    
    async def _run_realtime_simulation(self, duration_hours: int):
        """Simulation temps réel"""
        logger.info("Mode temps réel activé")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(hours=duration_hours)
        
        while datetime.now() < end_time and self.running:
            current_time = datetime.now()
            
            # Générer lectures pour tous les capteurs
            readings = []
            for sensor_id in self.environment.sensors:
                reading = self.environment.generate_reading(sensor_id, current_time)
                readings.append(reading)
                
                # Stream temps réel si configuré
                if self.exporter.mqtt_client:
                    self.exporter.stream_to_mqtt(reading)
            
            # Mise à jour stats
            self.stats['total_readings'] += len(readings)
            self.stats['readings_per_second'] = len(readings)
            
            # Attendre avant prochaine itération
            await asyncio.sleep(1.0 / self.config['simulation']['speed_multiplier'])
        
        logger.info("Simulation temps réel terminée")
        self._print_stats()
    
    async def _export_batch(self, readings: List[SensorReading]):
        """Exporte un batch de lectures"""
        export_dir = Path(self.config['export']['directory'])
        export_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for format_type in self.config['export']['formats']:
            if format_type == 'csv':
                filename = export_dir / f"industrial_data_{timestamp}.csv"
                self.exporter.export_to_csv(readings, filename)
            elif format_type == 'json':
                filename = export_dir / f"industrial_data_{timestamp}.json"
                self.exporter.export_to_json(readings, filename)
        
        # Export vers InfluxDB si configuré
        if self.exporter.influxdb_client:
            self.exporter.store_to_influxdb(readings)
    
    def _print_stats(self):
        """Affiche les statistiques finales"""
        print("\n" + "="*60)
        print("📊 STATISTIQUES SIMULATION IoT INDUSTRIELLE")
        print("="*60)
        print(f"📈 Total lectures générées : {self.stats['total_readings']:,}")
        print(f"⚠️  Anomalies détectées     : {self.stats['anomalies_detected']:,}")
        print(f"🔧 Alertes maintenance     : {self.stats['maintenance_alerts']:,}")
        print(f"🏭 Capteurs simulés        : {len(self.environment.sensors)}")
        
        # Répartition par type de capteur
        print(f"\n🔍 Répartition capteurs :")
        sensor_types = {}
        for sensor in self.environment.sensors.values():
            sensor_types[sensor.sensor_type] = sensor_types.get(sensor.sensor_type, 0) + 1
        
        for sensor_type, count in sensor_types.items():
            print(f"   {sensor_type:15s} : {count:2d} capteurs")
        
        # Métriques de performance
        if self.stats['total_readings'] > 0:
            anomaly_rate = (self.stats['anomalies_detected'] / self.stats['total_readings']) * 100
            maintenance_rate = (self.stats['maintenance_alerts'] / self.stats['total_readings']) * 100
            
            print(f"\n📋 Métriques qualité :")
            print(f"   Taux anomalies          : {anomaly_rate:.2f}%")
            print(f"   Taux alertes maintenance: {maintenance_rate:.2f}%")
        
        print("="*60)

def main():
    """Point d'entrée principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Simulateur IoT Industriel")
    parser.add_argument('--config', help='Fichier de configuration JSON')
    parser.add_argument('--duration', type=int, default=24, help='Durée simulation (heures)')
    parser.add_argument('--realtime', action='store_true', help='Mode temps réel')
    parser.add_argument('--points-per-hour', type=int, default=100000, help='Points par heure')
    
    args = parser.parse_args()
    
    # Configuration dynamique
    config = {
        'simulation': {
            'real_time': args.realtime,
            'target_points_per_hour': args.points_per_hour,
            'export_batch_size': 10000
        },
        'export': {
            'formats': ['csv', 'json'],
            'directory': './data'
        }
    }
    
    if args.config:
        config_file = args.config
    else:
        # Sauvegarder config par défaut
        config_file = 'industrial_config.json'
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Configuration par défaut créée: {config_file}")
    
    # Lancer simulation
    simulator = IndustrialIoTSimulator(config_file)
    
    try:
        asyncio.run(simulator.start_simulation(args.duration))
    except KeyboardInterrupt:
        print("\nSimulation interrompue par l'utilisateur")

if __name__ == "__main__":
    main()