#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 6: Framework de Sécurité IoT Industriel Avancé

Système de sécurité complet pour l'écosystème IoT industriel incluant :
- Détection d'anomalies comportementales en temps réel
- Analyse des menaces spécialisées IoT/OT
- Protection des communications industrielles
- Gestion des identités et accès (IAM) pour équipements
- Surveillance de l'intégrité des données
- Réponse automatique aux incidents

Auteur: Spécialiste Sécurité IoT Industriel
Date: 2024
"""

import os
import json
import asyncio
import logging
import time
import threading
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
import uuid
import base64
from collections import deque, defaultdict
import ipaddress
import socket
import ssl
import struct

# Cryptographie et sécurité
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_pem_x509_certificate
import jwt
import bcrypt

# Machine Learning pour détection d'anomalies
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
from sklearn.metrics import classification_report
import joblib

# Deep Learning pour analyse comportementale
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# Réseaux et protocoles industriels
import scapy
from scapy.all import *
import modbus_tk
from pymodbus.client.sync import ModbusTcpClient
import opcua
from opcua import Client as OPCUAClient
import paho.mqtt.client as mqtt

# Surveillance système
import psutil
import GPUtil
import wmi  # Windows Management Instrumentation

# Base de données et stockage sécurisé
import sqlite3
import redis
from pymongo import MongoClient
import sqlalchemy
from sqlalchemy import create_engine, text

# Configuration avancée
import yaml
import configparser
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Utilitaires
import warnings
warnings.filterwarnings('ignore')

# Configuration des logs sécurisés
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('iot_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Niveaux de menace sécurité."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class DeviceType(Enum):
    """Types d'équipements IoT industriels."""
    PLC = "PLC"
    HMI = "HMI"
    SENSOR = "SENSOR"
    ACTUATOR = "ACTUATOR"
    GATEWAY = "GATEWAY"
    CONTROLLER = "CONTROLLER"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    UNKNOWN = "UNKNOWN"

class ProtocolType(Enum):
    """Protocoles industriels supportés."""
    MODBUS_TCP = "MODBUS_TCP"
    MODBUS_RTU = "MODBUS_RTU"
    OPCUA = "OPCUA"
    MQTT = "MQTT"
    ETHERNET_IP = "ETHERNET_IP"
    PROFINET = "PROFINET"
    BACNET = "BACNET"
    DNSS = "DNP3"
    IEC61850 = "IEC61850"
    HTTP = "HTTP"
    HTTPS = "HTTPS"

class AttackVector(Enum):
    """Vecteurs d'attaque identifiés."""
    NETWORK_INTRUSION = auto()
    MALWARE_INJECTION = auto()
    MAN_IN_THE_MIDDLE = auto()
    DENIAL_OF_SERVICE = auto()
    CREDENTIAL_THEFT = auto()
    FIRMWARE_TAMPERING = auto()
    DATA_EXFILTRATION = auto()
    COMMAND_INJECTION = auto()
    REPLAY_ATTACK = auto()
    ROGUE_DEVICE = auto()

@dataclass
class SecurityAlert:
    """Alerte de sécurité."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    threat_level: ThreatLevel = ThreatLevel.LOW
    attack_vector: AttackVector = AttackVector.NETWORK_INTRUSION
    source_ip: str = ""
    target_device: str = ""
    protocol: ProtocolType = ProtocolType.HTTP
    description: str = ""
    payload: Optional[Dict[str, Any]] = None
    confidence_score: float = 0.0
    is_blocked: bool = False
    response_actions: List[str] = field(default_factory=list)
    
@dataclass
class DeviceProfile:
    """Profil de sécurité d'un équipement IoT."""
    device_id: str
    device_type: DeviceType
    ip_address: str
    mac_address: str
    manufacturer: str = ""
    firmware_version: str = ""
    supported_protocols: List[ProtocolType] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    security_score: float = 100.0
    behavioral_baseline: Dict[str, Any] = field(default_factory=dict)
    certificates: List[str] = field(default_factory=list)
    is_authorized: bool = True
    risk_factors: List[str] = field(default_factory=list)
    
@dataclass
class NetworkFlow:
    """Flux réseau pour analyse."""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    timestamp: datetime
    payload_hash: str = ""
    flags: List[str] = field(default_factory=list)
    is_encrypted: bool = False

class CryptographicManager:
    """Gestionnaire cryptographique pour communications sécurisées."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.certificates = {}
        self.private_keys = {}
        self.symmetric_keys = {}
        self.key_derivation_iterations = 100000
        
        # Génération des clés maîtres
        self._generate_master_keys()
        
    def _generate_master_keys(self):
        """Génère les clés cryptographiques maîtres."""
        # Clé privée RSA pour signatures
        self.master_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        self.master_public_key = self.master_private_key.public_key()
        
        # Clé symétrique maître pour AES
        self.master_symmetric_key = secrets.token_bytes(32)  # AES-256
        
        logger.info("Clés cryptographiques maîtres générées")
    
    def encrypt_data(self, data: bytes, recipient_public_key=None) -> bytes:
        """Chiffrement hybride RSA+AES des données."""
        # Génération clé AES temporaire
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        # Chiffrement données avec AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding PKCS7
        padded_data = self._pad_data(data)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Chiffrement clé AES avec RSA
        if recipient_public_key is None:
            recipient_public_key = self.master_public_key
            
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Structure: [taille_clé_chiffrée][clé_chiffrée][iv][données_chiffrées]
        result = struct.pack('<I', len(encrypted_key))
        result += encrypted_key
        result += iv
        result += ciphertext
        
        return result
    
    def decrypt_data(self, encrypted_data: bytes, private_key=None) -> bytes:
        """Déchiffrement hybride RSA+AES des données."""
        if private_key is None:
            private_key = self.master_private_key
        
        # Extraction des composants
        key_size = struct.unpack('<I', encrypted_data[:4])[0]
        encrypted_key = encrypted_data[4:4+key_size]
        iv = encrypted_data[4+key_size:4+key_size+16]
        ciphertext = encrypted_data[4+key_size+16:]
        
        # Déchiffrement clé AES
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Déchiffrement données
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Suppression du padding
        return self._unpad_data(padded_data)
    
    def sign_data(self, data: bytes, private_key=None) -> bytes:
        """Signature numérique des données."""
        if private_key is None:
            private_key = self.master_private_key
            
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key=None) -> bool:
        """Vérification de signature numérique."""
        if public_key is None:
            public_key = self.master_public_key
            
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def generate_device_certificate(self, device_id: str, device_type: DeviceType) -> Dict[str, str]:
        """Génère un certificat pour un équipement IoT."""
        # Génération clé privée équipement
        device_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        device_public_key = device_private_key.public_key()
        
        # Sérialisation des clés
        private_pem = device_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = device_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # JWT comme certificat simplifié
        payload = {
            'device_id': device_id,
            'device_type': device_type.value,
            'issued_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=365)).isoformat(),
            'issuer': 'StationTraffeyereIoTSecurityFramework'
        }
        
        certificate = jwt.encode(payload, private_pem, algorithm='RS256')
        
        # Stockage
        self.certificates[device_id] = certificate
        self.private_keys[device_id] = private_pem
        
        return {
            'certificate': certificate,
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode()
        }
    
    def validate_device_certificate(self, certificate: str, device_id: str) -> bool:
        """Valide un certificat d'équipement."""
        try:
            if device_id not in self.private_keys:
                return False
                
            payload = jwt.decode(
                certificate, 
                self.private_keys[device_id], 
                algorithms=['RS256']
            )
            
            # Vérifications
            if payload.get('device_id') != device_id:
                return False
                
            expires_at = datetime.fromisoformat(payload.get('expires_at', ''))
            if datetime.now() > expires_at:
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Erreur validation certificat {device_id}: {e}")
            return False
    
    def _pad_data(self, data: bytes) -> bytes:
        """Padding PKCS7."""
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length] * pad_length)
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Suppression padding PKCS7."""
        pad_length = padded_data[-1]
        return padded_data[:-pad_length]

class AnomalyDetectionEngine:
    """Moteur de détection d'anomalies comportementales."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models = {}
        self.scalers = {}
        self.baselines = {}
        self.anomaly_threshold = config.get('anomaly_threshold', 0.1)
        
        # Modèles de détection
        self.isolation_forest = IsolationForest(
            contamination=self.anomaly_threshold,
            random_state=42
        )
        
        self.autoencoder = None
        self.lstm_model = None
        
        # Historique des données
        self.traffic_history = deque(maxlen=10000)
        self.device_behavior = defaultdict(lambda: deque(maxlen=1000))
        
        logger.info("Moteur de détection d'anomalies initialisé")
    
    def build_autoencoder(self, input_dim: int) -> keras.Model:
        """Construit un autoencodeur pour détection d'anomalies."""
        encoder = keras.Sequential([
            layers.Dense(64, activation='relu', input_shape=(input_dim,)),
            layers.Dense(32, activation='relu'),
            layers.Dense(16, activation='relu'),
            layers.Dense(8, activation='relu')
        ])
        
        decoder = keras.Sequential([
            layers.Dense(16, activation='relu', input_shape=(8,)),
            layers.Dense(32, activation='relu'),
            layers.Dense(64, activation='relu'),
            layers.Dense(input_dim, activation='sigmoid')
        ])
        
        autoencoder = keras.Model(
            inputs=encoder.input,
            outputs=decoder(encoder(encoder.input))
        )
        
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder
    
    def build_lstm_model(self, sequence_length: int, features: int) -> keras.Model:
        """Construit un modèle LSTM pour séquences temporelles."""
        model = keras.Sequential([
            layers.LSTM(50, return_sequences=True, input_shape=(sequence_length, features)),
            layers.LSTM(50, return_sequences=False),
            layers.Dense(25),
            layers.Dense(features)
        ])
        
        model.compile(optimizer='adam', loss='mse')
        return model
    
    def extract_network_features(self, flow: NetworkFlow) -> np.ndarray:
        """Extraction de caractéristiques réseau."""
        features = [
            flow.packet_size,
            flow.source_port,
            flow.dest_port,
            hash(flow.protocol) % 1000,  # Hash du protocole
            len(flow.flags),
            int(flow.is_encrypted),
            flow.timestamp.hour,  # Heure de la journée
            flow.timestamp.weekday(),  # Jour de la semaine
        ]
        
        # Ajout caractéristiques IP
        try:
            src_ip = ipaddress.ip_address(flow.source_ip)
            dest_ip = ipaddress.ip_address(flow.dest_ip)
            
            features.extend([
                int(src_ip.is_private),
                int(dest_ip.is_private),
                int(src_ip) % 1000000,  # Partie de l'IP
                int(dest_ip) % 1000000
            ])
        except:
            features.extend([0, 0, 0, 0])
        
        return np.array(features, dtype=np.float32)
    
    def extract_device_features(self, device_profile: DeviceProfile, 
                               recent_activity: List[NetworkFlow]) -> np.ndarray:
        """Extraction de caractéristiques comportementales d'équipement."""
        features = []
        
        # Caractéristiques de base
        features.extend([
            len(device_profile.supported_protocols),
            device_profile.security_score,
            len(device_profile.risk_factors),
            int(device_profile.is_authorized),
            (datetime.now() - device_profile.last_seen).total_seconds() / 3600  # Heures depuis dernière activité
        ])
        
        # Analyse de l'activité récente
        if recent_activity:
            packet_sizes = [flow.packet_size for flow in recent_activity]
            features.extend([
                len(recent_activity),  # Nombre de paquets
                np.mean(packet_sizes),  # Taille moyenne
                np.std(packet_sizes),   # Variance taille
                len(set(flow.dest_ip for flow in recent_activity)),  # Nombre destinations uniques
                len(set(flow.dest_port for flow in recent_activity)),  # Nombre ports uniques
            ])
        else:
            features.extend([0, 0, 0, 0, 0])
        
        # Caractéristiques temporelles
        current_time = datetime.now()
        features.extend([
            current_time.hour,
            current_time.weekday(),
            current_time.minute / 60.0  # Fraction heure
        ])
        
        return np.array(features, dtype=np.float32)
    
    def train_network_anomaly_model(self, flows: List[NetworkFlow]):
        """Entraîne le modèle de détection d'anomalies réseau."""
        logger.info("Entraînement du modèle de détection d'anomalies réseau")
        
        # Extraction des caractéristiques
        features = np.array([self.extract_network_features(flow) for flow in flows])
        
        if len(features) == 0:
            logger.warning("Aucune donnée pour l'entraînement")
            return
        
        # Normalisation
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        self.scalers['network'] = scaler
        
        # Entraînement Isolation Forest
        self.isolation_forest.fit(features_scaled)
        
        # Construction et entraînement de l'autoencodeur
        if len(features[0]) > 0:
            self.autoencoder = self.build_autoencoder(len(features[0]))
            self.autoencoder.fit(
                features_scaled, features_scaled,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
        
        logger.info(f"Modèle entraîné sur {len(features)} échantillons")
    
    def detect_network_anomaly(self, flow: NetworkFlow) -> Tuple[bool, float]:
        """Détecte les anomalies dans le trafic réseau."""
        features = self.extract_network_features(flow).reshape(1, -1)
        
        if 'network' not in self.scalers:
            return False, 0.0
        
        features_scaled = self.scalers['network'].transform(features)
        
        # Score Isolation Forest
        isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
        is_anomaly_isolation = self.isolation_forest.predict(features_scaled)[0] == -1
        
        # Score autoencodeur si disponible
        autoencoder_score = 0.0
        if self.autoencoder is not None:
            reconstruction = self.autoencoder.predict(features_scaled, verbose=0)
            reconstruction_error = np.mean(np.square(features_scaled - reconstruction))
            autoencoder_score = reconstruction_error
        
        # Score composite
        composite_score = abs(isolation_score) + autoencoder_score
        is_anomaly = is_anomaly_isolation or autoencoder_score > 0.5
        
        # Ajout à l'historique
        self.traffic_history.append({
            'flow': flow,
            'features': features[0],
            'anomaly_score': composite_score,
            'is_anomaly': is_anomaly
        })
        
        return is_anomaly, composite_score
    
    def detect_device_anomaly(self, device_profile: DeviceProfile, 
                             recent_activity: List[NetworkFlow]) -> Tuple[bool, float]:
        """Détecte les anomalies comportementales d'équipement."""
        device_id = device_profile.device_id
        features = self.extract_device_features(device_profile, recent_activity)
        
        # Première analyse - établissement baseline
        if device_id not in self.baselines:
            self.baselines[device_id] = {
                'mean': features,
                'std': np.zeros_like(features),
                'samples': [features]
            }
            return False, 0.0
        
        baseline = self.baselines[device_id]
        
        # Calcul de l'écart par rapport à la baseline
        deviation = np.abs(features - baseline['mean'])
        std_threshold = np.maximum(baseline['std'], 0.1)  # Seuil minimum
        
        # Score d'anomalie basé sur l'écart normalisé
        anomaly_scores = deviation / std_threshold
        max_anomaly_score = np.max(anomaly_scores)
        
        is_anomaly = max_anomaly_score > 3.0  # 3 sigma
        
        # Mise à jour de la baseline (apprentissage adaptatif)
        if not is_anomaly:
            baseline['samples'].append(features)
            if len(baseline['samples']) > 100:  # Gardez seulement les 100 derniers échantillons
                baseline['samples'] = baseline['samples'][-100:]
            
            # Recalcul baseline
            samples_array = np.array(baseline['samples'])
            baseline['mean'] = np.mean(samples_array, axis=0)
            baseline['std'] = np.std(samples_array, axis=0)
        
        # Historique comportemental
        self.device_behavior[device_id].append({
            'timestamp': datetime.now(),
            'features': features,
            'anomaly_score': max_anomaly_score,
            'is_anomaly': is_anomaly
        })
        
        return is_anomaly, float(max_anomaly_score)
    
    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques de détection d'anomalies."""
        total_flows = len(self.traffic_history)
        anomalous_flows = sum(1 for entry in self.traffic_history if entry['is_anomaly'])
        
        device_stats = {}
        for device_id, history in self.device_behavior.items():
            total_checks = len(history)
            anomalies = sum(1 for entry in history if entry['is_anomaly'])
            device_stats[device_id] = {
                'total_checks': total_checks,
                'anomalies_detected': anomalies,
                'anomaly_rate': anomalies / max(total_checks, 1)
            }
        
        return {
            'network_traffic': {
                'total_flows': total_flows,
                'anomalous_flows': anomalous_flows,
                'anomaly_rate': anomalous_flows / max(total_flows, 1)
            },
            'device_behavior': device_stats,
            'models_trained': bool(self.scalers),
            'baseline_devices': len(self.baselines)
        }

class ThreatIntelligenceEngine:
    """Moteur d'intelligence des menaces spécialisé IoT/OT."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_signatures = {}
        self.attack_patterns = {}
        self.iot_vulnerabilities = {}
        self.threat_feeds = []
        
        # Chargement des bases de connaissances
        self._load_threat_intelligence()
        
    def _load_threat_intelligence(self):
        """Charge les bases de connaissances des menaces IoT."""
        # Signatures d'attaques spécifiques IoT/OT
        self.threat_signatures = {
            'modbus_function_tampering': {
                'pattern': r'.*modbus.*function.*(?:01|02|03|04|05|06|15|16).*',
                'description': 'Tentative de manipulation des fonctions Modbus',
                'threat_level': ThreatLevel.HIGH,
                'attack_vector': AttackVector.COMMAND_INJECTION
            },
            'opcua_authentication_bypass': {
                'pattern': r'.*opcua.*anonymous.*',
                'description': 'Tentative de connexion OPC UA anonyme',
                'threat_level': ThreatLevel.MEDIUM,
                'attack_vector': AttackVector.CREDENTIAL_THEFT
            },
            'mqtt_topic_injection': {
                'pattern': r'.*mqtt.*topic.*[\$#\+].*',
                'description': 'Injection dans les topics MQTT',
                'threat_level': ThreatLevel.MEDIUM,
                'attack_vector': AttackVector.COMMAND_INJECTION
            },
            'plc_memory_scan': {
                'pattern': r'.*(?:read|write).*(?:holding|input|coil|discrete).*',
                'description': 'Scan mémoire PLC suspect',
                'threat_level': ThreatLevel.HIGH,
                'attack_vector': AttackVector.DATA_EXFILTRATION
            },
            'firmware_download': {
                'pattern': r'.*(?:firmware|flash|upgrade|update).*download.*',
                'description': 'Tentative de téléchargement de firmware',
                'threat_level': ThreatLevel.CRITICAL,
                'attack_vector': AttackVector.FIRMWARE_TAMPERING
            }
        }
        
        # Patterns d'attaques comportementales
        self.attack_patterns = {
            'port_scanning': {
                'description': 'Scan de ports industriels',
                'indicators': {
                    'ports': [502, 44818, 1883, 47808, 2404],  # Modbus, OPCUA, MQTT, BACnet, IEC61850
                    'connection_rate': 10,  # connexions/seconde
                    'failed_connections': 0.8  # ratio échecs
                },
                'threat_level': ThreatLevel.MEDIUM
            },
            'credential_stuffing': {
                'description': 'Attaque par dictionnaire sur équipements',
                'indicators': {
                    'failed_auth_rate': 0.9,
                    'auth_attempts': 50,
                    'time_window': 300  # secondes
                },
                'threat_level': ThreatLevel.HIGH
            },
            'data_exfiltration': {
                'description': 'Exfiltration de données industrielles',
                'indicators': {
                    'data_volume': 1000000,  # bytes
                    'external_connections': 5,
                    'unusual_hours': True
                },
                'threat_level': ThreatLevel.CRITICAL
            }
        }
        
        # Vulnérabilités IoT communes
        self.iot_vulnerabilities = {
            'default_credentials': {
                'description': 'Utilisation de mots de passe par défaut',
                'cve_refs': ['CVE-2019-6707', 'CVE-2020-10987'],
                'affected_types': [DeviceType.PLC, DeviceType.HMI, DeviceType.GATEWAY],
                'severity': ThreatLevel.HIGH
            },
            'unencrypted_communications': {
                'description': 'Communications non chiffrées',
                'protocols': [ProtocolType.MODBUS_TCP, ProtocolType.HTTP],
                'severity': ThreatLevel.MEDIUM
            },
            'firmware_outdated': {
                'description': 'Firmware obsolète avec vulnérabilités connues',
                'severity': ThreatLevel.HIGH
            },
            'weak_authentication': {
                'description': 'Mécanismes d\'authentification faibles',
                'severity': ThreatLevel.MEDIUM
            }
        }
        
        logger.info("Base de connaissances des menaces chargée")
    
    def analyze_traffic_for_threats(self, flows: List[NetworkFlow]) -> List[SecurityAlert]:
        """Analyse le trafic réseau pour identifier les menaces."""
        alerts = []
        
        # Analyse des signatures
        for flow in flows:
            payload_str = f"{flow.source_ip}:{flow.source_port} -> {flow.dest_ip}:{flow.dest_port} ({flow.protocol})"
            
            for signature_name, signature in self.threat_signatures.items():
                if re.search(signature['pattern'], payload_str, re.IGNORECASE):
                    alert = SecurityAlert(
                        threat_level=signature['threat_level'],
                        attack_vector=signature['attack_vector'],
                        source_ip=flow.source_ip,
                        target_device=flow.dest_ip,
                        protocol=ProtocolType(flow.protocol) if flow.protocol in [p.value for p in ProtocolType] else ProtocolType.HTTP,
                        description=f"{signature['description']} - {signature_name}",
                        confidence_score=0.8
                    )
                    alerts.append(alert)
        
        # Analyse des patterns comportementaux
        behavioral_alerts = self._analyze_behavioral_patterns(flows)
        alerts.extend(behavioral_alerts)
        
        return alerts
    
    def _analyze_behavioral_patterns(self, flows: List[NetworkFlow]) -> List[SecurityAlert]:
        """Analyse les patterns comportementaux suspects."""
        alerts = []
        
        # Groupement par IP source
        source_activities = defaultdict(list)
        for flow in flows:
            source_activities[flow.source_ip].append(flow)
        
        # Analyse de chaque source
        for source_ip, source_flows in source_activities.items():
            # Détection de scan de ports
            unique_ports = set(flow.dest_port for flow in source_flows)
            industrial_ports = {502, 44818, 1883, 47808, 2404}
            scanned_industrial_ports = unique_ports.intersection(industrial_ports)
            
            if len(scanned_industrial_ports) >= 3:
                alert = SecurityAlert(
                    threat_level=ThreatLevel.HIGH,
                    attack_vector=AttackVector.NETWORK_INTRUSION,
                    source_ip=source_ip,
                    target_device="multiple",
                    description=f"Scan de ports industriels détecté: {scanned_industrial_ports}",
                    confidence_score=0.9
                )
                alerts.append(alert)
            
            # Détection de volume de données suspect
            total_data = sum(flow.packet_size for flow in source_flows)
            if total_data > 10000000:  # 10MB
                alert = SecurityAlert(
                    threat_level=ThreatLevel.MEDIUM,
                    attack_vector=AttackVector.DATA_EXFILTRATION,
                    source_ip=source_ip,
                    description=f"Volume de données anormal: {total_data:,} bytes",
                    confidence_score=0.7
                )
                alerts.append(alert)
        
        return alerts
    
    def assess_device_vulnerabilities(self, device_profile: DeviceProfile) -> List[str]:
        """Évalue les vulnérabilités d'un équipement."""
        vulnerabilities = []
        
        # Vérification des protocoles non sécurisés
        unsafe_protocols = {ProtocolType.MODBUS_TCP, ProtocolType.HTTP, ProtocolType.MQTT}
        for protocol in device_profile.supported_protocols:
            if protocol in unsafe_protocols:
                vulnerabilities.append(f"Protocole non sécurisé: {protocol.value}")
        
        # Vérification des certificats
        if not device_profile.certificates:
            vulnerabilities.append("Aucun certificat de sécurité configuré")
        
        # Vérification de l'âge de la dernière activité
        last_seen_hours = (datetime.now() - device_profile.last_seen).total_seconds() / 3600
        if last_seen_hours > 24:
            vulnerabilities.append("Équipement non vu depuis plus de 24h")
        
        # Vérification du score de sécurité
        if device_profile.security_score < 70:
            vulnerabilities.append(f"Score de sécurité faible: {device_profile.security_score}")
        
        # Mise à jour des facteurs de risque
        device_profile.risk_factors = vulnerabilities
        
        return vulnerabilities
    
    def generate_threat_report(self, alerts: List[SecurityAlert], 
                              time_window: timedelta = None) -> Dict[str, Any]:
        """Génère un rapport d'intelligence des menaces."""
        if time_window:
            cutoff_time = datetime.now() - time_window
            alerts = [alert for alert in alerts if alert.timestamp >= cutoff_time]
        
        # Statistiques par niveau de menace
        threat_stats = {level.name: 0 for level in ThreatLevel}
        for alert in alerts:
            threat_stats[alert.threat_level.name] += 1
        
        # Top des vecteurs d'attaque
        attack_vectors = defaultdict(int)
        for alert in alerts:
            attack_vectors[alert.attack_vector.name] += 1
        
        # Top des sources d'attaque
        source_ips = defaultdict(int)
        for alert in alerts:
            if alert.source_ip:
                source_ips[alert.source_ip] += 1
        
        # Top des cibles
        targets = defaultdict(int)
        for alert in alerts:
            if alert.target_device:
                targets[alert.target_device] += 1
        
        return {
            'report_generated': datetime.now().isoformat(),
            'time_window': str(time_window) if time_window else 'All time',
            'total_alerts': len(alerts),
            'threat_level_distribution': dict(threat_stats),
            'top_attack_vectors': dict(sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_source_ips': dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_targets': dict(sorted(targets.items(), key=lambda x: x[1], reverse=True)[:10]),
            'critical_alerts': len([a for a in alerts if a.threat_level == ThreatLevel.CRITICAL]),
            'high_alerts': len([a for a in alerts if a.threat_level == ThreatLevel.HIGH])
        }

class NetworkSecurityMonitor:
    """Moniteur de sécurité réseau pour protocoles industriels."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_monitoring = False
        self.captured_flows = deque(maxlen=100000)
        self.protocol_parsers = {}
        self.firewall_rules = []
        
        self._setup_protocol_parsers()
        self._load_firewall_rules()
        
    def _setup_protocol_parsers(self):
        """Configure les parseurs de protocoles industriels."""
        # Parseur Modbus TCP
        def parse_modbus(packet):
            if packet.haslayer(scapy.layers.tcp.TCP) and packet[scapy.layers.tcp.TCP].dport == 502:
                return {
                    'protocol': ProtocolType.MODBUS_TCP,
                    'function_code': None,  # Extraction simplifiée
                    'is_encrypted': False
                }
            return None
        
        # Parseur OPC UA
        def parse_opcua(packet):
            if packet.haslayer(scapy.layers.tcp.TCP) and packet[scapy.layers.tcp.TCP].dport == 4840:
                return {
                    'protocol': ProtocolType.OPCUA,
                    'is_encrypted': False  # Detection simplifiée
                }
            return None
        
        # Parseur MQTT
        def parse_mqtt(packet):
            if packet.haslayer(scapy.layers.tcp.TCP) and packet[scapy.layers.tcp.TCP].dport == 1883:
                return {
                    'protocol': ProtocolType.MQTT,
                    'is_encrypted': False
                }
            return None
        
        self.protocol_parsers = {
            ProtocolType.MODBUS_TCP: parse_modbus,
            ProtocolType.OPCUA: parse_opcua,
            ProtocolType.MQTT: parse_mqtt
        }
    
    def _load_firewall_rules(self):
        """Charge les règles de pare-feu industriel."""
        self.firewall_rules = [
            {
                'name': 'block_external_modbus',
                'action': 'BLOCK',
                'protocol': ProtocolType.MODBUS_TCP,
                'source_type': 'external',
                'enabled': True
            },
            {
                'name': 'allow_internal_opcua',
                'action': 'ALLOW',
                'protocol': ProtocolType.OPCUA,
                'source_type': 'internal',
                'enabled': True
            },
            {
                'name': 'block_unauthorized_devices',
                'action': 'BLOCK',
                'source_type': 'unauthorized',
                'enabled': True
            }
        ]
    
    def start_monitoring(self, interface: str = None):
        """Démarre la surveillance réseau."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        logger.info(f"Démarrage surveillance réseau sur interface: {interface or 'default'}")
        
        # Thread de capture de paquets
        def packet_capture():
            try:
                if interface:
                    scapy.all.sniff(iface=interface, prn=self._process_packet, stop_filter=lambda x: not self.is_monitoring)
                else:
                    scapy.all.sniff(prn=self._process_packet, stop_filter=lambda x: not self.is_monitoring)
            except Exception as e:
                logger.error(f"Erreur capture paquets: {e}")
        
        self.capture_thread = threading.Thread(target=packet_capture, daemon=True)
        self.capture_thread.start()
    
    def stop_monitoring(self):
        """Arrête la surveillance réseau."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        logger.info("Arrêt de la surveillance réseau")
    
    def _process_packet(self, packet):
        """Traite un paquet capturé."""
        try:
            # Extraction des informations de base
            if not packet.haslayer(scapy.layers.inet.IP):
                return
            
            ip_layer = packet[scapy.layers.inet.IP]
            
            # Informations de flux
            flow = NetworkFlow(
                source_ip=ip_layer.src,
                dest_ip=ip_layer.dst,
                source_port=0,
                dest_port=0,
                protocol="IP",
                packet_size=len(packet),
                timestamp=datetime.now(),
                payload_hash=hashlib.sha256(bytes(packet)).hexdigest()[:16]
            )
            
            # Analyse TCP/UDP
            if packet.haslayer(scapy.layers.tcp.TCP):
                tcp_layer = packet[scapy.layers.tcp.TCP]
                flow.source_port = tcp_layer.sport
                flow.dest_port = tcp_layer.dport
                flow.protocol = "TCP"
                flow.flags = self._extract_tcp_flags(tcp_layer)
            
            elif packet.haslayer(scapy.layers.udp.UDP):
                udp_layer = packet[scapy.layers.udp.UDP]
                flow.source_port = udp_layer.sport
                flow.dest_port = udp_layer.dport
                flow.protocol = "UDP"
            
            # Analyse des protocoles industriels
            for protocol_type, parser in self.protocol_parsers.items():
                protocol_info = parser(packet)
                if protocol_info:
                    flow.protocol = protocol_info['protocol'].value
                    flow.is_encrypted = protocol_info.get('is_encrypted', False)
                    break
            
            # Application des règles de pare-feu
            action = self._apply_firewall_rules(flow)
            if action == 'BLOCK':
                flow.flags.append('BLOCKED')
            
            # Stockage du flux
            self.captured_flows.append(flow)
            
        except Exception as e:
            logger.error(f"Erreur traitement paquet: {e}")
    
    def _extract_tcp_flags(self, tcp_layer) -> List[str]:
        """Extrait les flags TCP."""
        flags = []
        if tcp_layer.flags & 0x01: flags.append('FIN')
        if tcp_layer.flags & 0x02: flags.append('SYN')
        if tcp_layer.flags & 0x04: flags.append('RST')
        if tcp_layer.flags & 0x08: flags.append('PSH')
        if tcp_layer.flags & 0x10: flags.append('ACK')
        if tcp_layer.flags & 0x20: flags.append('URG')
        return flags
    
    def _apply_firewall_rules(self, flow: NetworkFlow) -> str:
        """Applique les règles de pare-feu."""
        try:
            src_ip = ipaddress.ip_address(flow.source_ip)
            is_internal = src_ip.is_private
        except:
            is_internal = False
        
        for rule in self.firewall_rules:
            if not rule['enabled']:
                continue
            
            # Vérification du protocole
            if 'protocol' in rule and flow.protocol != rule['protocol'].value:
                continue
            
            # Vérification du type de source
            if rule['source_type'] == 'external' and is_internal:
                continue
            if rule['source_type'] == 'internal' and not is_internal:
                continue
            
            return rule['action']
        
        return 'ALLOW'  # Par défaut
    
    def get_traffic_statistics(self, time_window: timedelta = None) -> Dict[str, Any]:
        """Retourne les statistiques de trafic."""
        flows = list(self.captured_flows)
        
        if time_window:
            cutoff_time = datetime.now() - time_window
            flows = [f for f in flows if f.timestamp >= cutoff_time]
        
        if not flows:
            return {'total_flows': 0}
        
        # Statistiques générales
        total_flows = len(flows)
        total_bytes = sum(f.packet_size for f in flows)
        
        # Répartition par protocole
        protocols = defaultdict(int)
        for flow in flows:
            protocols[flow.protocol] += 1
        
        # Top sources et destinations
        sources = defaultdict(int)
        destinations = defaultdict(int)
        for flow in flows:
            sources[flow.source_ip] += 1
            destinations[flow.dest_ip] += 1
        
        # Flux bloqués
        blocked_flows = len([f for f in flows if 'BLOCKED' in f.flags])
        
        return {
            'total_flows': total_flows,
            'total_bytes': total_bytes,
            'protocols': dict(protocols),
            'top_sources': dict(sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]),
            'blocked_flows': blocked_flows,
            'block_rate': blocked_flows / max(total_flows, 1),
            'average_packet_size': total_bytes / max(total_flows, 1)
        }

class DeviceIdentityManager:
    """Gestionnaire d'identités et d'accès pour équipements IoT."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.devices = {}
        self.access_policies = {}
        self.sessions = {}
        self.crypto_manager = CryptographicManager(config)
        
        # Base de données des équipements autorisés
        self.authorized_devices = set()
        self.device_groups = defaultdict(set)
        
        logger.info("Gestionnaire d'identités IoT initialisé")
    
    def register_device(self, device_profile: DeviceProfile) -> Dict[str, str]:
        """Enregistre un nouvel équipement IoT."""
        device_id = device_profile.device_id
        
        # Génération des certificats
        certificates = self.crypto_manager.generate_device_certificate(
            device_id, device_profile.device_type
        )
        
        # Stockage du profil
        self.devices[device_id] = device_profile
        device_profile.certificates = [certificates['certificate']]
        
        # Ajout aux équipements autorisés
        self.authorized_devices.add(device_id)
        
        # Assignation à un groupe par type
        self.device_groups[device_profile.device_type.value].add(device_id)
        
        logger.info(f"Équipement enregistré: {device_id} ({device_profile.device_type.value})")
        
        return certificates
    
    def authenticate_device(self, device_id: str, certificate: str, 
                           challenge_response: str = None) -> Tuple[bool, str]:
        """Authentifie un équipement IoT."""
        if device_id not in self.devices:
            return False, "Équipement non enregistré"
        
        if device_id not in self.authorized_devices:
            return False, "Équipement non autorisé"
        
        # Vérification du certificat
        if not self.crypto_manager.validate_device_certificate(certificate, device_id):
            return False, "Certificat invalide"
        
        # Création d'une session
        session_id = str(uuid.uuid4())
        session = {
            'device_id': device_id,
            'authenticated_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24),
            'permissions': self._get_device_permissions(device_id)
        }
        
        self.sessions[session_id] = session
        
        # Mise à jour du profil
        self.devices[device_id].last_seen = datetime.now()
        
        logger.info(f"Équipement authentifié: {device_id}")
        return True, session_id
    
    def authorize_action(self, session_id: str, action: str, resource: str = None) -> bool:
        """Autorise une action pour un équipement authentifié."""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Vérification de l'expiration
        if datetime.now() > session['expires_at']:
            del self.sessions[session_id]
            return False
        
        # Vérification des permissions
        permissions = session['permissions']
        
        # Politique d'autorisation simplifiée
        if action in permissions.get('allowed_actions', []):
            return True
        
        if resource and resource in permissions.get('allowed_resources', []):
            return True
        
        return False
    
    def revoke_device_access(self, device_id: str, reason: str = ""):
        """Révoque l'accès d'un équipement."""
        if device_id in self.authorized_devices:
            self.authorized_devices.remove(device_id)
        
        # Suppression des sessions actives
        sessions_to_remove = [
            sid for sid, session in self.sessions.items()
            if session['device_id'] == device_id
        ]
        
        for sid in sessions_to_remove:
            del self.sessions[sid]
        
        # Mise à jour du profil
        if device_id in self.devices:
            self.devices[device_id].is_authorized = False
            self.devices[device_id].risk_factors.append(f"Accès révoqué: {reason}")
        
        logger.warning(f"Accès révoqué pour {device_id}: {reason}")
    
    def detect_rogue_devices(self, discovered_devices: List[str]) -> List[str]:
        """Détecte les équipements non autorisés."""
        rogue_devices = []
        
        for device_ip in discovered_devices:
            # Recherche d'un équipement correspondant
            device_found = False
            for device_profile in self.devices.values():
                if device_profile.ip_address == device_ip:
                    device_found = True
                    break
            
            if not device_found:
                rogue_devices.append(device_ip)
        
        return rogue_devices
    
    def _get_device_permissions(self, device_id: str) -> Dict[str, List[str]]:
        """Obtient les permissions d'un équipement."""
        if device_id not in self.devices:
            return {'allowed_actions': [], 'allowed_resources': []}
        
        device_profile = self.devices[device_id]
        device_type = device_profile.device_type
        
        # Permissions par type d'équipement
        permissions_map = {
            DeviceType.PLC: {
                'allowed_actions': ['read_holding_registers', 'read_input_registers', 'write_single_register'],
                'allowed_resources': ['modbus_tcp', 'internal_network']
            },
            DeviceType.HMI: {
                'allowed_actions': ['display_data', 'user_input', 'alarm_management'],
                'allowed_resources': ['opcua', 'database_access', 'historian']
            },
            DeviceType.SENSOR: {
                'allowed_actions': ['send_data', 'report_status'],
                'allowed_resources': ['mqtt', 'data_collector']
            },
            DeviceType.GATEWAY: {
                'allowed_actions': ['route_traffic', 'protocol_conversion', 'data_aggregation'],
                'allowed_resources': ['all_protocols', 'external_network']
            }
        }
        
        return permissions_map.get(device_type, {'allowed_actions': [], 'allowed_resources': []})
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Données pour tableau de bord sécurité."""
        total_devices = len(self.devices)
        authorized_devices = len(self.authorized_devices)
        active_sessions = len(self.sessions)
        
        # Répartition par type
        device_types = defaultdict(int)
        security_scores = []
        
        for device_profile in self.devices.values():
            device_types[device_profile.device_type.value] += 1
            security_scores.append(device_profile.security_score)
        
        # Équipements à risque
        risky_devices = [
            device_id for device_id, profile in self.devices.items()
            if profile.security_score < 70 or profile.risk_factors
        ]
        
        return {
            'total_devices': total_devices,
            'authorized_devices': authorized_devices,
            'unauthorized_devices': total_devices - authorized_devices,
            'active_sessions': active_sessions,
            'device_type_distribution': dict(device_types),
            'average_security_score': np.mean(security_scores) if security_scores else 0,
            'risky_devices_count': len(risky_devices),
            'risky_devices': risky_devices[:10],  # Top 10
            'certificate_expiry_alerts': self._check_certificate_expiry()
        }
    
    def _check_certificate_expiry(self) -> List[str]:
        """Vérifie l'expiration des certificats."""
        expiring_soon = []
        
        for device_id, profile in self.devices.items():
            for cert in profile.certificates:
                try:
                    # Décodage simplifié du JWT
                    payload = jwt.decode(cert, verify=False)
                    expires_at = datetime.fromisoformat(payload.get('expires_at', ''))
                    
                    if expires_at - datetime.now() < timedelta(days=30):
                        expiring_soon.append(device_id)
                except:
                    continue
        
        return expiring_soon

class SecurityIncidentResponder:
    """Système de réponse automatique aux incidents de sécurité."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.response_actions = {}
        self.incident_history = deque(maxlen=10000)
        self.escalation_rules = {}
        self.automated_response = config.get('automated_response', True)
        
        self._configure_response_actions()
        self._configure_escalation_rules()
        
    def _configure_response_actions(self):
        """Configure les actions de réponse automatique."""
        self.response_actions = {
            ThreatLevel.LOW: [
                'log_incident',
                'update_threat_intelligence'
            ],
            ThreatLevel.MEDIUM: [
                'log_incident',
                'alert_security_team',
                'increase_monitoring',
                'update_threat_intelligence'
            ],
            ThreatLevel.HIGH: [
                'log_incident',
                'alert_security_team',
                'block_source_ip',
                'isolate_affected_device',
                'increase_monitoring',
                'generate_forensic_snapshot'
            ],
            ThreatLevel.CRITICAL: [
                'log_incident',
                'emergency_alert',
                'block_source_ip',
                'isolate_affected_device',
                'shutdown_affected_systems',
                'activate_incident_response_team',
                'generate_forensic_snapshot',
                'backup_critical_data'
            ]
        }
    
    def _configure_escalation_rules(self):
        """Configure les règles d'escalade."""
        self.escalation_rules = {
            'repeated_attacks': {
                'threshold': 5,
                'time_window': timedelta(minutes=15),
                'escalation': ThreatLevel.HIGH
            },
            'multiple_sources': {
                'threshold': 3,
                'time_window': timedelta(minutes=10),
                'escalation': ThreatLevel.HIGH
            },
            'critical_system_targeted': {
                'escalation': ThreatLevel.CRITICAL
            }
        }
    
    async def handle_security_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Traite une alerte de sécurité et déclenche les réponses appropriées."""
        logger.warning(f"Traitement alerte sécurité: {alert.description} (Niveau: {alert.threat_level.name})")
        
        # Enregistrement de l'incident
        incident = {
            'id': alert.id,
            'timestamp': alert.timestamp,
            'alert': alert,
            'actions_taken': [],
            'escalated': False,
            'resolved': False
        }
        
        # Vérification des règles d'escalade
        escalated_level = self._check_escalation_rules(alert)
        if escalated_level and escalated_level.value > alert.threat_level.value:
            alert.threat_level = escalated_level
            incident['escalated'] = True
            logger.warning(f"Alerte escaladée au niveau {escalated_level.name}")
        
        # Exécution des actions de réponse
        if self.automated_response:
            response_actions = self.response_actions.get(alert.threat_level, [])
            
            for action_name in response_actions:
                try:
                    result = await self._execute_response_action(action_name, alert)
                    incident['actions_taken'].append({
                        'action': action_name,
                        'result': result,
                        'timestamp': datetime.now()
                    })
                    
                    if result.get('success'):
                        logger.info(f"Action {action_name} exécutée avec succès")
                    else:
                        logger.error(f"Échec action {action_name}: {result.get('error')}")
                        
                except Exception as e:
                    logger.error(f"Erreur exécution action {action_name}: {e}")
                    incident['actions_taken'].append({
                        'action': action_name,
                        'result': {'success': False, 'error': str(e)},
                        'timestamp': datetime.now()
                    })
        
        # Enregistrement de l'incident
        self.incident_history.append(incident)
        
        return {
            'incident_id': incident['id'],
            'threat_level': alert.threat_level.name,
            'actions_taken': len(incident['actions_taken']),
            'escalated': incident['escalated'],
            'automated_response': self.automated_response
        }
    
    def _check_escalation_rules(self, alert: SecurityAlert) -> Optional[ThreatLevel]:
        """Vérifie si l'alerte doit être escaladée."""
        # Règle: attaques répétées
        recent_incidents = [
            inc for inc in self.incident_history
            if inc['timestamp'] > datetime.now() - self.escalation_rules['repeated_attacks']['time_window']
            and inc['alert'].source_ip == alert.source_ip
        ]
        
        if len(recent_incidents) >= self.escalation_rules['repeated_attacks']['threshold']:
            return self.escalation_rules['repeated_attacks']['escalation']
        
        # Règle: sources multiples
        recent_sources = set(
            inc['alert'].source_ip for inc in self.incident_history
            if inc['timestamp'] > datetime.now() - self.escalation_rules['multiple_sources']['time_window']
            and inc['alert'].target_device == alert.target_device
        )
        
        if len(recent_sources) >= self.escalation_rules['multiple_sources']['threshold']:
            return self.escalation_rules['multiple_sources']['escalation']
        
        # Règle: système critique ciblé
        critical_systems = ['192.168.1.100', '192.168.1.101']  # IPs des systèmes critiques
        if alert.target_device in critical_systems:
            return ThreatLevel.CRITICAL
        
        return None
    
    async def _execute_response_action(self, action_name: str, alert: SecurityAlert) -> Dict[str, Any]:
        """Exécute une action de réponse spécifique."""
        
        if action_name == 'log_incident':
            return await self._log_incident(alert)
        
        elif action_name == 'alert_security_team':
            return await self._alert_security_team(alert)
        
        elif action_name == 'emergency_alert':
            return await self._emergency_alert(alert)
        
        elif action_name == 'block_source_ip':
            return await self._block_source_ip(alert.source_ip)
        
        elif action_name == 'isolate_affected_device':
            return await self._isolate_device(alert.target_device)
        
        elif action_name == 'shutdown_affected_systems':
            return await self._shutdown_systems([alert.target_device])
        
        elif action_name == 'increase_monitoring':
            return await self._increase_monitoring(alert.target_device)
        
        elif action_name == 'generate_forensic_snapshot':
            return await self._generate_forensic_snapshot(alert)
        
        elif action_name == 'backup_critical_data':
            return await self._backup_critical_data()
        
        elif action_name == 'update_threat_intelligence':
            return await self._update_threat_intelligence(alert)
        
        else:
            return {'success': False, 'error': f'Action inconnue: {action_name}'}
    
    async def _log_incident(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Enregistre l'incident dans les logs."""
        log_entry = {
            'timestamp': alert.timestamp.isoformat(),
            'alert_id': alert.id,
            'threat_level': alert.threat_level.name,
            'source_ip': alert.source_ip,
            'target': alert.target_device,
            'description': alert.description
        }
        
        # Simulation d'écriture dans SIEM
        logger.info(f"INCIDENT LOGGED: {json.dumps(log_entry)}")
        return {'success': True, 'log_entry': log_entry}
    
    async def _alert_security_team(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Alerte l'équipe de sécurité."""
        # Simulation d'envoi d'email/SMS
        message = f"ALERTE SÉCURITÉ IoT: {alert.description} (Source: {alert.source_ip})"
        logger.warning(f"SECURITY TEAM ALERT: {message}")
        
        # En production, ceci utiliserait des services comme:
        # - SMTP pour email
        # - API SMS
        # - Webhooks Slack/Teams
        # - API SIEM
        
        return {'success': True, 'alert_sent': True, 'recipients': ['security-team@company.com']}
    
    async def _emergency_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Alerte d'urgence niveau critique."""
        message = f"URGENCE SÉCURITÉ CRITIQUE: {alert.description}"
        logger.critical(f"EMERGENCY ALERT: {message}")
        
        # Notifications multiples pour urgence
        return {
            'success': True,
            'emergency_alert_sent': True,
            'channels': ['email', 'sms', 'phone_call', 'siem', 'dashboards']
        }
    
    async def _block_source_ip(self, source_ip: str) -> Dict[str, Any]:
        """Bloque une adresse IP source."""
        # Simulation d'ajout de règle firewall
        logger.warning(f"BLOCKING IP: {source_ip}")
        
        # En production:
        # - Commandes iptables
        # - API firewall hardware
        # - Mise à jour ACL routeur
        
        await asyncio.sleep(0.1)  # Simulation délai
        return {'success': True, 'blocked_ip': source_ip, 'method': 'firewall_rule'}
    
    async def _isolate_device(self, device_ip: str) -> Dict[str, Any]:
        """Isole un équipement du réseau."""
        logger.warning(f"ISOLATING DEVICE: {device_ip}")
        
        # En production:
        # - VLAN isolation
        # - Port shutdown sur switch
        # - Quarantine network
        
        await asyncio.sleep(0.2)  # Simulation délai
        return {'success': True, 'isolated_device': device_ip, 'method': 'vlan_isolation'}
    
    async def _shutdown_systems(self, systems: List[str]) -> Dict[str, Any]:
        """Arrêt d'urgence de systèmes critiques."""
        logger.critical(f"EMERGENCY SHUTDOWN: {systems}")
        
        # En production:
        # - Commandes SCADA
        # - API équipements
        # - Procédures d'arrêt sécurisées
        
        await asyncio.sleep(0.5)  # Simulation délai
        return {'success': True, 'shutdown_systems': systems, 'method': 'emergency_stop'}
    
    async def _increase_monitoring(self, target_device: str) -> Dict[str, Any]:
        """Augmente le niveau de surveillance."""
        logger.info(f"INCREASING MONITORING: {target_device}")
        
        # En production:
        # - Augmentation fréquence collecte
        # - Activation logs détaillés
        # - Surveillance temps réel
        
        return {'success': True, 'enhanced_monitoring': target_device, 'duration': '24h'}
    
    async def _generate_forensic_snapshot(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Génère un snapshot forensique."""
        logger.info(f"GENERATING FORENSIC SNAPSHOT: {alert.target_device}")
        
        # En production:
        # - Capture mémoire
        # - Logs système
        # - État réseau
        # - Configuration équipements
        
        snapshot_id = str(uuid.uuid4())
        return {
            'success': True,
            'snapshot_id': snapshot_id,
            'timestamp': datetime.now().isoformat(),
            'target': alert.target_device
        }
    
    async def _backup_critical_data(self) -> Dict[str, Any]:
        """Sauvegarde les données critiques."""
        logger.info("BACKING UP CRITICAL DATA")
        
        # En production:
        # - Backup base de données
        # - Configuration équipements
        # - Logs critiques
        
        backup_id = str(uuid.uuid4())
        return {
            'success': True,
            'backup_id': backup_id,
            'timestamp': datetime.now().isoformat(),
            'scope': 'critical_systems'
        }
    
    async def _update_threat_intelligence(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Met à jour l'intelligence des menaces."""
        logger.info("UPDATING THREAT INTELLIGENCE")
        
        # En production:
        # - Ajout signatures
        # - Mise à jour règles détection
        # - Feed threat intelligence
        
        return {
            'success': True,
            'updated_signatures': 1,
            'source_ip_added': alert.source_ip,
            'attack_vector': alert.attack_vector.name
        }
    
    def get_incident_statistics(self, time_window: timedelta = None) -> Dict[str, Any]:
        """Retourne les statistiques d'incidents."""
        incidents = list(self.incident_history)
        
        if time_window:
            cutoff_time = datetime.now() - time_window
            incidents = [inc for inc in incidents if inc['timestamp'] >= cutoff_time]
        
        if not incidents:
            return {'total_incidents': 0}
        
        # Statistiques par niveau
        threat_levels = defaultdict(int)
        for incident in incidents:
            threat_levels[incident['alert'].threat_level.name] += 1
        
        # Actions les plus fréquentes
        action_counts = defaultdict(int)
        for incident in incidents:
            for action in incident['actions_taken']:
                action_counts[action['action']] += 1
        
        # Taux de résolution
        resolved_count = sum(1 for inc in incidents if inc.get('resolved', False))
        escalated_count = sum(1 for inc in incidents if inc.get('escalated', False))
        
        return {
            'total_incidents': len(incidents),
            'threat_level_distribution': dict(threat_levels),
            'most_common_actions': dict(sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'resolution_rate': resolved_count / len(incidents),
            'escalation_rate': escalated_count / len(incidents),
            'average_response_time': '< 1 minute',  # Réponse automatique
            'automated_responses': sum(len(inc['actions_taken']) for inc in incidents)
        }

class IndustrialIoTSecurityFramework:
    """Framework principal de sécurité IoT industriel."""
    
    def __init__(self, config_path: str = "iot_security_config.json"):
        self.config = self._load_config(config_path)
        
        # Initialisation des composants
        self.crypto_manager = CryptographicManager(self.config.get('cryptography', {}))
        self.anomaly_detector = AnomalyDetectionEngine(self.config.get('anomaly_detection', {}))
        self.threat_intelligence = ThreatIntelligenceEngine(self.config.get('threat_intelligence', {}))
        self.network_monitor = NetworkSecurityMonitor(self.config.get('network_monitoring', {}))
        self.device_manager = DeviceIdentityManager(self.config.get('device_management', {}))
        self.incident_responder = SecurityIncidentResponder(self.config.get('incident_response', {}))
        
        # État du système
        self.is_running = False
        self.security_alerts = deque(maxlen=50000)
        self.system_health = {}
        
        # Thread pool pour traitement asynchrone
        self.alert_processing_queue = asyncio.Queue()
        
        logger.info("Framework de sécurité IoT industriel initialisé")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration du framework."""
        default_config = {
            'system': {
                'auto_start_monitoring': True,
                'alert_processing_threads': 4,
                'log_level': 'INFO',
                'data_retention_days': 90
            },
            'cryptography': {
                'key_size': 4096,
                'certificate_validity_days': 365,
                'encryption_algorithm': 'AES-256'
            },
            'anomaly_detection': {
                'anomaly_threshold': 0.1,
                'learning_rate': 0.001,
                'baseline_window_hours': 24
            },
            'threat_intelligence': {
                'signature_updates_hours': 4,
                'threat_feeds': ['internal'],
                'confidence_threshold': 0.7
            },
            'network_monitoring': {
                'capture_interface': None,
                'packet_filter': 'tcp or udp',
                'flow_timeout_minutes': 15
            },
            'device_management': {
                'auto_discovery': True,
                'certificate_renewal_days': 30,
                'session_timeout_hours': 24
            },
            'incident_response': {
                'automated_response': True,
                'escalation_enabled': True,
                'notification_channels': ['email', 'syslog']
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge avec defaults
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
    
    async def start_security_framework(self):
        """Démarre le framework de sécurité complet."""
        if self.is_running:
            logger.warning("Framework déjà en cours d'exécution")
            return
        
        logger.info("🛡️ Démarrage du Framework de Sécurité IoT Industriel")
        self.is_running = True
        
        # Démarrage de la surveillance réseau
        if self.config['system']['auto_start_monitoring']:
            interface = self.config['network_monitoring'].get('capture_interface')
            self.network_monitor.start_monitoring(interface)
        
        # Démarrage du traitement d'alertes
        asyncio.create_task(self._alert_processing_loop())
        
        # Démarrage de la surveillance système
        asyncio.create_task(self._system_health_monitoring())
        
        # Démarrage de l'analyse en temps réel
        asyncio.create_task(self._real_time_analysis_loop())
        
        logger.info("✅ Framework de sécurité démarré avec succès")
    
    async def stop_security_framework(self):
        """Arrête le framework de sécurité."""
        if not self.is_running:
            return
        
        logger.info("Arrêt du framework de sécurité")
        self.is_running = False
        
        # Arrêt de la surveillance réseau
        self.network_monitor.stop_monitoring()
        
        logger.info("Framework de sécurité arrêté")
    
    async def _alert_processing_loop(self):
        """Boucle de traitement des alertes de sécurité."""
        while self.is_running:
            try:
                # Attendre une alerte dans la queue
                alert = await asyncio.wait_for(self.alert_processing_queue.get(), timeout=1.0)
                
                # Traitement de l'alerte
                response = await self.incident_responder.handle_security_alert(alert)
                
                # Stockage de l'alerte
                self.security_alerts.append(alert)
                
                # Mise à jour des statistiques
                await self._update_security_metrics(alert, response)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Erreur traitement alerte: {e}")
    
    async def _real_time_analysis_loop(self):
        """Boucle d'analyse en temps réel du trafic."""
        while self.is_running:
            try:
                # Récupération du trafic récent
                recent_flows = list(self.network_monitor.captured_flows)[-100:]
                
                if recent_flows:
                    # Analyse des menaces
                    threat_alerts = self.threat_intelligence.analyze_traffic_for_threats(recent_flows)
                    
                    # Détection d'anomalies réseau
                    for flow in recent_flows[-10:]:  # Analyse des 10 derniers flux
                        is_anomaly, anomaly_score = self.anomaly_detector.detect_network_anomaly(flow)
                        
                        if is_anomaly:
                            anomaly_alert = SecurityAlert(
                                threat_level=ThreatLevel.MEDIUM if anomaly_score > 1.0 else ThreatLevel.LOW,
                                attack_vector=AttackVector.NETWORK_INTRUSION,
                                source_ip=flow.source_ip,
                                target_device=flow.dest_ip,
                                protocol=ProtocolType.HTTP,  # Simplification
                                description=f"Anomalie réseau détectée (score: {anomaly_score:.2f})",
                                confidence_score=min(anomaly_score, 1.0)
                            )
                            threat_alerts.append(anomaly_alert)
                    
                    # Ajout des alertes à la queue de traitement
                    for alert in threat_alerts:
                        await self.alert_processing_queue.put(alert)
                
                # Pause avant prochaine analyse
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Erreur analyse temps réel: {e}")
                await asyncio.sleep(10)
    
    async def _system_health_monitoring(self):
        """Surveillance de la santé du système."""
        while self.is_running:
            try:
                # Métriques système
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Métriques réseau
                net_io = psutil.net_io_counters()
                
                # Mise à jour de la santé système
                self.system_health = {
                    'timestamp': datetime.now(),
                    'cpu_usage_percent': cpu_usage,
                    'memory_usage_percent': memory.percent,
                    'disk_usage_percent': disk.percent,
                    'network_bytes_sent': net_io.bytes_sent,
                    'network_bytes_recv': net_io.bytes_recv,
                    'active_sessions': len(self.device_manager.sessions),
                    'monitored_devices': len(self.device_manager.devices),
                    'security_alerts_count': len(self.security_alerts),
                    'is_monitoring_active': self.network_monitor.is_monitoring
                }
                
                # Alertes de santé système
                if cpu_usage > 90:
                    logger.warning(f"CPU usage élevé: {cpu_usage}%")
                if memory.percent > 85:
                    logger.warning(f"Utilisation mémoire élevée: {memory.percent}%")
                if disk.percent > 90:
                    logger.warning(f"Espace disque faible: {disk.percent}%")
                
                await asyncio.sleep(30)  # Surveillance toutes les 30 secondes
                
            except Exception as e:
                logger.error(f"Erreur surveillance système: {e}")
                await asyncio.sleep(60)
    
    async def _update_security_metrics(self, alert: SecurityAlert, response: Dict[str, Any]):
        """Met à jour les métriques de sécurité."""
        # Mise à jour des scores de sécurité des équipements
        if alert.target_device and alert.target_device in self.device_manager.devices:
            device = self.device_manager.devices[alert.target_device]
            
            # Réduction du score selon le niveau de menace
            score_reduction = {
                ThreatLevel.LOW: 1,
                ThreatLevel.MEDIUM: 5,
                ThreatLevel.HIGH: 15,
                ThreatLevel.CRITICAL: 30
            }
            
            device.security_score = max(0, device.security_score - score_reduction[alert.threat_level])
            
            # Ajout du facteur de risque
            risk_factor = f"{alert.attack_vector.name}_{alert.timestamp.strftime('%Y%m%d')}"
            if risk_factor not in device.risk_factors:
                device.risk_factors.append(risk_factor)
    
    async def register_iot_device(self, ip_address: str, device_type: DeviceType, 
                                 manufacturer: str = "", firmware_version: str = "") -> Dict[str, Any]:
        """Enregistre un nouvel équipement IoT dans le système."""
        device_id = f"iot_{device_type.value.lower()}_{ip_address.replace('.', '_')}"
        
        # Création du profil d'équipement
        device_profile = DeviceProfile(
            device_id=device_id,
            device_type=device_type,
            ip_address=ip_address,
            mac_address="00:00:00:00:00:00",  # À découvrir
            manufacturer=manufacturer,
            firmware_version=firmware_version,
            supported_protocols=[],  # À découvrir
            security_score=100.0,
            is_authorized=True
        )
        
        # Enregistrement via le gestionnaire d'identités
        certificates = self.device_manager.register_device(device_profile)
        
        logger.info(f"Équipement IoT enregistré: {device_id}")
        
        return {
            'device_id': device_id,
            'registration_success': True,
            'certificates': certificates,
            'security_score': device_profile.security_score
        }
    
    async def authenticate_device_access(self, device_id: str, certificate: str) -> Dict[str, Any]:
        """Authentifie l'accès d'un équipement."""
        success, session_or_error = self.device_manager.authenticate_device(device_id, certificate)
        
        if success:
            return {
                'authentication_success': True,
                'session_id': session_or_error,
                'permissions': self.device_manager.sessions[session_or_error]['permissions']
            }
        else:
            # Génération d'alerte d'authentification échouée
            auth_alert = SecurityAlert(
                threat_level=ThreatLevel.MEDIUM,
                attack_vector=AttackVector.CREDENTIAL_THEFT,
                source_ip=self.device_manager.devices.get(device_id, DeviceProfile(device_id="", device_type=DeviceType.UNKNOWN, ip_address="")).ip_address,
                target_device=device_id,
                description=f"Échec d'authentification: {session_or_error}",
                confidence_score=0.8
            )
            
            await self.alert_processing_queue.put(auth_alert)
            
            return {
                'authentication_success': False,
                'error': session_or_error
            }
    
    async def scan_network_for_devices(self, network_range: str = "192.168.1.0/24") -> List[str]:
        """Scan réseau pour découverte d'équipements."""
        logger.info(f"Scan réseau: {network_range}")
        
        discovered_devices = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            # Simulation de découverte (en production, utiliserait nmap, scapy, etc.)
            for ip in list(network.hosts())[:10]:  # Limite à 10 pour la demo
                ip_str = str(ip)
                
                # Simulation de ping/scan
                await asyncio.sleep(0.1)
                
                # Simulation de découverte aléatoire
                if hash(ip_str) % 5 == 0:  # 20% de chance de découverte
                    discovered_devices.append(ip_str)
            
        except Exception as e:
            logger.error(f"Erreur scan réseau: {e}")
        
        # Détection d'équipements non autorisés
        rogue_devices = self.device_manager.detect_rogue_devices(discovered_devices)
        
        if rogue_devices:
            for rogue_ip in rogue_devices:
                rogue_alert = SecurityAlert(
                    threat_level=ThreatLevel.HIGH,
                    attack_vector=AttackVector.ROGUE_DEVICE,
                    source_ip=rogue_ip,
                    target_device="network",
                    description=f"Équipement non autorisé détecté: {rogue_ip}",
                    confidence_score=0.9
                )
                await self.alert_processing_queue.put(rogue_alert)
        
        logger.info(f"Découverte terminée: {len(discovered_devices)} équipements, {len(rogue_devices)} non autorisés")
        
        return discovered_devices
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """Tableau de bord sécurité complet."""
        # Statistiques des alertes récentes
        recent_alerts = [
            alert for alert in self.security_alerts
            if alert.timestamp > datetime.now() - timedelta(hours=24)
        ]
        
        # Répartition par niveau de menace
        threat_levels = defaultdict(int)
        for alert in recent_alerts:
            threat_levels[alert.threat_level.name] += 1
        
        # Top des sources d'attaque
        attack_sources = defaultdict(int)
        for alert in recent_alerts:
            if alert.source_ip:
                attack_sources[alert.source_ip] += 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'ACTIVE' if self.is_running else 'STOPPED',
            'system_health': self.system_health,
            
            # Alertes de sécurité
            'security_alerts': {
                'total_24h': len(recent_alerts),
                'critical': threat_levels.get('CRITICAL', 0),
                'high': threat_levels.get('HIGH', 0),
                'medium': threat_levels.get('MEDIUM', 0),
                'low': threat_levels.get('LOW', 0),
                'top_attack_sources': dict(sorted(attack_sources.items(), key=lambda x: x[1], reverse=True)[:5])
            },
            
            # Équipements IoT
            'device_management': self.device_manager.get_security_dashboard_data(),
            
            # Trafic réseau
            'network_security': self.network_monitor.get_traffic_statistics(timedelta(hours=1)),
            
            # Détection d'anomalies
            'anomaly_detection': self.anomaly_detector.get_anomaly_statistics(),
            
            # Réponse aux incidents
            'incident_response': self.incident_responder.get_incident_statistics(timedelta(hours=24)),
            
            # Intelligence des menaces
            'threat_intelligence': {
                'signatures_loaded': len(self.threat_intelligence.threat_signatures),
                'attack_patterns': len(self.threat_intelligence.attack_patterns),
                'vulnerabilities_tracked': len(self.threat_intelligence.iot_vulnerabilities)
            }
        }
    
    async def generate_security_report(self, report_type: str = "comprehensive") -> Dict[str, Any]:
        """Génère un rapport de sécurité détaillé."""
        logger.info(f"Génération rapport de sécurité: {report_type}")
        
        dashboard_data = self.get_security_dashboard()
        
        # Rapport des menaces
        threat_report = self.threat_intelligence.generate_threat_report(
            list(self.security_alerts),
            timedelta(days=7)
        )
        
        # Analyse des tendances
        weekly_alerts = [
            alert for alert in self.security_alerts
            if alert.timestamp > datetime.now() - timedelta(days=7)
        ]
        
        daily_alert_counts = defaultdict(int)
        for alert in weekly_alerts:
            day = alert.timestamp.strftime('%Y-%m-%d')
            daily_alert_counts[day] += 1
        
        report = {
            'report_type': report_type,
            'generated_at': datetime.now().isoformat(),
            'period': '7 days',
            
            'executive_summary': {
                'total_alerts': len(weekly_alerts),
                'critical_incidents': len([a for a in weekly_alerts if a.threat_level == ThreatLevel.CRITICAL]),
                'devices_monitored': len(self.device_manager.devices),
                'automated_responses': sum(len(inc['actions_taken']) for inc in self.incident_responder.incident_history),
                'security_posture': 'GOOD' if len([a for a in weekly_alerts if a.threat_level == ThreatLevel.CRITICAL]) == 0 else 'ATTENTION_REQUIRED'
            },
            
            'threat_landscape': threat_report,
            'daily_alert_trend': dict(daily_alert_counts),
            'system_performance': dashboard_data,
            
            'recommendations': self._generate_security_recommendations(weekly_alerts),
            
            'appendix': {
                'configuration': {
                    'monitoring_enabled': self.network_monitor.is_monitoring,
                    'automated_response': self.incident_responder.automated_response,
                    'device_count': len(self.device_manager.devices)
                }
            }
        }
        
        return report
    
    def _generate_security_recommendations(self, alerts: List[SecurityAlert]) -> List[Dict[str, str]]:
        """Génère des recommandations de sécurité basées sur l'analyse."""
        recommendations = []
        
        # Analyse des patterns d'alertes
        attack_vectors = defaultdict(int)
        source_ips = defaultdict(int)
        
        for alert in alerts:
            attack_vectors[alert.attack_vector] += 1
            if alert.source_ip:
                source_ips[alert.source_ip] += 1
        
        # Recommandations basées sur les vecteurs d'attaque fréquents
        if attack_vectors[AttackVector.NETWORK_INTRUSION] > 5:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Network Security',
                'recommendation': 'Renforcer les règles de pare-feu et implémenter une segmentation réseau plus stricte',
                'rationale': f'{attack_vectors[AttackVector.NETWORK_INTRUSION]} tentatives d\'intrusion réseau détectées'
            })
        
        if attack_vectors[AttackVector.CREDENTIAL_THEFT] > 3:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Authentication',
                'recommendation': 'Implémenter l\'authentification multi-facteurs et réviser les politiques de mots de passe',
                'rationale': f'{attack_vectors[AttackVector.CREDENTIAL_THEFT]} tentatives de vol d\'identifiants détectées'
            })
        
        if attack_vectors[AttackVector.ROGUE_DEVICE] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Device Management',
                'recommendation': 'Améliorer les procédures de découverte et d\'autorisation d\'équipements',
                'rationale': f'{attack_vectors[AttackVector.ROGUE_DEVICE]} équipements non autorisés détectés'
            })
        
        # Recommandations pour sources récurrentes
        frequent_sources = [ip for ip, count in source_ips.items() if count > 3]
        if frequent_sources:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Threat Intelligence',
                'recommendation': f'Investiguer et potentiellement bloquer les sources persistantes: {", ".join(frequent_sources[:3])}',
                'rationale': 'Multiples attaques depuis les mêmes sources'
            })
        
        # Recommandations générales
        if len(alerts) > 50:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Monitoring',
                'recommendation': 'Considérer l\'ajustement des seuils de détection pour réduire les faux positifs',
                'rationale': f'{len(alerts)} alertes générées en 7 jours'
            })
        
        return recommendations

# Fonction de démonstration
async def main():
    """Démonstration du framework de sécurité IoT industriel."""
    
    print("=== Framework de Sécurité IoT Industriel Avancé ===")
    print("🛡️ Station Traffeyère IoT AI Platform - Module Sécurité")
    print()
    
    # Initialisation du framework
    security_framework = IndustrialIoTSecurityFramework()
    
    print("✅ Framework de sécurité initialisé")
    print()
    
    # Démarrage du framework
    print("🚀 Démarrage du framework de sécurité...")
    await security_framework.start_security_framework()
    
    print("✅ Framework de sécurité démarré")
    print()
    
    try:
        # Simulation d'enregistrement d'équipements IoT
        print("📋 Enregistrement d'équipements IoT industriels...")
        
        devices_to_register = [
            ("192.168.1.100", DeviceType.PLC, "Schneider Electric", "v2.1.4"),
            ("192.168.1.101", DeviceType.HMI, "Siemens", "v1.8.3"),
            ("192.168.1.102", DeviceType.SENSOR, "Honeywell", "v3.2.1"),
            ("192.168.1.103", DeviceType.GATEWAY, "Cisco", "v4.0.2"),
            ("192.168.1.104", DeviceType.ACTUATOR, "ABB", "v2.5.0")
        ]
        
        registered_devices = []
        for ip, device_type, manufacturer, firmware in devices_to_register:
            result = await security_framework.register_iot_device(
                ip, device_type, manufacturer, firmware
            )
            registered_devices.append(result)
            print(f"  ✓ {device_type.value} ({ip}) - Score sécurité: {result['security_score']}")
        
        print(f"  • {len(registered_devices)} équipements enregistrés avec succès")
        print()
        
        # Simulation de découverte réseau
        print("🔍 Scan réseau pour découverte d'équipements...")
        discovered_devices = await security_framework.scan_network_for_devices("192.168.1.0/24")
        print(f"  • {len(discovered_devices)} équipements découverts sur le réseau")
        print()
        
        # Simulation d'activité de sécurité
        print("⚡ Simulation d'activité de sécurité (10 secondes)...")
        
        # Génération d'alertes de test
        test_alerts = [
            SecurityAlert(
                threat_level=ThreatLevel.HIGH,
                attack_vector=AttackVector.NETWORK_INTRUSION,
                source_ip="10.0.0.50",
                target_device="192.168.1.100",
                protocol=ProtocolType.MODBUS_TCP,
                description="Tentative d'accès non autorisé au PLC principal",
                confidence_score=0.9
            ),
            SecurityAlert(
                threat_level=ThreatLevel.MEDIUM,
                attack_vector=AttackVector.CREDENTIAL_THEFT,
                source_ip="172.16.1.25",
                target_device="192.168.1.101",
                protocol=ProtocolType.OPCUA,
                description="Multiples tentatives d'authentification échouées",
                confidence_score=0.7
            ),
            SecurityAlert(
                threat_level=ThreatLevel.CRITICAL,
                attack_vector=AttackVector.ROGUE_DEVICE,
                source_ip="192.168.1.200",
                target_device="network",
                description="Équipement non autorisé détecté sur réseau industriel",
                confidence_score=0.95
            )
        ]
        
        # Injection des alertes de test
        for alert in test_alerts:
            await security_framework.alert_processing_queue.put(alert)
        
        # Attente du traitement
        await asyncio.sleep(3)
        
        # Affichage du tableau de bord sécurité
        print("📊 Tableau de bord sécurité:")
        print("=" * 50)
        
        dashboard = security_framework.get_security_dashboard()
        
        print(f"🟢 Statut système: {dashboard['system_status']}")
        print(f"⚠️  Alertes 24h: {dashboard['security_alerts']['total_24h']}")
        print(f"🔴 Critiques: {dashboard['security_alerts']['critical']}")
        print(f"🟡 Élevées: {dashboard['security_alerts']['high']}")
        print(f"📱 Équipements surveillés: {dashboard['device_management']['total_devices']}")
        print(f"🔐 Sessions actives: {dashboard['device_management']['active_sessions']}")
        print()
        
        # Statistiques de santé système
        if dashboard['system_health']:
            health = dashboard['system_health']
            print("💻 Santé du système:")
            print(f"  • CPU: {health.get('cpu_usage_percent', 0):.1f}%")
            print(f"  • Mémoire: {health.get('memory_usage_percent', 0):.1f}%")
            print(f"  • Surveillance active: {'✅' if health.get('is_monitoring_active', False) else '❌'}")
            print()
        
        # Top des sources d'attaque
        if dashboard['security_alerts']['top_attack_sources']:
            print("🎯 Top sources d'attaque:")
            for ip, count in list(dashboard['security_alerts']['top_attack_sources'].items())[:3]:
                print(f"  • {ip}: {count} attaques")
            print()
        
        # Statistiques de réponse aux incidents
        incident_stats = dashboard['incident_response']
        print("🚨 Réponse aux incidents:")
        print(f"  • Incidents traités: {incident_stats.get('total_incidents', 0)}")
        print(f"  • Réponses automatiques: {incident_stats.get('automated_responses', 0)}")
        print(f"  • Temps de réponse moyen: {incident_stats.get('average_response_time', 'N/A')}")
        print()
        
        # Génération d'un rapport de sécurité
        print("📄 Génération du rapport de sécurité...")
        security_report = await security_framework.generate_security_report()
        
        print("📋 Résumé exécutif:")
        summary = security_report['executive_summary']
        print(f"  • Alertes totales (7 jours): {summary['total_alerts']}")
        print(f"  • Incidents critiques: {summary['critical_incidents']}")
        print(f"  • Posture sécurité: {summary['security_posture']}")
        print(f"  • Réponses automatiques: {summary['automated_responses']}")
        print()
        
        # Recommandations de sécurité
        recommendations = security_report.get('recommendations', [])
        if recommendations:
            print("💡 Recommandations de sécurité:")
            for i, rec in enumerate(recommendations[:3], 1):
                priority_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(rec['priority'], '⚪')
                print(f"  {i}. {priority_emoji} [{rec['category']}] {rec['recommendation']}")
                print(f"     Justification: {rec['rationale']}")
            print()
        
        # Test d'authentification
        print("🔐 Test d'authentification d'équipement...")
        if registered_devices:
            device_id = registered_devices[0]['device_id']
            certificate = registered_devices[0]['certificates']['certificate']
            
            auth_result = await security_framework.authenticate_device_access(device_id, certificate)
            
            if auth_result['authentication_success']:
                print(f"  ✅ Authentification réussie pour {device_id}")
                print(f"  📋 Session: {auth_result['session_id'][:8]}...")
            else:
                print(f"  ❌ Échec authentification: {auth_result['error']}")
        print()
        
        # Simulation d'analyse d'anomalies
        print("🔍 Analyse d'anomalies comportementales...")
        
        # Génération de flux réseau fictifs pour démonstration
        sample_flows = []
        for i in range(20):
            flow = NetworkFlow(
                source_ip=f"192.168.1.{100 + i % 5}",
                dest_ip=f"192.168.1.{200 + i % 3}",
                source_port=1024 + i,
                dest_port=502 if i % 3 == 0 else 80,  # Modbus ou HTTP
                protocol="TCP",
                packet_size=64 + i * 10,
                timestamp=datetime.now() - timedelta(seconds=i),
                is_encrypted=i % 4 == 0
            )
            sample_flows.append(flow)
        
        # Entraînement du modèle de détection
        security_framework.anomaly_detector.train_network_anomaly_model(sample_flows)
        
        # Test de détection sur nouveaux flux
        anomalies_detected = 0
        for flow in sample_flows[-5:]:  # Test sur les 5 derniers
            is_anomaly, score = security_framework.anomaly_detector.detect_network_anomaly(flow)
            if is_anomaly:
                anomalies_detected += 1
        
        print(f"  • Modèle entraîné sur {len(sample_flows)} flux réseau")
        print(f"  • Anomalies détectées: {anomalies_detected}/5 flux testés")
        
        # Statistiques finales
        anomaly_stats = security_framework.anomaly_detector.get_anomaly_statistics()
        print(f"  • Taux d'anomalies réseau: {anomaly_stats['network_traffic'].get('anomaly_rate', 0):.2%}")
        print()
        
        print("🎉 Démonstration du framework de sécurité terminée avec succès !")
        print()
        print("🛡️ Fonctionnalités démontrées:")
        print("  ✓ Enregistrement et authentification d'équipements IoT")
        print("  ✓ Découverte et surveillance réseau")
        print("  ✓ Détection d'anomalies comportementales")
        print("  ✓ Intelligence des menaces et analyse de sécurité")
        print("  ✓ Réponse automatique aux incidents")
        print("  ✓ Gestion des identités et certificats")
        print("  ✓ Génération de rapports de sécurité")
        print("  ✓ Surveillance temps réel et tableau de bord")
        
    except Exception as e:
        print(f"❌ Erreur durant la démonstration: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Arrêt propre du framework
        print("\n🛑 Arrêt du framework de sécurité...")
        await security_framework.stop_security_framework()
        print("✅ Framework arrêté proprement")

if __name__ == "__main__":
    asyncio.run(main())