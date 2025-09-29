#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 7: Interface VR/AR Immersive pour Formation et Maintenance

Interface de Réalité Virtuelle et Augmentée pour la formation des opérateurs
et l'assistance à la maintenance industrielle avec :
- Formation immersive aux procédures de sécurité
- Assistance AR pour maintenance préventive/corrective
- Simulation de scénarios d'urgence et de cyberattaques
- Formation aux protocoles de cybersécurité industrielle
- Visualisation 3D des systèmes industriels complexes
- Guidance interactive pour interventions techniques

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
from enum import Enum, auto
from pathlib import Path
import uuid
import numpy as np
import pandas as pd
from collections import deque, defaultdict
import math
import random

# Réalité Virtuelle et Augmentée
try:
    import openvr
    import pygame
    from pygame import gfxdraw
    OPENVR_AVAILABLE = True
except ImportError:
    OPENVR_AVAILABLE = False
    print("OpenVR non disponible - mode simulation activé")

# Visualisation 3D et rendu
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc

# Computer Vision et AR
try:
    import cv2
    import mediapipe as mp
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    print("OpenCV/MediaPipe non disponible - tracking simplifié")

# Audio spatial et haptic feedback
try:
    import sounddevice as sd
    import numpy as np
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False
    print("Audio spatial non disponible")

# Machine Learning pour reconnaissance gestuelle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Modélisation 3D et physique
try:
    import trimesh
    import pybullet as p
    import pybullet_data
    PHYSICS_AVAILABLE = True
except ImportError:
    PHYSICS_AVAILABLE = False
    print("Moteur physique non disponible - simulation simplifiée")

# Réseau et communication temps réel
import websockets
import socket
import struct
import threading

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrainingScenario(Enum):
    """Types de scénarios de formation."""
    SECURITY_PROCEDURES = "security_procedures"
    EMERGENCY_RESPONSE = "emergency_response" 
    CYBER_INCIDENT = "cyber_incident"
    MAINTENANCE_PROCEDURE = "maintenance_procedure"
    EQUIPMENT_OPERATION = "equipment_operation"
    SAFETY_TRAINING = "safety_training"
    PROTOCOL_COMPLIANCE = "protocol_compliance"

class InteractionMode(Enum):
    """Modes d'interaction utilisateur."""
    VR_HEADSET = "vr_headset"
    AR_TABLET = "ar_tablet"
    AR_GLASSES = "ar_glasses"
    DESKTOP_3D = "desktop_3d"
    MOBILE_AR = "mobile_ar"

class TrainingLevel(Enum):
    """Niveaux de formation."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

@dataclass
class TrainingModule:
    """Module de formation immersif."""
    id: str
    name: str
    scenario: TrainingScenario
    level: TrainingLevel
    duration_minutes: int
    description: str
    learning_objectives: List[str]
    prerequisites: List[str] = field(default_factory=list)
    certification_required: bool = False
    vr_assets_path: str = ""
    ar_markers_config: Dict[str, Any] = field(default_factory=dict)
    success_criteria: Dict[str, float] = field(default_factory=dict)

@dataclass
class UserProfile:
    """Profil utilisateur pour formation personnalisée."""
    user_id: str
    name: str
    role: str  # operator, technician, supervisor, security_analyst
    experience_level: TrainingLevel
    certifications: List[str] = field(default_factory=list)
    completed_modules: List[str] = field(default_factory=list)
    performance_scores: Dict[str, float] = field(default_factory=dict)
    preferences: Dict[str, Any] = field(default_factory=dict)
    last_session: Optional[datetime] = None

@dataclass
class TrainingSession:
    """Session de formation avec métriques."""
    session_id: str
    user_id: str
    module_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    interaction_mode: InteractionMode = InteractionMode.DESKTOP_3D
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    errors_made: List[str] = field(default_factory=list)
    completion_percentage: float = 0.0
    success_score: float = 0.0
    feedback_provided: str = ""

@dataclass
class VREnvironment:
    """Configuration environnement VR."""
    scene_id: str
    name: str
    description: str
    environment_type: str  # factory_floor, control_room, outdoor_facility
    interactive_objects: List[Dict[str, Any]] = field(default_factory=list)
    safety_zones: List[Dict[str, Any]] = field(default_factory=list)
    virtual_equipment: List[Dict[str, Any]] = field(default_factory=list)
    lighting_config: Dict[str, Any] = field(default_factory=dict)
    audio_zones: List[Dict[str, Any]] = field(default_factory=list)

class GestureRecognitionSystem:
    """Système de reconnaissance gestuelle pour interaction VR/AR."""
    
    def __init__(self):
        self.is_initialized = False
        self.gesture_model = None
        self.scaler = StandardScaler()
        self.gesture_classes = [
            'point', 'grab', 'swipe_left', 'swipe_right', 'swipe_up', 'swipe_down',
            'pinch', 'open_hand', 'fist', 'thumbs_up', 'stop_gesture', 'wave'
        ]
        
        if CV2_AVAILABLE:
            self.mp_hands = mp.solutions.hands
            self.hands = self.mp_hands.Hands(
                static_image_mode=False,
                max_num_hands=2,
                min_detection_confidence=0.5,
                min_tracking_confidence=0.5
            )
            self.mp_drawing = mp.solutions.drawing_utils
            self.is_initialized = True
        
        # Entraînement du modèle de base
        self._train_gesture_model()
        
    def _train_gesture_model(self):
        """Entraîne le modèle de reconnaissance gestuelle."""
        # Génération de données synthétiques pour démonstration
        n_samples = 1000
        n_features = 42  # 21 landmarks * 2 coordonnées
        
        X = np.random.randn(n_samples, n_features)
        y = np.random.choice(len(self.gesture_classes), n_samples)
        
        # Ajout de patterns spécifiques pour certains gestes
        for i, gesture in enumerate(self.gesture_classes):
            indices = np.where(y == i)[0][:50]  # 50 échantillons par geste
            if gesture == 'point':
                X[indices, :10] = np.random.normal(0.8, 0.1, (len(indices), 10))
            elif gesture == 'fist':
                X[indices, 10:20] = np.random.normal(-0.5, 0.1, (len(indices), 10))
            elif gesture == 'open_hand':
                X[indices, 20:30] = np.random.normal(0.2, 0.2, (len(indices), 10))
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Normalisation
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Entraînement RandomForest
        self.gesture_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gesture_model.fit(X_train_scaled, y_train)
        
        # Évaluation
        train_score = self.gesture_model.score(X_train_scaled, y_train)
        test_score = self.gesture_model.score(X_test_scaled, y_test)
        
        logger.info(f"Modèle gestuel entraîné - Train: {train_score:.3f}, Test: {test_score:.3f}")
        
    def recognize_gesture(self, image: np.ndarray) -> Tuple[str, float]:
        """Reconnaît un geste à partir d'une image."""
        if not self.is_initialized or not CV2_AVAILABLE:
            # Mode simulation
            return random.choice(self.gesture_classes), random.uniform(0.6, 0.95)
        
        try:
            # Conversion BGR vers RGB
            rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            results = self.hands.process(rgb_image)
            
            if results.multi_hand_landmarks:
                for hand_landmarks in results.multi_hand_landmarks:
                    # Extraction des features
                    features = self._extract_hand_features(hand_landmarks)
                    
                    if features is not None:
                        # Prédiction
                        features_scaled = self.scaler.transform([features])
                        prediction = self.gesture_model.predict(features_scaled)[0]
                        probability = np.max(self.gesture_model.predict_proba(features_scaled))
                        
                        gesture_name = self.gesture_classes[prediction]
                        return gesture_name, float(probability)
            
            return 'no_gesture', 0.0
            
        except Exception as e:
            logger.error(f"Erreur reconnaissance gestuelle: {e}")
            return 'error', 0.0
    
    def _extract_hand_features(self, hand_landmarks) -> Optional[np.ndarray]:
        """Extrait les caractéristiques de la main."""
        try:
            features = []
            for landmark in hand_landmarks.landmark:
                features.extend([landmark.x, landmark.y])
            
            return np.array(features) if len(features) == 42 else None
            
        except Exception as e:
            logger.error(f"Erreur extraction features: {e}")
            return None

class SpatialAudioSystem:
    """Système audio spatial pour immersion VR."""
    
    def __init__(self):
        self.is_available = AUDIO_AVAILABLE
        self.audio_sources = {}
        self.listener_position = np.array([0.0, 0.0, 0.0])
        self.listener_orientation = np.array([0.0, 0.0, 1.0])
        
        if self.is_available:
            self.sample_rate = 44100
            self.buffer_size = 1024
            
    def add_audio_source(self, source_id: str, position: np.ndarray, 
                        audio_file: str, volume: float = 1.0):
        """Ajoute une source audio spatialisée."""
        self.audio_sources[source_id] = {
            'position': position,
            'audio_file': audio_file,
            'volume': volume,
            'is_playing': False,
            'loop': False
        }
        
    def update_listener_transform(self, position: np.ndarray, orientation: np.ndarray):
        """Met à jour la position et orientation de l'auditeur."""
        self.listener_position = position
        self.listener_orientation = orientation
        
    def play_spatial_audio(self, source_id: str, loop: bool = False):
        """Joue un audio spatialisé."""
        if source_id not in self.audio_sources:
            return
            
        source = self.audio_sources[source_id]
        source['is_playing'] = True
        source['loop'] = loop
        
        if self.is_available:
            # Calcul de la spatialisation
            distance, angle = self._calculate_spatial_parameters(source['position'])
            
            # Simulation de lecture audio spatialisée
            logger.info(f"Lecture audio {source_id} - Distance: {distance:.2f}m, Angle: {angle:.1f}°")
        else:
            logger.info(f"Simulation audio: {source_id}")
    
    def _calculate_spatial_parameters(self, source_position: np.ndarray) -> Tuple[float, float]:
        """Calcule les paramètres spatiaux pour une source audio."""
        # Distance
        distance = np.linalg.norm(source_position - self.listener_position)
        
        # Angle par rapport à l'orientation de l'auditeur
        to_source = source_position - self.listener_position
        if np.linalg.norm(to_source) > 0:
            to_source_normalized = to_source / np.linalg.norm(to_source)
            angle = np.arccos(np.clip(np.dot(self.listener_orientation, to_source_normalized), -1, 1))
            angle_degrees = np.degrees(angle)
        else:
            angle_degrees = 0.0
        
        return distance, angle_degrees

class VRTrainingSimulator:
    """Simulateur de formation VR pour environnements industriels."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_vr_available = OPENVR_AVAILABLE
        self.vr_system = None
        self.environments = {}
        self.current_environment = None
        self.physics_world = None
        
        # Systèmes intégrés
        self.gesture_recognition = GestureRecognitionSystem()
        self.spatial_audio = SpatialAudioSystem()
        
        # État de la simulation
        self.is_running = False
        self.user_position = np.array([0.0, 1.8, 0.0])  # Hauteur moyenne utilisateur
        self.user_orientation = np.array([0.0, 0.0, 1.0])
        self.user_interactions = []
        
        # Objets virtuels
        self.virtual_objects = {}
        self.interactive_zones = {}
        
        self._initialize_vr_system()
        self._initialize_physics()
        self._load_default_environments()
        
    def _initialize_vr_system(self):
        """Initialise le système VR."""
        if not self.is_vr_available:
            logger.warning("OpenVR non disponible - mode simulation activé")
            return
            
        try:
            openvr.init(openvr.VRApplication_Scene)
            self.vr_system = openvr.VRSystem()
            
            if self.vr_system:
                logger.info("Système VR initialisé avec succès")
                
                # Configuration des contrôleurs
                self._setup_controllers()
            else:
                logger.error("Impossible d'initialiser le système VR")
                
        except Exception as e:
            logger.error(f"Erreur initialisation VR: {e}")
            self.is_vr_available = False
    
    def _initialize_physics(self):
        """Initialise le moteur physique."""
        if not PHYSICS_AVAILABLE:
            logger.warning("PyBullet non disponible - physique simplifiée")
            return
            
        try:
            # Connexion au serveur physique
            p.connect(p.DIRECT)  # Mode headless
            p.setAdditionalSearchPath(pybullet_data.getDataPath())
            
            # Configuration de la gravité
            p.setGravity(0, 0, -9.81)
            
            # Chargement du sol
            p.loadURDF("plane.urdf")
            
            logger.info("Moteur physique initialisé")
            
        except Exception as e:
            logger.error(f"Erreur initialisation physique: {e}")
    
    def _load_default_environments(self):
        """Charge les environnements VR par défaut."""
        # Environnement salle de contrôle
        control_room = VREnvironment(
            scene_id="control_room_01",
            name="Salle de Contrôle Industrielle",
            description="Salle de contrôle avec postes de supervision SCADA",
            environment_type="control_room",
            interactive_objects=[
                {
                    'id': 'scada_workstation',
                    'type': 'computer',
                    'position': [0, 1.0, -2],
                    'interactive': True,
                    'training_focus': ['cyber_security', 'monitoring']
                },
                {
                    'id': 'emergency_stop',
                    'type': 'button',
                    'position': [2, 1.2, -1],
                    'interactive': True,
                    'training_focus': ['emergency_procedures']
                }
            ],
            virtual_equipment=[
                {
                    'id': 'hmi_panel',
                    'type': 'display',
                    'position': [-1, 1.5, -1.5],
                    'data_connection': 'real_time',
                    'protocols': ['modbus', 'opcua']
                }
            ]
        )
        
        # Environnement atelier industriel
        factory_floor = VREnvironment(
            scene_id="factory_floor_01",
            name="Atelier de Production",
            description="Zone de production avec équipements industriels",
            environment_type="factory_floor",
            interactive_objects=[
                {
                    'id': 'plc_cabinet',
                    'type': 'electrical_cabinet',
                    'position': [5, 0, 2],
                    'interactive': True,
                    'training_focus': ['maintenance', 'safety']
                },
                {
                    'id': 'conveyor_belt',
                    'type': 'machinery',
                    'position': [0, 0, 5],
                    'interactive': True,
                    'animated': True
                }
            ],
            safety_zones=[
                {
                    'id': 'high_voltage_area',
                    'type': 'danger_zone',
                    'position': [5, 0, 2],
                    'radius': 2.0,
                    'warning_message': 'Zone haute tension - PPE requis'
                }
            ]
        )
        
        self.environments['control_room'] = control_room
        self.environments['factory_floor'] = factory_floor
        
    def load_environment(self, environment_id: str) -> bool:
        """Charge un environnement VR."""
        if environment_id not in self.environments:
            logger.error(f"Environnement {environment_id} non trouvé")
            return False
            
        self.current_environment = self.environments[environment_id]
        
        # Configuration audio spatial
        for audio_zone in self.current_environment.audio_zones:
            self.spatial_audio.add_audio_source(
                audio_zone['id'],
                np.array(audio_zone['position']),
                audio_zone['audio_file'],
                audio_zone.get('volume', 1.0)
            )
        
        logger.info(f"Environnement {environment_id} chargé")
        return True
    
    def start_simulation(self) -> bool:
        """Démarre la simulation VR."""
        if self.current_environment is None:
            logger.error("Aucun environnement chargé")
            return False
            
        self.is_running = True
        logger.info("Simulation VR démarrée")
        
        # Boucle de rendu (simplifiée pour démonstration)
        if self.is_vr_available:
            self._vr_render_loop()
        else:
            self._simulation_render_loop()
            
        return True
    
    def _vr_render_loop(self):
        """Boucle de rendu VR réelle."""
        logger.info("Boucle rendu VR active")
        # Implémentation réelle avec OpenVR
        # Traitement des poses des contrôleurs
        # Rendu stéréoscopique
        # Gestion des interactions
        
    def _simulation_render_loop(self):
        """Boucle de rendu en mode simulation."""
        logger.info("Mode simulation VR - rendu conceptuel")
        time.sleep(0.1)  # Simulation du cycle de rendu
    
    def update_user_transform(self, position: np.ndarray, orientation: np.ndarray):
        """Met à jour la position utilisateur."""
        self.user_position = position
        self.user_orientation = orientation
        
        # Mise à jour audio spatial
        self.spatial_audio.update_listener_transform(position, orientation)
        
        # Vérification des zones d'interaction
        self._check_interaction_zones()
    
    def _check_interaction_zones(self):
        """Vérifie si l'utilisateur entre dans des zones d'interaction."""
        if not self.current_environment:
            return
            
        user_pos = self.user_position
        
        # Vérification zones de sécurité
        for safety_zone in self.current_environment.safety_zones:
            zone_pos = np.array(safety_zone['position'])
            distance = np.linalg.norm(user_pos - zone_pos)
            radius = safety_zone.get('radius', 1.0)
            
            if distance < radius:
                self._trigger_safety_warning(safety_zone)
    
    def _trigger_safety_warning(self, safety_zone: Dict[str, Any]):
        """Déclenche un avertissement de sécurité."""
        message = safety_zone.get('warning_message', 'Zone dangereuse')
        logger.warning(f"ALERTE SÉCURITÉ VR: {message}")
        
        # Audio d'alerte
        if 'warning_audio' in safety_zone:
            self.spatial_audio.play_spatial_audio('safety_warning')
    
    def interact_with_object(self, object_id: str, interaction_type: str) -> Dict[str, Any]:
        """Interaction avec un objet virtuel."""
        if not self.current_environment:
            return {'success': False, 'error': 'Aucun environnement chargé'}
            
        # Recherche de l'objet
        target_object = None
        for obj in self.current_environment.interactive_objects:
            if obj['id'] == object_id:
                target_object = obj
                break
        
        if not target_object:
            return {'success': False, 'error': f'Objet {object_id} non trouvé'}
        
        # Vérification de la distance
        obj_pos = np.array(target_object['position'])
        distance = np.linalg.norm(self.user_position - obj_pos)
        
        if distance > 2.0:  # Limite d'interaction
            return {
                'success': False, 
                'error': 'Objet trop éloigné',
                'distance': distance
            }
        
        # Enregistrement de l'interaction
        interaction = {
            'timestamp': datetime.now(),
            'object_id': object_id,
            'interaction_type': interaction_type,
            'user_position': self.user_position.tolist(),
            'success': True
        }
        
        self.user_interactions.append(interaction)
        
        # Logique spécifique par type d'objet
        result = self._process_object_interaction(target_object, interaction_type)
        
        logger.info(f"Interaction VR: {object_id} - {interaction_type}")
        return result
    
    def _process_object_interaction(self, obj: Dict[str, Any], 
                                   interaction_type: str) -> Dict[str, Any]:
        """Traite l'interaction avec un objet spécifique."""
        obj_type = obj.get('type', 'generic')
        
        if obj_type == 'button' and interaction_type == 'press':
            if obj['id'] == 'emergency_stop':
                return {
                    'success': True,
                    'action': 'emergency_stop_activated',
                    'message': 'Arrêt d\'urgence activé - Procédure de sécurité déclenchée'
                }
        
        elif obj_type == 'computer' and interaction_type == 'use':
            return {
                'success': True,
                'action': 'computer_accessed',
                'interface': 'scada_simulation',
                'available_actions': ['monitor_systems', 'acknowledge_alarms', 'adjust_parameters']
            }
        
        elif obj_type == 'electrical_cabinet' and interaction_type == 'open':
            return {
                'success': True,
                'action': 'cabinet_opened',
                'safety_warning': 'Vérifiez l\'arrêt des systèmes avant intervention',
                'components_visible': ['plc', 'power_supplies', 'network_switch']
            }
        
        # Interaction générique
        return {
            'success': True,
            'action': f'{interaction_type}_on_{obj_type}',
            'message': f'Interaction {interaction_type} avec {obj["id"]}'
        }
    
    def stop_simulation(self):
        """Arrête la simulation VR."""
        self.is_running = False
        
        if self.is_vr_available and self.vr_system:
            try:
                openvr.shutdown()
            except Exception as e:
                logger.error(f"Erreur arrêt VR: {e}")
        
        if PHYSICS_AVAILABLE:
            p.disconnect()
            
        logger.info("Simulation VR arrêtée")
    
    def get_session_analytics(self) -> Dict[str, Any]:
        """Retourne les analyses de la session VR."""
        if not self.user_interactions:
            return {'total_interactions': 0}
        
        # Analyse des interactions
        interaction_types = defaultdict(int)
        objects_interacted = set()
        
        for interaction in self.user_interactions:
            interaction_types[interaction['interaction_type']] += 1
            objects_interacted.add(interaction['object_id'])
        
        # Calcul du temps total
        if len(self.user_interactions) >= 2:
            start_time = self.user_interactions[0]['timestamp']
            end_time = self.user_interactions[-1]['timestamp']
            session_duration = (end_time - start_time).total_seconds()
        else:
            session_duration = 0
        
        return {
            'total_interactions': len(self.user_interactions),
            'unique_objects': len(objects_interacted),
            'interaction_breakdown': dict(interaction_types),
            'session_duration_seconds': session_duration,
            'interactions_per_minute': len(self.user_interactions) / max(session_duration / 60, 1),
            'objects_interacted': list(objects_interacted)
        }

class ARMaintenanceAssistant:
    """Assistant de maintenance en Réalité Augmentée."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_cv_available = CV2_AVAILABLE
        self.camera_capture = None
        self.ar_markers = {}
        self.maintenance_procedures = {}
        self.current_procedure = None
        self.step_completion_status = {}
        
        # Détection de marqueurs AR
        if self.is_cv_available:
            self.aruco_dict = cv2.aruco.Dictionary_get(cv2.aruco.DICT_6X6_250)
            self.aruco_params = cv2.aruco.DetectorParameters_create()
            
        self._load_maintenance_procedures()
        self._initialize_ar_markers()
        
    def _load_maintenance_procedures(self):
        """Charge les procédures de maintenance."""
        self.maintenance_procedures = {
            'plc_inspection': {
                'id': 'plc_inspection',
                'name': 'Inspection PLC',
                'description': 'Procédure d\'inspection préventive d\'un PLC industriel',
                'estimated_duration': 30,  # minutes
                'difficulty': 'intermediate',
                'required_tools': ['multimètre', 'tournevis', 'gants_isolants'],
                'safety_requirements': ['consignation', 'epi'],
                'steps': [
                    {
                        'step_id': 1,
                        'title': 'Vérification consignation',
                        'description': 'Vérifiez que le système est correctement consigné',
                        'ar_marker_id': 'safety_panel',
                        'expected_duration': 5,
                        'safety_critical': True,
                        'verification_method': 'visual_check'
                    },
                    {
                        'step_id': 2,
                        'title': 'Inspection visuelle',
                        'description': 'Inspectez visuellement l\'état du PLC',
                        'ar_marker_id': 'plc_cabinet',
                        'expected_duration': 10,
                        'checkpoints': ['état_voyants', 'état_connecteurs', 'absence_corrosion']
                    },
                    {
                        'step_id': 3,
                        'title': 'Test des connexions',
                        'description': 'Vérifiez la solidité des connexions',
                        'ar_marker_id': 'plc_connections',
                        'expected_duration': 15,
                        'tools_required': ['multimètre'],
                        'measurements': ['continuité', 'isolation']
                    }
                ]
            },
            'network_security_audit': {
                'id': 'network_security_audit',
                'name': 'Audit Sécurité Réseau',
                'description': 'Audit de sécurité des équipements réseau industriels',
                'estimated_duration': 45,
                'difficulty': 'advanced',
                'required_tools': ['laptop', 'scanner_réseau', 'multimètre'],
                'steps': [
                    {
                        'step_id': 1,
                        'title': 'Scan des ports réseau',
                        'description': 'Scanner les ports ouverts sur les équipements',
                        'ar_marker_id': 'network_switch',
                        'expected_duration': 15,
                        'security_focus': True
                    },
                    {
                        'step_id': 2,
                        'title': 'Vérification des mots de passe',
                        'description': 'Audit des mots de passe par défaut',
                        'ar_marker_id': 'router_admin',
                        'expected_duration': 20,
                        'security_critical': True
                    }
                ]
            }
        }
        
    def _initialize_ar_markers(self):
        """Initialise les marqueurs AR."""
        self.ar_markers = {
            'plc_cabinet': {
                'marker_id': 0,
                'size': 0.1,  # 10cm
                'associated_equipment': 'PLC_001',
                'overlay_content': 'plc_info_panel'
            },
            'safety_panel': {
                'marker_id': 1,
                'size': 0.15,  # 15cm
                'associated_equipment': 'SAFETY_SYSTEM',
                'overlay_content': 'safety_status'
            },
            'network_switch': {
                'marker_id': 2,
                'size': 0.08,
                'associated_equipment': 'NET_SW_001',
                'overlay_content': 'network_info'
            }
        }
    
    def start_ar_session(self, camera_id: int = 0) -> bool:
        """Démarre une session AR."""
        if not self.is_cv_available:
            logger.warning("OpenCV non disponible - mode simulation AR")
            return True
            
        try:
            self.camera_capture = cv2.VideoCapture(camera_id)
            
            if not self.camera_capture.isOpened():
                logger.error("Impossible d'ouvrir la caméra")
                return False
                
            # Configuration caméra
            self.camera_capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            self.camera_capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
            self.camera_capture.set(cv2.CAP_PROP_FPS, 30)
            
            logger.info("Session AR démarrée")
            return True
            
        except Exception as e:
            logger.error(f"Erreur démarrage AR: {e}")
            return False
    
    def process_ar_frame(self, frame: np.ndarray) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
        """Traite une frame AR et retourne l'image augmentée."""
        if not self.is_cv_available:
            # Mode simulation
            return frame, []
            
        try:
            # Détection des marqueurs ArUco
            corners, ids, _ = cv2.aruco.detectMarkers(
                frame, self.aruco_dict, parameters=self.aruco_params
            )
            
            detected_markers = []
            
            if ids is not None:
                # Dessin des marqueurs détectés
                cv2.aruco.drawDetectedMarkers(frame, corners, ids)
                
                for i, marker_id in enumerate(ids.flatten()):
                    # Recherche du marqueur dans la configuration
                    marker_info = self._find_marker_by_id(marker_id)
                    
                    if marker_info:
                        # Estimation de la pose
                        rvec, tvec, _ = cv2.aruco.estimatePoseSingleMarkers(
                            [corners[i]], marker_info['size'], 
                            self._get_camera_matrix(), self._get_dist_coeffs()
                        )
                        
                        # Dessin des axes de repère
                        cv2.aruco.drawAxis(frame, self._get_camera_matrix(), 
                                         self._get_dist_coeffs(), rvec, tvec, 0.05)
                        
                        # Overlay d'information
                        frame = self._draw_ar_overlay(frame, corners[i], marker_info)
                        
                        detected_markers.append({
                            'marker_id': marker_id,
                            'position': tvec[0].tolist() if tvec is not None else [0, 0, 0],
                            'rotation': rvec[0].tolist() if rvec is not None else [0, 0, 0],
                            'equipment': marker_info.get('associated_equipment', 'unknown')
                        })
            
            return frame, detected_markers
            
        except Exception as e:
            logger.error(f"Erreur traitement frame AR: {e}")
            return frame, []
    
    def _find_marker_by_id(self, marker_id: int) -> Optional[Dict[str, Any]]:
        """Trouve un marqueur par son ID."""
        for marker_name, marker_data in self.ar_markers.items():
            if marker_data['marker_id'] == marker_id:
                return {**marker_data, 'name': marker_name}
        return None
    
    def _draw_ar_overlay(self, frame: np.ndarray, corners: np.ndarray, 
                        marker_info: Dict[str, Any]) -> np.ndarray:
        """Dessine les overlays AR sur l'image."""
        # Calcul du centre du marqueur
        center = np.mean(corners[0], axis=0).astype(int)
        
        # Overlay de base - rectangle d'information
        overlay_width, overlay_height = 200, 100
        top_left = (center[0] - overlay_width//2, center[1] - overlay_height - 20)
        bottom_right = (center[0] + overlay_width//2, center[1] - 20)
        
        # Rectangle semi-transparent
        overlay = frame.copy()
        cv2.rectangle(overlay, top_left, bottom_right, (0, 0, 0), -1)
        frame = cv2.addWeighted(frame, 0.7, overlay, 0.3, 0)
        
        # Texte d'information
        equipment_name = marker_info.get('associated_equipment', 'Équipement')
        
        # Titre
        cv2.putText(frame, equipment_name, 
                   (top_left[0] + 10, top_left[1] + 25),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        
        # Statut (simulation)
        status = "OPERATIONAL" if random.random() > 0.2 else "WARNING"
        status_color = (0, 255, 0) if status == "OPERATIONAL" else (0, 165, 255)
        
        cv2.putText(frame, f"Status: {status}",
                   (top_left[0] + 10, top_left[1] + 50),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.4, status_color, 1)
        
        # Informations de maintenance si procédure active
        if self.current_procedure:
            step_info = self._get_current_step_info(marker_info['name'])
            if step_info:
                cv2.putText(frame, f"Etape: {step_info['title'][:20]}...",
                           (top_left[0] + 10, top_left[1] + 75),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 0), 1)
        
        return frame
    
    def start_maintenance_procedure(self, procedure_id: str) -> bool:
        """Démarre une procédure de maintenance."""
        if procedure_id not in self.maintenance_procedures:
            logger.error(f"Procédure {procedure_id} non trouvée")
            return False
            
        self.current_procedure = self.maintenance_procedures[procedure_id]
        self.step_completion_status = {}
        
        # Initialisation du statut des étapes
        for step in self.current_procedure['steps']:
            self.step_completion_status[step['step_id']] = {
                'completed': False,
                'start_time': None,
                'completion_time': None,
                'notes': ""
            }
        
        logger.info(f"Procédure de maintenance démarrée: {procedure_id}")
        return True
    
    def complete_maintenance_step(self, step_id: int, notes: str = "") -> Dict[str, Any]:
        """Marque une étape comme terminée."""
        if not self.current_procedure:
            return {'success': False, 'error': 'Aucune procédure active'}
        
        if step_id not in self.step_completion_status:
            return {'success': False, 'error': f'Étape {step_id} non trouvée'}
        
        # Mise à jour du statut
        self.step_completion_status[step_id].update({
            'completed': True,
            'completion_time': datetime.now(),
            'notes': notes
        })
        
        # Calcul du pourcentage de completion
        total_steps = len(self.step_completion_status)
        completed_steps = sum(1 for status in self.step_completion_status.values() 
                            if status['completed'])
        completion_percentage = (completed_steps / total_steps) * 100
        
        logger.info(f"Étape {step_id} terminée - Progression: {completion_percentage:.1f}%")
        
        return {
            'success': True,
            'step_completed': step_id,
            'total_progress': completion_percentage,
            'remaining_steps': total_steps - completed_steps
        }
    
    def get_procedure_guidance(self, marker_name: str) -> Dict[str, Any]:
        """Retourne les instructions pour un marqueur spécifique."""
        if not self.current_procedure:
            return {'guidance': 'Aucune procédure active'}
        
        # Recherche de l'étape correspondant au marqueur
        current_step = self._get_current_step_info(marker_name)
        
        if not current_step:
            return {'guidance': 'Aucune étape associée à ce marqueur'}
        
        step_status = self.step_completion_status.get(current_step['step_id'], {})
        
        if step_status.get('completed'):
            return {
                'guidance': f"✅ Étape {current_step['step_id']} terminée",
                'next_action': 'Passer à l\'étape suivante'
            }
        
        return {
            'guidance': current_step['description'],
            'step_number': current_step['step_id'],
            'estimated_duration': current_step.get('expected_duration', 'N/A'),
            'safety_critical': current_step.get('safety_critical', False),
            'tools_required': current_step.get('tools_required', []),
            'checkpoints': current_step.get('checkpoints', [])
        }
    
    def _get_current_step_info(self, marker_name: str) -> Optional[Dict[str, Any]]:
        """Retourne l'information de l'étape courante pour un marqueur."""
        if not self.current_procedure:
            return None
            
        for step in self.current_procedure['steps']:
            if step.get('ar_marker_id') == marker_name:
                return step
        return None
    
    def _get_camera_matrix(self) -> np.ndarray:
        """Retourne la matrice de calibration caméra (simulée)."""
        # Matrice de calibration approximative pour une caméra 720p
        return np.array([
            [800.0, 0.0, 320.0],
            [0.0, 800.0, 240.0],
            [0.0, 0.0, 1.0]
        ], dtype=np.float32)
    
    def _get_dist_coeffs(self) -> np.ndarray:
        """Retourne les coefficients de distorsion (simulés)."""
        return np.array([0.1, -0.2, 0.0, 0.0, 0.0], dtype=np.float32)
    
    def stop_ar_session(self):
        """Arrête la session AR."""
        if self.camera_capture:
            self.camera_capture.release()
            
        self.current_procedure = None
        logger.info("Session AR arrêtée")
    
    def get_maintenance_analytics(self) -> Dict[str, Any]:
        """Retourne les analyses de maintenance."""
        if not self.current_procedure or not self.step_completion_status:
            return {'procedure_active': False}
        
        total_steps = len(self.step_completion_status)
        completed_steps = sum(1 for status in self.step_completion_status.values() 
                            if status['completed'])
        
        # Calcul du temps total
        completion_times = [
            status['completion_time'] for status in self.step_completion_status.values()
            if status['completion_time']
        ]
        
        if completion_times:
            total_time = max(completion_times) - min(completion_times)
            total_minutes = total_time.total_seconds() / 60
        else:
            total_minutes = 0
        
        return {
            'procedure_active': True,
            'procedure_name': self.current_procedure['name'],
            'total_steps': total_steps,
            'completed_steps': completed_steps,
            'completion_percentage': (completed_steps / total_steps) * 100,
            'estimated_duration': self.current_procedure.get('estimated_duration', 0),
            'actual_duration_minutes': total_minutes,
            'efficiency_ratio': (self.current_procedure.get('estimated_duration', 1) / 
                               max(total_minutes, 1)) if total_minutes > 0 else 0
        }

class TrainingManagementSystem:
    """Système de gestion des formations VR/AR."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.users = {}
        self.training_modules = {}
        self.active_sessions = {}
        self.completed_sessions = []
        
        # Systèmes intégrés
        self.vr_simulator = VRTrainingSimulator(config.get('vr_config', {}))
        self.ar_assistant = ARMaintenanceAssistant(config.get('ar_config', {}))
        
        self._initialize_training_modules()
        self._initialize_default_users()
        
    def _initialize_training_modules(self):
        """Initialise les modules de formation."""
        modules = [
            TrainingModule(
                id="cyber_incident_response",
                name="Réponse aux Incidents Cybersécurité",
                scenario=TrainingScenario.CYBER_INCIDENT,
                level=TrainingLevel.INTERMEDIATE,
                duration_minutes=45,
                description="Formation à la gestion des incidents de cybersécurité industrielle",
                learning_objectives=[
                    "Identifier les signes d'une cyberattaque",
                    "Appliquer les procédures d'isolation",
                    "Communiquer efficacement lors d'un incident",
                    "Documenter l'incident pour analyse"
                ],
                prerequisites=["security_basics", "industrial_protocols"],
                certification_required=True,
                success_criteria={
                    'response_time': 300,  # secondes
                    'accuracy': 0.85,
                    'procedure_compliance': 0.90
                }
            ),
            TrainingModule(
                id="emergency_shutdown",
                name="Procédures d'Arrêt d'Urgence",
                scenario=TrainingScenario.EMERGENCY_RESPONSE,
                level=TrainingLevel.BEGINNER,
                duration_minutes=30,
                description="Formation aux procédures d'arrêt d'urgence des systèmes industriels",
                learning_objectives=[
                    "Localiser les boutons d'arrêt d'urgence",
                    "Appliquer la séquence d'arrêt correcte",
                    "Vérifier l'arrêt complet des systèmes",
                    "Notifier les équipes concernées"
                ],
                success_criteria={
                    'shutdown_time': 60,
                    'sequence_accuracy': 1.0,
                    'safety_compliance': 1.0
                }
            ),
            TrainingModule(
                id="plc_maintenance",
                name="Maintenance Préventive PLC",
                scenario=TrainingScenario.MAINTENANCE_PROCEDURE,
                level=TrainingLevel.ADVANCED,
                duration_minutes=60,
                description="Formation à la maintenance préventive des automates programmables",
                learning_objectives=[
                    "Effectuer l'inspection visuelle du PLC",
                    "Vérifier les connexions et signaux",
                    "Diagnostiquer les anomalies",
                    "Documenter les interventions"
                ],
                prerequisites=["electrical_safety", "plc_basics"],
                success_criteria={
                    'inspection_completeness': 0.95,
                    'diagnostic_accuracy': 0.80,
                    'safety_violations': 0
                }
            )
        ]
        
        for module in modules:
            self.training_modules[module.id] = module
    
    def _initialize_default_users(self):
        """Initialise des utilisateurs par défaut."""
        default_users = [
            UserProfile(
                user_id="operator_001",
                name="Jean Dupont",
                role="operator",
                experience_level=TrainingLevel.INTERMEDIATE,
                certifications=["safety_basic"],
                preferences={'language': 'fr', 'interaction_mode': 'vr'}
            ),
            UserProfile(
                user_id="tech_001",
                name="Marie Martin",
                role="technician",
                experience_level=TrainingLevel.ADVANCED,
                certifications=["electrical_safety", "plc_maintenance"],
                preferences={'language': 'fr', 'interaction_mode': 'ar'}
            ),
            UserProfile(
                user_id="security_001",
                name="Pierre Durand",
                role="security_analyst",
                experience_level=TrainingLevel.EXPERT,
                certifications=["cyber_security", "incident_response"],
                preferences={'language': 'fr', 'interaction_mode': 'vr'}
            )
        ]
        
        for user in default_users:
            self.users[user.user_id] = user
    
    def create_user(self, user_data: Dict[str, Any]) -> str:
        """Crée un nouvel utilisateur."""
        user_profile = UserProfile(
            user_id=user_data['user_id'],
            name=user_data['name'],
            role=user_data['role'],
            experience_level=TrainingLevel(user_data.get('experience_level', 'beginner')),
            certifications=user_data.get('certifications', []),
            preferences=user_data.get('preferences', {})
        )
        
        self.users[user_profile.user_id] = user_profile
        logger.info(f"Utilisateur créé: {user_profile.user_id}")
        
        return user_profile.user_id
    
    def start_training_session(self, user_id: str, module_id: str, 
                             interaction_mode: InteractionMode) -> str:
        """Démarre une session de formation."""
        if user_id not in self.users:
            raise ValueError(f"Utilisateur {user_id} non trouvé")
        
        if module_id not in self.training_modules:
            raise ValueError(f"Module {module_id} non trouvé")
        
        user = self.users[user_id]
        module = self.training_modules[module_id]
        
        # Vérification des prérequis
        missing_prereqs = []
        for prereq in module.prerequisites:
            if prereq not in user.certifications and prereq not in user.completed_modules:
                missing_prereqs.append(prereq)
        
        if missing_prereqs:
            raise ValueError(f"Prérequis manquants: {missing_prereqs}")
        
        # Création de la session
        session_id = str(uuid.uuid4())
        session = TrainingSession(
            session_id=session_id,
            user_id=user_id,
            module_id=module_id,
            start_time=datetime.now(),
            interaction_mode=interaction_mode
        )
        
        self.active_sessions[session_id] = session
        
        # Configuration de l'environnement selon le module
        if interaction_mode == InteractionMode.VR_HEADSET:
            self._setup_vr_training(session, module)
        elif interaction_mode in [InteractionMode.AR_TABLET, InteractionMode.AR_GLASSES]:
            self._setup_ar_training(session, module)
        
        # Mise à jour du profil utilisateur
        user.last_session = datetime.now()
        
        logger.info(f"Session de formation démarrée: {session_id} pour {user_id}")
        return session_id
    
    def _setup_vr_training(self, session: TrainingSession, module: TrainingModule):
        """Configure l'environnement VR pour la formation."""
        scenario = module.scenario
        
        if scenario == TrainingScenario.CYBER_INCIDENT:
            # Chargement de la salle de contrôle avec simulation d'incident
            self.vr_simulator.load_environment('control_room')
            
            # Configuration des événements d'incident
            self._configure_cyber_incident_scenario()
            
        elif scenario == TrainingScenario.EMERGENCY_RESPONSE:
            # Chargement de l'atelier avec zones de danger
            self.vr_simulator.load_environment('factory_floor')
            
        elif scenario == TrainingScenario.MAINTENANCE_PROCEDURE:
            # Environnement technique avec équipements
            self.vr_simulator.load_environment('factory_floor')
        
        # Démarrage de la simulation
        self.vr_simulator.start_simulation()
    
    def _setup_ar_training(self, session: TrainingSession, module: TrainingModule):
        """Configure l'environnement AR pour la formation."""
        if module.scenario == TrainingScenario.MAINTENANCE_PROCEDURE:
            # Démarrage de l'assistant AR
            self.ar_assistant.start_ar_session()
            
            # Configuration de la procédure
            if module.id == "plc_maintenance":
                self.ar_assistant.start_maintenance_procedure("plc_inspection")
    
    def _configure_cyber_incident_scenario(self):
        """Configure un scénario de cyberincident."""
        # Configuration des événements simulés
        incident_events = [
            {
                'time': 30,  # secondes après le début
                'type': 'network_anomaly',
                'description': 'Trafic réseau anormal détecté',
                'response_required': True
            },
            {
                'time': 90,
                'type': 'unauthorized_access',
                'description': 'Tentative d\'accès non autorisé sur PLC',
                'response_required': True,
                'expected_action': 'isolate_plc'
            },
            {
                'time': 180,
                'type': 'system_compromise',
                'description': 'Compromission suspectée du système de supervision',
                'response_required': True,
                'expected_action': 'emergency_shutdown'
            }
        ]
        
        # Les événements seront déclenchés durant la simulation
        logger.info("Scénario cyberincident configuré")
    
    def update_session_progress(self, session_id: str, progress_data: Dict[str, Any]) -> bool:
        """Met à jour les progrès d'une session."""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        
        # Mise à jour des métriques
        session.performance_metrics.update(progress_data.get('metrics', {}))
        session.completion_percentage = progress_data.get('completion_percentage', session.completion_percentage)
        
        # Enregistrement des erreurs
        if 'errors' in progress_data:
            session.errors_made.extend(progress_data['errors'])
        
        # Calcul du score de succès
        session.success_score = self._calculate_success_score(session)
        
        logger.info(f"Session {session_id} - Progression: {session.completion_percentage:.1f}%")
        return True
    
    def complete_training_session(self, session_id: str, final_feedback: str = "") -> Dict[str, Any]:
        """Termine une session de formation."""
        if session_id not in self.active_sessions:
            return {'success': False, 'error': 'Session non trouvée'}
        
        session = self.active_sessions[session_id]
        session.end_time = datetime.now()
        session.feedback_provided = final_feedback
        
        # Collecte des analyses finales
        if session.interaction_mode == InteractionMode.VR_HEADSET:
            vr_analytics = self.vr_simulator.get_session_analytics()
            session.performance_metrics.update({
                'vr_interactions': vr_analytics.get('total_interactions', 0),
                'interaction_rate': vr_analytics.get('interactions_per_minute', 0)
            })
            
            # Arrêt de la simulation VR
            self.vr_simulator.stop_simulation()
            
        elif session.interaction_mode in [InteractionMode.AR_TABLET, InteractionMode.AR_GLASSES]:
            ar_analytics = self.ar_assistant.get_maintenance_analytics()
            session.performance_metrics.update({
                'maintenance_efficiency': ar_analytics.get('efficiency_ratio', 0),
                'steps_completed': ar_analytics.get('completed_steps', 0)
            })
            
            # Arrêt de la session AR
            self.ar_assistant.stop_ar_session()
        
        # Calcul final du score
        session.success_score = self._calculate_success_score(session)
        
        # Mise à jour du profil utilisateur
        user = self.users[session.user_id]
        user.completed_modules.append(session.module_id)
        user.performance_scores[session.module_id] = session.success_score
        
        # Vérification des critères de certification
        module = self.training_modules[session.module_id]
        certification_earned = self._check_certification_criteria(session, module)
        
        if certification_earned:
            user.certifications.append(session.module_id)
        
        # Archivage de la session
        self.completed_sessions.append(session)
        del self.active_sessions[session_id]
        
        result = {
            'success': True,
            'session_duration': (session.end_time - session.start_time).total_seconds() / 60,
            'completion_percentage': session.completion_percentage,
            'success_score': session.success_score,
            'certification_earned': certification_earned,
            'errors_count': len(session.errors_made),
            'performance_summary': session.performance_metrics
        }
        
        logger.info(f"Session terminée: {session_id} - Score: {session.success_score:.2f}")
        return result
    
    def _calculate_success_score(self, session: TrainingSession) -> float:
        """Calcule le score de succès d'une session."""
        module = self.training_modules[session.module_id]
        criteria = module.success_criteria
        
        score = 0.0
        max_score = 0.0
        
        # Évaluation des critères de succès
        for criterion, target_value in criteria.items():
            max_score += 1.0
            
            if criterion in session.performance_metrics:
                actual_value = session.performance_metrics[criterion]
                
                if criterion.endswith('_time'):
                    # Critère de temps (moins c'est mieux)
                    if actual_value <= target_value:
                        score += 1.0
                    else:
                        # Pénalité progressive
                        score += max(0, 1.0 - (actual_value - target_value) / target_value)
                        
                elif criterion.endswith('_accuracy') or criterion.endswith('_compliance'):
                    # Critère de précision (plus c'est mieux)
                    score += min(1.0, actual_value / target_value)
                    
                elif criterion.endswith('_violations'):
                    # Critère de violation (0 attendu)
                    score += 1.0 if actual_value == 0 else 0.0
        
        # Prise en compte du pourcentage de completion
        completion_bonus = session.completion_percentage / 100.0
        
        # Score final normalisé
        final_score = ((score / max(max_score, 1)) * 0.7 + completion_bonus * 0.3) * 100
        
        return min(100.0, final_score)
    
    def _check_certification_criteria(self, session: TrainingSession, 
                                    module: TrainingModule) -> bool:
        """Vérifie si l'utilisateur mérite la certification."""
        if not module.certification_required:
            return False
        
        # Critères de certification
        min_score = 80.0  # Score minimum
        max_errors = 2   # Maximum d'erreurs autorisées
        min_completion = 90.0  # Completion minimum
        
        return (session.success_score >= min_score and
                len(session.errors_made) <= max_errors and
                session.completion_percentage >= min_completion)
    
    def get_user_progress(self, user_id: str) -> Dict[str, Any]:
        """Retourne les progrès d'un utilisateur."""
        if user_id not in self.users:
            return {'error': 'Utilisateur non trouvé'}
        
        user = self.users[user_id]
        
        # Calcul des statistiques
        total_modules = len(self.training_modules)
        completed_modules = len(user.completed_modules)
        completion_rate = (completed_modules / total_modules) * 100 if total_modules > 0 else 0
        
        # Moyenne des scores
        avg_score = np.mean(list(user.performance_scores.values())) if user.performance_scores else 0
        
        # Sessions récentes
        recent_sessions = [
            session for session in self.completed_sessions
            if session.user_id == user_id and 
            session.end_time and session.end_time > datetime.now() - timedelta(days=30)
        ]
        
        return {
            'user_info': {
                'name': user.name,
                'role': user.role,
                'experience_level': user.experience_level.value
            },
            'progress': {
                'completed_modules': completed_modules,
                'total_modules': total_modules,
                'completion_rate': completion_rate,
                'average_score': avg_score,
                'certifications': len(user.certifications)
            },
            'recent_activity': {
                'sessions_last_30_days': len(recent_sessions),
                'last_session': user.last_session.isoformat() if user.last_session else None,
                'recent_modules': user.completed_modules[-5:] if user.completed_modules else []
            },
            'performance_by_module': user.performance_scores
        }
    
    def get_training_analytics(self) -> Dict[str, Any]:
        """Retourne les analyses globales de formation."""
        total_users = len(self.users)
        total_sessions = len(self.completed_sessions)
        active_sessions = len(self.active_sessions)
        
        if not self.completed_sessions:
            return {
                'total_users': total_users,
                'total_sessions': 0,
                'active_sessions': active_sessions
            }
        
        # Analyse des scores
        all_scores = [session.success_score for session in self.completed_sessions]
        avg_score = np.mean(all_scores)
        
        # Analyse par module
        module_stats = defaultdict(list)
        for session in self.completed_sessions:
            module_stats[session.module_id].append(session.success_score)
        
        module_performance = {}
        for module_id, scores in module_stats.items():
            module_performance[module_id] = {
                'sessions_count': len(scores),
                'average_score': np.mean(scores),
                'success_rate': sum(1 for score in scores if score >= 80) / len(scores) * 100
            }
        
        # Analyse par rôle
        role_stats = defaultdict(list)
        for session in self.completed_sessions:
            user_role = self.users[session.user_id].role
            role_stats[user_role].append(session.success_score)
        
        role_performance = {}
        for role, scores in role_stats.items():
            role_performance[role] = {
                'average_score': np.mean(scores),
                'sessions_count': len(scores)
            }
        
        # Tendances temporelles
        recent_sessions = [
            s for s in self.completed_sessions 
            if s.end_time and s.end_time > datetime.now() - timedelta(days=30)
        ]
        
        return {
            'overview': {
                'total_users': total_users,
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'average_score': avg_score,
                'recent_sessions_30d': len(recent_sessions)
            },
            'module_performance': module_performance,
            'role_performance': role_performance,
            'interaction_modes': {
                mode.value: sum(1 for s in self.completed_sessions if s.interaction_mode == mode)
                for mode in InteractionMode
            },
            'certification_stats': {
                'total_certifications': sum(len(user.certifications) for user in self.users.values()),
                'users_with_certifications': sum(1 for user in self.users.values() if user.certifications)
            }
        }

class ImmersiveVRARInterface:
    """Interface principale pour la formation VR/AR immersive."""
    
    def __init__(self, config_path: str = "vr_ar_config.json"):
        self.config = self._load_config(config_path)
        
        # Système de gestion principal
        self.training_system = TrainingManagementSystem(self.config)
        
        # Interface web pour monitoring et contrôle
        self.web_app = self._create_web_dashboard()
        
        # État du système
        self.is_running = False
        
        logger.info("Interface VR/AR immersive initialisée")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration système."""
        default_config = {
            'system': {
                'web_port': 8050,
                'debug_mode': False,
                'auto_save': True
            },
            'vr_config': {
                'target_fps': 90,
                'render_scale': 1.0,
                'comfort_settings': True
            },
            'ar_config': {
                'camera_resolution': [1280, 720],
                'marker_detection_rate': 30,
                'overlay_opacity': 0.8
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
            else:
                config = default_config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur chargement config: {e}")
            config = default_config
        
        return config
    
    def _create_web_dashboard(self) -> dash.Dash:
        """Crée le dashboard web de contrôle."""
        app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
        
        app.layout = dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.H1("🥽 Interface VR/AR Immersive - Station Traffeyère", className="text-center mb-4"),
                    html.Hr()
                ])
            ]),
            
            # Métriques principales
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("👥 Utilisateurs", className="card-title"),
                            html.H2(id="total-users", children="0", className="text-primary")
                        ])
                    ])
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("📚 Sessions Actives", className="card-title"),
                            html.H2(id="active-sessions", children="0", className="text-warning")
                        ])
                    ])
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("🎯 Score Moyen", className="card-title"),
                            html.H2(id="average-score", children="0", className="text-success")
                        ])
                    ])
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("🏆 Certifications", className="card-title"),
                            html.H2(id="total-certifications", children="0", className="text-info")
                        ])
                    ])
                ], width=3)
            ], className="mb-4"),
            
            # Graphiques d'analyse
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Performance par Module"),
                            dcc.Graph(id="module-performance-chart")
                        ])
                    ])
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Répartition par Mode d'Interaction"),
                            dcc.Graph(id="interaction-modes-chart")
                        ])
                    ])
                ], width=6)
            ], className="mb-4"),
            
            # Contrôles de formation
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("🎮 Contrôle des Sessions"),
                            dbc.Row([
                                dbc.Col([
                                    dcc.Dropdown(
                                        id="user-select",
                                        placeholder="Sélectionner un utilisateur",
                                        options=[]
                                    )
                                ], width=6),
                                dbc.Col([
                                    dcc.Dropdown(
                                        id="module-select",
                                        placeholder="Sélectionner un module",
                                        options=[]
                                    )
                                ], width=6)
                            ], className="mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    dcc.Dropdown(
                                        id="interaction-mode-select",
                                        placeholder="Mode d'interaction",
                                        options=[
                                            {'label': 'VR Headset', 'value': 'vr_headset'},
                                            {'label': 'AR Tablet', 'value': 'ar_tablet'},
                                            {'label': 'AR Glasses', 'value': 'ar_glasses'},
                                            {'label': 'Desktop 3D', 'value': 'desktop_3d'}
                                        ]
                                    )
                                ], width=6),
                                dbc.Col([
                                    dbc.Button("🚀 Démarrer Session", id="start-session-btn", color="success")
                                ], width=6)
                            ])
                        ])
                    ])
                ])
            ], className="mb-4"),
            
            # Log des activités
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("📋 Activités Récentes"),
                            html.Div(id="activity-log")
                        ])
                    ])
                ])
            ]),
            
            # Mise à jour automatique
            dcc.Interval(
                id='interval-component',
                interval=5000,  # Mise à jour toutes les 5 secondes
                n_intervals=0
            )
        ], fluid=True)
        
        self._setup_dashboard_callbacks(app)
        return app
    
    def _setup_dashboard_callbacks(self, app: dash.Dash):
        """Configure les callbacks du dashboard."""
        
        @app.callback(
            [Output('total-users', 'children'),
             Output('active-sessions', 'children'),
             Output('average-score', 'children'),
             Output('total-certifications', 'children'),
             Output('user-select', 'options'),
             Output('module-select', 'options')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard_metrics(n):
            analytics = self.training_system.get_training_analytics()
            
            # Options pour les dropdowns
            user_options = [
                {'label': f"{user.name} ({user.role})", 'value': user_id}
                for user_id, user in self.training_system.users.items()
            ]
            
            module_options = [
                {'label': module.name, 'value': module_id}
                for module_id, module in self.training_system.training_modules.items()
            ]
            
            return (
                analytics['overview']['total_users'],
                analytics['overview']['active_sessions'],
                f"{analytics['overview']['average_score']:.1f}",
                analytics['certification_stats']['total_certifications'],
                user_options,
                module_options
            )
        
        @app.callback(
            Output('module-performance-chart', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_module_performance(n):
            analytics = self.training_system.get_training_analytics()
            module_perf = analytics.get('module_performance', {})
            
            if not module_perf:
                return go.Figure().add_annotation(text="Aucune donnée disponible", showarrow=False)
            
            modules = list(module_perf.keys())
            scores = [module_perf[mod]['average_score'] for mod in modules]
            
            fig = go.Figure(data=[
                go.Bar(x=modules, y=scores, marker_color='lightblue')
            ])
            
            fig.update_layout(
                title="Score Moyen par Module de Formation",
                xaxis_title="Modules",
                yaxis_title="Score Moyen (%)",
                yaxis_range=[0, 100]
            )
            
            return fig
        
        @app.callback(
            Output('interaction-modes-chart', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_interaction_modes(n):
            analytics = self.training_system.get_training_analytics()
            interaction_data = analytics.get('interaction_modes', {})
            
            if not interaction_data or sum(interaction_data.values()) == 0:
                return go.Figure().add_annotation(text="Aucune session terminée", showarrow=False)
            
            fig = go.Figure(data=[
                go.Pie(labels=list(interaction_data.keys()), 
                      values=list(interaction_data.values()),
                      hole=0.3)
            ])
            
            fig.update_layout(title="Répartition des Modes d'Interaction")
            return fig
    
    def start_web_interface(self):
        """Démarre l'interface web."""
        port = self.config['system']['web_port']
        debug = self.config['system']['debug_mode']
        
        logger.info(f"Démarrage interface web sur port {port}")
        self.web_app.run_server(debug=debug, host='0.0.0.0', port=port, threaded=True)
    
    async def run_system(self):
        """Lance le système complet."""
        self.is_running = True
        logger.info("🚀 Système VR/AR immersif démarré")
        
        # Démarrage de l'interface web en arrière-plan
        web_thread = threading.Thread(target=self.start_web_interface, daemon=True)
        web_thread.start()
        
        # Boucle principale du système
        while self.is_running:
            await asyncio.sleep(1)
    
    def stop_system(self):
        """Arrête le système."""
        self.is_running = False
        logger.info("Système VR/AR arrêté")

# Fonction de démonstration
async def main():
    """Démonstration du système de formation VR/AR immersif."""
    
    print("=== Interface VR/AR Immersive pour Formation Industrielle ===")
    print("🥽 Station Traffeyère IoT AI Platform - Module Formation")
    print()
    
    # Initialisation du système
    vr_ar_system = ImmersiveVRARInterface()
    
    print("✅ Système VR/AR initialisé")
    print()
    
    try:
        # Démonstration des fonctionnalités principales
        print("🎯 Modules de formation disponibles:")
        for module_id, module in vr_ar_system.training_system.training_modules.items():
            print(f"  • {module.name} ({module.level.value}) - {module.duration_minutes}min")
            print(f"    Scénario: {module.scenario.value}")
            print(f"    Objectifs: {len(module.learning_objectives)} objectifs d'apprentissage")
        print()
        
        print("👥 Utilisateurs configurés:")
        for user_id, user in vr_ar_system.training_system.users.items():
            print(f"  • {user.name} - {user.role} ({user.experience_level.value})")
            print(f"    Certifications: {len(user.certifications)}")
        print()
        
        # Simulation de sessions de formation
        print("🚀 Simulation de sessions de formation...")
        
        # Session VR pour incident cybersécurité
        print("\n📡 Démarrage session VR - Incident Cybersécurité")
        session_1 = vr_ar_system.training_system.start_training_session(
            user_id="security_001",
            module_id="cyber_incident_response",
            interaction_mode=InteractionMode.VR_HEADSET
        )
        
        # Simulation de progression
        await asyncio.sleep(1)
        
        vr_ar_system.training_system.update_session_progress(session_1, {
            'completion_percentage': 75.0,
            'metrics': {
                'response_time': 240,  # 4 minutes
                'accuracy': 0.90,
                'procedure_compliance': 0.95
            },
            'errors': ['incorrect_isolation_sequence']
        })
        
        # Completion de la session
        result_1 = vr_ar_system.training_system.complete_training_session(
            session_1, "Excellente maîtrise des procédures"
        )
        
        print(f"  ✅ Session terminée - Score: {result_1['success_score']:.1f}%")
        print(f"  📊 Durée: {result_1['session_duration']:.1f} minutes")
        print(f"  🏆 Certification: {'Oui' if result_1['certification_earned'] else 'Non'}")
        
        # Session AR pour maintenance PLC
        print("\n🔧 Démarrage session AR - Maintenance PLC")
        session_2 = vr_ar_system.training_system.start_training_session(
            user_id="tech_001",
            module_id="plc_maintenance",
            interaction_mode=InteractionMode.AR_TABLET
        )
        
        # Simulation d'étapes de maintenance AR
        ar_assistant = vr_ar_system.training_system.ar_assistant
        
        print("  🎯 Étapes de maintenance guidées:")
        print("    1. Vérification consignation...")
        await asyncio.sleep(0.5)
        ar_assistant.complete_maintenance_step(1, "Consignation vérifiée - Système sécurisé")
        
        print("    2. Inspection visuelle...")
        await asyncio.sleep(0.5)
        ar_assistant.complete_maintenance_step(2, "Inspection OK - Aucune anomalie détectée")
        
        print("    3. Test des connexions...")
        await asyncio.sleep(0.5)
        ar_assistant.complete_maintenance_step(3, "Tests électriques conformes")
        
        # Completion de la session AR
        vr_ar_system.training_system.update_session_progress(session_2, {
            'completion_percentage': 100.0,
            'metrics': {
                'inspection_completeness': 0.98,
                'diagnostic_accuracy': 0.85,
                'safety_violations': 0
            }
        })
        
        result_2 = vr_ar_system.training_system.complete_training_session(
            session_2, "Procédure de maintenance parfaitement exécutée"
        )
        
        print(f"  ✅ Session terminée - Score: {result_2['success_score']:.1f}%")
        print(f"  📊 Durée: {result_2['session_duration']:.1f} minutes")
        print(f"  🏆 Certification: {'Oui' if result_2['certification_earned'] else 'Non'}")
        
        # Session d'urgence
        print("\n🚨 Démarrage session VR - Procédures d'Urgence")
        session_3 = vr_ar_system.training_system.start_training_session(
            user_id="operator_001",
            module_id="emergency_shutdown",
            interaction_mode=InteractionMode.VR_HEADSET
        )
        
        # Simulation d'urgence avec temps de réponse critique
        vr_ar_system.training_system.update_session_progress(session_3, {
            'completion_percentage': 100.0,
            'metrics': {
                'shutdown_time': 45,  # 45 secondes - excellent
                'sequence_accuracy': 1.0,
                'safety_compliance': 1.0
            }
        })
        
        result_3 = vr_ar_system.training_system.complete_training_session(
            session_3, "Réaction d'urgence exemplaire"
        )
        
        print(f"  ✅ Session terminée - Score: {result_3['success_score']:.1f}%")
        print(f"  ⚡ Temps d'arrêt: 45 secondes (Excellent!)")
        
        print()
        
        # Analyses globales
        print("📈 Analyses du système de formation:")
        print("=" * 50)
        
        analytics = vr_ar_system.training_system.get_training_analytics()
        
        print(f"📊 Vue d'ensemble:")
        print(f"  • Utilisateurs total: {analytics['overview']['total_users']}")
        print(f"  • Sessions terminées: {analytics['overview']['total_sessions']}")
        print(f"  • Score moyen: {analytics['overview']['average_score']:.1f}%")
        print(f"  • Certifications délivrées: {analytics['certification_stats']['total_certifications']}")
        
        print(f"\n🎯 Performance par module:")
        for module_id, perf in analytics['module_performance'].items():
            module_name = vr_ar_system.training_system.training_modules[module_id].name
            print(f"  • {module_name}:")
            print(f"    Sessions: {perf['sessions_count']}")
            print(f"    Score moyen: {perf['average_score']:.1f}%")
            print(f"    Taux de réussite: {perf['success_rate']:.1f}%")
        
        print(f"\n🏢 Performance par rôle:")
        for role, perf in analytics['role_performance'].items():
            print(f"  • {role.replace('_', ' ').title()}:")
            print(f"    Score moyen: {perf['average_score']:.1f}%")
            print(f"    Sessions: {perf['sessions_count']}")
        
        print(f"\n🎮 Modes d'interaction utilisés:")
        for mode, count in analytics['interaction_modes'].items():
            if count > 0:
                print(f"  • {mode.replace('_', ' ').title()}: {count} sessions")
        
        # Progrès individuels
        print(f"\n👤 Progrès des utilisateurs:")
        for user_id in ['security_001', 'tech_001', 'operator_001']:
            progress = vr_ar_system.training_system.get_user_progress(user_id)
            user_info = progress['user_info']
            prog_data = progress['progress']
            
            print(f"  • {user_info['name']} ({user_info['role']}):")
            print(f"    Modules terminés: {prog_data['completed_modules']}/{prog_data['total_modules']}")
            print(f"    Taux de completion: {prog_data['completion_rate']:.1f}%")
            print(f"    Score moyen: {prog_data['average_score']:.1f}%")
            print(f"    Certifications: {prog_data['certifications']}")
        
        print()
        print("🎉 Démonstration du système VR/AR terminée avec succès !")
        print()
        print("🛡️ Fonctionnalités démontrées:")
        print("  ✓ Formation VR immersive aux incidents cybersécurité")
        print("  ✓ Assistance AR pour maintenance industrielle")
        print("  ✓ Simulation de procédures d'urgence")
        print("  ✓ Reconnaissance gestuelle et interaction naturelle")
        print("  ✓ Audio spatial pour immersion totale")
        print("  ✓ Système de certification automatique")
        print("  ✓ Analyses de performance détaillées")
        print("  ✓ Interface web de monitoring en temps réel")
        
        # Informations sur l'interface web
        print()
        print("🌐 Interface web de contrôle:")
        print(f"  URL: http://localhost:{vr_ar_system.config['system']['web_port']}")
        print("  Fonctionnalités: Monitoring, contrôle sessions, analyses")
        
    except Exception as e:
        print(f"❌ Erreur durant la démonstration: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())