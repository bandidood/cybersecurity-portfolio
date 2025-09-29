#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
AI Correlator - Forensic Analysis Toolkit
============================================================================
Moteur d'intelligence artificielle pour corrélation forensique avancée :
- Corrélation multi-dimensionnelle des artefacts forensiques
- Détection d'anomalies basée sur machine learning
- Classification automatique des menaces avec deep learning
- Analyse comportementale et pattern recognition
- Prédiction de techniques d'attaque (MITRE ATT&CK)
- Clustering intelligent des événements temporels
- Attribution d'attaquants par signature comportementale
- Génération automatique d'hypothèses d'investigation

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
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import pickle
from collections import defaultdict, Counter
import math

# Machine Learning Libraries
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import Dense, LSTM, Embedding, Dropout, Conv1D, GlobalMaxPooling1D
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import silhouette_score, classification_report
    from sklearn.model_selection import train_test_split
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Statistical and Analysis Libraries
try:
    import scipy.stats as stats
    from scipy.spatial.distance import cosine
    import networkx as nx
    ANALYSIS_AVAILABLE = True
except ImportError:
    ANALYSIS_AVAILABLE = False

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Catégories de menaces selon MITRE ATT&CK"""
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class CorrelationType(Enum):
    """Types de corrélations forensiques"""
    TEMPORAL = "Temporal Correlation"
    BEHAVIORAL = "Behavioral Pattern"
    NETWORK_FLOW = "Network Flow"
    FILE_SYSTEM = "File System Activity"
    PROCESS_CHAIN = "Process Execution Chain"
    MEMORY_ARTIFACT = "Memory Artifact"
    CRYPTOGRAPHIC = "Cryptographic Pattern"
    GEOLOCATION = "Geolocation"


class ConfidenceLevel(Enum):
    """Niveaux de confiance pour les corrélations"""
    VERY_HIGH = 0.9
    HIGH = 0.7
    MEDIUM = 0.5
    LOW = 0.3
    VERY_LOW = 0.1


@dataclass
class ForensicArtifact:
    """Artefact forensique pour corrélation IA"""
    artifact_id: str
    artifact_type: str
    source_module: str
    timestamp: datetime
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    features: np.ndarray = None
    threat_indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class CorrelationCluster:
    """Cluster de corrélation d'artefacts"""
    cluster_id: str
    artifacts: List[ForensicArtifact]
    correlation_type: CorrelationType
    confidence_score: float
    threat_category: Optional[ThreatCategory] = None
    timeline: Tuple[datetime, datetime] = None
    behavioral_signature: Dict[str, Any] = field(default_factory=dict)
    attack_progression: List[str] = field(default_factory=list)
    geographical_indicators: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatHypothesis:
    """Hypothèse de menace générée par IA"""
    hypothesis_id: str
    threat_category: ThreatCategory
    confidence: float
    description: str
    supporting_evidence: List[str]
    mitre_techniques: List[str]
    timeline_analysis: Dict[str, Any]
    recommended_actions: List[str]
    risk_assessment: Dict[str, Any]


class FeatureExtractor:
    """
    Extracteur de features pour les artefacts forensiques
    """
    
    def __init__(self):
        """Initialise l'extracteur de features"""
        self.text_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def extract_temporal_features(self, artifacts: List[ForensicArtifact]) -> np.ndarray:
        """Extrait les features temporelles"""
        features = []
        
        for artifact in artifacts:
            # Features temporelles de base
            timestamp = artifact.timestamp
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            is_weekend = 1 if day_of_week >= 5 else 0
            is_night = 1 if hour < 6 or hour > 22 else 0
            
            # Fréquence d'activité dans une fenêtre temporelle
            time_window = timedelta(hours=1)
            activity_count = sum(1 for a in artifacts 
                               if abs((a.timestamp - timestamp).total_seconds()) < time_window.total_seconds())
            
            features.append([
                hour / 24.0,  # Normalisation 0-1
                day_of_week / 6.0,
                is_weekend,
                is_night,
                activity_count / len(artifacts)  # Normalisation par rapport au total
            ])
        
        return np.array(features)
    
    def extract_behavioral_features(self, artifacts: List[ForensicArtifact]) -> np.ndarray:
        """Extrait les features comportementales"""
        features = []
        
        for artifact in artifacts:
            # Features comportementales basiques
            entropy = self._calculate_entropy(str(artifact.data))
            data_size = len(str(artifact.data))
            unique_fields = len(set(artifact.data.keys()))
            
            # Features spécifiques selon le type d'artefact
            type_specific = self._extract_type_specific_features(artifact)
            
            features.append([
                entropy,
                math.log(data_size + 1),  # Log pour réduire l'impact des valeurs extrêmes
                unique_fields,
                *type_specific
            ])
        
        return np.array(features)
    
    def extract_network_features(self, artifacts: List[ForensicArtifact]) -> np.ndarray:
        """Extrait les features réseau"""
        features = []
        
        for artifact in artifacts:
            if artifact.artifact_type in ['network_flow', 'dns_query', 'http_request']:
                # Features réseau
                src_ip = artifact.data.get('source_ip', '')
                dst_ip = artifact.data.get('destination_ip', '')
                port = artifact.data.get('port', 0)
                protocol = artifact.data.get('protocol', '')
                
                # Conversion en features numériques
                src_private = self._is_private_ip(src_ip)
                dst_private = self._is_private_ip(dst_ip)
                high_port = 1 if port > 1024 else 0
                tcp_protocol = 1 if protocol.lower() == 'tcp' else 0
                
                features.append([
                    src_private,
                    dst_private,
                    high_port,
                    tcp_protocol,
                    port / 65535.0  # Normalisation
                ])
            else:
                features.append([0, 0, 0, 0, 0])  # Features par défaut
        
        return np.array(features)
    
    def extract_text_features(self, artifacts: List[ForensicArtifact]) -> np.ndarray:
        """Extrait les features textuelles avec TF-IDF"""
        # Préparation du corpus textuel
        texts = []
        for artifact in artifacts:
            # Concaténation des valeurs textuelles de l'artefact
            text_data = []
            for key, value in artifact.data.items():
                if isinstance(value, str):
                    text_data.append(value)
            
            combined_text = ' '.join(text_data) if text_data else 'empty'
            texts.append(combined_text)
        
        # Vectorisation TF-IDF
        if not self.is_fitted:
            features_matrix = self.text_vectorizer.fit_transform(texts)
            self.is_fitted = True
        else:
            features_matrix = self.text_vectorizer.transform(texts)
        
        return features_matrix.toarray()
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcule l'entropie de Shannon d'un texte"""
        if not text:
            return 0.0
        
        # Comptage des caractères
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calcul de l'entropie
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_type_specific_features(self, artifact: ForensicArtifact) -> List[float]:
        """Extrait des features spécifiques au type d'artefact"""
        features = []
        
        if artifact.artifact_type == 'file_analysis':
            features.extend([
                artifact.data.get('file_size', 0) / 1e6,  # Taille en MB
                1 if artifact.data.get('is_executable', False) else 0,
                1 if artifact.data.get('is_hidden', False) else 0
            ])
        
        elif artifact.artifact_type == 'process_execution':
            features.extend([
                artifact.data.get('cpu_usage', 0) / 100.0,
                artifact.data.get('memory_usage', 0) / 1e6,  # MB
                1 if artifact.data.get('elevated_privileges', False) else 0
            ])
        
        elif artifact.artifact_type == 'network_connection':
            features.extend([
                artifact.data.get('bytes_sent', 0) / 1e6,  # MB
                artifact.data.get('bytes_received', 0) / 1e6,  # MB
                artifact.data.get('duration', 0) / 3600.0  # Heures
            ])
        
        else:
            features.extend([0.0, 0.0, 0.0])  # Features par défaut
        
        # Compléter avec des zéros si nécessaire
        while len(features) < 5:
            features.append(0.0)
        
        return features[:5]  # Limiter à 5 features max
    
    def _is_private_ip(self, ip: str) -> int:
        """Vérifie si une IP est privée"""
        if not ip:
            return 0
        
        try:
            parts = [int(x) for x in ip.split('.')]
            if len(parts) != 4:
                return 0
            
            # Plages privées : 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            if parts[0] == 10:
                return 1
            elif parts[0] == 172 and 16 <= parts[1] <= 31:
                return 1
            elif parts[0] == 192 and parts[1] == 168:
                return 1
            
            return 0
        except:
            return 0
    
    def combine_features(self, artifacts: List[ForensicArtifact]) -> np.ndarray:
        """Combine toutes les features extraites"""
        if not artifacts:
            return np.array([])
        
        # Extraction des différents types de features
        temporal_features = self.extract_temporal_features(artifacts)
        behavioral_features = self.extract_behavioral_features(artifacts)
        network_features = self.extract_network_features(artifacts)
        
        # Combinaison horizontale
        combined = np.hstack([
            temporal_features,
            behavioral_features,
            network_features
        ])
        
        # Normalisation
        if not hasattr(self, '_scaler_fitted'):
            combined = self.scaler.fit_transform(combined)
            self._scaler_fitted = True
        else:
            combined = self.scaler.transform(combined)
        
        return combined


class AnomalyDetector:
    """
    Détecteur d'anomalies pour artefacts forensiques
    """
    
    def __init__(self, contamination: float = 0.1):
        """
        Initialise le détecteur d'anomalies
        
        Args:
            contamination: Pourcentage d'anomalies attendues
        """
        self.contamination = contamination
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.is_fitted = False
        self.feature_extractor = FeatureExtractor()
    
    def fit(self, artifacts: List[ForensicArtifact]):
        """Entraîne le modèle de détection d'anomalies"""
        if not artifacts:
            raise ValueError("Aucun artefact fourni pour l'entraînement")
        
        # Extraction des features
        features = self.feature_extractor.combine_features(artifacts)
        
        # Entraînement du modèle
        self.isolation_forest.fit(features)
        self.is_fitted = True
        
        logger.info(f"Détecteur d'anomalies entraîné sur {len(artifacts)} artefacts")
    
    def detect_anomalies(self, artifacts: List[ForensicArtifact]) -> List[Tuple[ForensicArtifact, float]]:
        """
        Détecte les anomalies dans les artefacts
        
        Returns:
            Liste de tuples (artefact, score_anomalie)
        """
        if not self.is_fitted:
            raise ValueError("Le modèle doit être entraîné avant la détection")
        
        if not artifacts:
            return []
        
        # Extraction des features
        features = self.feature_extractor.combine_features(artifacts)
        
        # Prédiction des anomalies
        predictions = self.isolation_forest.predict(features)
        scores = self.isolation_forest.decision_function(features)
        
        # Compilation des résultats
        anomalies = []
        for i, (artifact, pred, score) in enumerate(zip(artifacts, predictions, scores)):
            if pred == -1:  # Anomalie détectée
                # Conversion du score en probabilité (0-1)
                anomaly_score = max(0, (0.5 - score) * 2)
                anomalies.append((artifact, anomaly_score))
        
        # Tri par score d'anomalie décroissant
        anomalies.sort(key=lambda x: x[1], reverse=True)
        
        logger.info(f"Détection de {len(anomalies)} anomalies sur {len(artifacts)} artefacts")
        return anomalies


class ThreatClassifier:
    """
    Classificateur de menaces basé sur deep learning
    """
    
    def __init__(self, max_features: int = 10000, max_sequence_length: int = 100):
        """
        Initialise le classificateur de menaces
        
        Args:
            max_features: Nombre maximum de features pour le vocabulaire
            max_sequence_length: Longueur maximale des séquences
        """
        self.max_features = max_features
        self.max_sequence_length = max_sequence_length
        self.tokenizer = Tokenizer(num_words=max_features)
        self.label_encoder = LabelEncoder()
        self.model = None
        self.is_fitted = False
    
    def _build_model(self, num_classes: int) -> Model:
        """Construit le modèle de deep learning"""
        model = Sequential([
            Embedding(self.max_features, 128, input_length=self.max_sequence_length),
            Conv1D(64, 5, activation='relu'),
            GlobalMaxPooling1D(),
            Dense(64, activation='relu'),
            Dropout(0.5),
            Dense(32, activation='relu'),
            Dropout(0.3),
            Dense(num_classes, activation='softmax' if num_classes > 2 else 'sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy' if num_classes > 2 else 'binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def prepare_training_data(self, artifacts: List[ForensicArtifact]) -> Tuple[np.ndarray, np.ndarray]:
        """Prépare les données d'entraînement"""
        texts = []
        labels = []
        
        for artifact in artifacts:
            # Création d'un texte représentatif de l'artefact
            text_parts = [
                artifact.artifact_type,
                artifact.source_module,
                ' '.join(artifact.threat_indicators),
                ' '.join(artifact.mitre_techniques),
                str(artifact.data)
            ]
            
            combined_text = ' '.join(text_parts)
            texts.append(combined_text)
            
            # Label basé sur les indicateurs de menace
            if artifact.mitre_techniques:
                # Utilise la première technique MITRE comme label
                labels.append(artifact.mitre_techniques[0])
            elif artifact.threat_indicators:
                labels.append('suspicious')
            else:
                labels.append('benign')
        
        # Tokenisation
        self.tokenizer.fit_on_texts(texts)
        sequences = self.tokenizer.texts_to_sequences(texts)
        X = pad_sequences(sequences, maxlen=self.max_sequence_length)
        
        # Encodage des labels
        y = self.label_encoder.fit_transform(labels)
        
        return X, y
    
    def train(self, artifacts: List[ForensicArtifact], validation_split: float = 0.2, epochs: int = 10):
        """Entraîne le modèle de classification"""
        if not artifacts:
            raise ValueError("Aucun artefact fourni pour l'entraînement")
        
        # Préparation des données
        X, y = self.prepare_training_data(artifacts)
        
        # Construction du modèle
        num_classes = len(np.unique(y))
        self.model = self._build_model(num_classes)
        
        # Entraînement
        history = self.model.fit(
            X, y,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=32,
            verbose=1
        )
        
        self.is_fitted = True
        logger.info(f"Modèle entraîné sur {len(artifacts)} artefacts, {num_classes} classes")
        
        return history
    
    def classify_threats(self, artifacts: List[ForensicArtifact]) -> List[Tuple[ForensicArtifact, str, float]]:
        """
        Classifie les menaces dans les artefacts
        
        Returns:
            Liste de tuples (artefact, classe_menace, confiance)
        """
        if not self.is_fitted:
            raise ValueError("Le modèle doit être entraîné avant la classification")
        
        if not artifacts:
            return []
        
        # Préparation des données
        texts = []
        for artifact in artifacts:
            text_parts = [
                artifact.artifact_type,
                artifact.source_module,
                ' '.join(artifact.threat_indicators),
                str(artifact.data)
            ]
            combined_text = ' '.join(text_parts)
            texts.append(combined_text)
        
        # Tokenisation et prédiction
        sequences = self.tokenizer.texts_to_sequences(texts)
        X = pad_sequences(sequences, maxlen=self.max_sequence_length)
        
        predictions = self.model.predict(X)
        
        # Interprétation des résultats
        results = []
        for i, (artifact, pred) in enumerate(zip(artifacts, predictions)):
            class_idx = np.argmax(pred)
            confidence = float(np.max(pred))
            threat_class = self.label_encoder.inverse_transform([class_idx])[0]
            
            results.append((artifact, threat_class, confidence))
        
        logger.info(f"Classification de {len(artifacts)} artefacts terminée")
        return results


class CorrelationEngine:
    """
    Moteur de corrélation principal pour les artefacts forensiques
    """
    
    def __init__(self):
        """Initialise le moteur de corrélation"""
        self.clustering_model = DBSCAN(eps=0.5, min_samples=3)
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.feature_extractor = FeatureExtractor()
    
    def temporal_correlation(self, artifacts: List[ForensicArtifact], 
                           time_window: timedelta = timedelta(minutes=30)) -> List[CorrelationCluster]:
        """Corrélation temporelle des artefacts"""
        if not artifacts:
            return []
        
        # Tri par timestamp
        sorted_artifacts = sorted(artifacts, key=lambda x: x.timestamp)
        clusters = []
        
        current_cluster = []
        cluster_start = None
        
        for artifact in sorted_artifacts:
            if not current_cluster:
                current_cluster = [artifact]
                cluster_start = artifact.timestamp
            else:
                # Vérifier si l'artefact appartient à la fenêtre temporelle
                time_diff = artifact.timestamp - cluster_start
                if time_diff <= time_window:
                    current_cluster.append(artifact)
                else:
                    # Créer un cluster si suffisamment d'artefacts
                    if len(current_cluster) >= 2:
                        cluster_id = f"temporal_{len(clusters)}_{cluster_start.strftime('%Y%m%d_%H%M%S')}"
                        confidence = min(len(current_cluster) / 10.0, 1.0)  # Plus d'artefacts = plus de confiance
                        
                        cluster = CorrelationCluster(
                            cluster_id=cluster_id,
                            artifacts=current_cluster.copy(),
                            correlation_type=CorrelationType.TEMPORAL,
                            confidence_score=confidence,
                            timeline=(cluster_start, current_cluster[-1].timestamp)
                        )
                        clusters.append(cluster)
                    
                    # Commencer un nouveau cluster
                    current_cluster = [artifact]
                    cluster_start = artifact.timestamp
        
        # Traiter le dernier cluster
        if len(current_cluster) >= 2:
            cluster_id = f"temporal_{len(clusters)}_{cluster_start.strftime('%Y%m%d_%H%M%S')}"
            confidence = min(len(current_cluster) / 10.0, 1.0)
            
            cluster = CorrelationCluster(
                cluster_id=cluster_id,
                artifacts=current_cluster,
                correlation_type=CorrelationType.TEMPORAL,
                confidence_score=confidence,
                timeline=(cluster_start, current_cluster[-1].timestamp)
            )
            clusters.append(cluster)
        
        logger.info(f"Corrélation temporelle: {len(clusters)} clusters identifiés")
        return clusters
    
    def behavioral_correlation(self, artifacts: List[ForensicArtifact]) -> List[CorrelationCluster]:
        """Corrélation comportementale basée sur clustering"""
        if not artifacts or not ML_AVAILABLE:
            return []
        
        # Extraction des features comportementales
        features = self.feature_extractor.combine_features(artifacts)
        
        if features.size == 0:
            return []
        
        # Clustering DBSCAN
        cluster_labels = self.clustering_model.fit_predict(features)
        
        # Groupement par clusters
        cluster_groups = defaultdict(list)
        for artifact, label in zip(artifacts, cluster_labels):
            if label != -1:  # Exclure le bruit
                cluster_groups[label].append(artifact)
        
        # Création des clusters de corrélation
        clusters = []
        for cluster_id, group_artifacts in cluster_groups.items():
            if len(group_artifacts) >= 2:  # Minimum 2 artefacts par cluster
                
                # Calcul de la signature comportementale
                behavioral_sig = self._calculate_behavioral_signature(group_artifacts)
                
                # Calcul de la confiance basé sur la cohésion du cluster
                confidence = self._calculate_cluster_confidence(group_artifacts, features, cluster_labels, cluster_id)
                
                correlation_cluster = CorrelationCluster(
                    cluster_id=f"behavioral_{cluster_id}",
                    artifacts=group_artifacts,
                    correlation_type=CorrelationType.BEHAVIORAL,
                    confidence_score=confidence,
                    behavioral_signature=behavioral_sig
                )
                clusters.append(correlation_cluster)
        
        logger.info(f"Corrélation comportementale: {len(clusters)} clusters identifiés")
        return clusters
    
    def network_flow_correlation(self, artifacts: List[ForensicArtifact]) -> List[CorrelationCluster]:
        """Corrélation des flux réseau"""
        network_artifacts = [a for a in artifacts if 'network' in a.artifact_type.lower()]
        
        if not network_artifacts:
            return []
        
        # Groupement par connexions réseau similaires
        connection_groups = defaultdict(list)
        
        for artifact in network_artifacts:
            # Création d'une clé de groupement basée sur les IPs et ports
            src_ip = artifact.data.get('source_ip', '')
            dst_ip = artifact.data.get('destination_ip', '')
            dst_port = artifact.data.get('destination_port', 0)
            
            # Normalisation des IPs (garder seulement les 3 premiers octets)
            src_subnet = '.'.join(src_ip.split('.')[:3]) if src_ip else 'unknown'
            dst_subnet = '.'.join(dst_ip.split('.')[:3]) if dst_ip else 'unknown'
            
            group_key = f"{src_subnet}_to_{dst_subnet}_{dst_port}"
            connection_groups[group_key].append(artifact)
        
        # Création des clusters
        clusters = []
        for group_key, group_artifacts in connection_groups.items():
            if len(group_artifacts) >= 2:
                
                # Analyse des patterns de communication
                total_bytes = sum(
                    artifact.data.get('bytes_sent', 0) + artifact.data.get('bytes_received', 0)
                    for artifact in group_artifacts
                )
                
                avg_duration = np.mean([
                    artifact.data.get('duration', 0) for artifact in group_artifacts
                ])
                
                # Calcul de confiance basé sur la cohérence des communications
                confidence = min(len(group_artifacts) / 20.0, 0.9)
                
                correlation_cluster = CorrelationCluster(
                    cluster_id=f"network_{group_key}",
                    artifacts=group_artifacts,
                    correlation_type=CorrelationType.NETWORK_FLOW,
                    confidence_score=confidence,
                    behavioral_signature={
                        'total_bytes': total_bytes,
                        'average_duration': avg_duration,
                        'connection_count': len(group_artifacts),
                        'group_pattern': group_key
                    }
                )
                clusters.append(correlation_cluster)
        
        logger.info(f"Corrélation réseau: {len(clusters)} clusters identifiés")
        return clusters
    
    def _calculate_behavioral_signature(self, artifacts: List[ForensicArtifact]) -> Dict[str, Any]:
        """Calcule la signature comportementale d'un groupe d'artefacts"""
        signature = {
            'artifact_types': Counter([a.artifact_type for a in artifacts]),
            'source_modules': Counter([a.source_module for a in artifacts]),
            'time_distribution': self._analyze_time_distribution(artifacts),
            'threat_indicators': Counter([ti for a in artifacts for ti in a.threat_indicators]),
            'mitre_techniques': Counter([mt for a in artifacts for mt in a.mitre_techniques])
        }
        
        # Conversion des Counters en dictionnaires pour sérialisation JSON
        for key, value in signature.items():
            if isinstance(value, Counter):
                signature[key] = dict(value)
        
        return signature
    
    def _analyze_time_distribution(self, artifacts: List[ForensicArtifact]) -> Dict[str, Any]:
        """Analyse la distribution temporelle des artefacts"""
        timestamps = [a.timestamp for a in artifacts]
        
        if not timestamps:
            return {}
        
        # Statistiques temporelles
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        avg_interval = duration / len(timestamps) if len(timestamps) > 1 else 0
        
        # Distribution par heure de la journée
        hours = [ts.hour for ts in timestamps]
        hour_distribution = Counter(hours)
        
        # Distribution par jour de la semaine
        weekdays = [ts.weekday() for ts in timestamps]
        weekday_distribution = Counter(weekdays)
        
        return {
            'duration_seconds': duration,
            'average_interval': avg_interval,
            'hour_distribution': dict(hour_distribution),
            'weekday_distribution': dict(weekday_distribution),
            'peak_hour': max(hour_distribution, key=hour_distribution.get) if hour_distribution else None,
            'peak_weekday': max(weekday_distribution, key=weekday_distribution.get) if weekday_distribution else None
        }
    
    def _calculate_cluster_confidence(self, artifacts: List[ForensicArtifact], 
                                    features: np.ndarray, labels: np.ndarray, cluster_id: int) -> float:
        """Calcule la confiance d'un cluster basé sur sa cohésion"""
        if not ANALYSIS_AVAILABLE:
            return 0.5  # Confiance par défaut
        
        try:
            # Extraire les features du cluster
            cluster_features = features[labels == cluster_id]
            
            if len(cluster_features) < 2:
                return 0.5
            
            # Calcul de la cohésion intra-cluster (distance moyenne au centroïde)
            centroid = np.mean(cluster_features, axis=0)
            distances = [np.linalg.norm(feat - centroid) for feat in cluster_features]
            avg_distance = np.mean(distances)
            
            # Normalisation de la confiance (plus la distance est faible, plus la confiance est élevée)
            max_distance = np.linalg.norm(np.max(features, axis=0) - np.min(features, axis=0))
            confidence = max(0.1, 1.0 - (avg_distance / max_distance))
            
            return min(confidence, 0.95)  # Plafonner à 95%
            
        except Exception as e:
            logger.warning(f"Erreur calcul confiance cluster: {e}")
            return 0.5


class AttackProgressionAnalyzer:
    """
    Analyseur de progression d'attaque basé sur MITRE ATT&CK
    """
    
    def __init__(self):
        """Initialise l'analyseur de progression d'attaque"""
        # Mapping des techniques MITRE vers les catégories de menaces
        self.mitre_mapping = {
            'T1595': ThreatCategory.RECONNAISSANCE,
            'T1190': ThreatCategory.INITIAL_ACCESS,
            'T1059': ThreatCategory.EXECUTION,
            'T1053': ThreatCategory.PERSISTENCE,
            'T1548': ThreatCategory.PRIVILEGE_ESCALATION,
            'T1055': ThreatCategory.DEFENSE_EVASION,
            'T1003': ThreatCategory.CREDENTIAL_ACCESS,
            'T1083': ThreatCategory.DISCOVERY,
            'T1021': ThreatCategory.LATERAL_MOVEMENT,
            'T1005': ThreatCategory.COLLECTION,
            'T1071': ThreatCategory.COMMAND_AND_CONTROL,
            'T1041': ThreatCategory.EXFILTRATION,
            'T1486': ThreatCategory.IMPACT
        }
        
        # Ordre typique de progression d'attaque
        self.attack_progression_order = [
            ThreatCategory.RECONNAISSANCE,
            ThreatCategory.INITIAL_ACCESS,
            ThreatCategory.EXECUTION,
            ThreatCategory.PERSISTENCE,
            ThreatCategory.PRIVILEGE_ESCALATION,
            ThreatCategory.DEFENSE_EVASION,
            ThreatCategory.CREDENTIAL_ACCESS,
            ThreatCategory.DISCOVERY,
            ThreatCategory.LATERAL_MOVEMENT,
            ThreatCategory.COLLECTION,
            ThreatCategory.COMMAND_AND_CONTROL,
            ThreatCategory.EXFILTRATION,
            ThreatCategory.IMPACT
        ]
    
    def analyze_attack_progression(self, clusters: List[CorrelationCluster]) -> Dict[str, Any]:
        """Analyse la progression d'attaque à travers les clusters"""
        
        # Extraction des techniques MITRE de tous les clusters
        techniques_timeline = []
        
        for cluster in clusters:
            cluster_techniques = set()
            earliest_time = None
            
            for artifact in cluster.artifacts:
                if artifact.mitre_techniques:
                    cluster_techniques.update(artifact.mitre_techniques)
                
                if earliest_time is None or artifact.timestamp < earliest_time:
                    earliest_time = artifact.timestamp
            
            if cluster_techniques and earliest_time:
                techniques_timeline.append({
                    'timestamp': earliest_time,
                    'techniques': list(cluster_techniques),
                    'cluster_id': cluster.cluster_id,
                    'confidence': cluster.confidence_score
                })
        
        # Tri par timestamp
        techniques_timeline.sort(key=lambda x: x['timestamp'])
        
        # Analyse de la progression
        progression_analysis = {
            'attack_phases': self._identify_attack_phases(techniques_timeline),
            'progression_score': self._calculate_progression_score(techniques_timeline),
            'missing_phases': self._identify_missing_phases(techniques_timeline),
            'timeline_coherence': self._analyze_timeline_coherence(techniques_timeline),
            'attack_sophistication': self._assess_attack_sophistication(techniques_timeline)
        }
        
        return progression_analysis
    
    def _identify_attack_phases(self, techniques_timeline: List[Dict]) -> List[Dict[str, Any]]:
        """Identifie les phases d'attaque présentes"""
        phases = []
        
        for entry in techniques_timeline:
            entry_phases = set()
            
            for technique in entry['techniques']:
                if technique in self.mitre_mapping:
                    category = self.mitre_mapping[technique]
                    entry_phases.add(category)
            
            if entry_phases:
                phases.append({
                    'timestamp': entry['timestamp'],
                    'phases': list(entry_phases),
                    'techniques': entry['techniques'],
                    'cluster_id': entry['cluster_id'],
                    'confidence': entry['confidence']
                })
        
        return phases
    
    def _calculate_progression_score(self, techniques_timeline: List[Dict]) -> float:
        """Calcule un score de progression d'attaque (0-1)"""
        if not techniques_timeline:
            return 0.0
        
        # Identifier les phases présentes
        observed_phases = set()
        for entry in techniques_timeline:
            for technique in entry['techniques']:
                if technique in self.mitre_mapping:
                    observed_phases.add(self.mitre_mapping[technique])
        
        # Score basé sur le nombre de phases et leur ordre
        phase_coverage = len(observed_phases) / len(self.attack_progression_order)
        
        # Bonus pour l'ordre correct des phases
        order_bonus = 0.0
        if len(observed_phases) > 1:
            phase_indices = []
            for phase in observed_phases:
                if phase in self.attack_progression_order:
                    phase_indices.append(self.attack_progression_order.index(phase))
            
            # Vérifier si les phases sont dans l'ordre croissant
            if phase_indices == sorted(phase_indices):
                order_bonus = 0.3
        
        total_score = min(1.0, phase_coverage + order_bonus)
        return total_score
    
    def _identify_missing_phases(self, techniques_timeline: List[Dict]) -> List[ThreatCategory]:
        """Identifie les phases d'attaque manquantes"""
        observed_phases = set()
        for entry in techniques_timeline:
            for technique in entry['techniques']:
                if technique in self.mitre_mapping:
                    observed_phases.add(self.mitre_mapping[technique])
        
        missing_phases = []
        for phase in self.attack_progression_order:
            if phase not in observed_phases:
                missing_phases.append(phase)
        
        return missing_phases
    
    def _analyze_timeline_coherence(self, techniques_timeline: List[Dict]) -> Dict[str, Any]:
        """Analyse la cohérence temporelle de la progression"""
        if len(techniques_timeline) < 2:
            return {'coherence_score': 1.0, 'anomalies': []}
        
        # Calcul des intervalles entre les phases
        intervals = []
        for i in range(1, len(techniques_timeline)):
            prev_time = techniques_timeline[i-1]['timestamp']
            curr_time = techniques_timeline[i]['timestamp']
            interval = (curr_time - prev_time).total_seconds()
            intervals.append(interval)
        
        # Détection d'anomalies temporelles
        if intervals:
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            anomalies = []
            for i, interval in enumerate(intervals):
                # Détecter les intervalles anormalement longs ou courts
                if abs(interval - mean_interval) > 2 * std_interval:
                    anomalies.append({
                        'index': i,
                        'interval': interval,
                        'expected_range': (mean_interval - std_interval, mean_interval + std_interval)
                    })
            
            # Score de cohérence (moins d'anomalies = meilleure cohérence)
            coherence_score = max(0.0, 1.0 - len(anomalies) / len(intervals))
            
            return {
                'coherence_score': coherence_score,
                'anomalies': anomalies,
                'mean_interval_seconds': mean_interval,
                'std_interval_seconds': std_interval
            }
        
        return {'coherence_score': 1.0, 'anomalies': []}
    
    def _assess_attack_sophistication(self, techniques_timeline: List[Dict]) -> Dict[str, Any]:
        """Évalue la sophistication de l'attaque"""
        if not techniques_timeline:
            return {'sophistication_level': 'Unknown', 'score': 0.0}
        
        # Comptage des techniques uniques
        unique_techniques = set()
        for entry in techniques_timeline:
            unique_techniques.update(entry['techniques'])
        
        num_techniques = len(unique_techniques)
        num_phases = len(set(
            self.mitre_mapping.get(technique, None) 
            for technique in unique_techniques
        ) - {None})
        
        # Score de sophistication basé sur :
        # - Nombre de techniques utilisées
        # - Nombre de phases couvertes
        # - Cohérence temporelle
        
        technique_score = min(num_techniques / 20.0, 1.0)  # Max 20 techniques
        phase_score = num_phases / len(self.attack_progression_order)
        
        overall_score = (technique_score + phase_score) / 2
        
        # Classification de la sophistication
        if overall_score >= 0.8:
            sophistication_level = 'Advanced Persistent Threat (APT)'
        elif overall_score >= 0.6:
            sophistication_level = 'Advanced'
        elif overall_score >= 0.4:
            sophistication_level = 'Intermediate'
        elif overall_score >= 0.2:
            sophistication_level = 'Basic'
        else:
            sophistication_level = 'Opportunistic'
        
        return {
            'sophistication_level': sophistication_level,
            'score': overall_score,
            'techniques_count': num_techniques,
            'phases_count': num_phases,
            'unique_techniques': list(unique_techniques)
        }


class HypothesisGenerator:
    """
    Générateur d'hypothèses de menaces basé sur IA
    """
    
    def __init__(self):
        """Initialise le générateur d'hypothèses"""
        self.attack_analyzer = AttackProgressionAnalyzer()
    
    def generate_threat_hypotheses(self, clusters: List[CorrelationCluster], 
                                  artifacts: List[ForensicArtifact]) -> List[ThreatHypothesis]:
        """Génère des hypothèses de menaces basées sur les clusters et artefacts"""
        
        hypotheses = []
        
        # Analyse de la progression d'attaque
        progression_analysis = self.attack_analyzer.analyze_attack_progression(clusters)
        
        # Génération d'hypothèses basées sur les clusters
        for i, cluster in enumerate(clusters):
            hypothesis = self._generate_cluster_hypothesis(cluster, progression_analysis)
            if hypothesis:
                hypotheses.append(hypothesis)
        
        # Génération d'hypothèses basées sur la progression globale
        global_hypothesis = self._generate_global_hypothesis(clusters, progression_analysis, artifacts)
        if global_hypothesis:
            hypotheses.append(global_hypothesis)
        
        # Tri par confiance décroissante
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        
        return hypotheses
    
    def _generate_cluster_hypothesis(self, cluster: CorrelationCluster, 
                                   progression_analysis: Dict[str, Any]) -> Optional[ThreatHypothesis]:
        """Génère une hypothèse pour un cluster spécifique"""
        
        # Collecte des techniques MITRE du cluster
        mitre_techniques = set()
        threat_indicators = set()
        
        for artifact in cluster.artifacts:
            mitre_techniques.update(artifact.mitre_techniques)
            threat_indicators.update(artifact.threat_indicators)
        
        if not mitre_techniques and not threat_indicators:
            return None
        
        # Détermination de la catégorie de menace principale
        threat_categories = []
        for technique in mitre_techniques:
            if technique in self.attack_analyzer.mitre_mapping:
                threat_categories.append(self.attack_analyzer.mitre_mapping[technique])
        
        primary_category = max(set(threat_categories), key=threat_categories.count) if threat_categories else None
        
        # Génération de la description
        description = self._generate_cluster_description(cluster, primary_category, mitre_techniques, threat_indicators)
        
        # Calcul de la confiance
        confidence = self._calculate_hypothesis_confidence(cluster, mitre_techniques, threat_indicators)
        
        # Génération des actions recommandées
        recommended_actions = self._generate_recommended_actions(primary_category, mitre_techniques)
        
        # Évaluation des risques
        risk_assessment = self._assess_cluster_risk(cluster, primary_category, confidence)
        
        hypothesis = ThreatHypothesis(
            hypothesis_id=f"hypothesis_cluster_{cluster.cluster_id}",
            threat_category=primary_category or ThreatCategory.RECONNAISSANCE,
            confidence=confidence,
            description=description,
            supporting_evidence=[artifact.artifact_id for artifact in cluster.artifacts],
            mitre_techniques=list(mitre_techniques),
            timeline_analysis={
                'start_time': cluster.timeline[0] if cluster.timeline else None,
                'end_time': cluster.timeline[1] if cluster.timeline else None,
                'correlation_type': cluster.correlation_type.value,
                'behavioral_signature': cluster.behavioral_signature
            },
            recommended_actions=recommended_actions,
            risk_assessment=risk_assessment
        )
        
        return hypothesis
    
    def _generate_global_hypothesis(self, clusters: List[CorrelationCluster], 
                                  progression_analysis: Dict[str, Any], 
                                  artifacts: List[ForensicArtifact]) -> Optional[ThreatHypothesis]:
        """Génère une hypothèse globale basée sur tous les clusters"""
        
        if not clusters:
            return None
        
        # Analyse de la sophistication de l'attaque
        sophistication = progression_analysis.get('attack_sophistication', {})
        sophistication_level = sophistication.get('sophistication_level', 'Unknown')
        progression_score = progression_analysis.get('progression_score', 0.0)
        
        # Détermination de la catégorie de menace principale
        all_techniques = set()
        for cluster in clusters:
            for artifact in cluster.artifacts:
                all_techniques.update(artifact.mitre_techniques)
        
        threat_categories = []
        for technique in all_techniques:
            if technique in self.attack_analyzer.mitre_mapping:
                threat_categories.append(self.attack_analyzer.mitre_mapping[technique])
        
        primary_category = max(set(threat_categories), key=threat_categories.count) if threat_categories else ThreatCategory.RECONNAISSANCE
        
        # Génération de la description globale
        description = self._generate_global_description(clusters, sophistication_level, progression_score)
        
        # Calcul de la confiance globale
        cluster_confidences = [c.confidence_score for c in clusters]
        global_confidence = np.mean(cluster_confidences) if cluster_confidences else 0.5
        
        # Ajustement selon la progression
        global_confidence *= (0.5 + progression_score * 0.5)  # Bonus pour progression cohérente
        
        # Actions recommandées globales
        recommended_actions = self._generate_global_recommended_actions(sophistication_level, primary_category)
        
        # Évaluation des risques globaux
        risk_assessment = self._assess_global_risk(clusters, sophistication_level, global_confidence)
        
        hypothesis = ThreatHypothesis(
            hypothesis_id="hypothesis_global_campaign",
            threat_category=primary_category,
            confidence=min(global_confidence, 0.95),
            description=description,
            supporting_evidence=[cluster.cluster_id for cluster in clusters],
            mitre_techniques=list(all_techniques),
            timeline_analysis={
                'progression_analysis': progression_analysis,
                'clusters_count': len(clusters),
                'total_artifacts': sum(len(c.artifacts) for c in clusters)
            },
            recommended_actions=recommended_actions,
            risk_assessment=risk_assessment
        )
        
        return hypothesis
    
    def _generate_cluster_description(self, cluster: CorrelationCluster, 
                                    primary_category: Optional[ThreatCategory],
                                    mitre_techniques: set, threat_indicators: set) -> str:
        """Génère la description d'une hypothèse de cluster"""
        
        descriptions = []
        
        # Description basée sur le type de corrélation
        if cluster.correlation_type == CorrelationType.TEMPORAL:
            descriptions.append(f"Activité suspecte corrélée temporellement avec {len(cluster.artifacts)} artefacts")
        elif cluster.correlation_type == CorrelationType.BEHAVIORAL:
            descriptions.append(f"Pattern comportemental suspect identifié avec {len(cluster.artifacts)} artefacts similaires")
        elif cluster.correlation_type == CorrelationType.NETWORK_FLOW:
            descriptions.append(f"Communications réseau suspectes avec {len(cluster.artifacts)} connexions corrélées")
        
        # Description basée sur la catégorie de menace
        if primary_category:
            category_descriptions = {
                ThreatCategory.RECONNAISSANCE: "suggesting reconnaissance activities",
                ThreatCategory.INITIAL_ACCESS: "indicating potential initial compromise",
                ThreatCategory.EXECUTION: "showing malicious code execution",
                ThreatCategory.PERSISTENCE: "demonstrating persistence mechanisms",
                ThreatCategory.PRIVILEGE_ESCALATION: "revealing privilege escalation attempts",
                ThreatCategory.DEFENSE_EVASION: "indicating evasion techniques",
                ThreatCategory.CREDENTIAL_ACCESS: "suggesting credential harvesting",
                ThreatCategory.DISCOVERY: "showing system discovery activities",
                ThreatCategory.LATERAL_MOVEMENT: "indicating lateral movement",
                ThreatCategory.COLLECTION: "demonstrating data collection",
                ThreatCategory.COMMAND_AND_CONTROL: "establishing command and control",
                ThreatCategory.EXFILTRATION: "indicating data exfiltration",
                ThreatCategory.IMPACT: "showing destructive activities"
            }
            
            descriptions.append(category_descriptions.get(primary_category, "with unknown intent"))
        
        # Ajout des indicateurs de menace
        if threat_indicators:
            indicators_str = ", ".join(list(threat_indicators)[:3])
            descriptions.append(f"Key indicators: {indicators_str}")
        
        # Ajout des techniques MITRE
        if mitre_techniques:
            techniques_str = ", ".join(list(mitre_techniques)[:3])
            descriptions.append(f"MITRE techniques: {techniques_str}")
        
        return ". ".join(descriptions) + "."
    
    def _generate_global_description(self, clusters: List[CorrelationCluster], 
                                   sophistication_level: str, progression_score: float) -> str:
        """Génère la description d'une hypothèse globale"""
        
        descriptions = [
            f"Campagne d'attaque coordonnée détectée avec {len(clusters)} clusters de corrélation",
            f"Niveau de sophistication: {sophistication_level}",
            f"Score de progression: {progression_score:.1%}"
        ]
        
        # Analyse des types de corrélation
        correlation_types = [c.correlation_type for c in clusters]
        type_counts = Counter(correlation_types)
        
        if len(type_counts) > 1:
            descriptions.append("Multiple correlation types suggest complex attack campaign")
        
        # Timeline globale
        all_timestamps = []
        for cluster in clusters:
            for artifact in cluster.artifacts:
                all_timestamps.append(artifact.timestamp)
        
        if all_timestamps:
            duration = (max(all_timestamps) - min(all_timestamps)).total_seconds()
            if duration > 86400:  # Plus d'un jour
                descriptions.append(f"Attack campaign spanning {duration/86400:.1f} days")
            elif duration > 3600:  # Plus d'une heure
                descriptions.append(f"Attack campaign spanning {duration/3600:.1f} hours")
        
        return ". ".join(descriptions) + "."
    
    def _calculate_hypothesis_confidence(self, cluster: CorrelationCluster, 
                                       mitre_techniques: set, threat_indicators: set) -> float:
        """Calcule la confiance d'une hypothèse"""
        base_confidence = cluster.confidence_score
        
        # Bonus pour les techniques MITRE
        mitre_bonus = min(len(mitre_techniques) * 0.1, 0.3)
        
        # Bonus pour les indicateurs de menace
        indicator_bonus = min(len(threat_indicators) * 0.05, 0.2)
        
        # Bonus pour le nombre d'artefacts
        artifact_bonus = min(len(cluster.artifacts) * 0.02, 0.2)
        
        total_confidence = base_confidence + mitre_bonus + indicator_bonus + artifact_bonus
        return min(total_confidence, 0.95)
    
    def _generate_recommended_actions(self, threat_category: Optional[ThreatCategory], 
                                    mitre_techniques: set) -> List[str]:
        """Génère les actions recommandées pour une hypothèse"""
        actions = []
        
        # Actions basées sur la catégorie de menace
        if threat_category == ThreatCategory.INITIAL_ACCESS:
            actions.extend([
                "Isoler les systèmes compromis du réseau",
                "Analyser les points d'entrée identifiés",
                "Renforcer les contrôles d'accès"
            ])
        elif threat_category == ThreatCategory.PERSISTENCE:
            actions.extend([
                "Rechercher et supprimer les mécanismes de persistance",
                "Auditer les comptes utilisateurs et services",
                "Vérifier l'intégrité des fichiers système"
            ])
        elif threat_category == ThreatCategory.CREDENTIAL_ACCESS:
            actions.extend([
                "Réinitialiser les mots de passe compromis",
                "Activer l'authentification multi-facteurs",
                "Surveiller les tentatives de connexion anormales"
            ])
        elif threat_category == ThreatCategory.LATERAL_MOVEMENT:
            actions.extend([
                "Segmenter le réseau pour limiter la propagation",
                "Surveiller les connexions inter-systèmes",
                "Analyser les comptes privilégiés"
            ])
        
        # Actions générales
        actions.extend([
            "Effectuer une analyse forensique approfondie",
            "Mettre à jour les signatures de détection",
            "Documenter l'incident pour améliorer la détection future"
        ])
        
        return actions[:5]  # Limiter à 5 actions prioritaires
    
    def _generate_global_recommended_actions(self, sophistication_level: str, 
                                           primary_category: ThreatCategory) -> List[str]:
        """Génère les actions recommandées globales"""
        actions = []
        
        if sophistication_level in ['Advanced Persistent Threat (APT)', 'Advanced']:
            actions.extend([
                "Activer la réponse d'incident de niveau critique",
                "Contacter les autorités compétentes si nécessaire",
                "Effectuer une analyse d'attribution de l'attaquant",
                "Mettre en place une surveillance renforcée à long terme"
            ])
        
        actions.extend([
            "Coordonner la réponse entre tous les systèmes affectés",
            "Effectuer une évaluation complète de l'impact",
            "Développer des IOCs pour la détection future",
            "Former les équipes sur les nouvelles techniques identifiées",
            "Réviser et améliorer les procédures de sécurité"
        ])
        
        return actions[:7]  # Actions prioritaires
    
    def _assess_cluster_risk(self, cluster: CorrelationCluster, 
                           threat_category: Optional[ThreatCategory], 
                           confidence: float) -> Dict[str, Any]:
        """Évalue les risques d'un cluster"""
        
        # Score de base selon la catégorie de menace
        category_risk_scores = {
            ThreatCategory.IMPACT: 1.0,
            ThreatCategory.EXFILTRATION: 0.9,
            ThreatCategory.CREDENTIAL_ACCESS: 0.8,
            ThreatCategory.LATERAL_MOVEMENT: 0.7,
            ThreatCategory.PRIVILEGE_ESCALATION: 0.7,
            ThreatCategory.PERSISTENCE: 0.6,
            ThreatCategory.DEFENSE_EVASION: 0.6,
            ThreatCategory.EXECUTION: 0.5,
            ThreatCategory.COLLECTION: 0.5,
            ThreatCategory.DISCOVERY: 0.4,
            ThreatCategory.INITIAL_ACCESS: 0.4,
            ThreatCategory.COMMAND_AND_CONTROL: 0.3,
            ThreatCategory.RECONNAISSANCE: 0.2
        }
        
        base_risk = category_risk_scores.get(threat_category, 0.3) if threat_category else 0.3
        
        # Ajustement selon la confiance
        adjusted_risk = base_risk * confidence
        
        # Détermination du niveau de risque
        if adjusted_risk >= 0.8:
            risk_level = "CRITICAL"
        elif adjusted_risk >= 0.6:
            risk_level = "HIGH"
        elif adjusted_risk >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_level': risk_level,
            'risk_score': adjusted_risk,
            'base_category_risk': base_risk,
            'confidence_factor': confidence,
            'affected_systems': len(set(a.source_module for a in cluster.artifacts))
        }
    
    def _assess_global_risk(self, clusters: List[CorrelationCluster], 
                          sophistication_level: str, confidence: float) -> Dict[str, Any]:
        """Évalue les risques globaux"""
        
        # Score selon la sophistication
        sophistication_scores = {
            'Advanced Persistent Threat (APT)': 1.0,
            'Advanced': 0.8,
            'Intermediate': 0.6,
            'Basic': 0.4,
            'Opportunistic': 0.2
        }
        
        sophistication_risk = sophistication_scores.get(sophistication_level, 0.5)
        
        # Score selon le nombre de clusters
        cluster_risk = min(len(clusters) * 0.1, 0.8)
        
        # Score combiné
        global_risk = (sophistication_risk + cluster_risk) * confidence / 2
        
        # Niveau de risque
        if global_risk >= 0.8:
            risk_level = "CRITICAL"
        elif global_risk >= 0.6:
            risk_level = "HIGH"
        elif global_risk >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_level': risk_level,
            'risk_score': global_risk,
            'sophistication_risk': sophistication_risk,
            'cluster_risk': cluster_risk,
            'confidence_factor': confidence,
            'clusters_affected': len(clusters),
            'total_artifacts': sum(len(c.artifacts) for c in clusters)
        }


class AICorrelator:
    """
    Moteur principal d'IA pour la corrélation forensique
    """
    
    def __init__(self, evidence_dir: str = "./evidence", models_dir: str = "./models"):
        """
        Initialise l'AI Correlator
        
        Args:
            evidence_dir: Répertoire contenant les données forensiques
            models_dir: Répertoire pour stocker les modèles IA
        """
        self.evidence_dir = Path(evidence_dir)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Composants IA
        self.correlation_engine = CorrelationEngine()
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.attack_analyzer = AttackProgressionAnalyzer()
        self.hypothesis_generator = HypothesisGenerator()
        
        # Base de données pour les corrélations
        self.correlation_db = self.evidence_dir / "ai_correlations.db"
        self._init_correlation_database()
    
    def _init_correlation_database(self):
        """Initialise la base de données des corrélations"""
        conn = sqlite3.connect(self.correlation_db)
        cursor = conn.cursor()
        
        # Table des artefacts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forensic_artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT,
                artifact_type TEXT,
                source_module TEXT,
                timestamp TIMESTAMP,
                data_json TEXT,
                metadata_json TEXT,
                threat_indicators TEXT,
                mitre_techniques TEXT,
                confidence_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table des clusters de corrélation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_clusters (
                cluster_id TEXT PRIMARY KEY,
                case_id TEXT,
                correlation_type TEXT,
                confidence_score REAL,
                threat_category TEXT,
                timeline_start TIMESTAMP,
                timeline_end TIMESTAMP,
                behavioral_signature TEXT,
                attack_progression TEXT,
                artifact_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table des hypothèses de menaces
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_hypotheses (
                hypothesis_id TEXT PRIMARY KEY,
                case_id TEXT,
                threat_category TEXT,
                confidence REAL,
                description TEXT,
                supporting_evidence TEXT,
                mitre_techniques TEXT,
                timeline_analysis TEXT,
                recommended_actions TEXT,
                risk_assessment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table de liaison artefacts-clusters
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cluster_artifacts (
                cluster_id TEXT,
                artifact_id TEXT,
                PRIMARY KEY (cluster_id, artifact_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_artifacts_from_modules(self, case_id: str) -> List[ForensicArtifact]:
        """Charge les artefacts depuis tous les modules d'analyse"""
        artifacts = []
        
        # Mapping des bases de données des modules
        module_dbs = {
            'disk': 'disk_analysis.db',
            'memory': 'memory_analysis.db',
            'network': 'network_analysis.db',
            'mobile': 'mobile_analysis.db',
            'crypto': 'crypto_analysis.db',
            'timeline': 'timeline_analysis.db'
        }
        
        for module_name, db_name in module_dbs.items():
            db_path = self.evidence_dir / db_name
            if db_path.exists():
                module_artifacts = self._load_artifacts_from_db(db_path, module_name, case_id)
                artifacts.extend(module_artifacts)
        
        logger.info(f"Chargement de {len(artifacts)} artefacts pour le cas {case_id}")
        return artifacts
    
    def _load_artifacts_from_db(self, db_path: Path, module_name: str, case_id: str) -> List[ForensicArtifact]:
        """Charge les artefacts depuis une base de données de module"""
        artifacts = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Requêtes spécifiques selon le module
            if module_name == 'disk':
                cursor.execute('''
                    SELECT file_path, timestamp, file_size, file_type, is_deleted, 
                           malware_score, entropy FROM file_analysis 
                    WHERE case_id = ?
                ''', (case_id,))
                
                for row in cursor.fetchall():
                    artifact = ForensicArtifact(
                        artifact_id=f"disk_{hashlib.md5(row[0].encode()).hexdigest()[:16]}",
                        artifact_type="file_analysis",
                        source_module="disk",
                        timestamp=datetime.fromisoformat(row[1]) if row[1] else datetime.now(),
                        data={
                            'file_path': row[0],
                            'file_size': row[2] or 0,
                            'file_type': row[3] or '',
                            'is_deleted': bool(row[4]),
                            'malware_score': row[5] or 0.0,
                            'entropy': row[6] or 0.0
                        }
                    )
                    
                    # Indicateurs de menace basés sur les données
                    if row[5] and row[5] > 0.5:  # malware_score
                        artifact.threat_indicators.append('malware_detected')
                        artifact.mitre_techniques.append('T1105')  # Ingress Tool Transfer
                    
                    if row[4]:  # is_deleted
                        artifact.threat_indicators.append('deleted_file')
                        artifact.mitre_techniques.append('T1070.004')  # File Deletion
                    
                    artifacts.append(artifact)
            
            elif module_name == 'memory':
                cursor.execute('''
                    SELECT process_name, pid, command_line, timestamp, 
                           cpu_usage, memory_usage FROM memory_processes 
                    WHERE case_id = ?
                ''', (case_id,))
                
                for row in cursor.fetchall():
                    artifact = ForensicArtifact(
                        artifact_id=f"memory_{row[1]}_{hashlib.md5(row[0].encode()).hexdigest()[:16]}",
                        artifact_type="process_execution",
                        source_module="memory",
                        timestamp=datetime.fromisoformat(row[3]) if row[3] else datetime.now(),
                        data={
                            'process_name': row[0],
                            'pid': row[1],
                            'command_line': row[2] or '',
                            'cpu_usage': row[4] or 0.0,
                            'memory_usage': row[5] or 0.0
                        }
                    )
                    
                    # Détection de processus suspects
                    suspicious_processes = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']
                    if any(susp in row[0].lower() for susp in suspicious_processes):
                        artifact.threat_indicators.append('suspicious_process')
                        artifact.mitre_techniques.append('T1059')  # Command and Scripting Interpreter
                    
                    artifacts.append(artifact)
            
            elif module_name == 'network':
                cursor.execute('''
                    SELECT source_ip, destination_ip, destination_port, protocol, 
                           timestamp, bytes_sent, bytes_received FROM network_flows 
                    WHERE case_id = ?
                ''', (case_id,))
                
                for row in cursor.fetchall():
                    artifact = ForensicArtifact(
                        artifact_id=f"network_{hashlib.md5(f'{row[0]}_{row[1]}_{row[2]}'.encode()).hexdigest()[:16]}",
                        artifact_type="network_connection",
                        source_module="network",
                        timestamp=datetime.fromisoformat(row[4]) if row[4] else datetime.now(),
                        data={
                            'source_ip': row[0],
                            'destination_ip': row[1],
                            'destination_port': row[2],
                            'protocol': row[3],
                            'bytes_sent': row[5] or 0,
                            'bytes_received': row[6] or 0
                        }
                    )
                    
                    # Détection de communications suspectes
                    if row[2] in [4444, 1337, 31337]:  # Ports communs des backdoors
                        artifact.threat_indicators.append('suspicious_port')
                        artifact.mitre_techniques.append('T1071')  # Application Layer Protocol
                    
                    artifacts.append(artifact)
            
            elif module_name == 'crypto':
                cursor.execute('''
                    SELECT algorithm, file_path, entropy, timestamp 
                    FROM crypto_artifacts WHERE case_id = ?
                ''', (case_id,))
                
                for row in cursor.fetchall():
                    artifact = ForensicArtifact(
                        artifact_id=f"crypto_{hashlib.md5(row[1].encode()).hexdigest()[:16]}",
                        artifact_type="cryptographic_artifact",
                        source_module="crypto",
                        timestamp=datetime.fromisoformat(row[3]) if row[3] else datetime.now(),
                        data={
                            'algorithm': row[0],
                            'file_path': row[1],
                            'entropy': row[2] or 0.0
                        }
                    )
                    
                    # Détection de crypto suspicieux
                    if row[2] and row[2] > 7.5:  # Haute entropie
                        artifact.threat_indicators.append('high_entropy')
                        artifact.mitre_techniques.append('T1027')  # Obfuscated Files or Information
                    
                    artifacts.append(artifact)
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Erreur chargement artefacts {module_name}: {e}")
        
        return artifacts
    
    def perform_correlation_analysis(self, case_id: str) -> Dict[str, Any]:
        """Effectue l'analyse de corrélation complète"""
        logger.info(f"Début de l'analyse de corrélation IA pour le cas {case_id}")
        
        # 1. Chargement des artefacts
        artifacts = self.load_artifacts_from_modules(case_id)
        if not artifacts:
            logger.warning("Aucun artefact trouvé pour l'analyse")
            return {'status': 'no_artifacts', 'clusters': [], 'hypotheses': []}
        
        # 2. Corrélations multiples
        all_clusters = []
        
        # Corrélation temporelle
        temporal_clusters = self.correlation_engine.temporal_correlation(artifacts)
        all_clusters.extend(temporal_clusters)
        
        # Corrélation comportementale
        if ML_AVAILABLE:
            behavioral_clusters = self.correlation_engine.behavioral_correlation(artifacts)
            all_clusters.extend(behavioral_clusters)
        
        # Corrélation réseau
        network_clusters = self.correlation_engine.network_flow_correlation(artifacts)
        all_clusters.extend(network_clusters)
        
        # 3. Détection d'anomalies
        anomalies = []
        if ML_AVAILABLE and len(artifacts) > 10:  # Minimum d'artefacts pour l'entraînement
            try:
                # Utiliser une partie des artefacts pour l'entraînement
                train_artifacts = artifacts[:int(len(artifacts) * 0.8)]
                test_artifacts = artifacts[int(len(artifacts) * 0.8):]
                
                self.anomaly_detector.fit(train_artifacts)
                anomalies = self.anomaly_detector.detect_anomalies(test_artifacts)
            except Exception as e:
                logger.warning(f"Erreur détection d'anomalies: {e}")
        
        # 4. Classification des menaces
        threat_classifications = []
        if ML_AVAILABLE and len(artifacts) > 20:  # Minimum pour classification
            try:
                # Préparation des artefacts avec labels pour l'entraînement
                labeled_artifacts = [a for a in artifacts if a.mitre_techniques or a.threat_indicators]
                if len(labeled_artifacts) >= 10:
                    self.threat_classifier.train(labeled_artifacts, epochs=5)
                    threat_classifications = self.threat_classifier.classify_threats(artifacts)
            except Exception as e:
                logger.warning(f"Erreur classification des menaces: {e}")
        
        # 5. Génération d'hypothèses
        hypotheses = self.hypothesis_generator.generate_threat_hypotheses(all_clusters, artifacts)
        
        # 6. Sauvegarde des résultats
        self._save_correlation_results(case_id, artifacts, all_clusters, hypotheses, anomalies)
        
        # 7. Compilation des résultats
        results = {
            'status': 'success',
            'case_id': case_id,
            'artifacts_analyzed': len(artifacts),
            'clusters': {
                'total': len(all_clusters),
                'temporal': len(temporal_clusters),
                'behavioral': len([c for c in all_clusters if c.correlation_type == CorrelationType.BEHAVIORAL]),
                'network': len(network_clusters),
                'details': [self._serialize_cluster(c) for c in all_clusters]
            },
            'anomalies': {
                'count': len(anomalies),
                'details': [(a.artifact_id, score) for a, score in anomalies[:10]]  # Top 10
            },
            'threat_classifications': {
                'count': len(threat_classifications),
                'details': [(a.artifact_id, threat_class, conf) for a, threat_class, conf in threat_classifications[:10]]
            },
            'hypotheses': {
                'count': len(hypotheses),
                'details': [self._serialize_hypothesis(h) for h in hypotheses]
            },
            'analysis_summary': self._generate_analysis_summary(all_clusters, hypotheses, anomalies)
        }
        
        logger.info(f"Analyse de corrélation terminée: {len(all_clusters)} clusters, {len(hypotheses)} hypothèses")
        return results
    
    def _save_correlation_results(self, case_id: str, artifacts: List[ForensicArtifact],
                                clusters: List[CorrelationCluster], hypotheses: List[ThreatHypothesis],
                                anomalies: List[Tuple[ForensicArtifact, float]]):
        """Sauvegarde les résultats de corrélation dans la base de données"""
        conn = sqlite3.connect(self.correlation_db)
        cursor = conn.cursor()
        
        try:
            # Sauvegarde des artefacts
            for artifact in artifacts:
                cursor.execute('''
                    INSERT OR REPLACE INTO forensic_artifacts 
                    (artifact_id, case_id, artifact_type, source_module, timestamp, 
                     data_json, metadata_json, threat_indicators, mitre_techniques, confidence_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    artifact.artifact_id, case_id, artifact.artifact_type, artifact.source_module,
                    artifact.timestamp.isoformat(), json.dumps(artifact.data), 
                    json.dumps(artifact.metadata), json.dumps(artifact.threat_indicators),
                    json.dumps(artifact.mitre_techniques), artifact.confidence_score
                ))
            
            # Sauvegarde des clusters
            for cluster in clusters:
                cursor.execute('''
                    INSERT OR REPLACE INTO correlation_clusters 
                    (cluster_id, case_id, correlation_type, confidence_score, threat_category,
                     timeline_start, timeline_end, behavioral_signature, attack_progression, artifact_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cluster.cluster_id, case_id, cluster.correlation_type.value, cluster.confidence_score,
                    cluster.threat_category.value if cluster.threat_category else None,
                    cluster.timeline[0].isoformat() if cluster.timeline else None,
                    cluster.timeline[1].isoformat() if cluster.timeline else None,
                    json.dumps(cluster.behavioral_signature), json.dumps(cluster.attack_progression),
                    len(cluster.artifacts)
                ))
                
                # Liaison artefacts-clusters
                for artifact in cluster.artifacts:
                    cursor.execute('''
                        INSERT OR REPLACE INTO cluster_artifacts (cluster_id, artifact_id)
                        VALUES (?, ?)
                    ''', (cluster.cluster_id, artifact.artifact_id))
            
            # Sauvegarde des hypothèses
            for hypothesis in hypotheses:
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_hypotheses 
                    (hypothesis_id, case_id, threat_category, confidence, description,
                     supporting_evidence, mitre_techniques, timeline_analysis, 
                     recommended_actions, risk_assessment)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    hypothesis.hypothesis_id, case_id, hypothesis.threat_category.value,
                    hypothesis.confidence, hypothesis.description,
                    json.dumps(hypothesis.supporting_evidence), json.dumps(hypothesis.mitre_techniques),
                    json.dumps(hypothesis.timeline_analysis), json.dumps(hypothesis.recommended_actions),
                    json.dumps(hypothesis.risk_assessment)
                ))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde corrélations: {e}")
        finally:
            conn.close()
    
    def _serialize_cluster(self, cluster: CorrelationCluster) -> Dict[str, Any]:
        """Sérialise un cluster pour JSON"""
        return {
            'cluster_id': cluster.cluster_id,
            'correlation_type': cluster.correlation_type.value,
            'confidence_score': cluster.confidence_score,
            'threat_category': cluster.threat_category.value if cluster.threat_category else None,
            'artifact_count': len(cluster.artifacts),
            'timeline': {
                'start': cluster.timeline[0].isoformat() if cluster.timeline else None,
                'end': cluster.timeline[1].isoformat() if cluster.timeline else None
            },
            'behavioral_signature': cluster.behavioral_signature,
            'attack_progression': cluster.attack_progression
        }
    
    def _serialize_hypothesis(self, hypothesis: ThreatHypothesis) -> Dict[str, Any]:
        """Sérialise une hypothèse pour JSON"""
        return {
            'hypothesis_id': hypothesis.hypothesis_id,
            'threat_category': hypothesis.threat_category.value,
            'confidence': hypothesis.confidence,
            'description': hypothesis.description,
            'supporting_evidence_count': len(hypothesis.supporting_evidence),
            'mitre_techniques': hypothesis.mitre_techniques,
            'recommended_actions': hypothesis.recommended_actions[:3],  # Top 3
            'risk_assessment': hypothesis.risk_assessment
        }
    
    def _generate_analysis_summary(self, clusters: List[CorrelationCluster], 
                                 hypotheses: List[ThreatHypothesis],
                                 anomalies: List[Tuple[ForensicArtifact, float]]) -> Dict[str, Any]:
        """Génère un résumé de l'analyse"""
        
        # Analyse des catégories de menaces
        threat_categories = [h.threat_category for h in hypotheses if h.threat_category]
        category_counts = Counter(threat_categories)
        
        # Analyse de la confiance moyenne
        avg_cluster_confidence = np.mean([c.confidence_score for c in clusters]) if clusters else 0.0
        avg_hypothesis_confidence = np.mean([h.confidence for h in hypotheses]) if hypotheses else 0.0
        
        # Analyse des techniques MITRE
        all_mitre_techniques = set()
        for hypothesis in hypotheses:
            all_mitre_techniques.update(hypothesis.mitre_techniques)
        
        # Niveau de risque global
        if hypotheses:
            max_risk = max([h.risk_assessment.get('risk_score', 0) for h in hypotheses])
            if max_risk >= 0.8:
                global_risk_level = "CRITICAL"
            elif max_risk >= 0.6:
                global_risk_level = "HIGH"
            elif max_risk >= 0.4:
                global_risk_level = "MEDIUM"
            else:
                global_risk_level = "LOW"
        else:
            global_risk_level = "UNKNOWN"
        
        return {
            'global_risk_level': global_risk_level,
            'average_cluster_confidence': avg_cluster_confidence,
            'average_hypothesis_confidence': avg_hypothesis_confidence,
            'threat_categories': dict(category_counts),
            'mitre_techniques_count': len(all_mitre_techniques),
            'top_mitre_techniques': list(all_mitre_techniques)[:10],
            'anomalies_detected': len(anomalies),
            'high_confidence_clusters': len([c for c in clusters if c.confidence_score > 0.7]),
            'high_confidence_hypotheses': len([h for h in hypotheses if h.confidence > 0.7]),
            'attack_progression_detected': any('progression' in h.timeline_analysis for h in hypotheses),
            'coordinated_campaign_likelihood': self._assess_campaign_likelihood(clusters, hypotheses)
        }
    
    def _assess_campaign_likelihood(self, clusters: List[CorrelationCluster], 
                                  hypotheses: List[ThreatHypothesis]) -> float:
        """Évalue la probabilité d'une campagne coordonnée"""
        if not clusters or not hypotheses:
            return 0.0
        
        # Facteurs indiquant une campagne coordonnée
        factors = []
        
        # Nombre de clusters temporels
        temporal_clusters = [c for c in clusters if c.correlation_type == CorrelationType.TEMPORAL]
        if len(temporal_clusters) > 2:
            factors.append(0.3)
        
        # Diversité des types de corrélation
        correlation_types = set([c.correlation_type for c in clusters])
        if len(correlation_types) > 2:
            factors.append(0.2)
        
        # Présence de progression d'attaque
        progression_indicators = [h for h in hypotheses if 'progression' in str(h.timeline_analysis)]
        if progression_indicators:
            factors.append(0.3)
        
        # Techniques MITRE diversifiées
        all_techniques = set()
        for h in hypotheses:
            all_techniques.update(h.mitre_techniques)
        if len(all_techniques) > 5:
            factors.append(0.2)
        
        # Score final
        likelihood = sum(factors)
        return min(likelihood, 0.95)  # Plafonner à 95%
    
    def export_correlation_report(self, case_id: str, output_path: str = None) -> str:
        """Exporte un rapport de corrélation détaillé"""
        if not output_path:
            output_path = f"ai_correlation_report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Récupération des résultats depuis la base de données
        conn = sqlite3.connect(self.correlation_db)
        
        try:
            # Clusters
            clusters_df = pd.read_sql_query('''
                SELECT * FROM correlation_clusters WHERE case_id = ?
            ''', conn, params=(case_id,))
            
            # Hypothèses
            hypotheses_df = pd.read_sql_query('''
                SELECT * FROM threat_hypotheses WHERE case_id = ?
            ''', conn, params=(case_id,))
            
            # Artefacts
            artifacts_df = pd.read_sql_query('''
                SELECT * FROM forensic_artifacts WHERE case_id = ?
            ''', conn, params=(case_id,))
            
            # Compilation du rapport
            report = {
                'case_id': case_id,
                'analysis_timestamp': datetime.now().isoformat(),
                'summary': {
                    'artifacts_count': len(artifacts_df),
                    'clusters_count': len(clusters_df),
                    'hypotheses_count': len(hypotheses_df)
                },
                'clusters': clusters_df.to_dict('records') if not clusters_df.empty else [],
                'hypotheses': hypotheses_df.to_dict('records') if not hypotheses_df.empty else [],
                'artifacts_summary': {
                    'by_type': artifacts_df.groupby('artifact_type').size().to_dict() if not artifacts_df.empty else {},
                    'by_module': artifacts_df.groupby('source_module').size().to_dict() if not artifacts_df.empty else {}
                }
            }
            
            # Sauvegarde du rapport
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Rapport de corrélation exporté: {output_path}")
            return output_path
            
        finally:
            conn.close()


def main():
    """Fonction de démonstration"""
    print("🤖 Forensic Analysis Toolkit - AI Correlator")
    print("=" * 50)
    
    if not ML_AVAILABLE:
        print("⚠️  Bibliothèques ML non disponibles - Fonctionnalités limitées")
    
    if not ANALYSIS_AVAILABLE:
        print("⚠️  Bibliothèques d'analyse non disponibles - Fonctionnalités limitées")
    
    # Exemple d'utilisation
    ai_correlator = AICorrelator(
        evidence_dir="./evidence",
        models_dir="./models"
    )
    
    # Cas d'exemple
    case_id = "DEMO_AI_CASE_2024"
    print(f"\n🔍 Analyse IA pour le cas: {case_id}")
    
    try:
        # Création d'artefacts de démonstration
        demo_artifacts = [
            ForensicArtifact(
                artifact_id="demo_1",
                artifact_type="file_analysis",
                source_module="disk",
                timestamp=datetime.now() - timedelta(hours=2),
                data={"file_path": "C:\\temp\\malware.exe", "malware_score": 0.9},
                threat_indicators=["malware_detected"],
                mitre_techniques=["T1105"]
            ),
            ForensicArtifact(
                artifact_id="demo_2",
                artifact_type="process_execution",
                source_module="memory",
                timestamp=datetime.now() - timedelta(hours=1),
                data={"process_name": "powershell.exe", "command_line": "encoded_command"},
                threat_indicators=["suspicious_process"],
                mitre_techniques=["T1059.001"]
            ),
            ForensicArtifact(
                artifact_id="demo_3",
                artifact_type="network_connection",
                source_module="network",
                timestamp=datetime.now() - timedelta(minutes=30),
                data={"destination_ip": "192.168.1.100", "destination_port": 4444},
                threat_indicators=["suspicious_port"],
                mitre_techniques=["T1071"]
            )
        ]
        
        print(f"📊 Artefacts de démonstration créés: {len(demo_artifacts)}")
        
        # Analyse de corrélation temporelle
        print("\n⏱️  Corrélation temporelle...")
        temporal_clusters = ai_correlator.correlation_engine.temporal_correlation(demo_artifacts)
        print(f"   Clusters temporels identifiés: {len(temporal_clusters)}")
        
        # Analyse de corrélation réseau
        print("\n🌐 Corrélation réseau...")
        network_clusters = ai_correlator.correlation_engine.network_flow_correlation(demo_artifacts)
        print(f"   Clusters réseau identifiés: {len(network_clusters)}")
        
        # Génération d'hypothèses
        print("\n🧠 Génération d'hypothèses...")
        all_clusters = temporal_clusters + network_clusters
        hypotheses = ai_correlator.hypothesis_generator.generate_threat_hypotheses(all_clusters, demo_artifacts)
        
        print(f"   Hypothèses générées: {len(hypotheses)}")
        for i, hypothesis in enumerate(hypotheses[:3]):  # Top 3
            print(f"   #{i+1}: {hypothesis.threat_category.value} (confiance: {hypothesis.confidence:.1%})")
            print(f"        {hypothesis.description[:100]}...")
        
        # Analyse de progression d'attaque
        print("\n🎯 Analyse de progression d'attaque...")
        progression = ai_correlator.attack_analyzer.analyze_attack_progression(all_clusters)
        print(f"   Score de progression: {progression.get('progression_score', 0):.1%}")
        print(f"   Niveau de sophistication: {progression.get('attack_sophistication', {}).get('sophistication_level', 'Unknown')}")
        
        if ML_AVAILABLE:
            # Test de détection d'anomalies
            print("\n🚨 Détection d'anomalies ML...")
            try:
                ai_correlator.anomaly_detector.fit(demo_artifacts)
                anomalies = ai_correlator.anomaly_detector.detect_anomalies(demo_artifacts)
                print(f"   Anomalies détectées: {len(anomalies)}")
                for artifact, score in anomalies[:2]:  # Top 2
                    print(f"   - {artifact.artifact_id}: score {score:.3f}")
            except Exception as e:
                print(f"   ⚠️  Erreur détection anomalies: {e}")
        
        # Sauvegarde des résultats
        print("\n💾 Sauvegarde des résultats...")
        ai_correlator._save_correlation_results(case_id, demo_artifacts, all_clusters, hypotheses, [])
        
        # Export du rapport
        report_path = ai_correlator.export_correlation_report(case_id)
        print(f"   Rapport exporté: {report_path}")
        
    except Exception as e:
        print(f"❌ Erreur durant l'analyse: {e}")
        logger.error(f"Erreur démonstration AI Correlator: {e}")
    
    print("\n✅ Démonstration AI Correlator terminée")


if __name__ == "__main__":
    main()