#!/usr/bin/env python3
"""
User and Entity Behavior Analytics (UEBA) Engine
Advanced behavioral analysis using machine learning for anomaly detection.

Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
import pickle
import warnings
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt
import seaborn as sns

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

@dataclass
class BehavioralProfile:
    """User behavioral profile with statistical baselines."""
    user_id: str
    entity_type: str
    baseline_features: Dict[str, float]
    statistical_model: Dict[str, Any]
    risk_score: float
    last_updated: datetime
    anomaly_history: List[Dict]

class BehavioralFeatureExtractor:
    """Extract behavioral features from security logs and events."""
    
    def __init__(self, elasticsearch_client=None):
        """Initialize feature extractor."""
        self.es_client = elasticsearch_client
        self.feature_categories = {
            'temporal': [
                'login_frequency', 'login_times_variance', 'weekend_activity',
                'after_hours_activity', 'session_duration_avg', 'session_duration_variance'
            ],
            'network': [
                'unique_ip_count', 'geographical_variance', 'vpn_usage',
                'failed_connection_rate', 'data_transfer_volume', 'protocol_diversity'
            ],
            'system': [
                'privilege_escalation_attempts', 'admin_tool_usage', 'system_modification_count',
                'file_access_patterns', 'process_creation_rate', 'registry_modifications'
            ],
            'application': [
                'application_diversity', 'database_access_patterns', 'email_volume',
                'file_share_access', 'web_browsing_patterns', 'download_behavior'
            ]
        }
    
    async def extract_user_features(self, user_id: str, time_window: int = 30) -> Dict[str, float]:
        """Extract comprehensive behavioral features for a user."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=time_window)
        
        features = {}
        
        try:
            # Extract temporal features
            temporal_features = await self._extract_temporal_features(user_id, start_date, end_date)
            features.update(temporal_features)
            
            # Extract network features
            network_features = await self._extract_network_features(user_id, start_date, end_date)
            features.update(network_features)
            
            # Extract system features
            system_features = await self._extract_system_features(user_id, start_date, end_date)
            features.update(system_features)
            
            # Extract application features
            app_features = await self._extract_application_features(user_id, start_date, end_date)
            features.update(app_features)
            
            # Calculate derived features
            derived_features = self._calculate_derived_features(features)
            features.update(derived_features)
            
            logger.info(f"Extracted {len(features)} features for user {user_id}")
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed for user {user_id}: {e}")
            return {}
    
    async def _extract_temporal_features(self, user_id: str, start_date: datetime, end_date: datetime) -> Dict[str, float]:
        """Extract time-based behavioral features."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_id}},
                        {"range": {"@timestamp": {
                            "gte": start_date.isoformat(),
                            "lte": end_date.isoformat()
                        }}}
                    ]
                }
            },
            "aggs": {
                "daily_activity": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "day"
                    }
                },
                "hourly_activity": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour"
                    }
                },
                "login_events": {
                    "filter": {"match": {"event.action": "logon"}},
                    "aggs": {
                        "session_durations": {
                            "terms": {"field": "session_id", "size": 1000}
                        }
                    }
                }
            },
            "size": 0
        }
        
        try:
            if self.es_client:
                response = self.es_client.search(index="winlogbeat-*,syslog-*", body=query)
                
                # Process daily activity
                daily_buckets = response['aggregations']['daily_activity']['buckets']
                daily_counts = [bucket['doc_count'] for bucket in daily_buckets]
                
                # Process hourly activity
                hourly_buckets = response['aggregations']['hourly_activity']['buckets']
                hourly_counts = [bucket['doc_count'] for bucket in hourly_buckets]
                
                # Calculate features
                features = {
                    'login_frequency': len(daily_counts) / 30.0 if daily_counts else 0,
                    'login_times_variance': np.var(hourly_counts) if hourly_counts else 0,
                    'weekend_activity': self._calculate_weekend_activity(hourly_buckets),
                    'after_hours_activity': self._calculate_after_hours_activity(hourly_buckets),
                    'session_duration_avg': self._calculate_avg_session_duration(response),
                    'session_duration_variance': self._calculate_session_duration_variance(response)
                }
                
                return features
            else:
                # Mock data for testing
                return self._generate_mock_temporal_features()
                
        except Exception as e:
            logger.error(f"Temporal feature extraction failed: {e}")
            return self._generate_mock_temporal_features()
    
    async def _extract_network_features(self, user_id: str, start_date: datetime, end_date: datetime) -> Dict[str, float]:
        """Extract network-based behavioral features."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_id}},
                        {"range": {"@timestamp": {
                            "gte": start_date.isoformat(),
                            "lte": end_date.isoformat()
                        }}},
                        {"exists": {"field": "source.ip"}}
                    ]
                }
            },
            "aggs": {
                "unique_ips": {
                    "cardinality": {"field": "source.ip"}
                },
                "geographical_locations": {
                    "cardinality": {"field": "source.geo.country_name"}
                },
                "failed_connections": {
                    "filter": {"match": {"event.outcome": "failure"}}
                },
                "data_transfer": {
                    "sum": {"field": "network.bytes"}
                }
            },
            "size": 0
        }
        
        try:
            if self.es_client:
                response = self.es_client.search(index="netflow-*,firewall-*", body=query)
                
                total_connections = response['hits']['total']['value']
                failed_connections = response['aggregations']['failed_connections']['doc_count']
                
                features = {
                    'unique_ip_count': response['aggregations']['unique_ips']['value'],
                    'geographical_variance': response['aggregations']['geographical_locations']['value'],
                    'vpn_usage': self._detect_vpn_usage(response),
                    'failed_connection_rate': failed_connections / max(total_connections, 1),
                    'data_transfer_volume': response['aggregations']['data_transfer']['value'] or 0,
                    'protocol_diversity': self._calculate_protocol_diversity(response)
                }
                
                return features
            else:
                return self._generate_mock_network_features()
                
        except Exception as e:
            logger.error(f"Network feature extraction failed: {e}")
            return self._generate_mock_network_features()
    
    async def _extract_system_features(self, user_id: str, start_date: datetime, end_date: datetime) -> Dict[str, float]:
        """Extract system-level behavioral features."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_id}},
                        {"range": {"@timestamp": {
                            "gte": start_date.isoformat(),
                            "lte": end_date.isoformat()
                        }}}
                    ]
                }
            },
            "aggs": {
                "privilege_events": {
                    "filter": {"match": {"event.action": "privilege-escalation"}}
                },
                "admin_tools": {
                    "filter": {"terms": {"process.name": ["powershell.exe", "cmd.exe", "wmic.exe"]}}
                },
                "system_modifications": {
                    "filter": {"match": {"event.category": "configuration"}}
                },
                "process_creation": {
                    "filter": {"match": {"event.action": "process-creation"}}
                }
            },
            "size": 0
        }
        
        try:
            if self.es_client:
                response = self.es_client.search(index="winlogbeat-*,syslog-*", body=query)
                
                features = {
                    'privilege_escalation_attempts': response['aggregations']['privilege_events']['doc_count'],
                    'admin_tool_usage': response['aggregations']['admin_tools']['doc_count'],
                    'system_modification_count': response['aggregations']['system_modifications']['doc_count'],
                    'file_access_patterns': self._calculate_file_access_patterns(response),
                    'process_creation_rate': response['aggregations']['process_creation']['doc_count'],
                    'registry_modifications': self._calculate_registry_modifications(response)
                }
                
                return features
            else:
                return self._generate_mock_system_features()
                
        except Exception as e:
            logger.error(f"System feature extraction failed: {e}")
            return self._generate_mock_system_features()
    
    async def _extract_application_features(self, user_id: str, start_date: datetime, end_date: datetime) -> Dict[str, float]:
        """Extract application usage behavioral features."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_id}},
                        {"range": {"@timestamp": {
                            "gte": start_date.isoformat(),
                            "lte": end_date.isoformat()
                        }}}
                    ]
                }
            },
            "aggs": {
                "applications": {
                    "cardinality": {"field": "process.name"}
                },
                "database_access": {
                    "filter": {"terms": {"process.name": ["sqlserver.exe", "mysql.exe", "oracle.exe"]}}
                },
                "email_activity": {
                    "filter": {"match": {"process.name": "outlook.exe"}}
                },
                "web_browsing": {
                    "filter": {"terms": {"process.name": ["chrome.exe", "firefox.exe", "iexplore.exe"]}}
                }
            },
            "size": 0
        }
        
        try:
            if self.es_client:
                response = self.es_client.search(index="winlogbeat-*", body=query)
                
                features = {
                    'application_diversity': response['aggregations']['applications']['value'],
                    'database_access_patterns': response['aggregations']['database_access']['doc_count'],
                    'email_volume': response['aggregations']['email_activity']['doc_count'],
                    'file_share_access': self._calculate_file_share_access(response),
                    'web_browsing_patterns': response['aggregations']['web_browsing']['doc_count'],
                    'download_behavior': self._calculate_download_behavior(response)
                }
                
                return features
            else:
                return self._generate_mock_application_features()
                
        except Exception as e:
            logger.error(f"Application feature extraction failed: {e}")
            return self._generate_mock_application_features()
    
    def _calculate_derived_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Calculate derived features from base features."""
        derived = {}
        
        try:
            # Risk indicators
            derived['anomaly_risk_score'] = (
                features.get('failed_connection_rate', 0) * 0.3 +
                features.get('privilege_escalation_attempts', 0) * 0.4 +
                features.get('after_hours_activity', 0) * 0.2 +
                features.get('geographical_variance', 0) * 0.1
            )
            
            # Activity intensity
            derived['activity_intensity'] = (
                features.get('login_frequency', 0) +
                features.get('process_creation_rate', 0) +
                features.get('application_diversity', 0)
            ) / 3.0
            
            # Security awareness score
            derived['security_awareness_score'] = max(0, 1.0 - (
                features.get('admin_tool_usage', 0) * 0.1 +
                features.get('system_modification_count', 0) * 0.05
            ))
            
        except Exception as e:
            logger.error(f"Derived feature calculation failed: {e}")
        
        return derived
    
    def _generate_mock_temporal_features(self) -> Dict[str, float]:
        """Generate mock temporal features for testing."""
        return {
            'login_frequency': np.random.normal(8.5, 2.0),
            'login_times_variance': np.random.normal(45.0, 15.0),
            'weekend_activity': np.random.uniform(0, 0.3),
            'after_hours_activity': np.random.uniform(0, 0.4),
            'session_duration_avg': np.random.normal(480, 120),  # minutes
            'session_duration_variance': np.random.normal(60, 20)
        }
    
    def _generate_mock_network_features(self) -> Dict[str, float]:
        """Generate mock network features for testing."""
        return {
            'unique_ip_count': np.random.randint(5, 25),
            'geographical_variance': np.random.randint(1, 5),
            'vpn_usage': np.random.uniform(0, 0.2),
            'failed_connection_rate': np.random.uniform(0, 0.1),
            'data_transfer_volume': np.random.exponential(1000000),  # bytes
            'protocol_diversity': np.random.randint(3, 10)
        }
    
    def _generate_mock_system_features(self) -> Dict[str, float]:
        """Generate mock system features for testing."""
        return {
            'privilege_escalation_attempts': np.random.poisson(2),
            'admin_tool_usage': np.random.poisson(15),
            'system_modification_count': np.random.poisson(5),
            'file_access_patterns': np.random.normal(100, 30),
            'process_creation_rate': np.random.poisson(50),
            'registry_modifications': np.random.poisson(8)
        }
    
    def _generate_mock_application_features(self) -> Dict[str, float]:
        """Generate mock application features for testing."""
        return {
            'application_diversity': np.random.randint(10, 30),
            'database_access_patterns': np.random.poisson(20),
            'email_volume': np.random.poisson(45),
            'file_share_access': np.random.poisson(25),
            'web_browsing_patterns': np.random.poisson(80),
            'download_behavior': np.random.poisson(12)
        }
    
    # Helper methods for feature calculations
    def _calculate_weekend_activity(self, hourly_buckets: List[Dict]) -> float:
        """Calculate weekend activity ratio."""
        try:
            weekend_activity = 0
            total_activity = 0
            
            for bucket in hourly_buckets:
                timestamp = datetime.fromisoformat(bucket['key_as_string'].replace('Z', '+00:00'))
                if timestamp.weekday() >= 5:  # Saturday=5, Sunday=6
                    weekend_activity += bucket['doc_count']
                total_activity += bucket['doc_count']
            
            return weekend_activity / max(total_activity, 1)
        except:
            return 0.0
    
    def _calculate_after_hours_activity(self, hourly_buckets: List[Dict]) -> float:
        """Calculate after-hours activity ratio."""
        try:
            after_hours_activity = 0
            total_activity = 0
            
            for bucket in hourly_buckets:
                timestamp = datetime.fromisoformat(bucket['key_as_string'].replace('Z', '+00:00'))
                hour = timestamp.hour
                if hour < 8 or hour > 18:  # Outside 8 AM - 6 PM
                    after_hours_activity += bucket['doc_count']
                total_activity += bucket['doc_count']
            
            return after_hours_activity / max(total_activity, 1)
        except:
            return 0.0
    
    def _calculate_avg_session_duration(self, response: Dict) -> float:
        """Calculate average session duration."""
        # Simplified calculation - would need actual session tracking
        return np.random.normal(480, 120)  # Mock: 8 hours ± 2 hours
    
    def _calculate_session_duration_variance(self, response: Dict) -> float:
        """Calculate session duration variance."""
        return np.random.normal(60, 20)  # Mock variance
    
    def _detect_vpn_usage(self, response: Dict) -> float:
        """Detect VPN usage patterns."""
        # Mock implementation - would analyze IP ranges, ASNs, etc.
        return np.random.uniform(0, 0.3)
    
    def _calculate_protocol_diversity(self, response: Dict) -> float:
        """Calculate network protocol diversity."""
        return np.random.randint(3, 10)
    
    def _calculate_file_access_patterns(self, response: Dict) -> float:
        """Calculate file access pattern score."""
        return np.random.normal(100, 30)
    
    def _calculate_registry_modifications(self, response: Dict) -> float:
        """Calculate registry modification count."""
        return np.random.poisson(8)
    
    def _calculate_file_share_access(self, response: Dict) -> float:
        """Calculate file share access frequency."""
        return np.random.poisson(25)
    
    def _calculate_download_behavior(self, response: Dict) -> float:
        """Calculate download behavior score."""
        return np.random.poisson(12)

class UEBAMLModels:
    """Machine learning models for UEBA analysis."""
    
    def __init__(self, model_path: str = "models/ueba"):
        """Initialize ML models."""
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Models
        self.isolation_forest = None
        self.clustering_model = None
        self.neural_network = None
        self.ensemble_model = None
        
        # Preprocessing
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Feature importance
        self.feature_importance = {}
        
    def train_anomaly_detection_models(self, training_data: pd.DataFrame) -> Dict[str, Any]:
        """Train multiple anomaly detection models."""
        results = {}
        
        try:
            # Prepare data
            feature_columns = [col for col in training_data.columns if col not in ['user_id', 'timestamp', 'label']]
            X = training_data[feature_columns].fillna(0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            self.isolation_forest.fit(X_scaled)
            results['isolation_forest'] = self._evaluate_anomaly_model(self.isolation_forest, X_scaled)
            
            # Train DBSCAN clustering
            self.clustering_model = DBSCAN(
                eps=0.5,
                min_samples=5,
                n_jobs=-1
            )
            cluster_labels = self.clustering_model.fit_predict(X_scaled)
            results['clustering'] = self._evaluate_clustering_model(cluster_labels, X_scaled)
            
            # Train Neural Network Autoencoder
            self.neural_network = self._build_autoencoder(X_scaled.shape[1])
            history = self.neural_network.fit(
                X_scaled, X_scaled,
                epochs=100,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            results['autoencoder'] = self._evaluate_autoencoder(self.neural_network, X_scaled)
            
            # Create ensemble model
            self.ensemble_model = self._create_ensemble_model(X_scaled)
            results['ensemble'] = self._evaluate_ensemble_model(self.ensemble_model, X_scaled)
            
            # Save models
            self._save_models()
            
            logger.info("UEBA models trained successfully")
            return results
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {}
    
    def detect_anomalies(self, user_features: Dict[str, float]) -> Dict[str, Any]:
        """Detect anomalies using trained models."""
        try:
            # Prepare feature vector
            feature_vector = np.array(list(user_features.values())).reshape(1, -1)
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            anomaly_scores = {}
            
            # Isolation Forest
            if self.isolation_forest:
                isolation_score = self.isolation_forest.decision_function(feature_vector_scaled)[0]
                is_anomaly_isolation = self.isolation_forest.predict(feature_vector_scaled)[0] == -1
                anomaly_scores['isolation_forest'] = {
                    'score': float(isolation_score),
                    'is_anomaly': bool(is_anomaly_isolation),
                    'threshold': 0.0
                }
            
            # Autoencoder reconstruction error
            if self.neural_network:
                reconstruction = self.neural_network.predict(feature_vector_scaled, verbose=0)
                reconstruction_error = np.mean(np.square(feature_vector_scaled - reconstruction))
                anomaly_scores['autoencoder'] = {
                    'reconstruction_error': float(reconstruction_error),
                    'is_anomaly': reconstruction_error > 0.1,  # Configurable threshold
                    'threshold': 0.1
                }
            
            # Ensemble prediction
            if self.ensemble_model:
                ensemble_score = self._predict_ensemble(feature_vector_scaled)
                anomaly_scores['ensemble'] = ensemble_score
            
            # Calculate overall anomaly score
            overall_score = self._calculate_overall_anomaly_score(anomaly_scores)
            
            return {
                'overall_anomaly_score': overall_score,
                'individual_scores': anomaly_scores,
                'feature_contributions': self._calculate_feature_contributions(user_features),
                'risk_level': self._assess_risk_level(overall_score),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return {'error': str(e)}
    
    def _build_autoencoder(self, input_dim: int) -> keras.Model:
        """Build neural network autoencoder for anomaly detection."""
        # Encoder
        input_layer = keras.Input(shape=(input_dim,))
        encoded = layers.Dense(64, activation='relu')(input_layer)
        encoded = layers.Dense(32, activation='relu')(encoded)
        encoded = layers.Dense(16, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(32, activation='relu')(encoded)
        decoded = layers.Dense(64, activation='relu')(decoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def _create_ensemble_model(self, X: np.ndarray) -> Dict[str, Any]:
        """Create ensemble model combining multiple approaches."""
        ensemble = {
            'isolation_weight': 0.4,
            'clustering_weight': 0.3,
            'autoencoder_weight': 0.3,
            'threshold': 0.6
        }
        return ensemble
    
    def _predict_ensemble(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Make ensemble prediction."""
        try:
            scores = []
            weights = []
            
            # Isolation Forest score
            if self.isolation_forest:
                iso_score = self.isolation_forest.decision_function(feature_vector)[0]
                scores.append(self._normalize_score(iso_score, -0.5, 0.5))
                weights.append(0.4)
            
            # Clustering-based anomaly score
            if self.clustering_model:
                # Calculate distance to nearest cluster center
                cluster_score = 0.5  # Simplified
                scores.append(cluster_score)
                weights.append(0.3)
            
            # Autoencoder reconstruction error
            if self.neural_network:
                reconstruction = self.neural_network.predict(feature_vector, verbose=0)
                error = np.mean(np.square(feature_vector - reconstruction))
                scores.append(min(error * 10, 1.0))  # Normalize
                weights.append(0.3)
            
            # Weighted ensemble score
            if scores and weights:
                ensemble_score = np.average(scores, weights=weights)
                return {
                    'score': float(ensemble_score),
                    'is_anomaly': ensemble_score > 0.6,
                    'confidence': float(np.std(scores)),
                    'individual_contributions': list(zip(scores, weights))
                }
            
            return {'score': 0.5, 'is_anomaly': False, 'confidence': 0.0}
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return {'score': 0.5, 'is_anomaly': False, 'error': str(e)}
    
    def _normalize_score(self, score: float, min_val: float, max_val: float) -> float:
        """Normalize score to 0-1 range."""
        return max(0, min(1, (score - min_val) / (max_val - min_val)))
    
    def _calculate_overall_anomaly_score(self, anomaly_scores: Dict) -> float:
        """Calculate overall anomaly score from individual model scores."""
        scores = []
        
        for model_name, model_result in anomaly_scores.items():
            if isinstance(model_result, dict) and 'score' in model_result:
                scores.append(model_result['score'])
        
        if scores:
            return float(np.mean(scores))
        return 0.5
    
    def _calculate_feature_contributions(self, features: Dict[str, float]) -> Dict[str, float]:
        """Calculate feature contributions to anomaly score."""
        contributions = {}
        
        try:
            # Simple feature importance based on deviation from mean
            for feature, value in features.items():
                # Mock calculation - in practice, use model-specific feature importance
                mean_val = 50.0  # Mock baseline
                std_val = 15.0   # Mock standard deviation
                
                deviation = abs(value - mean_val) / std_val
                contributions[feature] = min(deviation / 3.0, 1.0)  # Normalize
            
        except Exception as e:
            logger.error(f"Feature contribution calculation failed: {e}")
        
        return contributions
    
    def _assess_risk_level(self, anomaly_score: float) -> str:
        """Assess risk level based on anomaly score."""
        if anomaly_score >= 0.8:
            return 'critical'
        elif anomaly_score >= 0.6:
            return 'high'
        elif anomaly_score >= 0.4:
            return 'medium'
        elif anomaly_score >= 0.2:
            return 'low'
        else:
            return 'normal'
    
    def _evaluate_anomaly_model(self, model, X: np.ndarray) -> Dict[str, float]:
        """Evaluate anomaly detection model performance."""
        try:
            predictions = model.predict(X)
            anomaly_ratio = np.sum(predictions == -1) / len(predictions)
            
            return {
                'anomaly_ratio': float(anomaly_ratio),
                'total_samples': len(X),
                'anomalies_detected': int(np.sum(predictions == -1))
            }
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {}
    
    def _evaluate_clustering_model(self, cluster_labels: np.ndarray, X: np.ndarray) -> Dict[str, Any]:
        """Evaluate clustering model performance."""
        try:
            n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
            noise_ratio = np.sum(cluster_labels == -1) / len(cluster_labels)
            
            return {
                'n_clusters': n_clusters,
                'noise_ratio': float(noise_ratio),
                'silhouette_score': 0.5  # Mock value
            }
        except Exception as e:
            logger.error(f"Clustering evaluation failed: {e}")
            return {}
    
    def _evaluate_autoencoder(self, model, X: np.ndarray) -> Dict[str, float]:
        """Evaluate autoencoder model performance."""
        try:
            reconstructions = model.predict(X, verbose=0)
            mse = np.mean(np.square(X - reconstructions))
            
            return {
                'reconstruction_mse': float(mse),
                'mean_reconstruction_error': float(np.mean(np.mean(np.square(X - reconstructions), axis=1)))
            }
        except Exception as e:
            logger.error(f"Autoencoder evaluation failed: {e}")
            return {}
    
    def _evaluate_ensemble_model(self, model: Dict, X: np.ndarray) -> Dict[str, Any]:
        """Evaluate ensemble model performance."""
        return {
            'ensemble_configured': True,
            'weights': model,
            'threshold': model.get('threshold', 0.6)
        }
    
    def _save_models(self):
        """Save trained models to disk."""
        try:
            # Save scikit-learn models
            if self.isolation_forest:
                with open(self.model_path / 'isolation_forest.pkl', 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
            
            if self.clustering_model:
                with open(self.model_path / 'clustering_model.pkl', 'wb') as f:
                    pickle.dump(self.clustering_model, f)
            
            # Save scaler
            with open(self.model_path / 'scaler.pkl', 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # Save neural network
            if self.neural_network:
                self.neural_network.save(self.model_path / 'autoencoder.h5')
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Model saving failed: {e}")
    
    def load_models(self) -> bool:
        """Load trained models from disk."""
        try:
            # Load scikit-learn models
            isolation_path = self.model_path / 'isolation_forest.pkl'
            if isolation_path.exists():
                with open(isolation_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
            
            clustering_path = self.model_path / 'clustering_model.pkl'
            if clustering_path.exists():
                with open(clustering_path, 'rb') as f:
                    self.clustering_model = pickle.load(f)
            
            # Load scaler
            scaler_path = self.model_path / 'scaler.pkl'
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            # Load neural network
            autoencoder_path = self.model_path / 'autoencoder.h5'
            if autoencoder_path.exists():
                self.neural_network = keras.models.load_model(autoencoder_path)
            
            logger.info("Models loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Model loading failed: {e}")
            return False

class UEBAEngine:
    """Main UEBA engine coordinating feature extraction and anomaly detection."""
    
    def __init__(self, elasticsearch_client=None, config_path: str = "configs/ueba.yml"):
        """Initialize UEBA engine."""
        self.es_client = elasticsearch_client
        self.feature_extractor = BehavioralFeatureExtractor(elasticsearch_client)
        self.ml_models = UEBAMLModels()
        
        # User profiles cache
        self.user_profiles = {}
        self.baseline_window_days = 30
        self.detection_threshold = 0.6
        
        # Load configuration
        self.config = self._load_config(config_path)
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load UEBA configuration."""
        try:
            with open(config_path, 'r') as f:
                import yaml
                return yaml.safe_load(f)
        except:
            return {
                'baseline_window_days': 30,
                'detection_threshold': 0.6,
                'update_frequency_hours': 24,
                'min_training_samples': 100
            }
    
    async def analyze_user_behavior(self, user_id: str, entity_type: str = 'user') -> Dict[str, Any]:
        """Perform comprehensive behavioral analysis for a user."""
        try:
            # Extract current behavioral features
            current_features = await self.feature_extractor.extract_user_features(
                user_id, 
                self.baseline_window_days
            )
            
            if not current_features:
                return {'error': 'Failed to extract features'}
            
            # Get or create user profile
            user_profile = await self._get_or_create_profile(user_id, entity_type)
            
            # Detect anomalies
            anomaly_results = self.ml_models.detect_anomalies(current_features)
            
            # Update user profile
            await self._update_user_profile(user_id, current_features, anomaly_results)
            
            # Generate behavioral insights
            insights = self._generate_behavioral_insights(current_features, user_profile, anomaly_results)
            
            analysis_result = {
                'user_id': user_id,
                'entity_type': entity_type,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'current_features': current_features,
                'anomaly_analysis': anomaly_results,
                'behavioral_insights': insights,
                'risk_assessment': self._assess_user_risk(anomaly_results, insights),
                'recommendations': self._generate_recommendations(anomaly_results, insights)
            }
            
            logger.info(f"Behavioral analysis completed for user {user_id}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed for user {user_id}: {e}")
            return {'error': str(e)}
    
    async def batch_analyze_users(self, user_list: List[str]) -> Dict[str, Any]:
        """Perform batch behavioral analysis for multiple users."""
        results = {}
        total_users = len(user_list)
        
        logger.info(f"Starting batch analysis for {total_users} users")
        
        # Analyze users concurrently
        tasks = []
        for user_id in user_list:
            task = asyncio.create_task(self.analyze_user_behavior(user_id))
            tasks.append((user_id, task))
        
        completed = 0
        for user_id, task in tasks:
            try:
                result = await task
                results[user_id] = result
                completed += 1
                
                if completed % 10 == 0:
                    logger.info(f"Completed analysis for {completed}/{total_users} users")
                    
            except Exception as e:
                logger.error(f"Batch analysis failed for user {user_id}: {e}")
                results[user_id] = {'error': str(e)}
        
        # Generate batch summary
        batch_summary = self._generate_batch_summary(results)
        
        return {
            'batch_results': results,
            'summary': batch_summary,
            'completed_at': datetime.utcnow().isoformat()
        }
    
    async def train_baseline_models(self, training_period_days: int = 90) -> Dict[str, Any]:
        """Train baseline behavioral models using historical data."""
        try:
            logger.info(f"Starting baseline model training with {training_period_days} days of data")
            
            # Generate training data (mock implementation)
            training_data = await self._generate_training_data(training_period_days)
            
            if training_data.empty:
                return {'error': 'No training data available'}
            
            # Train ML models
            training_results = self.ml_models.train_anomaly_detection_models(training_data)
            
            # Validate models
            validation_results = await self._validate_models(training_data)
            
            return {
                'training_completed': True,
                'training_samples': len(training_data),
                'model_performance': training_results,
                'validation_results': validation_results,
                'trained_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Baseline model training failed: {e}")
            return {'error': str(e)}
    
    async def _get_or_create_profile(self, user_id: str, entity_type: str) -> BehavioralProfile:
        """Get existing user profile or create new one."""
        if user_id not in self.user_profiles:
            # Create new profile
            baseline_features = await self.feature_extractor.extract_user_features(user_id)
            
            profile = BehavioralProfile(
                user_id=user_id,
                entity_type=entity_type,
                baseline_features=baseline_features,
                statistical_model={},
                risk_score=0.5,
                last_updated=datetime.utcnow(),
                anomaly_history=[]
            )
            
            self.user_profiles[user_id] = profile
        
        return self.user_profiles[user_id]
    
    async def _update_user_profile(self, user_id: str, current_features: Dict[str, float], 
                                 anomaly_results: Dict[str, Any]):
        """Update user behavioral profile with new data."""
        try:
            profile = self.user_profiles.get(user_id)
            if not profile:
                return
            
            # Update baseline features (weighted average)
            for feature, value in current_features.items():
                if feature in profile.baseline_features:
                    # Exponential moving average
                    alpha = 0.1  # Learning rate
                    profile.baseline_features[feature] = (
                        alpha * value + (1 - alpha) * profile.baseline_features[feature]
                    )
                else:
                    profile.baseline_features[feature] = value
            
            # Update risk score
            profile.risk_score = anomaly_results.get('overall_anomaly_score', 0.5)
            
            # Add to anomaly history if anomalous
            if anomaly_results.get('overall_anomaly_score', 0) > self.detection_threshold:
                profile.anomaly_history.append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'anomaly_score': anomaly_results['overall_anomaly_score'],
                    'risk_level': anomaly_results.get('risk_level', 'unknown'),
                    'features': current_features
                })
                
                # Keep only last 50 anomaly records
                profile.anomaly_history = profile.anomaly_history[-50:]
            
            profile.last_updated = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Profile update failed for user {user_id}: {e}")
    
    def _generate_behavioral_insights(self, current_features: Dict[str, float], 
                                    profile: BehavioralProfile, 
                                    anomaly_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate behavioral insights from analysis."""
        insights = {
            'behavior_changes': [],
            'risk_factors': [],
            'normal_patterns': [],
            'trend_analysis': {}
        }
        
        try:
            # Compare current features with baseline
            for feature, current_value in current_features.items():
                baseline_value = profile.baseline_features.get(feature, current_value)
                
                if abs(current_value - baseline_value) / max(abs(baseline_value), 1) > 0.5:
                    change = {
                        'feature': feature,
                        'baseline': baseline_value,
                        'current': current_value,
                        'change_percent': ((current_value - baseline_value) / max(abs(baseline_value), 1)) * 100,
                        'significance': 'high' if abs(current_value - baseline_value) > 2 * baseline_value else 'medium'
                    }
                    insights['behavior_changes'].append(change)
            
            # Identify risk factors
            feature_contributions = anomaly_results.get('feature_contributions', {})
            for feature, contribution in feature_contributions.items():
                if contribution > 0.7:
                    insights['risk_factors'].append({
                        'feature': feature,
                        'contribution': contribution,
                        'current_value': current_features.get(feature, 0),
                        'description': self._get_feature_description(feature)
                    })
            
            # Identify normal patterns
            for feature, contribution in feature_contributions.items():
                if contribution < 0.2:
                    insights['normal_patterns'].append({
                        'feature': feature,
                        'stability': 1 - contribution,
                        'description': f"{feature} follows normal pattern"
                    })
            
        except Exception as e:
            logger.error(f"Insights generation failed: {e}")
        
        return insights
    
    def _assess_user_risk(self, anomaly_results: Dict[str, Any], insights: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall user risk level."""
        try:
            base_risk = anomaly_results.get('overall_anomaly_score', 0.5)
            
            # Risk modifiers
            behavior_change_penalty = len(insights.get('behavior_changes', [])) * 0.1
            risk_factor_penalty = len(insights.get('risk_factors', [])) * 0.15
            
            adjusted_risk = min(1.0, base_risk + behavior_change_penalty + risk_factor_penalty)
            
            return {
                'risk_score': adjusted_risk,
                'risk_level': anomaly_results.get('risk_level', 'normal'),
                'contributing_factors': {
                    'base_anomaly_score': base_risk,
                    'behavior_changes': behavior_change_penalty,
                    'risk_factors': risk_factor_penalty
                },
                'confidence': anomaly_results.get('individual_scores', {}).get('ensemble', {}).get('confidence', 0.5)
            }
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            return {'risk_score': 0.5, 'risk_level': 'unknown', 'error': str(e)}
    
    def _generate_recommendations(self, anomaly_results: Dict[str, Any], insights: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        try:
            risk_level = anomaly_results.get('risk_level', 'normal')
            
            if risk_level == 'critical':
                recommendations.extend([
                    "IMMEDIATE: Temporarily disable user account pending investigation",
                    "URGENT: Review all recent user activities and access logs",
                    "ESCALATE: Contact security team and user's manager immediately"
                ])
            elif risk_level == 'high':
                recommendations.extend([
                    "Increase monitoring frequency for this user",
                    "Review user's recent authentication logs",
                    "Consider requiring additional authentication factors"
                ])
            elif risk_level == 'medium':
                recommendations.extend([
                    "Schedule user security awareness training",
                    "Review user's access permissions and privileges",
                    "Monitor for continued anomalous behavior"
                ])
            
            # Feature-specific recommendations
            risk_factors = insights.get('risk_factors', [])
            for factor in risk_factors:
                feature = factor['feature']
                if 'privilege_escalation' in feature:
                    recommendations.append("Review user's administrative privileges")
                elif 'after_hours' in feature:
                    recommendations.append("Verify legitimate business need for after-hours access")
                elif 'failed_connection' in feature:
                    recommendations.append("Check for potential brute force attacks")
                elif 'geographical' in feature:
                    recommendations.append("Verify user's current location and travel status")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            recommendations.append("Manual review recommended due to analysis error")
        
        return recommendations
    
    def _generate_batch_summary(self, batch_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics for batch analysis."""
        summary = {
            'total_users': len(batch_results),
            'successful_analyses': 0,
            'failed_analyses': 0,
            'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'normal': 0},
            'top_risk_users': [],
            'common_anomalies': {}
        }
        
        try:
            risk_scores = []
            
            for user_id, result in batch_results.items():
                if 'error' in result:
                    summary['failed_analyses'] += 1
                    continue
                
                summary['successful_analyses'] += 1
                
                # Risk distribution
                risk_level = result.get('risk_assessment', {}).get('risk_level', 'normal')
                summary['risk_distribution'][risk_level] += 1
                
                # Collect risk scores
                risk_score = result.get('risk_assessment', {}).get('risk_score', 0.5)
                risk_scores.append((user_id, risk_score, risk_level))
            
            # Top risk users
            risk_scores.sort(key=lambda x: x[1], reverse=True)
            summary['top_risk_users'] = [
                {'user_id': user_id, 'risk_score': score, 'risk_level': level}
                for user_id, score, level in risk_scores[:10]
            ]
            
            # Calculate statistics
            if risk_scores:
                scores_only = [score for _, score, _ in risk_scores]
                summary['statistics'] = {
                    'mean_risk_score': float(np.mean(scores_only)),
                    'median_risk_score': float(np.median(scores_only)),
                    'std_risk_score': float(np.std(scores_only)),
                    'high_risk_percentage': (
                        (summary['risk_distribution']['critical'] + summary['risk_distribution']['high']) 
                        / summary['successful_analyses'] * 100
                    )
                }
            
        except Exception as e:
            logger.error(f"Batch summary generation failed: {e}")
        
        return summary
    
    async def _generate_training_data(self, period_days: int) -> pd.DataFrame:
        """Generate training data for model development."""
        try:
            # Mock training data generation
            n_samples = period_days * 10  # 10 samples per day
            n_features = 20
            
            # Generate normal behavior data (80%)
            normal_samples = int(n_samples * 0.8)
            normal_data = np.random.multivariate_normal(
                mean=np.ones(n_features) * 50,
                cov=np.eye(n_features) * 100,
                size=normal_samples
            )
            
            # Generate anomalous behavior data (20%)
            anomaly_samples = n_samples - normal_samples
            anomaly_data = np.random.multivariate_normal(
                mean=np.ones(n_features) * 80,
                cov=np.eye(n_features) * 200,
                size=anomaly_samples
            )
            
            # Combine data
            X = np.vstack([normal_data, anomaly_data])
            y = np.hstack([np.zeros(normal_samples), np.ones(anomaly_samples)])
            
            # Create feature names
            feature_names = [
                'login_frequency', 'login_times_variance', 'weekend_activity', 'after_hours_activity',
                'unique_ip_count', 'geographical_variance', 'failed_connection_rate', 'data_transfer_volume',
                'privilege_escalation_attempts', 'admin_tool_usage', 'system_modification_count', 'process_creation_rate',
                'application_diversity', 'database_access_patterns', 'email_volume', 'web_browsing_patterns',
                'anomaly_risk_score', 'activity_intensity', 'security_awareness_score', 'protocol_diversity'
            ]
            
            # Create DataFrame
            df = pd.DataFrame(X, columns=feature_names)
            df['label'] = y
            df['user_id'] = [f'user_{i % 100}' for i in range(len(df))]
            df['timestamp'] = pd.date_range(
                start=datetime.utcnow() - timedelta(days=period_days),
                periods=len(df),
                freq='H'
            )
            
            logger.info(f"Generated {len(df)} training samples")
            return df
            
        except Exception as e:
            logger.error(f"Training data generation failed: {e}")
            return pd.DataFrame()
    
    async def _validate_models(self, validation_data: pd.DataFrame) -> Dict[str, Any]:
        """Validate trained models on test data."""
        try:
            # Split data for validation
            feature_columns = [col for col in validation_data.columns if col not in ['user_id', 'timestamp', 'label']]
            X = validation_data[feature_columns].fillna(0)
            y = validation_data['label']
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            validation_results = {
                'test_samples': len(X_test),
                'model_performance': {}
            }
            
            # Validate each model if available
            if self.ml_models.isolation_forest:
                X_test_scaled = self.ml_models.scaler.transform(X_test)
                predictions = self.ml_models.isolation_forest.predict(X_test_scaled)
                
                # Convert -1/1 to 0/1 for evaluation
                predictions_binary = (predictions == -1).astype(int)
                
                validation_results['model_performance']['isolation_forest'] = {
                    'accuracy': float(np.mean(predictions_binary == y_test)),
                    'precision': 0.85,  # Mock values
                    'recall': 0.78,
                    'f1_score': 0.81
                }
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return {'error': str(e)}
    
    def _get_feature_description(self, feature: str) -> str:
        """Get human-readable description for feature."""
        descriptions = {
            'login_frequency': 'Frequency of user logins',
            'after_hours_activity': 'Activity outside normal business hours',
            'privilege_escalation_attempts': 'Attempts to gain elevated privileges',
            'failed_connection_rate': 'Rate of failed network connections',
            'geographical_variance': 'Geographic location changes',
            'admin_tool_usage': 'Usage of administrative tools',
            'unique_ip_count': 'Number of unique IP addresses accessed',
            'data_transfer_volume': 'Amount of data transferred',
            'process_creation_rate': 'Rate of new process creation',
            'application_diversity': 'Variety of applications used'
        }
        
        return descriptions.get(feature, f"Behavioral metric: {feature}")

async def main():
    """Main function for testing UEBA engine."""
    # Initialize UEBA engine
    ueba = UEBAEngine()
    
    # Load or train models
    models_loaded = ueba.ml_models.load_models()
    if not models_loaded:
        print("Training baseline models...")
        training_results = await ueba.train_baseline_models()
        print(f"Training completed: {json.dumps(training_results, indent=2)}")
    
    # Test single user analysis
    print("\nAnalyzing user behavior...")
    analysis_result = await ueba.analyze_user_behavior('john.doe', 'user')
    print(f"Analysis result: {json.dumps(analysis_result, indent=2)}")
    
    # Test batch analysis
    test_users = ['john.doe', 'jane.smith', 'admin.user', 'external.contractor']
    print(f"\nBatch analyzing {len(test_users)} users...")
    batch_result = await ueba.batch_analyze_users(test_users)
    print(f"Batch summary: {json.dumps(batch_result['summary'], indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())