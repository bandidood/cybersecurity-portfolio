#!/usr/bin/env python3
"""
Project 25 - Station Traffeyère IoT AI Platform
Component 4: Explainable AI (XAI) Anomaly Detection Engine

Enterprise-grade XAI system for industrial IoT anomaly detection with comprehensive
interpretability features including LIME, SHAP, feature importance analysis,
and real-time explanations.

Author: Industrial IoT Security Specialist
Date: 2024
"""

import os
import json
import asyncio
import logging
import warnings
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import pickle
import joblib
from pathlib import Path

# ML and XAI Libraries
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# Explainability Libraries
import lime
import lime.lime_tabular
import shap
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import seaborn as sns

# Statistics and Math
import scipy.stats as stats
from scipy import signal
from scipy.spatial.distance import mahalanobis

# Suppress warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xai_anomaly_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AnomalyResult:
    """Data class for anomaly detection results."""
    timestamp: datetime
    sensor_id: str
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    explanation: str
    feature_importance: Dict[str, float]
    shap_values: Optional[List[float]]
    lime_explanation: Optional[Dict[str, Any]]
    model_consensus: Dict[str, bool]
    recommended_actions: List[str]
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL

@dataclass
class ModelPerformance:
    """Data class for model performance metrics."""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_score: float
    training_time: float
    inference_time: float
    memory_usage: float

class LSTMAutoencoder:
    """LSTM-based Autoencoder for time-series anomaly detection."""
    
    def __init__(self, sequence_length: int = 50, n_features: int = 10, 
                 encoding_dim: int = 32, learning_rate: float = 0.001):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.encoding_dim = encoding_dim
        self.learning_rate = learning_rate
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = None
        
    def build_model(self):
        """Build LSTM autoencoder model."""
        self.model = Sequential([
            # Encoder
            LSTM(self.encoding_dim, return_sequences=True, input_shape=(self.sequence_length, self.n_features)),
            Dropout(0.2),
            LSTM(self.encoding_dim//2, return_sequences=False),
            Dropout(0.2),
            
            # Repeat vector
            RepeatVector(self.sequence_length),
            
            # Decoder  
            LSTM(self.encoding_dim//2, return_sequences=True),
            Dropout(0.2),
            LSTM(self.encoding_dim, return_sequences=True),
            TimeDistributed(Dense(self.n_features))
        ])
        
        self.model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='mse',
            metrics=['mae']
        )
        
        return self.model
    
    def create_sequences(self, data: np.ndarray) -> np.ndarray:
        """Create sequences for LSTM training."""
        sequences = []
        for i in range(len(data) - self.sequence_length + 1):
            sequences.append(data[i:i + self.sequence_length])
        return np.array(sequences)
    
    def fit(self, X: np.ndarray, validation_split: float = 0.2, 
            epochs: int = 100, batch_size: int = 32):
        """Train the autoencoder."""
        # Scale the data
        X_scaled = self.scaler.fit_transform(X)
        
        # Create sequences
        X_seq = self.create_sequences(X_scaled)
        
        # Build model if not exists
        if self.model is None:
            self.build_model()
        
        # Callbacks
        callbacks = [
            EarlyStopping(patience=15, restore_best_weights=True),
            ReduceLROnPlateau(factor=0.5, patience=10, min_lr=1e-7)
        ]
        
        # Train
        history = self.model.fit(
            X_seq, X_seq,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=0
        )
        
        # Calculate threshold based on reconstruction error
        X_pred = self.model.predict(X_seq, verbose=0)
        mse = np.mean(np.square(X_seq - X_pred), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
        
        return history
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies."""
        X_scaled = self.scaler.transform(X)
        X_seq = self.create_sequences(X_scaled)
        
        X_pred = self.model.predict(X_seq, verbose=0)
        mse = np.mean(np.square(X_seq - X_pred), axis=(1, 2))
        
        is_anomaly = mse > self.threshold
        return is_anomaly, mse

class XAIAnomalyDetector:
    """Comprehensive XAI-enabled anomaly detection system."""
    
    def __init__(self, config_path: str = "xai_config.json"):
        """Initialize XAI Anomaly Detector."""
        self.config = self.load_config(config_path)
        self.models = {}
        self.scalers = {}
        self.explainers = {}
        self.feature_names = []
        self.performance_metrics = {}
        self.anomaly_history = []
        
        # Initialize models
        self._initialize_models()
        
        # Statistics tracking
        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'avg_processing_time': 0,
            'model_performance': {},
            'explanation_time': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        logger.info("XAI Anomaly Detector initialized successfully")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        default_config = {
            "models": {
                "isolation_forest": {
                    "enabled": True,
                    "contamination": 0.1,
                    "n_estimators": 200,
                    "max_samples": "auto",
                    "random_state": 42
                },
                "one_class_svm": {
                    "enabled": True,
                    "nu": 0.1,
                    "kernel": "rbf",
                    "gamma": "scale"
                },
                "lstm_autoencoder": {
                    "enabled": True,
                    "sequence_length": 50,
                    "encoding_dim": 32,
                    "learning_rate": 0.001,
                    "epochs": 100,
                    "batch_size": 32
                }
            },
            "explainability": {
                "lime": {
                    "enabled": True,
                    "n_samples": 5000,
                    "n_features": 10
                },
                "shap": {
                    "enabled": True,
                    "max_evals": 1000
                },
                "feature_importance": {
                    "enabled": True,
                    "method": "permutation"
                }
            },
            "ensemble": {
                "voting_threshold": 0.5,
                "weights": {
                    "isolation_forest": 0.4,
                    "one_class_svm": 0.3,
                    "lstm_autoencoder": 0.3
                }
            },
            "risk_thresholds": {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8,
                "critical": 0.9
            },
            "features": {
                "sensor_features": [
                    "temperature", "pressure", "vibration", "current",
                    "voltage", "frequency", "power", "flow_rate",
                    "humidity", "rpm"
                ],
                "derived_features": [
                    "temperature_gradient", "pressure_change_rate",
                    "vibration_rms", "power_factor", "efficiency"
                ]
            },
            "alerting": {
                "enabled": True,
                "channels": ["email", "sms", "slack"],
                "escalation_minutes": 15
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
            else:
                config = default_config
                # Save default config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                    
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
            config = default_config
            
        return config
    
    def _initialize_models(self):
        """Initialize all anomaly detection models."""
        # Isolation Forest
        if self.config["models"]["isolation_forest"]["enabled"]:
            if_config = self.config["models"]["isolation_forest"]
            self.models["isolation_forest"] = IsolationForest(
                contamination=if_config["contamination"],
                n_estimators=if_config["n_estimators"],
                max_samples=if_config["max_samples"],
                random_state=if_config["random_state"],
                n_jobs=-1
            )
            
        # One-Class SVM
        if self.config["models"]["one_class_svm"]["enabled"]:
            svm_config = self.config["models"]["one_class_svm"]
            self.models["one_class_svm"] = OneClassSVM(
                nu=svm_config["nu"],
                kernel=svm_config["kernel"],
                gamma=svm_config["gamma"]
            )
            
        # LSTM Autoencoder
        if self.config["models"]["lstm_autoencoder"]["enabled"]:
            lstm_config = self.config["models"]["lstm_autoencoder"]
            self.models["lstm_autoencoder"] = LSTMAutoencoder(
                sequence_length=lstm_config["sequence_length"],
                encoding_dim=lstm_config["encoding_dim"],
                learning_rate=lstm_config["learning_rate"]
            )
        
        # Initialize scalers
        for model_name in self.models.keys():
            if model_name != "lstm_autoencoder":  # LSTM has its own scaler
                self.scalers[model_name] = RobustScaler()
    
    def feature_engineering(self, data: pd.DataFrame) -> pd.DataFrame:
        """Engineer features for anomaly detection."""
        engineered_data = data.copy()
        
        # Time-based features
        if 'timestamp' in data.columns:
            engineered_data['hour'] = pd.to_datetime(data['timestamp']).dt.hour
            engineered_data['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
            engineered_data['is_weekend'] = engineered_data['day_of_week'].isin([5, 6]).astype(int)
        
        # Statistical features for sensor readings
        sensor_cols = [col for col in data.columns if col not in ['timestamp', 'sensor_id']]
        
        # Rolling statistics (if enough data points)
        if len(data) > 10:
            window_size = min(10, len(data) // 2)
            for col in sensor_cols:
                if pd.api.types.is_numeric_dtype(data[col]):
                    # Moving averages
                    engineered_data[f'{col}_ma_{window_size}'] = data[col].rolling(window=window_size).mean()
                    engineered_data[f'{col}_std_{window_size}'] = data[col].rolling(window=window_size).std()
                    
                    # Rate of change
                    engineered_data[f'{col}_rate'] = data[col].diff()
                    
                    # Z-score
                    engineered_data[f'{col}_zscore'] = (data[col] - data[col].mean()) / data[col].std()
        
        # Domain-specific features
        if 'temperature' in data.columns and 'pressure' in data.columns:
            engineered_data['temp_pressure_ratio'] = data['temperature'] / (data['pressure'] + 1e-6)
        
        if 'current' in data.columns and 'voltage' in data.columns:
            engineered_data['power'] = data['current'] * data['voltage']
        
        if 'vibration' in data.columns:
            # RMS vibration
            engineered_data['vibration_rms'] = np.sqrt(data['vibration'] ** 2)
        
        # Remove infinite values and fill NaN
        engineered_data = engineered_data.replace([np.inf, -np.inf], np.nan)
        engineered_data = engineered_data.fillna(method='forward').fillna(0)
        
        return engineered_data
    
    async def train_models(self, training_data: pd.DataFrame, 
                          validation_data: Optional[pd.DataFrame] = None):
        """Train all enabled models asynchronously."""
        logger.info(f"Training models on {len(training_data)} samples")
        
        # Feature engineering
        engineered_data = self.feature_engineering(training_data)
        
        # Extract feature columns (exclude metadata)
        feature_cols = [col for col in engineered_data.columns 
                       if col not in ['timestamp', 'sensor_id', 'label']]
        self.feature_names = feature_cols
        
        X = engineered_data[feature_cols].values
        
        # Train models in parallel
        training_tasks = []
        
        for model_name, model in self.models.items():
            if model_name == "lstm_autoencoder":
                # LSTM needs special handling
                task = asyncio.create_task(self._train_lstm_async(model, X))
            else:
                # Traditional ML models
                task = asyncio.create_task(self._train_model_async(model_name, model, X))
            
            training_tasks.append(task)
        
        # Wait for all training to complete
        results = await asyncio.gather(*training_tasks, return_exceptions=True)
        
        # Initialize explainers after training
        await self._initialize_explainers(engineered_data[feature_cols])
        
        logger.info("Model training completed successfully")
        return results
    
    async def _train_model_async(self, model_name: str, model: Any, X: np.ndarray):
        """Train a single model asynchronously."""
        start_time = datetime.now()
        
        try:
            # Scale data
            X_scaled = self.scalers[model_name].fit_transform(X)
            
            # Train model in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(executor, model.fit, X_scaled)
            
            training_time = (datetime.now() - start_time).total_seconds()
            
            # Calculate performance metrics if validation data available
            self.performance_metrics[model_name] = {
                'training_time': training_time,
                'status': 'completed'
            }
            
            logger.info(f"{model_name} training completed in {training_time:.2f}s")
            return model_name, "success"
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            return model_name, f"error: {str(e)}"
    
    async def _train_lstm_async(self, model: LSTMAutoencoder, X: np.ndarray):
        """Train LSTM autoencoder asynchronously."""
        start_time = datetime.now()
        
        try:
            # Update n_features based on actual data
            model.n_features = X.shape[1]
            
            # Train in thread pool (Keras training can block)
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                history = await loop.run_in_executor(
                    executor, 
                    model.fit, 
                    X, 
                    0.2,  # validation_split
                    self.config["models"]["lstm_autoencoder"]["epochs"],
                    self.config["models"]["lstm_autoencoder"]["batch_size"]
                )
            
            training_time = (datetime.now() - start_time).total_seconds()
            
            self.performance_metrics["lstm_autoencoder"] = {
                'training_time': training_time,
                'final_loss': history.history['loss'][-1],
                'status': 'completed'
            }
            
            logger.info(f"LSTM Autoencoder training completed in {training_time:.2f}s")
            return "lstm_autoencoder", "success"
            
        except Exception as e:
            logger.error(f"Error training LSTM Autoencoder: {e}")
            return "lstm_autoencoder", f"error: {str(e)}"
    
    async def _initialize_explainers(self, X: pd.DataFrame):
        """Initialize LIME and SHAP explainers."""
        try:
            # LIME explainer for tabular data
            if self.config["explainability"]["lime"]["enabled"]:
                self.explainers["lime"] = lime.lime_tabular.LimeTabularExplainer(
                    X.values,
                    feature_names=self.feature_names,
                    class_names=['Normal', 'Anomaly'],
                    mode='classification'
                )
            
            # SHAP explainers for each model
            if self.config["explainability"]["shap"]["enabled"]:
                self.explainers["shap"] = {}
                
                # For tree-based models
                if "isolation_forest" in self.models:
                    try:
                        # Use a sample of data for SHAP background
                        background = shap.sample(X, min(100, len(X)))
                        self.explainers["shap"]["isolation_forest"] = shap.Explainer(
                            self.models["isolation_forest"].decision_function,
                            background
                        )
                    except Exception as e:
                        logger.warning(f"Could not initialize SHAP for Isolation Forest: {e}")
                
            logger.info("Explainers initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing explainers: {e}")
    
    async def predict_anomaly(self, data: pd.DataFrame) -> List[AnomalyResult]:
        """Predict anomalies with explanations."""
        start_time = datetime.now()
        
        try:
            # Feature engineering
            engineered_data = self.feature_engineering(data)
            X = engineered_data[self.feature_names].values
            
            results = []
            
            for idx, row in data.iterrows():
                # Get predictions from all models
                model_predictions = {}
                model_scores = {}
                
                # Single sample for prediction
                X_sample = X[idx].reshape(1, -1)
                
                for model_name, model in self.models.items():
                    try:
                        if model_name == "lstm_autoencoder":
                            # LSTM requires sequence data - use padding if necessary
                            if len(X) >= model.sequence_length:
                                start_idx = max(0, idx - model.sequence_length + 1)
                                X_seq = X[start_idx:idx+1]
                                if len(X_seq) < model.sequence_length:
                                    # Pad with zeros
                                    padding = np.zeros((model.sequence_length - len(X_seq), X.shape[1]))
                                    X_seq = np.vstack([padding, X_seq])
                                X_seq = X_seq.reshape(1, model.sequence_length, -1)
                                is_anomaly, score = model.predict(X_seq)
                                model_predictions[model_name] = bool(is_anomaly[0])
                                model_scores[model_name] = float(score[0])
                            else:
                                # Not enough data for LSTM
                                model_predictions[model_name] = False
                                model_scores[model_name] = 0.0
                        else:
                            # Traditional models
                            X_scaled = self.scalers[model_name].transform(X_sample)
                            prediction = model.predict(X_scaled)[0]
                            score = model.score_samples(X_scaled)[0] if hasattr(model, 'score_samples') else 0.0
                            
                            model_predictions[model_name] = prediction == -1  # -1 indicates anomaly
                            model_scores[model_name] = abs(score)
                            
                    except Exception as e:
                        logger.warning(f"Error in {model_name} prediction: {e}")
                        model_predictions[model_name] = False
                        model_scores[model_name] = 0.0
                
                # Ensemble decision
                weights = self.config["ensemble"]["weights"]
                weighted_score = sum(
                    weights.get(model_name, 0.33) * model_scores[model_name]
                    for model_name in model_scores
                )
                
                # Count positive predictions
                positive_count = sum(model_predictions.values())
                total_models = len(model_predictions)
                consensus_ratio = positive_count / total_models if total_models > 0 else 0
                
                is_anomaly = consensus_ratio >= self.config["ensemble"]["voting_threshold"]
                
                # Generate explanations
                explanation = await self._generate_explanation(
                    X_sample, is_anomaly, model_predictions, model_scores
                )
                
                # Determine risk level
                risk_level = self._determine_risk_level(weighted_score)
                
                # Create result
                result = AnomalyResult(
                    timestamp=pd.to_datetime(row.get('timestamp', datetime.now())),
                    sensor_id=str(row.get('sensor_id', 'unknown')),
                    is_anomaly=is_anomaly,
                    anomaly_score=weighted_score,
                    confidence=max(consensus_ratio, 1 - consensus_ratio),
                    explanation=explanation["summary"],
                    feature_importance=explanation["feature_importance"],
                    shap_values=explanation.get("shap_values"),
                    lime_explanation=explanation.get("lime_explanation"),
                    model_consensus=model_predictions,
                    recommended_actions=self._generate_recommendations(
                        is_anomaly, risk_level, explanation
                    ),
                    risk_level=risk_level
                )
                
                results.append(result)
                
                # Update statistics
                self.stats['total_predictions'] += 1
                if is_anomaly:
                    self.stats['anomalies_detected'] += 1
                    
            processing_time = (datetime.now() - start_time).total_seconds()
            self.stats['avg_processing_time'] = (
                (self.stats['avg_processing_time'] * (self.stats['total_predictions'] - len(results)) + 
                 processing_time) / self.stats['total_predictions']
            )
            
            logger.info(f"Processed {len(results)} samples in {processing_time:.3f}s")
            return results
            
        except Exception as e:
            logger.error(f"Error in anomaly prediction: {e}")
            raise
    
    async def _generate_explanation(self, X_sample: np.ndarray, is_anomaly: bool,
                                   model_predictions: Dict[str, bool],
                                   model_scores: Dict[str, float]) -> Dict[str, Any]:
        """Generate comprehensive explanations for the prediction."""
        explanation = {
            "summary": "",
            "feature_importance": {},
            "shap_values": None,
            "lime_explanation": None
        }
        
        try:
            # Feature importance (simple version - could be enhanced)
            if self.feature_names and len(X_sample[0]) == len(self.feature_names):
                # Calculate feature importance based on deviation from mean
                # This is a simplified version - in production, use more sophisticated methods
                feature_values = X_sample[0]
                importance_scores = {}
                
                for i, feature_name in enumerate(self.feature_names):
                    # Normalize by feature value magnitude
                    importance_scores[feature_name] = abs(feature_values[i]) / (abs(feature_values[i]) + 1e-6)
                
                # Sort by importance
                sorted_features = sorted(importance_scores.items(), key=lambda x: x[1], reverse=True)
                explanation["feature_importance"] = dict(sorted_features[:10])  # Top 10
            
            # Generate textual explanation
            if is_anomaly:
                top_features = list(explanation["feature_importance"].keys())[:3]
                explanation["summary"] = (
                    f"Anomaly detected with {max(model_scores.values()):.3f} confidence. "
                    f"Key contributing factors: {', '.join(top_features)}. "
                    f"Models in agreement: {sum(model_predictions.values())}/{len(model_predictions)}"
                )
            else:
                explanation["summary"] = (
                    f"Normal operation detected with {1 - max(model_scores.values()):.3f} confidence. "
                    f"All systems within expected parameters."
                )
            
            # SHAP explanations (if available and enabled)
            if ("shap" in self.explainers and 
                self.config["explainability"]["shap"]["enabled"]):
                try:
                    # Use first available SHAP explainer
                    for model_name, explainer in self.explainers["shap"].items():
                        shap_values = explainer(X_sample)
                        if hasattr(shap_values, 'values'):
                            explanation["shap_values"] = shap_values.values[0].tolist()
                        break
                except Exception as e:
                    logger.warning(f"SHAP explanation failed: {e}")
            
            # LIME explanations (if available and enabled)
            if ("lime" in self.explainers and 
                self.config["explainability"]["lime"]["enabled"]):
                try:
                    lime_explainer = self.explainers["lime"]
                    
                    # Create a simple predict function for LIME
                    def predict_fn(X):
                        # Return probability-like scores
                        scores = []
                        for sample in X:
                            sample_score = 0
                            for model_name, model in self.models.items():
                                if model_name != "lstm_autoencoder":
                                    try:
                                        X_scaled = self.scalers[model_name].transform(sample.reshape(1, -1))
                                        if hasattr(model, 'decision_function'):
                                            score = model.decision_function(X_scaled)[0]
                                        else:
                                            score = model.score_samples(X_scaled)[0]
                                        sample_score += score
                                    except:
                                        pass
                            scores.append([1 - abs(sample_score), abs(sample_score)])  # [normal_prob, anomaly_prob]
                        return np.array(scores)
                    
                    lime_explanation = lime_explainer.explain_instance(
                        X_sample[0],
                        predict_fn,
                        num_features=min(10, len(self.feature_names))
                    )
                    
                    # Extract LIME results
                    explanation["lime_explanation"] = {
                        "features": dict(lime_explanation.as_list()),
                        "score": lime_explanation.score,
                        "intercept": getattr(lime_explanation, 'intercept', {})
                    }
                    
                except Exception as e:
                    logger.warning(f"LIME explanation failed: {e}")
                    
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            explanation["summary"] = "Explanation generation failed"
        
        return explanation
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on anomaly score."""
        thresholds = self.config["risk_thresholds"]
        
        if score >= thresholds["critical"]:
            return "CRITICAL"
        elif score >= thresholds["high"]:
            return "HIGH"
        elif score >= thresholds["medium"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, is_anomaly: bool, risk_level: str,
                                 explanation: Dict[str, Any]) -> List[str]:
        """Generate recommended actions based on anomaly detection results."""
        recommendations = []
        
        if not is_anomaly:
            recommendations.append("Continue normal monitoring")
            return recommendations
        
        # Risk-based recommendations
        if risk_level == "CRITICAL":
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Stop equipment operation",
                "Contact emergency response team",
                "Evacuate personnel if necessary",
                "Begin emergency shutdown procedure"
            ])
        elif risk_level == "HIGH":
            recommendations.extend([
                "Schedule immediate inspection",
                "Reduce operational parameters",
                "Increase monitoring frequency",
                "Prepare maintenance team"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "Schedule maintenance within 24 hours",
                "Monitor trending parameters",
                "Review operational procedures",
                "Check sensor calibration"
            ])
        else:  # LOW
            recommendations.extend([
                "Log anomaly for trending analysis",
                "Continue routine monitoring",
                "Schedule regular maintenance check"
            ])
        
        # Feature-specific recommendations
        top_features = list(explanation.get("feature_importance", {}).keys())[:3]
        
        for feature in top_features:
            if "temperature" in feature.lower():
                recommendations.append("Check cooling system and thermal management")
            elif "pressure" in feature.lower():
                recommendations.append("Inspect pressure relief systems and seals")
            elif "vibration" in feature.lower():
                recommendations.append("Examine bearing condition and alignment")
            elif "current" in feature.lower() or "voltage" in feature.lower():
                recommendations.append("Verify electrical connections and power quality")
        
        return recommendations[:10]  # Limit to 10 recommendations
    
    def save_models(self, model_dir: str = "xai_models"):
        """Save trained models and scalers."""
        os.makedirs(model_dir, exist_ok=True)
        
        try:
            # Save traditional ML models
            for model_name, model in self.models.items():
                if model_name != "lstm_autoencoder":
                    model_path = os.path.join(model_dir, f"{model_name}.pkl")
                    joblib.dump(model, model_path)
                    
                    scaler_path = os.path.join(model_dir, f"{model_name}_scaler.pkl")
                    joblib.dump(self.scalers[model_name], scaler_path)
            
            # Save LSTM model
            if "lstm_autoencoder" in self.models:
                lstm_model = self.models["lstm_autoencoder"]
                if lstm_model.model is not None:
                    lstm_model.model.save(os.path.join(model_dir, "lstm_autoencoder.h5"))
                    
                    # Save LSTM scaler and threshold
                    lstm_data = {
                        'scaler': lstm_model.scaler,
                        'threshold': lstm_model.threshold,
                        'sequence_length': lstm_model.sequence_length,
                        'n_features': lstm_model.n_features
                    }
                    joblib.dump(lstm_data, os.path.join(model_dir, "lstm_autoencoder_data.pkl"))
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'config': self.config,
                'performance_metrics': self.performance_metrics,
                'stats': self.stats
            }
            
            with open(os.path.join(model_dir, "metadata.json"), 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            logger.info(f"Models saved to {model_dir}")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            raise
    
    def load_models(self, model_dir: str = "xai_models"):
        """Load trained models and scalers."""
        try:
            # Load metadata
            with open(os.path.join(model_dir, "metadata.json"), 'r') as f:
                metadata = json.load(f)
            
            self.feature_names = metadata['feature_names']
            self.performance_metrics = metadata['performance_metrics']
            self.stats = metadata['stats']
            
            # Load traditional ML models
            for model_name in ["isolation_forest", "one_class_svm"]:
                model_path = os.path.join(model_dir, f"{model_name}.pkl")
                scaler_path = os.path.join(model_dir, f"{model_name}_scaler.pkl")
                
                if os.path.exists(model_path) and os.path.exists(scaler_path):
                    self.models[model_name] = joblib.load(model_path)
                    self.scalers[model_name] = joblib.load(scaler_path)
            
            # Load LSTM model
            lstm_model_path = os.path.join(model_dir, "lstm_autoencoder.h5")
            lstm_data_path = os.path.join(model_dir, "lstm_autoencoder_data.pkl")
            
            if os.path.exists(lstm_model_path) and os.path.exists(lstm_data_path):
                lstm_data = joblib.load(lstm_data_path)
                
                lstm_model = LSTMAutoencoder(
                    sequence_length=lstm_data['sequence_length'],
                    n_features=lstm_data['n_features']
                )
                lstm_model.model = load_model(lstm_model_path)
                lstm_model.scaler = lstm_data['scaler']
                lstm_model.threshold = lstm_data['threshold']
                
                self.models["lstm_autoencoder"] = lstm_model
            
            logger.info(f"Models loaded from {model_dir}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the XAI system."""
        stats = self.stats.copy()
        stats.update({
            'model_status': {
                model_name: 'trained' if model_name in self.models else 'not_trained'
                for model_name in ["isolation_forest", "one_class_svm", "lstm_autoencoder"]
            },
            'feature_count': len(self.feature_names),
            'explainers_available': list(self.explainers.keys()),
            'anomaly_rate': (
                self.stats['anomalies_detected'] / self.stats['total_predictions']
                if self.stats['total_predictions'] > 0 else 0
            ),
            'performance_metrics': self.performance_metrics
        })
        return stats

# Visualization and reporting functions
class XAIVisualizer:
    """Visualization component for XAI results."""
    
    def __init__(self, output_dir: str = "xai_visualizations"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def plot_anomaly_timeline(self, results: List[AnomalyResult], 
                             save_path: Optional[str] = None) -> str:
        """Create timeline plot of anomaly detections."""
        timestamps = [r.timestamp for r in results]
        anomaly_scores = [r.anomaly_score for r in results]
        is_anomaly = [r.is_anomaly for r in results]
        risk_levels = [r.risk_level for r in results]
        
        # Create plotly figure
        fig = go.Figure()
        
        # Add anomaly score trace
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=anomaly_scores,
            mode='lines+markers',
            name='Anomaly Score',
            line=dict(color='blue', width=2),
            marker=dict(
                size=[8 if anomaly else 4 for anomaly in is_anomaly],
                color=[self._get_risk_color(risk) for risk in risk_levels],
                line=dict(width=1, color='darkblue')
            ),
            hovertemplate='<b>%{x}</b><br>Score: %{y:.3f}<br>Risk: %{text}<extra></extra>',
            text=risk_levels
        ))
        
        # Add threshold line
        fig.add_hline(y=0.5, line_dash="dash", line_color="red", 
                     annotation_text="Alert Threshold")
        
        fig.update_layout(
            title='XAI Anomaly Detection Timeline',
            xaxis_title='Timestamp',
            yaxis_title='Anomaly Score',
            template='plotly_white',
            hovermode='x unified'
        )
        
        # Save
        if save_path is None:
            save_path = os.path.join(self.output_dir, "anomaly_timeline.html")
        
        fig.write_html(save_path)
        return save_path
    
    def plot_feature_importance_dashboard(self, results: List[AnomalyResult],
                                        save_path: Optional[str] = None) -> str:
        """Create comprehensive feature importance dashboard."""
        # Aggregate feature importance across all results
        feature_importance_agg = {}
        
        for result in results:
            if result.is_anomaly:  # Focus on anomalies
                for feature, importance in result.feature_importance.items():
                    if feature not in feature_importance_agg:
                        feature_importance_agg[feature] = []
                    feature_importance_agg[feature].append(importance)
        
        # Calculate average importance
        avg_importance = {
            feature: np.mean(values) 
            for feature, values in feature_importance_agg.items()
        }
        
        # Sort by importance
        sorted_features = sorted(avg_importance.items(), key=lambda x: x[1], reverse=True)
        top_features = sorted_features[:15]  # Top 15 features
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Feature Importance Ranking', 'Importance Distribution',
                           'Risk Level Distribution', 'Model Consensus'),
            specs=[[{"type": "bar"}, {"type": "box"}],
                   [{"type": "pie"}, {"type": "bar"}]]
        )
        
        # Feature importance ranking
        features, importances = zip(*top_features) if top_features else ([], [])
        fig.add_trace(go.Bar(
            x=list(importances),
            y=list(features),
            orientation='h',
            name='Avg Importance',
            marker_color='steelblue'
        ), row=1, col=1)
        
        # Importance distribution
        if feature_importance_agg:
            feature_name = list(feature_importance_agg.keys())[0]
            fig.add_trace(go.Box(
                y=feature_importance_agg[feature_name],
                name=feature_name,
                marker_color='lightgreen'
            ), row=1, col=2)
        
        # Risk level distribution
        risk_counts = {}
        for result in results:
            risk_counts[result.risk_level] = risk_counts.get(result.risk_level, 0) + 1
        
        if risk_counts:
            fig.add_trace(go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                name="Risk Levels"
            ), row=2, col=1)
        
        # Model consensus
        model_agreement = {'All Agree': 0, 'Partial': 0, 'Disagree': 0}
        for result in results:
            if result.is_anomaly:
                consensus_count = sum(result.model_consensus.values())
                total_models = len(result.model_consensus)
                if consensus_count == total_models:
                    model_agreement['All Agree'] += 1
                elif consensus_count > 0:
                    model_agreement['Partial'] += 1
                else:
                    model_agreement['Disagree'] += 1
        
        fig.add_trace(go.Bar(
            x=list(model_agreement.keys()),
            y=list(model_agreement.values()),
            name='Model Agreement',
            marker_color=['green', 'orange', 'red']
        ), row=2, col=2)
        
        fig.update_layout(
            title_text="XAI Feature Importance Dashboard",
            template='plotly_white',
            height=800
        )
        
        # Save
        if save_path is None:
            save_path = os.path.join(self.output_dir, "feature_importance_dashboard.html")
        
        fig.write_html(save_path)
        return save_path
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'orange',
            'CRITICAL': 'red'
        }
        return colors.get(risk_level, 'gray')

# Example usage and testing
async def main():
    """Main function for testing the XAI Anomaly Detector."""
    # Initialize XAI detector
    detector = XAIAnomalyDetector()
    
    # Generate sample industrial IoT data
    np.random.seed(42)
    n_samples = 1000
    
    # Normal data
    normal_data = {
        'timestamp': pd.date_range('2024-01-01', periods=n_samples, freq='1min'),
        'sensor_id': ['SENSOR_001'] * n_samples,
        'temperature': np.random.normal(75, 5, n_samples),  # Normal around 75°C
        'pressure': np.random.normal(1013, 50, n_samples),  # Normal atmospheric pressure
        'vibration': np.random.normal(0.1, 0.02, n_samples),  # Low vibration
        'current': np.random.normal(10, 1, n_samples),  # 10A nominal
        'voltage': np.random.normal(240, 5, n_samples),  # 240V nominal
        'frequency': np.random.normal(60, 0.1, n_samples),  # 60Hz
        'power': np.random.normal(2400, 200, n_samples),  # Power = V * I
        'flow_rate': np.random.normal(100, 10, n_samples),  # Flow rate
        'humidity': np.random.normal(45, 5, n_samples),  # Humidity %
        'rpm': np.random.normal(1800, 50, n_samples)  # RPM
    }
    
    # Add some anomalies (10% of data)
    anomaly_indices = np.random.choice(n_samples, size=int(0.1 * n_samples), replace=False)
    
    for idx in anomaly_indices:
        # Create different types of anomalies
        anomaly_type = np.random.choice(['temperature', 'vibration', 'electrical', 'mechanical'])
        
        if anomaly_type == 'temperature':
            normal_data['temperature'][idx] = np.random.choice([120, 30])  # Too hot or too cold
        elif anomaly_type == 'vibration':
            normal_data['vibration'][idx] = np.random.uniform(0.5, 1.0)  # High vibration
        elif anomaly_type == 'electrical':
            normal_data['current'][idx] = np.random.choice([20, 2])  # High or low current
            normal_data['voltage'][idx] = np.random.choice([300, 180])  # High or low voltage
        elif anomaly_type == 'mechanical':
            normal_data['rpm'][idx] = np.random.choice([3000, 500])  # High or low RPM
            normal_data['flow_rate'][idx] = np.random.choice([200, 20])  # High or low flow
    
    # Create DataFrame
    df = pd.DataFrame(normal_data)
    
    # Split into training and testing
    train_data = df.iloc[:800]
    test_data = df.iloc[800:]
    
    print("Training XAI models...")
    await detector.train_models(train_data)
    
    print("Making predictions on test data...")
    results = await detector.predict_anomaly(test_data)
    
    # Print results
    print(f"\n=== XAI Anomaly Detection Results ===")
    print(f"Total samples processed: {len(results)}")
    print(f"Anomalies detected: {sum(1 for r in results if r.is_anomaly)}")
    
    # Show some example results
    print(f"\n=== Sample Results ===")
    for i, result in enumerate(results[:5]):
        print(f"\nSample {i+1}:")
        print(f"  Timestamp: {result.timestamp}")
        print(f"  Anomaly: {result.is_anomaly}")
        print(f"  Score: {result.anomaly_score:.3f}")
        print(f"  Risk Level: {result.risk_level}")
        print(f"  Explanation: {result.explanation}")
        print(f"  Top Features: {list(result.feature_importance.keys())[:3]}")
        print(f"  Model Consensus: {result.model_consensus}")
        print(f"  Recommendations: {result.recommended_actions[:2]}")
    
    # Generate visualizations
    print("\nGenerating visualizations...")
    visualizer = XAIVisualizer()
    
    timeline_path = visualizer.plot_anomaly_timeline(results)
    dashboard_path = visualizer.plot_feature_importance_dashboard(results)
    
    print(f"Timeline plot saved: {timeline_path}")
    print(f"Dashboard saved: {dashboard_path}")
    
    # Save models
    print("Saving models...")
    detector.save_models()
    
    # Print statistics
    stats = detector.get_statistics()
    print(f"\n=== System Statistics ===")
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\nXAI Anomaly Detection demonstration completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())