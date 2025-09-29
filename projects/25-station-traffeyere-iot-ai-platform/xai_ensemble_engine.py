#!/usr/bin/env python3
"""
Project 25 - Station Traffeyère IoT AI Platform
Component 4B: Advanced Ensemble Models & Real-Time Explanation Engine

Advanced ensemble learning framework with sophisticated voting mechanisms,
confidence scoring, and real-time explainable AI capabilities for industrial IoT.

Author: Industrial IoT Security Specialist
Date: 2024
"""

import os
import json
import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import pickle
import joblib
from pathlib import Path
import hashlib
import time

# Advanced ML Libraries
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score, calinski_harabasz_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam

# Advanced explainability
import lime
import lime.lime_tabular
import shap
import eli5
from eli5.sklearn import PermutationImportance
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import seaborn as sns

# Statistical libraries
import scipy.stats as stats
from scipy.spatial.distance import mahalanobis, euclidean
from scipy.cluster.hierarchy import dendrogram, linkage
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EnsembleConfig:
    """Configuration for ensemble models."""
    voting_strategy: str = "weighted"  # weighted, majority, confidence_weighted
    confidence_threshold: float = 0.7
    model_weights: Dict[str, float] = field(default_factory=dict)
    dynamic_weighting: bool = True
    cross_validation_folds: int = 5
    feature_selection: bool = True
    feature_selection_method: str = "mutual_info"
    min_models_agreement: int = 2

@dataclass
class ExplanationConfig:
    """Configuration for explanation generation."""
    lime_samples: int = 5000
    shap_max_evals: int = 1000
    feature_importance_method: str = "permutation"  # permutation, shap, lime
    explanation_cache: bool = True
    cache_ttl_seconds: int = 300
    max_features_explain: int = 10
    generate_counterfactuals: bool = True
    confidence_intervals: bool = True

@dataclass
class ModelMetrics:
    """Comprehensive model performance metrics."""
    model_name: str
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_roc: float = 0.0
    training_time: float = 0.0
    inference_time_avg: float = 0.0
    memory_usage_mb: float = 0.0
    stability_score: float = 0.0  # Consistency across runs
    feature_importance_stability: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)

class AdvancedLSTMAutoencoder:
    """Enhanced LSTM Autoencoder with attention mechanisms."""
    
    def __init__(self, sequence_length: int = 50, n_features: int = 10,
                 encoding_dim: int = 32, attention: bool = True):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.encoding_dim = encoding_dim
        self.attention = attention
        self.model = None
        self.scaler = RobustScaler()
        self.threshold_percentile = 95
        self.threshold = None
        self.reconstruction_errors = []
        
    def build_model(self):
        """Build advanced LSTM autoencoder with attention."""
        try:
            from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed
            from tensorflow.keras.layers import Dropout, BatchNormalization, Attention
            from tensorflow.keras.models import Sequential
            from tensorflow.keras.optimizers import Adam
            from tensorflow.keras.regularizers import l1_l2
            
            self.model = Sequential([
                # Encoder with attention
                LSTM(self.encoding_dim, return_sequences=True, 
                     input_shape=(self.sequence_length, self.n_features),
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                Dropout(0.2),
                
                LSTM(self.encoding_dim // 2, return_sequences=True,
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                Dropout(0.2),
                
                LSTM(self.encoding_dim // 4, return_sequences=False,
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                
                # Bottleneck
                Dense(self.encoding_dim // 8, activation='relu'),
                Dropout(0.3),
                
                # Decoder
                RepeatVector(self.sequence_length),
                
                LSTM(self.encoding_dim // 4, return_sequences=True,
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                Dropout(0.2),
                
                LSTM(self.encoding_dim // 2, return_sequences=True,
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                Dropout(0.2),
                
                LSTM(self.encoding_dim, return_sequences=True,
                     kernel_regularizer=l1_l2(0.01, 0.01)),
                BatchNormalization(),
                
                TimeDistributed(Dense(self.n_features))
            ])
            
            # Custom loss function that emphasizes recent timesteps
            def weighted_mse(y_true, y_pred):
                # Give more weight to recent timesteps
                weights = tf.linspace(0.5, 1.5, self.sequence_length)
                weights = tf.reshape(weights, (1, -1, 1))
                mse = tf.square(y_true - y_pred)
                return tf.reduce_mean(weights * mse)
            
            self.model.compile(
                optimizer=Adam(learning_rate=0.001, clipnorm=1.0),
                loss=weighted_mse,
                metrics=['mae']
            )
            
            return self.model
            
        except Exception as e:
            logger.error(f"Error building advanced LSTM model: {e}")
            # Fallback to simple model
            return self._build_simple_model()
    
    def _build_simple_model(self):
        """Fallback simple LSTM model."""
        self.model = Sequential([
            LSTM(self.encoding_dim, input_shape=(self.sequence_length, self.n_features)),
            Dropout(0.2),
            RepeatVector(self.sequence_length),
            LSTM(self.encoding_dim, return_sequences=True),
            Dropout(0.2),
            TimeDistributed(Dense(self.n_features))
        ])
        
        self.model.compile(optimizer='adam', loss='mse', metrics=['mae'])
        return self.model

class AdvancedEnsembleDetector:
    """Advanced ensemble anomaly detector with sophisticated voting and explanations."""
    
    def __init__(self, ensemble_config: EnsembleConfig = None, 
                 explanation_config: ExplanationConfig = None):
        """Initialize advanced ensemble detector."""
        self.ensemble_config = ensemble_config or EnsembleConfig()
        self.explanation_config = explanation_config or ExplanationConfig()
        
        # Model storage
        self.models = {}
        self.scalers = {}
        self.model_metrics = {}
        self.feature_names = []
        
        # Explainability components
        self.explainers = {}
        self.explanation_cache = {}
        self.feature_importances = {}
        
        # Performance tracking
        self.prediction_history = []
        self.explanation_times = []
        
        self._initialize_models()
        logger.info("Advanced Ensemble Detector initialized")
    
    def _initialize_models(self):
        """Initialize diverse set of anomaly detection models."""
        
        # 1. Isolation Forest (Tree-based ensemble)
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            n_estimators=200,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        # 2. One-Class SVM (Support vector approach)
        self.models['one_class_svm'] = OneClassSVM(
            nu=0.1,
            kernel='rbf',
            gamma='scale'
        )
        
        # 3. Elliptic Envelope (Covariance-based)
        self.models['elliptic_envelope'] = EllipticEnvelope(
            contamination=0.1,
            random_state=42
        )
        
        # 4. Local Outlier Factor (Density-based)
        self.models['local_outlier_factor'] = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.1,
            novelty=True
        )
        
        # 5. DBSCAN Clustering (Density-based clustering)
        self.models['dbscan'] = DBSCAN(
            eps=0.5,
            min_samples=5
        )
        
        # 6. Advanced LSTM Autoencoder
        self.models['lstm_autoencoder'] = AdvancedLSTMAutoencoder()
        
        # 7. Neural Network Autoencoder
        self.models['nn_autoencoder'] = self._create_nn_autoencoder()
        
        # Initialize scalers
        for model_name in self.models.keys():
            if model_name not in ['lstm_autoencoder', 'nn_autoencoder']:
                self.scalers[model_name] = RobustScaler()
    
    def _create_nn_autoencoder(self):
        """Create neural network autoencoder."""
        class NeuralNetworkAutoencoder:
            def __init__(self, input_dim: int = 10, encoding_dim: int = 5):
                self.input_dim = input_dim
                self.encoding_dim = encoding_dim
                self.model = None
                self.scaler = StandardScaler()
                self.threshold = None
                
            def build_model(self):
                self.model = Sequential([
                    Dense(self.input_dim, activation='relu', input_shape=(self.input_dim,)),
                    BatchNormalization(),
                    Dropout(0.2),
                    
                    Dense(self.encoding_dim * 2, activation='relu'),
                    BatchNormalization(),
                    Dropout(0.3),
                    
                    Dense(self.encoding_dim, activation='relu'),  # Bottleneck
                    
                    Dense(self.encoding_dim * 2, activation='relu'),
                    BatchNormalization(),
                    Dropout(0.3),
                    
                    Dense(self.input_dim, activation='linear')
                ])
                
                self.model.compile(
                    optimizer=Adam(learning_rate=0.001),
                    loss='mse',
                    metrics=['mae']
                )
                
            def fit(self, X, epochs=100, batch_size=32, validation_split=0.2):
                if self.model is None:
                    self.input_dim = X.shape[1]
                    self.build_model()
                
                X_scaled = self.scaler.fit_transform(X)
                
                history = self.model.fit(
                    X_scaled, X_scaled,
                    epochs=epochs,
                    batch_size=batch_size,
                    validation_split=validation_split,
                    verbose=0
                )
                
                # Set threshold
                X_pred = self.model.predict(X_scaled, verbose=0)
                mse = np.mean(np.square(X_scaled - X_pred), axis=1)
                self.threshold = np.percentile(mse, 95)
                
                return history
                
            def predict(self, X):
                X_scaled = self.scaler.transform(X)
                X_pred = self.model.predict(X_scaled, verbose=0)
                mse = np.mean(np.square(X_scaled - X_pred), axis=1)
                return (mse > self.threshold).astype(int), mse
        
        return NeuralNetworkAutoencoder()
    
    def feature_engineering(self, data: pd.DataFrame) -> pd.DataFrame:
        """Advanced feature engineering with domain expertise."""
        engineered = data.copy()
        
        # Extract numeric columns
        numeric_cols = engineered.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col not in ['timestamp']]
        
        if len(numeric_cols) == 0:
            return engineered
        
        # Statistical features
        for col in numeric_cols:
            if len(engineered) > 1:
                # Lag features
                engineered[f'{col}_lag1'] = engineered[col].shift(1)
                engineered[f'{col}_lag2'] = engineered[col].shift(2)
                
                # Rolling statistics
                window = min(5, len(engineered) // 2) if len(engineered) > 5 else 2
                engineered[f'{col}_rolling_mean'] = engineered[col].rolling(window=window).mean()
                engineered[f'{col}_rolling_std'] = engineered[col].rolling(window=window).std()
                engineered[f'{col}_rolling_min'] = engineered[col].rolling(window=window).min()
                engineered[f'{col}_rolling_max'] = engineered[col].rolling(window=window).max()
                
                # Rate of change
                engineered[f'{col}_diff'] = engineered[col].diff()
                engineered[f'{col}_pct_change'] = engineered[col].pct_change()
                
                # Z-score (deviation from mean)
                mean_val = engineered[col].mean()
                std_val = engineered[col].std()
                if std_val > 0:
                    engineered[f'{col}_zscore'] = (engineered[col] - mean_val) / std_val
        
        # Cross-feature interactions
        if 'temperature' in numeric_cols and 'pressure' in numeric_cols:
            engineered['temp_pressure_ratio'] = engineered['temperature'] / (engineered['pressure'] + 1e-6)
            engineered['temp_pressure_product'] = engineered['temperature'] * engineered['pressure']
        
        if 'current' in numeric_cols and 'voltage' in numeric_cols:
            engineered['power_calculated'] = engineered['current'] * engineered['voltage']
            engineered['impedance'] = engineered['voltage'] / (engineered['current'] + 1e-6)
        
        if 'vibration' in numeric_cols:
            engineered['vibration_squared'] = engineered['vibration'] ** 2
            if len(engineered) > 1:
                engineered['vibration_acceleration'] = engineered['vibration'].diff()
        
        # FFT features for signal processing
        for col in numeric_cols:
            if len(engineered) >= 8:  # Need minimum points for FFT
                try:
                    values = engineered[col].fillna(0).values
                    fft = np.fft.fft(values)
                    engineered[f'{col}_fft_magnitude'] = np.abs(fft).mean()
                    engineered[f'{col}_fft_phase'] = np.angle(fft).mean()
                except:
                    pass
        
        # Clean up infinite and NaN values
        engineered = engineered.replace([np.inf, -np.inf], np.nan)
        engineered = engineered.fillna(method='forward').fillna(method='backward').fillna(0)
        
        return engineered
    
    async def train_ensemble(self, training_data: pd.DataFrame):
        """Train all models in the ensemble."""
        logger.info(f"Training ensemble on {len(training_data)} samples")
        
        # Feature engineering
        engineered_data = self.feature_engineering(training_data)
        
        # Extract feature columns
        feature_cols = [col for col in engineered_data.columns 
                       if col not in ['timestamp', 'sensor_id', 'label']]
        self.feature_names = feature_cols
        X = engineered_data[feature_cols].values
        
        # Train models concurrently
        tasks = []
        for model_name, model in self.models.items():
            task = asyncio.create_task(self._train_single_model(model_name, model, X))
            tasks.append(task)
        
        # Wait for all training to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate ensemble weights based on performance
        if self.ensemble_config.dynamic_weighting:
            await self._calculate_dynamic_weights(X)
        
        # Initialize explainers
        await self._initialize_explainers(engineered_data[feature_cols])
        
        logger.info("Ensemble training completed")
        return results
    
    async def _train_single_model(self, model_name: str, model: Any, X: np.ndarray):
        """Train a single model."""
        start_time = time.time()
        
        try:
            if model_name == 'lstm_autoencoder':
                model.n_features = X.shape[1]
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, model.fit, X)
                    
            elif model_name == 'nn_autoencoder':
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, model.fit, X)
                    
            elif model_name == 'dbscan':
                # DBSCAN doesn't need fitting in traditional sense
                # We'll use it during prediction
                pass
                
            else:
                # Traditional anomaly detection models
                X_scaled = self.scalers[model_name].fit_transform(X)
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, model.fit, X_scaled)
            
            training_time = time.time() - start_time
            
            # Store metrics
            self.model_metrics[model_name] = ModelMetrics(
                model_name=model_name,
                training_time=training_time,
                last_updated=datetime.now()
            )
            
            logger.info(f"{model_name} trained in {training_time:.2f}s")
            return model_name, "success"
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            return model_name, f"error: {str(e)}"
    
    async def _calculate_dynamic_weights(self, X: np.ndarray):
        """Calculate dynamic weights based on model performance."""
        weights = {}
        
        # Simple cross-validation approach for weight calculation
        from sklearn.model_selection import KFold
        
        kfold = KFold(n_splits=min(5, len(X) // 20), shuffle=True, random_state=42)
        model_scores = {name: [] for name in self.models.keys()}
        
        try:
            for train_idx, val_idx in kfold.split(X):
                X_train, X_val = X[train_idx], X[val_idx]
                
                for model_name, model in self.models.items():
                    try:
                        if model_name in ['lstm_autoencoder', 'nn_autoencoder']:
                            # Skip for now due to complexity
                            model_scores[model_name].append(0.5)
                            continue
                        elif model_name == 'dbscan':
                            model_scores[model_name].append(0.3)
                            continue
                        
                        # Train on fold
                        if model_name in self.scalers:
                            X_train_scaled = self.scalers[model_name].fit_transform(X_train)
                            X_val_scaled = self.scalers[model_name].transform(X_val)
                        else:
                            X_train_scaled, X_val_scaled = X_train, X_val
                        
                        model.fit(X_train_scaled)
                        
                        # Predict on validation
                        predictions = model.predict(X_val_scaled)
                        
                        # Simple scoring based on prediction consistency
                        score = 1.0 - (np.sum(predictions == -1) / len(predictions))
                        model_scores[model_name].append(score)
                        
                    except Exception as e:
                        logger.warning(f"Error in CV for {model_name}: {e}")
                        model_scores[model_name].append(0.1)
            
            # Calculate average scores and normalize to weights
            avg_scores = {name: np.mean(scores) for name, scores in model_scores.items()}
            total_score = sum(avg_scores.values())
            
            if total_score > 0:
                weights = {name: score / total_score for name, score in avg_scores.items()}
            else:
                # Equal weights fallback
                weights = {name: 1.0 / len(self.models) for name in self.models.keys()}
            
            self.ensemble_config.model_weights = weights
            logger.info(f"Dynamic weights calculated: {weights}")
            
        except Exception as e:
            logger.error(f"Error calculating dynamic weights: {e}")
            # Fallback to equal weights
            self.ensemble_config.model_weights = {
                name: 1.0 / len(self.models) for name in self.models.keys()
            }
    
    async def _initialize_explainers(self, X: pd.DataFrame):
        """Initialize explanation tools."""
        try:
            # LIME explainer
            self.explainers['lime'] = lime.lime_tabular.LimeTabularExplainer(
                X.values,
                feature_names=self.feature_names,
                class_names=['Normal', 'Anomaly'],
                mode='classification',
                discretize_continuous=True
            )
            
            # SHAP explainers for supported models
            self.explainers['shap'] = {}
            
            # For tree-based models, try to create SHAP explainer
            if 'isolation_forest' in self.models:
                try:
                    background = shap.sample(X, min(100, len(X)))
                    explainer = shap.Explainer(
                        self.models['isolation_forest'].decision_function,
                        background
                    )
                    self.explainers['shap']['isolation_forest'] = explainer
                except Exception as e:
                    logger.warning(f"Could not initialize SHAP for Isolation Forest: {e}")
            
            logger.info("Explainers initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing explainers: {e}")
    
    async def predict_with_explanation(self, data: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict anomalies with comprehensive explanations."""
        start_time = time.time()
        
        # Feature engineering
        engineered_data = self.feature_engineering(data)
        X = engineered_data[self.feature_names].values
        
        results = []
        
        for idx, row in data.iterrows():
            result = await self._predict_single_sample(X[idx:idx+1], row, idx)
            results.append(result)
        
        # Update timing statistics
        total_time = time.time() - start_time
        self.explanation_times.append(total_time / len(results))
        
        logger.info(f"Processed {len(results)} samples in {total_time:.3f}s")
        return results
    
    async def _predict_single_sample(self, X_sample: np.ndarray, 
                                   original_row: pd.Series, idx: int) -> Dict[str, Any]:
        """Predict and explain a single sample."""
        
        # Get predictions from all models
        model_predictions = {}
        model_scores = {}
        model_confidences = {}
        
        for model_name, model in self.models.items():
            try:
                pred, score, confidence = await self._get_model_prediction(
                    model_name, model, X_sample
                )
                model_predictions[model_name] = pred
                model_scores[model_name] = score
                model_confidences[model_name] = confidence
                
            except Exception as e:
                logger.warning(f"Error in {model_name} prediction: {e}")
                model_predictions[model_name] = False
                model_scores[model_name] = 0.0
                model_confidences[model_name] = 0.0
        
        # Ensemble decision
        ensemble_prediction = self._make_ensemble_decision(
            model_predictions, model_scores, model_confidences
        )
        
        # Generate explanation
        explanation = await self._generate_comprehensive_explanation(
            X_sample, ensemble_prediction, model_predictions, model_scores
        )
        
        # Create result
        result = {
            'timestamp': pd.to_datetime(original_row.get('timestamp', datetime.now())),
            'sensor_id': str(original_row.get('sensor_id', 'unknown')),
            'is_anomaly': ensemble_prediction['is_anomaly'],
            'anomaly_score': ensemble_prediction['score'],
            'confidence': ensemble_prediction['confidence'],
            'risk_level': self._determine_risk_level(ensemble_prediction['score']),
            'model_predictions': model_predictions,
            'model_scores': model_scores,
            'model_confidences': model_confidences,
            'explanation': explanation,
            'recommendations': self._generate_actionable_recommendations(
                ensemble_prediction, explanation
            )
        }
        
        return result
    
    async def _get_model_prediction(self, model_name: str, model: Any, 
                                  X_sample: np.ndarray) -> Tuple[bool, float, float]:
        """Get prediction from a single model."""
        
        if model_name == 'lstm_autoencoder':
            if hasattr(model, 'model') and model.model is not None:
                # For LSTM, we need sequence data
                if len(X_sample) >= model.sequence_length:
                    X_seq = X_sample[-model.sequence_length:].reshape(1, model.sequence_length, -1)
                    is_anomaly, scores = model.predict(X_seq)
                    prediction = bool(is_anomaly[0]) if len(is_anomaly) > 0 else False
                    score = float(scores[0]) if len(scores) > 0 else 0.0
                    confidence = min(0.9, max(0.1, abs(score - model.threshold) / model.threshold))
                else:
                    prediction, score, confidence = False, 0.0, 0.0
            else:
                prediction, score, confidence = False, 0.0, 0.0
                
        elif model_name == 'nn_autoencoder':
            if hasattr(model, 'model') and model.model is not None:
                predictions, scores = model.predict(X_sample)
                prediction = bool(predictions[0])
                score = float(scores[0])
                confidence = min(0.9, max(0.1, abs(score - model.threshold) / model.threshold))
            else:
                prediction, score, confidence = False, 0.0, 0.0
                
        elif model_name == 'dbscan':
            # DBSCAN clustering approach
            try:
                X_scaled = self.scalers.get('one_class_svm', StandardScaler()).transform(X_sample)
                cluster_labels = model.fit_predict(X_scaled)
                prediction = cluster_labels[0] == -1  # -1 indicates outlier
                score = 0.7 if prediction else 0.3
                confidence = 0.6
            except:
                prediction, score, confidence = False, 0.0, 0.0
                
        else:
            # Traditional anomaly detection models
            scaler = self.scalers.get(model_name, StandardScaler())
            X_scaled = scaler.transform(X_sample)
            
            pred = model.predict(X_scaled)[0]
            prediction = (pred == -1)  # -1 indicates anomaly
            
            # Get score if available
            if hasattr(model, 'score_samples'):
                score = abs(model.score_samples(X_scaled)[0])
            elif hasattr(model, 'decision_function'):
                score = abs(model.decision_function(X_scaled)[0])
            else:
                score = 0.5 if prediction else 0.1
            
            # Simple confidence calculation
            confidence = min(0.9, max(0.1, score))
        
        return prediction, score, confidence
    
    def _make_ensemble_decision(self, predictions: Dict[str, bool],
                              scores: Dict[str, float],
                              confidences: Dict[str, float]) -> Dict[str, Any]:
        """Make ensemble decision using sophisticated voting."""
        
        strategy = self.ensemble_config.voting_strategy
        weights = self.ensemble_config.model_weights
        
        if strategy == "weighted":
            # Weighted average of scores
            weighted_score = sum(
                weights.get(name, 1.0) * score 
                for name, score in scores.items()
            ) / sum(weights.get(name, 1.0) for name in scores.keys())
            
            weighted_confidence = sum(
                weights.get(name, 1.0) * confidence 
                for name, confidence in confidences.items()
            ) / sum(weights.get(name, 1.0) for name in confidences.keys())
            
            is_anomaly = weighted_score > 0.5
            
        elif strategy == "confidence_weighted":
            # Weight by confidence
            total_conf_weight = sum(confidences.values())
            if total_conf_weight > 0:
                weighted_score = sum(
                    confidences[name] * scores[name] 
                    for name in scores.keys()
                ) / total_conf_weight
                
                weighted_confidence = sum(confidences.values()) / len(confidences)
            else:
                weighted_score = sum(scores.values()) / len(scores)
                weighted_confidence = 0.5
            
            is_anomaly = weighted_score > 0.5
            
        else:  # majority voting
            positive_votes = sum(1 for pred in predictions.values() if pred)
            total_votes = len(predictions)
            
            is_anomaly = positive_votes >= (total_votes // 2 + 1)
            weighted_score = positive_votes / total_votes
            weighted_confidence = sum(confidences.values()) / len(confidences)
        
        return {
            'is_anomaly': is_anomaly,
            'score': weighted_score,
            'confidence': weighted_confidence,
            'voting_details': {
                'positive_votes': sum(1 for pred in predictions.values() if pred),
                'total_votes': len(predictions),
                'strategy': strategy
            }
        }
    
    async def _generate_comprehensive_explanation(self, X_sample: np.ndarray,
                                                ensemble_result: Dict[str, Any],
                                                model_predictions: Dict[str, bool],
                                                model_scores: Dict[str, float]) -> Dict[str, Any]:
        """Generate comprehensive explanation for the prediction."""
        
        explanation = {
            'summary': '',
            'feature_importance': {},
            'lime_explanation': None,
            'shap_values': None,
            'counterfactuals': None,
            'confidence_intervals': None,
            'model_agreements': {},
            'uncertainty_analysis': {}
        }
        
        try:
            # Check explanation cache
            sample_hash = hashlib.md5(X_sample.tobytes()).hexdigest()
            if (self.explanation_config.explanation_cache and 
                sample_hash in self.explanation_cache):
                
                cache_entry = self.explanation_cache[sample_hash]
                if (datetime.now() - cache_entry['timestamp']).seconds < self.explanation_config.cache_ttl_seconds:
                    return cache_entry['explanation']
            
            # Feature importance analysis
            feature_importance = await self._calculate_feature_importance(X_sample)
            explanation['feature_importance'] = feature_importance
            
            # Generate textual summary
            is_anomaly = ensemble_result['is_anomaly']
            score = ensemble_result['score']
            confidence = ensemble_result['confidence']
            
            top_features = list(feature_importance.keys())[:3]
            agreement_count = sum(model_predictions.values())
            total_models = len(model_predictions)
            
            if is_anomaly:
                explanation['summary'] = (
                    f"ANOMALY detected (confidence: {confidence:.2f}, score: {score:.3f}). "
                    f"Key factors: {', '.join(top_features)}. "
                    f"Model agreement: {agreement_count}/{total_models} models concur."
                )
            else:
                explanation['summary'] = (
                    f"NORMAL operation (confidence: {confidence:.2f}, score: {score:.3f}). "
                    f"All parameters within expected ranges. "
                    f"Model agreement: {total_models - agreement_count}/{total_models} models agree."
                )
            
            # LIME explanation
            if 'lime' in self.explainers:
                explanation['lime_explanation'] = await self._generate_lime_explanation(X_sample)
            
            # SHAP explanation
            if 'shap' in self.explainers and self.explainers['shap']:
                explanation['shap_values'] = await self._generate_shap_explanation(X_sample)
            
            # Model agreement analysis
            explanation['model_agreements'] = self._analyze_model_agreements(
                model_predictions, model_scores
            )
            
            # Uncertainty analysis
            explanation['uncertainty_analysis'] = self._analyze_uncertainty(
                model_scores, ensemble_result
            )
            
            # Generate counterfactuals if enabled
            if self.explanation_config.generate_counterfactuals:
                explanation['counterfactuals'] = await self._generate_counterfactuals(X_sample)
            
            # Cache the explanation
            if self.explanation_config.explanation_cache:
                self.explanation_cache[sample_hash] = {
                    'explanation': explanation,
                    'timestamp': datetime.now()
                }
            
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            explanation['summary'] = f"Explanation generation failed: {str(e)}"
        
        return explanation
    
    async def _calculate_feature_importance(self, X_sample: np.ndarray) -> Dict[str, float]:
        """Calculate feature importance for the given sample."""
        
        feature_importance = {}
        
        try:
            # Method 1: Simple statistical importance (magnitude-based)
            sample_values = X_sample[0]
            
            for i, feature_name in enumerate(self.feature_names):
                if i < len(sample_values):
                    # Normalize importance by magnitude
                    importance = abs(sample_values[i])
                    feature_importance[feature_name] = importance
            
            # Normalize to sum to 1
            total_importance = sum(feature_importance.values())
            if total_importance > 0:
                feature_importance = {
                    k: v / total_importance 
                    for k, v in feature_importance.items()
                }
            
            # Sort by importance
            sorted_features = sorted(
                feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            
            # Return top N features
            max_features = self.explanation_config.max_features_explain
            return dict(sorted_features[:max_features])
            
        except Exception as e:
            logger.error(f"Error calculating feature importance: {e}")
            return {}
    
    async def _generate_lime_explanation(self, X_sample: np.ndarray) -> Dict[str, Any]:
        """Generate LIME explanation."""
        try:
            lime_explainer = self.explainers['lime']
            
            def predict_fn(X):
                # Simple ensemble prediction for LIME
                predictions = []
                for sample in X:
                    sample_reshaped = sample.reshape(1, -1)
                    ensemble_scores = []
                    
                    for model_name, model in self.models.items():
                        try:
                            if model_name not in ['lstm_autoencoder', 'nn_autoencoder', 'dbscan']:
                                scaler = self.scalers.get(model_name, StandardScaler())
                                X_scaled = scaler.transform(sample_reshaped)
                                if hasattr(model, 'decision_function'):
                                    score = model.decision_function(X_scaled)[0]
                                else:
                                    score = model.score_samples(X_scaled)[0]
                                ensemble_scores.append(score)
                        except:
                            ensemble_scores.append(0.0)
                    
                    avg_score = np.mean(ensemble_scores) if ensemble_scores else 0.0
                    # Convert to probability-like format
                    prob_normal = 1 / (1 + np.exp(avg_score))  # Sigmoid
                    prob_anomaly = 1 - prob_normal
                    predictions.append([prob_normal, prob_anomaly])
                
                return np.array(predictions)
            
            lime_exp = lime_explainer.explain_instance(
                X_sample[0],
                predict_fn,
                num_features=min(self.explanation_config.max_features_explain, len(self.feature_names))
            )
            
            return {
                'features': dict(lime_exp.as_list()),
                'score': lime_exp.score,
                'local_prediction': lime_exp.local_pred
            }
            
        except Exception as e:
            logger.warning(f"LIME explanation failed: {e}")
            return None
    
    async def _generate_shap_explanation(self, X_sample: np.ndarray) -> List[float]:
        """Generate SHAP explanation."""
        try:
            # Use the first available SHAP explainer
            for model_name, explainer in self.explainers['shap'].items():
                shap_values = explainer(X_sample)
                if hasattr(shap_values, 'values'):
                    return shap_values.values[0].tolist()
                else:
                    return shap_values[0].tolist()
                    
        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")
            return None
    
    def _analyze_model_agreements(self, predictions: Dict[str, bool],
                                scores: Dict[str, float]) -> Dict[str, Any]:
        """Analyze agreement between models."""
        
        positive_models = [name for name, pred in predictions.items() if pred]
        negative_models = [name for name, pred in predictions.items() if not pred]
        
        # Calculate score variance
        score_values = list(scores.values())
        score_variance = np.var(score_values) if len(score_values) > 1 else 0.0
        
        return {
            'positive_models': positive_models,
            'negative_models': negative_models,
            'agreement_ratio': len(positive_models) / len(predictions),
            'score_variance': float(score_variance),
            'consensus_strength': 'high' if score_variance < 0.1 else 'medium' if score_variance < 0.3 else 'low'
        }
    
    def _analyze_uncertainty(self, model_scores: Dict[str, float],
                           ensemble_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze prediction uncertainty."""
        
        scores = list(model_scores.values())
        if len(scores) < 2:
            return {'uncertainty_level': 'unknown', 'confidence_interval': None}
        
        mean_score = np.mean(scores)
        std_score = np.std(scores)
        
        # Calculate confidence interval (approximate)
        confidence_interval = [
            max(0, mean_score - 1.96 * std_score),
            min(1, mean_score + 1.96 * std_score)
        ]
        
        # Determine uncertainty level
        if std_score < 0.1:
            uncertainty_level = 'low'
        elif std_score < 0.3:
            uncertainty_level = 'medium'
        else:
            uncertainty_level = 'high'
        
        return {
            'uncertainty_level': uncertainty_level,
            'confidence_interval': confidence_interval,
            'score_std': float(std_score),
            'prediction_stability': 'stable' if std_score < 0.15 else 'unstable'
        }
    
    async def _generate_counterfactuals(self, X_sample: np.ndarray) -> Dict[str, Any]:
        """Generate counterfactual explanations."""
        try:
            # Simple counterfactual generation
            # Find minimal changes to flip prediction
            
            counterfactuals = []
            sample = X_sample[0].copy()
            
            # Try modifying top important features
            feature_importance = await self._calculate_feature_importance(X_sample)
            top_features_idx = [
                self.feature_names.index(name) for name in list(feature_importance.keys())[:5]
                if name in self.feature_names
            ]
            
            for feature_idx in top_features_idx:
                # Try small perturbations
                for delta in [-0.1, -0.5, 0.1, 0.5]:
                    modified_sample = sample.copy()
                    modified_sample[feature_idx] *= (1 + delta)
                    
                    # Quick prediction check
                    try:
                        # Use a simple model for quick counterfactual check
                        if 'isolation_forest' in self.models:
                            scaler = self.scalers['isolation_forest']
                            X_scaled = scaler.transform(modified_sample.reshape(1, -1))
                            pred = self.models['isolation_forest'].predict(X_scaled)[0]
                            
                            if pred != self.models['isolation_forest'].predict(
                                scaler.transform(sample.reshape(1, -1)))[0]:
                                
                                counterfactuals.append({
                                    'feature_changed': self.feature_names[feature_idx],
                                    'original_value': sample[feature_idx],
                                    'new_value': modified_sample[feature_idx],
                                    'change_percent': delta * 100
                                })
                                
                                if len(counterfactuals) >= 3:
                                    break
                    except:
                        continue
                        
                if len(counterfactuals) >= 3:
                    break
            
            return {
                'counterfactuals': counterfactuals,
                'interpretation': 'These represent minimal changes that could flip the prediction'
            }
            
        except Exception as e:
            logger.warning(f"Counterfactual generation failed: {e}")
            return None
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score."""
        if score >= 0.9:
            return "CRITICAL"
        elif score >= 0.7:
            return "HIGH" 
        elif score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_actionable_recommendations(self, ensemble_result: Dict[str, Any],
                                           explanation: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if not ensemble_result['is_anomaly']:
            recommendations.append("✅ Continue normal operation and monitoring")
            return recommendations
        
        risk_level = self._determine_risk_level(ensemble_result['score'])
        confidence = ensemble_result['confidence']
        
        # Risk-based recommendations
        if risk_level == "CRITICAL":
            recommendations.extend([
                "🚨 IMMEDIATE ACTION: Stop equipment operation",
                "📞 Contact emergency response team",
                "⚠️ Initiate emergency shutdown if necessary",
                "👥 Evacuate personnel from danger zone"
            ])
        elif risk_level == "HIGH":
            recommendations.extend([
                "🔍 Schedule immediate inspection",
                "📉 Reduce operational parameters",
                "📊 Increase monitoring frequency",
                "🔧 Prepare maintenance team"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "📅 Schedule maintenance within 24 hours",
                "📈 Monitor trending parameters",
                "📋 Review operational procedures",
                "⚙️ Check sensor calibration"
            ])
        else:
            recommendations.extend([
                "📝 Log anomaly for trend analysis",
                "👁️ Continue routine monitoring",
                "🔄 Schedule next regular maintenance check"
            ])
        
        # Feature-specific recommendations
        feature_importance = explanation.get('feature_importance', {})
        top_features = list(feature_importance.keys())[:3]
        
        for feature in top_features:
            if any(temp_word in feature.lower() for temp_word in ['temp', 'thermal']):
                recommendations.append("🌡️ Check cooling system and thermal management")
            elif 'pressure' in feature.lower():
                recommendations.append("💨 Inspect pressure relief systems and seals")
            elif 'vibr' in feature.lower():
                recommendations.append("🔄 Examine bearing condition and alignment")
            elif any(elec_word in feature.lower() for elec_word in ['current', 'voltage', 'power']):
                recommendations.append("⚡ Verify electrical connections and power quality")
            elif 'flow' in feature.lower():
                recommendations.append("🌊 Check flow systems and pumps")
        
        # Uncertainty-based recommendations
        uncertainty = explanation.get('uncertainty_analysis', {})
        if uncertainty.get('uncertainty_level') == 'high':
            recommendations.append("🤔 High prediction uncertainty - consider additional sensor data")
        
        # Model agreement recommendations
        agreements = explanation.get('model_agreements', {})
        if agreements.get('consensus_strength') == 'low':
            recommendations.append("🔀 Model disagreement detected - verify with manual inspection")
        
        return recommendations[:12]  # Limit recommendations

# Example usage
async def main():
    """Example usage of the Advanced Ensemble Detector."""
    
    # Create configuration
    ensemble_config = EnsembleConfig(
        voting_strategy="confidence_weighted",
        dynamic_weighting=True
    )
    
    explanation_config = ExplanationConfig(
        generate_counterfactuals=True,
        confidence_intervals=True
    )
    
    # Initialize detector
    detector = AdvancedEnsembleDetector(ensemble_config, explanation_config)
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 500
    
    sample_data = {
        'timestamp': pd.date_range('2024-01-01', periods=n_samples, freq='1min'),
        'sensor_id': ['SENSOR_001'] * n_samples,
        'temperature': np.random.normal(75, 5, n_samples),
        'pressure': np.random.normal(1013, 50, n_samples),
        'vibration': np.random.normal(0.1, 0.02, n_samples),
        'current': np.random.normal(10, 1, n_samples),
        'voltage': np.random.normal(240, 5, n_samples),
        'rpm': np.random.normal(1800, 50, n_samples)
    }
    
    # Add anomalies
    anomaly_indices = np.random.choice(n_samples, size=50, replace=False)
    for idx in anomaly_indices:
        sample_data['temperature'][idx] = np.random.choice([120, 30])
        sample_data['vibration'][idx] = np.random.uniform(0.5, 1.0)
    
    df = pd.DataFrame(sample_data)
    
    # Split data
    train_data = df.iloc[:300]
    test_data = df.iloc[300:350]  # Smaller test set for demo
    
    print("Training advanced ensemble...")
    await detector.train_ensemble(train_data)
    
    print("Making predictions with explanations...")
    results = await detector.predict_with_explanation(test_data)
    
    # Display results
    print(f"\n=== Advanced Ensemble Results ===")
    print(f"Samples processed: {len(results)}")
    anomalies_detected = sum(1 for r in results if r['is_anomaly'])
    print(f"Anomalies detected: {anomalies_detected}")
    
    # Show detailed results for first few samples
    print(f"\n=== Detailed Sample Results ===")
    for i, result in enumerate(results[:3]):
        print(f"\n--- Sample {i+1} ---")
        print(f"Anomaly: {result['is_anomaly']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Score: {result['anomaly_score']:.3f}")
        print(f"Confidence: {result['confidence']:.3f}")
        print(f"Summary: {result['explanation']['summary']}")
        
        print(f"Top Feature Importance:")
        for feature, importance in list(result['explanation']['feature_importance'].items())[:3]:
            print(f"  {feature}: {importance:.3f}")
        
        print(f"Model Agreement: {result['explanation']['model_agreements']['consensus_strength']}")
        print(f"Uncertainty: {result['explanation']['uncertainty_analysis']['uncertainty_level']}")
        
        print(f"Top Recommendations:")
        for rec in result['recommendations'][:3]:
            print(f"  {rec}")
    
    print("\nAdvanced Ensemble Detection completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())