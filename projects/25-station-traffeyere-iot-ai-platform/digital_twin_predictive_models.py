#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 5C: Modèles Prédictifs Avancés du Jumeau Numérique

Système de modélisation prédictive avancée pour la prédiction d'usure,
maintenance prédictive et optimisation des performances basé sur les données
du jumeau numérique avec intelligence artificielle et apprentissage automatique.

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
import pickle
import joblib
import warnings
from collections import deque, defaultdict

# Machine Learning Libraries
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor, IsolationForest
from sklearn.linear_model import LinearRegression, Ridge, Lasso, ElasticNet
from sklearn.svm import SVR
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.model_selection import train_test_split, GridSearchCV, TimeSeriesSplit
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans, DBSCAN

# Deep Learning
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, GRU, Dense, Dropout, Conv1D, MaxPooling1D
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau

# Advanced ML
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostRegressor
from scipy import stats
from scipy.optimize import minimize
from scipy.signal import find_peaks, savgol_filter
from scipy.interpolate import interp1d

# Time Series Analysis
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.holtwinters import ExponentialSmoothing
from statsmodels.tsa.seasonal import seasonal_decompose
import pmdarima as pm

# Optimization
from sklearn.metrics import make_scorer
from hyperopt import hp, fmin, tpe, Trials, STATUS_OK
import optuna

# Visualization and Analysis
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.dates import DateFormatter
import plotly.graph_objects as go
from plotly.subplots import make_subplots

warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PredictionResult:
    """Résultat d'une prédiction."""
    equipment_id: str
    prediction_type: str  # wear, failure, performance, maintenance
    timestamp: datetime
    predicted_value: float
    confidence: float
    prediction_horizon: int  # heures
    features_used: List[str]
    model_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MaintenanceRecommendation:
    """Recommandation de maintenance."""
    equipment_id: str
    priority: str  # critical, high, medium, low
    action_type: str  # preventive, predictive, corrective
    description: str
    estimated_cost: float
    time_window: Tuple[datetime, datetime]
    confidence: float
    risk_level: float
    components_affected: List[str]
    predicted_failure_probability: float

@dataclass
class WearAnalysis:
    """Analyse d'usure d'équipement."""
    equipment_id: str
    component: str
    current_wear_level: float  # 0-100%
    wear_rate: float  # %/jour
    remaining_useful_life: int  # jours
    confidence: float
    wear_pattern: str  # linear, exponential, cyclic, irregular
    contributing_factors: Dict[str, float]
    recommended_actions: List[str]

class AdvancedFeatureEngineering:
    """Ingénierie de caractéristiques avancée pour modèles prédictifs."""
    
    def __init__(self):
        self.scalers = {}
        self.feature_history = defaultdict(list)
        self.statistical_features = {}
        
    def extract_temporal_features(self, data: pd.DataFrame, timestamp_col: str = 'timestamp') -> pd.DataFrame:
        """Extrait les caractéristiques temporelles."""
        df = data.copy()
        
        # Conversion timestamp
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
        
        # Caractéristiques temporelles de base
        df['hour'] = df[timestamp_col].dt.hour
        df['day_of_week'] = df[timestamp_col].dt.dayofweek
        df['day_of_month'] = df[timestamp_col].dt.day
        df['month'] = df[timestamp_col].dt.month
        df['quarter'] = df[timestamp_col].dt.quarter
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        
        # Caractéristiques cycliques (encodage sinusoïdal)
        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        df['month_sin'] = np.sin(2 * np.pi * df['month'] / 12)
        df['month_cos'] = np.cos(2 * np.pi * df['month'] / 12)
        
        return df
    
    def create_lag_features(self, data: pd.DataFrame, target_cols: List[str], 
                           lags: List[int] = [1, 3, 6, 12, 24]) -> pd.DataFrame:
        """Crée les caractéristiques de retard (lag features)."""
        df = data.copy()
        
        for col in target_cols:
            if col in df.columns:
                for lag in lags:
                    df[f'{col}_lag_{lag}'] = df[col].shift(lag)
        
        return df
    
    def create_rolling_features(self, data: pd.DataFrame, target_cols: List[str],
                               windows: List[int] = [3, 6, 12, 24]) -> pd.DataFrame:
        """Crée les caractéristiques de fenêtre glissante."""
        df = data.copy()
        
        for col in target_cols:
            if col in df.columns:
                for window in windows:
                    # Statistiques de fenêtre glissante
                    df[f'{col}_rolling_mean_{window}'] = df[col].rolling(window=window).mean()
                    df[f'{col}_rolling_std_{window}'] = df[col].rolling(window=window).std()
                    df[f'{col}_rolling_min_{window}'] = df[col].rolling(window=window).min()
                    df[f'{col}_rolling_max_{window}'] = df[col].rolling(window=window).max()
                    df[f'{col}_rolling_median_{window}'] = df[col].rolling(window=window).median()
                    
                    # Caractéristiques de tendance
                    df[f'{col}_rolling_trend_{window}'] = (
                        df[col] - df[f'{col}_rolling_mean_{window}']
                    ) / (df[f'{col}_rolling_std_{window}'] + 1e-8)
        
        return df
    
    def create_statistical_features(self, data: pd.DataFrame, target_cols: List[str],
                                   window: int = 24) -> pd.DataFrame:
        """Crée des caractéristiques statistiques avancées."""
        df = data.copy()
        
        for col in target_cols:
            if col in df.columns:
                # Moments statistiques
                df[f'{col}_skewness_{window}'] = df[col].rolling(window=window).skew()
                df[f'{col}_kurtosis_{window}'] = df[col].rolling(window=window).kurt()
                
                # Percentiles
                df[f'{col}_q25_{window}'] = df[col].rolling(window=window).quantile(0.25)
                df[f'{col}_q75_{window}'] = df[col].rolling(window=window).quantile(0.75)
                df[f'{col}_iqr_{window}'] = (
                    df[f'{col}_q75_{window}'] - df[f'{col}_q25_{window}']
                )
                
                # Variabilité
                df[f'{col}_cv_{window}'] = (
                    df[f'{col}_rolling_std_{window}'] / 
                    (df[f'{col}_rolling_mean_{window}'] + 1e-8)
                )
                
                # Détection de pics
                peaks_series = df[col].rolling(window=window).apply(
                    lambda x: len(find_peaks(x.values)[0]), raw=False
                )
                df[f'{col}_peaks_count_{window}'] = peaks_series
        
        return df
    
    def create_interaction_features(self, data: pd.DataFrame, 
                                   feature_pairs: List[Tuple[str, str]]) -> pd.DataFrame:
        """Crée des caractéristiques d'interaction."""
        df = data.copy()
        
        for col1, col2 in feature_pairs:
            if col1 in df.columns and col2 in df.columns:
                # Interactions multiplicatives
                df[f'{col1}_x_{col2}'] = df[col1] * df[col2]
                
                # Ratios
                df[f'{col1}_div_{col2}'] = df[col1] / (df[col2] + 1e-8)
                
                # Différences
                df[f'{col1}_minus_{col2}'] = df[col1] - df[col2]
                
                # Distances
                df[f'{col1}_{col2}_distance'] = np.sqrt(df[col1]**2 + df[col2]**2)
        
        return df
    
    def create_frequency_features(self, data: pd.DataFrame, target_cols: List[str]) -> pd.DataFrame:
        """Crée des caractéristiques basées sur l'analyse fréquentielle."""
        df = data.copy()
        
        for col in target_cols:
            if col in df.columns and len(df[col].dropna()) > 10:
                values = df[col].fillna(method='ffill').values
                
                # FFT
                fft = np.fft.fft(values)
                freqs = np.fft.fftfreq(len(values))
                
                # Fréquence dominante
                dominant_freq_idx = np.argmax(np.abs(fft[1:len(fft)//2])) + 1
                df[f'{col}_dominant_frequency'] = freqs[dominant_freq_idx]
                
                # Énergie spectrale
                df[f'{col}_spectral_energy'] = np.sum(np.abs(fft)**2)
                
                # Centroïde spectral
                spectrum = np.abs(fft[:len(fft)//2])
                freqs_positive = freqs[:len(freqs)//2]
                df[f'{col}_spectral_centroid'] = (
                    np.sum(freqs_positive * spectrum) / 
                    (np.sum(spectrum) + 1e-8)
                )
        
        return df
    
    def detect_anomalies(self, data: pd.DataFrame, target_cols: List[str],
                        contamination: float = 0.1) -> pd.DataFrame:
        """Détecte les anomalies et crée des caractéristiques associées."""
        df = data.copy()
        
        for col in target_cols:
            if col in df.columns:
                values = df[col].fillna(method='ffill').values.reshape(-1, 1)
                
                # Isolation Forest
                iso_forest = IsolationForest(contamination=contamination, random_state=42)
                anomaly_scores = iso_forest.fit_predict(values)
                df[f'{col}_is_anomaly'] = (anomaly_scores == -1).astype(int)
                df[f'{col}_anomaly_score'] = iso_forest.decision_function(values)
                
                # Z-score
                z_scores = np.abs(stats.zscore(values.flatten()))
                df[f'{col}_zscore'] = z_scores
                df[f'{col}_is_outlier'] = (z_scores > 3).astype(int)
        
        return df

class WearPredictionModel:
    """Modèle de prédiction d'usure avancé."""
    
    def __init__(self, equipment_type: str):
        self.equipment_type = equipment_type
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.performance_metrics = {}
        self.is_trained = False
        
    def create_ensemble_model(self) -> Dict[str, Any]:
        """Crée un ensemble de modèles pour la prédiction d'usure."""
        models = {
            'random_forest': RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            ),
            'xgboost': xgb.XGBRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            ),
            'lightgbm': lgb.LGBMRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                verbose=-1
            ),
            'neural_network': self._create_neural_network()
        }
        
        return models
    
    def _create_neural_network(self) -> Sequential:
        """Crée un réseau de neurones pour la prédiction d'usure."""
        model = Sequential([
            Dense(128, activation='relu', input_shape=(None,)),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='linear')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def train_models(self, X: np.ndarray, y: np.ndarray, 
                    validation_split: float = 0.2) -> Dict[str, float]:
        """Entraîne l'ensemble de modèles."""
        # Division des données
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=validation_split, random_state=42
        )
        
        # Normalisation
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        self.scalers['wear_scaler'] = scaler
        
        # Création et entraînement des modèles
        models = self.create_ensemble_model()
        performance = {}
        
        for model_name, model in models.items():
            try:
                logger.info(f"Entraînement du modèle {model_name}")
                
                if model_name == 'neural_network':
                    # Entraînement du réseau de neurones
                    callbacks = [
                        EarlyStopping(patience=10, restore_best_weights=True),
                        ReduceLROnPlateau(factor=0.5, patience=5)
                    ]
                    
                    history = model.fit(
                        X_train_scaled, y_train,
                        validation_split=0.2,
                        epochs=100,
                        batch_size=32,
                        callbacks=callbacks,
                        verbose=0
                    )
                    
                    y_pred = model.predict(X_test_scaled, verbose=0).flatten()
                    
                else:
                    # Entraînement des modèles sklearn/xgboost/lightgbm
                    model.fit(X_train_scaled, y_train)
                    y_pred = model.predict(X_test_scaled)
                
                # Calcul des métriques
                mse = mean_squared_error(y_test, y_pred)
                mae = mean_absolute_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)
                
                performance[model_name] = {
                    'mse': mse,
                    'mae': mae,
                    'r2': r2,
                    'rmse': np.sqrt(mse)
                }
                
                # Sauvegarde du modèle
                self.models[model_name] = model
                
                # Importance des caractéristiques (si applicable)
                if hasattr(model, 'feature_importances_'):
                    self.feature_importance[model_name] = model.feature_importances_
                
                logger.info(f"{model_name} - R²: {r2:.3f}, RMSE: {np.sqrt(mse):.3f}")
                
            except Exception as e:
                logger.error(f"Erreur entraînement {model_name}: {e}")
                performance[model_name] = {'error': str(e)}
        
        self.performance_metrics = performance
        self.is_trained = True
        
        return performance
    
    def predict_wear(self, X: np.ndarray, ensemble_method: str = 'weighted_average') -> Tuple[np.ndarray, np.ndarray]:
        """Prédit l'usure avec méthode d'ensemble."""
        if not self.is_trained:
            raise ValueError("Les modèles doivent être entraînés avant la prédiction")
        
        # Normalisation
        X_scaled = self.scalers['wear_scaler'].transform(X)
        
        predictions = {}
        weights = {}
        
        # Prédictions individuelles
        for model_name, model in self.models.items():
            try:
                if model_name == 'neural_network':
                    pred = model.predict(X_scaled, verbose=0).flatten()
                else:
                    pred = model.predict(X_scaled)
                
                predictions[model_name] = pred
                
                # Poids basé sur la performance R²
                perf = self.performance_metrics.get(model_name, {})
                if 'r2' in perf:
                    weights[model_name] = max(0, perf['r2'])  # Poids positifs seulement
                else:
                    weights[model_name] = 0.1  # Poids minimal
                    
            except Exception as e:
                logger.error(f"Erreur prédiction {model_name}: {e}")
        
        if not predictions:
            raise RuntimeError("Aucune prédiction valide obtenue")
        
        # Ensemble des prédictions
        if ensemble_method == 'weighted_average':
            # Normalisation des poids
            total_weight = sum(weights.values())
            if total_weight > 0:
                weights = {k: v/total_weight for k, v in weights.items()}
            
            # Moyenne pondérée
            ensemble_pred = np.zeros(len(list(predictions.values())[0]))
            ensemble_var = np.zeros(len(list(predictions.values())[0]))
            
            for model_name, pred in predictions.items():
                weight = weights.get(model_name, 0)
                ensemble_pred += weight * pred
            
            # Calcul de l'incertitude (variance des prédictions)
            for model_name, pred in predictions.items():
                weight = weights.get(model_name, 0)
                ensemble_var += weight * (pred - ensemble_pred) ** 2
            
            confidence = 1.0 / (1.0 + np.sqrt(ensemble_var))
            
        elif ensemble_method == 'median':
            pred_matrix = np.column_stack(list(predictions.values()))
            ensemble_pred = np.median(pred_matrix, axis=1)
            confidence = 1.0 - np.std(pred_matrix, axis=1) / (np.mean(pred_matrix, axis=1) + 1e-8)
            
        else:  # simple_average
            pred_matrix = np.column_stack(list(predictions.values()))
            ensemble_pred = np.mean(pred_matrix, axis=1)
            confidence = 1.0 - np.std(pred_matrix, axis=1) / (np.mean(pred_matrix, axis=1) + 1e-8)
        
        return ensemble_pred, confidence
    
    def analyze_wear_pattern(self, wear_history: np.ndarray, 
                            timestamps: np.ndarray) -> Dict[str, Any]:
        """Analyse le pattern d'usure."""
        if len(wear_history) < 10:
            return {'pattern': 'insufficient_data', 'confidence': 0.0}
        
        # Détection de tendance
        x = np.arange(len(wear_history))
        slope, intercept, r_value, p_value, std_err = stats.linregress(x, wear_history)
        
        # Classification du pattern
        if abs(r_value) > 0.9:
            if slope > 0:
                pattern = 'linear_increasing'
            else:
                pattern = 'linear_decreasing'
        elif abs(r_value) > 0.7:
            pattern = 'moderately_linear'
        else:
            # Test d'exponentialité
            log_wear = np.log(np.maximum(wear_history, 1e-8))
            exp_slope, exp_intercept, exp_r_value, _, _ = stats.linregress(x, log_wear)
            
            if abs(exp_r_value) > 0.8:
                pattern = 'exponential'
            else:
                # Test de cyclicité
                fft = np.fft.fft(wear_history - np.mean(wear_history))
                power_spectrum = np.abs(fft)**2
                
                # Trouver la fréquence dominante
                freqs = np.fft.fftfreq(len(wear_history))
                dominant_freq_idx = np.argmax(power_spectrum[1:len(power_spectrum)//2]) + 1
                
                if power_spectrum[dominant_freq_idx] > 2 * np.mean(power_spectrum):
                    pattern = 'cyclic'
                else:
                    pattern = 'irregular'
        
        return {
            'pattern': pattern,
            'linear_correlation': r_value,
            'slope': slope,
            'confidence': min(abs(r_value), 1.0),
            'trend_direction': 'increasing' if slope > 0 else 'decreasing',
            'acceleration': np.mean(np.diff(np.diff(wear_history))) if len(wear_history) > 2 else 0
        }

class MaintenancePredictionEngine:
    """Moteur de prédiction de maintenance avancé."""
    
    def __init__(self):
        self.failure_models = {}
        self.optimization_models = {}
        self.cost_models = {}
        self.risk_assessor = None
        
    def train_failure_prediction_model(self, equipment_data: pd.DataFrame) -> Dict[str, Any]:
        """Entraîne un modèle de prédiction de défaillance."""
        
        # Préparation des données
        feature_cols = [col for col in equipment_data.columns 
                       if col not in ['equipment_id', 'timestamp', 'failure_occurred']]
        
        X = equipment_data[feature_cols].fillna(method='ffill')
        y = equipment_data['failure_occurred'].astype(int)
        
        # Gestion du déséquilibre des classes
        from sklearn.utils.class_weight import compute_class_weight
        
        classes = np.unique(y)
        class_weights = compute_class_weight('balanced', classes=classes, y=y)
        class_weight_dict = dict(zip(classes, class_weights))
        
        # Modèles de classification
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from xgboost import XGBClassifier
        
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                class_weight=class_weight_dict,
                random_state=42
            ),
            'logistic_regression': LogisticRegression(
                class_weight=class_weight_dict,
                random_state=42
            ),
            'xgboost': XGBClassifier(
                n_estimators=200,
                max_depth=6,
                random_state=42,
                eval_metric='logloss'
            )
        }
        
        # Division et évaluation
        from sklearn.model_selection import StratifiedKFold
        from sklearn.metrics import classification_report, roc_auc_score
        
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        results = {}
        
        for model_name, model in models.items():
            cv_scores = []
            
            for train_idx, test_idx in cv.split(X, y):
                X_train_cv, X_test_cv = X.iloc[train_idx], X.iloc[test_idx]
                y_train_cv, y_test_cv = y.iloc[train_idx], y.iloc[test_idx]
                
                # Normalisation
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train_cv)
                X_test_scaled = scaler.transform(X_test_cv)
                
                # Entraînement
                if model_name == 'xgboost':
                    model.fit(X_train_scaled, y_train_cv)
                else:
                    model.fit(X_train_scaled, y_train_cv)
                
                # Prédiction
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
                
                # AUC Score
                auc_score = roc_auc_score(y_test_cv, y_pred_proba)
                cv_scores.append(auc_score)
            
            results[model_name] = {
                'mean_auc': np.mean(cv_scores),
                'std_auc': np.std(cv_scores),
                'model': model
            }
            
            logger.info(f"{model_name} - AUC moyen: {np.mean(cv_scores):.3f} ± {np.std(cv_scores):.3f}")
        
        # Sélection du meilleur modèle
        best_model_name = max(results, key=lambda x: results[x]['mean_auc'])
        best_model = results[best_model_name]['model']
        
        # Entraînement final
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        best_model.fit(X_scaled, y)
        
        self.failure_models['best'] = {
            'model': best_model,
            'scaler': scaler,
            'features': feature_cols,
            'performance': results[best_model_name]
        }
        
        return results
    
    def predict_failure_probability(self, equipment_data: pd.DataFrame, 
                                  time_horizon: int = 24) -> List[PredictionResult]:
        """Prédit la probabilité de défaillance."""
        if 'best' not in self.failure_models:
            raise ValueError("Le modèle de prédiction de défaillance doit être entraîné")
        
        model_info = self.failure_models['best']
        model = model_info['model']
        scaler = model_info['scaler']
        features = model_info['features']
        
        results = []
        
        for equipment_id in equipment_data['equipment_id'].unique():
            equipment_subset = equipment_data[equipment_data['equipment_id'] == equipment_id]
            
            if len(equipment_subset) > 0:
                # Préparation des données
                X = equipment_subset[features].fillna(method='ffill')
                X_scaled = scaler.transform(X)
                
                # Prédiction
                failure_proba = model.predict_proba(X_scaled)[:, 1]
                
                # Prédiction pour l'horizon temporel
                avg_failure_proba = np.mean(failure_proba[-min(time_horizon, len(failure_proba)):])
                confidence = 1.0 - np.std(failure_proba[-min(time_horizon, len(failure_proba)):])
                
                result = PredictionResult(
                    equipment_id=equipment_id,
                    prediction_type='failure',
                    timestamp=datetime.now(),
                    predicted_value=avg_failure_proba,
                    confidence=confidence,
                    prediction_horizon=time_horizon,
                    features_used=features,
                    model_version='ensemble_v1',
                    metadata={
                        'failure_probability': avg_failure_proba,
                        'risk_level': 'high' if avg_failure_proba > 0.7 else 'medium' if avg_failure_proba > 0.3 else 'low'
                    }
                )
                
                results.append(result)
        
        return results
    
    def generate_maintenance_recommendations(self, predictions: List[PredictionResult],
                                           wear_analyses: List[WearAnalysis]) -> List[MaintenanceRecommendation]:
        """Génère des recommandations de maintenance."""
        recommendations = []
        
        # Grouper par équipement
        equipment_predictions = defaultdict(list)
        equipment_wear = {}
        
        for pred in predictions:
            equipment_predictions[pred.equipment_id].append(pred)
        
        for wear in wear_analyses:
            equipment_wear[wear.equipment_id] = wear
        
        # Génération des recommandations
        for equipment_id, preds in equipment_predictions.items():
            # Analyse des prédictions
            failure_preds = [p for p in preds if p.prediction_type == 'failure']
            wear_preds = [p for p in preds if p.prediction_type == 'wear']
            
            if not failure_preds:
                continue
            
            failure_prob = np.mean([p.predicted_value for p in failure_preds])
            confidence = np.mean([p.confidence for p in failure_preds])
            
            # Analyse d'usure correspondante
            wear_analysis = equipment_wear.get(equipment_id)
            
            # Détermination de la priorité
            if failure_prob > 0.8 or (wear_analysis and wear_analysis.current_wear_level > 90):
                priority = 'critical'
                action_type = 'corrective'
                time_window = (datetime.now(), datetime.now() + timedelta(hours=24))
            elif failure_prob > 0.6 or (wear_analysis and wear_analysis.current_wear_level > 75):
                priority = 'high'
                action_type = 'predictive'
                time_window = (datetime.now() + timedelta(days=1), datetime.now() + timedelta(days=7))
            elif failure_prob > 0.3 or (wear_analysis and wear_analysis.current_wear_level > 50):
                priority = 'medium'
                action_type = 'preventive'
                time_window = (datetime.now() + timedelta(days=7), datetime.now() + timedelta(days=30))
            else:
                priority = 'low'
                action_type = 'preventive'
                time_window = (datetime.now() + timedelta(days=30), datetime.now() + timedelta(days=90))
            
            # Description et coût estimé
            if wear_analysis:
                description = f"Maintenance {action_type} recommandée pour {equipment_id}. "
                description += f"Usure actuelle: {wear_analysis.current_wear_level:.1f}%, "
                description += f"Vie utile restante: {wear_analysis.remaining_useful_life} jours."
                
                components_affected = [wear_analysis.component]
                
                # Estimation de coût basée sur la priorité et l'usure
                base_cost = 1000  # Coût de base
                wear_multiplier = 1 + (wear_analysis.current_wear_level / 100)
                priority_multiplier = {'critical': 3, 'high': 2, 'medium': 1.5, 'low': 1}[priority]
                estimated_cost = base_cost * wear_multiplier * priority_multiplier
                
            else:
                description = f"Maintenance {action_type} recommandée pour {equipment_id} "
                description += f"basée sur la probabilité de défaillance ({failure_prob:.1%})."
                components_affected = ['general']
                estimated_cost = 1000 * {'critical': 3, 'high': 2, 'medium': 1.5, 'low': 1}[priority]
            
            recommendation = MaintenanceRecommendation(
                equipment_id=equipment_id,
                priority=priority,
                action_type=action_type,
                description=description,
                estimated_cost=estimated_cost,
                time_window=time_window,
                confidence=confidence,
                risk_level=failure_prob,
                components_affected=components_affected,
                predicted_failure_probability=failure_prob
            )
            
            recommendations.append(recommendation)
        
        # Tri par priorité et risque
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(
            key=lambda x: (priority_order[x.priority], -x.risk_level, -x.confidence)
        )
        
        return recommendations

class PerformanceOptimizer:
    """Optimiseur de performance basé sur l'IA."""
    
    def __init__(self):
        self.optimization_models = {}
        self.pareto_fronts = {}
        self.constraint_functions = {}
        
    def define_optimization_objectives(self, equipment_type: str) -> Dict[str, Callable]:
        """Définit les objectifs d'optimisation multi-objectifs."""
        
        if equipment_type == 'pump':
            objectives = {
                'efficiency': lambda params: self._calculate_pump_efficiency(params),
                'energy_consumption': lambda params: -self._calculate_energy_consumption(params),  # Minimiser
                'wear_rate': lambda params: -self._calculate_wear_rate(params),  # Minimiser
                'maintenance_cost': lambda params: -self._calculate_maintenance_cost(params)  # Minimiser
            }
        elif equipment_type == 'motor':
            objectives = {
                'power_output': lambda params: self._calculate_power_output(params),
                'efficiency': lambda params: self._calculate_motor_efficiency(params),
                'temperature': lambda params: -self._calculate_operating_temperature(params),  # Minimiser
                'vibration': lambda params: -self._calculate_vibration_level(params)  # Minimiser
            }
        else:  # Génériques
            objectives = {
                'performance': lambda params: self._calculate_generic_performance(params),
                'efficiency': lambda params: self._calculate_generic_efficiency(params),
                'cost': lambda params: -self._calculate_generic_cost(params)
            }
        
        return objectives
    
    def _calculate_pump_efficiency(self, params: Dict[str, float]) -> float:
        """Calcule l'efficacité d'une pompe."""
        speed = params.get('speed', 1500)  # RPM
        pressure = params.get('pressure', 5)  # bar
        flow_rate = params.get('flow_rate', 100)  # L/min
        
        # Modèle simplifié d'efficacité de pompe
        optimal_speed = 1800
        optimal_pressure = 7
        
        speed_factor = 1 - abs(speed - optimal_speed) / optimal_speed * 0.3
        pressure_factor = 1 - abs(pressure - optimal_pressure) / optimal_pressure * 0.2
        flow_factor = min(flow_rate / 150, 1.0)  # Efficacité maximale à 150 L/min
        
        efficiency = speed_factor * pressure_factor * flow_factor * 0.85  # Max 85%
        return max(0, min(efficiency, 1))
    
    def _calculate_energy_consumption(self, params: Dict[str, float]) -> float:
        """Calcule la consommation d'énergie."""
        speed = params.get('speed', 1500)
        load = params.get('load', 0.8)
        
        # Modèle de consommation d'énergie (kW)
        base_consumption = 10  # kW de base
        speed_factor = (speed / 1800) ** 2.5
        load_factor = load ** 1.8
        
        consumption = base_consumption * speed_factor * load_factor
        return consumption
    
    def _calculate_wear_rate(self, params: Dict[str, float]) -> float:
        """Calcule le taux d'usure."""
        speed = params.get('speed', 1500)
        temperature = params.get('temperature', 70)
        vibration = params.get('vibration', 2)
        
        # Facteurs d'usure
        speed_wear = (speed / 1800) ** 2
        temp_wear = max(0, (temperature - 60) / 40) ** 1.5
        vib_wear = (vibration / 5) ** 2
        
        wear_rate = 0.1 * (speed_wear + temp_wear + vib_wear)
        return max(0, wear_rate)
    
    def _calculate_maintenance_cost(self, params: Dict[str, float]) -> float:
        """Calcule le coût de maintenance."""
        wear_rate = self._calculate_wear_rate(params)
        efficiency = self._calculate_pump_efficiency(params)
        
        # Coût basé sur l'usure et l'inefficacité
        base_cost = 1000  # Euro par mois
        wear_cost = wear_rate * 5000
        efficiency_cost = (1 - efficiency) * 2000
        
        return base_cost + wear_cost + efficiency_cost
    
    def optimize_parameters(self, equipment_id: str, equipment_type: str,
                           current_params: Dict[str, float],
                           constraints: Dict[str, Tuple[float, float]] = None) -> Dict[str, Any]:
        """Optimise les paramètres opérationnels multi-objectifs."""
        
        objectives = self.define_optimization_objectives(equipment_type)
        
        if constraints is None:
            constraints = {
                'speed': (1000, 2500),
                'pressure': (1, 10),
                'temperature': (40, 100),
                'load': (0.3, 1.0)
            }
        
        # Optimisation avec Optuna (multi-objectif)
        def objective(trial):
            # Paramètres à optimiser
            params = {}
            for param_name, (min_val, max_val) in constraints.items():
                if param_name in current_params:
                    params[param_name] = trial.suggest_float(param_name, min_val, max_val)
            
            # Calcul des objectifs
            objective_values = []
            for obj_name, obj_func in objectives.items():
                try:
                    value = obj_func(params)
                    objective_values.append(value)
                except:
                    objective_values.append(0)  # Valeur par défaut en cas d'erreur
            
            return objective_values
        
        # Étude multi-objectif
        study = optuna.create_study(
            directions=['maximize'] * len(objectives),  # Maximiser tous les objectifs
            study_name=f'optimization_{equipment_id}'
        )
        
        study.optimize(objective, n_trials=200)
        
        # Analyse des résultats
        pareto_solutions = []
        
        for trial in study.best_trials:
            solution = {
                'parameters': trial.params,
                'objectives': dict(zip(objectives.keys(), trial.values)),
                'trial_number': trial.number
            }
            pareto_solutions.append(solution)
        
        # Sélection de la meilleure solution (compromis équilibré)
        if pareto_solutions:
            # Score composite basé sur la normalisation des objectifs
            scores = []
            
            # Normalisation des objectifs
            obj_values = {obj: [sol['objectives'][obj] for sol in pareto_solutions] 
                         for obj in objectives.keys()}
            
            obj_ranges = {obj: (min(values), max(values)) 
                         for obj, values in obj_values.items()}
            
            for solution in pareto_solutions:
                score = 0
                for obj_name, obj_value in solution['objectives'].items():
                    min_val, max_val = obj_ranges[obj_name]
                    if max_val > min_val:
                        normalized_value = (obj_value - min_val) / (max_val - min_val)
                    else:
                        normalized_value = 1.0
                    score += normalized_value
                
                scores.append(score / len(objectives))  # Score moyen
                solution['composite_score'] = score / len(objectives)
            
            # Meilleure solution
            best_idx = np.argmax(scores)
            best_solution = pareto_solutions[best_idx]
            
        else:
            best_solution = {
                'parameters': current_params,
                'objectives': {obj: func(current_params) for obj, func in objectives.items()},
                'composite_score': 0.0
            }
        
        # Calcul des améliorations
        current_objectives = {obj: func(current_params) for obj, func in objectives.items()}
        improvements = {}
        
        for obj_name in objectives.keys():
            current_val = current_objectives[obj_name]
            optimized_val = best_solution['objectives'][obj_name]
            
            if current_val != 0:
                improvement = ((optimized_val - current_val) / abs(current_val)) * 100
            else:
                improvement = 0
            
            improvements[obj_name] = improvement
        
        return {
            'equipment_id': equipment_id,
            'current_parameters': current_params,
            'optimized_parameters': best_solution['parameters'],
            'current_performance': current_objectives,
            'optimized_performance': best_solution['objectives'],
            'improvements': improvements,
            'pareto_solutions': pareto_solutions[:10],  # Top 10 solutions
            'composite_score': best_solution['composite_score'],
            'optimization_summary': {
                'total_trials': len(study.trials),
                'pareto_solutions_count': len(pareto_solutions),
                'best_composite_score': best_solution['composite_score']
            }
        }

class DigitalTwinPredictiveSystem:
    """Système prédictif principal du jumeau numérique."""
    
    def __init__(self, config_path: str = "predictive_config.json"):
        self.config = self._load_config(config_path)
        
        # Composants principaux
        self.feature_engineer = AdvancedFeatureEngineering()
        self.wear_models = {}  # equipment_type -> WearPredictionModel
        self.maintenance_engine = MaintenancePredictionEngine()
        self.performance_optimizer = PerformanceOptimizer()
        
        # Données et historiques
        self.equipment_data = defaultdict(list)
        self.prediction_history = defaultdict(list)
        self.optimization_history = defaultdict(list)
        
        # État du système
        self.models_trained = {}
        self.last_optimization = {}
        self.active_recommendations = []
        
        logger.info("Système prédictif du jumeau numérique initialisé")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration."""
        default_config = {
            'models': {
                'retrain_interval_hours': 24,
                'prediction_horizons': [1, 6, 24, 72, 168],  # heures
                'wear_threshold': 80,
                'failure_probability_threshold': 0.6
            },
            'optimization': {
                'optimization_interval_hours': 12,
                'pareto_solutions_count': 10,
                'constraint_safety_margin': 0.1
            },
            'maintenance': {
                'cost_per_hour_delay': 100,
                'critical_response_time_hours': 4,
                'preventive_cost_multiplier': 0.3
            },
            'data': {
                'min_samples_for_training': 100,
                'feature_selection_method': 'importance',
                'outlier_removal_threshold': 3.0
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge avec les valeurs par défaut
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
    
    def add_equipment_data(self, equipment_id: str, equipment_type: str, 
                          sensor_data: Dict[str, Any], timestamp: datetime = None):
        """Ajoute des données d'équipement pour l'analyse prédictive."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Préparation des données
        data_point = {
            'equipment_id': equipment_id,
            'equipment_type': equipment_type,
            'timestamp': timestamp,
            **sensor_data
        }
        
        self.equipment_data[equipment_id].append(data_point)
        
        # Limitation de l'historique
        max_history = 10000  # Points maximum par équipement
        if len(self.equipment_data[equipment_id]) > max_history:
            self.equipment_data[equipment_id] = self.equipment_data[equipment_id][-max_history:]
    
    async def train_predictive_models(self, equipment_id: str = None) -> Dict[str, Any]:
        """Entraîne les modèles prédictifs."""
        results = {}
        
        equipment_list = [equipment_id] if equipment_id else self.equipment_data.keys()
        
        for eq_id in equipment_list:
            if eq_id not in self.equipment_data or len(self.equipment_data[eq_id]) < self.config['data']['min_samples_for_training']:
                logger.warning(f"Données insuffisantes pour {eq_id}")
                continue
            
            try:
                # Conversion en DataFrame
                df = pd.DataFrame(self.equipment_data[eq_id])
                equipment_type = df['equipment_type'].iloc[0]
                
                # Ingénierie des caractéristiques
                logger.info(f"Ingénierie des caractéristiques pour {eq_id}")
                
                # Caractéristiques temporelles
                df = self.feature_engineer.extract_temporal_features(df)
                
                # Caractéristiques de retard et fenêtre glissante
                sensor_cols = [col for col in df.columns 
                              if col not in ['equipment_id', 'equipment_type', 'timestamp']]
                
                df = self.feature_engineer.create_lag_features(df, sensor_cols[:5])  # Top 5 capteurs
                df = self.feature_engineer.create_rolling_features(df, sensor_cols[:5])
                df = self.feature_engineer.create_statistical_features(df, sensor_cols[:5])
                
                # Détection d'anomalies
                df = self.feature_engineer.detect_anomalies(df, sensor_cols[:3])
                
                # Nettoyage des données
                df = df.dropna()
                
                if len(df) < 50:
                    logger.warning(f"Données insuffisantes après nettoyage pour {eq_id}")
                    continue
                
                # Création du target pour l'usure (simulation)
                # Dans un cas réel, ceci viendrait des capteurs d'usure ou d'inspections
                df['wear_level'] = self._simulate_wear_progression(df)
                df['failure_occurred'] = (df['wear_level'] > 90).astype(int)
                
                # Entraînement du modèle d'usure
                if equipment_type not in self.wear_models:
                    self.wear_models[equipment_type] = WearPredictionModel(equipment_type)
                
                wear_model = self.wear_models[equipment_type]
                
                # Préparation des données pour l'entraînement
                feature_cols = [col for col in df.columns 
                               if col not in ['equipment_id', 'equipment_type', 'timestamp', 
                                            'wear_level', 'failure_occurred']]
                
                X = df[feature_cols].values
                y_wear = df['wear_level'].values
                
                # Entraînement
                wear_performance = wear_model.train_models(X, y_wear)
                
                # Entraînement du modèle de défaillance
                maintenance_performance = self.maintenance_engine.train_failure_prediction_model(df)
                
                results[eq_id] = {
                    'equipment_type': equipment_type,
                    'wear_model_performance': wear_performance,
                    'maintenance_model_performance': maintenance_performance,
                    'features_count': len(feature_cols),
                    'training_samples': len(df),
                    'training_timestamp': datetime.now()
                }
                
                self.models_trained[eq_id] = True
                logger.info(f"Modèles entraînés avec succès pour {eq_id}")
                
            except Exception as e:
                logger.error(f"Erreur entraînement modèles pour {eq_id}: {e}")
                results[eq_id] = {'error': str(e)}
        
        return results
    
    def _simulate_wear_progression(self, df: pd.DataFrame) -> np.ndarray:
        """Simule la progression d'usure (pour la démonstration)."""
        n_samples = len(df)
        
        # Base d'usure basée sur le temps et les conditions
        time_factor = np.linspace(0, 1, n_samples)
        
        # Facteurs d'usure basés sur les conditions opérationnelles
        wear_factors = np.ones(n_samples)
        
        if 'temperature' in df.columns:
            temp_factor = (df['temperature'] - 60) / 40  # Usure augmente avec température
            wear_factors += np.maximum(temp_factor, 0) * 0.3
        
        if 'vibration' in df.columns:
            vib_factor = df['vibration'] / 5  # Usure augmente avec vibration
            wear_factors += vib_factor * 0.2
        
        if 'speed' in df.columns:
            speed_factor = (df['speed'] - 1800) / 1000  # Usure augmente avec vitesse excessive
            wear_factors += np.maximum(speed_factor, 0) * 0.25
        
        # Progression d'usure avec bruit
        base_wear = time_factor * 100  # 0-100%
        condition_wear = np.cumsum(wear_factors) * 0.1
        noise = np.random.normal(0, 2, n_samples)  # Bruit de mesure
        
        wear_level = base_wear + condition_wear + noise
        wear_level = np.clip(wear_level, 0, 100)  # 0-100%
        
        return wear_level
    
    async def predict_equipment_performance(self, equipment_id: str, 
                                          prediction_horizons: List[int] = None) -> Dict[str, Any]:
        """Prédit les performances d'équipement."""
        if equipment_id not in self.models_trained or not self.models_trained[equipment_id]:
            raise ValueError(f"Modèles non entraînés pour {equipment_id}")
        
        if prediction_horizons is None:
            prediction_horizons = self.config['models']['prediction_horizons']
        
        # Récupération des données récentes
        recent_data = pd.DataFrame(self.equipment_data[equipment_id][-100:])  # 100 derniers points
        equipment_type = recent_data['equipment_type'].iloc[0]
        
        # Ingénierie des caractéristiques (même pipeline qu'à l'entraînement)
        recent_data = self.feature_engineer.extract_temporal_features(recent_data)
        
        sensor_cols = [col for col in recent_data.columns 
                      if col not in ['equipment_id', 'equipment_type', 'timestamp']]
        
        recent_data = self.feature_engineer.create_lag_features(recent_data, sensor_cols[:5])
        recent_data = self.feature_engineer.create_rolling_features(recent_data, sensor_cols[:5])
        recent_data = self.feature_engineer.create_statistical_features(recent_data, sensor_cols[:5])
        recent_data = self.feature_engineer.detect_anomalies(recent_data, sensor_cols[:3])
        
        # Nettoyage
        recent_data = recent_data.dropna()
        
        if len(recent_data) == 0:
            raise ValueError(f"Aucune donnée valide pour la prédiction de {equipment_id}")
        
        predictions = {}
        
        for horizon in prediction_horizons:
            try:
                # Données pour la prédiction
                feature_cols = [col for col in recent_data.columns 
                               if col not in ['equipment_id', 'equipment_type', 'timestamp']]
                
                X_recent = recent_data[feature_cols].iloc[-1:].values  # Dernier point
                
                # Prédiction d'usure
                wear_model = self.wear_models[equipment_type]
                wear_pred, wear_confidence = wear_model.predict_wear(X_recent)
                
                # Analyse du pattern d'usure
                wear_history = self._simulate_wear_progression(recent_data)  # Historique simulé
                timestamps = recent_data['timestamp'].values
                
                wear_pattern = wear_model.analyze_wear_pattern(wear_history, timestamps)
                
                # Prédiction de défaillance
                failure_predictions = self.maintenance_engine.predict_failure_probability(
                    recent_data, time_horizon=horizon
                )
                
                # Analyse d'usure
                wear_analysis = WearAnalysis(
                    equipment_id=equipment_id,
                    component='general',
                    current_wear_level=float(wear_pred[0]),
                    wear_rate=wear_pattern.get('slope', 0) * 24,  # Par jour
                    remaining_useful_life=max(0, int((100 - wear_pred[0]) / max(wear_pattern.get('slope', 0.1) * 24, 0.1))),
                    confidence=float(wear_confidence[0]),
                    wear_pattern=wear_pattern.get('pattern', 'unknown'),
                    contributing_factors={
                        'temperature': 0.3,
                        'vibration': 0.2,
                        'speed': 0.25,
                        'age': 0.25
                    },
                    recommended_actions=[
                        'Surveillance continue' if wear_pred[0] < 50 else
                        'Planifier maintenance préventive' if wear_pred[0] < 80 else
                        'Maintenance urgente requise'
                    ]
                )
                
                # Recommandations de maintenance
                maintenance_recommendations = self.maintenance_engine.generate_maintenance_recommendations(
                    failure_predictions, [wear_analysis]
                )
                
                predictions[f'{horizon}h'] = {
                    'horizon_hours': horizon,
                    'wear_prediction': {
                        'level': float(wear_pred[0]),
                        'confidence': float(wear_confidence[0]),
                        'pattern': wear_pattern
                    },
                    'failure_predictions': [
                        {
                            'probability': pred.predicted_value,
                            'confidence': pred.confidence,
                            'risk_level': pred.metadata.get('risk_level', 'unknown')
                        }
                        for pred in failure_predictions
                    ],
                    'wear_analysis': asdict(wear_analysis),
                    'maintenance_recommendations': [
                        asdict(rec) for rec in maintenance_recommendations
                    ],
                    'prediction_timestamp': datetime.now()
                }
                
            except Exception as e:
                logger.error(f"Erreur prédiction horizon {horizon}h: {e}")
                predictions[f'{horizon}h'] = {'error': str(e)}
        
        # Sauvegarde de l'historique
        self.prediction_history[equipment_id].append({
            'timestamp': datetime.now(),
            'predictions': predictions
        })
        
        return {
            'equipment_id': equipment_id,
            'equipment_type': equipment_type,
            'predictions': predictions,
            'data_points_used': len(recent_data),
            'prediction_timestamp': datetime.now()
        }
    
    async def optimize_equipment_performance(self, equipment_id: str, 
                                           current_parameters: Dict[str, float] = None) -> Dict[str, Any]:
        """Optimise les paramètres de performance d'équipement."""
        if equipment_id not in self.equipment_data:
            raise ValueError(f"Aucune donnée disponible pour {equipment_id}")
        
        # Récupération du type d'équipement
        equipment_type = self.equipment_data[equipment_id][-1]['equipment_type']
        
        # Paramètres actuels (depuis les dernières données si non fournis)
        if current_parameters is None:
            recent_data = self.equipment_data[equipment_id][-1]
            current_parameters = {
                'speed': recent_data.get('speed', 1500),
                'pressure': recent_data.get('pressure', 5),
                'temperature': recent_data.get('temperature', 70),
                'load': recent_data.get('load', 0.8)
            }
        
        # Optimisation
        optimization_result = self.performance_optimizer.optimize_parameters(
            equipment_id, equipment_type, current_parameters
        )
        
        # Sauvegarde de l'historique
        self.optimization_history[equipment_id].append({
            'timestamp': datetime.now(),
            'optimization': optimization_result
        })
        
        self.last_optimization[equipment_id] = datetime.now()
        
        return optimization_result
    
    def get_system_status(self) -> Dict[str, Any]:
        """Retourne le statut complet du système prédictif."""
        status = {
            'equipment_count': len(self.equipment_data),
            'trained_models': len([eq for eq, trained in self.models_trained.items() if trained]),
            'total_data_points': sum(len(data) for data in self.equipment_data.values()),
            'active_recommendations': len(self.active_recommendations),
            'last_training': max([
                max([datetime.fromisoformat(point['timestamp'].isoformat()) 
                     for point in data] + [datetime.min])
                for data in self.equipment_data.values()
            ] + [datetime.min]) if self.equipment_data else None,
            'system_health': 'operational'
        }
        
        # Statut par équipement
        equipment_status = {}
        for eq_id, data in self.equipment_data.items():
            equipment_status[eq_id] = {
                'data_points': len(data),
                'last_update': data[-1]['timestamp'] if data else None,
                'model_trained': self.models_trained.get(eq_id, False),
                'last_prediction': len(self.prediction_history.get(eq_id, [])),
                'last_optimization': self.last_optimization.get(eq_id)
            }
        
        status['equipment_status'] = equipment_status
        
        return status

# Fonction de démonstration
async def main():
    """Démonstration du système prédictif avancé."""
    
    print("=== Système Prédictif Avancé du Jumeau Numérique ===")
    
    # Initialisation
    predictive_system = DigitalTwinPredictiveSystem()
    
    # Équipements de test
    equipment_list = [
        {'id': 'PUMP_001', 'type': 'pump'},
        {'id': 'MOTOR_001', 'type': 'motor'},
        {'id': 'HEAT_EXCHANGER_001', 'type': 'heat_exchanger'}
    ]
    
    print(f"\n=== Génération de Données Historiques ===")
    
    # Génération de données historiques simulées
    for equipment in equipment_list:
        eq_id = equipment['id']
        eq_type = equipment['type']
        
        print(f"Génération de données pour {eq_id}...")
        
        # Simulation de 30 jours de données (1 point par heure)
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(30 * 24):  # 720 points de données
            timestamp = base_time + timedelta(hours=i)
            
            # Conditions opérationnelles variables
            hour = timestamp.hour
            day_cycle = np.sin(2 * np.pi * i / 24)  # Cycle journalier
            week_cycle = np.sin(2 * np.pi * i / (24 * 7))  # Cycle hebdomadaire
            
            # Données de capteurs simulées
            sensor_data = {
                'temperature': 60 + 20 * day_cycle + np.random.normal(0, 3) + i * 0.01,  # Dérive thermique
                'pressure': 5 + 2 * day_cycle + np.random.normal(0, 0.5),
                'vibration': 2 + 1 * abs(day_cycle) + np.random.normal(0, 0.3) + i * 0.001,  # Usure progressive
                'speed': 1500 + 300 * day_cycle + np.random.normal(0, 50),
                'current': 15 + 5 * day_cycle + np.random.normal(0, 1),
                'voltage': 400 + 20 * week_cycle + np.random.normal(0, 5),
                'load': 0.7 + 0.2 * day_cycle + np.random.normal(0, 0.05),
                'efficiency': 0.85 - i * 0.00001 + np.random.normal(0, 0.02)  # Dégradation progressive
            }
            
            # Ajout au système
            predictive_system.add_equipment_data(eq_id, eq_type, sensor_data, timestamp)
        
        print(f"  ✓ {720} points de données générés pour {eq_id}")
    
    print(f"\n=== Entraînement des Modèles Prédictifs ===")
    
    # Entraînement des modèles
    training_results = await predictive_system.train_predictive_models()
    
    for eq_id, result in training_results.items():
        if 'error' not in result:
            print(f"✓ Modèles entraînés pour {eq_id}")
            print(f"  - Type: {result['equipment_type']}")
            print(f"  - Caractéristiques: {result['features_count']}")
            print(f"  - Échantillons: {result['training_samples']}")
            
            # Meilleure performance d'usure
            if 'wear_model_performance' in result:
                best_wear_model = max(result['wear_model_performance'], 
                                    key=lambda x: result['wear_model_performance'][x].get('r2', 0) 
                                    if isinstance(result['wear_model_performance'][x], dict) else 0)
                best_r2 = result['wear_model_performance'][best_wear_model].get('r2', 0)
                print(f"  - Meilleur modèle d'usure: {best_wear_model} (R² = {best_r2:.3f})")
        else:
            print(f"❌ Erreur pour {eq_id}: {result['error']}")
    
    print(f"\n=== Prédictions de Performance ===")
    
    # Prédictions pour chaque équipement
    for equipment in equipment_list:
        eq_id = equipment['id']
        
        if eq_id in training_results and 'error' not in training_results[eq_id]:
            try:
                print(f"\nPrédictions pour {eq_id}:")
                
                predictions = await predictive_system.predict_equipment_performance(
                    eq_id, prediction_horizons=[1, 24, 168]
                )
                
                for horizon, pred_data in predictions['predictions'].items():
                    if 'error' not in pred_data:
                        wear_pred = pred_data['wear_prediction']
                        failure_preds = pred_data['failure_predictions']
                        wear_analysis = pred_data['wear_analysis']
                        maintenance_recs = pred_data['maintenance_recommendations']
                        
                        print(f"  Horizon {horizon}:")
                        print(f"    • Usure prédite: {wear_pred['level']:.1f}% (confiance: {wear_pred['confidence']:.2f})")
                        print(f"    • Pattern d'usure: {wear_pred['pattern']['pattern']}")
                        
                        if failure_preds:
                            avg_failure_prob = np.mean([fp['probability'] for fp in failure_preds])
                            print(f"    • Probabilité de défaillance: {avg_failure_prob:.1%}")
                        
                        print(f"    • Vie utile restante: {wear_analysis['remaining_useful_life']} jours")
                        
                        if maintenance_recs:
                            rec = maintenance_recs[0]
                            print(f"    • Recommandation: {rec['priority']} - {rec['action_type']}")
                
            except Exception as e:
                print(f"❌ Erreur prédiction {eq_id}: {e}")
    
    print(f"\n=== Optimisation de Performance ===")
    
    # Optimisation pour le premier équipement
    eq_id = equipment_list[0]['id']
    
    try:
        print(f"Optimisation des paramètres pour {eq_id}...")
        
        current_params = {
            'speed': 1600,
            'pressure': 6,
            'temperature': 75,
            'load': 0.85
        }
        
        optimization = await predictive_system.optimize_equipment_performance(
            eq_id, current_params
        )
        
        print(f"✓ Optimisation terminée")
        print(f"  Paramètres actuels: {optimization['current_parameters']}")
        print(f"  Paramètres optimisés: {optimization['optimized_parameters']}")
        print(f"  Améliorations:")
        
        for objective, improvement in optimization['improvements'].items():
            print(f"    • {objective}: {improvement:+.1f}%")
        
        print(f"  Score composite: {optimization['composite_score']:.3f}")
        
    except Exception as e:
        print(f"❌ Erreur optimisation: {e}")
    
    print(f"\n=== Statut du Système ===")
    
    # Statut global
    status = predictive_system.get_system_status()
    
    print(f"Équipements surveillés: {status['equipment_count']}")
    print(f"Modèles entraînés: {status['trained_models']}")
    print(f"Points de données total: {status['total_data_points']}")
    print(f"Santé du système: {status['system_health']}")
    
    # Statut détaillé par équipement
    print(f"\nDétail par équipement:")
    for eq_id, eq_status in status['equipment_status'].items():
        print(f"  {eq_id}:")
        print(f"    • Points de données: {eq_status['data_points']}")
        print(f"    • Modèle entraîné: {'✓' if eq_status['model_trained'] else '❌'}")
        print(f"    • Prédictions: {eq_status['last_prediction']}")
    
    print(f"\n=== Démonstration Terminée ===")
    print(f"Le système prédictif est opérationnel et prêt pour l'intégration !")

if __name__ == "__main__":
    asyncio.run(main())