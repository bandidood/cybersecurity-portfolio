#!/usr/bin/env python3
"""
Attack Prediction Model
Time series forecasting for attack prediction and threat trend analysis
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.model_selection import train_test_split, TimeSeriesSplit
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
import statsmodels.api as sm
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.seasonal import seasonal_decompose
from statsmodels.tsa.stattools import adfuller
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any, Optional, Union
import warnings
import logging
import joblib
from datetime import datetime, timedelta
import calendar

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackPredictor:
    """
    Advanced Attack Prediction System using multiple time series techniques:
    - LSTM/GRU neural networks for sequential pattern learning
    - ARIMA models for statistical time series analysis
    - XGBoost for ensemble-based forecasting
    - Seasonal decomposition and trend analysis
    - Multi-variate attack prediction with external factors
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the Attack Predictor"""
        self.config = config or self._default_config()
        
        # Time series models
        self.lstm_model = None
        self.gru_model = None
        self.arima_model = None
        self.xgb_model = None
        self.ensemble_weights = None
        
        # Preprocessing components
        self.scaler = MinMaxScaler()
        self.feature_scaler = StandardScaler()
        
        # Time series parameters
        self.sequence_length = self.config['sequence_length']
        self.prediction_horizon = self.config['prediction_horizon']
        self.feature_columns = []
        self.target_column = 'attack_count'
        
        # Model state
        self.is_trained = False
        self.training_history = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the predictor"""
        return {
            # Time series parameters
            'sequence_length': 24,  # Look back 24 hours
            'prediction_horizon': 6,  # Predict next 6 hours
            'test_size': 0.2,
            'validation_split': 0.2,
            
            # LSTM parameters
            'lstm_units': [128, 64, 32],
            'lstm_dropout': 0.2,
            'lstm_epochs': 100,
            'lstm_batch_size': 32,
            'lstm_learning_rate': 0.001,
            
            # GRU parameters
            'gru_units': [128, 64, 32],
            'gru_dropout': 0.2,
            'gru_epochs': 100,
            'gru_batch_size': 32,
            'gru_learning_rate': 0.001,
            
            # ARIMA parameters
            'arima_order': (2, 1, 2),
            'seasonal_order': (1, 1, 1, 24),
            
            # XGBoost parameters
            'xgb_n_estimators': 200,
            'xgb_max_depth': 6,
            'xgb_learning_rate': 0.1,
            
            # Ensemble parameters
            'ensemble_weights': [0.4, 0.3, 0.2, 0.1],  # LSTM, GRU, ARIMA, XGBoost
            
            # Data generation parameters
            'n_days': 365,
            'base_attack_rate': 10,
            'seasonal_amplitude': 5,
            'noise_level': 0.2
        }
    
    def generate_synthetic_attack_data(self, n_days: int = None) -> pd.DataFrame:
        """
        Generate synthetic attack time series data
        
        Args:
            n_days: Number of days to generate
            
        Returns:
            DataFrame with synthetic attack data
        """
        if n_days is None:
            n_days = self.config['n_days']
        
        np.random.seed(42)
        
        # Generate time index (hourly data)
        start_date = datetime.now() - timedelta(days=n_days)
        date_range = pd.date_range(start=start_date, periods=n_days * 24, freq='H')
        
        # Base attack pattern with multiple components
        n_hours = len(date_range)
        
        # 1. Daily seasonal pattern (more attacks during business hours)
        daily_pattern = np.sin(2 * np.pi * np.arange(n_hours) / 24) * 3 + 5
        
        # 2. Weekly pattern (more attacks on weekdays)
        weekly_pattern = np.sin(2 * np.pi * np.arange(n_hours) / (24 * 7)) * 2
        
        # 3. Monthly pattern (more attacks at month-end/beginning)
        monthly_pattern = np.sin(2 * np.pi * np.arange(n_hours) / (24 * 30)) * 1.5
        
        # 4. Trend component (increasing attacks over time)
        trend = np.linspace(0, 3, n_hours)
        
        # 5. Random spikes (major attack events)
        spike_probability = 0.01
        spikes = np.random.binomial(1, spike_probability, n_hours) * np.random.exponential(20, n_hours)
        
        # 6. Weekend effect (fewer attacks on weekends)
        weekend_effect = []
        for dt in date_range:
            if dt.weekday() >= 5:  # Saturday = 5, Sunday = 6
                weekend_effect.append(-2)
            else:
                weekend_effect.append(0)
        weekend_effect = np.array(weekend_effect)
        
        # 7. Holiday effect (fewer attacks during major holidays)
        holiday_effect = []
        for dt in date_range:
            if (dt.month == 12 and dt.day in [24, 25, 31]) or \
               (dt.month == 1 and dt.day == 1) or \
               (dt.month == 7 and dt.day == 4):  # Christmas, New Year, July 4th
                holiday_effect.append(-3)
            else:
                holiday_effect.append(0)
        holiday_effect = np.array(holiday_effect)
        
        # Combine all patterns
        base_attacks = (
            self.config['base_attack_rate'] +
            daily_pattern +
            weekly_pattern +
            monthly_pattern +
            trend +
            spikes +
            weekend_effect +
            holiday_effect
        )
        
        # Add noise
        noise = np.random.normal(0, self.config['noise_level'] * np.std(base_attacks), n_hours)
        attack_counts = np.maximum(0, base_attacks + noise)
        
        # Generate external features that might influence attacks
        data = {
            'timestamp': date_range,
            'attack_count': attack_counts.astype(int),
            'hour_of_day': [dt.hour for dt in date_range],
            'day_of_week': [dt.weekday() for dt in date_range],
            'day_of_month': [dt.day for dt in date_range],
            'month': [dt.month for dt in date_range],
            'is_weekend': [1 if dt.weekday() >= 5 else 0 for dt in date_range],
            'is_business_hours': [1 if 9 <= dt.hour <= 17 and dt.weekday() < 5 else 0 for dt in date_range],
            'quarter': [((dt.month - 1) // 3) + 1 for dt in date_range]
        }
        
        # Add vulnerability disclosure events (affect attack patterns)
        vuln_disclosure_effect = np.random.binomial(1, 0.02, n_hours) * np.random.exponential(5, n_hours)
        data['vuln_disclosure_impact'] = vuln_disclosure_effect
        
        # Add threat intelligence alerts
        threat_intel_alerts = np.random.poisson(2, n_hours)
        data['threat_intel_alerts'] = threat_intel_alerts
        
        # Add security events from previous periods that might predict future attacks
        data['prev_hour_attacks'] = [0] + attack_counts[:-1].tolist()
        data['prev_day_avg_attacks'] = []
        data['prev_week_avg_attacks'] = []
        
        for i in range(n_hours):
            if i >= 24:
                prev_day_avg = np.mean(attack_counts[max(0, i-24):i])
            else:
                prev_day_avg = np.mean(attack_counts[:i+1])
            data['prev_day_avg_attacks'].append(prev_day_avg)
            
            if i >= 24*7:
                prev_week_avg = np.mean(attack_counts[max(0, i-24*7):i])
            else:
                prev_week_avg = np.mean(attack_counts[:i+1])
            data['prev_week_avg_attacks'].append(prev_week_avg)
        
        # Network activity indicators
        data['network_connections'] = np.random.poisson(1000, n_hours) + attack_counts * 10
        data['failed_logins'] = np.random.poisson(50, n_hours) + attack_counts * 2
        data['dns_queries'] = np.random.poisson(5000, n_hours) + attack_counts * 20
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        df.set_index('timestamp', inplace=True)
        
        logger.info(f"Generated {len(df)} hours of synthetic attack data")
        logger.info(f"Attack statistics:")
        logger.info(f"  Mean attacks per hour: {df['attack_count'].mean():.2f}")
        logger.info(f"  Max attacks per hour: {df['attack_count'].max()}")
        logger.info(f"  Total attacks: {df['attack_count'].sum()}")
        
        return df
    
    def create_sequences(self, data: np.ndarray, target: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create sequences for time series prediction
        
        Args:
            data: Feature data
            target: Target values
            
        Returns:
            Sequences and corresponding targets
        """
        X, y = [], []
        
        for i in range(self.sequence_length, len(data) - self.prediction_horizon + 1):
            X.append(data[i - self.sequence_length:i])
            y.append(target[i:i + self.prediction_horizon])
        
        return np.array(X), np.array(y)
    
    def build_lstm_model(self, input_shape: Tuple[int, int]) -> keras.Model:
        """
        Build LSTM model for attack prediction
        
        Args:
            input_shape: Shape of input sequences
            
        Returns:
            Compiled LSTM model
        """
        model = keras.Sequential()
        
        # LSTM layers
        for i, units in enumerate(self.config['lstm_units']):
            return_sequences = i < len(self.config['lstm_units']) - 1
            
            if i == 0:
                model.add(layers.LSTM(
                    units,
                    return_sequences=return_sequences,
                    input_shape=input_shape,
                    dropout=self.config['lstm_dropout']
                ))
            else:
                model.add(layers.LSTM(
                    units,
                    return_sequences=return_sequences,
                    dropout=self.config['lstm_dropout']
                ))
        
        # Dense layers for prediction
        model.add(layers.Dense(64, activation='relu'))
        model.add(layers.Dropout(0.2))
        model.add(layers.Dense(32, activation='relu'))
        model.add(layers.Dense(self.prediction_horizon, activation='linear'))
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config['lstm_learning_rate']),
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def build_gru_model(self, input_shape: Tuple[int, int]) -> keras.Model:
        """
        Build GRU model for attack prediction
        
        Args:
            input_shape: Shape of input sequences
            
        Returns:
            Compiled GRU model
        """
        model = keras.Sequential()
        
        # GRU layers
        for i, units in enumerate(self.config['gru_units']):
            return_sequences = i < len(self.config['gru_units']) - 1
            
            if i == 0:
                model.add(layers.GRU(
                    units,
                    return_sequences=return_sequences,
                    input_shape=input_shape,
                    dropout=self.config['gru_dropout']
                ))
            else:
                model.add(layers.GRU(
                    units,
                    return_sequences=return_sequences,
                    dropout=self.config['gru_dropout']
                ))
        
        # Dense layers for prediction
        model.add(layers.Dense(64, activation='relu'))
        model.add(layers.Dropout(0.2))
        model.add(layers.Dense(32, activation='relu'))
        model.add(layers.Dense(self.prediction_horizon, activation='linear'))
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config['gru_learning_rate']),
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def prepare_features_for_ml(self, df: pd.DataFrame) -> np.ndarray:
        """
        Prepare features for traditional ML models (ARIMA, XGBoost)
        
        Args:
            df: DataFrame with time series data
            
        Returns:
            Feature matrix for ML models
        """
        # Create lag features
        features_df = df.copy()
        
        # Lag features for attack count
        for lag in [1, 2, 3, 6, 12, 24, 48, 168]:  # 1h, 2h, 3h, 6h, 12h, 1d, 2d, 1w
            features_df[f'attack_count_lag_{lag}'] = features_df['attack_count'].shift(lag)
        
        # Rolling statistics
        for window in [3, 6, 12, 24]:
            features_df[f'attack_count_rolling_mean_{window}'] = features_df['attack_count'].rolling(window).mean()
            features_df[f'attack_count_rolling_std_{window}'] = features_df['attack_count'].rolling(window).std()
            features_df[f'attack_count_rolling_min_{window}'] = features_df['attack_count'].rolling(window).min()
            features_df[f'attack_count_rolling_max_{window}'] = features_df['attack_count'].rolling(window).max()
        
        # Time-based features
        features_df['hour_sin'] = np.sin(2 * np.pi * features_df['hour_of_day'] / 24)
        features_df['hour_cos'] = np.cos(2 * np.pi * features_df['hour_of_day'] / 24)
        features_df['day_sin'] = np.sin(2 * np.pi * features_df['day_of_week'] / 7)
        features_df['day_cos'] = np.cos(2 * np.pi * features_df['day_of_week'] / 7)
        features_df['month_sin'] = np.sin(2 * np.pi * features_df['month'] / 12)
        features_df['month_cos'] = np.cos(2 * np.pi * features_df['month'] / 12)
        
        # Remove original time features and target
        features_to_remove = ['attack_count', 'hour_of_day', 'day_of_week', 'day_of_month', 'month']
        feature_columns = [col for col in features_df.columns if col not in features_to_remove]
        
        # Fill NaN values (from rolling operations)
        features_df = features_df[feature_columns].fillna(method='bfill').fillna(0)
        
        self.feature_columns = feature_columns
        
        return features_df.values
    
    def fit(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Train all prediction models
        
        Args:
            df: Time series data
            
        Returns:
            Training metrics
        """
        logger.info("Training attack prediction models...")
        
        # Prepare data for neural networks
        feature_data = df.drop(columns=[self.target_column]).values
        target_data = df[self.target_column].values
        
        # Scale the data
        feature_data_scaled = self.feature_scaler.fit_transform(feature_data)
        target_data_scaled = self.scaler.fit_transform(target_data.reshape(-1, 1)).flatten()
        
        # Create sequences for neural networks
        X_seq, y_seq = self.create_sequences(feature_data_scaled, target_data_scaled)
        
        # Split data
        split_idx = int(len(X_seq) * (1 - self.config['test_size']))
        X_train_seq, X_test_seq = X_seq[:split_idx], X_seq[split_idx:]
        y_train_seq, y_test_seq = y_seq[:split_idx], y_seq[split_idx:]
        
        training_metrics = {}
        
        # Train LSTM model
        logger.info("Training LSTM model...")
        self.lstm_model = self.build_lstm_model((X_train_seq.shape[1], X_train_seq.shape[2]))
        
        lstm_callbacks = [
            keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5)
        ]
        
        lstm_history = self.lstm_model.fit(
            X_train_seq, y_train_seq,
            epochs=self.config['lstm_epochs'],
            batch_size=self.config['lstm_batch_size'],
            validation_split=self.config['validation_split'],
            callbacks=lstm_callbacks,
            verbose=0
        )
        
        lstm_pred = self.lstm_model.predict(X_test_seq)
        lstm_mse = mean_squared_error(y_test_seq.flatten(), lstm_pred.flatten())
        training_metrics['lstm_mse'] = lstm_mse
        
        # Train GRU model
        logger.info("Training GRU model...")
        self.gru_model = self.build_gru_model((X_train_seq.shape[1], X_train_seq.shape[2]))
        
        gru_callbacks = [
            keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5)
        ]
        
        gru_history = self.gru_model.fit(
            X_train_seq, y_train_seq,
            epochs=self.config['gru_epochs'],
            batch_size=self.config['gru_batch_size'],
            validation_split=self.config['validation_split'],
            callbacks=gru_callbacks,
            verbose=0
        )
        
        gru_pred = self.gru_model.predict(X_test_seq)
        gru_mse = mean_squared_error(y_test_seq.flatten(), gru_pred.flatten())
        training_metrics['gru_mse'] = gru_mse
        
        # Prepare data for traditional ML models
        X_ml = self.prepare_features_for_ml(df)
        y_ml = df[self.target_column].values
        
        # Remove NaN values
        valid_idx = ~np.isnan(X_ml).any(axis=1) & ~np.isnan(y_ml)
        X_ml = X_ml[valid_idx]
        y_ml = y_ml[valid_idx]
        
        # Create multi-step targets for ML models
        y_ml_multi = []
        X_ml_multi = []
        
        for i in range(len(X_ml) - self.prediction_horizon + 1):
            X_ml_multi.append(X_ml[i])
            y_ml_multi.append(y_ml[i:i + self.prediction_horizon])
        
        X_ml_multi = np.array(X_ml_multi)
        y_ml_multi = np.array(y_ml_multi)
        
        # Split data for ML models
        ml_split_idx = int(len(X_ml_multi) * (1 - self.config['test_size']))
        X_train_ml, X_test_ml = X_ml_multi[:ml_split_idx], X_ml_multi[ml_split_idx:]
        y_train_ml, y_test_ml = y_ml_multi[:ml_split_idx], y_ml_multi[ml_split_idx:]
        
        # Train XGBoost model (for multi-step prediction, we'll train separate models for each step)
        logger.info("Training XGBoost model...")
        self.xgb_model = []
        xgb_predictions = []
        
        for step in range(self.prediction_horizon):
            step_model = xgb.XGBRegressor(
                n_estimators=self.config['xgb_n_estimators'],
                max_depth=self.config['xgb_max_depth'],
                learning_rate=self.config['xgb_learning_rate'],
                random_state=42,
                verbosity=0
            )
            step_model.fit(X_train_ml, y_train_ml[:, step])
            self.xgb_model.append(step_model)
            
            step_pred = step_model.predict(X_test_ml)
            xgb_predictions.append(step_pred)
        
        xgb_predictions = np.array(xgb_predictions).T
        xgb_mse = mean_squared_error(y_test_ml.flatten(), xgb_predictions.flatten())
        training_metrics['xgb_mse'] = xgb_mse
        
        # Train ARIMA model (univariate)
        logger.info("Training ARIMA model...")
        try:
            train_data = df[self.target_column][:split_idx * self.sequence_length]
            self.arima_model = ARIMA(
                train_data,
                order=self.config['arima_order'],
                seasonal_order=self.config['seasonal_order']
            ).fit()
            
            # Make ARIMA predictions
            arima_pred = self.arima_model.forecast(steps=len(y_test_seq) * self.prediction_horizon)
            arima_pred = arima_pred.values.reshape(-1, self.prediction_horizon)
            arima_mse = mean_squared_error(y_test_seq.flatten(), arima_pred.flatten())
            training_metrics['arima_mse'] = arima_mse
            
        except Exception as e:
            logger.warning(f"ARIMA model training failed: {e}")
            self.arima_model = None
            training_metrics['arima_mse'] = float('inf')
        
        # Calculate ensemble weights based on performance
        models_mse = [
            training_metrics['lstm_mse'],
            training_metrics['gru_mse'],
            training_metrics['arima_mse'] if training_metrics['arima_mse'] != float('inf') else 1000,
            training_metrics['xgb_mse']
        ]
        
        # Inverse MSE weights (better models get higher weights)
        inverse_mse = [1 / (mse + 1e-8) for mse in models_mse]
        total_inverse = sum(inverse_mse)
        self.ensemble_weights = [w / total_inverse for w in inverse_mse]
        
        training_metrics.update({
            'ensemble_weights_lstm': self.ensemble_weights[0],
            'ensemble_weights_gru': self.ensemble_weights[1],
            'ensemble_weights_arima': self.ensemble_weights[2],
            'ensemble_weights_xgb': self.ensemble_weights[3],
            'total_training_samples': len(df)
        })
        
        # Store training history
        self.training_history = {
            'lstm_history': lstm_history.history,
            'gru_history': gru_history.history
        }
        
        self.is_trained = True
        logger.info("Training completed successfully")
        
        return training_metrics
    
    def predict(self, df: pd.DataFrame, n_steps: int = None) -> Dict[str, np.ndarray]:
        """
        Make attack predictions using ensemble of models
        
        Args:
            df: Input data for prediction
            n_steps: Number of future steps to predict
            
        Returns:
            Dictionary with predictions from each model and ensemble
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        if n_steps is None:
            n_steps = self.prediction_horizon
        
        predictions = {}
        
        # Prepare data for neural networks
        feature_data = df.drop(columns=[self.target_column]).values
        feature_data_scaled = self.feature_scaler.transform(feature_data)
        
        # Get last sequence for prediction
        if len(feature_data_scaled) >= self.sequence_length:
            last_sequence = feature_data_scaled[-self.sequence_length:].reshape(1, self.sequence_length, -1)
            
            # LSTM prediction
            lstm_pred = self.lstm_model.predict(last_sequence, verbose=0)
            lstm_pred_rescaled = self.scaler.inverse_transform(lstm_pred.reshape(-1, 1)).flatten()
            predictions['lstm'] = lstm_pred_rescaled[:n_steps]
            
            # GRU prediction
            gru_pred = self.gru_model.predict(last_sequence, verbose=0)
            gru_pred_rescaled = self.scaler.inverse_transform(gru_pred.reshape(-1, 1)).flatten()
            predictions['gru'] = gru_pred_rescaled[:n_steps]
        
        # ARIMA prediction
        if self.arima_model is not None:
            try:
                arima_pred = self.arima_model.forecast(steps=n_steps)
                predictions['arima'] = arima_pred.values
            except:
                predictions['arima'] = np.zeros(n_steps)
        else:
            predictions['arima'] = np.zeros(n_steps)
        
        # XGBoost prediction
        X_ml = self.prepare_features_for_ml(df)
        if len(X_ml) > 0:
            last_features = X_ml[-1].reshape(1, -1)
            xgb_pred = []
            for i, model in enumerate(self.xgb_model):
                if i < n_steps:
                    step_pred = model.predict(last_features)[0]
                    xgb_pred.append(step_pred)
            predictions['xgb'] = np.array(xgb_pred)
        else:
            predictions['xgb'] = np.zeros(n_steps)
        
        # Ensemble prediction
        ensemble_pred = np.zeros(n_steps)
        total_weight = 0
        
        for i, (model_name, weight) in enumerate(zip(['lstm', 'gru', 'arima', 'xgb'], self.ensemble_weights)):
            if model_name in predictions and len(predictions[model_name]) >= n_steps:
                ensemble_pred += weight * predictions[model_name][:n_steps]
                total_weight += weight
        
        if total_weight > 0:
            ensemble_pred /= total_weight
        
        predictions['ensemble'] = ensemble_pred
        
        return predictions
    
    def evaluate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluate model performance on test data
        
        Args:
            df: Test data
            
        Returns:
            Evaluation metrics
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        # Generate predictions
        predictions = self.predict(df)
        
        # Get true values (assuming we want to predict the next steps from the current data)
        if len(df) >= self.prediction_horizon:
            y_true = df[self.target_column][-self.prediction_horizon:].values
        else:
            y_true = df[self.target_column].values
        
        results = {}
        
        for model_name, y_pred in predictions.items():
            if len(y_pred) == len(y_true):
                mse = mean_squared_error(y_true, y_pred)
                mae = mean_absolute_error(y_true, y_pred)
                rmse = np.sqrt(mse)
                
                # Calculate MAPE (Mean Absolute Percentage Error)
                mape = np.mean(np.abs((y_true - y_pred) / (y_true + 1e-8))) * 100
                
                results[model_name] = {
                    'mse': mse,
                    'rmse': rmse,
                    'mae': mae,
                    'mape': mape
                }
        
        return results
    
    def plot_predictions(self, df: pd.DataFrame, predictions: Dict[str, np.ndarray], save_path: Optional[str] = None):
        """Plot predictions vs actual values"""
        plt.figure(figsize=(15, 10))
        
        # Plot historical data
        plt.subplot(2, 1, 1)
        plt.plot(df.index, df[self.target_column], label='Historical', alpha=0.7)
        plt.title('Historical Attack Patterns')
        plt.xlabel('Time')
        plt.ylabel('Attack Count')
        plt.legend()
        plt.grid(True)
        
        # Plot predictions
        plt.subplot(2, 1, 2)
        
        # Generate future timestamps
        last_timestamp = df.index[-1]
        future_timestamps = pd.date_range(
            start=last_timestamp + pd.Timedelta(hours=1),
            periods=len(predictions['ensemble']),
            freq='H'
        )
        
        # Plot each model's predictions
        for model_name, pred in predictions.items():
            plt.plot(future_timestamps, pred, label=f'{model_name.upper()}', marker='o', alpha=0.7)
        
        plt.title('Attack Predictions')
        plt.xlabel('Time')
        plt.ylabel('Predicted Attack Count')
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
        plt.show()
    
    def save_model(self, model_path: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        # Save neural network models
        self.lstm_model.save(f"{model_path}_lstm.h5")
        self.gru_model.save(f"{model_path}_gru.h5")
        
        # Save other components
        model_data = {
            'xgb_model': self.xgb_model,
            'arima_model': self.arima_model,
            'scaler': self.scaler,
            'feature_scaler': self.feature_scaler,
            'ensemble_weights': self.ensemble_weights,
            'feature_columns': self.feature_columns,
            'config': self.config,
            'training_history': self.training_history
        }
        
        joblib.dump(model_data, f"{model_path}_components.pkl")
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load trained model"""
        # Load neural network models
        self.lstm_model = keras.models.load_model(f"{model_path}_lstm.h5")
        self.gru_model = keras.models.load_model(f"{model_path}_gru.h5")
        
        # Load other components
        model_data = joblib.load(f"{model_path}_components.pkl")
        self.xgb_model = model_data['xgb_model']
        self.arima_model = model_data['arima_model']
        self.scaler = model_data['scaler']
        self.feature_scaler = model_data['feature_scaler']
        self.ensemble_weights = model_data['ensemble_weights']
        self.feature_columns = model_data['feature_columns']
        self.config.update(model_data['config'])
        self.training_history = model_data['training_history']
        self.is_trained = True
        
        logger.info(f"Model loaded from {model_path}")

def main():
    """Demonstration of Attack Prediction"""
    logger.info("Starting Attack Prediction demonstration...")
    
    # Initialize predictor
    predictor = AttackPredictor()
    
    # Generate synthetic data
    data = predictor.generate_synthetic_attack_data(n_days=90)
    
    # Split data for training and testing
    split_point = len(data) - 24 * 7  # Keep last week for testing
    train_data = data[:split_point]
    test_data = data[split_point:]
    
    # Train models
    logger.info("Training attack prediction models...")
    training_metrics = predictor.fit(train_data)
    
    # Make predictions
    logger.info("Making predictions...")
    predictions = predictor.predict(test_data)
    
    # Evaluate models
    evaluation_results = predictor.evaluate(test_data)
    
    # Print results
    print("\n" + "="*50)
    print("ATTACK PREDICTION RESULTS")
    print("="*50)
    
    print("\nTraining Metrics:")
    for metric, value in training_metrics.items():
        print(f"  {metric}: {value:.4f}")
    
    print("\nEvaluation Results:")
    for model, metrics in evaluation_results.items():
        print(f"\n{model.upper()} Model:")
        for metric, value in metrics.items():
            print(f"  {metric}: {value:.4f}")
    
    # Plot predictions
    predictor.plot_predictions(test_data, predictions)
    
    # Save model
    model_path = "projects/21-ai-powered-cybersecurity/ml_models/attack_predictor_model"
    predictor.save_model(model_path)
    
    logger.info("Attack Prediction demonstration completed!")

if __name__ == "__main__":
    main()