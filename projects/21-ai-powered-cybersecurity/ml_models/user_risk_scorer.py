#!/usr/bin/env python3
"""
User Risk Scoring Model
Advanced behavioral analytics for user risk assessment and insider threat detection
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any, Optional, Union
import warnings
import logging
import joblib
from datetime import datetime, timedelta
import networkx as nx
from scipy import stats
import pickle

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserRiskScorer:
    """
    Advanced User Risk Scoring System using behavioral analytics:
    - Baseline behavior learning for individual users
    - Anomaly detection for unusual user activities
    - Risk scoring based on multiple behavioral indicators
    - Insider threat detection using ensemble methods
    - Peer group analysis and deviation scoring
    - Network analysis of user interactions
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the User Risk Scorer"""
        self.config = config or self._default_config()
        
        # ML models
        self.isolation_forest = IsolationForest(
            contamination=self.config['contamination_rate'],
            random_state=42
        )
        self.lof_detector = LocalOutlierFactor(
            n_neighbors=self.config['lof_neighbors'],
            contamination=self.config['contamination_rate']
        )
        self.dbscan_clusterer = DBSCAN(
            eps=self.config['dbscan_eps'],
            min_samples=self.config['dbscan_min_samples']
        )
        self.kmeans_clusterer = KMeans(
            n_clusters=self.config['n_user_clusters'],
            random_state=42
        )
        self.autoencoder = None
        self.risk_classifier = None
        
        # Preprocessing components
        self.scaler = StandardScaler()
        self.robust_scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.pca = PCA(n_components=self.config['pca_components'])
        
        # User behavior baselines
        self.user_baselines = {}
        self.peer_groups = {}
        self.feature_weights = {}
        
        # Risk scoring thresholds
        self.risk_thresholds = {
            'low': self.config['low_risk_threshold'],
            'medium': self.config['medium_risk_threshold'],
            'high': self.config['high_risk_threshold']
        }
        
        # Model state
        self.is_trained = False
        self.feature_names = []
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the risk scorer"""
        return {
            # Model parameters
            'contamination_rate': 0.05,
            'lof_neighbors': 20,
            'dbscan_eps': 0.5,
            'dbscan_min_samples': 5,
            'n_user_clusters': 8,
            'pca_components': 20,
            
            # Autoencoder parameters
            'autoencoder_encoding_dim': 32,
            'autoencoder_hidden_dims': [128, 64, 32],
            'autoencoder_epochs': 100,
            'autoencoder_batch_size': 32,
            'autoencoder_learning_rate': 0.001,
            
            # Risk thresholds
            'low_risk_threshold': 0.3,
            'medium_risk_threshold': 0.6,
            'high_risk_threshold': 0.8,
            
            # Behavioral parameters
            'baseline_days': 30,
            'anomaly_threshold': 2.5,  # Standard deviations
            'peer_group_size': 10,
            
            # Data generation parameters
            'n_users': 1000,
            'n_days': 90,
            'insider_ratio': 0.05
        }
    
    def generate_synthetic_user_data(self, n_users: int = None, n_days: int = None) -> pd.DataFrame:
        """
        Generate synthetic user behavioral data
        
        Args:
            n_users: Number of users to simulate
            n_days: Number of days of activity
            
        Returns:
            DataFrame with user behavioral features
        """
        if n_users is None:
            n_users = self.config['n_users']
        if n_days is None:
            n_days = self.config['n_days']
        
        np.random.seed(42)
        
        # Generate user profiles
        users = []
        departments = ['IT', 'Finance', 'HR', 'Marketing', 'Operations', 'Legal', 'Sales']
        roles = ['Junior', 'Senior', 'Manager', 'Director', 'C-Level']
        
        for i in range(n_users):
            users.append({
                'user_id': f'user_{i:04d}',
                'department': np.random.choice(departments),
                'role': np.random.choice(roles),
                'tenure_months': np.random.randint(1, 120),
                'is_insider': np.random.random() < self.config['insider_ratio']
            })
        
        # Generate daily activities for each user
        all_activities = []
        
        for user in users:
            for day in range(n_days):
                date = datetime.now() - timedelta(days=n_days - day)
                
                # Base activity patterns by role
                role_multipliers = {
                    'Junior': 0.8,
                    'Senior': 1.0,
                    'Manager': 1.2,
                    'Director': 1.5,
                    'C-Level': 2.0
                }
                
                base_multiplier = role_multipliers.get(user['role'], 1.0)
                
                # Normal user behavior
                if not user['is_insider']:
                    activity = self._generate_normal_activity(user, date, base_multiplier)
                else:
                    # Insider behavior (gradually becoming more suspicious)
                    suspicion_factor = min(1.0, day / (n_days * 0.7))  # Ramp up over 70% of period
                    activity = self._generate_insider_activity(user, date, base_multiplier, suspicion_factor)
                
                activity['user_id'] = user['user_id']
                activity['date'] = date
                activity['department'] = user['department']
                activity['role'] = user['role']
                activity['tenure_months'] = user['tenure_months']
                activity['is_insider'] = user['is_insider']
                
                all_activities.append(activity)
        
        df = pd.DataFrame(all_activities)
        
        # Add derived features
        df = self._add_derived_features(df)
        
        logger.info(f"Generated behavioral data for {n_users} users over {n_days} days")
        logger.info(f"Total records: {len(df)}")
        logger.info(f"Insider threats: {df['is_insider'].sum()}")
        
        return df
    
    def _generate_normal_activity(self, user: Dict, date: datetime, multiplier: float) -> Dict:
        """Generate normal user activity for a day"""
        # Weekend effect
        weekend_factor = 0.3 if date.weekday() >= 5 else 1.0
        
        # Department-specific patterns
        dept_patterns = {
            'IT': {'late_hours': 0.3, 'weekend_work': 0.4, 'system_access': 2.0},
            'Finance': {'late_hours': 0.4, 'weekend_work': 0.2, 'system_access': 1.5},
            'HR': {'late_hours': 0.1, 'weekend_work': 0.1, 'system_access': 1.0},
            'Marketing': {'late_hours': 0.2, 'weekend_work': 0.2, 'system_access': 0.8},
            'Operations': {'late_hours': 0.2, 'weekend_work': 0.3, 'system_access': 1.2},
            'Legal': {'late_hours': 0.3, 'weekend_work': 0.1, 'system_access': 1.1},
            'Sales': {'late_hours': 0.3, 'weekend_work': 0.3, 'system_access': 0.9}
        }
        
        dept_pattern = dept_patterns.get(user['department'], dept_patterns['Operations'])
        
        # Base activity levels
        activity = {
            'login_count': max(0, int(np.random.poisson(3 * multiplier * weekend_factor))),
            'hours_worked': max(0, np.random.normal(8 * weekend_factor, 2)),
            'emails_sent': max(0, int(np.random.poisson(25 * multiplier * weekend_factor))),
            'emails_received': max(0, int(np.random.poisson(40 * multiplier * weekend_factor))),
            'files_accessed': max(0, int(np.random.poisson(15 * multiplier * weekend_factor))),
            'files_downloaded': max(0, int(np.random.poisson(3 * multiplier * weekend_factor))),
            'files_uploaded': max(0, int(np.random.poisson(2 * multiplier * weekend_factor))),
            'system_commands': max(0, int(np.random.poisson(10 * dept_pattern['system_access'] * multiplier * weekend_factor))),
            'failed_logins': max(0, int(np.random.poisson(0.2))),
            'after_hours_activity': np.random.random() < dept_pattern['late_hours'] * weekend_factor,
            'weekend_activity': np.random.random() < dept_pattern['weekend_work'] if date.weekday() >= 5 else False,
            'vpn_usage_hours': max(0, np.random.exponential(1) if np.random.random() < 0.3 else 0),
            'unique_ip_addresses': max(1, int(np.random.poisson(1.5))),
            'data_transfer_mb': max(0, np.random.lognormal(4, 1.5) * multiplier),
            'printing_pages': max(0, int(np.random.poisson(5 * multiplier * weekend_factor))),
            'usb_usage_count': max(0, int(np.random.poisson(0.1))),
            'policy_violations': max(0, int(np.random.poisson(0.05))),
            'security_alerts': max(0, int(np.random.poisson(0.1)))
        }
        
        return activity
    
    def _generate_insider_activity(self, user: Dict, date: datetime, multiplier: float, suspicion_factor: float) -> Dict:
        """Generate insider threat activity (gradually becoming more suspicious)"""
        # Start with normal activity
        activity = self._generate_normal_activity(user, date, multiplier)
        
        # Add suspicious behaviors that increase over time
        if suspicion_factor > 0.1:
            # Unusual file access patterns
            activity['files_accessed'] = int(activity['files_accessed'] * (1 + 3 * suspicion_factor))
            activity['files_downloaded'] = int(activity['files_downloaded'] * (1 + 5 * suspicion_factor))
            
            # Unusual data transfer
            activity['data_transfer_mb'] = activity['data_transfer_mb'] * (1 + 4 * suspicion_factor)
            
            # More after-hours activity
            if np.random.random() < 0.3 * suspicion_factor:
                activity['after_hours_activity'] = True
                activity['hours_worked'] += np.random.exponential(3)
            
            # More failed login attempts (trying to access restricted areas)
            activity['failed_logins'] += int(np.random.poisson(suspicion_factor * 2))
            
            # More system commands (reconnaissance)
            activity['system_commands'] = int(activity['system_commands'] * (1 + 2 * suspicion_factor))
            
            # USB usage (data exfiltration)
            if np.random.random() < 0.2 * suspicion_factor:
                activity['usb_usage_count'] += 1
            
            # More unique IP addresses (accessing from different locations)
            activity['unique_ip_addresses'] = int(activity['unique_ip_addresses'] * (1 + suspicion_factor))
            
            # More printing (physical data theft)
            if np.random.random() < 0.3 * suspicion_factor:
                activity['printing_pages'] = int(activity['printing_pages'] * (1 + 2 * suspicion_factor))
            
            # Policy violations
            activity['policy_violations'] += int(np.random.poisson(suspicion_factor))
            
            # Security alerts
            activity['security_alerts'] += int(np.random.poisson(suspicion_factor * 0.5))
        
        return activity
    
    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add derived behavioral features"""
        df = df.copy()
        
        # Time-based features
        df['is_weekend'] = (df['date'].dt.weekday >= 5).astype(int)
        df['day_of_week'] = df['date'].dt.dayofweek
        df['month'] = df['date'].dt.month
        
        # Ratios and derived metrics
        df['files_downloaded_ratio'] = df['files_downloaded'] / (df['files_accessed'] + 1)
        df['failed_login_ratio'] = df['failed_logins'] / (df['login_count'] + 1)
        df['email_ratio'] = df['emails_sent'] / (df['emails_received'] + 1)
        df['data_per_hour'] = df['data_transfer_mb'] / (df['hours_worked'] + 0.1)
        df['commands_per_hour'] = df['system_commands'] / (df['hours_worked'] + 0.1)
        
        # Rolling averages (simulated with noise for synthetic data)
        for user_id in df['user_id'].unique():
            user_mask = df['user_id'] == user_id
            user_data = df.loc[user_mask].sort_values('date')
            
            # 7-day rolling averages
            for col in ['login_count', 'hours_worked', 'files_accessed', 'data_transfer_mb']:
                rolling_avg = user_data[col].rolling(window=7, min_periods=1).mean()
                df.loc[user_mask, f'{col}_7day_avg'] = rolling_avg.values
                
                # Deviation from average
                df.loc[user_mask, f'{col}_deviation'] = (user_data[col] - rolling_avg) / (rolling_avg + 0.1)
        
        return df
    
    def create_user_baselines(self, df: pd.DataFrame) -> Dict[str, Dict]:
        """
        Create behavioral baselines for each user
        
        Args:
            df: User behavioral data
            
        Returns:
            Dictionary of user baselines
        """
        baselines = {}
        
        behavioral_features = [
            'login_count', 'hours_worked', 'emails_sent', 'emails_received',
            'files_accessed', 'files_downloaded', 'system_commands',
            'data_transfer_mb', 'vpn_usage_hours', 'unique_ip_addresses'
        ]
        
        for user_id in df['user_id'].unique():
            user_data = df[df['user_id'] == user_id]
            
            # Calculate baseline statistics
            baseline = {}
            for feature in behavioral_features:
                values = user_data[feature]
                baseline[feature] = {
                    'mean': values.mean(),
                    'std': values.std() if len(values) > 1 else 0,
                    'median': values.median(),
                    'q25': values.quantile(0.25),
                    'q75': values.quantile(0.75),
                    'min': values.min(),
                    'max': values.max()
                }
            
            # Behavioral patterns
            baseline['patterns'] = {
                'avg_after_hours_rate': user_data['after_hours_activity'].mean(),
                'avg_weekend_rate': user_data['weekend_activity'].mean(),
                'avg_failed_login_rate': user_data['failed_login_ratio'].mean(),
                'typical_work_hours': user_data['hours_worked'].median(),
                'typical_login_count': user_data['login_count'].median()
            }
            
            baselines[user_id] = baseline
        
        return baselines
    
    def create_peer_groups(self, df: pd.DataFrame) -> Dict[str, List[str]]:
        """
        Create peer groups based on role and department
        
        Args:
            df: User behavioral data
            
        Returns:
            Dictionary mapping users to their peer groups
        """
        peer_groups = {}
        
        # Get unique user information
        user_info = df.groupby('user_id').agg({
            'department': 'first',
            'role': 'first',
            'tenure_months': 'first'
        }).reset_index()
        
        for _, user in user_info.iterrows():
            user_id = user['user_id']
            
            # Find similar users (same department and similar role/tenure)
            similar_users = user_info[
                (user_info['department'] == user['department']) &
                (user_info['user_id'] != user_id)
            ]
            
            # Sort by role and tenure similarity
            role_order = ['Junior', 'Senior', 'Manager', 'Director', 'C-Level']
            user_role_idx = role_order.index(user['role']) if user['role'] in role_order else 2
            
            similar_users = similar_users.copy()
            similar_users['role_score'] = similar_users['role'].apply(
                lambda x: abs(role_order.index(x) - user_role_idx) if x in role_order else 5
            )
            similar_users['tenure_score'] = abs(similar_users['tenure_months'] - user['tenure_months'])
            similar_users['similarity_score'] = similar_users['role_score'] + similar_users['tenure_score'] / 12
            
            # Select top peers
            peers = similar_users.nsmallest(self.config['peer_group_size'], 'similarity_score')
            peer_groups[user_id] = peers['user_id'].tolist()
        
        return peer_groups
    
    def build_autoencoder(self, input_dim: int) -> keras.Model:
        """
        Build autoencoder for behavioral anomaly detection
        
        Args:
            input_dim: Input feature dimension
            
        Returns:
            Compiled autoencoder model
        """
        # Input layer
        input_layer = keras.Input(shape=(input_dim,))
        
        # Encoder layers
        encoded = input_layer
        for dim in self.config['autoencoder_hidden_dims']:
            encoded = layers.Dense(dim, activation='relu')(encoded)
            encoded = layers.Dropout(0.2)(encoded)
        
        # Bottleneck
        encoded = layers.Dense(self.config['autoencoder_encoding_dim'], activation='relu')(encoded)
        
        # Decoder layers
        decoded = encoded
        for dim in reversed(self.config['autoencoder_hidden_dims']):
            decoded = layers.Dense(dim, activation='relu')(decoded)
            decoded = layers.Dropout(0.2)(decoded)
        
        # Output layer
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Create and compile model
        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config['autoencoder_learning_rate']),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder
    
    def extract_behavioral_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Extract and preprocess behavioral features
        
        Args:
            df: Raw behavioral data
            
        Returns:
            Processed feature matrix
        """
        # Select behavioral features
        behavioral_features = [
            'login_count', 'hours_worked', 'emails_sent', 'emails_received',
            'files_accessed', 'files_downloaded', 'files_uploaded', 'system_commands',
            'failed_logins', 'after_hours_activity', 'weekend_activity',
            'vpn_usage_hours', 'unique_ip_addresses', 'data_transfer_mb',
            'printing_pages', 'usb_usage_count', 'policy_violations', 'security_alerts',
            'files_downloaded_ratio', 'failed_login_ratio', 'email_ratio',
            'data_per_hour', 'commands_per_hour', 'is_weekend', 'day_of_week', 'month'
        ]
        
        # Add rolling features if they exist
        rolling_features = [col for col in df.columns if '_7day_avg' in col or '_deviation' in col]
        behavioral_features.extend(rolling_features)
        
        # Select available features
        available_features = [col for col in behavioral_features if col in df.columns]
        self.feature_names = available_features
        
        # Extract feature matrix
        feature_matrix = df[available_features].values
        
        # Handle missing values
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0)
        
        return feature_matrix.astype(np.float32)
    
    def fit(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Train the user risk scoring models
        
        Args:
            df: Training data with user behaviors
            
        Returns:
            Training metrics
        """
        logger.info("Training user risk scoring models...")
        
        # Create user baselines and peer groups
        self.user_baselines = self.create_user_baselines(df)
        self.peer_groups = self.create_peer_groups(df)
        
        # Extract features
        X = self.extract_behavioral_features(df)
        y = df['is_insider'].values
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        X_robust = self.robust_scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, stratify=y, random_state=42
        )
        
        training_metrics = {}
        
        # Train Isolation Forest
        logger.info("Training Isolation Forest...")
        self.isolation_forest.fit(X_train)
        iso_pred = self.isolation_forest.predict(X_test)
        iso_scores = self.isolation_forest.score_samples(X_test)
        
        # Train autoencoder
        logger.info("Training autoencoder...")
        self.autoencoder = self.build_autoencoder(X_train.shape[1])
        
        callbacks = [
            keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5)
        ]
        
        history = self.autoencoder.fit(
            X_train, X_train,
            epochs=self.config['autoencoder_epochs'],
            batch_size=self.config['autoencoder_batch_size'],
            validation_split=0.2,
            callbacks=callbacks,
            verbose=0
        )
        
        # Calculate reconstruction errors
        reconstructions = self.autoencoder.predict(X_test)
        reconstruction_errors = np.mean(np.power(X_test - reconstructions, 2), axis=1)
        
        # Train clustering models
        logger.info("Training clustering models...")
        self.kmeans_clusterer.fit(X_scaled)
        cluster_labels = self.kmeans_clusterer.predict(X_test)
        
        # Train supervised classifier for risk assessment
        logger.info("Training risk classifier...")
        self.risk_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42
        )
        self.risk_classifier.fit(X_train, y_train)
        
        # Calculate training metrics
        rf_pred = self.risk_classifier.predict(X_test)
        rf_proba = self.risk_classifier.predict_proba(X_test)[:, 1]
        
        training_metrics = {
            'isolation_forest_anomalies': np.sum(iso_pred == -1),
            'autoencoder_mean_reconstruction_error': np.mean(reconstruction_errors),
            'autoencoder_std_reconstruction_error': np.std(reconstruction_errors),
            'kmeans_clusters': len(np.unique(cluster_labels)),
            'risk_classifier_accuracy': np.mean(rf_pred == y_test),
            'risk_classifier_auc': roc_auc_score(y_test, rf_proba),
            'training_samples': len(X_train),
            'feature_count': X_train.shape[1]
        }
        
        # Calculate feature importance weights
        self.feature_weights = dict(zip(
            self.feature_names,
            self.risk_classifier.feature_importances_
        ))
        
        self.is_trained = True
        logger.info("Training completed successfully")
        
        return training_metrics
    
    def calculate_risk_score(self, user_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a user
        
        Args:
            user_data: User's behavioral data
            
        Returns:
            Risk assessment results
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before calculating risk scores")
        
        user_id = user_data['user_id'].iloc[0]
        
        # Extract features
        X = self.extract_behavioral_features(user_data)
        X_scaled = self.scaler.transform(X)
        
        # Get latest behavior
        latest_behavior = X_scaled[-1:] if len(X_scaled) > 0 else X_scaled
        
        risk_components = {}
        
        # 1. Isolation Forest anomaly score
        iso_score = self.isolation_forest.decision_function(latest_behavior)[0]
        risk_components['isolation_anomaly'] = max(0, -iso_score / 2)  # Normalize to positive
        
        # 2. Autoencoder reconstruction error
        reconstruction = self.autoencoder.predict(latest_behavior, verbose=0)
        reconstruction_error = np.mean(np.power(latest_behavior - reconstruction, 2))
        risk_components['autoencoder_anomaly'] = min(1.0, reconstruction_error * 10)
        
        # 3. Supervised risk prediction
        risk_proba = self.risk_classifier.predict_proba(latest_behavior)[0, 1]
        risk_components['supervised_risk'] = risk_proba
        
        # 4. Baseline deviation score
        if user_id in self.user_baselines:
            baseline_score = self._calculate_baseline_deviation(user_data.iloc[-1], user_id)
            risk_components['baseline_deviation'] = baseline_score
        else:
            risk_components['baseline_deviation'] = 0.0
        
        # 5. Peer comparison score
        if user_id in self.peer_groups:
            peer_score = self._calculate_peer_deviation(user_data.iloc[-1], user_id, user_data)
            risk_components['peer_deviation'] = peer_score
        else:
            risk_components['peer_deviation'] = 0.0
        
        # Calculate composite risk score
        weights = {
            'isolation_anomaly': 0.2,
            'autoencoder_anomaly': 0.25,
            'supervised_risk': 0.3,
            'baseline_deviation': 0.15,
            'peer_deviation': 0.1
        }
        
        composite_score = sum(
            weights[component] * score
            for component, score in risk_components.items()
        )
        
        # Determine risk level
        if composite_score >= self.risk_thresholds['high']:
            risk_level = 'HIGH'
        elif composite_score >= self.risk_thresholds['medium']:
            risk_level = 'MEDIUM'
        elif composite_score >= self.risk_thresholds['low']:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        # Generate risk factors
        risk_factors = self._identify_risk_factors(user_data.iloc[-1], risk_components)
        
        return {
            'user_id': user_id,
            'risk_score': composite_score,
            'risk_level': risk_level,
            'risk_components': risk_components,
            'risk_factors': risk_factors,
            'timestamp': datetime.now()
        }
    
    def _calculate_baseline_deviation(self, current_behavior: pd.Series, user_id: str) -> float:
        """Calculate deviation from user's baseline behavior"""
        baseline = self.user_baselines[user_id]
        deviation_scores = []
        
        behavioral_features = [
            'login_count', 'hours_worked', 'files_accessed', 'files_downloaded',
            'system_commands', 'data_transfer_mb'
        ]
        
        for feature in behavioral_features:
            if feature in current_behavior and feature in baseline:
                current_value = current_behavior[feature]
                baseline_mean = baseline[feature]['mean']
                baseline_std = baseline[feature]['std']
                
                if baseline_std > 0:
                    z_score = abs((current_value - baseline_mean) / baseline_std)
                    deviation_scores.append(min(1.0, z_score / self.config['anomaly_threshold']))
        
        return np.mean(deviation_scores) if deviation_scores else 0.0
    
    def _calculate_peer_deviation(self, current_behavior: pd.Series, user_id: str, all_data: pd.DataFrame) -> float:
        """Calculate deviation from peer group behavior"""
        peers = self.peer_groups.get(user_id, [])
        if not peers:
            return 0.0
        
        # Get recent peer behavior (last 7 days)
        recent_date = all_data['date'].max() - timedelta(days=7)
        peer_data = all_data[
            (all_data['user_id'].isin(peers)) &
            (all_data['date'] >= recent_date)
        ]
        
        if len(peer_data) == 0:
            return 0.0
        
        deviation_scores = []
        behavioral_features = [
            'login_count', 'hours_worked', 'files_accessed', 'files_downloaded',
            'system_commands', 'data_transfer_mb'
        ]
        
        for feature in behavioral_features:
            if feature in current_behavior:
                current_value = current_behavior[feature]
                peer_values = peer_data[feature]
                
                if len(peer_values) > 0:
                    peer_mean = peer_values.mean()
                    peer_std = peer_values.std()
                    
                    if peer_std > 0:
                        z_score = abs((current_value - peer_mean) / peer_std)
                        deviation_scores.append(min(1.0, z_score / self.config['anomaly_threshold']))
        
        return np.mean(deviation_scores) if deviation_scores else 0.0
    
    def _identify_risk_factors(self, current_behavior: pd.Series, risk_components: Dict) -> List[str]:
        """Identify specific risk factors contributing to the score"""
        risk_factors = []
        
        # High values in key metrics
        if current_behavior.get('after_hours_activity', False):
            risk_factors.append("Unusual after-hours activity")
        
        if current_behavior.get('weekend_activity', False):
            risk_factors.append("Weekend activity detected")
        
        if current_behavior.get('failed_logins', 0) > 5:
            risk_factors.append("High number of failed login attempts")
        
        if current_behavior.get('files_downloaded', 0) > current_behavior.get('files_accessed', 1) * 0.5:
            risk_factors.append("High file download ratio")
        
        if current_behavior.get('data_transfer_mb', 0) > 1000:
            risk_factors.append("Large data transfer volume")
        
        if current_behavior.get('usb_usage_count', 0) > 0:
            risk_factors.append("USB device usage")
        
        if current_behavior.get('policy_violations', 0) > 0:
            risk_factors.append("Policy violations detected")
        
        if current_behavior.get('unique_ip_addresses', 1) > 3:
            risk_factors.append("Access from multiple IP addresses")
        
        # High risk component scores
        if risk_components.get('supervised_risk', 0) > 0.7:
            risk_factors.append("High ML-based risk prediction")
        
        if risk_components.get('baseline_deviation', 0) > 0.6:
            risk_factors.append("Significant deviation from personal baseline")
        
        if risk_components.get('peer_deviation', 0) > 0.6:
            risk_factors.append("Behavior differs significantly from peers")
        
        return risk_factors
    
    def batch_score_users(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate risk scores for all users in batch
        
        Args:
            df: User behavioral data
            
        Returns:
            DataFrame with risk scores for all users
        """
        results = []
        
        for user_id in df['user_id'].unique():
            user_data = df[df['user_id'] == user_id].sort_values('date')
            
            try:
                risk_assessment = self.calculate_risk_score(user_data)
                results.append(risk_assessment)
            except Exception as e:
                logger.warning(f"Failed to score user {user_id}: {e}")
                # Add default risk assessment
                results.append({
                    'user_id': user_id,
                    'risk_score': 0.0,
                    'risk_level': 'UNKNOWN',
                    'risk_components': {},
                    'risk_factors': [],
                    'timestamp': datetime.now()
                })
        
        return pd.DataFrame(results)
    
    def save_model(self, model_path: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        # Save neural network
        self.autoencoder.save(f"{model_path}_autoencoder.h5")
        
        # Save other components
        model_data = {
            'isolation_forest': self.isolation_forest,
            'kmeans_clusterer': self.kmeans_clusterer,
            'risk_classifier': self.risk_classifier,
            'scaler': self.scaler,
            'robust_scaler': self.robust_scaler,
            'user_baselines': self.user_baselines,
            'peer_groups': self.peer_groups,
            'feature_weights': self.feature_weights,
            'feature_names': self.feature_names,
            'config': self.config
        }
        
        joblib.dump(model_data, f"{model_path}_components.pkl")
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load trained model"""
        # Load neural network
        self.autoencoder = keras.models.load_model(f"{model_path}_autoencoder.h5")
        
        # Load other components
        model_data = joblib.load(f"{model_path}_components.pkl")
        self.isolation_forest = model_data['isolation_forest']
        self.kmeans_clusterer = model_data['kmeans_clusterer']
        self.risk_classifier = model_data['risk_classifier']
        self.scaler = model_data['scaler']
        self.robust_scaler = model_data['robust_scaler']
        self.user_baselines = model_data['user_baselines']
        self.peer_groups = model_data['peer_groups']
        self.feature_weights = model_data['feature_weights']
        self.feature_names = model_data['feature_names']
        self.config.update(model_data['config'])
        self.is_trained = True
        
        logger.info(f"Model loaded from {model_path}")

def main():
    """Demonstration of User Risk Scoring"""
    logger.info("Starting User Risk Scoring demonstration...")
    
    # Initialize risk scorer
    scorer = UserRiskScorer()
    
    # Generate synthetic data
    data = scorer.generate_synthetic_user_data(n_users=200, n_days=60)
    
    # Split data for training and testing
    split_date = data['date'].max() - timedelta(days=14)
    train_data = data[data['date'] <= split_date]
    test_data = data[data['date'] > split_date]
    
    # Train models
    logger.info("Training user risk scoring models...")
    training_metrics = scorer.fit(train_data)
    
    # Calculate risk scores for test users
    logger.info("Calculating risk scores...")
    risk_scores = scorer.batch_score_users(test_data)
    
    # Print results
    print("\n" + "="*60)
    print("USER RISK SCORING RESULTS")
    print("="*60)
    
    print("\nTraining Metrics:")
    for metric, value in training_metrics.items():
        print(f"  {metric}: {value:.4f}")
    
    print("\nRisk Score Distribution:")
    risk_distribution = risk_scores['risk_level'].value_counts()
    for level, count in risk_distribution.items():
        percentage = (count / len(risk_scores)) * 100
        print(f"  {level}: {count} users ({percentage:.1f}%)")
    
    print("\nTop 10 Highest Risk Users:")
    top_risk_users = risk_scores.nlargest(10, 'risk_score')
    for _, user in top_risk_users.iterrows():
        print(f"  {user['user_id']}: {user['risk_score']:.3f} ({user['risk_level']})")
        if user['risk_factors']:
            print(f"    Risk factors: {', '.join(user['risk_factors'][:3])}")
    
    print("\nFeature Importance (Top 10):")
    sorted_features = sorted(scorer.feature_weights.items(), key=lambda x: x[1], reverse=True)
    for feature, importance in sorted_features[:10]:
        print(f"  {feature}: {importance:.4f}")
    
    # Evaluate against true insider labels
    test_users = test_data.groupby('user_id')['is_insider'].first()
    risk_scores_with_labels = risk_scores.merge(
        test_users.reset_index(), on='user_id', how='left'
    )
    
    if 'is_insider' in risk_scores_with_labels.columns:
        # Calculate detection metrics
        y_true = risk_scores_with_labels['is_insider']
        y_scores = risk_scores_with_labels['risk_score']
        
        auc_score = roc_auc_score(y_true, y_scores)
        
        # High risk threshold detection
        high_risk_predictions = (risk_scores_with_labels['risk_level'] == 'HIGH').astype(int)
        precision = np.sum(y_true & high_risk_predictions) / (np.sum(high_risk_predictions) + 1e-8)
        recall = np.sum(y_true & high_risk_predictions) / (np.sum(y_true) + 1e-8)
        
        print("\nInsider Threat Detection Performance:")
        print(f"  AUC Score: {auc_score:.4f}")
        print(f"  High Risk Precision: {precision:.4f}")
        print(f"  High Risk Recall: {recall:.4f}")
    
    # Save model
    model_path = "projects/21-ai-powered-cybersecurity/ml_models/user_risk_scorer_model"
    scorer.save_model(model_path)
    
    logger.info("User Risk Scoring demonstration completed!")

if __name__ == "__main__":
    main()