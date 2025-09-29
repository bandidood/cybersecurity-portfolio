#!/usr/bin/env python3
"""
Network Anomaly Detection Model
Advanced autoencoder-based anomaly detection for network traffic analysis
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple, Dict, List, Any, Optional
import pickle
import joblib
import logging
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkAnomalyDetector:
    """
    Advanced Network Anomaly Detection using multiple ML techniques:
    - Autoencoder for unsupervised anomaly detection
    - Isolation Forest for outlier detection
    - DBSCAN for density-based clustering
    - Statistical methods for baseline comparison
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the Network Anomaly Detector"""
        self.config = config or self._default_config()
        self.autoencoder = None
        self.encoder = None
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=self.config['contamination_rate'],
            random_state=42
        )
        self.dbscan = DBSCAN(
            eps=self.config['dbscan_eps'],
            min_samples=self.config['dbscan_min_samples']
        )
        self.label_encoders = {}
        self.feature_columns = []
        self.threshold = None
        self.training_loss = []
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the model"""
        return {
            'encoding_dim': 32,
            'hidden_dims': [128, 64, 32],
            'learning_rate': 0.001,
            'epochs': 100,
            'batch_size': 256,
            'validation_split': 0.2,
            'contamination_rate': 0.1,
            'anomaly_threshold_percentile': 95,
            'dbscan_eps': 0.5,
            'dbscan_min_samples': 5,
            'early_stopping_patience': 10
        }
    
    def create_autoencoder(self, input_dim: int) -> keras.Model:
        """
        Create a deep autoencoder for anomaly detection
        
        Args:
            input_dim: Dimension of input features
            
        Returns:
            Compiled autoencoder model
        """
        # Input layer
        input_layer = keras.Input(shape=(input_dim,))
        
        # Encoder layers
        encoded = input_layer
        for dim in self.config['hidden_dims']:
            encoded = layers.Dense(dim, activation='relu')(encoded)
            encoded = layers.Dropout(0.2)(encoded)
        
        # Bottleneck layer
        encoded = layers.Dense(self.config['encoding_dim'], activation='relu')(encoded)
        
        # Decoder layers
        decoded = encoded
        for dim in reversed(self.config['hidden_dims']):
            decoded = layers.Dense(dim, activation='relu')(decoded)
            decoded = layers.Dropout(0.2)(decoded)
        
        # Output layer
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Create and compile autoencoder
        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config['learning_rate']),
            loss='mse',
            metrics=['mae']
        )
        
        # Create encoder model for feature extraction
        self.encoder = keras.Model(input_layer, encoded)
        
        return autoencoder
    
    def preprocess_network_data(self, data: pd.DataFrame) -> np.ndarray:
        """
        Preprocess network traffic data for anomaly detection
        
        Args:
            data: Raw network traffic data
            
        Returns:
            Preprocessed feature matrix
        """
        logger.info("Preprocessing network traffic data...")
        
        # Define network traffic features
        numeric_features = [
            'duration', 'protocol_type', 'service', 'flag',
            'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        
        categorical_features = ['protocol_type', 'service', 'flag']
        
        # Handle missing columns
        available_numeric = [col for col in numeric_features if col in data.columns]
        available_categorical = [col for col in categorical_features if col in data.columns]
        
        processed_data = data.copy()
        
        # Encode categorical features
        for feature in available_categorical:
            if feature not in self.label_encoders:
                self.label_encoders[feature] = LabelEncoder()
                processed_data[feature] = self.label_encoders[feature].fit_transform(
                    processed_data[feature].astype(str)
                )
            else:
                processed_data[feature] = self.label_encoders[feature].transform(
                    processed_data[feature].astype(str)
                )
        
        # Select numerical features
        feature_matrix = processed_data[available_numeric + available_categorical].values
        
        # Handle NaN values
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0)
        
        self.feature_columns = available_numeric + available_categorical
        
        return feature_matrix.astype(np.float32)
    
    def generate_synthetic_network_data(self, n_samples: int = 10000) -> pd.DataFrame:
        """
        Generate synthetic network traffic data for demonstration
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            Synthetic network traffic DataFrame
        """
        np.random.seed(42)
        
        # Generate normal traffic patterns
        normal_samples = int(n_samples * 0.9)
        anomaly_samples = n_samples - normal_samples
        
        # Normal traffic features
        normal_data = {
            'duration': np.random.exponential(1.0, normal_samples),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], normal_samples, p=[0.7, 0.25, 0.05]),
            'service': np.random.choice(['http', 'smtp', 'ftp', 'ssh', 'dns'], normal_samples, p=[0.4, 0.2, 0.15, 0.15, 0.1]),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR'], normal_samples, p=[0.8, 0.1, 0.05, 0.05]),
            'src_bytes': np.random.lognormal(8, 2, normal_samples),
            'dst_bytes': np.random.lognormal(9, 2, normal_samples),
            'land': np.random.choice([0, 1], normal_samples, p=[0.99, 0.01]),
            'wrong_fragment': np.random.poisson(0.1, normal_samples),
            'urgent': np.random.poisson(0.05, normal_samples),
            'hot': np.random.poisson(0.2, normal_samples),
            'num_failed_logins': np.random.poisson(0.1, normal_samples),
            'logged_in': np.random.choice([0, 1], normal_samples, p=[0.3, 0.7]),
            'num_compromised': np.zeros(normal_samples),
            'root_shell': np.zeros(normal_samples),
            'su_attempted': np.zeros(normal_samples),
            'num_root': np.random.poisson(0.1, normal_samples),
            'num_file_creations': np.random.poisson(1.0, normal_samples),
            'num_shells': np.random.poisson(0.1, normal_samples),
            'num_access_files': np.random.poisson(0.5, normal_samples),
            'num_outbound_cmds': np.zeros(normal_samples),
            'is_host_login': np.random.choice([0, 1], normal_samples, p=[0.9, 0.1]),
            'is_guest_login': np.random.choice([0, 1], normal_samples, p=[0.95, 0.05]),
            'count': np.random.poisson(10, normal_samples),
            'srv_count': np.random.poisson(8, normal_samples),
            'serror_rate': np.random.beta(1, 10, normal_samples),
            'srv_serror_rate': np.random.beta(1, 10, normal_samples),
            'rerror_rate': np.random.beta(1, 20, normal_samples),
            'srv_rerror_rate': np.random.beta(1, 20, normal_samples),
            'same_srv_rate': np.random.beta(8, 2, normal_samples),
            'diff_srv_rate': np.random.beta(2, 8, normal_samples),
            'srv_diff_host_rate': np.random.beta(2, 8, normal_samples),
            'dst_host_count': np.random.poisson(50, normal_samples),
            'dst_host_srv_count': np.random.poisson(30, normal_samples),
            'dst_host_same_srv_rate': np.random.beta(8, 2, normal_samples),
            'dst_host_diff_srv_rate': np.random.beta(2, 8, normal_samples),
            'dst_host_same_src_port_rate': np.random.beta(5, 5, normal_samples),
            'dst_host_srv_diff_host_rate': np.random.beta(2, 8, normal_samples),
            'dst_host_serror_rate': np.random.beta(1, 10, normal_samples),
            'dst_host_srv_serror_rate': np.random.beta(1, 10, normal_samples),
            'dst_host_rerror_rate': np.random.beta(1, 20, normal_samples),
            'dst_host_srv_rerror_rate': np.random.beta(1, 20, normal_samples),
            'label': ['normal'] * normal_samples
        }
        
        # Anomalous traffic features (attacks)
        anomaly_data = {
            'duration': np.random.exponential(5.0, anomaly_samples),  # Longer durations
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], anomaly_samples, p=[0.5, 0.3, 0.2]),
            'service': np.random.choice(['http', 'smtp', 'ftp', 'ssh', 'dns'], anomaly_samples),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR'], anomaly_samples, p=[0.4, 0.3, 0.2, 0.1]),
            'src_bytes': np.random.lognormal(12, 3, anomaly_samples),  # Larger transfers
            'dst_bytes': np.random.lognormal(6, 3, anomaly_samples),   # Unusual patterns
            'land': np.random.choice([0, 1], anomaly_samples, p=[0.8, 0.2]),  # More land attacks
            'wrong_fragment': np.random.poisson(2.0, anomaly_samples),  # More fragmentation issues
            'urgent': np.random.poisson(1.0, anomaly_samples),  # More urgent packets
            'hot': np.random.poisson(5.0, anomaly_samples),     # More hot indicators
            'num_failed_logins': np.random.poisson(5.0, anomaly_samples),  # Failed login attempts
            'logged_in': np.random.choice([0, 1], anomaly_samples, p=[0.7, 0.3]),
            'num_compromised': np.random.poisson(2.0, anomaly_samples),  # Compromise indicators
            'root_shell': np.random.poisson(1.0, anomaly_samples),      # Root access attempts
            'su_attempted': np.random.poisson(1.0, anomaly_samples),    # Privilege escalation
            'num_root': np.random.poisson(3.0, anomaly_samples),
            'num_file_creations': np.random.poisson(10.0, anomaly_samples),  # Unusual file activity
            'num_shells': np.random.poisson(2.0, anomaly_samples),           # Shell access
            'num_access_files': np.random.poisson(10.0, anomaly_samples),
            'num_outbound_cmds': np.random.poisson(5.0, anomaly_samples),    # Command execution
            'is_host_login': np.random.choice([0, 1], anomaly_samples, p=[0.6, 0.4]),
            'is_guest_login': np.random.choice([0, 1], anomaly_samples, p=[0.7, 0.3]),
            'count': np.random.poisson(100, anomaly_samples),    # High connection counts
            'srv_count': np.random.poisson(80, anomaly_samples),
            'serror_rate': np.random.beta(5, 5, anomaly_samples),     # Higher error rates
            'srv_serror_rate': np.random.beta(5, 5, anomaly_samples),
            'rerror_rate': np.random.beta(3, 7, anomaly_samples),
            'srv_rerror_rate': np.random.beta(3, 7, anomaly_samples),
            'same_srv_rate': np.random.beta(2, 8, anomaly_samples),   # Different service patterns
            'diff_srv_rate': np.random.beta(8, 2, anomaly_samples),
            'srv_diff_host_rate': np.random.beta(8, 2, anomaly_samples),
            'dst_host_count': np.random.poisson(200, anomaly_samples),  # Scanning behavior
            'dst_host_srv_count': np.random.poisson(150, anomaly_samples),
            'dst_host_same_srv_rate': np.random.beta(2, 8, anomaly_samples),
            'dst_host_diff_srv_rate': np.random.beta(8, 2, anomaly_samples),
            'dst_host_same_src_port_rate': np.random.beta(2, 8, anomaly_samples),
            'dst_host_srv_diff_host_rate': np.random.beta(8, 2, anomaly_samples),
            'dst_host_serror_rate': np.random.beta(5, 5, anomaly_samples),
            'dst_host_srv_serror_rate': np.random.beta(5, 5, anomaly_samples),
            'dst_host_rerror_rate': np.random.beta(3, 7, anomaly_samples),
            'dst_host_srv_rerror_rate': np.random.beta(3, 7, anomaly_samples),
            'label': ['attack'] * anomaly_samples
        }
        
        # Combine normal and anomalous data
        combined_data = {}
        for key in normal_data.keys():
            combined_data[key] = np.concatenate([normal_data[key], anomaly_data[key]])
        
        # Create DataFrame and shuffle
        df = pd.DataFrame(combined_data)
        df = df.sample(frac=1).reset_index(drop=True)
        
        logger.info(f"Generated {len(df)} synthetic network traffic samples")
        logger.info(f"Normal samples: {len(df[df['label'] == 'normal'])}")
        logger.info(f"Attack samples: {len(df[df['label'] == 'attack'])}")
        
        return df
    
    def fit(self, X: np.ndarray, validation_data: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Train the anomaly detection models
        
        Args:
            X: Training data
            validation_data: Optional validation data
            
        Returns:
            Training history and metrics
        """
        logger.info("Training network anomaly detection models...")
        
        # Normalize the data
        X_scaled = self.scaler.fit_transform(X)
        
        # Create and train autoencoder
        self.autoencoder = self.create_autoencoder(X_scaled.shape[1])
        
        # Setup callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.config['early_stopping_patience'],
                restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            )
        ]
        
        # Train autoencoder
        history = self.autoencoder.fit(
            X_scaled, X_scaled,
            epochs=self.config['epochs'],
            batch_size=self.config['batch_size'],
            validation_split=self.config['validation_split'],
            callbacks=callbacks,
            verbose=1
        )
        
        # Calculate reconstruction errors for threshold setting
        predictions = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        self.threshold = np.percentile(mse, self.config['anomaly_threshold_percentile'])
        
        # Train Isolation Forest
        logger.info("Training Isolation Forest...")
        self.isolation_forest.fit(X_scaled)
        
        # Train DBSCAN clustering
        logger.info("Training DBSCAN clustering...")
        dbscan_labels = self.dbscan.fit_predict(X_scaled)
        
        # Store training metrics
        training_metrics = {
            'autoencoder_loss': history.history['loss'][-1],
            'autoencoder_val_loss': history.history['val_loss'][-1],
            'reconstruction_threshold': self.threshold,
            'isolation_forest_score': np.mean(self.isolation_forest.score_samples(X_scaled)),
            'dbscan_clusters': len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0),
            'dbscan_outliers': np.sum(dbscan_labels == -1)
        }
        
        self.training_loss = history.history['loss']
        
        logger.info("Training completed successfully")
        return training_metrics
    
    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Predict anomalies using ensemble of methods
        
        Args:
            X: Input data for prediction
            
        Returns:
            Dictionary with predictions from different methods
        """
        X_scaled = self.scaler.transform(X)
        
        # Autoencoder predictions
        reconstructions = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        autoencoder_anomalies = (mse > self.threshold).astype(int)
        
        # Isolation Forest predictions
        isolation_predictions = self.isolation_forest.predict(X_scaled)
        isolation_anomalies = (isolation_predictions == -1).astype(int)
        
        # DBSCAN predictions
        dbscan_predictions = self.dbscan.fit_predict(X_scaled)
        dbscan_anomalies = (dbscan_predictions == -1).astype(int)
        
        # Ensemble prediction (majority vote)
        ensemble_predictions = (
            autoencoder_anomalies + isolation_anomalies + dbscan_anomalies
        ) >= 2
        
        return {
            'autoencoder_anomalies': autoencoder_anomalies,
            'isolation_forest_anomalies': isolation_anomalies,
            'dbscan_anomalies': dbscan_anomalies,
            'ensemble_anomalies': ensemble_predictions.astype(int),
            'reconstruction_errors': mse,
            'isolation_scores': self.isolation_forest.score_samples(X_scaled),
            'dbscan_labels': dbscan_predictions
        }
    
    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (higher = more anomalous)
        
        Args:
            X: Input data
            
        Returns:
            Anomaly scores
        """
        X_scaled = self.scaler.transform(X)
        
        # Autoencoder reconstruction error
        reconstructions = self.autoencoder.predict(X_scaled)
        reconstruction_errors = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        
        # Isolation Forest anomaly scores (negative = more anomalous)
        isolation_scores = -self.isolation_forest.score_samples(X_scaled)
        
        # Normalize scores to 0-1 range
        reconstruction_norm = (reconstruction_errors - reconstruction_errors.min()) / \
                             (reconstruction_errors.max() - reconstruction_errors.min())
        isolation_norm = (isolation_scores - isolation_scores.min()) / \
                        (isolation_scores.max() - isolation_scores.min())
        
        # Combined anomaly score
        combined_scores = (reconstruction_norm + isolation_norm) / 2
        
        return combined_scores
    
    def evaluate(self, X: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model performance
        
        Args:
            X: Test features
            y_true: True labels (0 = normal, 1 = anomaly)
            
        Returns:
            Evaluation metrics
        """
        predictions = self.predict(X)
        
        results = {}
        
        for method_name, y_pred in predictions.items():
            if method_name.endswith('_anomalies'):
                method = method_name.replace('_anomalies', '').replace('_', ' ').title()
                
                from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
                
                results[method] = {
                    'accuracy': accuracy_score(y_true, y_pred),
                    'precision': precision_score(y_true, y_pred, zero_division=0),
                    'recall': recall_score(y_true, y_pred, zero_division=0),
                    'f1_score': f1_score(y_true, y_pred, zero_division=0)
                }
                
                try:
                    results[method]['auc'] = roc_auc_score(y_true, y_pred)
                except ValueError:
                    results[method]['auc'] = 0.0
        
        return results
    
    def plot_training_history(self, save_path: Optional[str] = None):
        """Plot training history"""
        if not self.training_loss:
            logger.warning("No training history available")
            return
        
        plt.figure(figsize=(12, 4))
        
        plt.subplot(1, 2, 1)
        plt.plot(self.training_loss)
        plt.title('Autoencoder Training Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.grid(True)
        
        plt.subplot(1, 2, 2)
        # Plot reconstruction error distribution
        plt.hist(self.training_loss, bins=50, alpha=0.7)
        plt.axvline(self.threshold, color='red', linestyle='--', label='Threshold')
        plt.title('Reconstruction Error Distribution')
        plt.xlabel('Reconstruction Error')
        plt.ylabel('Frequency')
        plt.legend()
        plt.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
        plt.show()
    
    def save_model(self, model_path: str):
        """Save trained model"""
        # Save autoencoder
        self.autoencoder.save(f"{model_path}_autoencoder.h5")
        
        # Save other components
        model_data = {
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
            'label_encoders': self.label_encoders,
            'threshold': self.threshold,
            'feature_columns': self.feature_columns,
            'config': self.config
        }
        
        joblib.dump(model_data, f"{model_path}_components.pkl")
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load trained model"""
        # Load autoencoder
        self.autoencoder = keras.models.load_model(f"{model_path}_autoencoder.h5")
        
        # Create encoder from loaded autoencoder
        input_layer = self.autoencoder.input
        encoded_layer = None
        for layer in self.autoencoder.layers:
            if layer.name.endswith('dense') and layer.output_shape[1] == self.config['encoding_dim']:
                encoded_layer = layer.output
                break
        
        if encoded_layer is not None:
            self.encoder = keras.Model(input_layer, encoded_layer)
        
        # Load other components
        model_data = joblib.load(f"{model_path}_components.pkl")
        self.scaler = model_data['scaler']
        self.isolation_forest = model_data['isolation_forest']
        self.label_encoders = model_data['label_encoders']
        self.threshold = model_data['threshold']
        self.feature_columns = model_data['feature_columns']
        self.config.update(model_data['config'])
        
        logger.info(f"Model loaded from {model_path}")

def main():
    """Demonstration of Network Anomaly Detection"""
    logger.info("Starting Network Anomaly Detection demonstration...")
    
    # Initialize detector
    detector = NetworkAnomalyDetector()
    
    # Generate synthetic data
    data = detector.generate_synthetic_network_data(n_samples=20000)
    
    # Separate features and labels
    X = detector.preprocess_network_data(data.drop('label', axis=1))
    y = (data['label'] == 'attack').astype(int)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )
    
    # Train models
    logger.info("Training anomaly detection models...")
    training_metrics = detector.fit(X_train)
    
    # Evaluate models
    logger.info("Evaluating models...")
    evaluation_results = detector.evaluate(X_test, y_test)
    
    # Print results
    print("\n" + "="*50)
    print("NETWORK ANOMALY DETECTION RESULTS")
    print("="*50)
    
    print("\nTraining Metrics:")
    for metric, value in training_metrics.items():
        print(f"  {metric}: {value:.4f}")
    
    print("\nEvaluation Results:")
    for method, metrics in evaluation_results.items():
        print(f"\n{method} Method:")
        for metric, value in metrics.items():
            print(f"  {metric}: {value:.4f}")
    
    # Plot training history
    detector.plot_training_history()
    
    # Save model
    model_path = "projects/21-ai-powered-cybersecurity/ml_models/network_anomaly_model"
    detector.save_model(model_path)
    
    logger.info("Network Anomaly Detection demonstration completed!")

if __name__ == "__main__":
    main()