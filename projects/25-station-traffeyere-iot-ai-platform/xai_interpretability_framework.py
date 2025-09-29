#!/usr/bin/env python3
"""
Project 25 - Station Traffeyère IoT AI Platform  
Component 4D: Advanced Model Interpretability Framework

Comprehensive framework for global and local model interpretability with
feature attribution, decision boundary analysis, model behavior understanding,
and advanced XAI techniques for industrial IoT anomaly detection.

Author: Industrial IoT Security Specialist
Date: 2024
"""

import os
import json
import asyncio
import logging
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field
import numpy as np
import pandas as pd
from pathlib import Path
import pickle
import joblib

# Advanced ML and interpretability
import sklearn
from sklearn.inspection import permutation_importance
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier, export_text, export_graphviz
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc

# Deep learning interpretability
import tensorflow as tf
from tensorflow.keras.models import Model
import tensorflow.keras.backend as K

# Advanced XAI libraries
import lime
import lime.lime_tabular
import shap
import eli5
from eli5.sklearn import PermutationImportance
import anchor
from anchor import anchor_tabular

# Visualization and analysis
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Statistical analysis
import scipy.stats as stats
from scipy.spatial.distance import pdist, squareform
from scipy.cluster.hierarchy import dendrogram, linkage
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

# Dimensionality reduction and visualization
from umap import UMAP
import networkx as nx

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class InterpretabilityConfig:
    """Configuration for interpretability framework."""
    
    # Global interpretability settings
    global_methods: List[str] = field(default_factory=lambda: [
        "feature_importance", "partial_dependence", "interaction_effects",
        "model_behavior_analysis", "decision_boundary_analysis"
    ])
    
    # Local interpretability settings  
    local_methods: List[str] = field(default_factory=lambda: [
        "lime", "shap", "anchor", "counterfactual", "prototype"
    ])
    
    # Analysis settings
    max_features_analyze: int = 50
    sample_size_global: int = 10000
    sample_size_local: int = 1000
    confidence_level: float = 0.95
    
    # Visualization settings
    generate_plots: bool = True
    plot_format: str = "png"  # png, svg, html
    output_dir: str = "interpretability_output"
    
    # Performance settings
    parallel_processing: bool = True
    max_workers: int = 4
    cache_results: bool = True
    cache_ttl_hours: int = 24

@dataclass  
class InterpretabilityResult:
    """Container for interpretability analysis results."""
    model_name: str
    analysis_type: str  # global, local, decision_boundary
    timestamp: datetime
    
    # Feature analysis
    feature_importance: Dict[str, float] = field(default_factory=dict)
    feature_interactions: Dict[str, Dict[str, float]] = field(default_factory=dict) 
    partial_dependence: Dict[str, Any] = field(default_factory=dict)
    
    # Local explanations
    local_explanations: List[Dict[str, Any]] = field(default_factory=list)
    counterfactuals: List[Dict[str, Any]] = field(default_factory=list)
    prototypes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Model behavior
    decision_boundaries: Dict[str, Any] = field(default_factory=dict)
    model_complexity: Dict[str, float] = field(default_factory=dict)
    stability_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Visualization paths
    visualization_paths: List[str] = field(default_factory=list)
    
    # Metadata
    computation_time: float = 0.0
    data_size: int = 0
    confidence_scores: Dict[str, float] = field(default_factory=dict)

class AdvancedInterpretabilityFramework:
    """Comprehensive model interpretability framework for XAI systems."""
    
    def __init__(self, config: InterpretabilityConfig = None):
        """Initialize interpretability framework."""
        self.config = config or InterpretabilityConfig()
        
        # Create output directory
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize explainers cache
        self.explainers_cache = {}
        self.analysis_cache = {}
        
        # Initialize visualization components
        self.plot_configs = {
            "figure_size": (12, 8),
            "dpi": 300,
            "style": "seaborn-v0_8",
            "color_palette": "Set2"
        }
        
        logger.info("Advanced Interpretability Framework initialized")
    
    async def analyze_model_interpretability(self, model: Any, model_name: str,
                                           X: np.ndarray, y: np.ndarray = None,
                                           feature_names: List[str] = None) -> InterpretabilityResult:
        """Perform comprehensive interpretability analysis on a model."""
        
        start_time = datetime.now()
        logger.info(f"Starting interpretability analysis for {model_name}")
        
        # Initialize result container
        result = InterpretabilityResult(
            model_name=model_name,
            analysis_type="comprehensive",
            timestamp=start_time,
            data_size=len(X)
        )
        
        # Set default feature names
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(X.shape[1])]
        
        try:
            # Global interpretability analysis
            if "feature_importance" in self.config.global_methods:
                result.feature_importance = await self._analyze_feature_importance(
                    model, X, y, feature_names
                )
            
            if "partial_dependence" in self.config.global_methods:
                result.partial_dependence = await self._analyze_partial_dependence(
                    model, X, feature_names
                )
            
            if "interaction_effects" in self.config.global_methods:
                result.feature_interactions = await self._analyze_feature_interactions(
                    model, X, feature_names
                )
            
            if "model_behavior_analysis" in self.config.global_methods:
                behavior_analysis = await self._analyze_model_behavior(model, X, y)
                result.model_complexity = behavior_analysis.get("complexity", {})
                result.stability_analysis = behavior_analysis.get("stability", {})
            
            if "decision_boundary_analysis" in self.config.global_methods:
                result.decision_boundaries = await self._analyze_decision_boundaries(
                    model, X, feature_names
                )
            
            # Local interpretability analysis (sample-based)
            local_sample_indices = np.random.choice(
                len(X), 
                size=min(self.config.sample_size_local, len(X)), 
                replace=False
            )
            
            for method in self.config.local_methods:
                if method == "lime":
                    lime_results = await self._generate_lime_explanations(
                        model, X[local_sample_indices], feature_names
                    )
                    result.local_explanations.extend(lime_results)
                
                elif method == "shap":
                    shap_results = await self._generate_shap_explanations(
                        model, X[local_sample_indices], feature_names
                    )
                    result.local_explanations.extend(shap_results)
                
                elif method == "counterfactual":
                    counterfactuals = await self._generate_counterfactuals(
                        model, X[local_sample_indices], feature_names
                    )
                    result.counterfactuals = counterfactuals
                
                elif method == "prototype":
                    prototypes = await self._find_prototypes(
                        model, X, feature_names
                    )
                    result.prototypes = prototypes
            
            # Generate visualizations
            if self.config.generate_plots:
                viz_paths = await self._generate_visualizations(result, X, feature_names)
                result.visualization_paths = viz_paths
            
            # Calculate confidence scores
            result.confidence_scores = self._calculate_confidence_scores(result)
            
        except Exception as e:
            logger.error(f"Error in interpretability analysis: {e}")
            result.confidence_scores = {"error": 0.0}
        
        # Record computation time
        result.computation_time = (datetime.now() - start_time).total_seconds()
        
        # Cache results if enabled
        if self.config.cache_results:
            cache_key = f"{model_name}_{hash(str(X.tobytes()))}"
            self.analysis_cache[cache_key] = result
        
        logger.info(f"Interpretability analysis completed in {result.computation_time:.2f}s")
        return result
    
    async def _analyze_feature_importance(self, model: Any, X: np.ndarray, 
                                        y: np.ndarray, feature_names: List[str]) -> Dict[str, float]:
        """Analyze global feature importance using multiple methods."""
        
        importance_scores = {}
        
        try:
            # Method 1: Built-in feature importance (for tree-based models)
            if hasattr(model, 'feature_importances_'):
                builtin_importance = model.feature_importances_
                for i, name in enumerate(feature_names):
                    importance_scores[f"{name}_builtin"] = float(builtin_importance[i])
            
            # Method 2: Permutation importance
            if y is not None:
                perm_importance = permutation_importance(
                    model, X, y, 
                    n_repeats=10,
                    random_state=42,
                    n_jobs=-1 if self.config.parallel_processing else 1
                )
                
                for i, name in enumerate(feature_names):
                    importance_scores[f"{name}_permutation"] = float(perm_importance.importances_mean[i])
                    importance_scores[f"{name}_permutation_std"] = float(perm_importance.importances_std[i])
            
            # Method 3: Coefficient-based importance (for linear models)
            if hasattr(model, 'coef_'):
                coeffs = model.coef_
                if coeffs.ndim > 1:
                    coeffs = coeffs[0]  # Take first class for binary classification
                
                for i, name in enumerate(feature_names):
                    importance_scores[f"{name}_coefficient"] = float(abs(coeffs[i]))
            
            # Method 4: Statistical correlation (if y available)
            if y is not None and len(np.unique(y)) == 2:  # Binary classification
                for i, name in enumerate(feature_names):
                    correlation = abs(np.corrcoef(X[:, i], y)[0, 1])
                    importance_scores[f"{name}_correlation"] = float(correlation) if not np.isnan(correlation) else 0.0
            
            # Aggregate importance scores
            aggregated_importance = {}
            for name in feature_names:
                scores = [v for k, v in importance_scores.items() if k.startswith(name)]
                if scores:
                    aggregated_importance[name] = np.mean(scores)
                else:
                    aggregated_importance[name] = 0.0
            
            return aggregated_importance
            
        except Exception as e:
            logger.error(f"Error analyzing feature importance: {e}")
            return {name: 0.0 for name in feature_names}
    
    async def _analyze_partial_dependence(self, model: Any, X: np.ndarray,
                                        feature_names: List[str]) -> Dict[str, Any]:
        """Analyze partial dependence effects."""
        
        partial_dependence = {}
        
        try:
            from sklearn.inspection import partial_dependence as pd_sklearn
            
            # Analyze top features only
            feature_importance = await self._analyze_feature_importance(model, X, None, feature_names)
            top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
            
            for feature_name, _ in top_features:
                try:
                    feature_idx = feature_names.index(feature_name)
                    
                    # Calculate partial dependence
                    pd_result = pd_sklearn(
                        model, X, [feature_idx], 
                        kind='average',
                        grid_resolution=50
                    )
                    
                    partial_dependence[feature_name] = {
                        'values': pd_result['values'][0].tolist(),
                        'grid_values': pd_result['grid_values'][0].tolist(),
                        'feature_idx': feature_idx
                    }
                    
                except Exception as e:
                    logger.warning(f"Could not calculate partial dependence for {feature_name}: {e}")
                    partial_dependence[feature_name] = {'error': str(e)}
            
        except Exception as e:
            logger.error(f"Error in partial dependence analysis: {e}")
        
        return partial_dependence
    
    async def _analyze_feature_interactions(self, model: Any, X: np.ndarray,
                                          feature_names: List[str]) -> Dict[str, Dict[str, float]]:
        """Analyze feature interactions."""
        
        interactions = {}
        
        try:
            # Get top features for interaction analysis
            feature_importance = await self._analyze_feature_importance(model, X, None, feature_names)
            top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
            top_feature_names = [name for name, _ in top_features]
            
            # Calculate pairwise interactions
            for i, feature1 in enumerate(top_feature_names):
                interactions[feature1] = {}
                
                for j, feature2 in enumerate(top_feature_names):
                    if i != j:
                        try:
                            # Simple interaction measure: correlation between features
                            idx1 = feature_names.index(feature1)
                            idx2 = feature_names.index(feature2)
                            
                            correlation = np.corrcoef(X[:, idx1], X[:, idx2])[0, 1]
                            interactions[feature1][feature2] = float(abs(correlation)) if not np.isnan(correlation) else 0.0
                            
                        except Exception as e:
                            logger.warning(f"Could not calculate interaction {feature1}-{feature2}: {e}")
                            interactions[feature1][feature2] = 0.0
            
        except Exception as e:
            logger.error(f"Error analyzing feature interactions: {e}")
        
        return interactions
    
    async def _analyze_model_behavior(self, model: Any, X: np.ndarray,
                                    y: np.ndarray = None) -> Dict[str, Any]:
        """Analyze overall model behavior and complexity."""
        
        behavior_analysis = {
            "complexity": {},
            "stability": {}
        }
        
        try:
            # Model complexity measures
            
            # 1. Decision tree depth (if applicable)
            if hasattr(model, 'tree_'):
                behavior_analysis["complexity"]["tree_depth"] = model.tree_.max_depth
                behavior_analysis["complexity"]["n_nodes"] = model.tree_.node_count
                behavior_analysis["complexity"]["n_leaves"] = model.tree_.n_leaves
            
            # 2. Number of parameters (for neural networks)
            if hasattr(model, 'count_params'):
                behavior_analysis["complexity"]["n_parameters"] = model.count_params()
            
            # 3. Model capacity (for ensemble methods)
            if hasattr(model, 'n_estimators'):
                behavior_analysis["complexity"]["n_estimators"] = model.n_estimators
            
            # Stability analysis
            if len(X) > 100:
                # Sample different subsets and measure prediction consistency
                n_samples = 10
                subset_size = min(1000, len(X) // 2)
                predictions_sets = []
                
                for _ in range(n_samples):
                    indices = np.random.choice(len(X), size=subset_size, replace=False)
                    X_subset = X[indices]
                    
                    try:
                        if hasattr(model, 'predict_proba'):
                            pred = model.predict_proba(X_subset)[:, 1] if pred.ndim > 1 else model.predict_proba(X_subset)
                        else:
                            pred = model.predict(X_subset)
                        predictions_sets.append(pred)
                    except:
                        pred = model.predict(X_subset)
                        predictions_sets.append(pred)
                
                # Calculate prediction stability
                if predictions_sets:
                    pred_std = np.std([np.mean(pred_set) for pred_set in predictions_sets])
                    behavior_analysis["stability"]["prediction_std"] = float(pred_std)
                    behavior_analysis["stability"]["consistency_score"] = float(1.0 / (1.0 + pred_std))
            
        except Exception as e:
            logger.error(f"Error analyzing model behavior: {e}")
        
        return behavior_analysis
    
    async def _analyze_decision_boundaries(self, model: Any, X: np.ndarray,
                                         feature_names: List[str]) -> Dict[str, Any]:
        """Analyze model decision boundaries."""
        
        boundaries = {}
        
        try:
            # Use dimensionality reduction for visualization
            if X.shape[1] > 2:
                # PCA for linear projection
                pca = PCA(n_components=2)
                X_pca = pca.fit_transform(X)
                boundaries["pca_components"] = pca.components_.tolist()
                boundaries["pca_explained_variance"] = pca.explained_variance_ratio_.tolist()
                
                # TSNE for non-linear projection  
                if len(X) > 50:  # TSNE needs sufficient samples
                    tsne = TSNE(n_components=2, random_state=42, n_iter=300)
                    sample_size = min(1000, len(X))
                    sample_indices = np.random.choice(len(X), size=sample_size, replace=False)
                    X_tsne = tsne.fit_transform(X[sample_indices])
                    boundaries["tsne_embedding"] = X_tsne.tolist()
                    boundaries["tsne_sample_indices"] = sample_indices.tolist()
            
            # Decision boundary complexity measure
            if hasattr(model, 'predict'):
                # Sample points in feature space
                n_boundary_samples = 1000
                feature_mins = X.min(axis=0)
                feature_maxs = X.max(axis=0)
                
                # Generate random points in feature space
                random_points = np.random.uniform(
                    feature_mins, feature_maxs, 
                    size=(n_boundary_samples, X.shape[1])
                )
                
                try:
                    predictions = model.predict(random_points)
                    
                    # Calculate boundary complexity (approximation)
                    if len(np.unique(predictions)) > 1:
                        # Count prediction changes in sorted order
                        sorted_indices = np.argsort(random_points[:, 0])  # Sort by first feature
                        sorted_predictions = predictions[sorted_indices]
                        
                        boundary_changes = np.sum(np.diff(sorted_predictions) != 0)
                        boundaries["boundary_complexity"] = float(boundary_changes / len(predictions))
                    else:
                        boundaries["boundary_complexity"] = 0.0
                        
                except Exception as e:
                    logger.warning(f"Could not analyze decision boundary: {e}")
                    boundaries["boundary_complexity"] = None
            
        except Exception as e:
            logger.error(f"Error analyzing decision boundaries: {e}")
        
        return boundaries
    
    async def _generate_lime_explanations(self, model: Any, X_sample: np.ndarray,
                                        feature_names: List[str]) -> List[Dict[str, Any]]:
        """Generate LIME explanations for sample points."""
        
        explanations = []
        
        try:
            # Initialize LIME explainer if not cached
            cache_key = f"lime_{model.__class__.__name__}"
            
            if cache_key not in self.explainers_cache:
                explainer = lime.lime_tabular.LimeTabularExplainer(
                    X_sample,
                    feature_names=feature_names,
                    class_names=['Normal', 'Anomaly'],
                    mode='classification',
                    discretize_continuous=True,
                    random_state=42
                )
                self.explainers_cache[cache_key] = explainer
            else:
                explainer = self.explainers_cache[cache_key]
            
            # Create prediction function
            def predict_fn(X):
                try:
                    if hasattr(model, 'predict_proba'):
                        probs = model.predict_proba(X)
                        return probs
                    else:
                        preds = model.predict(X)
                        # Convert to probability-like format
                        return np.column_stack([1 - preds, preds])
                except:
                    preds = model.predict(X)
                    return np.column_stack([1 - preds, preds])
            
            # Generate explanations for samples
            sample_size = min(50, len(X_sample))  # Limit for performance
            for i in range(sample_size):
                try:
                    explanation = explainer.explain_instance(
                        X_sample[i], 
                        predict_fn,
                        num_features=min(10, len(feature_names))
                    )
                    
                    explanations.append({
                        'sample_index': i,
                        'method': 'lime',
                        'features': dict(explanation.as_list()),
                        'score': explanation.score,
                        'intercept': getattr(explanation, 'intercept', 0.0),
                        'local_prediction': explanation.local_pred
                    })
                    
                except Exception as e:
                    logger.warning(f"LIME explanation failed for sample {i}: {e}")
                    
        except Exception as e:
            logger.error(f"Error generating LIME explanations: {e}")
        
        return explanations
    
    async def _generate_shap_explanations(self, model: Any, X_sample: np.ndarray,
                                        feature_names: List[str]) -> List[Dict[str, Any]]:
        """Generate SHAP explanations for sample points."""
        
        explanations = []
        
        try:
            cache_key = f"shap_{model.__class__.__name__}"
            
            if cache_key not in self.explainers_cache:
                # Choose appropriate SHAP explainer
                if hasattr(model, 'tree_'):
                    # Tree explainer for tree-based models
                    explainer = shap.TreeExplainer(model)
                else:
                    # Kernel explainer for other models
                    background_size = min(100, len(X_sample))
                    background = shap.sample(X_sample, background_size)
                    explainer = shap.KernelExplainer(
                        lambda x: model.predict(x), 
                        background
                    )
                
                self.explainers_cache[cache_key] = explainer
            else:
                explainer = self.explainers_cache[cache_key]
            
            # Generate SHAP values for samples
            sample_size = min(50, len(X_sample))
            X_explain = X_sample[:sample_size]
            
            shap_values = explainer.shap_values(X_explain)
            
            # Handle different SHAP value formats
            if isinstance(shap_values, list):
                shap_values = shap_values[1]  # Take positive class for binary classification
            
            for i in range(len(X_explain)):
                feature_shap = {}
                for j, feature_name in enumerate(feature_names):
                    if j < len(shap_values[i]):
                        feature_shap[feature_name] = float(shap_values[i][j])
                
                explanations.append({
                    'sample_index': i,
                    'method': 'shap',
                    'features': feature_shap,
                    'base_value': float(explainer.expected_value) if hasattr(explainer, 'expected_value') else 0.0
                })
                
        except Exception as e:
            logger.error(f"Error generating SHAP explanations: {e}")
        
        return explanations
    
    async def _generate_counterfactuals(self, model: Any, X_sample: np.ndarray,
                                      feature_names: List[str]) -> List[Dict[str, Any]]:
        """Generate counterfactual explanations."""
        
        counterfactuals = []
        
        try:
            # Simple counterfactual generation by feature perturbation
            sample_size = min(20, len(X_sample))
            
            for i in range(sample_size):
                sample = X_sample[i].copy()
                original_pred = model.predict([sample])[0]
                
                sample_counterfactuals = []
                
                # Try perturbing each feature
                for j, feature_name in enumerate(feature_names[:10]):  # Limit features
                    # Try different perturbation magnitudes
                    for magnitude in [0.1, 0.5, 1.0, 2.0]:
                        for direction in [-1, 1]:
                            perturbed_sample = sample.copy()
                            
                            # Calculate perturbation
                            feature_std = np.std(X_sample[:, j])
                            perturbation = direction * magnitude * feature_std
                            perturbed_sample[j] += perturbation
                            
                            try:
                                new_pred = model.predict([perturbed_sample])[0]
                                
                                # Check if prediction changed
                                if new_pred != original_pred:
                                    sample_counterfactuals.append({
                                        'feature': feature_name,
                                        'original_value': float(sample[j]),
                                        'counterfactual_value': float(perturbed_sample[j]),
                                        'change': float(perturbation),
                                        'original_prediction': int(original_pred),
                                        'counterfactual_prediction': int(new_pred)
                                    })
                                    
                                    # Stop after finding one counterfactual per feature
                                    break
                                    
                            except Exception as e:
                                continue
                
                if sample_counterfactuals:
                    counterfactuals.append({
                        'sample_index': i,
                        'counterfactuals': sample_counterfactuals
                    })
                    
        except Exception as e:
            logger.error(f"Error generating counterfactuals: {e}")
        
        return counterfactuals
    
    async def _find_prototypes(self, model: Any, X: np.ndarray,
                             feature_names: List[str]) -> List[Dict[str, Any]]:
        """Find prototype examples for each class."""
        
        prototypes = []
        
        try:
            # Get predictions for all data
            predictions = model.predict(X)
            unique_classes = np.unique(predictions)
            
            for class_label in unique_classes:
                class_indices = np.where(predictions == class_label)[0]
                class_data = X[class_indices]
                
                if len(class_data) > 0:
                    # Find prototypes using k-means clustering
                    n_prototypes = min(5, len(class_data))
                    
                    if len(class_data) >= n_prototypes:
                        kmeans = KMeans(n_clusters=n_prototypes, random_state=42, n_init=10)
                        kmeans.fit(class_data)
                        
                        # Find closest points to centroids
                        for i, centroid in enumerate(kmeans.cluster_centers_):
                            distances = np.linalg.norm(class_data - centroid, axis=1)
                            closest_idx = np.argmin(distances)
                            global_idx = class_indices[closest_idx]
                            
                            prototypes.append({
                                'class': int(class_label),
                                'prototype_id': i,
                                'global_index': int(global_idx),
                                'features': {
                                    feature_names[j]: float(X[global_idx, j])
                                    for j in range(min(len(feature_names), X.shape[1]))
                                },
                                'distance_to_centroid': float(distances[closest_idx]),
                                'representativeness': float(1.0 / (1.0 + distances[closest_idx]))
                            })
                    else:
                        # If too few samples, use all as prototypes
                        for j, idx in enumerate(class_indices):
                            prototypes.append({
                                'class': int(class_label),
                                'prototype_id': j,
                                'global_index': int(idx),
                                'features': {
                                    feature_names[k]: float(X[idx, k])
                                    for k in range(min(len(feature_names), X.shape[1]))
                                },
                                'distance_to_centroid': 0.0,
                                'representativeness': 1.0
                            })
                            
        except Exception as e:
            logger.error(f"Error finding prototypes: {e}")
        
        return prototypes
    
    async def _generate_visualizations(self, result: InterpretabilityResult,
                                     X: np.ndarray, feature_names: List[str]) -> List[str]:
        """Generate visualization plots for interpretability results."""
        
        visualization_paths = []
        
        try:
            plt.style.use(self.plot_configs["style"])
            
            # 1. Feature importance plot
            if result.feature_importance:
                fig, ax = plt.subplots(figsize=self.plot_configs["figure_size"])
                
                sorted_features = sorted(result.feature_importance.items(), 
                                       key=lambda x: x[1], reverse=True)[:15]
                features, importances = zip(*sorted_features)
                
                ax.barh(range(len(features)), importances)
                ax.set_yticks(range(len(features)))
                ax.set_yticklabels(features)
                ax.set_xlabel('Importance Score')
                ax.set_title(f'Feature Importance - {result.model_name}')
                
                path = Path(self.config.output_dir) / f"{result.model_name}_feature_importance.{self.config.plot_format}"
                plt.savefig(path, dpi=self.plot_configs["dpi"], bbox_inches='tight')
                plt.close()
                visualization_paths.append(str(path))
            
            # 2. Feature interactions heatmap
            if result.feature_interactions:
                fig, ax = plt.subplots(figsize=self.plot_configs["figure_size"])
                
                # Create interaction matrix
                features = list(result.feature_interactions.keys())
                interaction_matrix = np.zeros((len(features), len(features)))
                
                for i, f1 in enumerate(features):
                    for j, f2 in enumerate(features):
                        if f2 in result.feature_interactions[f1]:
                            interaction_matrix[i, j] = result.feature_interactions[f1][f2]
                
                sns.heatmap(interaction_matrix, 
                           xticklabels=features, 
                           yticklabels=features,
                           annot=True, 
                           cmap='coolwarm',
                           ax=ax)
                ax.set_title(f'Feature Interactions - {result.model_name}')
                
                path = Path(self.config.output_dir) / f"{result.model_name}_interactions.{self.config.plot_format}"
                plt.savefig(path, dpi=self.plot_configs["dpi"], bbox_inches='tight')
                plt.close()
                visualization_paths.append(str(path))
            
            # 3. Partial dependence plots
            if result.partial_dependence:
                n_features = min(6, len(result.partial_dependence))
                fig, axes = plt.subplots(2, 3, figsize=(15, 10))
                axes = axes.flatten()
                
                for i, (feature, pd_data) in enumerate(list(result.partial_dependence.items())[:n_features]):
                    if 'values' in pd_data and 'grid_values' in pd_data:
                        axes[i].plot(pd_data['grid_values'], pd_data['values'])
                        axes[i].set_xlabel(feature)
                        axes[i].set_ylabel('Partial Dependence')
                        axes[i].set_title(f'PD: {feature}')
                        axes[i].grid(True, alpha=0.3)
                
                # Hide unused subplots
                for i in range(n_features, len(axes)):
                    axes[i].set_visible(False)
                
                plt.suptitle(f'Partial Dependence Plots - {result.model_name}')
                plt.tight_layout()
                
                path = Path(self.config.output_dir) / f"{result.model_name}_partial_dependence.{self.config.plot_format}"
                plt.savefig(path, dpi=self.plot_configs["dpi"], bbox_inches='tight')
                plt.close()
                visualization_paths.append(str(path))
            
            # 4. Decision boundary visualization (if 2D projection available)
            if 'pca_components' in result.decision_boundaries and X.shape[1] > 1:
                fig, ax = plt.subplots(figsize=self.plot_configs["figure_size"])
                
                # Project data to 2D
                pca_components = np.array(result.decision_boundaries['pca_components'])
                X_2d = X @ pca_components.T
                
                # Get predictions
                try:
                    predictions = model.predict(X)
                    scatter = ax.scatter(X_2d[:, 0], X_2d[:, 1], c=predictions, 
                                       alpha=0.6, cmap='viridis')
                    plt.colorbar(scatter)
                    ax.set_xlabel('First Principal Component')
                    ax.set_ylabel('Second Principal Component') 
                    ax.set_title(f'Decision Boundary Visualization - {result.model_name}')
                    
                    path = Path(self.config.output_dir) / f"{result.model_name}_decision_boundary.{self.config.plot_format}"
                    plt.savefig(path, dpi=self.plot_configs["dpi"], bbox_inches='tight')
                    plt.close()
                    visualization_paths.append(str(path))
                    
                except Exception as e:
                    plt.close()
                    logger.warning(f"Could not create decision boundary plot: {e}")
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
        
        return visualization_paths
    
    def _calculate_confidence_scores(self, result: InterpretabilityResult) -> Dict[str, float]:
        """Calculate confidence scores for different interpretability analyses."""
        
        confidence_scores = {}
        
        try:
            # Feature importance confidence
            if result.feature_importance:
                # Based on number of features and variance in importance
                importance_values = list(result.feature_importance.values())
                if importance_values:
                    importance_std = np.std(importance_values)
                    importance_mean = np.mean(importance_values)
                    
                    # Higher variance relative to mean indicates lower confidence
                    if importance_mean > 0:
                        confidence_scores['feature_importance'] = min(1.0, importance_mean / (importance_std + 1e-6))
                    else:
                        confidence_scores['feature_importance'] = 0.1
            
            # Local explanations confidence
            if result.local_explanations:
                # Based on consistency across local explanations
                feature_scores = {}
                for explanation in result.local_explanations:
                    for feature, score in explanation.get('features', {}).items():
                        if feature not in feature_scores:
                            feature_scores[feature] = []
                        feature_scores[feature].append(abs(score))
                
                if feature_scores:
                    consistency_scores = []
                    for feature, scores in feature_scores.items():
                        if len(scores) > 1:
                            consistency = 1.0 - (np.std(scores) / (np.mean(scores) + 1e-6))
                            consistency_scores.append(max(0, consistency))
                    
                    if consistency_scores:
                        confidence_scores['local_explanations'] = np.mean(consistency_scores)
            
            # Model complexity confidence
            if result.model_complexity:
                # Simpler models generally have more interpretable results
                complexity_indicators = []
                
                if 'tree_depth' in result.model_complexity:
                    # Normalize tree depth (lower is better for interpretability)
                    depth = result.model_complexity['tree_depth']
                    complexity_indicators.append(max(0, 1.0 - depth / 20.0))  # Assume max reasonable depth of 20
                
                if 'n_parameters' in result.model_complexity:
                    # Normalize parameter count (lower is better)
                    n_params = result.model_complexity['n_parameters']
                    complexity_indicators.append(max(0, 1.0 - np.log10(n_params + 1) / 10.0))
                
                if complexity_indicators:
                    confidence_scores['model_complexity'] = np.mean(complexity_indicators)
            
            # Stability confidence
            if result.stability_analysis:
                if 'consistency_score' in result.stability_analysis:
                    confidence_scores['stability'] = result.stability_analysis['consistency_score']
            
            # Overall confidence
            if confidence_scores:
                confidence_scores['overall'] = np.mean(list(confidence_scores.values()))
            else:
                confidence_scores['overall'] = 0.5  # Default moderate confidence
            
        except Exception as e:
            logger.error(f"Error calculating confidence scores: {e}")
            confidence_scores = {'overall': 0.1}
        
        return confidence_scores
    
    def generate_interpretability_report(self, result: InterpretabilityResult) -> str:
        """Generate a comprehensive interpretability report."""
        
        report = f"""
# Model Interpretability Report: {result.model_name}

**Generated:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
**Analysis Duration:** {result.computation_time:.2f} seconds
**Data Size:** {result.data_size} samples

## Overall Confidence Score: {result.confidence_scores.get('overall', 0.0):.2f}

---

## Global Interpretability

### Feature Importance
"""
        
        if result.feature_importance:
            sorted_features = sorted(result.feature_importance.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
            
            report += "\n**Top 10 Most Important Features:**\n"
            for i, (feature, importance) in enumerate(sorted_features, 1):
                report += f"{i}. {feature}: {importance:.4f}\n"
        else:
            report += "\nNo feature importance data available.\n"
        
        report += f"""
### Model Complexity Analysis
"""
        
        if result.model_complexity:
            report += "\n**Complexity Metrics:**\n"
            for metric, value in result.model_complexity.items():
                report += f"- {metric}: {value}\n"
        
        if result.stability_analysis:
            report += "\n**Stability Metrics:**\n"
            for metric, value in result.stability_analysis.items():
                report += f"- {metric}: {value:.4f}\n"
        
        report += """
---

## Local Interpretability
"""
        
        if result.local_explanations:
            report += f"\n**Generated {len(result.local_explanations)} local explanations**\n"
            
            # Show example explanations
            for i, explanation in enumerate(result.local_explanations[:3]):
                report += f"\n### Example {i+1} ({explanation.get('method', 'unknown')} method):\n"
                features = explanation.get('features', {})
                sorted_local_features = sorted(features.items(), 
                                             key=lambda x: abs(x[1]), reverse=True)[:5]
                for feature, score in sorted_local_features:
                    report += f"- {feature}: {score:.4f}\n"
        
        if result.counterfactuals:
            report += f"\n**Counterfactual Explanations:** {len(result.counterfactuals)} samples analyzed\n"
            
        if result.prototypes:
            report += f"\n**Prototype Examples:** {len(result.prototypes)} prototypes identified\n"
        
        report += """
---

## Visualizations
"""
        
        if result.visualization_paths:
            report += "\n**Generated Visualizations:**\n"
            for path in result.visualization_paths:
                report += f"- {Path(path).name}\n"
        else:
            report += "\nNo visualizations generated.\n"
        
        report += f"""
---

## Confidence Assessment

{self._generate_confidence_assessment(result.confidence_scores)}

## Recommendations

{self._generate_recommendations(result)}
"""
        
        return report
    
    def _generate_confidence_assessment(self, confidence_scores: Dict[str, float]) -> str:
        """Generate confidence assessment text."""
        
        assessment = ""
        
        overall_confidence = confidence_scores.get('overall', 0.0)
        
        if overall_confidence >= 0.8:
            assessment = "**HIGH CONFIDENCE**: The interpretability analysis provides reliable insights with consistent results across multiple methods."
        elif overall_confidence >= 0.6:
            assessment = "**MODERATE CONFIDENCE**: The analysis provides useful insights, but some results may vary. Consider additional validation."
        elif overall_confidence >= 0.4:
            assessment = "**LOW CONFIDENCE**: The interpretability results show high variance or inconsistency. Use with caution and seek additional evidence."
        else:
            assessment = "**VERY LOW CONFIDENCE**: The analysis results are highly uncertain. Consider improving data quality or model stability."
        
        assessment += "\n\n**Detailed Confidence Breakdown:**\n"
        for metric, score in confidence_scores.items():
            if metric != 'overall':
                assessment += f"- {metric.replace('_', ' ').title()}: {score:.2f}\n"
        
        return assessment
    
    def _generate_recommendations(self, result: InterpretabilityResult) -> str:
        """Generate actionable recommendations based on interpretability analysis."""
        
        recommendations = []
        
        # Feature importance recommendations
        if result.feature_importance:
            top_features = sorted(result.feature_importance.items(), 
                                key=lambda x: x[1], reverse=True)[:5]
            if top_features:
                recommendations.append(
                    f"Focus monitoring and quality checks on top features: {', '.join([f[0] for f in top_features[:3]])}"
                )
        
        # Model complexity recommendations
        if result.model_complexity:
            if 'tree_depth' in result.model_complexity and result.model_complexity['tree_depth'] > 15:
                recommendations.append("Consider pruning the decision tree to improve interpretability")
            
            if 'n_parameters' in result.model_complexity and result.model_complexity['n_parameters'] > 1000000:
                recommendations.append("Consider model compression or distillation to improve interpretability")
        
        # Stability recommendations
        if result.stability_analysis:
            consistency = result.stability_analysis.get('consistency_score', 1.0)
            if consistency < 0.7:
                recommendations.append("Model predictions show low stability. Consider ensemble methods or more robust training")
        
        # Confidence-based recommendations
        overall_confidence = result.confidence_scores.get('overall', 0.0)
        if overall_confidence < 0.6:
            recommendations.append("Low interpretability confidence suggests need for additional validation and simpler models")
        
        # Default recommendations
        if not recommendations:
            recommendations = [
                "Continue monitoring model performance and interpretability",
                "Regularly validate explanations with domain experts",
                "Consider A/B testing for model updates"
            ]
        
        return "\n".join(f"- {rec}" for rec in recommendations)

# Example usage and testing
async def main():
    """Example usage of the Advanced Interpretability Framework."""
    
    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 15
    
    # Generate synthetic IoT sensor data
    X = np.random.normal(0, 1, (n_samples, n_features))
    
    # Add some pattern for anomaly detection
    # Normal data: features correlated
    normal_indices = np.random.choice(n_samples, size=int(0.8 * n_samples), replace=False)
    X[normal_indices, 1] = X[normal_indices, 0] + np.random.normal(0, 0.1, len(normal_indices))
    X[normal_indices, 2] = X[normal_indices, 0] * 0.5 + np.random.normal(0, 0.2, len(normal_indices))
    
    # Anomalies: break correlations
    anomaly_indices = np.setdiff1d(np.arange(n_samples), normal_indices)
    X[anomaly_indices] = np.random.normal(3, 2, (len(anomaly_indices), n_features))
    
    # Create labels
    y = np.zeros(n_samples)
    y[anomaly_indices] = 1
    
    # Feature names
    feature_names = [
        'temperature', 'pressure', 'vibration', 'current', 'voltage',
        'frequency', 'power', 'flow_rate', 'humidity', 'rpm',
        'temp_gradient', 'pressure_change', 'vibration_rms', 
        'power_factor', 'efficiency'
    ]
    
    print("Training models for interpretability analysis...")
    
    # Train different types of models
    models = {}
    
    # Random Forest
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf.fit(X, y)
    models['RandomForest'] = rf
    
    # Decision Tree
    dt = DecisionTreeClassifier(max_depth=8, random_state=42)
    dt.fit(X, y)
    models['DecisionTree'] = dt
    
    # Logistic Regression
    lr = LogisticRegression(random_state=42)
    lr.fit(X, y)
    models['LogisticRegression'] = lr
    
    print("Initializing interpretability framework...")
    
    # Initialize interpretability framework
    config = InterpretabilityConfig(
        global_methods=['feature_importance', 'partial_dependence', 'model_behavior_analysis'],
        local_methods=['lime', 'shap', 'counterfactual'],
        generate_plots=True,
        max_features_analyze=n_features
    )
    
    framework = AdvancedInterpretabilityFramework(config)
    
    # Analyze each model
    results = {}
    for model_name, model in models.items():
        print(f"\nAnalyzing interpretability for {model_name}...")
        
        result = await framework.analyze_model_interpretability(
            model, model_name, X, y, feature_names
        )
        
        results[model_name] = result
        
        # Generate and save report
        report = framework.generate_interpretability_report(result)
        report_path = Path(config.output_dir) / f"{model_name}_interpretability_report.md"
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"Report saved: {report_path}")
        print(f"Analysis completed in {result.computation_time:.2f}s")
        print(f"Overall confidence: {result.confidence_scores.get('overall', 0):.2f}")
        
        # Show top features
        if result.feature_importance:
            top_features = sorted(result.feature_importance.items(), 
                                key=lambda x: x[1], reverse=True)[:5]
            print("Top 5 features:")
            for feature, importance in top_features:
                print(f"  {feature}: {importance:.4f}")
    
    # Compare models
    print(f"\n=== Model Interpretability Comparison ===")
    print("Model\t\tConfidence\tComplexity\tStability")
    print("-" * 50)
    
    for model_name, result in results.items():
        confidence = result.confidence_scores.get('overall', 0)
        complexity = result.model_complexity.get('tree_depth', 'N/A')
        stability = result.stability_analysis.get('consistency_score', 'N/A')
        
        print(f"{model_name:12}\t{confidence:.2f}\t\t{complexity}\t\t{stability}")
    
    print(f"\nInterpretability analysis completed!")
    print(f"Visualizations and reports saved in: {config.output_dir}")

if __name__ == "__main__":
    asyncio.run(main())