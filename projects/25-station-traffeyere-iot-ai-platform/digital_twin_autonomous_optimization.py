#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 5E: Système d'Optimisation Autonome du Jumeau Numérique

Système d'optimisation autonome utilisant des algorithmes génétiques, 
l'apprentissage par renforcement et l'optimisation multi-objectifs pour 
l'amélioration continue et automatique des performances industrielles.

Auteur: Spécialiste Sécurité IoT Industriel
Date: 2024
"""

import os
import json
import asyncio
import logging
import time
import threading
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field, asdict
import numpy as np
import pandas as pd
from pathlib import Path
import uuid
from collections import deque, defaultdict
import math
import random
import copy

# Algorithmes génétiques et optimisation
import pygad
from deap import base, creator, tools, algorithms
from scipy.optimize import minimize, differential_evolution, dual_annealing
import optuna
from hyperopt import hp, fmin, tpe, Trials

# Apprentissage par renforcement
import gymnasium as gym
from gymnasium import spaces
import stable_baselines3 as sb3
from stable_baselines3 import PPO, A2C, DQN, SAC
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

# Machine Learning et optimisation Bayésienne
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import RBF, Matern
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

# Optimisation multi-objectifs
from pymoo.algorithms.moo.nsga2 import NSGA2
from pymoo.algorithms.moo.nsga3 import NSGA3
from pymoo.core.problem import Problem
from pymoo.optimize import minimize as pymoo_minimize
from pymoo.core.callback import Callback

# Utilitaires
import warnings
warnings.filterwarnings('ignore')

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class OptimizationObjective:
    """Objectif d'optimisation."""
    name: str
    type: str  # maximize, minimize
    weight: float
    target_value: Optional[float] = None
    current_value: float = 0.0
    bounds: Tuple[float, float] = (0.0, 100.0)
    priority: str = "normal"  # low, normal, high, critical

@dataclass
class OptimizationConstraint:
    """Contrainte d'optimisation."""
    name: str
    type: str  # equality, inequality, bounds
    function: Callable
    bounds: Tuple[float, float]
    violation_penalty: float = 100.0
    is_active: bool = True

@dataclass
class OptimizationResult:
    """Résultat d'optimisation."""
    algorithm: str
    timestamp: datetime
    parameters: Dict[str, float]
    objectives: Dict[str, float]
    constraints_satisfied: bool
    fitness_score: float
    generation: int = 0
    evaluation_time: float = 0.0
    convergence_info: Dict[str, Any] = field(default_factory=dict)

class IndustrialProcessEnvironment(gym.Env):
    """Environnement RL pour optimisation des processus industriels."""
    
    def __init__(self, process_config: Dict[str, Any]):
        super().__init__()
        
        self.process_config = process_config
        self.equipment_params = process_config.get('equipment_parameters', {})
        self.operational_constraints = process_config.get('constraints', {})
        
        # Espace d'actions (paramètres à optimiser)
        self.param_bounds = {}
        for param_name, bounds in self.equipment_params.items():
            self.param_bounds[param_name] = bounds
        
        # Actions continues (normalisées entre -1 et 1)
        n_params = len(self.equipment_params)
        self.action_space = spaces.Box(low=-1.0, high=1.0, shape=(n_params,), dtype=np.float32)
        
        # Espace d'observations (état du système)
        # [paramètres actuels, performances, contraintes, temps]
        obs_size = n_params * 2 + 10  # params + perfs + contraintes + meta
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(obs_size,), dtype=np.float32)
        
        # État du système
        self.current_params = {}
        self.performance_history = deque(maxlen=100)
        self.constraint_violations = []
        self.step_count = 0
        self.episode_length = 1000  # Nombre maximum d'étapes par épisode
        
        # Métriques de performance
        self.efficiency = 0.0
        self.energy_consumption = 0.0
        self.maintenance_cost = 0.0
        self.quality_index = 0.0
        self.safety_score = 0.0
        
        self.reset()
    
    def reset(self, seed=None, options=None):
        """Réinitialise l'environnement."""
        super().reset(seed=seed)
        
        # Initialisation aléatoire des paramètres dans les bornes
        self.current_params = {}
        for param_name, (min_val, max_val) in self.param_bounds.items():
            self.current_params[param_name] = np.random.uniform(min_val, max_val)
        
        self.performance_history.clear()
        self.constraint_violations.clear()
        self.step_count = 0
        
        # Calcul de l'état initial
        self._update_performance_metrics()
        observation = self._get_observation()
        
        return observation, {}
    
    def step(self, action):
        """Exécute une action et retourne le nouvel état."""
        self.step_count += 1
        
        # Conversion des actions normalisées en changements de paramètres
        param_changes = self._denormalize_actions(action)
        
        # Application des changements avec contraintes
        for i, (param_name, change) in enumerate(zip(self.param_bounds.keys(), param_changes)):
            min_val, max_val = self.param_bounds[param_name]
            new_value = self.current_params[param_name] + change
            self.current_params[param_name] = np.clip(new_value, min_val, max_val)
        
        # Simulation des effets sur les performances
        self._update_performance_metrics()
        
        # Calcul de la récompense
        reward = self._calculate_reward()
        
        # Vérification des conditions de terminaison
        terminated = self._check_termination_conditions()
        truncated = self.step_count >= self.episode_length
        
        # Nouvel état
        observation = self._get_observation()
        
        # Informations additionnelles
        info = {
            'efficiency': self.efficiency,
            'energy_consumption': self.energy_consumption,
            'maintenance_cost': self.maintenance_cost,
            'constraint_violations': len(self.constraint_violations),
            'step_count': self.step_count
        }
        
        return observation, reward, terminated, truncated, info
    
    def _denormalize_actions(self, actions: np.ndarray) -> np.ndarray:
        """Convertit les actions normalisées en changements de paramètres."""
        max_changes = []
        
        for param_name in self.param_bounds.keys():
            min_val, max_val = self.param_bounds[param_name]
            max_change = (max_val - min_val) * 0.05  # Maximum 5% de changement par step
            max_changes.append(max_change)
        
        return actions * np.array(max_changes)
    
    def _update_performance_metrics(self):
        """Met à jour les métriques de performance basées sur les paramètres actuels."""
        # Simulation réaliste des performances industrielles
        
        # Efficacité (fonction complexe des paramètres)
        speed = self.current_params.get('speed', 1500)
        temperature = self.current_params.get('temperature', 70)
        pressure = self.current_params.get('pressure', 5)
        
        # Modèle d'efficacité non-linéaire
        optimal_speed = 1800
        optimal_temp = 75
        optimal_pressure = 6
        
        speed_eff = 1 - (abs(speed - optimal_speed) / optimal_speed) ** 2
        temp_eff = 1 - (abs(temperature - optimal_temp) / optimal_temp) ** 1.5
        pressure_eff = 1 - (abs(pressure - optimal_pressure) / optimal_pressure) ** 2
        
        self.efficiency = max(0, speed_eff * temp_eff * pressure_eff * 100)
        
        # Consommation d'énergie
        base_consumption = 10  # kW
        speed_factor = (speed / 1500) ** 2.5
        temp_factor = 1 + max(0, (temperature - 60) / 40) * 0.5
        self.energy_consumption = base_consumption * speed_factor * temp_factor
        
        # Coût de maintenance (augmente avec l'usure)
        wear_factor = ((speed / 1800) ** 2 + (temperature / 100) ** 1.5) / 2
        self.maintenance_cost = 1000 * (1 + wear_factor)
        
        # Indice qualité
        stability = 1 / (1 + np.std(list(self.performance_history)[-10:]) if len(self.performance_history) > 10 else 1)
        self.quality_index = self.efficiency * stability
        
        # Score sécurité (diminue avec les paramètres extrêmes)
        safety_factors = []
        for param_name, value in self.current_params.items():
            min_val, max_val = self.param_bounds[param_name]
            normalized = (value - min_val) / (max_val - min_val)
            # Pénalité pour valeurs extrêmes
            safety_factor = 1 - 4 * (normalized - 0.5) ** 2
            safety_factors.append(max(0, safety_factor))
        
        self.safety_score = np.mean(safety_factors) * 100
        
        # Vérification des contraintes
        self._check_constraints()
        
        # Ajout à l'historique
        performance = {
            'efficiency': self.efficiency,
            'energy': self.energy_consumption,
            'maintenance': self.maintenance_cost,
            'quality': self.quality_index,
            'safety': self.safety_score
        }
        self.performance_history.append(performance)
    
    def _check_constraints(self):
        """Vérifie les contraintes opérationnelles."""
        self.constraint_violations.clear()
        
        # Contrainte de température maximale
        if self.current_params.get('temperature', 0) > 90:
            self.constraint_violations.append('temperature_max')
        
        # Contrainte de pression
        if self.current_params.get('pressure', 0) > 8:
            self.constraint_violations.append('pressure_max')
        
        # Contrainte d'efficacité minimale
        if self.efficiency < 40:
            self.constraint_violations.append('efficiency_min')
        
        # Contrainte de sécurité
        if self.safety_score < 60:
            self.constraint_violations.append('safety_min')
    
    def _calculate_reward(self) -> float:
        """Calcule la récompense basée sur les objectifs multi-objectifs."""
        # Récompenses positives
        efficiency_reward = self.efficiency / 100.0  # 0-1
        energy_reward = max(0, (20 - self.energy_consumption) / 20)  # Économie d'énergie
        quality_reward = self.quality_index / 100.0
        safety_reward = self.safety_score / 100.0
        
        # Pénalités pour violations de contraintes
        constraint_penalty = len(self.constraint_violations) * 0.5
        
        # Récompense composite avec pondération
        reward = (
            0.3 * efficiency_reward +
            0.2 * energy_reward +
            0.2 * quality_reward +
            0.3 * safety_reward -
            constraint_penalty
        )
        
        # Bonus pour amélioration continue
        if len(self.performance_history) >= 2:
            current_perf = self.performance_history[-1]['efficiency']
            previous_perf = self.performance_history[-2]['efficiency']
            improvement_bonus = max(0, (current_perf - previous_perf) / 100)
            reward += improvement_bonus
        
        # Bonus de stabilité
        if len(self.performance_history) >= 10:
            recent_efficiencies = [p['efficiency'] for p in list(self.performance_history)[-10:]]
            stability = 1 / (1 + np.std(recent_efficiencies))
            reward += 0.1 * stability
        
        return float(reward)
    
    def _get_observation(self) -> np.ndarray:
        """Construit l'observation de l'état actuel."""
        obs = []
        
        # Paramètres actuels normalisés
        for param_name in self.param_bounds.keys():
            min_val, max_val = self.param_bounds[param_name]
            normalized = (self.current_params[param_name] - min_val) / (max_val - min_val)
            obs.append(normalized)
        
        # Gradients des paramètres (changements récents)
        if len(self.performance_history) >= 2:
            for param_name in self.param_bounds.keys():
                # Approximation du gradient (simplifiée)
                obs.append(0.0)  # Placeholder pour gradient
        else:
            obs.extend([0.0] * len(self.param_bounds))
        
        # Métriques de performance normalisées
        obs.extend([
            self.efficiency / 100.0,
            min(self.energy_consumption / 20, 1.0),
            min(self.maintenance_cost / 5000, 1.0),
            self.quality_index / 100.0,
            self.safety_score / 100.0
        ])
        
        # État des contraintes
        obs.extend([
            1.0 if 'temperature_max' in self.constraint_violations else 0.0,
            1.0 if 'pressure_max' in self.constraint_violations else 0.0,
            1.0 if 'efficiency_min' in self.constraint_violations else 0.0,
            1.0 if 'safety_min' in self.constraint_violations else 0.0
        ])
        
        # Métadonnées temporelles
        obs.append(self.step_count / self.episode_length)
        
        return np.array(obs, dtype=np.float32)
    
    def _check_termination_conditions(self) -> bool:
        """Vérifie si l'épisode doit se terminer prématurément."""
        # Conditions de sécurité critiques
        if self.safety_score < 30:
            return True
        
        # Défaillance critique
        if len(self.constraint_violations) >= 3:
            return True
        
        return False

class GeneticAlgorithmOptimizer:
    """Optimiseur basé sur algorithmes génétiques."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.population_size = config.get('population_size', 50)
        self.num_generations = config.get('num_generations', 100)
        self.crossover_rate = config.get('crossover_rate', 0.8)
        self.mutation_rate = config.get('mutation_rate', 0.1)
        
        # Historique des optimisations
        self.optimization_history = []
        self.best_solutions = []
        
    def define_fitness_function(self, objectives: List[OptimizationObjective],
                               constraints: List[OptimizationConstraint]) -> Callable:
        """Définit la fonction de fitness multi-objectifs."""
        
        def fitness_function(solution, sol_idx):
            """Évalue la fitness d'une solution."""
            try:
                # Conversion de la solution en paramètres
                parameters = self._solution_to_parameters(solution)
                
                # Calcul des objectifs
                objective_values = {}
                for obj in objectives:
                    value = self._evaluate_objective(obj, parameters)
                    objective_values[obj.name] = value
                
                # Vérification des contraintes
                constraint_violations = 0
                total_penalty = 0
                
                for constraint in constraints:
                    if constraint.is_active:
                        violation = self._check_constraint(constraint, parameters)
                        if violation > 0:
                            constraint_violations += 1
                            total_penalty += violation * constraint.violation_penalty
                
                # Calcul de la fitness composite
                fitness_score = 0
                for obj in objectives:
                    value = objective_values[obj.name]
                    normalized_value = self._normalize_objective_value(obj, value)
                    
                    if obj.type == 'maximize':
                        fitness_score += obj.weight * normalized_value
                    else:  # minimize
                        fitness_score += obj.weight * (1 - normalized_value)
                
                # Application des pénalités
                fitness_score -= total_penalty
                
                # Bonus pour solutions sans violations
                if constraint_violations == 0:
                    fitness_score += 10  # Bonus bonus
                
                return max(0, fitness_score)  # Fitness non-négative
                
            except Exception as e:
                logger.error(f"Erreur calcul fitness: {e}")
                return 0.0
        
        return fitness_function
    
    def optimize(self, objectives: List[OptimizationObjective],
                constraints: List[OptimizationConstraint],
                parameter_bounds: Dict[str, Tuple[float, float]]) -> OptimizationResult:
        """Lance l'optimisation génétique."""
        
        logger.info("Démarrage optimisation génétique")
        start_time = time.time()
        
        # Configuration PyGAD
        fitness_function = self.define_fitness_function(objectives, constraints)
        
        # Bornes des gènes
        gene_bounds = []
        param_names = list(parameter_bounds.keys())
        
        for param_name in param_names:
            min_val, max_val = parameter_bounds[param_name]
            gene_bounds.append({'low': min_val, 'high': max_val})
        
        # Instance PyGAD
        ga_instance = pygad.GA(
            num_generations=self.num_generations,
            num_parents_mating=self.population_size // 2,
            fitness_func=fitness_function,
            sol_per_pop=self.population_size,
            num_genes=len(param_names),
            gene_space=gene_bounds,
            parent_selection_type="sss",  # Steady-state selection
            keep_parents=2,
            crossover_type="single_point",
            mutation_type="random",
            mutation_percent_genes=int(self.mutation_rate * 100),
            callback_generation=self._generation_callback
        )
        
        # Exécution de l'optimisation
        ga_instance.run()
        
        # Meilleure solution
        solution, solution_fitness, _ = ga_instance.best_solution()
        best_parameters = self._solution_to_parameters(solution, param_names)
        
        # Évaluation finale des objectifs
        final_objectives = {}
        for obj in objectives:
            final_objectives[obj.name] = self._evaluate_objective(obj, best_parameters)
        
        # Vérification des contraintes
        constraints_satisfied = True
        for constraint in constraints:
            if constraint.is_active:
                violation = self._check_constraint(constraint, best_parameters)
                if violation > 0:
                    constraints_satisfied = False
                    break
        
        # Résultat
        result = OptimizationResult(
            algorithm="genetic_algorithm",
            timestamp=datetime.now(),
            parameters=best_parameters,
            objectives=final_objectives,
            constraints_satisfied=constraints_satisfied,
            fitness_score=float(solution_fitness),
            generation=self.num_generations,
            evaluation_time=time.time() - start_time,
            convergence_info={
                'final_fitness': float(solution_fitness),
                'population_diversity': self._calculate_diversity(ga_instance.population),
                'convergence_generation': self._find_convergence_generation()
            }
        )
        
        self.optimization_history.append(result)
        logger.info(f"Optimisation génétique terminée - Fitness: {solution_fitness:.3f}")
        
        return result
    
    def _solution_to_parameters(self, solution: np.ndarray, 
                               param_names: List[str] = None) -> Dict[str, float]:
        """Convertit une solution en dictionnaire de paramètres."""
        if param_names is None:
            param_names = [f'param_{i}' for i in range(len(solution))]
        
        return dict(zip(param_names, solution))
    
    def _evaluate_objective(self, objective: OptimizationObjective, 
                           parameters: Dict[str, float]) -> float:
        """Évalue un objectif pour les paramètres donnés."""
        # Simulation d'évaluation d'objectif
        # En pratique, ceci interfacerait avec le simulateur industriel
        
        if objective.name == 'efficiency':
            # Modèle d'efficacité simplifié
            speed = parameters.get('speed', 1500)
            temp = parameters.get('temperature', 70)
            optimal_speed, optimal_temp = 1800, 75
            
            speed_factor = 1 - abs(speed - optimal_speed) / optimal_speed
            temp_factor = 1 - abs(temp - optimal_temp) / optimal_temp
            
            return max(0, speed_factor * temp_factor * 100)
            
        elif objective.name == 'energy_consumption':
            speed = parameters.get('speed', 1500)
            load = parameters.get('load', 0.8)
            
            base_consumption = 10
            consumption = base_consumption * (speed / 1500) ** 2 * load ** 1.5
            return consumption
            
        elif objective.name == 'maintenance_cost':
            # Coût basé sur l'usure prédite
            wear_factors = []
            for param_name, value in parameters.items():
                if 'temperature' in param_name.lower():
                    wear_factors.append(max(0, (value - 60) / 40))
                elif 'speed' in param_name.lower():
                    wear_factors.append((value / 2000) ** 2)
            
            avg_wear = np.mean(wear_factors) if wear_factors else 0
            return 1000 * (1 + avg_wear * 2)
        
        else:
            # Objectif générique
            return np.random.uniform(objective.bounds[0], objective.bounds[1])
    
    def _check_constraint(self, constraint: OptimizationConstraint,
                         parameters: Dict[str, float]) -> float:
        """Vérifie une contrainte et retourne le niveau de violation."""
        try:
            if constraint.type == 'bounds':
                # Contrainte de bornes
                param_name = constraint.name.replace('_bounds', '')
                if param_name in parameters:
                    value = parameters[param_name]
                    min_val, max_val = constraint.bounds
                    
                    if value < min_val:
                        return min_val - value
                    elif value > max_val:
                        return value - max_val
                    else:
                        return 0.0
            
            elif constraint.type == 'inequality':
                # Contrainte d'inégalité générale
                result = constraint.function(parameters)
                return max(0, result)  # Violation positive
            
            elif constraint.type == 'equality':
                # Contrainte d'égalité
                result = constraint.function(parameters)
                return abs(result)  # Écart par rapport à zéro
            
        except Exception as e:
            logger.error(f"Erreur vérification contrainte {constraint.name}: {e}")
            return 100.0  # Pénalité élevée en cas d'erreur
        
        return 0.0
    
    def _normalize_objective_value(self, objective: OptimizationObjective, 
                                  value: float) -> float:
        """Normalise une valeur d'objectif entre 0 et 1."""
        min_val, max_val = objective.bounds
        
        if max_val == min_val:
            return 1.0
        
        normalized = (value - min_val) / (max_val - min_val)
        return np.clip(normalized, 0.0, 1.0)
    
    def _generation_callback(self, ga_instance):
        """Callback appelé à chaque génération."""
        generation = ga_instance.generations_completed
        
        if generation % 10 == 0:  # Log tous les 10 générations
            best_fitness = ga_instance.best_solution()[1]
            logger.info(f"Génération {generation}: Meilleure fitness = {best_fitness:.3f}")
    
    def _calculate_diversity(self, population: np.ndarray) -> float:
        """Calcule la diversité de la population."""
        if len(population) < 2:
            return 0.0
        
        # Calcul distance moyenne entre individus
        total_distance = 0
        count = 0
        
        for i in range(len(population)):
            for j in range(i + 1, len(population)):
                distance = np.linalg.norm(population[i] - population[j])
                total_distance += distance
                count += 1
        
        return total_distance / count if count > 0 else 0.0
    
    def _find_convergence_generation(self) -> int:
        """Trouve la génération de convergence approximative."""
        # Implémentation simplifiée
        # En pratique, analyserait l'historique de fitness
        return max(1, self.num_generations // 2)

class ReinforcementLearningOptimizer:
    """Optimiseur basé sur apprentissage par renforcement."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.algorithm = config.get('algorithm', 'PPO')  # PPO, A2C, SAC, DQN
        self.total_timesteps = config.get('total_timesteps', 100000)
        self.learning_rate = config.get('learning_rate', 3e-4)
        
        # Modèles et environnements
        self.env = None
        self.model = None
        self.training_history = []
        
        # Répertoire de sauvegarde
        self.save_dir = Path(config.get('save_dir', './rl_models'))
        self.save_dir.mkdir(exist_ok=True)
        
    def setup_environment(self, process_config: Dict[str, Any]) -> gym.Env:
        """Configure l'environnement d'optimisation."""
        # Création de l'environnement industriel
        env = IndustrialProcessEnvironment(process_config)
        
        # Monitoring pour la collecte de statistiques
        env = Monitor(env)
        
        self.env = env
        return env
    
    def create_model(self, env: gym.Env) -> Any:
        """Crée le modèle d'apprentissage par renforcement."""
        
        model_config = {
            'learning_rate': self.learning_rate,
            'verbose': 1,
            'tensorboard_log': str(self.save_dir / 'tensorboard')
        }
        
        if self.algorithm == 'PPO':
            model = PPO(
                'MlpPolicy',
                env,
                **model_config,
                n_steps=2048,
                batch_size=64,
                n_epochs=10,
                gamma=0.99,
                gae_lambda=0.95,
                clip_range=0.2
            )
        elif self.algorithm == 'A2C':
            model = A2C(
                'MlpPolicy',
                env,
                **model_config,
                n_steps=5,
                gamma=0.99,
                gae_lambda=1.0,
                ent_coef=0.01,
                vf_coef=0.25
            )
        elif self.algorithm == 'SAC':
            model = SAC(
                'MlpPolicy',
                env,
                **model_config,
                buffer_size=100000,
                batch_size=256,
                tau=0.005,
                gamma=0.99
            )
        else:
            raise ValueError(f"Algorithm non supporté: {self.algorithm}")
        
        self.model = model
        return model
    
    def train_model(self, callback_freq: int = 10000) -> Dict[str, Any]:
        """Entraîne le modèle RL."""
        if self.model is None or self.env is None:
            raise ValueError("Modèle et environnement doivent être configurés avant l'entraînement")
        
        logger.info(f"Démarrage entraînement RL avec {self.algorithm}")
        
        # Callback d'évaluation
        eval_callback = EvalCallback(
            self.env,
            best_model_save_path=str(self.save_dir),
            log_path=str(self.save_dir),
            eval_freq=callback_freq,
            deterministic=True,
            render=False
        )
        
        # Entraînement
        start_time = time.time()
        self.model.learn(
            total_timesteps=self.total_timesteps,
            callback=eval_callback
        )
        training_time = time.time() - start_time
        
        # Sauvegarde
        model_path = self.save_dir / f"best_model_{self.algorithm.lower()}"
        self.model.save(str(model_path))
        
        # Statistiques d'entraînement
        training_stats = {
            'algorithm': self.algorithm,
            'total_timesteps': self.total_timesteps,
            'training_time': training_time,
            'model_path': str(model_path),
            'final_mean_reward': self._get_final_reward()
        }
        
        self.training_history.append(training_stats)
        logger.info(f"Entraînement RL terminé - Temps: {training_time:.1f}s")
        
        return training_stats
    
    def optimize_process(self, optimization_steps: int = 1000) -> OptimizationResult:
        """Utilise le modèle entraîné pour optimiser le processus."""
        if self.model is None:
            raise ValueError("Modèle non entraîné")
        
        logger.info("Démarrage optimisation RL")
        start_time = time.time()
        
        # Réinitialisation de l'environnement
        obs, _ = self.env.reset()
        
        best_reward = float('-inf')
        best_params = None
        best_performance = None
        
        episode_rewards = []
        
        # Optimisation sur plusieurs épisodes
        for episode in range(optimization_steps):
            episode_reward = 0
            done = False
            
            while not done:
                # Prédiction de l'action
                action, _ = self.model.predict(obs, deterministic=True)
                
                # Exécution de l'action
                obs, reward, terminated, truncated, info = self.env.step(action)
                episode_reward += reward
                done = terminated or truncated
                
                # Mise à jour du meilleur résultat
                if reward > best_reward:
                    best_reward = reward
                    best_params = copy.deepcopy(self.env.current_params)
                    best_performance = {
                        'efficiency': info.get('efficiency', 0),
                        'energy_consumption': info.get('energy_consumption', 0),
                        'maintenance_cost': info.get('maintenance_cost', 0)
                    }
            
            episode_rewards.append(episode_reward)
            
            # Log périodique
            if episode % 100 == 0:
                avg_reward = np.mean(episode_rewards[-100:])
                logger.info(f"Épisode {episode}: Récompense moyenne = {avg_reward:.3f}")
            
            # Réinitialisation pour le prochain épisode
            obs, _ = self.env.reset()
        
        # Résultat final
        result = OptimizationResult(
            algorithm=f"RL_{self.algorithm}",
            timestamp=datetime.now(),
            parameters=best_params or {},
            objectives=best_performance or {},
            constraints_satisfied=True,  # Géré par l'environnement
            fitness_score=best_reward,
            evaluation_time=time.time() - start_time,
            convergence_info={
                'episodes_run': optimization_steps,
                'best_reward': best_reward,
                'mean_reward': np.mean(episode_rewards),
                'reward_std': np.std(episode_rewards)
            }
        )
        
        logger.info(f"Optimisation RL terminée - Meilleure récompense: {best_reward:.3f}")
        return result
    
    def load_pretrained_model(self, model_path: str) -> bool:
        """Charge un modèle pré-entraîné."""
        try:
            if self.algorithm == 'PPO':
                self.model = PPO.load(model_path)
            elif self.algorithm == 'A2C':
                self.model = A2C.load(model_path)
            elif self.algorithm == 'SAC':
                self.model = SAC.load(model_path)
            else:
                return False
            
            logger.info(f"Modèle chargé depuis {model_path}")
            return True
        except Exception as e:
            logger.error(f"Erreur chargement modèle: {e}")
            return False
    
    def _get_final_reward(self) -> float:
        """Récupère la récompense finale moyenne."""
        # Implémentation simplifiée
        # En pratique, analyserait les logs d'entraînement
        return 0.0

class BayesianOptimizer:
    """Optimiseur Bayésien avec processus gaussiens."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.n_iterations = config.get('n_iterations', 50)
        self.acquisition_function = config.get('acquisition', 'EI')  # EI, UCB, PI
        
        # Modèle de processus gaussien
        self.gp_model = None
        self.X_samples = []
        self.y_samples = []
        
        # Historique d'optimisation
        self.optimization_history = []
        
    def setup_gaussian_process(self, parameter_bounds: Dict[str, Tuple[float, float]]):
        """Configure le modèle de processus gaussien."""
        # Kernel RBF avec bruit
        kernel = RBF(length_scale=1.0) + Matern(length_scale=1.0, nu=2.5)
        
        self.gp_model = GaussianProcessRegressor(
            kernel=kernel,
            alpha=1e-6,
            normalize_y=True,
            n_restarts_optimizer=5,
            random_state=42
        )
        
        self.parameter_bounds = parameter_bounds
        self.param_names = list(parameter_bounds.keys())
        
    def optimize(self, objectives: List[OptimizationObjective],
                constraints: List[OptimizationConstraint]) -> OptimizationResult:
        """Optimisation Bayésienne."""
        logger.info("Démarrage optimisation Bayésienne")
        start_time = time.time()
        
        # Échantillonnage initial aléatoire
        n_initial = 10
        self._generate_initial_samples(n_initial)
        
        best_result = None
        best_score = float('-inf')
        
        # Iterations d'optimisation Bayésienne
        for iteration in range(self.n_iterations):
            # Entraînement du modèle GP sur les données collectées
            if len(self.X_samples) > 0:
                X = np.array(self.X_samples)
                y = np.array(self.y_samples)
                self.gp_model.fit(X, y)
            
            # Acquisition du prochain point à évaluer
            next_point = self._optimize_acquisition_function()
            
            # Évaluation du point
            score = self._evaluate_point(next_point, objectives, constraints)
            
            # Mise à jour des échantillons
            self.X_samples.append(next_point)
            self.y_samples.append(score)
            
            # Mise à jour du meilleur résultat
            if score > best_score:
                best_score = score
                best_params = dict(zip(self.param_names, next_point))
                
                # Évaluation détaillée du meilleur point
                obj_values = {}
                for obj in objectives:
                    obj_values[obj.name] = self._evaluate_single_objective(obj, best_params)
                
                constraints_ok = all(
                    self._check_single_constraint(c, best_params) == 0
                    for c in constraints if c.is_active
                )
                
                best_result = OptimizationResult(
                    algorithm="bayesian_optimization",
                    timestamp=datetime.now(),
                    parameters=best_params,
                    objectives=obj_values,
                    constraints_satisfied=constraints_ok,
                    fitness_score=best_score,
                    generation=iteration + 1,
                    evaluation_time=time.time() - start_time
                )
            
            # Log périodique
            if iteration % 10 == 0:
                logger.info(f"Itération BO {iteration}: Meilleur score = {best_score:.3f}")
        
        self.optimization_history.append(best_result)
        logger.info(f"Optimisation Bayésienne terminée - Score: {best_score:.3f}")
        
        return best_result
    
    def _generate_initial_samples(self, n_samples: int):
        """Génère des échantillons initiaux aléatoirement."""
        self.X_samples = []
        self.y_samples = []
        
        for _ in range(n_samples):
            sample = []
            for param_name in self.param_names:
                min_val, max_val = self.parameter_bounds[param_name]
                value = np.random.uniform(min_val, max_val)
                sample.append(value)
            
            self.X_samples.append(sample)
            # Score sera calculé lors de la première itération
            self.y_samples.append(0.0)
    
    def _optimize_acquisition_function(self) -> List[float]:
        """Optimise la fonction d'acquisition pour trouver le prochain point."""
        if self.gp_model is None:
            # Échantillonnage aléatoire si pas de modèle
            sample = []
            for param_name in self.param_names:
                min_val, max_val = self.parameter_bounds[param_name]
                value = np.random.uniform(min_val, max_val)
                sample.append(value)
            return sample
        
        def acquisition_function(x):
            """Expected Improvement (EI)."""
            x = x.reshape(1, -1)
            mu, sigma = self.gp_model.predict(x, return_std=True)
            
            if sigma == 0:
                return 0
            
            best_y = max(self.y_samples) if self.y_samples else 0
            
            # Expected Improvement
            xi = 0.01  # Exploration parameter
            z = (mu - best_y - xi) / sigma
            ei = (mu - best_y - xi) * stats.norm.cdf(z) + sigma * stats.norm.pdf(z)
            
            return -ei  # Négatif pour minimisation
        
        # Limites pour l'optimisation
        bounds = [self.parameter_bounds[name] for name in self.param_names]
        
        # Optimisation multi-start
        best_x = None
        best_score = float('inf')
        
        for _ in range(10):  # 10 tentatives
            x0 = [np.random.uniform(b[0], b[1]) for b in bounds]
            
            try:
                result = minimize(
                    acquisition_function,
                    x0,
                    method='L-BFGS-B',
                    bounds=bounds
                )
                
                if result.success and result.fun < best_score:
                    best_score = result.fun
                    best_x = result.x
            except:
                continue
        
        return best_x.tolist() if best_x is not None else x0
    
    def _evaluate_point(self, point: List[float], 
                       objectives: List[OptimizationObjective],
                       constraints: List[OptimizationConstraint]) -> float:
        """Évalue un point selon les objectifs et contraintes."""
        parameters = dict(zip(self.param_names, point))
        
        # Évaluation des objectifs
        total_score = 0
        for obj in objectives:
            value = self._evaluate_single_objective(obj, parameters)
            normalized = self._normalize_value(value, obj.bounds)
            
            if obj.type == 'maximize':
                total_score += obj.weight * normalized
            else:
                total_score += obj.weight * (1 - normalized)
        
        # Pénalités pour contraintes
        penalty = 0
        for constraint in constraints:
            if constraint.is_active:
                violation = self._check_single_constraint(constraint, parameters)
                penalty += violation * constraint.violation_penalty
        
        return total_score - penalty
    
    def _evaluate_single_objective(self, objective: OptimizationObjective,
                                  parameters: Dict[str, float]) -> float:
        """Évalue un objectif unique."""
        # Utilise la même logique que GeneticAlgorithmOptimizer
        if objective.name == 'efficiency':
            speed = parameters.get('speed', 1500)
            temp = parameters.get('temperature', 70)
            optimal_speed, optimal_temp = 1800, 75
            
            speed_factor = 1 - abs(speed - optimal_speed) / optimal_speed
            temp_factor = 1 - abs(temp - optimal_temp) / optimal_temp
            
            return max(0, speed_factor * temp_factor * 100)
        
        # Autres objectifs...
        return np.random.uniform(*objective.bounds)
    
    def _check_single_constraint(self, constraint: OptimizationConstraint,
                                parameters: Dict[str, float]) -> float:
        """Vérifie une contrainte unique."""
        # Utilise la même logique que GeneticAlgorithmOptimizer
        if constraint.type == 'bounds':
            param_name = constraint.name.replace('_bounds', '')
            if param_name in parameters:
                value = parameters[param_name]
                min_val, max_val = constraint.bounds
                
                if value < min_val:
                    return min_val - value
                elif value > max_val:
                    return value - max_val
        
        return 0.0
    
    def _normalize_value(self, value: float, bounds: Tuple[float, float]) -> float:
        """Normalise une valeur entre 0 et 1."""
        min_val, max_val = bounds
        if max_val == min_val:
            return 1.0
        return np.clip((value - min_val) / (max_val - min_val), 0.0, 1.0)

class AutonomousOptimizationSystem:
    """Système d'optimisation autonome principal."""
    
    def __init__(self, config_path: str = "optimization_config.json"):
        self.config = self._load_config(config_path)
        
        # Optimiseurs disponibles
        self.genetic_optimizer = GeneticAlgorithmOptimizer(self.config.get('genetic', {}))
        self.rl_optimizer = ReinforcementLearningOptimizer(self.config.get('reinforcement_learning', {}))
        self.bayesian_optimizer = BayesianOptimizer(self.config.get('bayesian', {}))
        
        # État du système
        self.objectives = []
        self.constraints = []
        self.parameter_bounds = {}
        self.optimization_history = []
        
        # Système de décision automatique
        self.algorithm_selector = AlgorithmSelector()
        
        # Métriques et monitoring
        self.performance_metrics = {}
        self.system_status = "idle"
        
        logger.info("Système d'optimisation autonome initialisé")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration du système."""
        default_config = {
            'genetic': {
                'population_size': 50,
                'num_generations': 100,
                'crossover_rate': 0.8,
                'mutation_rate': 0.1
            },
            'reinforcement_learning': {
                'algorithm': 'PPO',
                'total_timesteps': 100000,
                'learning_rate': 3e-4,
                'save_dir': './rl_models'
            },
            'bayesian': {
                'n_iterations': 50,
                'acquisition': 'EI'
            },
            'system': {
                'optimization_interval_hours': 6,
                'max_concurrent_optimizations': 2,
                'auto_apply_results': False,
                'safety_checks': True
            },
            'objectives': {
                'efficiency': {
                    'weight': 0.4,
                    'target': 90,
                    'bounds': [0, 100]
                },
                'energy_consumption': {
                    'weight': 0.3,
                    'bounds': [5, 20]
                },
                'maintenance_cost': {
                    'weight': 0.3,
                    'bounds': [500, 5000]
                }
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
                    elif isinstance(value, dict) and isinstance(config[key], dict):
                        for subkey, subvalue in value.items():
                            if subkey not in config[key]:
                                config[key][subkey] = subvalue
            else:
                config = default_config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur chargement config: {e}")
            config = default_config
        
        return config
    
    def setup_optimization_problem(self, 
                                  objectives: List[OptimizationObjective],
                                  constraints: List[OptimizationConstraint],
                                  parameter_bounds: Dict[str, Tuple[float, float]]):
        """Configure le problème d'optimisation."""
        self.objectives = objectives
        self.constraints = constraints
        self.parameter_bounds = parameter_bounds
        
        # Configuration des optimiseurs spécialisés
        self.bayesian_optimizer.setup_gaussian_process(parameter_bounds)
        
        # Configuration de l'environnement RL
        process_config = {
            'equipment_parameters': parameter_bounds,
            'constraints': {c.name: c.bounds for c in constraints}
        }
        self.rl_optimizer.setup_environment(process_config)
        
        logger.info(f"Problème d'optimisation configuré: {len(objectives)} objectifs, {len(constraints)} contraintes")
    
    async def run_autonomous_optimization(self, algorithms: List[str] = None) -> Dict[str, OptimizationResult]:
        """Lance l'optimisation autonome avec sélection automatique d'algorithmes."""
        if not self.objectives:
            raise ValueError("Objectifs d'optimisation non définis")
        
        logger.info("Démarrage optimisation autonome")
        self.system_status = "optimizing"
        
        # Sélection automatique des algorithmes si non spécifiés
        if algorithms is None:
            algorithms = self.algorithm_selector.select_algorithms(
                self.objectives, self.constraints, self.parameter_bounds
            )
        
        results = {}
        optimization_tasks = []
        
        # Lancement des optimisations en parallèle
        for algorithm in algorithms:
            task = self._run_single_optimization(algorithm)
            optimization_tasks.append((algorithm, task))
        
        # Attente des résultats
        for algorithm, task in optimization_tasks:
            try:
                result = await task
                results[algorithm] = result
                logger.info(f"Optimisation {algorithm} terminée")
            except Exception as e:
                logger.error(f"Erreur optimisation {algorithm}: {e}")
                results[algorithm] = None
        
        # Analyse et sélection du meilleur résultat
        best_result = self._select_best_result(results)
        
        # Application automatique si configuré
        if self.config['system']['auto_apply_results'] and best_result:
            await self._apply_optimization_result(best_result)
        
        self.system_status = "idle"
        logger.info("Optimisation autonome terminée")
        
        return results
    
    async def _run_single_optimization(self, algorithm: str) -> OptimizationResult:
        """Lance une optimisation avec un algorithme spécifique."""
        
        if algorithm == 'genetic':
            return self.genetic_optimizer.optimize(
                self.objectives, self.constraints, self.parameter_bounds
            )
        
        elif algorithm == 'reinforcement_learning':
            # Entraînement si nécessaire
            if self.rl_optimizer.model is None:
                env = self.rl_optimizer.env
                model = self.rl_optimizer.create_model(env)
                await asyncio.get_event_loop().run_in_executor(
                    None, self.rl_optimizer.train_model
                )
            
            # Optimisation
            return await asyncio.get_event_loop().run_in_executor(
                None, self.rl_optimizer.optimize_process
            )
        
        elif algorithm == 'bayesian':
            return await asyncio.get_event_loop().run_in_executor(
                None, self.bayesian_optimizer.optimize,
                self.objectives, self.constraints
            )
        
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
    
    def _select_best_result(self, results: Dict[str, OptimizationResult]) -> OptimizationResult:
        """Sélectionne le meilleur résultat parmi tous les algorithmes."""
        valid_results = {k: v for k, v in results.items() if v is not None}
        
        if not valid_results:
            return None
        
        # Critères de sélection
        best_result = None
        best_score = float('-inf')
        
        for algorithm, result in valid_results.items():
            # Score composite basé sur fitness et satisfaction des contraintes
            score = result.fitness_score
            
            # Bonus pour satisfaction des contraintes
            if result.constraints_satisfied:
                score += 10
            
            # Pénalité pour temps d'évaluation excessif
            if result.evaluation_time > 300:  # 5 minutes
                score -= 5
            
            if score > best_score:
                best_score = score
                best_result = result
        
        return best_result
    
    async def _apply_optimization_result(self, result: OptimizationResult):
        """Applique automatiquement un résultat d'optimisation."""
        if not self.config['system']['safety_checks']:
            logger.warning("Application sans vérifications de sécurité")
        else:
            # Vérifications de sécurité
            if not self._safety_check_parameters(result.parameters):
                logger.error("Échec vérifications sécurité - Application annulée")
                return
        
        logger.info(f"Application des paramètres optimisés: {result.parameters}")
        
        # Interface avec le système de contrôle industriel
        # En pratique, ceci communiquerait avec les contrôleurs PLC/SCADA
        await self._send_to_industrial_control_system(result.parameters)
    
    def _safety_check_parameters(self, parameters: Dict[str, float]) -> bool:
        """Vérifie la sécurité des paramètres avant application."""
        for param_name, value in parameters.items():
            if param_name in self.parameter_bounds:
                min_val, max_val = self.parameter_bounds[param_name]
                if not (min_val <= value <= max_val):
                    logger.error(f"Paramètre {param_name}={value} hors limites [{min_val}, {max_val}]")
                    return False
        
        # Vérifications spécifiques de sécurité
        if 'temperature' in parameters and parameters['temperature'] > 95:
            logger.error("Température trop élevée pour sécurité")
            return False
        
        if 'pressure' in parameters and parameters['pressure'] > 9:
            logger.error("Pression trop élevée pour sécurité")
            return False
        
        return True
    
    async def _send_to_industrial_control_system(self, parameters: Dict[str, float]):
        """Envoie les paramètres au système de contrôle industriel."""
        # Simulation d'envoi au système de contrôle
        logger.info("Envoi paramètres au système de contrôle:")
        for param, value in parameters.items():
            logger.info(f"  {param}: {value}")
        
        # En pratique, utiliserait des protocoles industriels comme:
        # - Modbus TCP
        # - OPC UA
        # - EtherNet/IP
        # - MQTT industriel
        
        await asyncio.sleep(1)  # Simulation du délai d'application
    
    def get_system_status(self) -> Dict[str, Any]:
        """Retourne le statut du système d'optimisation."""
        return {
            'status': self.system_status,
            'objectives_count': len(self.objectives),
            'constraints_count': len(self.constraints),
            'parameters_count': len(self.parameter_bounds),
            'optimization_history_count': len(self.optimization_history),
            'last_optimization': self.optimization_history[-1].timestamp if self.optimization_history else None,
            'available_algorithms': ['genetic', 'reinforcement_learning', 'bayesian'],
            'system_config': self.config['system']
        }

class AlgorithmSelector:
    """Sélecteur automatique d'algorithmes d'optimisation."""
    
    def select_algorithms(self, 
                         objectives: List[OptimizationObjective],
                         constraints: List[OptimizationConstraint],
                         parameter_bounds: Dict[str, Tuple[float, float]]) -> List[str]:
        """Sélectionne automatiquement les algorithmes les plus appropriés."""
        
        algorithms = []
        
        # Facteurs de décision
        n_objectives = len(objectives)
        n_constraints = len(constraints)
        n_parameters = len(parameter_bounds)
        
        # Complexité du problème
        complexity = n_objectives * n_constraints * n_parameters
        
        # Sélection basée sur les caractéristiques du problème
        
        # Algorithmes génétiques - Bons pour multi-objectifs
        if n_objectives >= 2:
            algorithms.append('genetic')
        
        # Apprentissage par renforcement - Bon pour apprentissage adaptatif
        if complexity > 10:  # Problèmes complexes
            algorithms.append('reinforcement_learning')
        
        # Optimisation Bayésienne - Efficace pour peu de paramètres
        if n_parameters <= 10:
            algorithms.append('bayesian')
        
        # Au moins un algorithme
        if not algorithms:
            algorithms = ['genetic']
        
        return algorithms

# Fonction de démonstration
async def main():
    """Démonstration du système d'optimisation autonome."""
    
    print("=== Système d'Optimisation Autonome du Jumeau Numérique ===")
    print("🏭 Station Traffeyère IoT AI Platform")
    print()
    
    # Initialisation du système
    optimization_system = AutonomousOptimizationSystem()
    
    print("✅ Système d'optimisation autonome initialisé")
    print()
    
    # Configuration du problème d'optimisation
    print("📋 Configuration du problème d'optimisation...")
    
    # Objectifs d'optimisation
    objectives = [
        OptimizationObjective(
            name="efficiency",
            type="maximize",
            weight=0.4,
            bounds=(0.0, 100.0),
            target_value=90.0,
            priority="high"
        ),
        OptimizationObjective(
            name="energy_consumption",
            type="minimize",
            weight=0.3,
            bounds=(5.0, 20.0),
            priority="normal"
        ),
        OptimizationObjective(
            name="maintenance_cost",
            type="minimize",
            weight=0.3,
            bounds=(500.0, 5000.0),
            priority="normal"
        )
    ]
    
    # Contraintes opérationnelles
    constraints = [
        OptimizationConstraint(
            name="temperature_bounds",
            type="bounds",
            function=None,
            bounds=(40.0, 95.0),
            violation_penalty=50.0
        ),
        OptimizationConstraint(
            name="pressure_bounds",
            type="bounds",
            function=None,
            bounds=(1.0, 9.0),
            violation_penalty=75.0
        )
    ]
    
    # Paramètres à optimiser
    parameter_bounds = {
        'speed': (1000.0, 2500.0),
        'temperature': (40.0, 95.0),
        'pressure': (1.0, 9.0),
        'load': (0.3, 1.0)
    }
    
    # Configuration du système
    optimization_system.setup_optimization_problem(objectives, constraints, parameter_bounds)
    
    print(f"  • {len(objectives)} objectifs définis")
    print(f"  • {len(constraints)} contraintes configurées")
    print(f"  • {len(parameter_bounds)} paramètres à optimiser")
    print()
    
    print("🚀 Lancement de l'optimisation autonome...")
    print("   Algorithmes sélectionnés automatiquement...")
    print()
    
    try:
        # Lancement de l'optimisation autonome
        results = await optimization_system.run_autonomous_optimization()
        
        print("✅ Optimisation terminée !")
        print()
        print("📊 Résultats par algorithme:")
        print("=" * 60)
        
        for algorithm, result in results.items():
            if result is not None:
                print(f"\n🔧 {algorithm.upper()}:")
                print(f"  • Score de fitness: {result.fitness_score:.3f}")
                print(f"  • Contraintes satisfaites: {'✅' if result.constraints_satisfied else '❌'}")
                print(f"  • Temps d'évaluation: {result.evaluation_time:.1f}s")
                print(f"  • Paramètres optimaux:")
                for param, value in result.parameters.items():
                    print(f"    - {param}: {value:.2f}")
                print(f"  • Objectifs atteints:")
                for obj_name, obj_value in result.objectives.items():
                    print(f"    - {obj_name}: {obj_value:.2f}")
            else:
                print(f"\n❌ {algorithm.upper()}: Échec d'optimisation")
        
        print()
        print("🎯 Sélection automatique du meilleur résultat...")
        
        # Recherche du meilleur résultat
        best_algorithm = None
        best_score = float('-inf')
        
        for algorithm, result in results.items():
            if result is not None and result.fitness_score > best_score:
                best_score = result.fitness_score
                best_algorithm = algorithm
        
        if best_algorithm:
            best_result = results[best_algorithm]
            print(f"🏆 Meilleur algorithme: {best_algorithm.upper()}")
            print(f"   Score: {best_result.fitness_score:.3f}")
            print(f"   Paramètres recommandés:")
            for param, value in best_result.parameters.items():
                print(f"     • {param}: {value:.2f}")
        else:
            print("❌ Aucun résultat valide obtenu")
        
        print()
        print("📈 Analyse des améliorations:")
        
        if best_algorithm:
            # Calcul des améliorations par rapport aux valeurs initiales
            initial_params = {
                'speed': 1500,
                'temperature': 70,
                'pressure': 5,
                'load': 0.8
            }
            
            print("  Paramètres initiaux → Optimisés:")
            for param in parameter_bounds.keys():
                initial = initial_params.get(param, 0)
                optimized = best_result.parameters.get(param, 0)
                change = ((optimized - initial) / initial * 100) if initial != 0 else 0
                print(f"    • {param}: {initial:.1f} → {optimized:.1f} ({change:+.1f}%)")
        
    except Exception as e:
        print(f"❌ Erreur durant l'optimisation: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("📊 Statut du système:")
    status = optimization_system.get_system_status()
    print(f"  • État: {status['status']}")
    print(f"  • Algorithmes disponibles: {', '.join(status['available_algorithms'])}")
    print(f"  • Historique d'optimisations: {status['optimization_history_count']}")
    
    print()
    print("🎉 Démonstration terminée avec succès !")
    print("   Le système d'optimisation autonome est opérationnel !")

if __name__ == "__main__":
    asyncio.run(main())