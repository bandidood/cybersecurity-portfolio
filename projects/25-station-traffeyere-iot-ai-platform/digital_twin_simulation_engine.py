#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 5A: Moteur de Simulation du Jumeau Numérique

Moteur de simulation physique avancé pour la modélisation thermodynamique,
mécanique et électrique des équipements industriels avec synchronisation
temps réel et prédictions de performance.

Auteur: Spécialiste Sécurité IoT Industriel
Date: 2024
"""

import os
import json
import asyncio
import logging
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod
import numpy as np
import pandas as pd
from pathlib import Path
import math
import pickle
from concurrent.futures import ThreadPoolExecutor
import threading
import time

# Bibliothèques de simulation physique
import scipy as sp
from scipy.integrate import odeint, solve_ivp
from scipy.optimize import minimize, differential_evolution
from scipy.interpolate import interp1d, griddata
from scipy.signal import butter, filtfilt, find_peaks
import control
from control import TransferFunction, feedback, step_response, bode_plot

# Analyse numérique et calculs scientifiques  
import sympy as sym
from sympy import symbols, diff, integrate, solve, lambdify
import numpy.linalg as la

# Visualisation et monitoring
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Machine Learning pour modélisation
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import Dense, LSTM, Conv1D, MaxPooling1D, Flatten, Dropout
from tensorflow.keras.optimizers import Adam

warnings.filterwarnings('ignore')

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PhysicalProperties:
    """Propriétés physiques d'un équipement."""
    mass: float = 0.0  # kg
    density: float = 0.0  # kg/m³
    specific_heat: float = 0.0  # J/(kg·K)
    thermal_conductivity: float = 0.0  # W/(m·K)
    electrical_resistance: float = 0.0  # Ω
    mechanical_stiffness: float = 0.0  # N/m
    damping_coefficient: float = 0.0  # N·s/m
    surface_area: float = 0.0  # m²
    volume: float = 0.0  # m³
    moment_of_inertia: float = 0.0  # kg·m²

@dataclass
class OperatingConditions:
    """Conditions opérationnelles actuelles."""
    temperature: float = 20.0  # °C
    pressure: float = 101325.0  # Pa
    humidity: float = 50.0  # %
    vibration_amplitude: float = 0.0  # m
    vibration_frequency: float = 0.0  # Hz
    electrical_voltage: float = 240.0  # V
    electrical_current: float = 0.0  # A
    rotational_speed: float = 0.0  # rpm
    flow_rate: float = 0.0  # m³/s
    load_force: float = 0.0  # N

@dataclass
class SimulationState:
    """État actuel de la simulation."""
    timestamp: datetime
    equipment_id: str
    state_variables: Dict[str, float] = field(default_factory=dict)
    derivatives: Dict[str, float] = field(default_factory=dict)
    energy_balance: Dict[str, float] = field(default_factory=dict)
    wear_indicators: Dict[str, float] = field(default_factory=dict)
    efficiency_metrics: Dict[str, float] = field(default_factory=dict)
    fault_probabilities: Dict[str, float] = field(default_factory=dict)

class PhysicalModel(ABC):
    """Classe abstraite pour les modèles physiques."""
    
    def __init__(self, name: str, properties: PhysicalProperties):
        self.name = name
        self.properties = properties
        self.state = SimulationState(
            timestamp=datetime.now(),
            equipment_id=name
        )
        
    @abstractmethod
    def update_state(self, dt: float, conditions: OperatingConditions) -> SimulationState:
        """Met à jour l'état du modèle physique."""
        pass
    
    @abstractmethod  
    def get_health_indicators(self) -> Dict[str, float]:
        """Retourne les indicateurs de santé de l'équipement."""
        pass
    
    @abstractmethod
    def predict_future_state(self, time_horizon: float) -> List[SimulationState]:
        """Prédit l'état futur de l'équipement."""
        pass

class ThermalModel(PhysicalModel):
    """Modèle thermique avancé pour équipements industriels."""
    
    def __init__(self, name: str, properties: PhysicalProperties, 
                 ambient_temp: float = 20.0):
        super().__init__(name, properties)
        self.ambient_temperature = ambient_temp
        self.internal_temperature = ambient_temp
        self.heat_generation_rate = 0.0  # W
        self.heat_transfer_coefficient = 10.0  # W/(m²·K)
        
        # Historique thermique
        self.temperature_history = []
        self.thermal_stress_accumulation = 0.0
        
    def calculate_heat_generation(self, conditions: OperatingConditions) -> float:
        """Calcule la génération de chaleur basée sur les conditions."""
        # Chaleur par résistance électrique (Effet Joule)
        electrical_heat = (conditions.electrical_current ** 2) * self.properties.electrical_resistance
        
        # Chaleur par friction mécanique
        friction_heat = 0.1 * conditions.load_force * (conditions.rotational_speed * 2 * np.pi / 60)
        
        # Chaleur par compression/décompression
        compression_heat = 0.05 * abs(conditions.pressure - 101325) * conditions.flow_rate
        
        return electrical_heat + friction_heat + compression_heat
    
    def calculate_heat_transfer(self, conditions: OperatingConditions) -> float:
        """Calcule le transfert de chaleur vers l'environnement."""
        # Convection naturelle et forcée
        temp_diff = self.internal_temperature - conditions.temperature
        convection = self.heat_transfer_coefficient * self.properties.surface_area * temp_diff
        
        # Rayonnement (loi de Stefan-Boltzmann simplifiée)
        stefan_boltzmann = 5.67e-8  # W/(m²·K⁴)
        emissivity = 0.8  # Facteur d'émissivité typique
        T_int_K = self.internal_temperature + 273.15
        T_amb_K = conditions.temperature + 273.15
        radiation = emissivity * stefan_boltzmann * self.properties.surface_area * (T_int_K**4 - T_amb_K**4)
        
        # Conduction (négligeable pour la plupart des cas)
        conduction = 0.0
        
        return convection + radiation + conduction
    
    def update_state(self, dt: float, conditions: OperatingConditions) -> SimulationState:
        """Met à jour l'état thermique."""
        # Calcul des termes énergétiques
        heat_generated = self.calculate_heat_generation(conditions)
        heat_transferred = self.calculate_heat_transfer(conditions)
        
        # Équation différentielle thermique: m·c·dT/dt = Q_gen - Q_loss
        thermal_mass = self.properties.mass * self.properties.specific_heat
        
        if thermal_mass > 0:
            dT_dt = (heat_generated - heat_transferred) / thermal_mass
        else:
            dT_dt = 0.0
        
        # Mise à jour de la température
        self.internal_temperature += dT_dt * dt
        
        # Accumulation du stress thermique
        temp_range = abs(self.internal_temperature - self.ambient_temperature)
        self.thermal_stress_accumulation += temp_range * dt / 3600  # Par heure
        
        # Mise à jour de l'état
        self.state.timestamp = datetime.now()
        self.state.state_variables.update({
            'internal_temperature': self.internal_temperature,
            'heat_generation_rate': heat_generated,
            'heat_transfer_rate': heat_transferred,
            'temperature_gradient': dT_dt,
            'thermal_stress': self.thermal_stress_accumulation
        })
        
        self.state.energy_balance.update({
            'thermal_energy_in': heat_generated,
            'thermal_energy_out': heat_transferred,
            'thermal_energy_stored': thermal_mass * (self.internal_temperature - self.ambient_temperature)
        })
        
        # Historique
        self.temperature_history.append({
            'timestamp': datetime.now(),
            'temperature': self.internal_temperature
        })
        
        # Garder seulement les 1000 derniers points
        if len(self.temperature_history) > 1000:
            self.temperature_history.pop(0)
        
        return self.state
    
    def get_health_indicators(self) -> Dict[str, float]:
        """Calcule les indicateurs de santé thermique."""
        indicators = {}
        
        # Température excessive
        if self.internal_temperature > 100:  # Seuil critique
            indicators['thermal_overload'] = min(1.0, (self.internal_temperature - 100) / 50)
        else:
            indicators['thermal_overload'] = 0.0
        
        # Stress thermique cumulé  
        indicators['thermal_fatigue'] = min(1.0, self.thermal_stress_accumulation / 10000)
        
        # Stabilité thermique
        if len(self.temperature_history) > 10:
            recent_temps = [point['temperature'] for point in self.temperature_history[-10:]]
            temp_variance = np.var(recent_temps)
            indicators['thermal_instability'] = min(1.0, temp_variance / 100)
        else:
            indicators['thermal_instability'] = 0.0
        
        return indicators
    
    def predict_future_state(self, time_horizon: float) -> List[SimulationState]:
        """Prédit l'évolution thermique future."""
        # Simulation simplifiée avec conditions constantes
        future_states = []
        dt = 60  # Pas de 1 minute
        steps = int(time_horizon * 3600 / dt)
        
        # Conditions moyennes basées sur l'historique récent
        avg_conditions = OperatingConditions()  # Conditions par défaut
        
        temp_current = self.internal_temperature
        
        for i in range(steps):
            # Modèle prédictif simple (exponentielle vers équilibre)
            equilibrium_temp = self.ambient_temperature + 20  # Estimation
            tau = 1800  # Constante de temps thermique (30 min)
            
            temp_current += (equilibrium_temp - temp_current) * (1 - np.exp(-dt / tau))
            
            # Création d'un état futur
            future_state = SimulationState(
                timestamp=datetime.now() + timedelta(seconds=i * dt),
                equipment_id=self.name
            )
            future_state.state_variables['internal_temperature'] = temp_current
            future_state.state_variables['predicted'] = True
            
            future_states.append(future_state)
        
        return future_states

class MechanicalModel(PhysicalModel):
    """Modèle mécanique pour équipements rotatifs."""
    
    def __init__(self, name: str, properties: PhysicalProperties):
        super().__init__(name, properties)
        self.angular_velocity = 0.0  # rad/s
        self.angular_acceleration = 0.0  # rad/s²
        self.torque_applied = 0.0  # N·m
        self.bearing_wear = 0.0  # Usure des roulements (0-1)
        self.alignment_deviation = 0.0  # Défaut d'alignement (mm)
        self.vibration_level = 0.0  # Niveau de vibration RMS
        
        # Historique mécanique
        self.vibration_history = []
        self.load_cycles = 0
        
    def calculate_dynamic_forces(self, conditions: OperatingConditions) -> Dict[str, float]:
        """Calcule les forces dynamiques."""
        forces = {}
        
        # Force centrifuge
        if conditions.rotational_speed > 0:
            omega = conditions.rotational_speed * 2 * np.pi / 60  # rad/s
            forces['centrifugal'] = self.properties.mass * omega**2 * 0.1  # Estimation
        else:
            forces['centrifugal'] = 0.0
        
        # Forces de débalancement
        unbalance_mass = 0.001  # kg (masse débalancée typique)
        forces['unbalance'] = unbalance_mass * (conditions.rotational_speed * 2 * np.pi / 60)**2 * 0.05
        
        # Forces de friction
        friction_coefficient = 0.1 + self.bearing_wear * 0.2  # Augmente avec l'usure
        forces['friction'] = friction_coefficient * conditions.load_force
        
        return forces
    
    def calculate_vibration_signature(self, conditions: OperatingConditions) -> Dict[str, float]:
        """Calcule la signature vibratoire."""
        signature = {}
        
        # Fréquence de rotation
        rotation_freq = conditions.rotational_speed / 60  # Hz
        
        # Amplitudes harmoniques
        signature['1x_amplitude'] = 0.1 + self.bearing_wear * 2.0  # Fondamentale
        signature['2x_amplitude'] = 0.05 + self.alignment_deviation * 0.5  # 2ème harmonique
        signature['3x_amplitude'] = 0.02 + self.bearing_wear * 0.3  # 3ème harmonique
        
        # Fréquences de défaut de roulement
        bearing_freq = rotation_freq * 3.2  # Fréquence caractéristique
        signature['bearing_amplitude'] = self.bearing_wear * 1.5
        
        # Niveau global RMS
        signature['overall_rms'] = np.sqrt(
            signature['1x_amplitude']**2 + 
            signature['2x_amplitude']**2 + 
            signature['3x_amplitude']**2 + 
            signature['bearing_amplitude']**2
        )
        
        return signature
    
    def update_state(self, dt: float, conditions: OperatingConditions) -> SimulationState:
        """Met à jour l'état mécanique."""
        # Conversion des unités
        target_omega = conditions.rotational_speed * 2 * np.pi / 60  # rad/s
        
        # Modèle dynamique simplifié (système du premier ordre)
        tau_mechanical = 5.0  # Constante de temps mécanique (secondes)
        
        # Équation différentielle: τ·dω/dt + ω = ω_target
        if tau_mechanical > 0:
            domega_dt = (target_omega - self.angular_velocity) / tau_mechanical
        else:
            domega_dt = 0.0
        
        self.angular_velocity += domega_dt * dt
        self.angular_acceleration = domega_dt
        
        # Calcul des forces dynamiques
        dynamic_forces = self.calculate_dynamic_forces(conditions)
        
        # Signature vibratoire
        vibration_signature = self.calculate_vibration_signature(conditions)
        self.vibration_level = vibration_signature['overall_rms']
        
        # Évolution de l'usure
        if conditions.rotational_speed > 0:
            # Facteurs d'usure
            speed_factor = (conditions.rotational_speed / 1800) ** 2  # Normalisé à 1800 rpm
            load_factor = max(1.0, conditions.load_force / 1000)  # Normalisé à 1000 N
            temp_factor = max(1.0, (conditions.temperature - 20) / 60)  # Facteur température
            
            # Taux d'usure (très faible pour simulation)
            wear_rate = 1e-8 * speed_factor * load_factor * temp_factor
            self.bearing_wear = min(1.0, self.bearing_wear + wear_rate * dt)
            
            # Cycles de charge
            self.load_cycles += conditions.rotational_speed / 60 * dt / 60  # Cycles par minute
        
        # Mise à jour de l'état
        self.state.timestamp = datetime.now()
        self.state.state_variables.update({
            'angular_velocity': self.angular_velocity,
            'angular_acceleration': self.angular_acceleration,
            'vibration_rms': self.vibration_level,
            'bearing_wear': self.bearing_wear,
            'load_cycles': self.load_cycles
        })
        
        # Forces dynamiques
        self.state.state_variables.update(dynamic_forces)
        
        # Signature vibratoire
        self.state.state_variables.update({
            f'vib_{k}': v for k, v in vibration_signature.items()
        })
        
        # Indicateurs d'usure
        self.state.wear_indicators.update({
            'bearing_condition': 1.0 - self.bearing_wear,
            'mechanical_efficiency': max(0.5, 1.0 - self.bearing_wear * 0.3),
            'alignment_quality': max(0.0, 1.0 - self.alignment_deviation / 5.0)
        })
        
        # Historique vibratoire
        self.vibration_history.append({
            'timestamp': datetime.now(),
            'rms_level': self.vibration_level,
            'rotation_speed': conditions.rotational_speed
        })
        
        if len(self.vibration_history) > 1000:
            self.vibration_history.pop(0)
        
        return self.state
    
    def get_health_indicators(self) -> Dict[str, float]:
        """Calcule les indicateurs de santé mécanique."""
        indicators = {}
        
        # Niveau d'usure des roulements
        indicators['bearing_degradation'] = self.bearing_wear
        
        # Niveau de vibration excessif
        if self.vibration_level > 5.0:  # Seuil critique
            indicators['excessive_vibration'] = min(1.0, (self.vibration_level - 5.0) / 10.0)
        else:
            indicators['excessive_vibration'] = 0.0
        
        # Instabilité mécanique
        if len(self.vibration_history) > 10:
            recent_vibrations = [point['rms_level'] for point in self.vibration_history[-10:]]
            vibration_variance = np.var(recent_vibrations)
            indicators['mechanical_instability'] = min(1.0, vibration_variance / 2.0)
        else:
            indicators['mechanical_instability'] = 0.0
        
        # Défaillance imminente basée sur les cycles de charge
        mtbf_cycles = 1e8  # Cycles moyens avant défaillance
        indicators['fatigue_level'] = min(1.0, self.load_cycles / mtbf_cycles)
        
        return indicators
    
    def predict_future_state(self, time_horizon: float) -> List[SimulationState]:
        """Prédit l'évolution mécanique future."""
        future_states = []
        dt = 300  # Pas de 5 minutes
        steps = int(time_horizon * 3600 / dt)
        
        current_wear = self.bearing_wear
        current_cycles = self.load_cycles
        
        for i in range(steps):
            # Modèle de dégradation exponentielle
            wear_growth_rate = 1e-6  # Taux de croissance de l'usure
            projected_wear = current_wear * (1 + wear_growth_rate * i)
            projected_wear = min(1.0, projected_wear)
            
            # Cycles supplémentaires (estimation)
            additional_cycles = 1800 / 60 * dt / 60  # À vitesse nominale
            projected_cycles = current_cycles + additional_cycles * i
            
            # État futur
            future_state = SimulationState(
                timestamp=datetime.now() + timedelta(seconds=i * dt),
                equipment_id=self.name
            )
            
            future_state.state_variables.update({
                'bearing_wear': projected_wear,
                'load_cycles': projected_cycles,
                'predicted_vibration': 0.1 + projected_wear * 2.0,
                'predicted': True
            })
            
            future_state.wear_indicators.update({
                'bearing_condition': 1.0 - projected_wear,
                'remaining_life': max(0.0, 1.0 - projected_cycles / 1e8)
            })
            
            future_states.append(future_state)
        
        return future_states

class ElectricalModel(PhysicalModel):
    """Modèle électrique pour équipements électriques."""
    
    def __init__(self, name: str, properties: PhysicalProperties, 
                 rated_voltage: float = 240.0, rated_current: float = 10.0):
        super().__init__(name, properties)
        self.rated_voltage = rated_voltage
        self.rated_current = rated_current
        self.power_factor = 0.85
        self.efficiency = 0.90
        self.insulation_resistance = 1e6  # Ω
        self.winding_temperature = 20.0  # °C
        
        # Historique électrique
        self.power_history = []
        self.voltage_harmonics = {'thd': 0.05}  # Distorsion harmonique
        
    def calculate_electrical_parameters(self, conditions: OperatingConditions) -> Dict[str, float]:
        """Calcule les paramètres électriques."""
        params = {}
        
        # Puissance apparente, active et réactive
        apparent_power = conditions.electrical_voltage * conditions.electrical_current
        active_power = apparent_power * self.power_factor
        reactive_power = apparent_power * np.sin(np.arccos(self.power_factor))
        
        params['apparent_power'] = apparent_power
        params['active_power'] = active_power
        params['reactive_power'] = reactive_power
        
        # Résistance et impédance
        if conditions.electrical_current > 0:
            impedance = conditions.electrical_voltage / conditions.electrical_current
            resistance_component = impedance * self.power_factor
        else:
            impedance = float('inf')
            resistance_component = self.properties.electrical_resistance
        
        params['impedance'] = impedance
        params['resistance'] = resistance_component
        
        # Pertes électriques
        copper_losses = conditions.electrical_current**2 * self.properties.electrical_resistance
        iron_losses = 0.02 * active_power  # Estimation 2% de pertes fer
        total_losses = copper_losses + iron_losses
        
        params['copper_losses'] = copper_losses
        params['iron_losses'] = iron_losses
        params['total_losses'] = total_losses
        
        # Efficacité instantanée
        if active_power > 0:
            instantaneous_efficiency = (active_power - total_losses) / active_power
        else:
            instantaneous_efficiency = 0.0
        
        params['efficiency'] = max(0.0, min(1.0, instantaneous_efficiency))
        
        return params
    
    def update_insulation_degradation(self, conditions: OperatingConditions, dt: float):
        """Met à jour la dégradation de l'isolant."""
        # Modèle d'Arrhenius pour la dégradation thermique
        base_temp = 40.0  # Température de référence
        activation_energy = 15000  # J/mol (valeur typique)
        gas_constant = 8.314  # J/(mol·K)
        
        temp_kelvin = conditions.temperature + 273.15
        base_temp_kelvin = base_temp + 273.15
        
        # Facteur d'accélération thermique
        thermal_factor = np.exp(
            (activation_energy / gas_constant) * 
            ((1 / base_temp_kelvin) - (1 / temp_kelvin))
        )
        
        # Facteur de tension
        voltage_stress = conditions.electrical_voltage / self.rated_voltage
        voltage_factor = voltage_stress ** 2
        
        # Facteur d'humidité
        humidity_factor = 1 + (conditions.humidity - 50) / 100
        
        # Taux de dégradation combiné
        degradation_rate = 1e-8 * thermal_factor * voltage_factor * humidity_factor
        
        # Réduction de la résistance d'isolement
        resistance_loss = self.insulation_resistance * degradation_rate * dt
        self.insulation_resistance = max(1000, self.insulation_resistance - resistance_loss)
    
    def update_state(self, dt: float, conditions: OperatingConditions) -> SimulationState:
        """Met à jour l'état électrique."""
        # Calcul des paramètres électriques
        electrical_params = self.calculate_electrical_parameters(conditions)
        
        # Mise à jour de la température des bobinages
        # La température augmente avec les pertes par effet Joule
        thermal_resistance = 0.1  # K/W (résistance thermique bobinage-ambiant)
        steady_state_temp = conditions.temperature + electrical_params['copper_losses'] * thermal_resistance
        
        # Dynamique thermique du bobinage
        tau_thermal = 600  # Constante de temps thermique (10 min)
        dT_dt = (steady_state_temp - self.winding_temperature) / tau_thermal
        self.winding_temperature += dT_dt * dt
        
        # Mise à jour de l'efficacité basée sur la température
        temp_derating = 1.0 - max(0, (self.winding_temperature - 80) / 100)
        self.efficiency = self.efficiency * temp_derating
        
        # Dégradation de l'isolement
        self.update_insulation_degradation(conditions, dt)
        
        # Mise à jour de l'état
        self.state.timestamp = datetime.now()
        self.state.state_variables.update(electrical_params)
        self.state.state_variables.update({
            'winding_temperature': self.winding_temperature,
            'insulation_resistance': self.insulation_resistance,
            'power_factor': self.power_factor,
            'efficiency': self.efficiency
        })
        
        # Bilan énergétique électrique
        self.state.energy_balance.update({
            'electrical_input': electrical_params['active_power'],
            'electrical_losses': electrical_params['total_losses'],
            'mechanical_output': electrical_params['active_power'] - electrical_params['total_losses']
        })
        
        # Indicateurs d'efficacité
        self.state.efficiency_metrics.update({
            'electrical_efficiency': self.efficiency,
            'power_factor': self.power_factor,
            'load_factor': conditions.electrical_current / self.rated_current if self.rated_current > 0 else 0.0
        })
        
        # Historique de puissance
        self.power_history.append({
            'timestamp': datetime.now(),
            'active_power': electrical_params['active_power'],
            'efficiency': self.efficiency
        })
        
        if len(self.power_history) > 1000:
            self.power_history.pop(0)
        
        return self.state
    
    def get_health_indicators(self) -> Dict[str, float]:
        """Calcule les indicateurs de santé électrique."""
        indicators = {}
        
        # Résistance d'isolement critique
        if self.insulation_resistance < 1e5:  # Seuil critique 100kΩ
            indicators['insulation_degradation'] = 1.0 - (self.insulation_resistance / 1e5)
        else:
            indicators['insulation_degradation'] = 0.0
        
        # Surchauffe des bobinages
        if self.winding_temperature > 100:  # Classe thermique B
            indicators['thermal_overload'] = min(1.0, (self.winding_temperature - 100) / 50)
        else:
            indicators['thermal_overload'] = 0.0
        
        # Efficacité dégradée
        nominal_efficiency = 0.90
        if self.efficiency < nominal_efficiency:
            indicators['efficiency_loss'] = (nominal_efficiency - self.efficiency) / nominal_efficiency
        else:
            indicators['efficiency_loss'] = 0.0
        
        # Instabilité de puissance
        if len(self.power_history) > 10:
            recent_powers = [point['active_power'] for point in self.power_history[-10:]]
            power_variance = np.var(recent_powers)
            mean_power = np.mean(recent_powers)
            if mean_power > 0:
                cv = np.sqrt(power_variance) / mean_power  # Coefficient de variation
                indicators['power_instability'] = min(1.0, cv * 10)
            else:
                indicators['power_instability'] = 0.0
        else:
            indicators['power_instability'] = 0.0
        
        return indicators
    
    def predict_future_state(self, time_horizon: float) -> List[SimulationState]:
        """Prédit l'évolution électrique future."""
        future_states = []
        dt = 300  # Pas de 5 minutes
        steps = int(time_horizon * 3600 / dt)
        
        current_insulation = self.insulation_resistance
        current_efficiency = self.efficiency
        
        for i in range(steps):
            # Modèle de dégradation de l'isolant
            degradation_rate = 1e-6  # Taux de dégradation horaire
            projected_insulation = current_insulation * (1 - degradation_rate * i * dt / 3600)
            projected_insulation = max(1000, projected_insulation)
            
            # Évolution de l'efficacité
            efficiency_loss_rate = 1e-5  # Perte d'efficacité horaire
            projected_efficiency = current_efficiency * (1 - efficiency_loss_rate * i * dt / 3600)
            projected_efficiency = max(0.5, projected_efficiency)
            
            # État futur
            future_state = SimulationState(
                timestamp=datetime.now() + timedelta(seconds=i * dt),
                equipment_id=self.name
            )
            
            future_state.state_variables.update({
                'insulation_resistance': projected_insulation,
                'efficiency': projected_efficiency,
                'predicted': True
            })
            
            # Probabilités de défaillance
            insulation_risk = 1.0 - (projected_insulation / 1e6)
            efficiency_risk = 1.0 - (projected_efficiency / 0.9)
            
            future_state.fault_probabilities.update({
                'insulation_failure': min(1.0, max(0.0, insulation_risk)),
                'efficiency_degradation': min(1.0, max(0.0, efficiency_risk))
            })
            
            future_states.append(future_state)
        
        return future_states

class DigitalTwinEngine:
    """Moteur principal du jumeau numérique."""
    
    def __init__(self, config_path: str = "digital_twin_config.json"):
        """Initialise le moteur du jumeau numérique."""
        self.config = self.load_config(config_path)
        self.models = {}  # Dictionnaire des modèles physiques
        self.simulation_time = 0.0
        self.time_step = self.config.get('time_step', 1.0)  # Pas de temps par défaut
        self.real_time_mode = self.config.get('real_time_mode', True)
        
        # Historique des états
        self.state_history = []
        self.max_history_size = self.config.get('max_history_size', 10000)
        
        # Thread pour la simulation en temps réel
        self.simulation_thread = None
        self.running = False
        
        # Statistiques
        self.simulation_stats = {
            'total_simulations': 0,
            'average_step_time': 0.0,
            'last_update': datetime.now()
        }
        
        logger.info("Moteur de jumeau numérique initialisé")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration du jumeau numérique."""
        default_config = {
            'time_step': 1.0,
            'real_time_mode': True,
            'max_history_size': 10000,
            'models': {
                'pump_001': {
                    'type': 'rotating_equipment',
                    'thermal_model': True,
                    'mechanical_model': True,
                    'electrical_model': True,
                    'properties': {
                        'mass': 50.0,
                        'density': 7800.0,
                        'specific_heat': 460.0,
                        'thermal_conductivity': 50.0,
                        'electrical_resistance': 0.5,
                        'surface_area': 2.0,
                        'volume': 0.006
                    }
                }
            },
            'simulation': {
                'solver': 'runge_kutta',
                'tolerance': 1e-6,
                'max_iterations': 1000
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Fusion avec la configuration par défaut
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
            else:
                config = default_config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la config: {e}")
            config = default_config
        
        return config
    
    def add_equipment(self, equipment_id: str, equipment_type: str, 
                     properties: PhysicalProperties) -> bool:
        """Ajoute un équipement au jumeau numérique."""
        try:
            models_for_equipment = {}
            
            # Création des modèles selon le type d'équipement
            if equipment_type in ['rotating_equipment', 'pump', 'motor', 'compressor']:
                # Modèle thermique
                thermal_model = ThermalModel(f"{equipment_id}_thermal", properties)
                models_for_equipment['thermal'] = thermal_model
                
                # Modèle mécanique
                mechanical_model = MechanicalModel(f"{equipment_id}_mechanical", properties)
                models_for_equipment['mechanical'] = mechanical_model
                
                # Modèle électrique
                electrical_model = ElectricalModel(f"{equipment_id}_electrical", properties)
                models_for_equipment['electrical'] = electrical_model
            
            elif equipment_type in ['heat_exchanger', 'boiler']:
                # Uniquement modèle thermique pour les échangeurs
                thermal_model = ThermalModel(f"{equipment_id}_thermal", properties)
                models_for_equipment['thermal'] = thermal_model
            
            elif equipment_type in ['electrical_panel', 'transformer']:
                # Uniquement modèle électrique
                electrical_model = ElectricalModel(f"{equipment_id}_electrical", properties)
                models_for_equipment['electrical'] = electrical_model
            
            # Stockage des modèles
            self.models[equipment_id] = models_for_equipment
            
            logger.info(f"Équipement {equipment_id} ajouté avec {len(models_for_equipment)} modèles")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de l'équipement {equipment_id}: {e}")
            return False
    
    def update_equipment_conditions(self, equipment_id: str, 
                                   conditions: OperatingConditions) -> bool:
        """Met à jour les conditions opérationnelles d'un équipement."""
        try:
            if equipment_id not in self.models:
                logger.warning(f"Équipement {equipment_id} non trouvé")
                return False
            
            # Mise à jour de tous les modèles de l'équipement
            equipment_models = self.models[equipment_id]
            combined_state = SimulationState(
                timestamp=datetime.now(),
                equipment_id=equipment_id
            )
            
            for model_type, model in equipment_models.items():
                state = model.update_state(self.time_step, conditions)
                
                # Combinaison des états
                combined_state.state_variables.update(state.state_variables)
                combined_state.derivatives.update(state.derivatives)
                combined_state.energy_balance.update(state.energy_balance)
                combined_state.wear_indicators.update(state.wear_indicators)
                combined_state.efficiency_metrics.update(state.efficiency_metrics)
                combined_state.fault_probabilities.update(state.fault_probabilities)
            
            # Stockage dans l'historique
            self.state_history.append({
                'equipment_id': equipment_id,
                'timestamp': datetime.now(),
                'state': combined_state,
                'conditions': conditions
            })
            
            # Limitation de la taille de l'historique
            if len(self.state_history) > self.max_history_size:
                self.state_history.pop(0)
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur mise à jour équipement {equipment_id}: {e}")
            return False
    
    def get_equipment_health(self, equipment_id: str) -> Dict[str, Any]:
        """Obtient l'état de santé d'un équipement."""
        try:
            if equipment_id not in self.models:
                return {'error': 'Équipement non trouvé'}
            
            health_summary = {
                'equipment_id': equipment_id,
                'timestamp': datetime.now(),
                'overall_health': 1.0,
                'indicators': {},
                'recommendations': []
            }
            
            all_indicators = {}
            
            # Collecte des indicateurs de tous les modèles
            for model_type, model in self.models[equipment_id].items():
                model_indicators = model.get_health_indicators()
                for key, value in model_indicators.items():
                    all_indicators[f"{model_type}_{key}"] = value
            
            health_summary['indicators'] = all_indicators
            
            # Calcul de la santé globale (moyenne pondérée)
            if all_indicators:
                # Indicateurs critiques ont plus de poids
                critical_indicators = [k for k in all_indicators.keys() 
                                     if any(word in k.lower() for word in 
                                           ['overload', 'degradation', 'failure'])]
                
                total_weight = 0
                weighted_sum = 0
                
                for key, value in all_indicators.items():
                    weight = 2.0 if key in critical_indicators else 1.0
                    weighted_sum += (1.0 - value) * weight  # Inverser car 0 = bon état
                    total_weight += weight
                
                if total_weight > 0:
                    health_summary['overall_health'] = max(0.0, weighted_sum / total_weight)
            
            # Génération de recommandations
            recommendations = []
            for key, value in all_indicators.items():
                if value > 0.7:  # Seuil critique
                    if 'thermal' in key:
                        recommendations.append("Vérifier le système de refroidissement")
                    elif 'mechanical' in key:
                        recommendations.append("Planifier maintenance mécanique")
                    elif 'electrical' in key:
                        recommendations.append("Inspecter les connexions électriques")
            
            if health_summary['overall_health'] < 0.5:
                recommendations.append("URGENT: Arrêt d'équipement recommandé")
            elif health_summary['overall_health'] < 0.7:
                recommendations.append("Maintenance préventive requise")
            
            health_summary['recommendations'] = recommendations
            
            return health_summary
            
        except Exception as e:
            logger.error(f"Erreur calcul santé équipement {equipment_id}: {e}")
            return {'error': str(e)}
    
    def predict_equipment_future(self, equipment_id: str, 
                               time_horizon_hours: float) -> Dict[str, Any]:
        """Prédit l'état futur d'un équipement."""
        try:
            if equipment_id not in self.models:
                return {'error': 'Équipement non trouvé'}
            
            predictions = {
                'equipment_id': equipment_id,
                'prediction_horizon': time_horizon_hours,
                'generated_at': datetime.now(),
                'future_states': {},
                'maintenance_schedule': [],
                'risk_assessment': {}
            }
            
            # Prédictions pour chaque modèle
            for model_type, model in self.models[equipment_id].items():
                future_states = model.predict_future_state(time_horizon_hours)
                predictions['future_states'][model_type] = [
                    {
                        'timestamp': state.timestamp,
                        'state_variables': state.state_variables,
                        'wear_indicators': state.wear_indicators,
                        'fault_probabilities': state.fault_probabilities
                    } for state in future_states
                ]
            
            # Analyse des risques futurs
            risk_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            
            for model_type, states in predictions['future_states'].items():
                for state in states:
                    # Analyse des probabilités de défaillance
                    max_fault_prob = max(state['fault_probabilities'].values()) if state['fault_probabilities'] else 0.0
                    
                    if max_fault_prob > 0.8:
                        risk_levels['critical'] += 1
                    elif max_fault_prob > 0.6:
                        risk_levels['high'] += 1
                    elif max_fault_prob > 0.4:
                        risk_levels['medium'] += 1
                    else:
                        risk_levels['low'] += 1
            
            predictions['risk_assessment'] = risk_levels
            
            # Programmation de maintenance préventive
            maintenance_tasks = []
            
            # Analyse des indicateurs d'usure futurs
            for model_type, states in predictions['future_states'].items():
                if states:
                    final_state = states[-1]
                    wear_indicators = final_state.get('wear_indicators', {})
                    
                    for indicator, value in wear_indicators.items():
                        if value < 0.3:  # Seuil de maintenance préventive
                            estimated_time = time_horizon_hours * (1 - value)  # Estimation
                            maintenance_tasks.append({
                                'task': f"Maintenance {indicator}",
                                'estimated_time_hours': estimated_time,
                                'priority': 'high' if value < 0.2 else 'medium',
                                'model_type': model_type
                            })
            
            predictions['maintenance_schedule'] = sorted(maintenance_tasks, 
                                                       key=lambda x: x['estimated_time_hours'])
            
            return predictions
            
        except Exception as e:
            logger.error(f"Erreur prédiction équipement {equipment_id}: {e}")
            return {'error': str(e)}
    
    def start_real_time_simulation(self):
        """Démarre la simulation en temps réel."""
        if self.running:
            logger.warning("Simulation déjà en cours")
            return
        
        self.running = True
        self.simulation_thread = threading.Thread(target=self._simulation_loop)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()
        
        logger.info("Simulation temps réel démarrée")
    
    def stop_real_time_simulation(self):
        """Arrête la simulation en temps réel."""
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=5.0)
        
        logger.info("Simulation temps réel arrêtée")
    
    def _simulation_loop(self):
        """Boucle principale de simulation."""
        while self.running:
            start_time = time.time()
            
            # Mise à jour de tous les équipements avec leurs dernières conditions
            # (ici on utiliserait les données des capteurs IoT réels)
            for equipment_id in self.models.keys():
                # Conditions par défaut pour la démo
                default_conditions = OperatingConditions(
                    temperature=25.0 + np.random.normal(0, 2),
                    rotational_speed=1800 + np.random.normal(0, 50),
                    electrical_voltage=240 + np.random.normal(0, 5),
                    electrical_current=10 + np.random.normal(0, 1),
                    load_force=1000 + np.random.normal(0, 100)
                )
                
                self.update_equipment_conditions(equipment_id, default_conditions)
            
            # Statistiques de performance
            step_time = time.time() - start_time
            self.simulation_stats['total_simulations'] += 1
            self.simulation_stats['average_step_time'] = (
                self.simulation_stats['average_step_time'] * 0.9 + step_time * 0.1
            )
            self.simulation_stats['last_update'] = datetime.now()
            
            # Attendre pour respecter le pas de temps
            sleep_time = max(0, self.time_step - step_time)
            time.sleep(sleep_time)
    
    def get_simulation_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques de simulation."""
        return {
            **self.simulation_stats,
            'equipment_count': len(self.models),
            'history_size': len(self.state_history),
            'running': self.running,
            'time_step': self.time_step
        }
    
    def export_historical_data(self, equipment_id: str = None, 
                              start_time: datetime = None, 
                              end_time: datetime = None) -> pd.DataFrame:
        """Exporte les données historiques en DataFrame."""
        try:
            # Filtrage des données
            filtered_data = []
            
            for record in self.state_history:
                # Filtre par équipement
                if equipment_id and record['equipment_id'] != equipment_id:
                    continue
                
                # Filtre par temps
                record_time = record['timestamp']
                if start_time and record_time < start_time:
                    continue
                if end_time and record_time > end_time:
                    continue
                
                # Préparation des données pour DataFrame
                row_data = {
                    'equipment_id': record['equipment_id'],
                    'timestamp': record['timestamp']
                }
                
                # Ajout des variables d'état
                state = record['state']
                row_data.update(state.state_variables)
                row_data.update(state.energy_balance)
                row_data.update(state.wear_indicators)
                row_data.update(state.efficiency_metrics)
                
                # Conditions opérationnelles
                conditions = record['conditions']
                row_data.update({
                    'operating_temperature': conditions.temperature,
                    'operating_pressure': conditions.pressure,
                    'operating_voltage': conditions.electrical_voltage,
                    'operating_current': conditions.electrical_current,
                    'operating_speed': conditions.rotational_speed
                })
                
                filtered_data.append(row_data)
            
            # Création du DataFrame
            if filtered_data:
                df = pd.DataFrame(filtered_data)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df.set_index('timestamp', inplace=True)
                return df
            else:
                return pd.DataFrame()
                
        except Exception as e:
            logger.error(f"Erreur export données: {e}")
            return pd.DataFrame()

# Fonction de test et démonstration
async def main():
    """Démonstration du moteur de jumeau numérique."""
    
    # Initialisation du moteur
    engine = DigitalTwinEngine()
    
    # Propriétés d'une pompe industrielle
    pump_properties = PhysicalProperties(
        mass=45.0,  # kg
        density=7800.0,  # kg/m³ (acier)
        specific_heat=460.0,  # J/(kg·K)
        thermal_conductivity=50.0,  # W/(m·K)
        electrical_resistance=0.8,  # Ω
        mechanical_stiffness=1e6,  # N/m
        surface_area=1.5,  # m²
        volume=0.005,  # m³
        moment_of_inertia=0.2  # kg·m²
    )
    
    # Ajout d'équipements
    equipment_list = [
        ('PUMP_001', 'rotating_equipment'),
        ('MOTOR_001', 'rotating_equipment'),
        ('HEAT_EXCHANGER_001', 'heat_exchanger')
    ]
    
    print("=== Initialisation du Jumeau Numérique ===")
    for equipment_id, equipment_type in equipment_list:
        success = engine.add_equipment(equipment_id, equipment_type, pump_properties)
        print(f"Équipement {equipment_id}: {'✓' if success else '✗'}")
    
    # Démarrage de la simulation temps réel
    print("\n=== Démarrage de la Simulation ===")
    engine.start_real_time_simulation()
    
    # Simulation de conditions opérationnelles variables
    print("Simulation de conditions variables...")
    
    for i in range(10):
        # Conditions variables pour tester le comportement
        conditions = OperatingConditions(
            temperature=20 + i * 5,  # Température croissante
            pressure=101325 + np.random.normal(0, 1000),
            electrical_voltage=240 + np.random.normal(0, 10),
            electrical_current=8 + np.random.normal(0, 2),
            rotational_speed=1800 + i * 100,  # Vitesse croissante
            load_force=800 + i * 200  # Charge croissante
        )
        
        # Mise à jour des conditions pour tous les équipements
        for equipment_id, _ in equipment_list:
            engine.update_equipment_conditions(equipment_id, conditions)
        
        # Attendre un peu pour voir l'évolution
        await asyncio.sleep(2)
        
        # Affichage de l'état de santé
        if i % 3 == 0:  # Tous les 3 pas
            print(f"\n--- Étape {i+1} ---")
            for equipment_id, _ in equipment_list:
                health = engine.get_equipment_health(equipment_id)
                if 'overall_health' in health:
                    health_pct = health['overall_health'] * 100
                    print(f"{equipment_id}: Santé {health_pct:.1f}%")
                    
                    # Afficher les recommandations si nécessaire
                    if health['recommendations']:
                        for rec in health['recommendations'][:2]:  # Max 2 recommandations
                            print(f"  → {rec}")
    
    print("\n=== Analyse Prédictive ===")
    # Test des prédictions
    for equipment_id, _ in equipment_list[:2]:  # Seulement les 2 premiers
        predictions = engine.predict_equipment_future(equipment_id, 24.0)  # 24 heures
        
        if 'maintenance_schedule' in predictions:
            print(f"\nPrédictions pour {equipment_id}:")
            maintenance_tasks = predictions['maintenance_schedule']
            
            if maintenance_tasks:
                print("  Maintenance programmée:")
                for task in maintenance_tasks[:3]:  # Top 3
                    hours = task['estimated_time_hours']
                    print(f"    - {task['task']}: dans {hours:.1f}h ({task['priority']})")
            else:
                print("  Aucune maintenance prévue")
            
            # Évaluation des risques
            risks = predictions['risk_assessment']
            total_assessments = sum(risks.values())
            if total_assessments > 0:
                critical_pct = risks['critical'] / total_assessments * 100
                high_pct = risks['high'] / total_assessments * 100
                print(f"  Risques: {critical_pct:.1f}% critiques, {high_pct:.1f}% élevés")
    
    print("\n=== Export des Données ===")
    # Export des données historiques
    df = engine.export_historical_data('PUMP_001')
    if not df.empty:
        print(f"Données exportées: {len(df)} enregistrements")
        print(f"Colonnes disponibles: {len(df.columns)}")
        print(f"Période: {df.index.min()} à {df.index.max()}")
        
        # Statistiques de base
        if 'internal_temperature' in df.columns:
            temp_stats = df['internal_temperature'].describe()
            print(f"Température: {temp_stats['min']:.1f}°C à {temp_stats['max']:.1f}°C")
    
    print("\n=== Statistiques de Simulation ===")
    stats = engine.get_simulation_statistics()
    print(f"Simulations totales: {stats['total_simulations']}")
    print(f"Temps moyen par pas: {stats['average_step_time']:.3f}s")
    print(f"Équipements: {stats['equipment_count']}")
    print(f"Historique: {stats['history_size']} enregistrements")
    
    # Arrêt de la simulation
    print("\nArrêt de la simulation...")
    engine.stop_real_time_simulation()
    print("✓ Simulation arrêtée")

if __name__ == "__main__":
    asyncio.run(main())