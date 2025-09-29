#!/usr/bin/env python3
"""
Projet 25 - Plateforme IoT AI Station Traffeyère
Composant 5D: Interface de Visualisation 3D Interactive du Jumeau Numérique

Interface de visualisation 3D avancée avec rendu temps réel, contrôles immersifs,
tableaux de bord interactifs et intégration WebGL pour une expérience utilisateur
riche du jumeau numérique industriel.

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
import base64
from io import BytesIO
import math

# Visualisation 3D et WebGL
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo
from plotly.graph_objs import Scatter3d, Surface, Mesh3d
import plotly.io as pio

# Dashboard et interfaces web
import dash
from dash import dcc, html, Input, Output, State, callback_context, no_update
import dash_bootstrap_components as dbc
import dash_daq as daq
from dash.exceptions import PreventUpdate

# Traitement d'images et génération 3D
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.animation as animation
from matplotlib.colors import LinearSegmentedColormap
import seaborn as sns

# Géométrie et calculs 3D
from scipy.spatial.transform import Rotation
from scipy import ndimage
import cv2
from PIL import Image

# Streaming et communication temps réel
import websockets
import aiohttp
from aiohttp import web, WSMsgType
import socketio
from flask import Flask
from flask_socketio import SocketIO, emit

# Utilitaires
import warnings
warnings.filterwarnings('ignore')

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Equipment3DModel:
    """Modèle 3D d'équipement industriel."""
    equipment_id: str
    equipment_type: str
    position: Tuple[float, float, float]
    rotation: Tuple[float, float, float]  # Angles Euler en degrés
    scale: Tuple[float, float, float] = (1.0, 1.0, 1.0)
    color: str = '#3498db'
    opacity: float = 0.8
    mesh_data: Dict[str, Any] = field(default_factory=dict)
    animations: List[Dict[str, Any]] = field(default_factory=list)
    sensors_positions: List[Tuple[float, float, float]] = field(default_factory=list)

@dataclass
class VisualizationState:
    """État de visualisation 3D."""
    camera_position: Tuple[float, float, float] = (10, 10, 10)
    camera_target: Tuple[float, float, float] = (0, 0, 0)
    lighting_intensity: float = 1.0
    show_sensors: bool = True
    show_data_flows: bool = True
    show_anomalies: bool = True
    animation_speed: float = 1.0
    current_timestamp: datetime = field(default_factory=datetime.now)
    selected_equipment: Optional[str] = None

class Equipment3DGenerator:
    """Générateur de modèles 3D d'équipements industriels."""
    
    def __init__(self):
        self.equipment_templates = {
            'pump': self._generate_pump_model,
            'motor': self._generate_motor_model,
            'heat_exchanger': self._generate_heat_exchanger_model,
            'valve': self._generate_valve_model,
            'tank': self._generate_tank_model,
            'pipe': self._generate_pipe_model
        }
    
    def _generate_pump_model(self, equipment_id: str, position: Tuple[float, float, float]) -> Equipment3DModel:
        """Génère un modèle 3D de pompe centrifuge."""
        # Corps principal de la pompe (cylindre)
        theta = np.linspace(0, 2*np.pi, 20)
        z_pump = np.linspace(-1, 1, 10)
        
        # Géométrie cylindrique
        theta_mesh, z_mesh = np.meshgrid(theta, z_pump)
        x_mesh = 2 * np.cos(theta_mesh)
        y_mesh = 2 * np.sin(theta_mesh)
        
        # Volute (spirale externe)
        spiral_factor = 1 + 0.3 * theta_mesh / (2*np.pi)
        x_volute = spiral_factor * x_mesh
        y_volute = spiral_factor * y_mesh
        
        mesh_data = {
            'main_body': {
                'x': x_volute + position[0],
                'y': y_volute + position[1], 
                'z': z_mesh + position[2],
                'type': 'surface',
                'color': '#e74c3c'
            },
            'inlet_pipe': {
                'x': [position[0], position[0]],
                'y': [position[1] - 3, position[1] - 1],
                'z': [position[2], position[2]],
                'type': 'cylinder',
                'radius': 0.8,
                'color': '#34495e'
            },
            'outlet_pipe': {
                'x': [position[0] + 2, position[0] + 4],
                'y': [position[1], position[1]],
                'z': [position[2], position[2]],
                'type': 'cylinder', 
                'radius': 0.6,
                'color': '#34495e'
            }
        }
        
        # Positions des capteurs
        sensor_positions = [
            (position[0] + 2.5, position[1], position[2] + 1),  # Température
            (position[0], position[1] + 2.5, position[2]),      # Pression
            (position[0] - 2, position[1], position[2]),        # Vibration
            (position[0], position[1], position[2] - 1.5)       # Débit
        ]
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type='pump',
            position=position,
            rotation=(0, 0, 0),
            color='#e74c3c',
            mesh_data=mesh_data,
            sensors_positions=sensor_positions
        )
    
    def _generate_motor_model(self, equipment_id: str, position: Tuple[float, float, float]) -> Equipment3DModel:
        """Génère un modèle 3D de moteur électrique."""
        # Corps du moteur (cylindre principal)
        theta = np.linspace(0, 2*np.pi, 16)
        z_motor = np.linspace(-2, 2, 8)
        
        theta_mesh, z_mesh = np.meshgrid(theta, z_motor)
        x_mesh = 1.5 * np.cos(theta_mesh)
        y_mesh = 1.5 * np.sin(theta_mesh)
        
        # Boîte de connexions
        connection_box = {
            'x': np.array([0.5, 2, 2, 0.5, 0.5, 2, 2, 0.5]) + position[0],
            'y': np.array([1.5, 1.5, 2.5, 2.5, 1.5, 1.5, 2.5, 2.5]) + position[1],
            'z': np.array([0.5, 0.5, 0.5, 0.5, 1.5, 1.5, 1.5, 1.5]) + position[2]
        }
        
        mesh_data = {
            'motor_body': {
                'x': x_mesh + position[0],
                'y': y_mesh + position[1],
                'z': z_mesh + position[2],
                'type': 'surface',
                'color': '#3498db'
            },
            'connection_box': {
                'vertices': connection_box,
                'type': 'mesh',
                'color': '#95a5a6'
            },
            'shaft': {
                'x': [position[0], position[0]],
                'y': [position[1], position[1]],
                'z': [position[2] - 3, position[2] + 3],
                'type': 'cylinder',
                'radius': 0.3,
                'color': '#7f8c8d'
            }
        }
        
        # Capteurs moteur
        sensor_positions = [
            (position[0] + 1.8, position[1], position[2]),       # Température bobinage
            (position[0], position[1] + 1.8, position[2]),       # Vibration
            (position[0] + 2.2, position[1] + 1.5, position[2]), # Courant
            (position[0] - 1.8, position[1], position[2])        # Vitesse
        ]
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type='motor',
            position=position,
            rotation=(0, 0, 0),
            color='#3498db',
            mesh_data=mesh_data,
            sensors_positions=sensor_positions
        )
    
    def _generate_heat_exchanger_model(self, equipment_id: str, position: Tuple[float, float, float]) -> Equipment3DModel:
        """Génère un modèle 3D d'échangeur de chaleur."""
        # Coque principale (cylindre horizontal)
        theta = np.linspace(0, 2*np.pi, 24)
        x_hx = np.linspace(-3, 3, 12)
        
        theta_mesh, x_mesh = np.meshgrid(theta, x_hx)
        y_mesh = 1.8 * np.cos(theta_mesh)
        z_mesh = 1.8 * np.sin(theta_mesh)
        
        # Faisceaux tubulaires (représentés par des lignes internes)
        num_tubes = 37  # Configuration réaliste
        tube_positions = []
        
        # Arrangement hexagonal des tubes
        for ring in range(4):
            for i in range(max(1, 6 * ring)):
                if ring == 0:
                    r, angle = 0, 0
                else:
                    r = ring * 0.4
                    angle = i * 2 * np.pi / (6 * ring)
                
                y_tube = r * np.cos(angle)
                z_tube = r * np.sin(angle)
                tube_positions.append((y_tube, z_tube))
        
        mesh_data = {
            'shell': {
                'x': x_mesh + position[0],
                'y': y_mesh + position[1],
                'z': z_mesh + position[2],
                'type': 'surface',
                'color': '#e67e22'
            },
            'tubes': {
                'positions': tube_positions,
                'length': 6,
                'radius': 0.05,
                'type': 'tube_bundle',
                'color': '#bdc3c7'
            },
            'inlet_hot': {
                'x': [position[0] - 4, position[0] - 3],
                'y': [position[1], position[1]],
                'z': [position[2] + 2.2, position[2] + 2.2],
                'type': 'cylinder',
                'radius': 0.4,
                'color': '#e74c3c'
            },
            'outlet_hot': {
                'x': [position[0] + 3, position[0] + 4],
                'y': [position[1], position[1]],
                'z': [position[2] + 2.2, position[2] + 2.2],
                'type': 'cylinder',
                'radius': 0.4,
                'color': '#e74c3c'
            },
            'inlet_cold': {
                'x': [position[0] + 3, position[0] + 4],
                'y': [position[1], position[1]],
                'z': [position[2] - 2.2, position[2] - 2.2],
                'type': 'cylinder',
                'radius': 0.35,
                'color': '#3498db'
            },
            'outlet_cold': {
                'x': [position[0] - 4, position[0] - 3],
                'y': [position[1], position[1]],
                'z': [position[2] - 2.2, position[2] - 2.2],
                'type': 'cylinder',
                'radius': 0.35,
                'color': '#3498db'
            }
        }
        
        # Capteurs échangeur
        sensor_positions = [
            (position[0] - 3.5, position[1], position[2] + 2.5), # T entrée chaude
            (position[0] + 3.5, position[1], position[2] + 2.5), # T sortie chaude  
            (position[0] + 3.5, position[1], position[2] - 2.5), # T entrée froide
            (position[0] - 3.5, position[1], position[2] - 2.5), # T sortie froide
            (position[0], position[1], position[2] + 2),          # Pression
            (position[0], position[1] + 2, position[2])           # Débit
        ]
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type='heat_exchanger',
            position=position,
            rotation=(0, 0, 90),  # Horizontal
            color='#e67e22',
            mesh_data=mesh_data,
            sensors_positions=sensor_positions
        )
    
    def _generate_valve_model(self, equipment_id: str, position: Tuple[float, float, float]) -> Equipment3DModel:
        """Génère un modèle 3D de vanne."""
        # Corps de vanne
        mesh_data = {
            'body': {
                'vertices': np.array([
                    [-0.8, -0.8, -0.5], [0.8, -0.8, -0.5], [0.8, 0.8, -0.5], [-0.8, 0.8, -0.5],
                    [-0.8, -0.8, 0.5], [0.8, -0.8, 0.5], [0.8, 0.8, 0.5], [-0.8, 0.8, 0.5]
                ]) + position,
                'type': 'mesh',
                'color': '#9b59b6'
            },
            'actuator': {
                'x': [position[0], position[0]],
                'y': [position[1], position[1]],
                'z': [position[2] + 0.5, position[2] + 2],
                'type': 'cylinder',
                'radius': 0.3,
                'color': '#8e44ad'
            }
        }
        
        sensor_positions = [
            (position[0], position[1], position[2] + 2.5),    # Position vanne
            (position[0] + 1, position[1], position[2])       # Débit
        ]
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type='valve',
            position=position,
            rotation=(0, 0, 0),
            color='#9b59b6',
            mesh_data=mesh_data,
            sensors_positions=sensor_positions
        )
    
    def _generate_tank_model(self, equipment_id: str, position: Tuple[float, float, float]) -> Equipment3DModel:
        """Génère un modèle 3D de réservoir."""
        # Réservoir cylindrique vertical
        theta = np.linspace(0, 2*np.pi, 20)
        z_tank = np.linspace(-2, 2, 15)
        
        theta_mesh, z_mesh = np.meshgrid(theta, z_tank)
        x_mesh = 2.5 * np.cos(theta_mesh)
        y_mesh = 2.5 * np.sin(theta_mesh)
        
        mesh_data = {
            'shell': {
                'x': x_mesh + position[0],
                'y': y_mesh + position[1],
                'z': z_mesh + position[2],
                'type': 'surface',
                'color': '#27ae60'
            },
            'top_head': {
                'center': (position[0], position[1], position[2] + 2),
                'radius': 2.5,
                'type': 'sphere_section',
                'color': '#27ae60'
            },
            'bottom_head': {
                'center': (position[0], position[1], position[2] - 2),
                'radius': 2.5,
                'type': 'sphere_section',
                'color': '#27ae60'
            }
        }
        
        sensor_positions = [
            (position[0] + 2.8, position[1], position[2] + 1),    # Niveau
            (position[0] + 2.8, position[1], position[2]),        # Pression
            (position[0] + 2.8, position[1], position[2] - 1),    # Température
        ]
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type='tank',
            position=position,
            rotation=(0, 0, 0),
            color='#27ae60',
            mesh_data=mesh_data,
            sensors_positions=sensor_positions
        )
    
    def _generate_pipe_model(self, start: Tuple[float, float, float], 
                           end: Tuple[float, float, float], pipe_id: str) -> Equipment3DModel:
        """Génère un modèle 3D de tuyauterie."""
        # Calcul direction et longueur
        direction = np.array(end) - np.array(start)
        length = np.linalg.norm(direction)
        direction_norm = direction / length
        
        # Génération segments de pipe
        num_segments = max(int(length * 2), 5)
        t = np.linspace(0, 1, num_segments)
        
        pipe_points = []
        for ti in t:
            point = np.array(start) + ti * direction
            pipe_points.append(point)
        
        mesh_data = {
            'pipe_segments': {
                'points': pipe_points,
                'radius': 0.2,
                'type': 'tube_path',
                'color': '#7f8c8d'
            }
        }
        
        center_position = ((start[0] + end[0])/2, (start[1] + end[1])/2, (start[2] + end[2])/2)
        
        return Equipment3DModel(
            equipment_id=pipe_id,
            equipment_type='pipe',
            position=center_position,
            rotation=(0, 0, 0),
            color='#7f8c8d',
            mesh_data=mesh_data,
            sensors_positions=[]
        )
    
    def generate_equipment(self, equipment_type: str, equipment_id: str, 
                         position: Tuple[float, float, float], **kwargs) -> Equipment3DModel:
        """Génère un équipement 3D selon son type."""
        if equipment_type in self.equipment_templates:
            return self.equipment_templates[equipment_type](equipment_id, position)
        else:
            # Modèle générique (cube)
            return self._generate_generic_model(equipment_id, position, equipment_type)
    
    def _generate_generic_model(self, equipment_id: str, position: Tuple[float, float, float], 
                               equipment_type: str) -> Equipment3DModel:
        """Génère un modèle 3D générique."""
        mesh_data = {
            'generic_box': {
                'vertices': np.array([
                    [-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1],
                    [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]
                ]) + position,
                'type': 'mesh',
                'color': '#95a5a6'
            }
        }
        
        return Equipment3DModel(
            equipment_id=equipment_id,
            equipment_type=equipment_type,
            position=position,
            rotation=(0, 0, 0),
            color='#95a5a6',
            mesh_data=mesh_data,
            sensors_positions=[(position[0], position[1], position[2] + 1.5)]
        )

class RealTimeDataVisualizer:
    """Visualiseur de données temps réel en 3D."""
    
    def __init__(self):
        self.data_streams = {}
        self.animation_queue = []
        self.color_maps = {
            'temperature': 'RdYlBu_r',
            'pressure': 'Blues',
            'vibration': 'Reds',
            'flow': 'Greens',
            'anomaly': 'plasma'
        }
    
    def create_sensor_visualization(self, sensor_data: Dict[str, Any], 
                                  position: Tuple[float, float, float]) -> go.Scatter3d:
        """Crée une visualisation 3D de capteur."""
        sensor_type = sensor_data.get('type', 'generic')
        value = sensor_data.get('value', 0)
        quality = sensor_data.get('quality', 1.0)
        
        # Couleur basée sur la valeur et le type
        color_scale = self.color_maps.get(sensor_type, 'viridis')
        
        # Normalisation de la valeur pour la couleur
        if sensor_type == 'temperature':
            normalized_value = (value - 20) / 80  # 20-100°C range
        elif sensor_type == 'pressure':
            normalized_value = value / 10  # 0-10 bar range
        elif sensor_type == 'vibration':
            normalized_value = value / 5  # 0-5 mm/s range
        else:
            normalized_value = 0.5
        
        normalized_value = np.clip(normalized_value, 0, 1)
        
        # Taille basée sur la qualité
        size = 8 + quality * 12  # 8-20 pixels
        
        # Opacité basée sur la qualité
        opacity = 0.4 + quality * 0.6  # 0.4-1.0
        
        return go.Scatter3d(
            x=[position[0]],
            y=[position[1]], 
            z=[position[2]],
            mode='markers',
            marker=dict(
                size=size,
                color=normalized_value,
                colorscale=color_scale,
                opacity=opacity,
                line=dict(color='black', width=1)
            ),
            text=f"{sensor_type}: {value:.1f}",
            hoverinfo='text',
            showlegend=False
        )
    
    def create_data_flow_visualization(self, flow_data: Dict[str, Any]) -> List[go.Scatter3d]:
        """Crée une visualisation de flux de données 3D."""
        flows = []
        
        source = flow_data.get('source', (0, 0, 0))
        target = flow_data.get('target', (1, 1, 1))
        intensity = flow_data.get('intensity', 1.0)
        flow_type = flow_data.get('type', 'data')
        
        # Génération de la trajectoire du flux
        num_points = 20
        t = np.linspace(0, 1, num_points)
        
        # Trajectoire courbe pour plus de réalisme
        control_point = (
            (source[0] + target[0]) / 2,
            (source[1] + target[1]) / 2,
            max(source[2], target[2]) + 2
        )
        
        x_flow = []
        y_flow = []
        z_flow = []
        
        for ti in t:
            # Courbe de Bézier quadratique
            x = (1-ti)**2 * source[0] + 2*(1-ti)*ti * control_point[0] + ti**2 * target[0]
            y = (1-ti)**2 * source[1] + 2*(1-ti)*ti * control_point[1] + ti**2 * target[1]
            z = (1-ti)**2 * source[2] + 2*(1-ti)*ti * control_point[2] + ti**2 * target[2]
            
            x_flow.append(x)
            y_flow.append(y)
            z_flow.append(z)
        
        # Couleur basée sur l'intensité et le type
        color_map = {
            'data': 'lightblue',
            'alarm': 'red',
            'control': 'green',
            'energy': 'orange'
        }
        color = color_map.get(flow_type, 'gray')
        
        # Ligne de flux
        flow_line = go.Scatter3d(
            x=x_flow,
            y=y_flow,
            z=z_flow,
            mode='lines+markers',
            line=dict(
                color=color,
                width=max(2, intensity * 8),
                dash='solid' if flow_type == 'data' else 'dash'
            ),
            marker=dict(
                size=3,
                color=color,
                opacity=0.7
            ),
            showlegend=False
        )
        
        flows.append(flow_line)
        
        # Flèche directionnelle
        arrow_pos = len(x_flow) * 3 // 4  # 75% du chemin
        if arrow_pos < len(x_flow) - 1:
            # Direction de la flèche
            dx = x_flow[arrow_pos + 1] - x_flow[arrow_pos]
            dy = y_flow[arrow_pos + 1] - y_flow[arrow_pos]
            dz = z_flow[arrow_pos + 1] - z_flow[arrow_pos]
            
            # Normalisation
            length = math.sqrt(dx**2 + dy**2 + dz**2)
            if length > 0:
                dx, dy, dz = dx/length, dy/length, dz/length
                
                arrow = go.Cone(
                    x=[x_flow[arrow_pos] + dx * 0.5],
                    y=[y_flow[arrow_pos] + dy * 0.5],
                    z=[z_flow[arrow_pos] + dz * 0.5],
                    u=[dx], v=[dy], w=[dz],
                    sizemode="absolute",
                    sizeref=0.3 * intensity,
                    colorscale=[[0, color], [1, color]],
                    showscale=False
                )
                flows.append(arrow)
        
        return flows
    
    def create_anomaly_visualization(self, anomaly_data: Dict[str, Any], 
                                   position: Tuple[float, float, float]) -> go.Scatter3d:
        """Crée une visualisation d'anomalie 3D."""
        severity = anomaly_data.get('severity', 'low')
        confidence = anomaly_data.get('confidence', 0.5)
        anomaly_type = anomaly_data.get('type', 'unknown')
        
        # Couleur et taille basées sur la sévérité
        severity_config = {
            'low': {'color': 'yellow', 'size': 15},
            'medium': {'color': 'orange', 'size': 20},
            'high': {'color': 'red', 'size': 25},
            'critical': {'color': 'darkred', 'size': 30}
        }
        
        config = severity_config.get(severity, severity_config['low'])
        
        # Animation de clignotement pour les anomalies
        return go.Scatter3d(
            x=[position[0]],
            y=[position[1]],
            z=[position[2] + 1],  # Légèrement au-dessus
            mode='markers',
            marker=dict(
                size=config['size'],
                color=config['color'],
                opacity=0.6 + 0.4 * confidence,
                symbol='diamond',
                line=dict(color='black', width=2)
            ),
            text=f"⚠️ {anomaly_type.upper()}<br>Sévérité: {severity}<br>Confiance: {confidence:.1%}",
            hoverinfo='text',
            name='Anomalies',
            showlegend=False
        )
    
    def create_heatmap_overlay(self, equipment_model: Equipment3DModel, 
                             temperature_data: np.ndarray) -> go.Surface:
        """Crée une superposition de carte de chaleur sur l'équipement."""
        x, y, z = equipment_model.position
        
        # Grille autour de l'équipement
        grid_size = 20
        x_range = np.linspace(x - 3, x + 3, grid_size)
        y_range = np.linspace(y - 3, y + 3, grid_size)
        
        X, Y = np.meshgrid(x_range, y_range)
        
        # Génération de données de température simulées si pas de données réelles
        if temperature_data is None or temperature_data.size == 0:
            # Distance depuis le centre de l'équipement
            distance = np.sqrt((X - x)**2 + (Y - y)**2)
            # Température décroissante avec la distance
            Z_temp = 80 * np.exp(-distance / 2) + 20  # 20-100°C
        else:
            # Redimensionner les données réelles à la grille
            Z_temp = np.resize(temperature_data, (grid_size, grid_size))
        
        # Surface de température
        return go.Surface(
            x=X,
            y=Y,
            z=np.full_like(X, z + 0.1),  # Légèrement au-dessus
            surfacecolor=Z_temp,
            colorscale='RdYlBu_r',
            opacity=0.6,
            showscale=True,
            colorbar=dict(
                title="Température (°C)",
                x=0.95
            ),
            name="Température"
        )

class InteractiveDashboard:
    """Tableau de bord interactif 3D."""
    
    def __init__(self, port: int = 8050):
        self.port = port
        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
        self.equipment_generator = Equipment3DGenerator()
        self.data_visualizer = RealTimeDataVisualizer()
        self.visualization_state = VisualizationState()
        
        # Données simulées
        self.equipment_models = {}
        self.sensor_data = {}
        self.anomalies = {}
        
        # Configuration de l'interface
        self._setup_layout()
        self._setup_callbacks()
        
        logger.info(f"Dashboard 3D initialisé sur le port {port}")
    
    def _setup_layout(self):
        """Configure la mise en page du dashboard."""
        self.app.layout = dbc.Container([
            # En-tête
            dbc.Row([
                dbc.Col([
                    html.H1("🏭 Jumeau Numérique 3D - Station Traffeyère", 
                           className="text-center mb-4"),
                    html.Hr()
                ])
            ]),
            
            # Contrôles principaux
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🎮 Contrôles de Visualisation"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Équipements:"),
                                    dcc.Dropdown(
                                        id='equipment-selector',
                                        options=[],
                                        value=None,
                                        placeholder="Sélectionner un équipement"
                                    )
                                ], width=6),
                                dbc.Col([
                                    html.Label("Vue:"),
                                    dcc.Dropdown(
                                        id='view-selector',
                                        options=[
                                            {'label': '👁️ Vue Globale', 'value': 'global'},
                                            {'label': '🔍 Vue Détaillée', 'value': 'detailed'},
                                            {'label': '🌡️ Vue Thermique', 'value': 'thermal'},
                                            {'label': '⚡ Vue Énergétique', 'value': 'energy'}
                                        ],
                                        value='global'
                                    )
                                ], width=6)
                            ]),
                            html.Hr(),
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Affichage:"),
                                    dbc.Checklist(
                                        id='display-options',
                                        options=[
                                            {'label': '📊 Capteurs', 'value': 'sensors'},
                                            {'label': '🌊 Flux de données', 'value': 'flows'},
                                            {'label': '⚠️ Anomalies', 'value': 'anomalies'},
                                            {'label': '🌡️ Carte thermique', 'value': 'thermal'}
                                        ],
                                        value=['sensors', 'flows', 'anomalies'],
                                        inline=True
                                    )
                                ], width=12)
                            ]),
                            html.Hr(),
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Vitesse Animation:"),
                                    dcc.Slider(
                                        id='animation-speed',
                                        min=0.1, max=5.0, step=0.1,
                                        value=1.0,
                                        marks={i: f'{i}x' for i in [0.5, 1, 2, 3, 5]}
                                    )
                                ], width=6),
                                dbc.Col([
                                    html.Label("Intensité Éclairage:"),
                                    dcc.Slider(
                                        id='lighting-intensity',
                                        min=0.1, max=2.0, step=0.1,
                                        value=1.0,
                                        marks={i: f'{i}' for i in [0.5, 1, 1.5, 2]}
                                    )
                                ], width=6)
                            ])
                        ])
                    ])
                ], width=12)
            ], className="mb-4"),
            
            # Visualisation 3D principale
            dbc.Row([
                dbc.Col([
                    dcc.Graph(
                        id='main-3d-plot',
                        style={'height': '600px'},
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d'],
                            'toImageButtonOptions': {
                                'format': 'png',
                                'filename': 'jumeau_numerique_3d',
                                'height': 600,
                                'width': 1200,
                                'scale': 2
                            }
                        }
                    )
                ], width=9),
                
                # Panneau d'informations
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("📊 Informations en Temps Réel"),
                        dbc.CardBody([
                            html.Div(id='equipment-info'),
                            html.Hr(),
                            html.Div(id='sensor-readings'),
                            html.Hr(), 
                            html.Div(id='system-status')
                        ])
                    ])
                ], width=3)
            ]),
            
            # Métriques de performance
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("⚡ Métriques de Performance"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    daq.Gauge(
                                        id='efficiency-gauge',
                                        label="Efficacité Globale",
                                        value=85,
                                        max=100,
                                        min=0,
                                        showCurrentValue=True,
                                        color={"gradient": True, "ranges": {
                                            "red": [0, 50],
                                            "yellow": [50, 80], 
                                            "green": [80, 100]
                                        }}
                                    )
                                ], width=3),
                                dbc.Col([
                                    daq.Gauge(
                                        id='energy-gauge',
                                        label="Consommation Énergie",
                                        value=65,
                                        max=100,
                                        min=0,
                                        showCurrentValue=True,
                                        color={"gradient": True, "ranges": {
                                            "green": [0, 40],
                                            "yellow": [40, 70],
                                            "red": [70, 100]
                                        }}
                                    )
                                ], width=3),
                                dbc.Col([
                                    daq.Gauge(
                                        id='anomaly-gauge',
                                        label="Score Anomalies",
                                        value=15,
                                        max=100,
                                        min=0,
                                        showCurrentValue=True,
                                        color={"gradient": True, "ranges": {
                                            "green": [0, 20],
                                            "yellow": [20, 50],
                                            "red": [50, 100]
                                        }}
                                    )
                                ], width=3),
                                dbc.Col([
                                    daq.Gauge(
                                        id='health-gauge',
                                        label="Santé Système",
                                        value=92,
                                        max=100,
                                        min=0,
                                        showCurrentValue=True,
                                        color={"gradient": True, "ranges": {
                                            "red": [0, 60],
                                            "yellow": [60, 85],
                                            "green": [85, 100]
                                        }}
                                    )
                                ], width=3)
                            ])
                        ])
                    ])
                ], width=12)
            ], className="mt-4"),
            
            # Graphiques temporels
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id='time-series-plot', style={'height': '300px'})
                ], width=6),
                dbc.Col([
                    dcc.Graph(id='anomaly-timeline', style={'height': '300px'})
                ], width=6)
            ], className="mt-4"),
            
            # Timer pour mise à jour temps réel
            dcc.Interval(
                id='interval-component',
                interval=2000,  # 2 secondes
                n_intervals=0
            ),
            
            # Stockage des données
            dcc.Store(id='equipment-data-store'),
            dcc.Store(id='animation-state-store')
            
        ], fluid=True)
    
    def _setup_callbacks(self):
        """Configure les callbacks interactifs."""
        
        @self.app.callback(
            Output('equipment-data-store', 'data'),
            Input('interval-component', 'n_intervals')
        )
        def update_equipment_data(n_intervals):
            """Mise à jour des données d'équipement."""
            return self._generate_mock_data()
        
        @self.app.callback(
            [Output('main-3d-plot', 'figure'),
             Output('equipment-selector', 'options')],
            [Input('equipment-data-store', 'data'),
             Input('equipment-selector', 'value'),
             Input('view-selector', 'value'),
             Input('display-options', 'value'),
             Input('animation-speed', 'value'),
             Input('lighting-intensity', 'value')]
        )
        def update_3d_plot(equipment_data, selected_equipment, view_type, 
                          display_options, animation_speed, lighting_intensity):
            """Mise à jour du graphique 3D principal."""
            
            if not equipment_data:
                return go.Figure(), []
            
            # Création de la figure 3D
            fig = go.Figure()
            
            # Options d'équipements pour le dropdown
            equipment_options = [
                {'label': f"🏭 {eq_id}", 'value': eq_id}
                for eq_id in equipment_data.keys()
            ]
            
            # Génération des modèles 3D
            if not hasattr(self, '_models_generated'):
                self._generate_3d_models(equipment_data)
                self._models_generated = True
            
            # Ajout des équipements
            for eq_id, eq_data in equipment_data.items():
                if eq_id in self.equipment_models:
                    model = self.equipment_models[eq_id]
                    
                    # Filtrage si équipement sélectionné
                    if selected_equipment and selected_equipment != eq_id:
                        continue
                    
                    # Ajout du modèle 3D
                    self._add_equipment_to_figure(fig, model, eq_data)
                    
                    # Ajout des capteurs si activé
                    if 'sensors' in display_options:
                        self._add_sensors_to_figure(fig, model, eq_data.get('sensors', {}))
                    
                    # Ajout des anomalies si activé
                    if 'anomalies' in display_options:
                        self._add_anomalies_to_figure(fig, model, eq_data.get('anomalies', []))
            
            # Ajout des flux de données si activé
            if 'flows' in display_options:
                self._add_data_flows_to_figure(fig, equipment_data)
            
            # Configuration de la mise en page 3D
            self._configure_3d_layout(fig, view_type, lighting_intensity, selected_equipment)
            
            return fig, equipment_options
        
        @self.app.callback(
            [Output('equipment-info', 'children'),
             Output('sensor-readings', 'children'),
             Output('system-status', 'children')],
            [Input('equipment-selector', 'value'),
             Input('equipment-data-store', 'data')]
        )
        def update_info_panel(selected_equipment, equipment_data):
            """Mise à jour du panneau d'informations."""
            
            if not selected_equipment or not equipment_data:
                return "Aucun équipement sélectionné", "", ""
            
            eq_data = equipment_data.get(selected_equipment, {})
            
            # Informations équipement
            equipment_info = [
                html.H5(f"🏭 {selected_equipment}"),
                html.P(f"Type: {eq_data.get('type', 'Unknown')}"),
                html.P(f"Statut: {eq_data.get('status', 'Unknown')}"),
                html.P(f"Dernière MaJ: {eq_data.get('last_update', 'N/A')}")
            ]
            
            # Lectures capteurs
            sensors = eq_data.get('sensors', {})
            sensor_readings = []
            
            for sensor_id, sensor_data in sensors.items():
                sensor_type = sensor_data.get('type', 'unknown')
                value = sensor_data.get('value', 0)
                unit = sensor_data.get('unit', '')
                quality = sensor_data.get('quality', 1.0)
                
                # Couleur basée sur la qualité
                color = 'success' if quality > 0.8 else 'warning' if quality > 0.5 else 'danger'
                
                sensor_readings.append(
                    dbc.Alert([
                        html.Strong(f"{sensor_type.upper()}: "),
                        f"{value:.1f} {unit} ",
                        dbc.Badge(f"{quality:.0%}", color=color, className="ml-2")
                    ], color="light", className="p-2 mb-1")
                )
            
            # Statut système
            anomalies = eq_data.get('anomalies', [])
            anomaly_count = len(anomalies)
            
            if anomaly_count == 0:
                status_color = "success"
                status_text = "✅ Normal"
            elif anomaly_count < 3:
                status_color = "warning" 
                status_text = f"⚠️ {anomaly_count} anomalie(s)"
            else:
                status_color = "danger"
                status_text = f"🚨 {anomaly_count} anomalies"
            
            system_status = dbc.Alert(status_text, color=status_color)
            
            return equipment_info, sensor_readings, system_status
        
        @self.app.callback(
            [Output('time-series-plot', 'figure'),
             Output('anomaly-timeline', 'figure')],
            [Input('equipment-selector', 'value'),
             Input('equipment-data-store', 'data')]
        )
        def update_time_series(selected_equipment, equipment_data):
            """Mise à jour des graphiques temporels."""
            
            # Graphique série temporelle
            ts_fig = go.Figure()
            
            if selected_equipment and equipment_data:
                # Génération données temporelles simulées
                timestamps = pd.date_range(
                    start=datetime.now() - timedelta(hours=1),
                    end=datetime.now(),
                    freq='1min'
                )
                
                # Données simulées pour différents capteurs
                temperature_data = 70 + 10 * np.sin(np.arange(len(timestamps)) * 0.1) + np.random.normal(0, 2, len(timestamps))
                pressure_data = 5 + 2 * np.cos(np.arange(len(timestamps)) * 0.05) + np.random.normal(0, 0.5, len(timestamps))
                
                ts_fig.add_trace(go.Scatter(
                    x=timestamps, y=temperature_data,
                    name="Température (°C)", line=dict(color='red')
                ))
                
                ts_fig.add_trace(go.Scatter(
                    x=timestamps, y=pressure_data * 10,  # Mise à l'échelle
                    name="Pression (bar x10)", line=dict(color='blue')
                ))
                
                ts_fig.update_layout(
                    title="Évolution Temporelle des Capteurs",
                    xaxis_title="Temps",
                    yaxis_title="Valeur",
                    height=250
                )
            
            # Timeline des anomalies
            anomaly_fig = go.Figure()
            
            if equipment_data:
                # Génération anomalies simulées
                anomaly_times = []
                anomaly_severities = []
                
                for i in range(5):
                    time = datetime.now() - timedelta(minutes=np.random.randint(5, 60))
                    severity = np.random.choice(['low', 'medium', 'high'])
                    
                    anomaly_times.append(time)
                    anomaly_severities.append(severity)
                
                severity_colors = {'low': 'yellow', 'medium': 'orange', 'high': 'red'}
                
                anomaly_fig.add_trace(go.Scatter(
                    x=anomaly_times,
                    y=[1] * len(anomaly_times),
                    mode='markers',
                    marker=dict(
                        size=[10, 15, 20][i % 3] for i in range(len(anomaly_times)),
                        color=[severity_colors[s] for s in anomaly_severities]
                    ),
                    text=[f"Anomalie {s}" for s in anomaly_severities],
                    hoverinfo='text'
                ))
                
                anomaly_fig.update_layout(
                    title="Timeline des Anomalies",
                    xaxis_title="Temps",
                    yaxis=dict(visible=False),
                    height=250
                )
            
            return ts_fig, anomaly_fig
    
    def _generate_mock_data(self) -> Dict[str, Any]:
        """Génère des données simulées pour la démonstration."""
        equipment_data = {}
        
        # Liste d'équipements simulés
        equipment_list = [
            ('PUMP_001', 'pump', (0, 0, 0)),
            ('MOTOR_001', 'motor', (8, 0, 0)),
            ('HEAT_EXCHANGER_001', 'heat_exchanger', (0, 8, 0)),
            ('TANK_001', 'tank', (8, 8, 0)),
            ('VALVE_001', 'valve', (4, 4, 0))
        ]
        
        for eq_id, eq_type, position in equipment_list:
            # Données de base
            equipment_data[eq_id] = {
                'type': eq_type,
                'position': position,
                'status': np.random.choice(['running', 'idle', 'maintenance'], p=[0.7, 0.2, 0.1]),
                'last_update': datetime.now().strftime("%H:%M:%S"),
                'sensors': {},
                'anomalies': []
            }
            
            # Capteurs selon le type d'équipement
            if eq_type == 'pump':
                sensors = {
                    'temperature': {'type': 'temperature', 'value': np.random.normal(75, 5), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'pressure': {'type': 'pressure', 'value': np.random.normal(6, 1), 'unit': 'bar', 'quality': np.random.uniform(0.8, 1.0)},
                    'vibration': {'type': 'vibration', 'value': np.random.normal(2, 0.5), 'unit': 'mm/s', 'quality': np.random.uniform(0.8, 1.0)},
                    'flow': {'type': 'flow', 'value': np.random.normal(120, 10), 'unit': 'L/min', 'quality': np.random.uniform(0.8, 1.0)}
                }
            elif eq_type == 'motor':
                sensors = {
                    'temperature': {'type': 'temperature', 'value': np.random.normal(85, 8), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'current': {'type': 'current', 'value': np.random.normal(18, 2), 'unit': 'A', 'quality': np.random.uniform(0.8, 1.0)},
                    'vibration': {'type': 'vibration', 'value': np.random.normal(1.5, 0.3), 'unit': 'mm/s', 'quality': np.random.uniform(0.8, 1.0)},
                    'speed': {'type': 'speed', 'value': np.random.normal(1750, 50), 'unit': 'rpm', 'quality': np.random.uniform(0.8, 1.0)}
                }
            elif eq_type == 'heat_exchanger':
                sensors = {
                    'temp_hot_in': {'type': 'temperature', 'value': np.random.normal(95, 3), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'temp_hot_out': {'type': 'temperature', 'value': np.random.normal(70, 3), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'temp_cold_in': {'type': 'temperature', 'value': np.random.normal(25, 2), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'temp_cold_out': {'type': 'temperature', 'value': np.random.normal(45, 2), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'pressure': {'type': 'pressure', 'value': np.random.normal(8, 0.5), 'unit': 'bar', 'quality': np.random.uniform(0.8, 1.0)}
                }
            elif eq_type == 'tank':
                sensors = {
                    'level': {'type': 'level', 'value': np.random.uniform(30, 90), 'unit': '%', 'quality': np.random.uniform(0.8, 1.0)},
                    'temperature': {'type': 'temperature', 'value': np.random.normal(60, 5), 'unit': '°C', 'quality': np.random.uniform(0.8, 1.0)},
                    'pressure': {'type': 'pressure', 'value': np.random.normal(3, 0.3), 'unit': 'bar', 'quality': np.random.uniform(0.8, 1.0)}
                }
            else:  # valve
                sensors = {
                    'position': {'type': 'position', 'value': np.random.uniform(0, 100), 'unit': '%', 'quality': np.random.uniform(0.8, 1.0)},
                    'flow': {'type': 'flow', 'value': np.random.normal(80, 10), 'unit': 'L/min', 'quality': np.random.uniform(0.8, 1.0)}
                }
            
            equipment_data[eq_id]['sensors'] = sensors
            
            # Génération d'anomalies aléatoires
            if np.random.random() < 0.2:  # 20% chance d'anomalie
                anomaly = {
                    'type': np.random.choice(['temperature', 'pressure', 'vibration', 'performance']),
                    'severity': np.random.choice(['low', 'medium', 'high'], p=[0.6, 0.3, 0.1]),
                    'confidence': np.random.uniform(0.7, 1.0),
                    'timestamp': datetime.now()
                }
                equipment_data[eq_id]['anomalies'].append(anomaly)
        
        return equipment_data
    
    def _generate_3d_models(self, equipment_data: Dict[str, Any]):
        """Génère les modèles 3D des équipements."""
        for eq_id, eq_data in equipment_data.items():
            eq_type = eq_data['type']
            position = eq_data['position']
            
            model = self.equipment_generator.generate_equipment(eq_type, eq_id, position)
            self.equipment_models[eq_id] = model
    
    def _add_equipment_to_figure(self, fig: go.Figure, model: Equipment3DModel, eq_data: Dict[str, Any]):
        """Ajoute un équipement à la figure 3D."""
        x, y, z = model.position
        
        # Modèle simplifié pour la démonstration (cube avec couleur du type)
        type_colors = {
            'pump': '#e74c3c',
            'motor': '#3498db', 
            'heat_exchanger': '#e67e22',
            'tank': '#27ae60',
            'valve': '#9b59b6'
        }
        
        color = type_colors.get(model.equipment_type, '#95a5a6')
        
        # Status opacity
        status = eq_data.get('status', 'running')
        opacity = 0.9 if status == 'running' else 0.6 if status == 'idle' else 0.3
        
        # Cube représentant l'équipement
        cube_size = 2
        vertices = np.array([
            [x-cube_size, y-cube_size, z-cube_size], [x+cube_size, y-cube_size, z-cube_size],
            [x+cube_size, y+cube_size, z-cube_size], [x-cube_size, y+cube_size, z-cube_size],
            [x-cube_size, y-cube_size, z+cube_size], [x+cube_size, y-cube_size, z+cube_size],
            [x+cube_size, y+cube_size, z+cube_size], [x-cube_size, y+cube_size, z+cube_size]
        ])
        
        # Faces du cube (triangles)
        faces = [
            [0, 1, 2], [0, 2, 3],  # Bottom
            [4, 7, 6], [4, 6, 5],  # Top
            [0, 4, 5], [0, 5, 1],  # Front
            [2, 6, 7], [2, 7, 3],  # Back
            [0, 3, 7], [0, 7, 4],  # Left
            [1, 5, 6], [1, 6, 2]   # Right
        ]
        
        fig.add_trace(go.Mesh3d(
            x=vertices[:, 0], y=vertices[:, 1], z=vertices[:, 2],
            i=[f[0] for f in faces],
            j=[f[1] for f in faces], 
            k=[f[2] for f in faces],
            color=color,
            opacity=opacity,
            name=f"{model.equipment_type} - {model.equipment_id}",
            hovertemplate=f"<b>{model.equipment_id}</b><br>" +
                         f"Type: {model.equipment_type}<br>" +
                         f"Status: {status}<br>" +
                         f"Position: ({x:.1f}, {y:.1f}, {z:.1f})<extra></extra>"
        ))
    
    def _add_sensors_to_figure(self, fig: go.Figure, model: Equipment3DModel, sensors: Dict[str, Any]):
        """Ajoute les capteurs à la figure 3D."""
        if not model.sensors_positions:
            return
        
        for i, (sensor_id, sensor_data) in enumerate(sensors.items()):
            if i < len(model.sensors_positions):
                position = model.sensors_positions[i]
                sensor_viz = self.data_visualizer.create_sensor_visualization(sensor_data, position)
                fig.add_trace(sensor_viz)
    
    def _add_anomalies_to_figure(self, fig: go.Figure, model: Equipment3DModel, anomalies: List[Dict[str, Any]]):
        """Ajoute les anomalies à la figure 3D."""
        for anomaly in anomalies:
            anomaly_viz = self.data_visualizer.create_anomaly_visualization(anomaly, model.position)
            fig.add_trace(anomaly_viz)
    
    def _add_data_flows_to_figure(self, fig: go.Figure, equipment_data: Dict[str, Any]):
        """Ajoute les flux de données à la figure 3D."""
        # Connexions simulées entre équipements
        connections = [
            ('PUMP_001', 'HEAT_EXCHANGER_001'),
            ('HEAT_EXCHANGER_001', 'TANK_001'),
            ('MOTOR_001', 'PUMP_001'),
            ('VALVE_001', 'TANK_001')
        ]
        
        for source_id, target_id in connections:
            if source_id in equipment_data and target_id in equipment_data:
                source_pos = equipment_data[source_id]['position']
                target_pos = equipment_data[target_id]['position']
                
                flow_data = {
                    'source': source_pos,
                    'target': target_pos,
                    'intensity': np.random.uniform(0.5, 1.0),
                    'type': np.random.choice(['data', 'control', 'energy'])
                }
                
                flows = self.data_visualizer.create_data_flow_visualization(flow_data)
                for flow in flows:
                    fig.add_trace(flow)
    
    def _configure_3d_layout(self, fig: go.Figure, view_type: str, lighting_intensity: float, selected_equipment: Optional[str]):
        """Configure la mise en page 3D."""
        
        # Configuration de la caméra selon la vue
        if view_type == 'global':
            camera_eye = dict(x=1.5, y=1.5, z=1.2)
        elif view_type == 'detailed' and selected_equipment:
            # Vue rapprochée sur l'équipement sélectionné
            camera_eye = dict(x=0.8, y=0.8, z=0.8)
        else:
            camera_eye = dict(x=1.2, y=1.2, z=1.0)
        
        fig.update_layout(
            scene=dict(
                xaxis=dict(title="X (m)", range=[-5, 15]),
                yaxis=dict(title="Y (m)", range=[-5, 15]),
                zaxis=dict(title="Z (m)", range=[-5, 10]),
                bgcolor="rgba(240, 240, 240, 0.1)",
                camera=dict(eye=camera_eye),
                aspectmode='cube'
            ),
            title=dict(
                text="🏭 Vue 3D du Jumeau Numérique - Station Traffeyère",
                x=0.5,
                font=dict(size=16)
            ),
            showlegend=True,
            legend=dict(
                x=0.02, y=0.98,
                bgcolor="rgba(255, 255, 255, 0.8)"
            ),
            margin=dict(l=0, r=0, t=50, b=0)
        )
    
    def run(self, debug: bool = False, host: str = '0.0.0.0'):
        """Lance le dashboard interactif."""
        logger.info(f"Lancement du dashboard 3D sur http://{host}:{self.port}")
        self.app.run_server(debug=debug, host=host, port=self.port)

# Classe principale du système de visualisation 3D
class DigitalTwin3DVisualizationSystem:
    """Système complet de visualisation 3D du jumeau numérique."""
    
    def __init__(self, config_path: str = "visualization_config.json"):
        self.config = self._load_config(config_path)
        self.dashboard = InteractiveDashboard(port=self.config.get('dashboard_port', 8050))
        
        # WebSocket server pour communication temps réel
        self.websocket_server = None
        
        logger.info("Système de visualisation 3D initialisé")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration du système."""
        default_config = {
            'dashboard_port': 8050,
            'websocket_port': 8765,
            'update_interval_ms': 2000,
            'max_history_points': 1000,
            'rendering': {
                'quality': 'high',
                'anti_aliasing': True,
                'shadows': True,
                'reflections': False
            },
            'camera': {
                'default_position': [10, 10, 10],
                'movement_speed': 1.0,
                'zoom_sensitivity': 1.0
            },
            'colors': {
                'background': '#f8f9fa',
                'equipment': {
                    'pump': '#e74c3c',
                    'motor': '#3498db',
                    'heat_exchanger': '#e67e22',
                    'tank': '#27ae60',
                    'valve': '#9b59b6'
                },
                'sensors': {
                    'temperature': 'RdYlBu_r',
                    'pressure': 'Blues',
                    'vibration': 'Reds'
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
            else:
                config = default_config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur chargement config: {e}")
            config = default_config
        
        return config
    
    async def start_websocket_server(self):
        """Démarre le serveur WebSocket pour communication temps réel."""
        async def websocket_handler(websocket, path):
            logger.info(f"Nouvelle connexion WebSocket: {websocket.remote_address}")
            try:
                async for message in websocket:
                    data = json.loads(message)
                    # Traitement des messages temps réel
                    await self._process_websocket_message(websocket, data)
            except websockets.exceptions.ConnectionClosed:
                logger.info("Connexion WebSocket fermée")
        
        self.websocket_server = await websockets.serve(
            websocket_handler, 
            'localhost', 
            self.config['websocket_port']
        )
        
        logger.info(f"Serveur WebSocket démarré sur ws://localhost:{self.config['websocket_port']}")
    
    async def _process_websocket_message(self, websocket, data: Dict[str, Any]):
        """Traite un message WebSocket reçu."""
        message_type = data.get('type')
        
        if message_type == 'update_equipment_data':
            # Mise à jour données équipement
            equipment_id = data.get('equipment_id')
            sensor_data = data.get('sensor_data', {})
            
            # Traitement et diffusion vers le dashboard
            response = {
                'type': 'equipment_updated',
                'equipment_id': equipment_id,
                'timestamp': datetime.now().isoformat()
            }
            
            await websocket.send(json.dumps(response))
            
        elif message_type == 'camera_update':
            # Mise à jour position caméra
            camera_data = data.get('camera', {})
            # Synchronisation avec autres clients connectés
            pass
    
    def run(self, debug: bool = False):
        """Lance le système complet de visualisation 3D."""
        logger.info("🚀 Lancement du système de visualisation 3D du jumeau numérique")
        
        # Lancement du dashboard
        try:
            self.dashboard.run(debug=debug)
        except KeyboardInterrupt:
            logger.info("Arrêt du système de visualisation 3D")

# Fonction de démonstration
async def main():
    """Démonstration du système de visualisation 3D."""
    
    print("=== Système de Visualisation 3D du Jumeau Numérique ===")
    print("🏭 Station Traffeyère IoT AI Platform")
    print()
    
    # Initialisation du système
    viz_system = DigitalTwin3DVisualizationSystem()
    
    print("✅ Système de visualisation 3D initialisé")
    print(f"🌐 Dashboard accessible sur: http://localhost:{viz_system.config['dashboard_port']}")
    print(f"🔌 WebSocket server sur: ws://localhost:{viz_system.config['websocket_port']}")
    print()
    
    print("📋 Fonctionnalités disponibles:")
    print("  • 🎮 Contrôles interactifs 3D")
    print("  • 📊 Visualisation capteurs temps réel")
    print("  • 🌊 Flux de données animés")
    print("  • ⚠️ Alertes visuelles anomalies")
    print("  • 🌡️ Cartes thermiques superposées")
    print("  • 📈 Graphiques temporels intégrés")
    print("  • 🎯 Vues multiples (globale, détaillée, thermique)")
    print("  • ⚙️ Paramètres d'affichage configurables")
    print()
    
    print("🚀 Lancement du dashboard...")
    print("   (Ctrl+C pour arrêter)")
    print()
    
    try:
        # Démarrage du serveur WebSocket en parallèle (simulation)
        print("🔌 Serveur WebSocket simulé démarré")
        
        # Lancement du dashboard (bloquant)
        viz_system.run(debug=True)
        
    except KeyboardInterrupt:
        print("\n⏹️ Arrêt du système de visualisation")
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    print("✅ Système arrêté proprement")

if __name__ == "__main__":
    # Lancement direct du dashboard sans WebSocket pour la démo
    viz_system = DigitalTwin3DVisualizationSystem()
    viz_system.run(debug=False)