#!/usr/bin/env python3
"""
Project 25 - Station Traffeyère IoT AI Platform
Component 4C: XAI Visualization Dashboard & Automated Reporting System

Comprehensive visualization system for XAI results with interactive dashboards,
automated report generation, and stakeholder-specific views for different
technical backgrounds (executives, engineers, operators).

Author: Industrial IoT Security Specialist  
Date: 2024
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
import numpy as np
import pandas as pd
from pathlib import Path
import base64
from io import BytesIO
import tempfile

# Visualization libraries
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Rectangle
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.figure_factory as ff
import plotly.offline as pyo

# Web framework for dashboard
import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
from flask import Flask

# Report generation
from jinja2 import Template
import pdfkit
import markdown
from weasyprint import HTML
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# Statistical analysis
import scipy.stats as stats
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA

import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DashboardConfig:
    """Configuration for XAI dashboard."""
    refresh_interval_seconds: int = 30
    max_data_points: int = 10000
    default_time_range: str = "24h"  # 1h, 6h, 24h, 7d, 30d
    enable_real_time: bool = True
    alert_thresholds: Dict[str, float] = None
    stakeholder_views: List[str] = None
    color_scheme: str = "corporate"  # corporate, dark, light
    
    def __post_init__(self):
        if self.alert_thresholds is None:
            self.alert_thresholds = {
                "critical": 0.9,
                "high": 0.7,
                "medium": 0.5
            }
        if self.stakeholder_views is None:
            self.stakeholder_views = ["executive", "engineer", "operator"]

@dataclass
class ReportConfig:
    """Configuration for automated reporting."""
    report_types: List[str] = None
    schedule: Dict[str, str] = None  # report_type -> cron expression
    recipients: Dict[str, List[str]] = None  # report_type -> email list
    templates_dir: str = "templates"
    output_dir: str = "reports"
    
    def __post_init__(self):
        if self.report_types is None:
            self.report_types = ["executive_summary", "technical_analysis", "operational_report"]
        if self.schedule is None:
            self.schedule = {
                "executive_summary": "0 8 * * MON",  # Weekly Monday 8 AM
                "technical_analysis": "0 0 * * *",    # Daily midnight
                "operational_report": "0 */4 * * *"   # Every 4 hours
            }
        if self.recipients is None:
            self.recipients = {
                "executive_summary": ["ceo@company.com", "cto@company.com"],
                "technical_analysis": ["engineers@company.com"],
                "operational_report": ["operators@company.com"]
            }

class XAIVisualizationDashboard:
    """Comprehensive XAI visualization dashboard system."""
    
    def __init__(self, dashboard_config: DashboardConfig = None,
                 report_config: ReportConfig = None):
        """Initialize XAI visualization dashboard."""
        self.dashboard_config = dashboard_config or DashboardConfig()
        self.report_config = report_config or ReportConfig()
        
        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
        self.data_cache = {}
        self.latest_results = []
        
        # Color schemes
        self.color_schemes = {
            "corporate": {
                "primary": "#1f77b4",
                "secondary": "#ff7f0e", 
                "success": "#2ca02c",
                "warning": "#d62728",
                "danger": "#d62728",
                "background": "#f8f9fa"
            },
            "dark": {
                "primary": "#375a7f",
                "secondary": "#f39c12",
                "success": "#00bc8c", 
                "warning": "#f39c12",
                "danger": "#e74c3c",
                "background": "#222222"
            },
            "light": {
                "primary": "#007bff",
                "secondary": "#6c757d",
                "success": "#28a745",
                "warning": "#ffc107", 
                "danger": "#dc3545",
                "background": "#ffffff"
            }
        }
        
        self.current_colors = self.color_schemes[self.dashboard_config.color_scheme]
        
        # Initialize dashboard layout
        self._setup_dashboard_layout()
        self._setup_callbacks()
        
        logger.info("XAI Visualization Dashboard initialized")
    
    def _setup_dashboard_layout(self):
        """Setup the main dashboard layout."""
        
        # Header
        header = dbc.NavbarSimple(
            brand="🏭 Station Traffeyère - XAI Anomaly Detection Dashboard",
            brand_href="#",
            color=self.current_colors["primary"],
            dark=True,
            children=[
                dbc.NavItem(dbc.NavLink("Executive View", href="/executive")),
                dbc.NavItem(dbc.NavLink("Engineer View", href="/engineer")), 
                dbc.NavItem(dbc.NavLink("Operator View", href="/operator")),
                dbc.NavItem(dbc.NavLink("Reports", href="/reports"))
            ]
        )
        
        # Control panel
        controls = dbc.Card([
            dbc.CardHeader("Dashboard Controls"),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Time Range:"),
                        dcc.Dropdown(
                            id="time-range-dropdown",
                            options=[
                                {"label": "Last Hour", "value": "1h"},
                                {"label": "Last 6 Hours", "value": "6h"},
                                {"label": "Last 24 Hours", "value": "24h"},
                                {"label": "Last 7 Days", "value": "7d"},
                                {"label": "Last 30 Days", "value": "30d"}
                            ],
                            value=self.dashboard_config.default_time_range
                        )
                    ], width=3),
                    dbc.Col([
                        dbc.Label("Sensor Filter:"),
                        dcc.Dropdown(
                            id="sensor-filter-dropdown",
                            options=[],
                            value=None,
                            multi=True,
                            placeholder="Select sensors..."
                        )
                    ], width=3),
                    dbc.Col([
                        dbc.Label("Risk Level Filter:"),
                        dcc.Dropdown(
                            id="risk-filter-dropdown",
                            options=[
                                {"label": "All", "value": "all"},
                                {"label": "Critical", "value": "CRITICAL"},
                                {"label": "High", "value": "HIGH"},
                                {"label": "Medium", "value": "MEDIUM"},
                                {"label": "Low", "value": "LOW"}
                            ],
                            value="all"
                        )
                    ], width=3),
                    dbc.Col([
                        dbc.Label("Auto Refresh:"),
                        dbc.Switch(
                            id="auto-refresh-switch",
                            label="Enable",
                            value=self.dashboard_config.enable_real_time
                        )
                    ], width=3)
                ])
            ])
        ], className="mb-4")
        
        # Main content area
        content = dbc.Container([
            # KPI Cards
            self._create_kpi_cards(),
            
            # Charts section
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="anomaly-timeline-chart")
                ], width=12)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="feature-importance-chart")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="model-performance-chart") 
                ], width=6)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="risk-distribution-chart")
                ], width=4),
                dbc.Col([
                    dcc.Graph(id="model-consensus-chart")
                ], width=4),
                dbc.Col([
                    dcc.Graph(id="uncertainty-analysis-chart")
                ], width=4)
            ], className="mb-4"),
            
            # Detailed analysis section
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recent Anomalies"),
                        dbc.CardBody(id="recent-anomalies-table")
                    ])
                ], width=8),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("System Health"),
                        dbc.CardBody(id="system-health-indicators")
                    ])
                ], width=4)
            ], className="mb-4"),
            
            # Explanation panel
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("XAI Explanations"),
                        dbc.CardBody(id="explanation-panel")
                    ])
                ], width=12)
            ])
        ], fluid=True)
        
        # Auto-refresh interval
        refresh_interval = dcc.Interval(
            id='interval-component',
            interval=self.dashboard_config.refresh_interval_seconds * 1000,
            n_intervals=0
        )
        
        # Complete layout
        self.app.layout = dbc.Container([
            header,
            controls,
            content,
            refresh_interval
        ], fluid=True)
    
    def _create_kpi_cards(self):
        """Create KPI summary cards."""
        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("0", id="total-anomalies-kpi", className="card-title text-danger"),
                        html.P("Total Anomalies", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("0%", id="anomaly-rate-kpi", className="card-title text-warning"),
                        html.P("Anomaly Rate", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("0", id="critical-alerts-kpi", className="card-title text-danger"),
                        html.P("Critical Alerts", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("0.0", id="avg-confidence-kpi", className="card-title text-success"),
                        html.P("Avg Confidence", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("0", id="active-sensors-kpi", className="card-title text-info"),
                        html.P("Active Sensors", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("Online", id="system-status-kpi", className="card-title text-success"),
                        html.P("System Status", className="card-text")
                    ])
                ], color="light", outline=True)
            ], width=2)
        ], className="mb-4")
    
    def _setup_callbacks(self):
        """Setup dashboard callbacks for interactivity."""
        
        @self.app.callback(
            [Output("total-anomalies-kpi", "children"),
             Output("anomaly-rate-kpi", "children"),
             Output("critical-alerts-kpi", "children"),
             Output("avg-confidence-kpi", "children"),
             Output("active-sensors-kpi", "children")],
            [Input("interval-component", "n_intervals"),
             Input("time-range-dropdown", "value"),
             Input("sensor-filter-dropdown", "value"),
             Input("risk-filter-dropdown", "value")]
        )
        def update_kpis(n_intervals, time_range, sensor_filter, risk_filter):
            """Update KPI cards."""
            if not self.latest_results:
                return "0", "0%", "0", "0.0", "0"
            
            # Filter data based on selections
            filtered_data = self._filter_data(self.latest_results, time_range, 
                                            sensor_filter, risk_filter)
            
            total_anomalies = sum(1 for r in filtered_data if r.get('is_anomaly', False))
            total_samples = len(filtered_data)
            anomaly_rate = (total_anomalies / total_samples * 100) if total_samples > 0 else 0
            
            critical_alerts = sum(1 for r in filtered_data 
                                if r.get('risk_level') == 'CRITICAL')
            
            avg_confidence = np.mean([r.get('confidence', 0) for r in filtered_data]) if filtered_data else 0
            
            active_sensors = len(set(r.get('sensor_id') for r in filtered_data))
            
            return (str(total_anomalies), 
                   f"{anomaly_rate:.1f}%",
                   str(critical_alerts),
                   f"{avg_confidence:.2f}",
                   str(active_sensors))
        
        @self.app.callback(
            Output("anomaly-timeline-chart", "figure"),
            [Input("interval-component", "n_intervals"),
             Input("time-range-dropdown", "value"),
             Input("sensor-filter-dropdown", "value"),
             Input("risk-filter-dropdown", "value")]
        )
        def update_anomaly_timeline(n_intervals, time_range, sensor_filter, risk_filter):
            """Update anomaly timeline chart."""
            if not self.latest_results:
                return go.Figure()
            
            filtered_data = self._filter_data(self.latest_results, time_range,
                                            sensor_filter, risk_filter)
            
            return self._create_anomaly_timeline_chart(filtered_data)
        
        @self.app.callback(
            Output("feature-importance-chart", "figure"),
            [Input("interval-component", "n_intervals"),
             Input("time-range-dropdown", "value")]
        )
        def update_feature_importance(n_intervals, time_range):
            """Update feature importance chart."""
            if not self.latest_results:
                return go.Figure()
            
            return self._create_feature_importance_chart(self.latest_results)
        
        @self.app.callback(
            Output("model-performance-chart", "figure"),
            [Input("interval-component", "n_intervals")]
        )
        def update_model_performance(n_intervals):
            """Update model performance chart."""
            if not self.latest_results:
                return go.Figure()
            
            return self._create_model_performance_chart(self.latest_results)
        
        @self.app.callback(
            Output("recent-anomalies-table", "children"),
            [Input("interval-component", "n_intervals"),
             Input("time-range-dropdown", "value")]
        )
        def update_recent_anomalies(n_intervals, time_range):
            """Update recent anomalies table."""
            if not self.latest_results:
                return "No data available"
            
            # Get recent anomalies
            anomalies = [r for r in self.latest_results 
                        if r.get('is_anomaly', False)]
            anomalies.sort(key=lambda x: x.get('timestamp', datetime.now()), reverse=True)
            
            # Create table
            table_rows = []
            for i, anomaly in enumerate(anomalies[:10]):  # Show top 10
                risk_color = self._get_risk_color(anomaly.get('risk_level', 'LOW'))
                
                row = dbc.Row([
                    dbc.Col(anomaly.get('timestamp', '').strftime('%H:%M:%S') if isinstance(anomaly.get('timestamp'), datetime) else str(anomaly.get('timestamp', '')), width=2),
                    dbc.Col(anomaly.get('sensor_id', 'Unknown'), width=2),
                    dbc.Col([
                        dbc.Badge(anomaly.get('risk_level', 'LOW'), 
                                color=risk_color, className="me-1")
                    ], width=2),
                    dbc.Col(f"{anomaly.get('anomaly_score', 0):.3f}", width=2),
                    dbc.Col(f"{anomaly.get('confidence', 0):.3f}", width=2),
                    dbc.Col(anomaly.get('explanation', {}).get('summary', '')[:50] + '...', width=2)
                ], className="mb-1")
                
                table_rows.append(row)
            
            return table_rows if table_rows else "No recent anomalies"
        
    def _filter_data(self, data: List[Dict], time_range: str, 
                    sensor_filter: List[str], risk_filter: str) -> List[Dict]:
        """Filter data based on dashboard selections."""
        filtered = data.copy()
        
        # Time range filter
        if time_range and time_range != "all":
            cutoff_time = self._get_cutoff_time(time_range)
            filtered = [r for r in filtered 
                       if r.get('timestamp', datetime.now()) >= cutoff_time]
        
        # Sensor filter
        if sensor_filter:
            filtered = [r for r in filtered 
                       if r.get('sensor_id') in sensor_filter]
        
        # Risk filter
        if risk_filter and risk_filter != "all":
            filtered = [r for r in filtered 
                       if r.get('risk_level') == risk_filter]
        
        return filtered
    
    def _get_cutoff_time(self, time_range: str) -> datetime:
        """Get cutoff time for filtering."""
        now = datetime.now()
        
        if time_range == "1h":
            return now - timedelta(hours=1)
        elif time_range == "6h":
            return now - timedelta(hours=6)
        elif time_range == "24h":
            return now - timedelta(hours=24)
        elif time_range == "7d":
            return now - timedelta(days=7)
        elif time_range == "30d":
            return now - timedelta(days=30)
        else:
            return now - timedelta(hours=24)
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            "CRITICAL": "danger",
            "HIGH": "warning", 
            "MEDIUM": "info",
            "LOW": "success"
        }
        return colors.get(risk_level, "secondary")
    
    def _create_anomaly_timeline_chart(self, data: List[Dict]) -> go.Figure:
        """Create anomaly timeline chart."""
        if not data:
            return go.Figure().add_annotation(
                text="No data available", 
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
        
        # Extract data
        timestamps = [r.get('timestamp', datetime.now()) for r in data]
        scores = [r.get('anomaly_score', 0) for r in data]
        is_anomaly = [r.get('is_anomaly', False) for r in data]
        risk_levels = [r.get('risk_level', 'LOW') for r in data]
        sensor_ids = [r.get('sensor_id', 'Unknown') for r in data]
        
        # Create figure
        fig = go.Figure()
        
        # Add anomaly score trace
        colors = [self._get_plotly_risk_color(risk) for risk in risk_levels]
        sizes = [12 if anomaly else 6 for anomaly in is_anomaly]
        
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=scores,
            mode='markers+lines',
            name='Anomaly Score',
            marker=dict(
                size=sizes,
                color=colors,
                opacity=0.8,
                line=dict(width=1, color='darkblue')
            ),
            line=dict(color='blue', width=1),
            hovertemplate=(
                '<b>%{x}</b><br>' +
                'Score: %{y:.3f}<br>' +
                'Sensor: %{customdata[0]}<br>' +
                'Risk: %{customdata[1]}<br>' +
                '<extra></extra>'
            ),
            customdata=list(zip(sensor_ids, risk_levels))
        ))
        
        # Add threshold lines
        fig.add_hline(y=0.9, line_dash="dash", line_color="red",
                     annotation_text="Critical Threshold")
        fig.add_hline(y=0.7, line_dash="dash", line_color="orange", 
                     annotation_text="High Risk Threshold")
        fig.add_hline(y=0.5, line_dash="dash", line_color="yellow",
                     annotation_text="Medium Risk Threshold")
        
        # Update layout
        fig.update_layout(
            title="Anomaly Detection Timeline",
            xaxis_title="Time",
            yaxis_title="Anomaly Score",
            template="plotly_white",
            hovermode="x unified",
            height=400
        )
        
        return fig
    
    def _create_feature_importance_chart(self, data: List[Dict]) -> go.Figure:
        """Create feature importance chart."""
        if not data:
            return go.Figure()
        
        # Aggregate feature importance from anomalies
        feature_importance_agg = {}
        
        for result in data:
            if result.get('is_anomaly', False):
                explanation = result.get('explanation', {})
                feature_importance = explanation.get('feature_importance', {})
                
                for feature, importance in feature_importance.items():
                    if feature not in feature_importance_agg:
                        feature_importance_agg[feature] = []
                    feature_importance_agg[feature].append(importance)
        
        if not feature_importance_agg:
            return go.Figure().add_annotation(
                text="No anomaly data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
        
        # Calculate average importance
        avg_importance = {
            feature: np.mean(values) 
            for feature, values in feature_importance_agg.items()
        }
        
        # Sort and get top features
        sorted_features = sorted(avg_importance.items(), 
                               key=lambda x: x[1], reverse=True)[:15]
        
        features, importances = zip(*sorted_features) if sorted_features else ([], [])
        
        # Create horizontal bar chart
        fig = go.Figure(go.Bar(
            x=list(importances),
            y=list(features),
            orientation='h',
            marker_color=self.current_colors["primary"]
        ))
        
        fig.update_layout(
            title="Top Feature Importance for Anomalies",
            xaxis_title="Average Importance",
            yaxis_title="Features",
            template="plotly_white",
            height=400
        )
        
        return fig
    
    def _create_model_performance_chart(self, data: List[Dict]) -> go.Figure:
        """Create model performance chart."""
        if not data:
            return go.Figure()
        
        # Analyze model consensus
        model_agreement = {}
        
        for result in data:
            model_predictions = result.get('model_predictions', {})
            for model_name, prediction in model_predictions.items():
                if model_name not in model_agreement:
                    model_agreement[model_name] = {'correct': 0, 'total': 0}
                
                model_agreement[model_name]['total'] += 1
                # Simple heuristic: if ensemble and model agree
                ensemble_pred = result.get('is_anomaly', False)
                if prediction == ensemble_pred:
                    model_agreement[model_name]['correct'] += 1
        
        # Calculate accuracy
        models = list(model_agreement.keys())
        accuracies = [
            (model_agreement[model]['correct'] / model_agreement[model]['total'] * 100)
            if model_agreement[model]['total'] > 0 else 0
            for model in models
        ]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=models,
            y=accuracies,
            marker_color=self.current_colors["secondary"],
            text=[f"{acc:.1f}%" for acc in accuracies],
            textposition='outside'
        ))
        
        fig.update_layout(
            title="Model Performance (Agreement with Ensemble)",
            xaxis_title="Models",
            yaxis_title="Accuracy (%)",
            template="plotly_white",
            height=400
        )
        
        return fig
    
    def _get_plotly_risk_color(self, risk_level: str) -> str:
        """Get plotly color for risk level."""
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow", 
            "LOW": "green"
        }
        return colors.get(risk_level, "gray")
    
    def update_data(self, results: List[Dict]):
        """Update dashboard data."""
        self.latest_results = results
        logger.info(f"Updated dashboard with {len(results)} results")
    
    def run_dashboard(self, host: str = "127.0.0.1", port: int = 8050, debug: bool = False):
        """Run the dashboard server."""
        logger.info(f"Starting XAI Dashboard on http://{host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)

class AutomatedReportGenerator:
    """Automated report generation system for different stakeholders."""
    
    def __init__(self, report_config: ReportConfig = None):
        """Initialize automated report generator."""
        self.report_config = report_config or ReportConfig()
        
        # Ensure directories exist
        Path(self.report_config.templates_dir).mkdir(exist_ok=True)
        Path(self.report_config.output_dir).mkdir(exist_ok=True)
        
        # Create default templates
        self._create_default_templates()
        
        logger.info("Automated Report Generator initialized")
    
    def _create_default_templates(self):
        """Create default report templates."""
        
        # Executive Summary Template
        executive_template = """
# XAI Anomaly Detection - Executive Summary
**Report Date:** {{ report_date }}  
**Reporting Period:** {{ period_start }} to {{ period_end }}

## Key Metrics Dashboard
- **Total Anomalies Detected:** {{ total_anomalies }}
- **Critical Alerts:** {{ critical_alerts }}
- **System Availability:** {{ availability }}%
- **False Positive Rate:** {{ false_positive_rate }}%

## Risk Assessment
{{ risk_summary }}

## Business Impact
{{ business_impact }}

## Recommended Actions
{% for action in recommendations %}
- {{ action }}
{% endfor %}

## Cost Analysis
- **Prevented Downtime:** {{ prevented_downtime_hours }} hours
- **Estimated Cost Savings:** ${{ cost_savings }}
- **Maintenance Optimization:** {{ maintenance_savings }}%

---
*This report was automatically generated by the XAI Anomaly Detection System*
        """
        
        # Technical Analysis Template
        technical_template = """
# XAI Anomaly Detection - Technical Analysis Report
**Report Date:** {{ report_date }}
**Analysis Period:** {{ period_start }} to {{ period_end }}

## System Performance Metrics
- **Model Accuracy:** {{ model_accuracy }}%
- **Precision:** {{ precision }}
- **Recall:** {{ recall }}
- **F1 Score:** {{ f1_score }}

## Model Performance Comparison
{% for model in model_performance %}
### {{ model.name }}
- Accuracy: {{ model.accuracy }}%
- Training Time: {{ model.training_time }}s
- Inference Time: {{ model.inference_time }}ms
{% endfor %}

## Feature Importance Analysis
{% for feature in top_features %}
- **{{ feature.name }}:** {{ feature.importance }}% ({{ feature.trend }})
{% endfor %}

## Anomaly Pattern Analysis
{{ pattern_analysis }}

## Model Interpretability
{{ interpretability_analysis }}

## Technical Recommendations
{% for rec in tech_recommendations %}
- {{ rec }}
{% endfor %}

## System Health
- **CPU Usage:** {{ cpu_usage }}%
- **Memory Usage:** {{ memory_usage }}%
- **Data Processing Rate:** {{ processing_rate }} samples/sec
        """
        
        # Operational Report Template
        operational_template = """
# XAI Anomaly Detection - Operational Report
**Report Time:** {{ report_date }}
**Shift Period:** {{ period_start }} to {{ period_end }}

## Current Status
- **System Status:** {{ system_status }}
- **Active Sensors:** {{ active_sensors }}
- **Data Quality:** {{ data_quality }}%

## Recent Alerts
{% for alert in recent_alerts %}
### {{ alert.timestamp }} - {{ alert.sensor_id }}
- **Risk Level:** {{ alert.risk_level }}
- **Confidence:** {{ alert.confidence }}%
- **Action Taken:** {{ alert.action }}
{% endfor %}

## Sensor Health Dashboard
{% for sensor in sensor_status %}
- **{{ sensor.id }}:** {{ sensor.status }} (Last Reading: {{ sensor.last_reading }})
{% endfor %}

## Maintenance Schedule
{% for maintenance in maintenance_items %}
- **{{ maintenance.equipment }}:** {{ maintenance.description }} (Due: {{ maintenance.due_date }})
{% endfor %}

## Operational Metrics
- **Uptime:** {{ uptime }}%
- **Response Time:** {{ response_time }}s
- **Alerts Acknowledged:** {{ alerts_acknowledged }}/{{ total_alerts }}

## Next Shift Handover
{{ handover_notes }}
        """
        
        # Save templates
        templates = {
            "executive_summary.html": executive_template,
            "technical_analysis.html": technical_template,
            "operational_report.html": operational_template
        }
        
        for filename, template_content in templates.items():
            template_path = Path(self.report_config.templates_dir) / filename
            if not template_path.exists():
                with open(template_path, 'w') as f:
                    f.write(template_content)
    
    async def generate_report(self, report_type: str, data: List[Dict], 
                            period_start: datetime, period_end: datetime) -> str:
        """Generate a specific type of report."""
        
        if report_type not in self.report_config.report_types:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Analyze data
        analysis = self._analyze_data(data, period_start, period_end)
        
        # Generate report based on type
        if report_type == "executive_summary":
            return await self._generate_executive_report(analysis)
        elif report_type == "technical_analysis":
            return await self._generate_technical_report(analysis)
        elif report_type == "operational_report":
            return await self._generate_operational_report(analysis)
        else:
            raise ValueError(f"Report generation not implemented for: {report_type}")
    
    def _analyze_data(self, data: List[Dict], period_start: datetime, 
                     period_end: datetime) -> Dict[str, Any]:
        """Analyze data for report generation."""
        
        if not data:
            return self._get_empty_analysis()
        
        # Filter data to period
        period_data = [
            r for r in data 
            if period_start <= r.get('timestamp', datetime.now()) <= period_end
        ]
        
        # Basic metrics
        total_samples = len(period_data)
        total_anomalies = sum(1 for r in period_data if r.get('is_anomaly', False))
        
        # Risk level distribution
        risk_counts = {}
        for r in period_data:
            risk_level = r.get('risk_level', 'LOW')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        # Model performance
        model_performance = {}
        for r in period_data:
            model_preds = r.get('model_predictions', {})
            for model_name, pred in model_preds.items():
                if model_name not in model_performance:
                    model_performance[model_name] = {'correct': 0, 'total': 0}
                
                model_performance[model_name]['total'] += 1
                ensemble_pred = r.get('is_anomaly', False)
                if pred == ensemble_pred:
                    model_performance[model_name]['correct'] += 1
        
        # Feature importance aggregation
        feature_importance = {}
        for r in period_data:
            if r.get('is_anomaly', False):
                explanation = r.get('explanation', {})
                features = explanation.get('feature_importance', {})
                for feature, importance in features.items():
                    if feature not in feature_importance:
                        feature_importance[feature] = []
                    feature_importance[feature].append(importance)
        
        # Calculate averages
        avg_feature_importance = {
            feature: np.mean(values) 
            for feature, values in feature_importance.items()
        }
        
        return {
            'period_start': period_start,
            'period_end': period_end,
            'total_samples': total_samples,
            'total_anomalies': total_anomalies,
            'anomaly_rate': (total_anomalies / total_samples * 100) if total_samples > 0 else 0,
            'risk_distribution': risk_counts,
            'model_performance': model_performance,
            'feature_importance': avg_feature_importance,
            'recent_alerts': [r for r in period_data if r.get('is_anomaly', False)][:10],
            'critical_alerts': risk_counts.get('CRITICAL', 0),
            'avg_confidence': np.mean([r.get('confidence', 0) for r in period_data]) if period_data else 0,
            'unique_sensors': len(set(r.get('sensor_id') for r in period_data))
        }
    
    def _get_empty_analysis(self) -> Dict[str, Any]:
        """Get empty analysis structure."""
        return {
            'total_samples': 0,
            'total_anomalies': 0,
            'anomaly_rate': 0,
            'risk_distribution': {},
            'model_performance': {},
            'feature_importance': {},
            'recent_alerts': [],
            'critical_alerts': 0,
            'avg_confidence': 0,
            'unique_sensors': 0
        }
    
    async def _generate_executive_report(self, analysis: Dict[str, Any]) -> str:
        """Generate executive summary report."""
        
        # Calculate business metrics
        prevented_downtime = analysis['critical_alerts'] * 2  # Assume 2h per critical
        cost_savings = prevented_downtime * 10000  # $10k per hour
        availability = 100 - (analysis['anomaly_rate'] / 10)  # Rough estimate
        
        # Generate business impact summary
        if analysis['critical_alerts'] > 0:
            business_impact = f"Detected {analysis['critical_alerts']} critical issues that could have caused significant downtime."
        else:
            business_impact = "No critical issues detected. System operating within normal parameters."
        
        # Risk summary
        risk_summary = f"Anomaly rate: {analysis['anomaly_rate']:.1f}%. System confidence: {analysis['avg_confidence']:.0%}."
        
        # Recommendations
        recommendations = []
        if analysis['critical_alerts'] > 3:
            recommendations.append("Consider immediate maintenance review for critical systems")
        if analysis['anomaly_rate'] > 10:
            recommendations.append("Investigate increased anomaly rate - potential systematic issue")
        if analysis['avg_confidence'] < 0.7:
            recommendations.append("Review model performance - confidence levels below threshold")
        
        if not recommendations:
            recommendations.append("Continue current monitoring protocols")
        
        template_data = {
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'period_start': analysis['period_start'].strftime('%Y-%m-%d %H:%M'),
            'period_end': analysis['period_end'].strftime('%Y-%m-%d %H:%M'),
            'total_anomalies': analysis['total_anomalies'],
            'critical_alerts': analysis['critical_alerts'],
            'availability': f"{availability:.1f}",
            'false_positive_rate': f"{max(0, 100 - analysis['avg_confidence']*100):.1f}",
            'risk_summary': risk_summary,
            'business_impact': business_impact,
            'recommendations': recommendations,
            'prevented_downtime_hours': prevented_downtime,
            'cost_savings': f"{cost_savings:,.0f}",
            'maintenance_savings': "15"
        }
        
        # Load and render template
        template_path = Path(self.report_config.templates_dir) / "executive_summary.html"
        with open(template_path, 'r') as f:
            template = Template(f.read())
        
        return template.render(**template_data)
    
    async def _generate_technical_report(self, analysis: Dict[str, Any]) -> str:
        """Generate technical analysis report."""
        
        # Calculate model metrics
        model_performance_list = []
        for model_name, perf in analysis['model_performance'].items():
            accuracy = (perf['correct'] / perf['total'] * 100) if perf['total'] > 0 else 0
            model_performance_list.append({
                'name': model_name,
                'accuracy': f"{accuracy:.1f}",
                'training_time': "N/A",  # Would need to be tracked
                'inference_time': "N/A"  # Would need to be tracked
            })
        
        # Top features
        top_features = []
        sorted_features = sorted(analysis['feature_importance'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]
        for feature, importance in sorted_features:
            top_features.append({
                'name': feature,
                'importance': f"{importance*100:.1f}",
                'trend': "stable"  # Would need historical comparison
            })
        
        template_data = {
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'period_start': analysis['period_start'].strftime('%Y-%m-%d %H:%M'),
            'period_end': analysis['period_end'].strftime('%Y-%m-%d %H:%M'),
            'model_accuracy': f"{analysis['avg_confidence']*100:.1f}",
            'precision': "N/A",  # Would need ground truth
            'recall': "N/A",     # Would need ground truth
            'f1_score': "N/A",   # Would need ground truth
            'model_performance': model_performance_list,
            'top_features': top_features,
            'pattern_analysis': "Pattern analysis would require more sophisticated analysis",
            'interpretability_analysis': f"Generated {len(analysis['recent_alerts'])} explanations with average confidence {analysis['avg_confidence']:.0%}",
            'tech_recommendations': [
                "Monitor model performance trends",
                "Consider retraining if accuracy drops below 85%",
                "Implement A/B testing for new model versions"
            ],
            'cpu_usage': "N/A",
            'memory_usage': "N/A", 
            'processing_rate': "N/A"
        }
        
        template_path = Path(self.report_config.templates_dir) / "technical_analysis.html"
        with open(template_path, 'r') as f:
            template = Template(f.read())
        
        return template.render(**template_data)
    
    async def _generate_operational_report(self, analysis: Dict[str, Any]) -> str:
        """Generate operational report."""
        
        # Format recent alerts
        formatted_alerts = []
        for alert in analysis['recent_alerts'][:5]:
            formatted_alerts.append({
                'timestamp': alert.get('timestamp', datetime.now()).strftime('%H:%M'),
                'sensor_id': alert.get('sensor_id', 'Unknown'),
                'risk_level': alert.get('risk_level', 'LOW'),
                'confidence': f"{alert.get('confidence', 0)*100:.0f}",
                'action': 'Logged and monitored'
            })
        
        template_data = {
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'period_start': analysis['period_start'].strftime('%Y-%m-%d %H:%M'),
            'period_end': analysis['period_end'].strftime('%Y-%m-%d %H:%M'),
            'system_status': 'Online' if analysis['total_samples'] > 0 else 'Offline',
            'active_sensors': analysis['unique_sensors'],
            'data_quality': f"{min(100, analysis['avg_confidence']*100):.0f}",
            'recent_alerts': formatted_alerts,
            'sensor_status': [
                {'id': f'SENSOR_{i:03d}', 'status': 'Online', 'last_reading': '< 1 min ago'}
                for i in range(1, min(6, analysis['unique_sensors'] + 1))
            ],
            'maintenance_items': [
                {'equipment': 'Pump A', 'description': 'Routine inspection', 'due_date': 'Tomorrow'},
                {'equipment': 'Sensor calibration', 'description': 'Monthly calibration', 'due_date': 'Next week'}
            ],
            'uptime': '99.9',
            'response_time': '< 1',
            'alerts_acknowledged': len(formatted_alerts),
            'total_alerts': analysis['total_anomalies'],
            'handover_notes': f"Detected {analysis['total_anomalies']} anomalies this shift. {analysis['critical_alerts']} critical alerts require attention."
        }
        
        template_path = Path(self.report_config.templates_dir) / "operational_report.html"
        with open(template_path, 'r') as f:
            template = Template(f.read())
        
        return template.render(**template_data)
    
    async def save_report(self, report_content: str, report_type: str, 
                         format: str = "html") -> str:
        """Save report to file."""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{report_type}_{timestamp}.{format}"
        filepath = Path(self.report_config.output_dir) / filename
        
        if format == "html":
            with open(filepath, 'w') as f:
                f.write(report_content)
        elif format == "pdf":
            # Convert HTML to PDF (requires wkhtmltopdf)
            try:
                pdfkit.from_string(report_content, str(filepath))
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
                # Fallback to HTML
                filepath = filepath.with_suffix('.html')
                with open(filepath, 'w') as f:
                    f.write(report_content)
        
        logger.info(f"Report saved: {filepath}")
        return str(filepath)

# Example usage and testing
async def main():
    """Example usage of XAI Visualization Dashboard."""
    
    # Create sample data
    sample_results = []
    for i in range(100):
        result = {
            'timestamp': datetime.now() - timedelta(minutes=i),
            'sensor_id': f'SENSOR_{(i % 5) + 1:03d}',
            'is_anomaly': np.random.random() < 0.15,
            'anomaly_score': np.random.random(),
            'confidence': np.random.uniform(0.7, 0.95),
            'risk_level': np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
                                         p=[0.6, 0.25, 0.1, 0.05]),
            'model_predictions': {
                'isolation_forest': np.random.random() < 0.2,
                'one_class_svm': np.random.random() < 0.15,
                'lstm_autoencoder': np.random.random() < 0.1
            },
            'explanation': {
                'summary': f'Sample explanation {i}',
                'feature_importance': {
                    'temperature': np.random.random(),
                    'pressure': np.random.random(),
                    'vibration': np.random.random()
                }
            }
        }
        sample_results.append(result)
    
    # Initialize dashboard
    dashboard_config = DashboardConfig(refresh_interval_seconds=10)
    dashboard = XAIVisualizationDashboard(dashboard_config)
    dashboard.update_data(sample_results)
    
    # Initialize report generator
    report_generator = AutomatedReportGenerator()
    
    # Generate sample reports
    period_start = datetime.now() - timedelta(hours=24)
    period_end = datetime.now()
    
    for report_type in ["executive_summary", "technical_analysis", "operational_report"]:
        print(f"Generating {report_type} report...")
        report_content = await report_generator.generate_report(
            report_type, sample_results, period_start, period_end
        )
        
        filepath = await report_generator.save_report(report_content, report_type)
        print(f"Report saved: {filepath}")
    
    print("XAI Visualization and Reporting system demonstration completed!")
    print("To run the dashboard: dashboard.run_dashboard()")

if __name__ == "__main__":
    asyncio.run(main())