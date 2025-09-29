#!/usr/bin/env python3
"""
DevSecOps Web Dashboard
Interface web de gestion et monitoring pour le système DevSecOps
"""

import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

# Flask et extensions pour l'interface web
from flask import Flask, render_template, jsonify, request, send_file, abort
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from flask_socketio import SocketIO, emit
import plotly.graph_objs as go
import plotly.utils

# Imports internes
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'monitoring'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'pipeline-orchestrator'))

from metrics_collector import MetricsCollector, MetricsDatabase, Alert, AlertSeverity
from security_orchestrator import SecurityOrchestrator, OrchestrationMode, ScanStage
from pipeline_adapters import PipelineAdapterFactory

class WebDashboard:
    """Interface web principale pour le dashboard DevSecOps"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.config['SECRET_KEY'] = config.get('secret_key', 'devsecops-dashboard-secret')
        
        # Configuration CORS pour permettre les requêtes cross-origin
        CORS(self.app)
        
        # Socket.IO pour les mises à jour en temps réel
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Composants
        self.metrics_collector = MetricsCollector(config.get('monitoring', {}))
        self.orchestrator = SecurityOrchestrator(config.get('orchestrator_config'))
        self.db = MetricsDatabase(config.get('database_path', './monitoring/metrics.db'))
        
        # État de l'application
        self.active_scans = {}
        self.websocket_clients = set()
        
        self._setup_routes()
        self._setup_websocket_events()
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure le logging pour l'application web"""
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('web_dashboard')
    
    def _setup_routes(self):
        """Configure les routes Flask"""
        
        @self.app.route('/')
        def index():
            """Page d'accueil du dashboard"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/dashboard/data')
        def dashboard_data():
            """API pour récupérer les données du dashboard"""
            hours = request.args.get('hours', 24, type=int)
            data = self.metrics_collector.get_dashboard_data(hours)
            return jsonify(data)
        
        @self.app.route('/api/projects')
        def projects_list():
            """API pour lister les projets"""
            projects = self._get_projects_summary()
            return jsonify(projects)
        
        @self.app.route('/api/projects/<project_name>/scans')
        def project_scans(project_name):
            """API pour récupérer les scans d'un projet"""
            hours = request.args.get('hours', 168, type=int)  # 7 jours par défaut
            scans = self._get_project_scans(project_name, hours)
            return jsonify(scans)
        
        @self.app.route('/api/scans/start', methods=['POST'])
        def start_scan():
            """API pour démarrer un nouveau scan"""
            data = request.get_json()
            
            if not data or 'project_path' not in data:
                return jsonify({'error': 'project_path required'}), 400
            
            try:
                # Paramètres du scan
                project_path = data['project_path']
                project_name = data.get('project_name', os.path.basename(project_path))
                mode = OrchestrationMode(data.get('mode', 'standard'))
                stage = ScanStage(data.get('stage', 'pre_build'))
                
                # Démarrer le scan de manière asynchrone
                scan_id = self._start_async_scan(project_path, project_name, mode, stage)
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'started',
                    'project_name': project_name,
                    'mode': mode.value,
                    'stage': stage.value
                })
                
            except Exception as e:
                self.logger.error(f"Error starting scan: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scans/<scan_id>/status')
        def scan_status(scan_id):
            """API pour récupérer le statut d'un scan"""
            if scan_id in self.active_scans:
                return jsonify(self.active_scans[scan_id])
            else:
                # Chercher dans l'historique
                scan_metrics = self.db.get_scan_metrics(hours=24)
                for scan in scan_metrics:
                    if scan.scan_id == scan_id:
                        return jsonify({
                            'scan_id': scan_id,
                            'status': 'completed' if scan.success else 'failed',
                            'project_name': scan.project_name,
                            'scan_type': scan.scan_type,
                            'start_time': scan.start_time.isoformat(),
                            'end_time': scan.end_time.isoformat() if scan.end_time else None,
                            'duration': scan.duration_seconds,
                            'issues_found': scan.issues_found,
                            'risk_score': scan.risk_score,
                            'error_message': scan.error_message
                        })
                
                return jsonify({'error': 'Scan not found'}), 404
        
        @self.app.route('/api/reports/<report_id>')
        def get_report(report_id):
            """API pour télécharger un rapport"""
            try:
                report_path = self._find_report_file(report_id)
                if report_path and os.path.exists(report_path):
                    return send_file(report_path)
                else:
                    return jsonify({'error': 'Report not found'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/alerts')
        def alerts_list():
            """API pour récupérer les alertes"""
            resolved = request.args.get('resolved', False, type=bool)
            hours = request.args.get('hours', 168, type=int)
            
            alerts = self.db.get_alerts(resolved=resolved, hours=hours)
            return jsonify([{
                'alert_id': alert.alert_id,
                'name': alert.name,
                'severity': alert.severity.value,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat(),
                'resolved': alert.resolved,
                'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None
            } for alert in alerts])
        
        @self.app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
        def resolve_alert(alert_id):
            """API pour résoudre une alerte"""
            try:
                alerts = self.db.get_alerts(resolved=False, hours=168)
                alert = next((a for a in alerts if a.alert_id == alert_id), None)
                
                if alert:
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
                    self.db.store_alert(alert)
                    
                    # Notifier via WebSocket
                    self.socketio.emit('alert_resolved', {
                        'alert_id': alert_id,
                        'resolved_at': alert.resolved_at.isoformat()
                    })
                    
                    return jsonify({'status': 'resolved'})
                else:
                    return jsonify({'error': 'Alert not found'}), 404
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/system/health')
        def system_health():
            """API pour vérifier l'état du système"""
            try:
                # Récupérer les métriques système récentes
                system_metrics = self.db.get_system_metrics(hours=1)
                current_metrics = system_metrics[0] if system_metrics else None
                
                health_status = {
                    'status': 'healthy',
                    'timestamp': datetime.now().isoformat(),
                    'services': {
                        'metrics_collector': self.metrics_collector.running,
                        'database': self._check_database_health(),
                        'orchestrator': True  # Toujours disponible
                    },
                    'system_metrics': {
                        'cpu_usage': current_metrics.cpu_usage if current_metrics else 0,
                        'memory_usage': current_metrics.memory_usage if current_metrics else 0,
                        'disk_usage': current_metrics.disk_usage if current_metrics else 0,
                        'active_scans': len(self.active_scans)
                    }
                }
                
                # Déterminer le statut global
                if not all(health_status['services'].values()):
                    health_status['status'] = 'degraded'
                
                if current_metrics:
                    if current_metrics.cpu_usage > 90 or current_metrics.memory_usage > 90:
                        health_status['status'] = 'critical'
                
                return jsonify(health_status)
                
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500
        
        @self.app.route('/api/charts/scans-timeline')
        def scans_timeline_chart():
            """API pour générer le graphique de timeline des scans"""
            hours = request.args.get('hours', 24, type=int)
            scan_metrics = self.db.get_scan_metrics(hours)
            
            # Données pour le graphique
            timestamps = []
            issues_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
            
            for scan in reversed(scan_metrics):
                timestamps.append(scan.start_time)
                issues_by_severity['critical'].append(scan.critical_issues)
                issues_by_severity['high'].append(scan.high_issues)
                issues_by_severity['medium'].append(scan.medium_issues)
                issues_by_severity['low'].append(scan.low_issues)
            
            # Créer le graphique Plotly
            traces = []
            colors = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}
            
            for severity, issues in issues_by_severity.items():
                traces.append(go.Scatter(
                    x=timestamps,
                    y=issues,
                    mode='lines+markers',
                    name=severity.title(),
                    line=dict(color=colors[severity])
                ))
            
            layout = go.Layout(
                title='Security Issues Timeline',
                xaxis=dict(title='Time'),
                yaxis=dict(title='Number of Issues'),
                hovermode='closest'
            )
            
            fig = go.Figure(data=traces, layout=layout)
            
            return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
        
        @self.app.route('/api/charts/system-metrics')
        def system_metrics_chart():
            """API pour générer le graphique des métriques système"""
            hours = request.args.get('hours', 24, type=int)
            system_metrics = self.db.get_system_metrics(hours)
            
            if not system_metrics:
                return jsonify({'error': 'No system metrics available'}), 404
            
            # Données pour le graphique
            timestamps = [m.timestamp for m in reversed(system_metrics)]
            cpu_usage = [m.cpu_usage for m in reversed(system_metrics)]
            memory_usage = [m.memory_usage for m in reversed(system_metrics)]
            
            traces = [
                go.Scatter(
                    x=timestamps, y=cpu_usage, mode='lines', name='CPU Usage (%)',
                    line=dict(color='#007bff')
                ),
                go.Scatter(
                    x=timestamps, y=memory_usage, mode='lines', name='Memory Usage (%)',
                    line=dict(color='#28a745')
                )
            ]
            
            layout = go.Layout(
                title='System Metrics',
                xaxis=dict(title='Time'),
                yaxis=dict(title='Usage (%)', range=[0, 100]),
                hovermode='closest'
            )
            
            fig = go.Figure(data=traces, layout=layout)
            
            return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
    
    def _setup_websocket_events(self):
        """Configure les événements WebSocket"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Gère les connexions WebSocket"""
            self.websocket_clients.add(request.sid)
            emit('connected', {'status': 'connected'})
            self.logger.info(f"WebSocket client connected: {request.sid}")
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Gère les déconnexions WebSocket"""
            self.websocket_clients.discard(request.sid)
            self.logger.info(f"WebSocket client disconnected: {request.sid}")
        
        @self.socketio.on('subscribe_scans')
        def handle_subscribe_scans():
            """Abonnement aux mises à jour de scans"""
            emit('subscribed', {'type': 'scans'})
    
    def _start_async_scan(self, project_path: str, project_name: str, 
                         mode: OrchestrationMode, stage: ScanStage) -> str:
        """Démarre un scan de manière asynchrone"""
        import threading
        import uuid
        
        scan_id = str(uuid.uuid4())
        
        # Enregistrer le scan actif
        self.active_scans[scan_id] = {
            'scan_id': scan_id,
            'status': 'starting',
            'project_name': project_name,
            'mode': mode.value,
            'stage': stage.value,
            'start_time': datetime.now().isoformat(),
            'progress': 0
        }
        
        # Notifier via WebSocket
        self.socketio.emit('scan_started', self.active_scans[scan_id])
        
        def run_scan():
            """Fonction pour exécuter le scan dans un thread séparé"""
            try:
                # Mettre à jour le statut
                self.active_scans[scan_id]['status'] = 'running'
                self.active_scans[scan_id]['progress'] = 10
                self.socketio.emit('scan_progress', self.active_scans[scan_id])
                
                # Enregistrer le début du scan dans les métriques
                self.metrics_collector.record_scan_start(scan_id, project_name, mode.value)
                
                # Exécuter le scan via l'orchestrateur
                self.active_scans[scan_id]['progress'] = 30
                self.socketio.emit('scan_progress', self.active_scans[scan_id])
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                report = loop.run_until_complete(
                    self.orchestrator.orchestrate_security_scan(
                        project_path=project_path,
                        project_name=project_name,
                        mode=mode,
                        stage=stage
                    )
                )
                
                loop.close()
                
                # Mettre à jour le statut final
                self.active_scans[scan_id]['status'] = 'completed' if report.security_gate_passed else 'failed'
                self.active_scans[scan_id]['progress'] = 100
                self.active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                self.active_scans[scan_id]['issues_found'] = report.total_issues
                self.active_scans[scan_id]['risk_score'] = report.risk_score
                self.active_scans[scan_id]['security_gate_passed'] = report.security_gate_passed
                
                # Enregistrer la fin du scan dans les métriques
                issues_by_severity = {
                    'critical': report.critical_issues,
                    'high': report.high_issues,
                    'medium': report.medium_issues,
                    'low': report.low_issues
                }
                
                self.metrics_collector.record_scan_completion(
                    scan_id=scan_id,
                    success=report.security_gate_passed,
                    issues_by_severity=issues_by_severity,
                    risk_score=report.risk_score,
                    error_message=None
                )
                
                # Notifier la fin du scan
                self.socketio.emit('scan_completed', self.active_scans[scan_id])
                
                # Nettoyer après 1 heure
                def cleanup():
                    import time
                    time.sleep(3600)  # 1 heure
                    if scan_id in self.active_scans:
                        del self.active_scans[scan_id]
                
                cleanup_thread = threading.Thread(target=cleanup)
                cleanup_thread.daemon = True
                cleanup_thread.start()
                
            except Exception as e:
                # Erreur dans le scan
                self.active_scans[scan_id]['status'] = 'error'
                self.active_scans[scan_id]['error'] = str(e)
                self.active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                
                self.logger.error(f"Scan {scan_id} failed: {e}")
                
                # Enregistrer l'échec
                self.metrics_collector.record_scan_completion(
                    scan_id=scan_id,
                    success=False,
                    issues_by_severity={},
                    risk_score=0,
                    error_message=str(e)
                )
                
                self.socketio.emit('scan_error', self.active_scans[scan_id])
        
        # Démarrer le scan dans un thread séparé
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        return scan_id
    
    def _get_projects_summary(self) -> List[Dict[str, Any]]:
        """Récupère un résumé de tous les projets"""
        scan_metrics = self.db.get_scan_metrics(hours=168)  # 7 jours
        
        projects = {}
        for scan in scan_metrics:
            if scan.project_name not in projects:
                projects[scan.project_name] = {
                    'name': scan.project_name,
                    'total_scans': 0,
                    'successful_scans': 0,
                    'failed_scans': 0,
                    'total_issues': 0,
                    'critical_issues': 0,
                    'high_issues': 0,
                    'last_scan': None,
                    'average_risk_score': 0,
                    'scan_types': set()
                }
            
            project = projects[scan.project_name]
            project['total_scans'] += 1
            project['scan_types'].add(scan.scan_type)
            
            if scan.success:
                project['successful_scans'] += 1
            else:
                project['failed_scans'] += 1
            
            project['total_issues'] += scan.issues_found
            project['critical_issues'] += scan.critical_issues
            project['high_issues'] += scan.high_issues
            
            if not project['last_scan'] or scan.start_time > project['last_scan']:
                project['last_scan'] = scan.start_time.isoformat()
        
        # Calculer les moyennes et nettoyer
        for project in projects.values():
            if project['total_scans'] > 0:
                project['average_risk_score'] = sum(
                    s.risk_score for s in scan_metrics 
                    if s.project_name == project['name']
                ) / project['total_scans']
            
            project['scan_types'] = list(project['scan_types'])
        
        return list(projects.values())
    
    def _get_project_scans(self, project_name: str, hours: int) -> List[Dict[str, Any]]:
        """Récupère les scans d'un projet spécifique"""
        scan_metrics = self.db.get_scan_metrics(hours)
        project_scans = [s for s in scan_metrics if s.project_name == project_name]
        
        return [{
            'scan_id': scan.scan_id,
            'scan_type': scan.scan_type,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration_seconds': scan.duration_seconds,
            'success': scan.success,
            'issues_found': scan.issues_found,
            'critical_issues': scan.critical_issues,
            'high_issues': scan.high_issues,
            'medium_issues': scan.medium_issues,
            'low_issues': scan.low_issues,
            'risk_score': scan.risk_score,
            'error_message': scan.error_message
        } for scan in project_scans]
    
    def _find_report_file(self, report_id: str) -> Optional[str]:
        """Trouve le fichier de rapport correspondant à un ID"""
        reports_dir = Path('./security-reports')
        
        if reports_dir.exists():
            for file_path in reports_dir.glob(f'*{report_id}*'):
                return str(file_path)
        
        return None
    
    def _check_database_health(self) -> bool:
        """Vérifie l'état de la base de données"""
        try:
            test_metrics = self.db.get_system_metrics(hours=1)
            return True
        except Exception:
            return False
    
    def start(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
        """Démarre le serveur web"""
        self.logger.info(f"Starting DevSecOps Dashboard on {host}:{port}")
        
        # Démarrer le collecteur de métriques
        self.metrics_collector.start()
        
        # Démarrer le serveur web
        self.socketio.run(self.app, host=host, port=port, debug=debug)
    
    def stop(self):
        """Arrête le serveur web"""
        self.metrics_collector.stop()
        self.logger.info("DevSecOps Dashboard stopped")

# Templates HTML intégrés
def create_dashboard_template():
    """Crée le template HTML principal du dashboard"""
    template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Security Dashboard</title>
    
    <!-- CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
            margin: 10px;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .metric-label {
            font-size: 0.9em;
            opacity: 0.8;
        }
        .alert-item {
            border-left: 4px solid;
            margin-bottom: 10px;
        }
        .alert-critical { border-left-color: #dc3545; }
        .alert-error { border-left-color: #fd7e14; }
        .alert-warning { border-left-color: #ffc107; }
        .alert-info { border-left-color: #17a2b8; }
        
        .scan-status-running { color: #007bff; }
        .scan-status-completed { color: #28a745; }
        .scan-status-failed { color: #dc3545; }
        .scan-status-error { color: #dc3545; }
        
        .progress-ring {
            width: 50px;
            height: 50px;
        }
        
        .sidebar {
            min-height: 100vh;
            background: #2c3e50;
        }
        
        .nav-link {
            color: #bdc3c7 !important;
        }
        
        .nav-link:hover, .nav-link.active {
            color: #3498db !important;
            background-color: rgba(52, 152, 219, 0.1);
        }
        
        .main-content {
            background-color: #f8f9fa;
            min-height: 100vh;
        }
        
        .chart-container {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 sidebar">
                <div class="p-3">
                    <h4 class="text-white">
                        <i class="fas fa-shield-alt"></i> DevSecOps
                    </h4>
                </div>
                <nav class="nav flex-column">
                    <a class="nav-link active" href="#" data-tab="dashboard">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                    <a class="nav-link" href="#" data-tab="projects">
                        <i class="fas fa-folder-open"></i> Projects
                    </a>
                    <a class="nav-link" href="#" data-tab="scans">
                        <i class="fas fa-search"></i> Security Scans
                    </a>
                    <a class="nav-link" href="#" data-tab="alerts">
                        <i class="fas fa-exclamation-triangle"></i> Alerts
                    </a>
                    <a class="nav-link" href="#" data-tab="reports">
                        <i class="fas fa-chart-bar"></i> Reports
                    </a>
                    <a class="nav-link" href="#" data-tab="settings">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                </nav>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-10 main-content">
                <div class="p-4">
                    <!-- Header -->
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 id="page-title">Security Dashboard</h2>
                        <div>
                            <button class="btn btn-primary" id="start-scan-btn">
                                <i class="fas fa-play"></i> Start Scan
                            </button>
                            <button class="btn btn-outline-secondary" id="refresh-btn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                        </div>
                    </div>
                    
                    <!-- Content Area -->
                    <div id="content-area">
                        <!-- Dashboard Tab -->
                        <div id="dashboard-tab" class="tab-content active">
                            <!-- Metrics Cards -->
                            <div class="row" id="metrics-cards">
                                <!-- Cards will be populated by JavaScript -->
                            </div>
                            
                            <!-- Charts -->
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="chart-container">
                                        <h5>Security Issues Timeline</h5>
                                        <div id="timeline-chart"></div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="chart-container">
                                        <h5>System Health</h5>
                                        <div id="system-chart"></div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Recent Scans -->
                            <div class="chart-container">
                                <h5>Recent Scans</h5>
                                <div class="table-responsive">
                                    <table class="table table-hover" id="recent-scans-table">
                                        <thead>
                                            <tr>
                                                <th>Project</th>
                                                <th>Type</th>
                                                <th>Status</th>
                                                <th>Issues</th>
                                                <th>Risk Score</th>
                                                <th>Duration</th>
                                                <th>Time</th>
                                            </tr>
                                        </thead>
                                        <tbody></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Other tabs content will be added here -->
                        <div id="projects-tab" class="tab-content">
                            <div class="chart-container">
                                <h5>Projects Overview</h5>
                                <div id="projects-list"></div>
                            </div>
                        </div>
                        
                        <div id="scans-tab" class="tab-content">
                            <div class="chart-container">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <h5>Active Scans</h5>
                                    <button class="btn btn-success" id="new-scan-btn">
                                        <i class="fas fa-plus"></i> New Scan
                                    </button>
                                </div>
                                <div id="active-scans-list"></div>
                            </div>
                        </div>
                        
                        <div id="alerts-tab" class="tab-content">
                            <div class="chart-container">
                                <h5>Active Alerts</h5>
                                <div id="alerts-list"></div>
                            </div>
                        </div>
                        
                        <div id="reports-tab" class="tab-content">
                            <div class="chart-container">
                                <h5>Security Reports</h5>
                                <div id="reports-list"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <!-- Start Scan Modal -->
    <div class="modal fade" id="startScanModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Start Security Scan</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="start-scan-form">
                        <div class="mb-3">
                            <label class="form-label">Project Path</label>
                            <input type="text" class="form-control" name="project_path" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Project Name</label>
                            <input type="text" class="form-control" name="project_name">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Scan Mode</label>
                            <select class="form-select" name="mode">
                                <option value="fast">Fast</option>
                                <option value="standard" selected>Standard</option>
                                <option value="comprehensive">Comprehensive</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Pipeline Stage</label>
                            <select class="form-select" name="stage">
                                <option value="pre_build" selected>Pre-Build</option>
                                <option value="build">Build</option>
                                <option value="post_build">Post-Build</option>
                                <option value="deploy">Deploy</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirm-start-scan">Start Scan</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    
    <script>
        // Global variables
        let socket = null;
        let currentTab = 'dashboard';
        let dashboardData = {};
        
        // Initialize the application
        document.addEventListener('DOMContentLoaded', function() {
            initializeApp();
            setupEventHandlers();
            connectWebSocket();
            loadDashboardData();
        });
        
        function initializeApp() {
            // Set up tab navigation
            const navLinks = document.querySelectorAll('.nav-link');
            navLinks.forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    switchTab(this.getAttribute('data-tab'));
                    
                    // Update active state
                    navLinks.forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                });
            });
        }
        
        function setupEventHandlers() {
            // Start scan button
            document.getElementById('start-scan-btn').addEventListener('click', function() {
                new bootstrap.Modal(document.getElementById('startScanModal')).show();
            });
            
            // Confirm start scan
            document.getElementById('confirm-start-scan').addEventListener('click', function() {
                startScan();
            });
            
            // Refresh button
            document.getElementById('refresh-btn').addEventListener('click', function() {
                loadDashboardData();
                this.classList.add('fa-spin');
                setTimeout(() => this.classList.remove('fa-spin'), 1000);
            });
        }
        
        function connectWebSocket() {
            socket = io();
            
            socket.on('connect', function() {
                console.log('Connected to WebSocket');
                socket.emit('subscribe_scans');
            });
            
            socket.on('scan_started', function(data) {
                console.log('Scan started:', data);
                updateActiveScan(data);
            });
            
            socket.on('scan_progress', function(data) {
                console.log('Scan progress:', data);
                updateActiveScan(data);
            });
            
            socket.on('scan_completed', function(data) {
                console.log('Scan completed:', data);
                updateActiveScan(data);
                loadDashboardData(); // Refresh dashboard
            });
            
            socket.on('scan_error', function(data) {
                console.log('Scan error:', data);
                updateActiveScan(data);
            });
        }
        
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
                tab.style.display = 'none';
            });
            
            // Show selected tab
            const selectedTab = document.getElementById(tabName + '-tab');
            if (selectedTab) {
                selectedTab.classList.add('active');
                selectedTab.style.display = 'block';
            }
            
            currentTab = tabName;
            
            // Update page title
            const titles = {
                'dashboard': 'Security Dashboard',
                'projects': 'Projects',
                'scans': 'Security Scans',
                'alerts': 'Alerts',
                'reports': 'Reports',
                'settings': 'Settings'
            };
            document.getElementById('page-title').textContent = titles[tabName] || 'Dashboard';
            
            // Load tab-specific data
            switch(tabName) {
                case 'projects':
                    loadProjectsData();
                    break;
                case 'alerts':
                    loadAlertsData();
                    break;
                case 'scans':
                    loadScansData();
                    break;
            }
        }
        
        async function loadDashboardData() {
            try {
                const response = await fetch('/api/dashboard/data?hours=24');
                dashboardData = await response.json();
                
                updateMetricsCards();
                updateRecentScansTable();
                loadCharts();
                
            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }
        
        function updateMetricsCards() {
            const cards = [
                {
                    title: 'Total Scans',
                    value: dashboardData.scan_stats?.total_scans || 0,
                    icon: 'fas fa-search',
                    color: '#3498db'
                },
                {
                    title: 'Critical Issues',
                    value: dashboardData.scan_stats?.critical_issues || 0,
                    icon: 'fas fa-exclamation-circle',
                    color: '#e74c3c'
                },
                {
                    title: 'Avg Risk Score',
                    value: Math.round(dashboardData.scan_stats?.average_risk_score || 0),
                    icon: 'fas fa-shield-alt',
                    color: '#f39c12'
                },
                {
                    title: 'Active Scans',
                    value: dashboardData.system_metrics?.active_scans || 0,
                    icon: 'fas fa-spinner',
                    color: '#27ae60'
                }
            ];
            
            const cardsHtml = cards.map(card => `
                <div class="col-md-3">
                    <div class="metric-card" style="background: linear-gradient(135deg, ${card.color}, ${card.color}CC)">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="metric-value">${card.value}</div>
                                <div class="metric-label">${card.title}</div>
                            </div>
                            <div><i class="${card.icon} fa-2x"></i></div>
                        </div>
                    </div>
                </div>
            `).join('');
            
            document.getElementById('metrics-cards').innerHTML = cardsHtml;
        }
        
        function updateRecentScansTable() {
            const tbody = document.querySelector('#recent-scans-table tbody');
            
            if (!dashboardData.recent_scans) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center">No recent scans</td></tr>';
                return;
            }
            
            const rowsHtml = dashboardData.recent_scans.map(scan => `
                <tr>
                    <td>${scan.project_name}</td>
                    <td><span class="badge bg-info">${scan.scan_type}</span></td>
                    <td>
                        <span class="scan-status-${scan.success ? 'completed' : 'failed'}">
                            <i class="fas fa-${scan.success ? 'check' : 'times'}"></i>
                            ${scan.success ? 'Success' : 'Failed'}
                        </span>
                    </td>
                    <td>${scan.issues_found}</td>
                    <td>${Math.round(scan.risk_score)}</td>
                    <td>${Math.round(scan.duration_seconds)}s</td>
                    <td>${new Date(scan.start_time).toLocaleString()}</td>
                </tr>
            `).join('');
            
            tbody.innerHTML = rowsHtml;
        }
        
        async function loadCharts() {
            try {
                // Timeline chart
                const timelineResponse = await fetch('/api/charts/scans-timeline?hours=24');
                const timelineData = await timelineResponse.json();
                Plotly.newPlot('timeline-chart', timelineData.data, timelineData.layout, {responsive: true});
                
                // System metrics chart
                const systemResponse = await fetch('/api/charts/system-metrics?hours=24');
                const systemData = await systemResponse.json();
                Plotly.newPlot('system-chart', systemData.data, systemData.layout, {responsive: true});
                
            } catch (error) {
                console.error('Error loading charts:', error);
            }
        }
        
        async function startScan() {
            const form = document.getElementById('start-scan-form');
            const formData = new FormData(form);
            
            const scanData = {
                project_path: formData.get('project_path'),
                project_name: formData.get('project_name') || null,
                mode: formData.get('mode'),
                stage: formData.get('stage')
            };
            
            try {
                const response = await fetch('/api/scans/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(scanData)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    bootstrap.Modal.getInstance(document.getElementById('startScanModal')).hide();
                    form.reset();
                    
                    // Show success message
                    console.log('Scan started successfully:', result);
                } else {
                    alert('Error starting scan: ' + result.error);
                }
                
            } catch (error) {
                console.error('Error starting scan:', error);
                alert('Error starting scan: ' + error.message);
            }
        }
        
        function updateActiveScan(scanData) {
            // Update active scans display if on scans tab
            if (currentTab === 'scans') {
                loadScansData();
            }
        }
        
        async function loadProjectsData() {
            try {
                const response = await fetch('/api/projects');
                const projects = await response.json();
                
                const projectsHtml = projects.map(project => `
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">${project.name}</h5>
                            <div class="row">
                                <div class="col-md-3">
                                    <small class="text-muted">Total Scans</small>
                                    <div class="h4">${project.total_scans}</div>
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">Success Rate</small>
                                    <div class="h4">${Math.round(project.successful_scans / project.total_scans * 100)}%</div>
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">Critical Issues</small>
                                    <div class="h4 text-danger">${project.critical_issues}</div>
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">Last Scan</small>
                                    <div>${project.last_scan ? new Date(project.last_scan).toLocaleDateString() : 'Never'}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('');
                
                document.getElementById('projects-list').innerHTML = projectsHtml;
                
            } catch (error) {
                console.error('Error loading projects:', error);
            }
        }
        
        async function loadAlertsData() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                
                const alertsHtml = alerts.map(alert => `
                    <div class="alert-item alert alert-${alert.severity} d-flex justify-content-between align-items-center">
                        <div>
                            <strong>${alert.name}</strong><br>
                            <small>${alert.message}</small><br>
                            <small class="text-muted">${new Date(alert.timestamp).toLocaleString()}</small>
                        </div>
                        <button class="btn btn-sm btn-outline-secondary" onclick="resolveAlert('${alert.alert_id}')">
                            <i class="fas fa-check"></i> Resolve
                        </button>
                    </div>
                `).join('');
                
                document.getElementById('alerts-list').innerHTML = alertsHtml || '<p class="text-muted">No active alerts</p>';
                
            } catch (error) {
                console.error('Error loading alerts:', error);
            }
        }
        
        async function loadScansData() {
            // Implementation for loading active scans
            const scansHtml = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    Active scans will appear here in real-time
                </div>
            `;
            
            document.getElementById('active-scans-list').innerHTML = scansHtml;
        }
        
        async function resolveAlert(alertId) {
            try {
                const response = await fetch(`/api/alerts/${alertId}/resolve`, {
                    method: 'POST'
                });
                
                if (response.ok) {
                    loadAlertsData(); // Reload alerts
                }
                
            } catch (error) {
                console.error('Error resolving alert:', error);
            }
        }
        
        // Auto-refresh every 30 seconds
        setInterval(function() {
            if (currentTab === 'dashboard') {
                loadDashboardData();
            }
        }, 30000);
    </script>
</body>
</html>'''
    
    return template_content

def main():
    """Point d'entrée principal pour le dashboard"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecOps Web Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Configuration par défaut
    config = {
        'secret_key': 'devsecops-dashboard-secret-key',
        'database_path': './monitoring/metrics.db',
        'monitoring': {
            'database_path': './monitoring/metrics.db',
            'prometheus': {
                'enabled': False,
                'port': 9090
            }
        }
    }
    
    # Charger la configuration personnalisée si fournie
    if args.config and os.path.exists(args.config):
        import yaml
        with open(args.config, 'r') as f:
            user_config = yaml.safe_load(f)
            config.update(user_config)
    
    # Créer le répertoire des templates
    templates_dir = Path('./dashboard/templates')
    templates_dir.mkdir(parents=True, exist_ok=True)
    
    # Créer le template HTML
    template_path = templates_dir / 'dashboard.html'
    with open(template_path, 'w', encoding='utf-8') as f:
        f.write(create_dashboard_template())
    
    # Démarrer le dashboard
    dashboard = WebDashboard(config)
    
    try:
        dashboard.start(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
        dashboard.stop()

if __name__ == "__main__":
    main()