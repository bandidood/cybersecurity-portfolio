#!/usr/bin/env python3
"""
Dashboard de Monitoring Temps Réel IDS/IPS
Projet 04 - Cybersecurity Portfolio

Interface web Flask pour monitoring en temps réel des alertes,
statistiques et métriques de performance des systèmes IDS/IPS.

Usage: python3 ids-dashboard.py --host 0.0.0.0 --port 5000
"""

import os
import sys
import json
import time
import logging
import argparse
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
import queue

# Flask et extensions
from flask import Flask, render_template_string, jsonify, request, Response
from flask_socketio import SocketIO, emit
import requests

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IDSMonitor:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialisation du moniteur IDS/IPS
        
        Args:
            config: Configuration du dashboard
        """
        self.config = config
        self.running = False
        
        # Stockage des données en mémoire
        self.alerts_buffer = deque(maxlen=1000)  # 1000 alertes max
        self.stats_buffer = deque(maxlen=60)     # 60 points de stats (1 min)
        self.performance_buffer = deque(maxlen=100)  # 100 points perf
        
        # Queues pour communication inter-threads
        self.alert_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        
        # Métriques en temps réel
        self.current_metrics = {
            'total_alerts': 0,
            'alerts_per_minute': 0,
            'top_attack_types': {},
            'top_source_ips': {},
            'top_target_ips': {},
            'severity_distribution': {1: 0, 2: 0, 3: 0, 4: 0},
            'system_health': {
                'suricata_status': 'unknown',
                'snort_status': 'unknown',
                'elasticsearch_status': 'unknown',
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0
            }
        }
        
        # Configuration des sources
        self.sources = {
            'suricata': {
                'log_path': config.get('suricata_log_path', '/var/log/suricata/eve.json'),
                'enabled': config.get('monitor_suricata', True)
            },
            'snort': {
                'log_path': config.get('snort_log_path', '/var/log/snort/alert'),
                'enabled': config.get('monitor_snort', True)
            },
            'elasticsearch': {
                'url': config.get('elasticsearch_url', 'http://localhost:9200'),
                'enabled': config.get('monitor_elasticsearch', True)
            }
        }
        
        logger.info("🖥️ Moniteur IDS/IPS initialisé")

    def start_monitoring(self):
        """Démarrage du monitoring"""
        if self.running:
            return
            
        self.running = True
        logger.info("🚀 Démarrage du monitoring IDS/IPS")
        
        # Démarrage des threads de monitoring
        threads = []
        
        if self.sources['suricata']['enabled']:
            t = threading.Thread(target=self._monitor_suricata)
            t.daemon = True
            t.start()
            threads.append(t)
            
        if self.sources['snort']['enabled']:
            t = threading.Thread(target=self._monitor_snort)
            t.daemon = True
            t.start()
            threads.append(t)
            
        if self.sources['elasticsearch']['enabled']:
            t = threading.Thread(target=self._monitor_elasticsearch)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Thread de traitement des alertes
        t = threading.Thread(target=self._process_alerts)
        t.daemon = True
        t.start()
        threads.append(t)
        
        # Thread de collecte des stats système
        t = threading.Thread(target=self._collect_system_stats)
        t.daemon = True
        t.start()
        threads.append(t)
        
        # Thread de calcul des métriques
        t = threading.Thread(target=self._calculate_metrics)
        t.daemon = True
        t.start()
        threads.append(t)
        
        logger.info(f"✅ {len(threads)} threads de monitoring démarrés")

    def stop_monitoring(self):
        """Arrêt du monitoring"""
        logger.info("⏹️ Arrêt du monitoring IDS/IPS")
        self.running = False

    def _monitor_suricata(self):
        """Monitoring des logs Suricata"""
        log_path = self.sources['suricata']['log_path']
        logger.info(f"📊 Monitoring Suricata: {log_path}")
        
        if not Path(log_path).exists():
            logger.warning(f"⚠️ Fichier log Suricata non trouvé: {log_path}")
            return
        
        try:
            # Suivi du fichier en temps réel (tail -f)
            with open(log_path, 'r') as f:
                # Se positionner à la fin du fichier
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        try:
                            log_entry = json.loads(line.strip())
                            if log_entry.get('event_type') == 'alert':
                                alert = self._parse_suricata_alert(log_entry)
                                self.alert_queue.put(alert)
                        except json.JSONDecodeError:
                            continue
                    else:
                        time.sleep(0.1)  # Attendre nouvelles données
                        
        except Exception as e:
            logger.error(f"❌ Erreur monitoring Suricata: {e}")

    def _monitor_snort(self):
        """Monitoring des logs Snort"""
        log_path = self.sources['snort']['log_path']
        logger.info(f"📊 Monitoring Snort: {log_path}")
        
        # Snort peut avoir plusieurs formats de logs
        log_files = [
            log_path,
            '/var/log/snort/snort.log',
            '/var/log/snort/alert.fast'
        ]
        
        active_log = None
        for log_file in log_files:
            if Path(log_file).exists():
                active_log = log_file
                break
        
        if not active_log:
            logger.warning("⚠️ Aucun fichier log Snort trouvé")
            return
        
        try:
            with open(active_log, 'r') as f:
                f.seek(0, 2)  # Fin du fichier
                
                while self.running:
                    line = f.readline()
                    if line and '[**]' in line:
                        alert = self._parse_snort_alert(line)
                        self.alert_queue.put(alert)
                    elif not line:
                        time.sleep(0.1)
                        
        except Exception as e:
            logger.error(f"❌ Erreur monitoring Snort: {e}")

    def _monitor_elasticsearch(self):
        """Monitoring via Elasticsearch"""
        es_url = self.sources['elasticsearch']['url']
        logger.info(f"📊 Monitoring Elasticsearch: {es_url}")
        
        last_query_time = datetime.now() - timedelta(minutes=1)
        
        while self.running:
            try:
                # Requête pour les nouvelles alertes
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {
                                    "@timestamp": {
                                        "gte": last_query_time.isoformat()
                                    }
                                }},
                                {"exists": {"field": "alert"}}
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "size": 50
                }
                
                response = requests.post(
                    f"{es_url}/suricata-*/_search",
                    json=query,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    hits = data.get('hits', {}).get('hits', [])
                    
                    for hit in hits:
                        alert = self._parse_elasticsearch_alert(hit['_source'])
                        self.alert_queue.put(alert)
                    
                    if hits:
                        last_query_time = datetime.now()
                
                time.sleep(5)  # Requête toutes les 5 secondes
                
            except Exception as e:
                logger.debug(f"Erreur requête Elasticsearch: {e}")
                time.sleep(10)  # Attendre plus longtemps en cas d'erreur

    def _parse_suricata_alert(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse une alerte Suricata"""
        alert_data = log_entry.get('alert', {})
        
        return {
            'source': 'suricata',
            'timestamp': log_entry.get('timestamp', datetime.now().isoformat()),
            'signature': alert_data.get('signature', ''),
            'signature_id': alert_data.get('signature_id', 0),
            'severity': alert_data.get('severity', 3),
            'category': alert_data.get('category', ''),
            'action': alert_data.get('action', ''),
            'src_ip': log_entry.get('src_ip', ''),
            'src_port': log_entry.get('src_port', 0),
            'dest_ip': log_entry.get('dest_ip', ''),
            'dest_port': log_entry.get('dest_port', 0),
            'proto': log_entry.get('proto', ''),
            'attack_type': self._classify_attack_type(alert_data.get('signature', '')),
            'raw_data': log_entry
        }

    def _parse_snort_alert(self, line: str) -> Dict[str, Any]:
        """Parse une alerte Snort"""
        # Format typique Snort: [**] [1:2100498:7] GPL CHAT IRC message [**] [Classification: ...] [Priority: 3] 
        
        signature = ''
        signature_id = 0
        severity = 3
        
        # Extraction signature
        if '[**]' in line:
            parts = line.split('[**]')
            if len(parts) > 2:
                signature = parts[2].strip()
        
        # Extraction ID
        if '[1:' in line:
            import re
            match = re.search(r'\[1:(\d+):\d+\]', line)
            if match:
                signature_id = int(match.group(1))
        
        # Extraction priorité
        if '[Priority:' in line:
            import re
            match = re.search(r'\[Priority: (\d+)\]', line)
            if match:
                severity = int(match.group(1))
        
        return {
            'source': 'snort',
            'timestamp': datetime.now().isoformat(),
            'signature': signature,
            'signature_id': signature_id,
            'severity': severity,
            'category': 'unknown',
            'action': 'alert',
            'src_ip': '',
            'src_port': 0,
            'dest_ip': '',
            'dest_port': 0,
            'proto': '',
            'attack_type': self._classify_attack_type(signature),
            'raw_data': {'raw_line': line}
        }

    def _parse_elasticsearch_alert(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Parse une alerte depuis Elasticsearch"""
        alert_data = doc.get('alert', {})
        
        return {
            'source': 'elasticsearch',
            'timestamp': doc.get('@timestamp', datetime.now().isoformat()),
            'signature': alert_data.get('signature', ''),
            'signature_id': alert_data.get('signature_id', 0),
            'severity': alert_data.get('severity', 3),
            'category': alert_data.get('category', ''),
            'action': alert_data.get('action', ''),
            'src_ip': doc.get('src_ip', ''),
            'src_port': doc.get('src_port', 0),
            'dest_ip': doc.get('dest_ip', ''),
            'dest_port': doc.get('dest_port', 0),
            'proto': doc.get('proto', ''),
            'attack_type': self._classify_attack_type(alert_data.get('signature', '')),
            'raw_data': doc
        }

    def _classify_attack_type(self, signature: str) -> str:
        """Classification automatique du type d'attaque"""
        signature_lower = signature.lower()
        
        if any(word in signature_lower for word in ['scan', 'port', 'reconnaissance', 'probe']):
            return 'port_scan'
        elif any(word in signature_lower for word in ['brute', 'login', 'auth', 'credential']):
            return 'brute_force'
        elif any(word in signature_lower for word in ['sql', 'injection', 'xss', 'script']):
            return 'web_attack'
        elif any(word in signature_lower for word in ['ddos', 'flood', 'dos']):
            return 'ddos'
        elif any(word in signature_lower for word in ['malware', 'trojan', 'virus', 'backdoor']):
            return 'malware'
        elif any(word in signature_lower for word in ['exploit', 'overflow', 'shellcode']):
            return 'exploit'
        elif any(word in signature_lower for word in ['lateral', 'smb', 'rdp', 'movement']):
            return 'lateral_movement'
        elif any(word in signature_lower for word in ['exfil', 'transfer', 'upload', 'tunnel']):
            return 'data_exfiltration'
        else:
            return 'other'

    def _process_alerts(self):
        """Traitement des alertes en file d'attente"""
        logger.info("🔄 Démarrage traitement des alertes")
        
        while self.running:
            try:
                # Traitement des alertes avec timeout
                alert = self.alert_queue.get(timeout=1)
                
                # Ajout à la buffer
                self.alerts_buffer.append(alert)
                
                # Mise à jour des métriques
                self.current_metrics['total_alerts'] += 1
                
                # Statistiques par type d'attaque
                attack_type = alert.get('attack_type', 'other')
                if attack_type not in self.current_metrics['top_attack_types']:
                    self.current_metrics['top_attack_types'][attack_type] = 0
                self.current_metrics['top_attack_types'][attack_type] += 1
                
                # Statistiques par IP source
                src_ip = alert.get('src_ip', '')
                if src_ip:
                    if src_ip not in self.current_metrics['top_source_ips']:
                        self.current_metrics['top_source_ips'][src_ip] = 0
                    self.current_metrics['top_source_ips'][src_ip] += 1
                
                # Statistiques par IP cible
                dest_ip = alert.get('dest_ip', '')
                if dest_ip:
                    if dest_ip not in self.current_metrics['top_target_ips']:
                        self.current_metrics['top_target_ips'][dest_ip] = 0
                    self.current_metrics['top_target_ips'][dest_ip] += 1
                
                # Distribution par sévérité
                severity = alert.get('severity', 3)
                if severity in self.current_metrics['severity_distribution']:
                    self.current_metrics['severity_distribution'][severity] += 1
                
                # Marquer la tâche comme terminée
                self.alert_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"❌ Erreur traitement alerte: {e}")

    def _collect_system_stats(self):
        """Collecte des statistiques système"""
        logger.info("📈 Démarrage collecte stats système")
        
        while self.running:
            try:
                import psutil
                
                # Stats système
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                self.current_metrics['system_health'].update({
                    'cpu_usage': cpu_percent,
                    'memory_usage': memory.percent,
                    'disk_usage': disk.percent
                })
                
                # Status des services
                self._check_service_status()
                
                time.sleep(10)  # Collecte toutes les 10 secondes
                
            except ImportError:
                logger.warning("⚠️ psutil non installé, stats système indisponibles")
                time.sleep(30)
            except Exception as e:
                logger.error(f"❌ Erreur collecte stats: {e}")
                time.sleep(10)

    def _check_service_status(self):
        """Vérification du statut des services"""
        import subprocess
        
        services = ['suricata', 'snort']
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True, text=True, timeout=5
                )
                status = 'active' if result.returncode == 0 else 'inactive'
                self.current_metrics['system_health'][f'{service}_status'] = status
            except Exception:
                self.current_metrics['system_health'][f'{service}_status'] = 'unknown'
        
        # Status Elasticsearch
        try:
            response = requests.get(
                f"{self.sources['elasticsearch']['url']}/_cluster/health",
                timeout=5
            )
            status = 'active' if response.status_code == 200 else 'inactive'
            self.current_metrics['system_health']['elasticsearch_status'] = status
        except Exception:
            self.current_metrics['system_health']['elasticsearch_status'] = 'inactive'

    def _calculate_metrics(self):
        """Calcul des métriques dérivées"""
        logger.info("🧮 Démarrage calcul métriques")
        
        while self.running:
            try:
                # Calcul alertes par minute
                now = datetime.now()
                one_minute_ago = now - timedelta(minutes=1)
                
                recent_alerts = [
                    alert for alert in self.alerts_buffer
                    if datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')) >= one_minute_ago
                ]
                
                self.current_metrics['alerts_per_minute'] = len(recent_alerts)
                
                # Ajout aux stats buffer
                stats_point = {
                    'timestamp': now.isoformat(),
                    'total_alerts': self.current_metrics['total_alerts'],
                    'alerts_per_minute': self.current_metrics['alerts_per_minute'],
                    'cpu_usage': self.current_metrics['system_health']['cpu_usage'],
                    'memory_usage': self.current_metrics['system_health']['memory_usage']
                }
                
                self.stats_buffer.append(stats_point)
                
                # Nettoyage des anciens compteurs (garder top 10)
                self.current_metrics['top_attack_types'] = dict(
                    sorted(self.current_metrics['top_attack_types'].items(),
                          key=lambda x: x[1], reverse=True)[:10]
                )
                
                self.current_metrics['top_source_ips'] = dict(
                    sorted(self.current_metrics['top_source_ips'].items(),
                          key=lambda x: x[1], reverse=True)[:10]
                )
                
                self.current_metrics['top_target_ips'] = dict(
                    sorted(self.current_metrics['top_target_ips'].items(),
                          key=lambda x: x[1], reverse=True)[:10]
                )
                
                time.sleep(5)  # Calcul toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur calcul métriques: {e}")
                time.sleep(5)

    def get_current_metrics(self) -> Dict[str, Any]:
        """Récupération des métriques actuelles"""
        return self.current_metrics.copy()
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Récupération des alertes récentes"""
        return list(self.alerts_buffer)[-limit:]
    
    def get_stats_history(self) -> List[Dict[str, Any]]:
        """Récupération de l'historique des stats"""
        return list(self.stats_buffer)

# Application Flask
def create_flask_app(monitor: IDSMonitor) -> Flask:
    """Création de l'application Flask avec SocketIO"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ids_dashboard_secret_key'
    socketio = SocketIO(app, cors_allowed_origins="*")

    @app.route('/')
    def dashboard():
        """Page principale du dashboard"""
        return render_template_string(DASHBOARD_HTML)

    @app.route('/api/metrics')
    def api_metrics():
        """API REST pour les métriques"""
        return jsonify(monitor.get_current_metrics())

    @app.route('/api/alerts')
    def api_alerts():
        """API REST pour les alertes récentes"""
        limit = request.args.get('limit', 50, type=int)
        return jsonify(monitor.get_recent_alerts(limit))

    @app.route('/api/stats')
    def api_stats():
        """API REST pour l'historique des stats"""
        return jsonify(monitor.get_stats_history())

    @app.route('/api/status')
    def api_status():
        """API REST pour le statut général"""
        return jsonify({
            'status': 'running' if monitor.running else 'stopped',
            'uptime': str(datetime.now() - app.start_time) if hasattr(app, 'start_time') else '0:00:00',
            'alerts_count': len(monitor.alerts_buffer),
            'services': monitor.current_metrics['system_health']
        })

    @socketio.on('connect')
    def handle_connect():
        """Gestion connexion WebSocket"""
        logger.info("📱 Client connecté au dashboard")
        emit('status', {'message': 'Connecté au monitoring IDS/IPS'})

    @socketio.on('get_live_data')
    def handle_get_live_data():
        """Envoi des données en temps réel"""
        emit('metrics_update', monitor.get_current_metrics())
        emit('alerts_update', monitor.get_recent_alerts(20))

    # Thread pour envoyer les mises à jour en temps réel
    def send_live_updates():
        """Envoi périodique des mises à jour"""
        while monitor.running:
            try:
                socketio.emit('metrics_update', monitor.get_current_metrics())
                socketio.emit('alerts_update', monitor.get_recent_alerts(10))
                time.sleep(2)  # Mise à jour toutes les 2 secondes
            except Exception as e:
                logger.error(f"❌ Erreur envoi mises à jour: {e}")
                time.sleep(5)

    # Démarrage du thread de mises à jour
    update_thread = threading.Thread(target=send_live_updates)
    update_thread.daemon = True
    update_thread.start()

    app.socketio = socketio
    return app

# Template HTML du dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Dashboard IDS/IPS - Monitoring Temps Réel</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            overflow-x: hidden;
        }
        
        .dashboard-header {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 15px 30px;
            border-bottom: 1px solid rgba(255,255,255,0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .dashboard-title {
            color: white;
            font-size: 28px;
            font-weight: bold;
        }
        
        .status-indicator {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .status-item {
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-size: 14px;
        }
        
        .status-active { background: rgba(46,204,113,0.8); }
        .status-inactive { background: rgba(231,76,60,0.8); }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            grid-template-rows: auto auto auto;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 80px);
        }
        
        .widget {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            display: flex;
            flex-direction: column;
        }
        
        .widget h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 18px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
        }
        
        .metric-card {
            text-align: center;
            padding: 15px;
        }
        
        .metric-value {
            font-size: 48px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .metric-label {
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .alerts-container {
            grid-column: span 2;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .alert-item {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 5px;
            font-size: 13px;
        }
        
        .alert-high { border-left-color: #e74c3c; }
        .alert-medium { border-left-color: #f39c12; }
        .alert-low { border-left-color: #2ecc71; }
        
        .alert-time {
            color: #7f8c8d;
            font-size: 11px;
            float: right;
        }
        
        .chart-container {
            position: relative;
            height: 200px;
            margin-top: 10px;
        }
        
        .top-list {
            max-height: 250px;
            overflow-y: auto;
        }
        
        .top-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 12px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 13px;
        }
        
        .top-item:hover {
            background: #f8f9fa;
        }
        
        .badge {
            background: #3498db;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
        }
        
        .system-stats {
            grid-column: span 4;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 15px;
            margin-top: 10px;
        }
        
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            margin-top: 8px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #2ecc71, #f39c12, #e74c3c);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .live-indicator {
            animation: pulse 2s infinite;
            color: #2ecc71;
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <div class="dashboard-title">
            🛡️ Dashboard IDS/IPS Monitoring
        </div>
        <div class="status-indicator">
            <div class="status-item live-indicator">● LIVE</div>
            <div id="suricata-status" class="status-item">Suricata</div>
            <div id="snort-status" class="status-item">Snort</div>
            <div id="elasticsearch-status" class="status-item">Elasticsearch</div>
        </div>
    </div>
    
    <div class="dashboard-grid">
        <!-- Métriques principales -->
        <div class="widget metric-card">
            <h3>📊 Total Alertes</h3>
            <div class="metric-value" id="total-alerts">0</div>
            <div class="metric-label">Depuis le début</div>
        </div>
        
        <div class="widget metric-card">
            <h3>⚡ Alertes/Min</h3>
            <div class="metric-value" id="alerts-per-minute">0</div>
            <div class="metric-label">Temps réel</div>
        </div>
        
        <div class="widget">
            <h3>🎯 Types d'Attaques</h3>
            <div class="top-list" id="attack-types"></div>
        </div>
        
        <div class="widget">
            <h3>🌐 IPs Sources</h3>
            <div class="top-list" id="source-ips"></div>
        </div>
        
        <!-- Alertes récentes -->
        <div class="widget alerts-container">
            <h3>🚨 Alertes Récentes</h3>
            <div id="recent-alerts"></div>
        </div>
        
        <!-- Graphiques -->
        <div class="widget">
            <h3>📈 Évolution Alertes</h3>
            <div class="chart-container">
                <canvas id="alertsChart"></canvas>
            </div>
        </div>
        
        <div class="widget">
            <h3>⚠️ Répartition Sévérité</h3>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <!-- Stats système -->
        <div class="widget system-stats">
            <h3>💻 Statistiques Système</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div>CPU</div>
                    <div id="cpu-usage">0%</div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="cpu-progress"></div>
                    </div>
                </div>
                <div class="stat-item">
                    <div>Mémoire</div>
                    <div id="memory-usage">0%</div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="memory-progress"></div>
                    </div>
                </div>
                <div class="stat-item">
                    <div>Disque</div>
                    <div id="disk-usage">0%</div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="disk-progress"></div>
                    </div>
                </div>
                <div class="stat-item">
                    <div>Uptime</div>
                    <div id="uptime">0:00:00</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Connexion WebSocket
        const socket = io();
        
        // Charts
        let alertsChart, severityChart;
        
        // Initialisation des graphiques
        function initCharts() {
            // Graphique évolution alertes
            const alertsCtx = document.getElementById('alertsChart').getContext('2d');
            alertsChart = new Chart(alertsCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Alertes/min',
                        data: [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52,152,219,0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
            
            // Graphique sévérité
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critique', 'Élevée', 'Moyenne', 'Faible'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }
        
        // Mise à jour des métriques
        function updateMetrics(metrics) {
            document.getElementById('total-alerts').textContent = metrics.total_alerts;
            document.getElementById('alerts-per-minute').textContent = metrics.alerts_per_minute;
            
            // Types d'attaques
            const attackTypesEl = document.getElementById('attack-types');
            attackTypesEl.innerHTML = '';
            Object.entries(metrics.top_attack_types).slice(0, 5).forEach(([type, count]) => {
                attackTypesEl.innerHTML += `
                    <div class="top-item">
                        <span>${type}</span>
                        <span class="badge">${count}</span>
                    </div>
                `;
            });
            
            // IPs sources
            const sourceIpsEl = document.getElementById('source-ips');
            sourceIpsEl.innerHTML = '';
            Object.entries(metrics.top_source_ips).slice(0, 5).forEach(([ip, count]) => {
                sourceIpsEl.innerHTML += `
                    <div class="top-item">
                        <span>${ip}</span>
                        <span class="badge">${count}</span>
                    </div>
                `;
            });
            
            // Stats système
            const health = metrics.system_health;
            document.getElementById('cpu-usage').textContent = Math.round(health.cpu_usage) + '%';
            document.getElementById('memory-usage').textContent = Math.round(health.memory_usage) + '%';
            document.getElementById('disk-usage').textContent = Math.round(health.disk_usage) + '%';
            
            // Barres de progression
            document.getElementById('cpu-progress').style.width = health.cpu_usage + '%';
            document.getElementById('memory-progress').style.width = health.memory_usage + '%';
            document.getElementById('disk-progress').style.width = health.disk_usage + '%';
            
            // Status des services
            updateServiceStatus('suricata', health.suricata_status);
            updateServiceStatus('snort', health.snort_status);
            updateServiceStatus('elasticsearch', health.elasticsearch_status);
            
            // Mise à jour graphique sévérité
            const severity = metrics.severity_distribution;
            severityChart.data.datasets[0].data = [severity[4] || 0, severity[3] || 0, severity[2] || 0, severity[1] || 0];
            severityChart.update();
        }
        
        // Mise à jour des alertes
        function updateAlerts(alerts) {
            const alertsEl = document.getElementById('recent-alerts');
            alertsEl.innerHTML = '';
            
            alerts.slice(0, 10).forEach(alert => {
                const severityClass = alert.severity <= 2 ? 'alert-high' : 
                                     alert.severity == 3 ? 'alert-medium' : 'alert-low';
                const time = new Date(alert.timestamp).toLocaleTimeString();
                
                alertsEl.innerHTML += `
                    <div class="alert-item ${severityClass}">
                        <strong>${alert.attack_type}</strong> - ${alert.signature}
                        <span class="alert-time">${time}</span><br>
                        <small>${alert.src_ip}:${alert.src_port} → ${alert.dest_ip}:${alert.dest_port}</small>
                    </div>
                `;
            });
        }
        
        // Mise à jour du statut des services
        function updateServiceStatus(service, status) {
            const el = document.getElementById(`${service}-status`);
            el.className = `status-item ${status === 'active' ? 'status-active' : 'status-inactive'}`;
            el.textContent = `${service.charAt(0).toUpperCase() + service.slice(1)} (${status})`;
        }
        
        // Événements WebSocket
        socket.on('connect', () => {
            console.log('Connecté au dashboard');
            socket.emit('get_live_data');
        });
        
        socket.on('metrics_update', updateMetrics);
        socket.on('alerts_update', updateAlerts);
        
        // Initialisation
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            
            // Demander les données toutes les 5 secondes
            setInterval(() => {
                socket.emit('get_live_data');
            }, 5000);
        });
    </script>
</body>
</html>
"""

def load_config(config_file: str = None) -> Dict[str, Any]:
    """Chargement de la configuration"""
    default_config = {
        'suricata_log_path': '/var/log/suricata/eve.json',
        'snort_log_path': '/var/log/snort/alert',
        'elasticsearch_url': 'http://localhost:9200',
        'monitor_suricata': True,
        'monitor_snort': True,
        'monitor_elasticsearch': True,
        'dashboard_host': '0.0.0.0',
        'dashboard_port': 5000,
        'debug': False
    }
    
    if config_file and Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            default_config.update(user_config)
        except Exception as e:
            logger.warning(f"Erreur chargement config: {e}. Utilisation config par défaut.")
    
    return default_config

def main():
    parser = argparse.ArgumentParser(
        description="Dashboard de monitoring temps réel IDS/IPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Dashboard par défaut
  python3 ids-dashboard.py
  
  # Configuration personnalisée
  python3 ids-dashboard.py --config dashboard_config.json --port 8080
  
  # Mode debug
  python3 ids-dashboard.py --debug --host localhost
        """
    )
    
    parser.add_argument('--config', help='Fichier de configuration JSON')
    parser.add_argument('--host', default='0.0.0.0', help='Adresse IP du serveur')
    parser.add_argument('--port', type=int, default=5000, help='Port du serveur')
    parser.add_argument('--debug', action='store_true', help='Mode debug')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Chargement de la configuration
    config = load_config(args.config)
    config['dashboard_host'] = args.host
    config['dashboard_port'] = args.port
    config['debug'] = args.debug
    
    try:
        logger.info("🚀 Démarrage Dashboard IDS/IPS")
        
        # Initialisation du moniteur
        monitor = IDSMonitor(config)
        
        # Démarrage du monitoring
        monitor.start_monitoring()
        
        # Création de l'application Flask
        app = create_flask_app(monitor)
        app.start_time = datetime.now()
        
        # Démarrage du serveur
        logger.info(f"🌐 Dashboard accessible sur http://{args.host}:{args.port}")
        app.socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=args.debug,
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        logger.info("⚠️ Dashboard interrompu par l'utilisateur")
    except Exception as e:
        logger.error(f"❌ Erreur dashboard: {e}")
        return 1
    finally:
        if 'monitor' in locals():
            monitor.stop_monitoring()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())