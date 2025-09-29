#!/usr/bin/env python3
"""
DevSecOps Metrics Collector
Système de collecte et d'analyse des métriques de sécurité
"""

import os
import json
import time
import asyncio
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import logging
import threading
from collections import defaultdict, deque
import psutil
import hashlib

# Imports pour monitoring externe
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary, start_http_server, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import influxdb_client
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False

class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning" 
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class MetricPoint:
    """Point de métrique individuel"""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.GAUGE

@dataclass
class Alert:
    """Alerte système"""
    alert_id: str
    name: str
    severity: AlertSeverity
    message: str
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None

@dataclass
class ScanMetrics:
    """Métriques d'un scan de sécurité"""
    scan_id: str
    project_name: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    issues_found: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    risk_score: float = 0.0
    files_scanned: int = 0
    lines_of_code: int = 0
    success: bool = False
    error_message: Optional[str] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0

@dataclass
class SystemMetrics:
    """Métriques système"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: Dict[str, float] = field(default_factory=dict)
    active_scans: int = 0
    queue_size: int = 0

class MetricsDatabase:
    """Base de données SQLite pour stocker les métriques"""
    
    def __init__(self, db_path: str = "./monitoring/metrics.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialise la base de données"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des métriques de scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_metrics (
                scan_id TEXT PRIMARY KEY,
                project_name TEXT,
                scan_type TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                duration_seconds REAL,
                issues_found INTEGER,
                critical_issues INTEGER,
                high_issues INTEGER,
                medium_issues INTEGER,
                low_issues INTEGER,
                risk_score REAL,
                files_scanned INTEGER,
                lines_of_code INTEGER,
                success BOOLEAN,
                error_message TEXT,
                memory_usage_mb REAL,
                cpu_usage_percent REAL
            )
        ''')
        
        # Table des métriques système
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                active_scans INTEGER,
                queue_size INTEGER
            )
        ''')
        
        # Table des alertes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                name TEXT,
                severity TEXT,
                message TEXT,
                timestamp TIMESTAMP,
                labels TEXT,
                resolved BOOLEAN,
                resolved_at TIMESTAMP
            )
        ''')
        
        # Index pour les requêtes fréquentes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_metrics(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_timestamp ON system_metrics(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        
        conn.commit()
        conn.close()
    
    def store_scan_metrics(self, metrics: ScanMetrics):
        """Stocke les métriques d'un scan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scan_metrics 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.scan_id, metrics.project_name, metrics.scan_type,
            metrics.start_time, metrics.end_time, metrics.duration_seconds,
            metrics.issues_found, metrics.critical_issues, metrics.high_issues,
            metrics.medium_issues, metrics.low_issues, metrics.risk_score,
            metrics.files_scanned, metrics.lines_of_code, metrics.success,
            metrics.error_message, metrics.memory_usage_mb, metrics.cpu_usage_percent
        ))
        
        conn.commit()
        conn.close()
    
    def store_system_metrics(self, metrics: SystemMetrics):
        """Stocke les métriques système"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO system_metrics 
            (timestamp, cpu_usage, memory_usage, disk_usage, active_scans, queue_size)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            metrics.timestamp, metrics.cpu_usage, metrics.memory_usage,
            metrics.disk_usage, metrics.active_scans, metrics.queue_size
        ))
        
        conn.commit()
        conn.close()
    
    def store_alert(self, alert: Alert):
        """Stocke une alerte"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id, alert.name, alert.severity.value,
            alert.message, alert.timestamp, json.dumps(alert.labels),
            alert.resolved, alert.resolved_at
        ))
        
        conn.commit()
        conn.close()
    
    def get_scan_metrics(self, hours: int = 24) -> List[ScanMetrics]:
        """Récupère les métriques de scan des dernières heures"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM scan_metrics 
            WHERE start_time > ? 
            ORDER BY start_time DESC
        ''', (since,))
        
        results = []
        for row in cursor.fetchall():
            results.append(ScanMetrics(
                scan_id=row[0], project_name=row[1], scan_type=row[2],
                start_time=datetime.fromisoformat(row[3]),
                end_time=datetime.fromisoformat(row[4]) if row[4] else None,
                duration_seconds=row[5], issues_found=row[6],
                critical_issues=row[7], high_issues=row[8], medium_issues=row[9],
                low_issues=row[10], risk_score=row[11], files_scanned=row[12],
                lines_of_code=row[13], success=bool(row[14]),
                error_message=row[15], memory_usage_mb=row[16],
                cpu_usage_percent=row[17]
            ))
        
        conn.close()
        return results
    
    def get_system_metrics(self, hours: int = 24) -> List[SystemMetrics]:
        """Récupère les métriques système des dernières heures"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM system_metrics 
            WHERE timestamp > ? 
            ORDER BY timestamp DESC
        ''', (since,))
        
        results = []
        for row in cursor.fetchall():
            results.append(SystemMetrics(
                timestamp=datetime.fromisoformat(row[1]),
                cpu_usage=row[2], memory_usage=row[3], disk_usage=row[4],
                active_scans=row[5], queue_size=row[6]
            ))
        
        conn.close()
        return results
    
    def get_alerts(self, resolved: bool = False, hours: int = 168) -> List[Alert]:
        """Récupère les alertes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM alerts 
            WHERE timestamp > ? AND resolved = ?
            ORDER BY timestamp DESC
        ''', (since, resolved))
        
        results = []
        for row in cursor.fetchall():
            results.append(Alert(
                alert_id=row[0], name=row[1],
                severity=AlertSeverity(row[2]), message=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                labels=json.loads(row[5]) if row[5] else {},
                resolved=bool(row[6]),
                resolved_at=datetime.fromisoformat(row[7]) if row[7] else None
            ))
        
        conn.close()
        return results

class PrometheusExporter:
    """Exporteur de métriques vers Prometheus"""
    
    def __init__(self, port: int = 9090):
        self.port = port
        self.registry = CollectorRegistry()
        
        if not PROMETHEUS_AVAILABLE:
            raise ImportError("prometheus_client not available")
        
        # Métriques Prometheus
        self.scan_duration = Histogram(
            'devsecops_scan_duration_seconds',
            'Duration of security scans',
            ['project', 'scan_type'],
            registry=self.registry
        )
        
        self.issues_found = Counter(
            'devsecops_issues_total',
            'Total security issues found',
            ['project', 'scan_type', 'severity'],
            registry=self.registry
        )
        
        self.risk_score = Gauge(
            'devsecops_risk_score',
            'Security risk score',
            ['project'],
            registry=self.registry
        )
        
        self.active_scans = Gauge(
            'devsecops_active_scans',
            'Number of active scans',
            registry=self.registry
        )
        
        self.system_cpu = Gauge(
            'devsecops_system_cpu_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory = Gauge(
            'devsecops_system_memory_percent',
            'Memory usage percentage',
            registry=self.registry
        )
    
    def start_server(self):
        """Démarre le serveur Prometheus"""
        start_http_server(self.port, registry=self.registry)
        logging.info(f"Prometheus metrics server started on port {self.port}")
    
    def update_scan_metrics(self, metrics: ScanMetrics):
        """Met à jour les métriques de scan Prometheus"""
        labels = [metrics.project_name, metrics.scan_type]
        
        self.scan_duration.labels(*labels).observe(metrics.duration_seconds)
        self.risk_score.labels(metrics.project_name).set(metrics.risk_score)
        
        # Issues par sévérité
        severity_counts = [
            ('critical', metrics.critical_issues),
            ('high', metrics.high_issues),
            ('medium', metrics.medium_issues),
            ('low', metrics.low_issues)
        ]
        
        for severity, count in severity_counts:
            if count > 0:
                self.issues_found.labels(metrics.project_name, metrics.scan_type, severity)._value._value += count
    
    def update_system_metrics(self, metrics: SystemMetrics):
        """Met à jour les métriques système Prometheus"""
        self.active_scans.set(metrics.active_scans)
        self.system_cpu.set(metrics.cpu_usage)
        self.system_memory.set(metrics.memory_usage)

class InfluxDBExporter:
    """Exporteur de métriques vers InfluxDB"""
    
    def __init__(self, url: str, token: str, org: str, bucket: str):
        if not INFLUXDB_AVAILABLE:
            raise ImportError("influxdb-client not available")
        
        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.bucket = bucket
        self.org = org
    
    def write_scan_metrics(self, metrics: ScanMetrics):
        """Écrit les métriques de scan dans InfluxDB"""
        point = (
            Point("security_scan")
            .tag("project", metrics.project_name)
            .tag("scan_type", metrics.scan_type)
            .tag("success", str(metrics.success))
            .field("duration_seconds", metrics.duration_seconds)
            .field("issues_found", metrics.issues_found)
            .field("critical_issues", metrics.critical_issues)
            .field("high_issues", metrics.high_issues)
            .field("medium_issues", metrics.medium_issues)
            .field("low_issues", metrics.low_issues)
            .field("risk_score", metrics.risk_score)
            .field("files_scanned", metrics.files_scanned)
            .field("lines_of_code", metrics.lines_of_code)
            .field("memory_usage_mb", metrics.memory_usage_mb)
            .field("cpu_usage_percent", metrics.cpu_usage_percent)
            .time(metrics.start_time, WritePrecision.S)
        )
        
        self.write_api.write(bucket=self.bucket, org=self.org, record=point)
    
    def write_system_metrics(self, metrics: SystemMetrics):
        """Écrit les métriques système dans InfluxDB"""
        point = (
            Point("system_metrics")
            .field("cpu_usage", metrics.cpu_usage)
            .field("memory_usage", metrics.memory_usage)
            .field("disk_usage", metrics.disk_usage)
            .field("active_scans", metrics.active_scans)
            .field("queue_size", metrics.queue_size)
            .time(metrics.timestamp, WritePrecision.S)
        )
        
        self.write_api.write(bucket=self.bucket, org=self.org, record=point)

class AlertManager:
    """Gestionnaire d'alertes"""
    
    def __init__(self, db: MetricsDatabase):
        self.db = db
        self.rules = []
        self.active_alerts = {}
        self.notification_handlers = []
    
    def add_rule(self, name: str, condition_func, severity: AlertSeverity, message: str):
        """Ajoute une règle d'alerte"""
        self.rules.append({
            'name': name,
            'condition': condition_func,
            'severity': severity,
            'message': message
        })
    
    def add_notification_handler(self, handler):
        """Ajoute un gestionnaire de notification"""
        self.notification_handlers.append(handler)
    
    def evaluate_rules(self, scan_metrics: List[ScanMetrics], system_metrics: List[SystemMetrics]):
        """Évalue les règles d'alerte"""
        for rule in self.rules:
            try:
                if rule['condition'](scan_metrics, system_metrics):
                    self._trigger_alert(rule)
                else:
                    self._resolve_alert(rule['name'])
            except Exception as e:
                logging.error(f"Error evaluating alert rule {rule['name']}: {e}")
    
    def _trigger_alert(self, rule):
        """Déclenche une alerte"""
        alert_id = hashlib.md5(rule['name'].encode()).hexdigest()
        
        if alert_id not in self.active_alerts:
            alert = Alert(
                alert_id=alert_id,
                name=rule['name'],
                severity=rule['severity'],
                message=rule['message'],
                timestamp=datetime.now()
            )
            
            self.active_alerts[alert_id] = alert
            self.db.store_alert(alert)
            
            # Envoyer notifications
            for handler in self.notification_handlers:
                try:
                    handler.send_alert(alert)
                except Exception as e:
                    logging.error(f"Error sending alert notification: {e}")
            
            logging.warning(f"Alert triggered: {rule['name']} - {rule['message']}")
    
    def _resolve_alert(self, alert_name):
        """Résout une alerte"""
        alert_id = hashlib.md5(alert_name.encode()).hexdigest()
        
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.resolved = True
            alert.resolved_at = datetime.now()
            
            self.db.store_alert(alert)
            del self.active_alerts[alert_id]
            
            logging.info(f"Alert resolved: {alert_name}")

class MetricsCollector:
    """Collecteur principal de métriques"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db = MetricsDatabase(config.get('database_path', './monitoring/metrics.db'))
        self.alert_manager = AlertManager(self.db)
        
        # Exporteurs externes
        self.prometheus_exporter = None
        self.influxdb_exporter = None
        
        self._setup_exporters()
        self._setup_alert_rules()
        
        # État du collecteur
        self.running = False
        self.system_monitor_thread = None
        self.active_scans = 0
        self.scan_queue_size = 0
        
        # Buffer de métriques en mémoire
        self.recent_scans = deque(maxlen=1000)
        self.recent_system_metrics = deque(maxlen=1440)  # 24h à 1 point/minute
    
    def _setup_exporters(self):
        """Configure les exporteurs de métriques"""
        # Prometheus
        if (self.config.get('prometheus', {}).get('enabled', False) and PROMETHEUS_AVAILABLE):
            try:
                port = self.config['prometheus'].get('port', 9090)
                self.prometheus_exporter = PrometheusExporter(port)
                self.prometheus_exporter.start_server()
            except Exception as e:
                logging.error(f"Failed to setup Prometheus exporter: {e}")
        
        # InfluxDB
        if (self.config.get('influxdb', {}).get('enabled', False) and INFLUXDB_AVAILABLE):
            try:
                influx_config = self.config['influxdb']
                self.influxdb_exporter = InfluxDBExporter(
                    url=influx_config['url'],
                    token=influx_config['token'],
                    org=influx_config['org'],
                    bucket=influx_config['bucket']
                )
            except Exception as e:
                logging.error(f"Failed to setup InfluxDB exporter: {e}")
    
    def _setup_alert_rules(self):
        """Configure les règles d'alerte"""
        # Alerte sur CPU élevé
        self.alert_manager.add_rule(
            name="high_cpu_usage",
            condition_func=lambda scan_metrics, system_metrics: (
                len(system_metrics) > 0 and 
                system_metrics[-1].cpu_usage > 80.0
            ),
            severity=AlertSeverity.WARNING,
            message="CPU usage is above 80%"
        )
        
        # Alerte sur mémoire élevée
        self.alert_manager.add_rule(
            name="high_memory_usage",
            condition_func=lambda scan_metrics, system_metrics: (
                len(system_metrics) > 0 and 
                system_metrics[-1].memory_usage > 85.0
            ),
            severity=AlertSeverity.WARNING,
            message="Memory usage is above 85%"
        )
        
        # Alerte sur vulnérabilités critiques
        self.alert_manager.add_rule(
            name="critical_vulnerabilities_found",
            condition_func=lambda scan_metrics, system_metrics: (
                len(scan_metrics) > 0 and 
                any(scan.critical_issues > 0 for scan in scan_metrics[-5:])
            ),
            severity=AlertSeverity.CRITICAL,
            message="Critical vulnerabilities detected in recent scans"
        )
        
        # Alerte sur échecs de scan répétés
        self.alert_manager.add_rule(
            name="multiple_scan_failures",
            condition_func=lambda scan_metrics, system_metrics: (
                len(scan_metrics) >= 3 and 
                all(not scan.success for scan in scan_metrics[-3:])
            ),
            severity=AlertSeverity.ERROR,
            message="Multiple consecutive scan failures detected"
        )
    
    def start(self):
        """Démarre le collecteur de métriques"""
        self.running = True
        
        # Démarrer le monitoring système en arrière-plan
        self.system_monitor_thread = threading.Thread(target=self._system_monitor_loop)
        self.system_monitor_thread.daemon = True
        self.system_monitor_thread.start()
        
        logging.info("Metrics collector started")
    
    def stop(self):
        """Arrête le collecteur de métriques"""
        self.running = False
        
        if self.system_monitor_thread:
            self.system_monitor_thread.join(timeout=5)
        
        logging.info("Metrics collector stopped")
    
    def _system_monitor_loop(self):
        """Boucle de monitoring système"""
        while self.running:
            try:
                # Collecter les métriques système
                system_metrics = SystemMetrics(
                    timestamp=datetime.now(),
                    cpu_usage=psutil.cpu_percent(interval=1),
                    memory_usage=psutil.virtual_memory().percent,
                    disk_usage=psutil.disk_usage('/').percent,
                    active_scans=self.active_scans,
                    queue_size=self.scan_queue_size
                )
                
                # Stocker dans la base de données
                self.db.store_system_metrics(system_metrics)
                
                # Ajouter au buffer en mémoire
                self.recent_system_metrics.append(system_metrics)
                
                # Exporter vers les systèmes externes
                if self.prometheus_exporter:
                    self.prometheus_exporter.update_system_metrics(system_metrics)
                
                if self.influxdb_exporter:
                    self.influxdb_exporter.write_system_metrics(system_metrics)
                
                # Évaluer les règles d'alerte
                recent_scans = list(self.recent_scans)[-10:]  # 10 derniers scans
                recent_system = list(self.recent_system_metrics)[-5:]  # 5 dernières mesures système
                self.alert_manager.evaluate_rules(recent_scans, recent_system)
                
            except Exception as e:
                logging.error(f"Error in system monitor loop: {e}")
            
            # Attendre 60 secondes avant la prochaine collecte
            time.sleep(60)
    
    def record_scan_start(self, scan_id: str, project_name: str, scan_type: str):
        """Enregistre le début d'un scan"""
        self.active_scans += 1
        
        process = psutil.Process()
        memory_info = process.memory_info()
        
        scan_metrics = ScanMetrics(
            scan_id=scan_id,
            project_name=project_name,
            scan_type=scan_type,
            start_time=datetime.now(),
            memory_usage_mb=memory_info.rss / 1024 / 1024,
            cpu_usage_percent=process.cpu_percent()
        )
        
        self.recent_scans.append(scan_metrics)
        return scan_metrics
    
    def record_scan_completion(self, scan_id: str, success: bool, issues_by_severity: Dict[str, int], 
                             risk_score: float, files_scanned: int = 0, lines_of_code: int = 0,
                             error_message: str = None):
        """Enregistre la fin d'un scan"""
        self.active_scans = max(0, self.active_scans - 1)
        
        # Trouver le scan dans les métriques récentes
        scan_metrics = None
        for metrics in reversed(self.recent_scans):
            if metrics.scan_id == scan_id:
                scan_metrics = metrics
                break
        
        if scan_metrics:
            # Mettre à jour les métriques
            scan_metrics.end_time = datetime.now()
            scan_metrics.duration_seconds = (scan_metrics.end_time - scan_metrics.start_time).total_seconds()
            scan_metrics.success = success
            scan_metrics.error_message = error_message
            scan_metrics.files_scanned = files_scanned
            scan_metrics.lines_of_code = lines_of_code
            scan_metrics.risk_score = risk_score
            
            # Issues par sévérité
            scan_metrics.critical_issues = issues_by_severity.get('critical', 0)
            scan_metrics.high_issues = issues_by_severity.get('high', 0)
            scan_metrics.medium_issues = issues_by_severity.get('medium', 0)
            scan_metrics.low_issues = issues_by_severity.get('low', 0)
            scan_metrics.issues_found = sum(issues_by_severity.values())
            
            # Mise à jour des métriques système
            try:
                process = psutil.Process()
                memory_info = process.memory_info()
                scan_metrics.memory_usage_mb = memory_info.rss / 1024 / 1024
                scan_metrics.cpu_usage_percent = process.cpu_percent()
            except:
                pass
            
            # Stocker dans la base de données
            self.db.store_scan_metrics(scan_metrics)
            
            # Exporter vers les systèmes externes
            if self.prometheus_exporter:
                self.prometheus_exporter.update_scan_metrics(scan_metrics)
            
            if self.influxdb_exporter:
                self.influxdb_exporter.write_scan_metrics(scan_metrics)
            
            logging.info(f"Scan {scan_id} completed: {success}, {scan_metrics.issues_found} issues, risk score {risk_score}")
    
    def get_dashboard_data(self, hours: int = 24) -> Dict[str, Any]:
        """Récupère les données pour le dashboard"""
        scan_metrics = self.db.get_scan_metrics(hours)
        system_metrics = self.db.get_system_metrics(hours)
        alerts = self.db.get_alerts(resolved=False, hours=168)  # 7 jours
        
        # Statistiques des scans
        scan_stats = {
            'total_scans': len(scan_metrics),
            'successful_scans': sum(1 for s in scan_metrics if s.success),
            'failed_scans': sum(1 for s in scan_metrics if not s.success),
            'total_issues': sum(s.issues_found for s in scan_metrics),
            'critical_issues': sum(s.critical_issues for s in scan_metrics),
            'high_issues': sum(s.high_issues for s in scan_metrics),
            'average_duration': sum(s.duration_seconds for s in scan_metrics) / len(scan_metrics) if scan_metrics else 0,
            'average_risk_score': sum(s.risk_score for s in scan_metrics) / len(scan_metrics) if scan_metrics else 0
        }
        
        # Statistiques par projet
        project_stats = defaultdict(lambda: {
            'scans': 0, 'issues': 0, 'risk_score': 0, 'last_scan': None
        })
        
        for scan in scan_metrics:
            stats = project_stats[scan.project_name]
            stats['scans'] += 1
            stats['issues'] += scan.issues_found
            stats['risk_score'] = max(stats['risk_score'], scan.risk_score)
            if not stats['last_scan'] or scan.start_time > stats['last_scan']:
                stats['last_scan'] = scan.start_time
        
        # Métriques système actuelles
        current_system = system_metrics[0] if system_metrics else SystemMetrics(
            timestamp=datetime.now(), cpu_usage=0, memory_usage=0, disk_usage=0
        )
        
        # Tendances (comparaison avec la période précédente)
        previous_scan_metrics = self.db.get_scan_metrics(hours * 2)
        previous_period_metrics = [s for s in previous_scan_metrics 
                                 if s.start_time < datetime.now() - timedelta(hours=hours)]
        
        trends = {
            'scans': len(scan_metrics) - len(previous_period_metrics),
            'issues': sum(s.issues_found for s in scan_metrics) - sum(s.issues_found for s in previous_period_metrics),
            'risk_score_change': (scan_stats['average_risk_score'] - 
                                (sum(s.risk_score for s in previous_period_metrics) / len(previous_period_metrics) 
                                 if previous_period_metrics else 0))
        }
        
        return {
            'scan_stats': scan_stats,
            'project_stats': dict(project_stats),
            'system_metrics': {
                'cpu_usage': current_system.cpu_usage,
                'memory_usage': current_system.memory_usage,
                'disk_usage': current_system.disk_usage,
                'active_scans': current_system.active_scans,
                'queue_size': current_system.queue_size
            },
            'alerts': [asdict(alert) for alert in alerts],
            'trends': trends,
            'recent_scans': [asdict(scan) for scan in scan_metrics[:10]],
            'timestamp': datetime.now()
        }

# Exemple d'utilisation
def main():
    """Test du collecteur de métriques"""
    config = {
        'database_path': './monitoring/metrics.db',
        'prometheus': {
            'enabled': PROMETHEUS_AVAILABLE,
            'port': 9090
        },
        'influxdb': {
            'enabled': False  # Configure selon votre environnement
        }
    }
    
    collector = MetricsCollector(config)
    collector.start()
    
    # Simuler quelques scans
    for i in range(3):
        scan_id = f"test_scan_{i}"
        collector.record_scan_start(scan_id, f"project_{i}", "sast")
        
        time.sleep(2)  # Simuler la durée du scan
        
        issues = {
            'critical': 1 if i == 0 else 0,
            'high': i * 2,
            'medium': i * 3,
            'low': i * 5
        }
        
        collector.record_scan_completion(
            scan_id=scan_id,
            success=i != 1,  # Le deuxième scan échoue
            issues_by_severity=issues,
            risk_score=30.0 + i * 20,
            files_scanned=100 + i * 50,
            lines_of_code=5000 + i * 2000,
            error_message="Simulated error" if i == 1 else None
        )
    
    # Afficher les données du dashboard
    time.sleep(3)
    dashboard_data = collector.get_dashboard_data()
    print("Dashboard Data:")
    print(json.dumps(dashboard_data, indent=2, default=str))
    
    collector.stop()

if __name__ == "__main__":
    main()