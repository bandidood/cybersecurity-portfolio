#!/usr/bin/env python3
"""
Tests de Performance IDS/IPS
Projet 04 - Cybersecurity Portfolio

Script pour évaluer les performances et limites du système IDS/IPS :
- Tests de throughput (paquets/seconde)
- Tests de latence de détection
- Tests de charge système (CPU/RAM)
- Tests de scalabilité
- Benchmarks de performance

Usage: python3 performance-test.py --test-type throughput --duration 300
"""

import os
import sys
import time
import json
import psutil
import argparse
import logging
import threading
import subprocess
import multiprocessing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import statistics
import concurrent.futures
import queue
import socket
import requests
from collections import deque, defaultdict

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Métriques de performance"""
    timestamp: str
    test_type: str
    duration: float
    
    # Throughput
    packets_sent: int
    packets_processed: int
    throughput_pps: float  # packets per second
    throughput_mbps: float  # megabits per second
    
    # Latence
    avg_detection_latency: float
    min_detection_latency: float
    max_detection_latency: float
    p95_detection_latency: float
    p99_detection_latency: float
    
    # Ressources système
    cpu_usage_avg: float
    cpu_usage_peak: float
    memory_usage_avg: float
    memory_usage_peak: float
    disk_io_avg: float
    network_io_avg: float
    
    # Détections
    total_detections: int
    detection_rate: float
    false_positives: int
    false_negatives: int
    
    # Qualité
    packet_loss: float
    error_rate: float
    system_stability: str

@dataclass
class PerformanceReport:
    """Rapport de performance complet"""
    test_suite: str
    start_time: str
    end_time: str
    total_duration: float
    
    system_info: Dict[str, Any]
    test_configuration: Dict[str, Any]
    
    metrics: List[PerformanceMetrics]
    summary: Dict[str, Any]
    recommendations: List[str]
    
    performance_grade: str
    bottlenecks: List[str]

class SystemMonitor:
    """Moniteur des ressources système"""
    
    def __init__(self):
        self.running = False
        self.metrics_queue = queue.Queue()
        self.monitoring_thread = None
        
    def start_monitoring(self, interval: float = 1.0):
        """Démarrage du monitoring système"""
        if self.running:
            return
            
        self.running = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop, 
            args=(interval,)
        )
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        logger.info("📊 Monitoring système démarré")
    
    def stop_monitoring(self):
        """Arrêt du monitoring système"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("⏹️ Monitoring système arrêté")
    
    def _monitoring_loop(self, interval: float):
        """Boucle de monitoring"""
        while self.running:
            try:
                # Collecte des métriques
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                net_io = psutil.net_io_counters()
                
                # Processus spécifiques IDS/IPS
                suricata_stats = self._get_process_stats('suricata')
                snort_stats = self._get_process_stats('snort')
                
                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_mb': memory.used / 1024 / 1024,
                    'disk_read_mb': disk_io.read_bytes / 1024 / 1024 if disk_io else 0,
                    'disk_write_mb': disk_io.write_bytes / 1024 / 1024 if disk_io else 0,
                    'network_sent_mb': net_io.bytes_sent / 1024 / 1024 if net_io else 0,
                    'network_recv_mb': net_io.bytes_recv / 1024 / 1024 if net_io else 0,
                    'suricata_cpu': suricata_stats['cpu_percent'],
                    'suricata_memory_mb': suricata_stats['memory_mb'],
                    'snort_cpu': snort_stats['cpu_percent'],
                    'snort_memory_mb': snort_stats['memory_mb']
                }
                
                self.metrics_queue.put(metrics)
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"❌ Erreur monitoring: {e}")
                time.sleep(interval)
    
    def _get_process_stats(self, process_name: str) -> Dict[str, float]:
        """Récupération stats d'un processus spécifique"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                if process_name.lower() in proc.info['name'].lower():
                    return {
                        'cpu_percent': proc.info['cpu_percent'] or 0,
                        'memory_mb': proc.info['memory_info'].rss / 1024 / 1024
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return {'cpu_percent': 0, 'memory_mb': 0}
    
    def get_current_metrics(self) -> List[Dict[str, Any]]:
        """Récupération des métriques collectées"""
        metrics = []
        while not self.metrics_queue.empty():
            try:
                metrics.append(self.metrics_queue.get_nowait())
            except queue.Empty:
                break
        return metrics

class TrafficGenerator:
    """Générateur de trafic pour tests de performance"""
    
    def __init__(self, target_network: str = "192.168.100.0/24"):
        self.target_network = target_network
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'start_time': None
        }
        
    def generate_high_volume_traffic(self, pps: int, duration: int, 
                                   traffic_types: List[str] = None) -> Dict[str, Any]:
        """
        Génération de trafic haute performance
        
        Args:
            pps: Paquets par seconde
            duration: Durée en secondes
            traffic_types: Types de trafic à générer
        """
        if traffic_types is None:
            traffic_types = ['tcp', 'udp', 'icmp', 'http']
        
        logger.info(f"🚀 Génération trafic: {pps} pps pendant {duration}s")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Calcul des paramètres
        packet_interval = 1.0 / pps if pps > 0 else 0.001
        target_ips = self._generate_target_ips()
        
        # Threads de génération
        num_threads = min(multiprocessing.cpu_count(), 8)
        pps_per_thread = pps // num_threads
        
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._traffic_worker,
                args=(pps_per_thread, duration, target_ips, traffic_types)
            )
            thread.daemon = True
            threads.append(thread)
        
        # Démarrage des threads
        for thread in threads:
            thread.start()
        
        # Attente de fin
        for thread in threads:
            thread.join()
        
        # Calcul des statistiques finales
        total_time = time.time() - self.stats['start_time']
        actual_pps = self.stats['packets_sent'] / total_time if total_time > 0 else 0
        
        return {
            'packets_sent': self.stats['packets_sent'],
            'bytes_sent': self.stats['bytes_sent'],
            'duration': total_time,
            'target_pps': pps,
            'actual_pps': actual_pps,
            'efficiency': (actual_pps / pps * 100) if pps > 0 else 0,
            'errors': self.stats['errors']
        }
    
    def _traffic_worker(self, pps: int, duration: int, target_ips: List[str], 
                       traffic_types: List[str]):
        """Worker thread pour génération de trafic"""
        end_time = time.time() + duration
        packet_interval = 1.0 / pps if pps > 0 else 0.001
        
        while self.running and time.time() < end_time:
            try:
                # Sélection aléatoire des paramètres
                import random
                target_ip = random.choice(target_ips)
                traffic_type = random.choice(traffic_types)
                
                # Génération du paquet selon le type
                if traffic_type == 'tcp':
                    self._send_tcp_packet(target_ip, random.randint(80, 8080))
                elif traffic_type == 'udp':
                    self._send_udp_packet(target_ip, random.randint(53, 5353))
                elif traffic_type == 'icmp':
                    self._send_icmp_packet(target_ip)
                elif traffic_type == 'http':
                    self._send_http_request(target_ip, random.choice([80, 443, 8080]))
                
                self.stats['packets_sent'] += 1
                
                # Rate limiting
                time.sleep(packet_interval)
                
            except Exception as e:
                self.stats['errors'] += 1
                logger.debug(f"Erreur génération paquet: {e}")
    
    def _generate_target_ips(self) -> List[str]:
        """Génération de la liste des IPs cibles"""
        import ipaddress
        
        try:
            network = ipaddress.ip_network(self.target_network, strict=False)
            # Limiter à 50 IPs pour éviter la surcharge
            return [str(ip) for ip in list(network.hosts())[:50]]
        except Exception:
            return ["192.168.100.10", "192.168.100.20", "192.168.100.30"]
    
    def _send_tcp_packet(self, target_ip: str, port: int):
        """Envoi paquet TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target_ip, port))
            sock.close()
            self.stats['bytes_sent'] += 64  # Estimation taille paquet
        except Exception:
            pass
    
    def _send_udp_packet(self, target_ip: str, port: int):
        """Envoi paquet UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            data = b"Performance test UDP packet"
            sock.sendto(data, (target_ip, port))
            sock.close()
            self.stats['bytes_sent'] += len(data) + 28  # UDP + IP headers
        except Exception:
            pass
    
    def _send_icmp_packet(self, target_ip: str):
        """Envoi paquet ICMP (ping)"""
        try:
            # Utilisation de ping système
            subprocess.run(
                ['ping', '-c', '1', '-W', '100', target_ip],
                capture_output=True, timeout=0.2
            )
            self.stats['bytes_sent'] += 84  # ICMP + IP headers
        except Exception:
            pass
    
    def _send_http_request(self, target_ip: str, port: int):
        """Envoi requête HTTP"""
        try:
            url = f"http://{target_ip}:{port}/"
            response = requests.get(url, timeout=0.1)
            self.stats['bytes_sent'] += len(response.content) if response else 0
        except Exception:
            pass
    
    def stop_generation(self):
        """Arrêt de la génération de trafic"""
        self.running = False

class DetectionLatencyMeasurer:
    """Mesureur de latence de détection"""
    
    def __init__(self, log_paths: Dict[str, str]):
        self.log_paths = log_paths
        self.detection_times = deque(maxlen=1000)
        self.running = False
        
    def start_measuring(self):
        """Démarrage de la mesure de latence"""
        self.running = True
        self.detection_times.clear()
        
        # Threads de surveillance des logs
        threads = []
        for source, log_path in self.log_paths.items():
            if Path(log_path).exists():
                thread = threading.Thread(
                    target=self._monitor_log_file,
                    args=(source, log_path)
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()
        
        logger.info(f"📏 Mesure latence démarrée ({len(threads)} sources)")
    
    def stop_measuring(self):
        """Arrêt de la mesure de latence"""
        self.running = False
    
    def _monitor_log_file(self, source: str, log_path: str):
        """Surveillance d'un fichier de log pour mesure latence"""
        try:
            with open(log_path, 'r') as f:
                f.seek(0, 2)  # Fin du fichier
                
                while self.running:
                    line = f.readline()
                    if line:
                        detection_time = self._parse_detection_time(source, line)
                        if detection_time:
                            # Calcul latence (approximatif)
                            current_time = time.time()
                            latency = current_time - detection_time
                            if 0 < latency < 60:  # Filtrer valeurs aberrantes
                                self.detection_times.append(latency)
                    else:
                        time.sleep(0.01)  # Attendre nouvelles données
                        
        except Exception as e:
            logger.error(f"❌ Erreur monitoring {source}: {e}")
    
    def _parse_detection_time(self, source: str, line: str) -> Optional[float]:
        """Parse le timestamp d'une détection"""
        try:
            if source == 'suricata' and line.strip():
                data = json.loads(line)
                if data.get('event_type') == 'alert':
                    timestamp_str = data.get('timestamp', '')
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    return dt.timestamp()
            elif source == 'snort' and '[**]' in line:
                # Approximation du timestamp pour Snort
                return time.time()
        except Exception:
            pass
        return None
    
    def get_latency_stats(self) -> Dict[str, float]:
        """Récupération des statistiques de latence"""
        if not self.detection_times:
            return {
                'avg': 0, 'min': 0, 'max': 0,
                'p95': 0, 'p99': 0, 'count': 0
            }
        
        latencies = list(self.detection_times)
        latencies.sort()
        
        return {
            'avg': statistics.mean(latencies),
            'min': min(latencies),
            'max': max(latencies),
            'p95': latencies[int(len(latencies) * 0.95)] if latencies else 0,
            'p99': latencies[int(len(latencies) * 0.99)] if latencies else 0,
            'count': len(latencies)
        }

class PerformanceTester:
    """Testeur de performance principal"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.system_monitor = SystemMonitor()
        self.traffic_generator = TrafficGenerator(config.get('target_network', '192.168.100.0/24'))
        self.latency_measurer = DetectionLatencyMeasurer({
            'suricata': config.get('suricata_log_path', '/var/log/suricata/eve.json'),
            'snort': config.get('snort_log_path', '/var/log/snort/alert')
        })
        
        self.test_results = []
        
    def run_throughput_test(self, pps_levels: List[int], duration: int = 60) -> List[PerformanceMetrics]:
        """Test de throughput à différents niveaux de PPS"""
        logger.info(f"🏎️ Tests de throughput: {pps_levels} PPS")
        results = []
        
        for pps in pps_levels:
            logger.info(f"📈 Test throughput {pps} PPS pendant {duration}s")
            
            # Démarrage monitoring
            self.system_monitor.start_monitoring(0.5)
            self.latency_measurer.start_measuring()
            
            start_time = datetime.now()
            
            # Génération du trafic
            traffic_stats = self.traffic_generator.generate_high_volume_traffic(
                pps, duration, ['tcp', 'udp', 'http']
            )
            
            # Arrêt monitoring
            time.sleep(2)  # Attendre dernières détections
            self.latency_measurer.stop_measuring()
            system_metrics = self.system_monitor.get_current_metrics()
            self.system_monitor.stop_monitoring()
            
            # Calcul des métriques
            metrics = self._calculate_performance_metrics(
                'throughput', start_time, duration,
                traffic_stats, system_metrics
            )
            
            results.append(metrics)
            
            # Pause entre tests
            logger.info(f"⏳ Pause 30s avant le prochain test...")
            time.sleep(30)
        
        return results
    
    def run_latency_test(self, attack_types: List[str], duration: int = 300) -> PerformanceMetrics:
        """Test de latence de détection"""
        logger.info(f"⏱️ Test latence détection pendant {duration}s")
        
        # Démarrage monitoring
        self.system_monitor.start_monitoring(1.0)
        self.latency_measurer.start_measuring()
        
        start_time = datetime.now()
        
        # Génération d'attaques variées
        attack_stats = self._generate_attack_traffic(attack_types, duration)
        
        # Attendre les détections
        time.sleep(10)
        
        # Arrêt monitoring
        self.latency_measurer.stop_measuring()
        system_metrics = self.system_monitor.get_current_metrics()
        self.system_monitor.stop_monitoring()
        
        # Calcul des métriques
        metrics = self._calculate_performance_metrics(
            'latency', start_time, duration + 10,
            attack_stats, system_metrics
        )
        
        return metrics
    
    def run_stress_test(self, max_pps: int, duration: int = 600) -> PerformanceMetrics:
        """Test de stress système"""
        logger.info(f"💥 Test de stress {max_pps} PPS pendant {duration}s")
        
        # Démarrage monitoring intensif
        self.system_monitor.start_monitoring(0.2)
        self.latency_measurer.start_measuring()
        
        start_time = datetime.now()
        
        # Montée progressive en charge
        ramp_duration = min(60, duration // 4)
        stable_duration = duration - 2 * ramp_duration
        
        # Phase 1: Montée en charge
        logger.info("📈 Phase 1: Montée en charge")
        for i in range(ramp_duration):
            current_pps = int(max_pps * (i + 1) / ramp_duration)
            self.traffic_generator.generate_high_volume_traffic(current_pps, 1)
            time.sleep(1)
        
        # Phase 2: Charge stable
        logger.info("🔥 Phase 2: Charge stable maximale")
        traffic_stats = self.traffic_generator.generate_high_volume_traffic(
            max_pps, stable_duration
        )
        
        # Phase 3: Descente en charge
        logger.info("📉 Phase 3: Descente en charge")
        for i in range(ramp_duration):
            current_pps = int(max_pps * (ramp_duration - i) / ramp_duration)
            self.traffic_generator.generate_high_volume_traffic(current_pps, 1)
            time.sleep(1)
        
        # Attendre stabilisation
        time.sleep(30)
        
        # Arrêt monitoring
        self.latency_measurer.stop_measuring()
        system_metrics = self.system_monitor.get_current_metrics()
        self.system_monitor.stop_monitoring()
        
        # Calcul des métriques
        metrics = self._calculate_performance_metrics(
            'stress', start_time, duration + 30,
            traffic_stats, system_metrics
        )
        
        return metrics
    
    def run_scalability_test(self, connection_counts: List[int], duration: int = 120) -> List[PerformanceMetrics]:
        """Test de scalabilité (nombre de connexions simultanées)"""
        logger.info(f"📏 Tests scalabilité: {connection_counts} connexions")
        results = []
        
        for conn_count in connection_counts:
            logger.info(f"🔗 Test {conn_count} connexions simultanées")
            
            # Démarrage monitoring
            self.system_monitor.start_monitoring(1.0)
            self.latency_measurer.start_measuring()
            
            start_time = datetime.now()
            
            # Simulation connexions simultanées
            connection_stats = self._simulate_concurrent_connections(conn_count, duration)
            
            # Attendre fin des connexions
            time.sleep(10)
            
            # Arrêt monitoring
            self.latency_measurer.stop_measuring()
            system_metrics = self.system_monitor.get_current_metrics()
            self.system_monitor.stop_monitoring()
            
            # Calcul des métriques
            metrics = self._calculate_performance_metrics(
                'scalability', start_time, duration + 10,
                connection_stats, system_metrics
            )
            
            results.append(metrics)
            
            # Pause entre tests
            time.sleep(20)
        
        return results
    
    def _generate_attack_traffic(self, attack_types: List[str], duration: int) -> Dict[str, Any]:
        """Génération de trafic d'attaque pour tests de latence"""
        stats = {'packets_sent': 0, 'attacks_generated': 0}
        
        # Utilisation du générateur de trafic malveillant existant
        script_path = self.config.get('malicious_traffic_generator',
                                    '../tools/generators/malicious-traffic-generator.py')
        
        if not Path(script_path).exists():
            logger.warning("⚠️ Générateur de trafic malveillant non trouvé")
            return stats
        
        try:
            for attack_type in attack_types:
                cmd = [
                    'python3', script_path,
                    '--attack', attack_type,
                    '--target', '192.168.100.10',
                    '--duration', str(duration // len(attack_types)),
                    '--rate-limit', '10'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
                if result.returncode == 0:
                    stats['attacks_generated'] += 1
                
                # Extraction stats depuis la sortie
                if "Requêtes envoyées:" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if "Requêtes envoyées:" in line:
                            stats['packets_sent'] += int(line.split(':')[1].strip())
                
        except Exception as e:
            logger.error(f"❌ Erreur génération attaques: {e}")
        
        return stats
    
    def _simulate_concurrent_connections(self, conn_count: int, duration: int) -> Dict[str, Any]:
        """Simulation de connexions simultanées"""
        stats = {
            'connections_attempted': 0,
            'connections_successful': 0,
            'connections_failed': 0,
            'total_bytes': 0
        }
        
        def connection_worker():
            """Worker pour une connexion"""
            target_ips = ["192.168.100.10", "192.168.100.20", "192.168.100.30"]
            ports = [80, 443, 22, 21, 23]
            
            import random
            target = random.choice(target_ips)
            port = random.choice(ports)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    stats['connections_successful'] += 1
                    # Maintenir la connexion
                    time.sleep(random.uniform(duration * 0.1, duration * 0.8))
                    sock.send(b"Performance test data\n")
                    stats['total_bytes'] += 25
                else:
                    stats['connections_failed'] += 1
                
                sock.close()
                stats['connections_attempted'] += 1
                
            except Exception:
                stats['connections_failed'] += 1
        
        # Lancement des connexions simultanées
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(conn_count, 200)) as executor:
            futures = [executor.submit(connection_worker) for _ in range(conn_count)]
            
            # Attendre que toutes les connexions se terminent
            for future in concurrent.futures.as_completed(futures, timeout=duration + 60):
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"Erreur connexion: {e}")
        
        return stats
    
    def _calculate_performance_metrics(self, test_type: str, start_time: datetime,
                                     duration: float, traffic_stats: Dict[str, Any],
                                     system_metrics: List[Dict[str, Any]]) -> PerformanceMetrics:
        """Calcul des métriques de performance"""
        
        # Statistiques de latence
        latency_stats = self.latency_measurer.get_latency_stats()
        
        # Statistiques système
        if system_metrics:
            cpu_values = [m['cpu_percent'] for m in system_metrics]
            memory_values = [m['memory_percent'] for m in system_metrics]
            
            cpu_avg = statistics.mean(cpu_values) if cpu_values else 0
            cpu_peak = max(cpu_values) if cpu_values else 0
            memory_avg = statistics.mean(memory_values) if memory_values else 0
            memory_peak = max(memory_values) if memory_values else 0
        else:
            cpu_avg = cpu_peak = memory_avg = memory_peak = 0
        
        # Calcul throughput
        packets_sent = traffic_stats.get('packets_sent', 0)
        bytes_sent = traffic_stats.get('bytes_sent', 0)
        
        throughput_pps = packets_sent / duration if duration > 0 else 0
        throughput_mbps = (bytes_sent * 8) / (duration * 1024 * 1024) if duration > 0 else 0
        
        # Estimation des détections (à améliorer avec vraie corrélation)
        estimated_detections = max(1, packets_sent // 100)  # 1% de détection estimé
        detection_rate = latency_stats['count'] / estimated_detections if estimated_detections > 0 else 0
        
        # Qualité du système
        error_rate = traffic_stats.get('errors', 0) / packets_sent * 100 if packets_sent > 0 else 0
        packet_loss = max(0, 100 - traffic_stats.get('efficiency', 100))
        
        # Stabilité système
        if cpu_peak < 80 and memory_peak < 80 and error_rate < 1:
            stability = "stable"
        elif cpu_peak < 95 and memory_peak < 95 and error_rate < 5:
            stability = "acceptable"
        else:
            stability = "unstable"
        
        return PerformanceMetrics(
            timestamp=start_time.isoformat(),
            test_type=test_type,
            duration=duration,
            
            packets_sent=packets_sent,
            packets_processed=packets_sent - traffic_stats.get('errors', 0),
            throughput_pps=throughput_pps,
            throughput_mbps=throughput_mbps,
            
            avg_detection_latency=latency_stats['avg'],
            min_detection_latency=latency_stats['min'],
            max_detection_latency=latency_stats['max'],
            p95_detection_latency=latency_stats['p95'],
            p99_detection_latency=latency_stats['p99'],
            
            cpu_usage_avg=cpu_avg,
            cpu_usage_peak=cpu_peak,
            memory_usage_avg=memory_avg,
            memory_usage_peak=memory_peak,
            disk_io_avg=0,  # À implémenter si nécessaire
            network_io_avg=0,  # À implémenter si nécessaire
            
            total_detections=latency_stats['count'],
            detection_rate=detection_rate,
            false_positives=0,  # À implémenter avec corrélation
            false_negatives=0,  # À implémenter avec corrélation
            
            packet_loss=packet_loss,
            error_rate=error_rate,
            system_stability=stability
        )
    
    def generate_performance_report(self, test_suite: str, 
                                  metrics_list: List[PerformanceMetrics]) -> PerformanceReport:
        """Génération du rapport de performance"""
        if not metrics_list:
            logger.warning("⚠️ Aucune métrique pour générer le rapport")
            return None
        
        start_time = min(m.timestamp for m in metrics_list)
        end_time = max(m.timestamp for m in metrics_list)
        total_duration = sum(m.duration for m in metrics_list)
        
        # Informations système
        system_info = {
            'cpu_count': multiprocessing.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'platform': psutil.platform.platform(),
            'python_version': sys.version.split()[0]
        }
        
        # Configuration de test
        test_config = {
            'target_network': self.config.get('target_network', '192.168.100.0/24'),
            'suricata_enabled': Path(self.config.get('suricata_log_path', '')).exists(),
            'snort_enabled': Path(self.config.get('snort_log_path', '')).exists()
        }
        
        # Résumé des performances
        summary = self._calculate_performance_summary(metrics_list)
        
        # Recommandations
        recommendations = self._generate_performance_recommendations(metrics_list, summary)
        
        # Note de performance
        grade = self._calculate_performance_grade(summary)
        
        # Identification des goulots d'étranglement
        bottlenecks = self._identify_bottlenecks(metrics_list)
        
        return PerformanceReport(
            test_suite=test_suite,
            start_time=start_time,
            end_time=end_time,
            total_duration=total_duration,
            
            system_info=system_info,
            test_configuration=test_config,
            
            metrics=metrics_list,
            summary=summary,
            recommendations=recommendations,
            
            performance_grade=grade,
            bottlenecks=bottlenecks
        )
    
    def _calculate_performance_summary(self, metrics_list: List[PerformanceMetrics]) -> Dict[str, Any]:
        """Calcul du résumé de performance"""
        throughput_values = [m.throughput_pps for m in metrics_list if m.throughput_pps > 0]
        latency_values = [m.avg_detection_latency for m in metrics_list if m.avg_detection_latency > 0]
        cpu_peaks = [m.cpu_usage_peak for m in metrics_list]
        memory_peaks = [m.memory_usage_peak for m in metrics_list]
        
        return {
            'max_throughput_pps': max(throughput_values) if throughput_values else 0,
            'avg_throughput_pps': statistics.mean(throughput_values) if throughput_values else 0,
            'min_detection_latency': min(latency_values) if latency_values else 0,
            'avg_detection_latency': statistics.mean(latency_values) if latency_values else 0,
            'max_detection_latency': max(latency_values) if latency_values else 0,
            'peak_cpu_usage': max(cpu_peaks) if cpu_peaks else 0,
            'avg_cpu_usage': statistics.mean(cpu_peaks) if cpu_peaks else 0,
            'peak_memory_usage': max(memory_peaks) if memory_peaks else 0,
            'avg_memory_usage': statistics.mean(memory_peaks) if memory_peaks else 0,
            'total_packets_processed': sum(m.packets_processed for m in metrics_list),
            'total_detections': sum(m.total_detections for m in metrics_list),
            'avg_detection_rate': statistics.mean([m.detection_rate for m in metrics_list if m.detection_rate > 0]) or 0,
            'system_stability': self._assess_overall_stability(metrics_list)
        }
    
    def _generate_performance_recommendations(self, metrics_list: List[PerformanceMetrics],
                                           summary: Dict[str, Any]) -> List[str]:
        """Génération des recommandations de performance"""
        recommendations = []
        
        # Throughput
        max_throughput = summary['max_throughput_pps']
        if max_throughput < 1000:
            recommendations.append("🚀 Throughput faible (<1K pps). Optimiser la configuration IDS/IPS ou upgrader le matériel.")
        elif max_throughput < 10000:
            recommendations.append("⚡ Throughput modéré. Considérer l'optimisation des règles de détection.")
        else:
            recommendations.append("✅ Excellent throughput détecté.")
        
        # Latence
        avg_latency = summary['avg_detection_latency']
        if avg_latency > 5.0:
            recommendations.append("⏱️ Latence de détection élevée (>5s). Réviser les règles complexes et optimiser les ressources.")
        elif avg_latency > 1.0:
            recommendations.append("🔧 Latence acceptable mais améliorable. Optimiser les règles fréquemment déclenchées.")
        else:
            recommendations.append("✅ Latence de détection excellente.")
        
        # CPU
        peak_cpu = summary['peak_cpu_usage']
        if peak_cpu > 90:
            recommendations.append("🔥 Usage CPU critique (>90%). Ajouter des ressources ou répartir la charge.")
        elif peak_cpu > 70:
            recommendations.append("⚠️ Usage CPU élevé. Surveiller et prévoir une montée en charge.")
        
        # Mémoire
        peak_memory = summary['peak_memory_usage']
        if peak_memory > 85:
            recommendations.append("💾 Usage mémoire critique (>85%). Augmenter la RAM ou optimiser la configuration.")
        elif peak_memory > 70:
            recommendations.append("📊 Usage mémoire élevé. Surveiller l'évolution.")
        
        # Détection
        detection_rate = summary['avg_detection_rate']
        if detection_rate < 0.5:
            recommendations.append("🎯 Taux de détection faible. Réviser les règles et la couverture des signatures.")
        elif detection_rate > 1.2:
            recommendations.append("🚨 Taux de détection élevé, possibles faux positifs. Affiner les règles.")
        
        # Stabilité
        if summary['system_stability'] == 'unstable':
            recommendations.append("⚠️ Système instable détecté. Réduire la charge ou optimiser la configuration.")
        elif summary['system_stability'] == 'acceptable':
            recommendations.append("🔧 Stabilité acceptable mais perfectible.")
        
        if not recommendations:
            recommendations.append("🎯 Système bien optimisé pour la charge testée.")
        
        return recommendations
    
    def _calculate_performance_grade(self, summary: Dict[str, Any]) -> str:
        """Calcul de la note de performance"""
        score = 0
        factors = 0
        
        # Throughput (30% du score)
        if summary['max_throughput_pps'] >= 10000:
            score += 30
        elif summary['max_throughput_pps'] >= 5000:
            score += 25
        elif summary['max_throughput_pps'] >= 1000:
            score += 20
        else:
            score += 10
        factors += 30
        
        # Latence (25% du score)
        if summary['avg_detection_latency'] <= 0.5:
            score += 25
        elif summary['avg_detection_latency'] <= 1.0:
            score += 22
        elif summary['avg_detection_latency'] <= 2.0:
            score += 18
        elif summary['avg_detection_latency'] <= 5.0:
            score += 15
        else:
            score += 10
        factors += 25
        
        # Ressources (25% du score)
        resource_score = 0
        if summary['peak_cpu_usage'] <= 70:
            resource_score += 12.5
        elif summary['peak_cpu_usage'] <= 85:
            resource_score += 10
        else:
            resource_score += 5
        
        if summary['peak_memory_usage'] <= 70:
            resource_score += 12.5
        elif summary['peak_memory_usage'] <= 85:
            resource_score += 10
        else:
            resource_score += 5
        
        score += resource_score
        factors += 25
        
        # Stabilité (20% du score)
        if summary['system_stability'] == 'stable':
            score += 20
        elif summary['system_stability'] == 'acceptable':
            score += 15
        else:
            score += 10
        factors += 20
        
        # Calcul final
        final_score = (score / factors) * 100 if factors > 0 else 0
        
        if final_score >= 90:
            return "A+ (Excellent)"
        elif final_score >= 80:
            return "A (Très bon)"
        elif final_score >= 70:
            return "B (Bon)"
        elif final_score >= 60:
            return "C (Acceptable)"
        elif final_score >= 50:
            return "D (Faible)"
        else:
            return "F (Insuffisant)"
    
    def _identify_bottlenecks(self, metrics_list: List[PerformanceMetrics]) -> List[str]:
        """Identification des goulots d'étranglement"""
        bottlenecks = []
        
        # Analyser les pics de ressources
        for metrics in metrics_list:
            if metrics.cpu_usage_peak > 90:
                bottlenecks.append(f"CPU surchargé ({metrics.cpu_usage_peak:.1f}%) - {metrics.test_type}")
            
            if metrics.memory_usage_peak > 85:
                bottlenecks.append(f"Mémoire saturée ({metrics.memory_usage_peak:.1f}%) - {metrics.test_type}")
            
            if metrics.avg_detection_latency > 5:
                bottlenecks.append(f"Latence excessive ({metrics.avg_detection_latency:.1f}s) - {metrics.test_type}")
            
            if metrics.error_rate > 5:
                bottlenecks.append(f"Taux d'erreur élevé ({metrics.error_rate:.1f}%) - {metrics.test_type}")
            
            if metrics.system_stability == 'unstable':
                bottlenecks.append(f"Instabilité système détectée - {metrics.test_type}")
        
        return list(set(bottlenecks))  # Supprimer doublons
    
    def _assess_overall_stability(self, metrics_list: List[PerformanceMetrics]) -> str:
        """Évaluation de la stabilité globale"""
        stability_scores = {
            'stable': 3,
            'acceptable': 2,
            'unstable': 1
        }
        
        scores = [stability_scores.get(m.system_stability, 1) for m in metrics_list]
        avg_score = statistics.mean(scores) if scores else 1
        
        if avg_score >= 2.7:
            return 'stable'
        elif avg_score >= 2.0:
            return 'acceptable'
        else:
            return 'unstable'
    
    def save_performance_report(self, report: PerformanceReport, output_file: str = None):
        """Sauvegarde du rapport de performance"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"performance_report_{timestamp}.json"
        
        # Conversion en dictionnaire
        report_dict = asdict(report)
        
        with open(output_file, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"💾 Rapport de performance sauvegardé: {output_file}")
        
        # Génération rapport HTML
        html_file = output_file.replace('.json', '.html')
        self._generate_html_performance_report(report, html_file)
    
    def _generate_html_performance_report(self, report: PerformanceReport, html_file: str):
        """Génération d'un rapport HTML de performance"""
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📈 Rapport de Performance IDS/IPS</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }}
        
        .report-header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #3498db;
        }}
        
        .report-title {{
            font-size: 36px;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .report-subtitle {{
            font-size: 18px;
            color: #7f8c8d;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 5px solid #3498db;
        }}
        
        .summary-value {{
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        
        .summary-label {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        
        .grade-card {{
            background: linear-gradient(135deg, #2ecc71, #27ae60);
            color: white;
            border-left: 5px solid #27ae60;
        }}
        
        .grade-card .summary-value {{
            color: white;
        }}
        
        .metrics-section {{
            margin: 40px 0;
        }}
        
        .section-title {{
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }}
        
        .chart-container {{
            margin: 20px 0;
            height: 400px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
        }}
        
        .recommendations {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
        }}
        
        .recommendation-item {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #f39c12;
        }}
        
        .bottlenecks {{
            background: #ffeaea;
            border: 1px solid #ff7675;
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
        }}
        
        .bottleneck-item {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #e74c3c;
        }}
        
        .system-info {{
            background: #e8f4fd;
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #3498db;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #2c3e50;
        }}
        
        .info-value {{
            color: #7f8c8d;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <div class="report-title">📈 Rapport de Performance IDS/IPS</div>
            <div class="report-subtitle">
                Suite: {report.test_suite} | 
                Durée: {report.total_duration:.1f}s | 
                Période: {report.start_time} - {report.end_time}
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{report.summary['max_throughput_pps']:,.0f}</div>
                <div class="summary-label">Throughput Max (PPS)</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{report.summary['avg_detection_latency']:.2f}s</div>
                <div class="summary-label">Latence Moyenne</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{report.summary['peak_cpu_usage']:.1f}%</div>
                <div class="summary-label">CPU Peak</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{report.summary['peak_memory_usage']:.1f}%</div>
                <div class="summary-label">Mémoire Peak</div>
            </div>
            <div class="summary-card grade-card">
                <div class="summary-value">{report.performance_grade}</div>
                <div class="summary-label">Note Globale</div>
            </div>
        </div>
        
        <div class="system-info">
            <div class="section-title">💻 Informations Système</div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">CPU</div>
                    <div class="info-value">{report.system_info['cpu_count']} cœurs</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Mémoire</div>
                    <div class="info-value">{report.system_info['memory_total_gb']:.1f} GB</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Plateforme</div>
                    <div class="info-value">{report.system_info['platform']}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Python</div>
                    <div class="info-value">{report.system_info['python_version']}</div>
                </div>
            </div>
        </div>
        
        <div class="metrics-section">
            <div class="section-title">📊 Graphiques de Performance</div>
            <div class="chart-container">
                <canvas id="throughputChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="latencyChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="resourceChart"></canvas>
            </div>
        </div>
        
        {'<div class="recommendations"><div class="section-title">🔧 Recommandations</div>' + 
         ''.join(f'<div class="recommendation-item">{rec}</div>' for rec in report.recommendations) + 
         '</div>' if report.recommendations else ''}
        
        {'<div class="bottlenecks"><div class="section-title">⚠️ Goulots d\'Étranglement</div>' + 
         ''.join(f'<div class="bottleneck-item">{bottleneck}</div>' for bottleneck in report.bottlenecks) + 
         '</div>' if report.bottlenecks else ''}
        
        <div class="system-info">
            <div class="section-title">📋 Résumé Détaillé</div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Paquets Traités</div>
                    <div class="info-value">{report.summary['total_packets_processed']:,}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Détections Totales</div>
                    <div class="info-value">{report.summary['total_detections']:,}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Taux de Détection</div>
                    <div class="info-value">{report.summary['avg_detection_rate']:.1%}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Stabilité Système</div>
                    <div class="info-value">{report.summary['system_stability'].title()}</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Données des métriques
        const metrics = {json.dumps([asdict(m) for m in report.metrics], default=str)};
        
        // Graphique Throughput
        const throughputCtx = document.getElementById('throughputChart').getContext('2d');
        new Chart(throughputCtx, {{
            type: 'line',
            data: {{
                labels: metrics.map((m, i) => `Test ${{i+1}} (${{m.test_type}})`),
                datasets: [{{
                    label: 'Throughput (PPS)',
                    data: metrics.map(m => m.throughput_pps),
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52,152,219,0.1)',
                    tension: 0.4,
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ beginAtZero: true, title: {{ display: true, text: 'Paquets/seconde' }} }}
                }},
                plugins: {{
                    title: {{ display: true, text: 'Évolution du Throughput' }}
                }}
            }}
        }});
        
        // Graphique Latence
        const latencyCtx = document.getElementById('latencyChart').getContext('2d');
        new Chart(latencyCtx, {{
            type: 'bar',
            data: {{
                labels: metrics.map((m, i) => `Test ${{i+1}}`),
                datasets: [{{
                    label: 'Latence Moyenne (s)',
                    data: metrics.map(m => m.avg_detection_latency),
                    backgroundColor: 'rgba(241,196,15,0.7)',
                    borderColor: '#f1c40f',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ beginAtZero: true, title: {{ display: true, text: 'Secondes' }} }}
                }},
                plugins: {{
                    title: {{ display: true, text: 'Latence de Détection' }}
                }}
            }}
        }});
        
        // Graphique Ressources
        const resourceCtx = document.getElementById('resourceChart').getContext('2d');
        new Chart(resourceCtx, {{
            type: 'line',
            data: {{
                labels: metrics.map((m, i) => `Test ${{i+1}}`),
                datasets: [
                    {{
                        label: 'CPU Peak (%)',
                        data: metrics.map(m => m.cpu_usage_peak),
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231,76,60,0.1)',
                        yAxisID: 'y'
                    }},
                    {{
                        label: 'Mémoire Peak (%)',
                        data: metrics.map(m => m.memory_usage_peak),
                        borderColor: '#9b59b6',
                        backgroundColor: 'rgba(155,89,182,0.1)',
                        yAxisID: 'y'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ 
                        beginAtZero: true, 
                        max: 100,
                        title: {{ display: true, text: 'Pourcentage (%)' }}
                    }}
                }},
                plugins: {{
                    title: {{ display: true, text: 'Utilisation des Ressources' }}
                }}
            }}
        }});
    </script>
</body>
</html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"📄 Rapport HTML généré: {html_file}")

def load_config(config_file: str = None) -> Dict[str, Any]:
    """Chargement de la configuration"""
    default_config = {
        'target_network': '192.168.100.0/24',
        'suricata_log_path': '/var/log/suricata/eve.json',
        'snort_log_path': '/var/log/snort/alert',
        'elasticsearch_url': 'http://localhost:9200',
        'malicious_traffic_generator': '../../tools/generators/malicious-traffic-generator.py'
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
        description="Tests de performance IDS/IPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Test de throughput
  python3 performance-test.py --test-type throughput --pps-levels 100,500,1000 --duration 60
  
  # Test de latence
  python3 performance-test.py --test-type latency --duration 300
  
  # Test de stress
  python3 performance-test.py --test-type stress --max-pps 5000 --duration 600
  
  # Test de scalabilité
  python3 performance-test.py --test-type scalability --connections 50,100,200 --duration 120
  
  # Suite complète
  python3 performance-test.py --test-type full --duration 300
        """
    )
    
    parser.add_argument('--test-type', 
                       choices=['throughput', 'latency', 'stress', 'scalability', 'full'],
                       default='throughput',
                       help='Type de test de performance')
    
    parser.add_argument('--pps-levels', 
                       default='100,500,1000,2000',
                       help='Niveaux PPS pour test throughput (séparés par virgules)')
    
    parser.add_argument('--max-pps', type=int, default=5000,
                       help='PPS maximum pour test de stress')
    
    parser.add_argument('--connections',
                       default='10,50,100,200',
                       help='Nombre de connexions pour test scalabilité (séparés par virgules)')
    
    parser.add_argument('--duration', type=int, default=60,
                       help='Durée des tests en secondes')
    
    parser.add_argument('--config', help='Fichier de configuration JSON')
    parser.add_argument('--output', help='Fichier de sortie pour le rapport')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Vérification droits administrateur pour certains tests
    if os.name != 'nt' and os.geteuid() != 0:
        logger.warning("⚠️ Tests de performance recommandés en tant qu'administrateur")
    
    try:
        logger.info("🚀 Démarrage des tests de performance IDS/IPS")
        
        # Chargement configuration
        config = load_config(args.config)
        
        # Initialisation du testeur
        tester = PerformanceTester(config)
        
        # Exécution des tests selon le type
        all_metrics = []
        
        if args.test_type == 'throughput':
            pps_levels = [int(x.strip()) for x in args.pps_levels.split(',')]
            metrics = tester.run_throughput_test(pps_levels, args.duration)
            all_metrics.extend(metrics)
            
        elif args.test_type == 'latency':
            attack_types = ['port_scan', 'brute_force', 'web_attacks']
            metrics = tester.run_latency_test(attack_types, args.duration)
            all_metrics.append(metrics)
            
        elif args.test_type == 'stress':
            metrics = tester.run_stress_test(args.max_pps, args.duration)
            all_metrics.append(metrics)
            
        elif args.test_type == 'scalability':
            conn_counts = [int(x.strip()) for x in args.connections.split(',')]
            metrics = tester.run_scalability_test(conn_counts, args.duration)
            all_metrics.extend(metrics)
            
        elif args.test_type == 'full':
            logger.info("🎯 Suite complète de tests de performance")
            
            # Throughput
            throughput_metrics = tester.run_throughput_test([500, 1000, 2000], args.duration)
            all_metrics.extend(throughput_metrics)
            
            time.sleep(30)  # Pause entre suites
            
            # Latence
            latency_metrics = tester.run_latency_test(['port_scan', 'web_attacks'], args.duration)
            all_metrics.append(latency_metrics)
            
            time.sleep(30)  # Pause entre suites
            
            # Scalabilité
            scalability_metrics = tester.run_scalability_test([50, 100], args.duration)
            all_metrics.extend(scalability_metrics)
        
        # Génération du rapport
        if all_metrics:
            report = tester.generate_performance_report(args.test_type, all_metrics)
            
            # Affichage résumé
            print("\n" + "="*80)
            print("📈 RAPPORT DE PERFORMANCE IDS/IPS")
            print("="*80)
            print(f"Suite de tests: {report.test_suite}")
            print(f"Durée totale: {report.total_duration:.1f}s")
            print(f"Tests exécutés: {len(report.metrics)}")
            
            print("\n📊 MÉTRIQUES PRINCIPALES")
            print("-" * 50)
            print(f"Throughput maximum: {report.summary['max_throughput_pps']:,.0f} PPS")
            print(f"Latence moyenne: {report.summary['avg_detection_latency']:.2f}s")
            print(f"CPU peak: {report.summary['peak_cpu_usage']:.1f}%")
            print(f"Mémoire peak: {report.summary['peak_memory_usage']:.1f}%")
            print(f"Note de performance: {report.performance_grade}")
            
            if report.recommendations:
                print("\n🔧 RECOMMANDATIONS PRINCIPALES")
                print("-" * 50)
                for rec in report.recommendations[:3]:
                    print(f"• {rec}")
            
            if report.bottlenecks:
                print("\n⚠️ GOULOTS D'ÉTRANGLEMENT")
                print("-" * 50)
                for bottleneck in report.bottlenecks[:3]:
                    print(f"• {bottleneck}")
            
            print("\n" + "="*80)
            
            # Sauvegarde
            tester.save_performance_report(report, args.output)
            
        else:
            logger.error("❌ Aucune métrique collectée")
            return 1
        
        logger.info("✅ Tests de performance terminés avec succès")
        return 0
        
    except KeyboardInterrupt:
        logger.info("⚠️ Tests interrompus par l'utilisateur")
        return 130
    except Exception as e:
        logger.error(f"❌ Erreur tests de performance: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())