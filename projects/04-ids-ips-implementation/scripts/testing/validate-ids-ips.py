#!/usr/bin/env python3
"""
Script de Validation Automatisée IDS/IPS
Projet 04 - Cybersecurity Portfolio

Fonctionnalités:
- Exécution automatisée de tests d'intrusion
- Vérification des détections Suricata/Snort
- Analyse des logs et génération de rapports
- Calcul de métriques de performance
- Validation de l'efficacité des règles de détection

Usage: python3 validate-ids-ips.py --test-suite comprehensive
"""

import os
import sys
import time
import json
import subprocess
import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import concurrent.futures
import threading
import signal
import statistics
from dataclasses import dataclass, asdict

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Résultat d'un test individuel"""
    test_name: str
    attack_type: str
    target: str
    start_time: str
    end_time: str
    duration: float
    attacks_sent: int
    detections_expected: int
    detections_found: int
    false_positives: int
    detection_rate: float
    response_time_avg: float
    success: bool
    details: Dict[str, Any]

@dataclass
class ValidationReport:
    """Rapport de validation complet"""
    test_suite: str
    start_time: str
    end_time: str
    total_duration: float
    tests_executed: int
    tests_passed: int
    tests_failed: int
    overall_detection_rate: float
    avg_response_time: float
    performance_metrics: Dict[str, Any]
    recommendations: List[str]
    test_results: List[TestResult]

class IDSIPSValidator:
    def __init__(self, config_file: str = None):
        """
        Initialisation du validateur IDS/IPS
        
        Args:
            config_file: Fichier de configuration JSON
        """
        self.config = self._load_config(config_file)
        self.running = False
        self.results = []
        self.start_time = None
        
        # Chemins des outils
        self.traffic_generator_path = self.config.get('traffic_generator_path', 
            '../../tools/generators/malicious-traffic-generator.py')
        self.log_analyzer_path = self.config.get('log_analyzer_path',
            '../../tools/analysis/ids-log-analyzer.py')
        
        # Configuration IDS/IPS
        self.suricata_log_path = self.config.get('suricata_log_path', '/var/log/suricata/eve.json')
        self.snort_log_path = self.config.get('snort_log_path', '/var/log/snort/alert')
        self.elasticsearch_url = self.config.get('elasticsearch_url', 'http://localhost:9200')
        
        # Configuration réseau de test
        self.test_network = self.config.get('test_network', '192.168.100.0/24')
        self.test_targets = self.config.get('test_targets', ['192.168.100.10', '192.168.100.20'])
        
        logger.info("🔧 Validateur IDS/IPS initialisé")

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Chargement de la configuration"""
        default_config = {
            'traffic_generator_path': '../../tools/generators/malicious-traffic-generator.py',
            'log_analyzer_path': '../../tools/analysis/ids-log-analyzer.py',
            'suricata_log_path': '/var/log/suricata/eve.json',
            'snort_log_path': '/var/log/snort/alert',
            'elasticsearch_url': 'http://localhost:9200',
            'test_network': '192.168.100.0/24',
            'test_targets': ['192.168.100.10', '192.168.100.20'],
            'test_duration': 30,
            'wait_time_between_tests': 5,
            'detection_timeout': 60,
            'expected_detection_rates': {
                'port_scan': 0.9,
                'brute_force': 0.85,
                'web_attacks': 0.8,
                'ddos': 0.95,
                'data_exfiltration': 0.7,
                'lateral_movement': 0.75
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Erreur chargement config: {e}. Utilisation config par défaut.")
        
        return default_config

    def check_prerequisites(self) -> bool:
        """Vérification des prérequis"""
        logger.info("🔍 Vérification des prérequis...")
        
        checks = []
        
        # Vérification outils
        if not Path(self.traffic_generator_path).exists():
            logger.error(f"❌ Générateur de trafic introuvable: {self.traffic_generator_path}")
            checks.append(False)
        else:
            checks.append(True)
            
        if not Path(self.log_analyzer_path).exists():
            logger.error(f"❌ Analyseur de logs introuvable: {self.log_analyzer_path}")
            checks.append(False)
        else:
            checks.append(True)
        
        # Vérification services IDS/IPS
        services_to_check = ['suricata', 'snort']
        for service in services_to_check:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'active' in result.stdout:
                    logger.info(f"✅ Service {service} actif")
                    checks.append(True)
                else:
                    logger.warning(f"⚠️ Service {service} non actif")
                    checks.append(False)
            except Exception as e:
                logger.warning(f"⚠️ Impossible de vérifier le service {service}: {e}")
                checks.append(False)
        
        # Vérification Elasticsearch
        try:
            import requests
            response = requests.get(f"{self.elasticsearch_url}/_cluster/health", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Elasticsearch accessible")
                checks.append(True)
            else:
                logger.warning("⚠️ Elasticsearch non accessible")
                checks.append(False)
        except Exception as e:
            logger.warning(f"⚠️ Erreur connexion Elasticsearch: {e}")
            checks.append(False)
        
        # Vérification fichiers de logs
        log_files = [self.suricata_log_path, self.snort_log_path]
        for log_file in log_files:
            if Path(log_file).exists() or Path(log_file).parent.exists():
                logger.info(f"✅ Répertoire de logs accessible: {log_file}")
                checks.append(True)
            else:
                logger.warning(f"⚠️ Répertoire de logs non accessible: {log_file}")
                checks.append(False)
        
        success_rate = sum(checks) / len(checks)
        logger.info(f"📊 Prérequis vérifiés: {success_rate:.1%} ({sum(checks)}/{len(checks)})")
        
        return success_rate >= 0.7  # 70% des prérequis requis

    def execute_attack_test(self, attack_type: str, target: str, 
                          duration: int = 30, extra_args: List[str] = None) -> Dict[str, Any]:
        """
        Exécution d'un test d'attaque
        
        Args:
            attack_type: Type d'attaque à tester
            target: Cible de l'attaque
            duration: Durée du test
            extra_args: Arguments supplémentaires
        """
        logger.info(f"🚀 Test d'attaque: {attack_type} vers {target}")
        
        # Préparation de la commande
        cmd = [
            'python3', self.traffic_generator_path,
            '--attack', attack_type,
            '--target', target,
            '--duration', str(duration),
            '--rate-limit', '5',  # Limitation pour les tests
            '--output', f'/tmp/attack_{attack_type}_{int(time.time())}.json'
        ]
        
        if extra_args:
            cmd.extend(extra_args)
        
        # Récupération timestamp pré-attaque pour filtrer les logs
        pre_attack_time = datetime.now()
        
        try:
            # Exécution de l'attaque
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
            end_time = time.time()
            
            # Parsing du résultat
            attack_result = {
                'success': result.returncode == 0,
                'duration': end_time - start_time,
                'stdout': result.stdout[-1000:],  # Derniers 1000 caractères
                'stderr': result.stderr[-1000:] if result.stderr else '',
                'command': ' '.join(cmd),
                'pre_attack_time': pre_attack_time.isoformat(),
                'post_attack_time': datetime.now().isoformat()
            }
            
            # Extraction des statistiques depuis la sortie
            if "Requêtes envoyées:" in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if "Requêtes envoyées:" in line:
                        attack_result['attacks_sent'] = int(line.split(':')[1].strip())
                    elif "Réponses reçues:" in line:
                        attack_result['responses_received'] = int(line.split(':')[1].strip())
                    elif "Erreurs:" in line:
                        attack_result['errors'] = int(line.split(':')[1].strip())
            
            if attack_result['success']:
                logger.info(f"✅ Attaque {attack_type} réussie ({attack_result['duration']:.1f}s)")
            else:
                logger.warning(f"⚠️ Attaque {attack_type} partiellement réussie")
                
            return attack_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Timeout attaque {attack_type}")
            return {'success': False, 'error': 'timeout', 'duration': duration}
        except Exception as e:
            logger.error(f"❌ Erreur attaque {attack_type}: {e}")
            return {'success': False, 'error': str(e), 'duration': 0}

    def check_detections(self, attack_type: str, pre_attack_time: str, 
                        post_attack_time: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Vérification des détections IDS/IPS
        
        Args:
            attack_type: Type d'attaque recherchée
            pre_attack_time: Timestamp pré-attaque
            post_attack_time: Timestamp post-attaque
            timeout: Timeout pour la vérification
        """
        logger.info(f"🔍 Vérification détections pour {attack_type}")
        
        detection_result = {
            'suricata_detections': 0,
            'snort_detections': 0,
            'total_detections': 0,
            'detection_details': [],
            'response_times': [],
            'false_positives': 0
        }
        
        # Attendre que les logs se stabilisent
        time.sleep(5)
        
        try:
            # Vérification Suricata
            suricata_detections = self._check_suricata_detections(
                attack_type, pre_attack_time, post_attack_time)
            detection_result['suricata_detections'] = len(suricata_detections)
            detection_result['detection_details'].extend(suricata_detections)
            
            # Vérification Snort
            snort_detections = self._check_snort_detections(
                attack_type, pre_attack_time, post_attack_time)
            detection_result['snort_detections'] = len(snort_detections)
            detection_result['detection_details'].extend(snort_detections)
            
            # Vérification Elasticsearch
            es_detections = self._check_elasticsearch_detections(
                attack_type, pre_attack_time, post_attack_time)
            detection_result['elasticsearch_detections'] = len(es_detections)
            
            detection_result['total_detections'] = (
                detection_result['suricata_detections'] +
                detection_result['snort_detections']
            )
            
            # Calcul temps de réponse moyen
            if detection_result['detection_details']:
                response_times = [d.get('response_time', 0) for d in detection_result['detection_details']]
                detection_result['avg_response_time'] = statistics.mean(response_times)
                detection_result['response_times'] = response_times
            else:
                detection_result['avg_response_time'] = 0
            
            logger.info(f"📊 Détections trouvées: {detection_result['total_detections']}")
            
        except Exception as e:
            logger.error(f"❌ Erreur vérification détections: {e}")
            detection_result['error'] = str(e)
        
        return detection_result

    def _check_suricata_detections(self, attack_type: str, start_time: str, 
                                  end_time: str) -> List[Dict[str, Any]]:
        """Vérification des détections Suricata"""
        detections = []
        
        if not Path(self.suricata_log_path).exists():
            logger.warning(f"⚠️ Fichier log Suricata non trouvé: {self.suricata_log_path}")
            return detections
        
        try:
            # Lecture des logs Suricata (format JSON)
            with open(self.suricata_log_path, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # Filtrage par timestamp
                        log_time = log_entry.get('timestamp', '')
                        if start_time <= log_time <= end_time:
                            # Vérification si c'est une alerte
                            if log_entry.get('event_type') == 'alert':
                                alert = log_entry.get('alert', {})
                                signature = alert.get('signature', '').lower()
                                
                                # Classification par type d'attaque
                                if self._is_relevant_detection(signature, attack_type):
                                    detection = {
                                        'source': 'suricata',
                                        'timestamp': log_time,
                                        'signature': signature,
                                        'severity': alert.get('severity', 0),
                                        'category': alert.get('category', ''),
                                        'src_ip': log_entry.get('src_ip', ''),
                                        'dest_ip': log_entry.get('dest_ip', ''),
                                        'src_port': log_entry.get('src_port', 0),
                                        'dest_port': log_entry.get('dest_port', 0),
                                        'proto': log_entry.get('proto', ''),
                                        'response_time': 1.0  # À calculer précisément
                                    }
                                    detections.append(detection)
                                    
                    except json.JSONDecodeError:
                        continue  # Ignorer les lignes malformées
                        
        except Exception as e:
            logger.error(f"❌ Erreur lecture logs Suricata: {e}")
        
        return detections

    def _check_snort_detections(self, attack_type: str, start_time: str, 
                               end_time: str) -> List[Dict[str, Any]]:
        """Vérification des détections Snort"""
        detections = []
        
        # Snort log peut être dans différents formats
        snort_log_files = [
            self.snort_log_path,
            '/var/log/snort/snort.log',
            '/var/log/snort/alert.fast'
        ]
        
        for log_file in snort_log_files:
            if Path(log_file).exists():
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Parsing basique des alertes Snort
                            if '[**]' in line and self._is_relevant_detection(line.lower(), attack_type):
                                detection = {
                                    'source': 'snort',
                                    'raw_line': line.strip(),
                                    'response_time': 1.0
                                }
                                detections.append(detection)
                                
                except Exception as e:
                    logger.debug(f"Erreur lecture {log_file}: {e}")
                break
        
        return detections

    def _check_elasticsearch_detections(self, attack_type: str, start_time: str,
                                      end_time: str) -> List[Dict[str, Any]]:
        """Vérification des détections dans Elasticsearch"""
        detections = []
        
        try:
            import requests
            
            # Requête Elasticsearch pour les alertes
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }},
                            {"exists": {"field": "alert"}}
                        ]
                    }
                },
                "size": 100
            }
            
            response = requests.post(
                f"{self.elasticsearch_url}/suricata-*/_search",
                json=query,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                
                for hit in hits:
                    source = hit.get('_source', {})
                    alert = source.get('alert', {})
                    signature = alert.get('signature', '').lower()
                    
                    if self._is_relevant_detection(signature, attack_type):
                        detection = {
                            'source': 'elasticsearch',
                            'timestamp': source.get('@timestamp', ''),
                            'signature': signature,
                            'src_ip': source.get('src_ip', ''),
                            'dest_ip': source.get('dest_ip', ''),
                            'response_time': 1.0
                        }
                        detections.append(detection)
                        
        except Exception as e:
            logger.debug(f"Erreur requête Elasticsearch: {e}")
        
        return detections

    def _is_relevant_detection(self, signature: str, attack_type: str) -> bool:
        """Vérification si une détection est pertinente pour le type d'attaque"""
        attack_keywords = {
            'port_scan': ['scan', 'port', 'reconnaissance', 'probe', 'nmap'],
            'brute_force': ['brute', 'login', 'auth', 'ssh', 'credential', 'password'],
            'web_attacks': ['sql', 'injection', 'xss', 'script', 'web', 'http', 'lfi'],
            'ddos': ['ddos', 'flood', 'dos', 'syn', 'amplification'],
            'data_exfiltration': ['exfil', 'transfer', 'upload', 'data', 'tunnel'],
            'lateral_movement': ['lateral', 'smb', 'rdp', 'wmi', 'movement', 'pivot']
        }
        
        keywords = attack_keywords.get(attack_type, [])
        return any(keyword in signature for keyword in keywords)

    def run_test_suite(self, suite_name: str) -> ValidationReport:
        """
        Exécution d'une suite de tests
        
        Args:
            suite_name: Nom de la suite (basic, comprehensive, performance)
        """
        logger.info(f"🧪 Exécution suite de tests: {suite_name}")
        
        self.running = True
        self.start_time = datetime.now()
        self.results = []
        
        test_suites = {
            'basic': [
                {'attack': 'port_scan', 'duration': 15},
                {'attack': 'brute_force', 'duration': 30, 'extra_args': ['--service', 'ssh']},
                {'attack': 'web_attacks', 'duration': 20}
            ],
            'comprehensive': [
                {'attack': 'port_scan', 'duration': 30},
                {'attack': 'brute_force', 'duration': 60, 'extra_args': ['--service', 'ssh']},
                {'attack': 'brute_force', 'duration': 45, 'extra_args': ['--service', 'http']},
                {'attack': 'web_attacks', 'duration': 45},
                {'attack': 'ddos', 'duration': 30, 'extra_args': ['--threads', '3']},
                {'attack': 'data_exfiltration', 'duration': 20},
                {'attack': 'lateral_movement', 'duration': 25}
            ],
            'performance': [
                {'attack': 'ddos', 'duration': 60, 'extra_args': ['--threads', '10']},
                {'attack': 'port_scan', 'duration': 45, 'extra_args': ['--rate-limit', '20']},
                {'scenario': 'full_attack_chain', 'duration': 120}
            ]
        }
        
        tests_to_run = test_suites.get(suite_name, test_suites['basic'])
        
        try:
            for i, test_config in enumerate(tests_to_run):
                if not self.running:
                    break
                
                logger.info(f"📋 Test {i+1}/{len(tests_to_run)}: {test_config}")
                
                # Sélection d'une cible
                target = self.test_targets[i % len(self.test_targets)]
                
                # Exécution du test
                test_result = self._execute_single_test(test_config, target, i+1)
                self.results.append(test_result)
                
                # Attente entre les tests
                if i < len(tests_to_run) - 1:
                    wait_time = self.config.get('wait_time_between_tests', 5)
                    logger.info(f"⏳ Attente {wait_time}s avant le prochain test...")
                    time.sleep(wait_time)
                    
        except KeyboardInterrupt:
            logger.info("⚠️ Suite de tests interrompue par l'utilisateur")
        except Exception as e:
            logger.error(f"❌ Erreur suite de tests: {e}")
        finally:
            self.running = False
            
        # Génération du rapport final
        return self._generate_validation_report(suite_name)

    def _execute_single_test(self, test_config: Dict[str, Any], target: str, 
                           test_number: int) -> TestResult:
        """Exécution d'un test individuel"""
        attack_type = test_config.get('attack', test_config.get('scenario'))
        duration = test_config.get('duration', 30)
        extra_args = test_config.get('extra_args', [])
        
        start_time = datetime.now()
        
        # Exécution de l'attaque
        attack_result = self.execute_attack_test(attack_type, target, duration, extra_args)
        
        # Vérification des détections
        detection_result = self.check_detections(
            attack_type, 
            attack_result.get('pre_attack_time', start_time.isoformat()),
            attack_result.get('post_attack_time', datetime.now().isoformat())
        )
        
        end_time = datetime.now()
        
        # Calcul des métriques
        attacks_sent = attack_result.get('attacks_sent', 0)
        detections_found = detection_result.get('total_detections', 0)
        expected_rate = self.config['expected_detection_rates'].get(attack_type, 0.8)
        expected_detections = max(1, int(attacks_sent * expected_rate)) if attacks_sent > 0 else 1
        
        detection_rate = detections_found / expected_detections if expected_detections > 0 else 0
        detection_rate = min(detection_rate, 1.0)  # Cap à 100%
        
        success = (
            attack_result.get('success', False) and 
            detection_rate >= 0.5  # Au moins 50% de détection requis
        )
        
        test_result = TestResult(
            test_name=f"Test_{test_number:02d}_{attack_type}",
            attack_type=attack_type,
            target=target,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration=(end_time - start_time).total_seconds(),
            attacks_sent=attacks_sent,
            detections_expected=expected_detections,
            detections_found=detections_found,
            false_positives=detection_result.get('false_positives', 0),
            detection_rate=detection_rate,
            response_time_avg=detection_result.get('avg_response_time', 0),
            success=success,
            details={
                'attack_result': attack_result,
                'detection_result': detection_result,
                'expected_rate': expected_rate
            }
        )
        
        status = "✅ RÉUSSI" if success else "❌ ÉCHEC"
        logger.info(f"{status} - {test_result.test_name}: {detection_rate:.1%} détections")
        
        return test_result

    def _generate_validation_report(self, suite_name: str) -> ValidationReport:
        """Génération du rapport de validation"""
        end_time = datetime.now()
        total_duration = (end_time - self.start_time).total_seconds()
        
        tests_passed = sum(1 for result in self.results if result.success)
        tests_failed = len(self.results) - tests_passed
        
        # Calcul des métriques globales
        all_detection_rates = [r.detection_rate for r in self.results if r.detection_rate > 0]
        overall_detection_rate = statistics.mean(all_detection_rates) if all_detection_rates else 0
        
        all_response_times = [r.response_time_avg for r in self.results if r.response_time_avg > 0]
        avg_response_time = statistics.mean(all_response_times) if all_response_times else 0
        
        # Métriques de performance
        performance_metrics = {
            'total_attacks_sent': sum(r.attacks_sent for r in self.results),
            'total_detections': sum(r.detections_found for r in self.results),
            'avg_detection_rate': overall_detection_rate,
            'min_detection_rate': min(all_detection_rates) if all_detection_rates else 0,
            'max_detection_rate': max(all_detection_rates) if all_detection_rates else 0,
            'avg_response_time': avg_response_time,
            'tests_per_minute': len(self.results) / (total_duration / 60) if total_duration > 0 else 0
        }
        
        # Génération des recommandations
        recommendations = self._generate_recommendations(performance_metrics)
        
        report = ValidationReport(
            test_suite=suite_name,
            start_time=self.start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_duration=total_duration,
            tests_executed=len(self.results),
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            overall_detection_rate=overall_detection_rate,
            avg_response_time=avg_response_time,
            performance_metrics=performance_metrics,
            recommendations=recommendations,
            test_results=self.results
        )
        
        return report

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Génération des recommandations"""
        recommendations = []
        
        detection_rate = metrics.get('avg_detection_rate', 0)
        if detection_rate < 0.7:
            recommendations.append(
                "🔧 Taux de détection faible (<70%). Réviser les règles Suricata/Snort."
            )
        elif detection_rate > 0.9:
            recommendations.append(
                "✅ Excellent taux de détection (>90%). Système bien configuré."
            )
        
        response_time = metrics.get('avg_response_time', 0)
        if response_time > 5.0:
            recommendations.append(
                "⚡ Temps de réponse élevé (>5s). Optimiser les performances IDS/IPS."
            )
        
        min_rate = metrics.get('min_detection_rate', 0)
        max_rate = metrics.get('max_detection_rate', 0)
        if max_rate - min_rate > 0.3:
            recommendations.append(
                "📊 Variabilité importante dans les détections. Homogénéiser les règles."
            )
        
        if metrics.get('tests_per_minute', 0) < 1:
            recommendations.append(
                "🚀 Performance des tests faible. Vérifier les ressources système."
            )
        
        if not recommendations:
            recommendations.append("🎯 Système IDS/IPS fonctionne correctement.")
        
        return recommendations

    def save_report(self, report: ValidationReport, output_file: str = None):
        """Sauvegarde du rapport"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ids_ips_validation_report_{timestamp}.json"
        
        # Conversion en dictionnaire pour sérialisation JSON
        report_dict = asdict(report)
        
        with open(output_file, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"💾 Rapport sauvegardé: {output_file}")
        
        # Génération d'un rapport HTML simple
        html_file = output_file.replace('.json', '.html')
        self._generate_html_report(report, html_file)

    def _generate_html_report(self, report: ValidationReport, html_file: str):
        """Génération d'un rapport HTML"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Validation IDS/IPS</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .metrics {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .metric {{ background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
        .success {{ background: #d5f4e6; }}
        .failure {{ background: #ffeaea; }}
        .recommendation {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Rapport de Validation IDS/IPS</h1>
        <p>Suite: {report.test_suite} | Durée: {report.total_duration:.1f}s | 
           Tests: {report.tests_executed} | Réussis: {report.tests_passed} | 
           Échecs: {report.tests_failed}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>Taux de Détection Global</h3>
            <h2>{report.overall_detection_rate:.1%}</h2>
        </div>
        <div class="metric">
            <h3>Temps de Réponse Moyen</h3>
            <h2>{report.avg_response_time:.1f}s</h2>
        </div>
        <div class="metric">
            <h3>Attaques Totales</h3>
            <h2>{report.performance_metrics['total_attacks_sent']}</h2>
        </div>
        <div class="metric">
            <h3>Détections Totales</h3>
            <h2>{report.performance_metrics['total_detections']}</h2>
        </div>
    </div>
    
    <h2>📋 Recommandations</h2>
    {''.join(f'<div class="recommendation">{rec}</div>' for rec in report.recommendations)}
    
    <h2>📊 Résultats Détaillés</h2>
    <table>
        <tr>
            <th>Test</th>
            <th>Type</th>
            <th>Cible</th>
            <th>Durée</th>
            <th>Attaques</th>
            <th>Détections</th>
            <th>Taux</th>
            <th>Statut</th>
        </tr>
        {''.join(f'''
        <tr class="{'success' if result.success else 'failure'}">
            <td>{result.test_name}</td>
            <td>{result.attack_type}</td>
            <td>{result.target}</td>
            <td>{result.duration:.1f}s</td>
            <td>{result.attacks_sent}</td>
            <td>{result.detections_found}</td>
            <td>{result.detection_rate:.1%}</td>
            <td>{'✅ Réussi' if result.success else '❌ Échec'}</td>
        </tr>
        ''' for result in report.test_results)}
    </table>
    
    <p><small>Rapport généré le {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
</body>
</html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"📄 Rapport HTML généré: {html_file}")

    def print_summary_report(self, report: ValidationReport):
        """Affichage du résumé du rapport"""
        print("\n" + "="*70)
        print("🛡️ RAPPORT DE VALIDATION IDS/IPS")
        print("="*70)
        print(f"Suite de tests: {report.test_suite}")
        print(f"Durée totale: {report.total_duration:.1f}s")
        print(f"Tests exécutés: {report.tests_executed}")
        print(f"Tests réussis: {report.tests_passed} ✅")
        print(f"Tests échoués: {report.tests_failed} ❌")
        print(f"Taux de réussite: {(report.tests_passed/report.tests_executed)*100:.1f}%")
        
        print("\n📊 MÉTRIQUES DE PERFORMANCE")
        print("-" * 40)
        print(f"Taux de détection global: {report.overall_detection_rate:.1%}")
        print(f"Temps de réponse moyen: {report.avg_response_time:.1f}s")
        print(f"Attaques totales envoyées: {report.performance_metrics['total_attacks_sent']}")
        print(f"Détections totales: {report.performance_metrics['total_detections']}")
        
        print("\n🔧 RECOMMANDATIONS")
        print("-" * 40)
        for recommendation in report.recommendations:
            print(f"• {recommendation}")
        
        print("\n📋 RÉSULTATS PAR TEST")
        print("-" * 40)
        for result in report.test_results:
            status = "✅" if result.success else "❌"
            print(f"{status} {result.test_name}: {result.detection_rate:.1%} "
                  f"({result.detections_found}/{result.detections_expected} détections)")
        
        print("\n" + "="*70)

def signal_handler(signum, frame):
    """Gestionnaire de signal pour arrêt propre"""
    logger.info("⚠️ Signal d'arrêt reçu...")
    sys.exit(0)

def main():
    # Gestion des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Script de validation automatisée IDS/IPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Suite de tests basique
  python3 validate-ids-ips.py --test-suite basic
  
  # Suite complète avec rapport détaillé
  python3 validate-ids-ips.py --test-suite comprehensive --output validation_report.json
  
  # Tests de performance
  python3 validate-ids-ips.py --test-suite performance --config my_config.json
  
  # Vérification prérequis seulement
  python3 validate-ids-ips.py --check-only
        """
    )
    
    parser.add_argument('--test-suite', choices=['basic', 'comprehensive', 'performance'],
                       default='basic', help='Suite de tests à exécuter')
    parser.add_argument('--config', help='Fichier de configuration JSON')
    parser.add_argument('--output', help='Fichier de sortie pour le rapport')
    parser.add_argument('--check-only', action='store_true', 
                       help='Vérifier les prérequis seulement')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialisation du validateur
    validator = IDSIPSValidator(args.config)
    
    try:
        # Vérification des prérequis
        if not validator.check_prerequisites():
            logger.error("❌ Prérequis non satisfaits. Arrêt du script.")
            return 1
        
        if args.check_only:
            logger.info("✅ Vérification des prérequis terminée.")
            return 0
        
        # Exécution de la suite de tests
        logger.info(f"🚀 Démarrage suite de tests: {args.test_suite}")
        report = validator.run_test_suite(args.test_suite)
        
        # Affichage du résumé
        validator.print_summary_report(report)
        
        # Sauvegarde du rapport
        validator.save_report(report, args.output)
        
        # Code de sortie basé sur les résultats
        success_rate = report.tests_passed / report.tests_executed if report.tests_executed > 0 else 0
        return 0 if success_rate >= 0.7 else 1  # 70% de réussite requis
        
    except KeyboardInterrupt:
        logger.info("⚠️ Validation interrompue par l'utilisateur")
        return 130
    except Exception as e:
        logger.error(f"❌ Erreur validation: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())