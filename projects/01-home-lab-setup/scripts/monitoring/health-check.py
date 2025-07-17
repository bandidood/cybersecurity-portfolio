#!/usr/bin/env python3
"""
health-check.py - Script de surveillance de l'état du laboratoire cybersécurité
Auteur: [Votre nom]
Date: 2025
Description: Vérifie l'état des ressources système, VMs, réseau et services
"""

import subprocess
import socket
import psutil
import json
import os
import sys
from datetime import datetime
from pathlib import Path

class LabHealthChecker:
    """Classe principale pour la surveillance du laboratoire"""
    
    def __init__(self):
        self.report = {}
        self.timestamp = datetime.now().isoformat()
        self.lab_dir = Path.home() / "lab"
        self.issues_count = 0
        
        # Configuration des seuils d'alerte
        self.thresholds = {
            'cpu': 80,      # % CPU
            'memory': 80,   # % RAM  
            'disk': 90,     # % Disque
        }
        
        # VMs critiques qui doivent être en marche
        self.critical_vms = {
            'pfSense': 'pfSense-Firewall',
            'DC': 'DC-Server'
        }
        
        # Services à surveiller
        self.services = {
            'ELK_Elasticsearch': ('172.16.2.10', 9200),
            'ELK_Kibana': ('172.16.2.10', 5601),
            'DVWA_Web': ('172.16.1.10', 80),
            'pfSense_Web': ('192.168.100.1', 443)
        }
        
        # Targets réseau
        self.network_targets = {
            'pfSense_LAN': '192.168.100.1',
            'DC_Server': '192.168.100.10',
            'SIEM_Server': '172.16.2.10',
            'DMZ_Web': '172.16.1.10'
        }

    def print_header(self):
        """Affiche l'en-tête du script"""
        print("🔍" + "="*60)
        print("  HEALTH CHECK - LABORATOIRE CYBERSÉCURITÉ")
        print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*62)

    def check_system_resources(self):
        """Vérification des ressources système"""
        print("\n🖥️ Vérification des ressources système...")
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available_gb = round(memory.available / (1024**3), 1)
            
            # Disk
            disk = psutil.disk_usage(str(self.lab_dir))
            disk_percent = round((disk.used / disk.total) * 100, 1)
            disk_available_gb = round(disk.free / (1024**3), 1)
            
            # Stockage des métriques
            self.report['system'] = {
                'cpu_usage': cpu_percent,
                'memory_usage': memory_percent,
                'memory_available_gb': memory_available_gb,
                'disk_usage': disk_percent,
                'disk_available_gb': disk_available_gb,
                'status': 'healthy'
            }
            
            # Vérification des seuils
            alerts = []
            if cpu_percent > self.thresholds['cpu']:
                alerts.append(f"CPU élevé: {cpu_percent}%")
                self.issues_count += 1
            
            if memory_percent > self.thresholds['memory']:
                alerts.append(f"Mémoire élevée: {memory_percent}%")
                self.issues_count += 1
                
            if disk_percent > self.thresholds['disk']:
                alerts.append(f"Disque plein: {disk_percent}%")
                self.issues_count += 1
            
            if alerts:
                self.report['system']['status'] = 'warning'
                self.report['system']['alerts'] = alerts
                for alert in alerts:
                    print(f"  ⚠️ {alert}")
            
            # Affichage des métriques
            status_icon = "✅" if not alerts else "⚠️"
            print(f"  {status_icon} CPU: {cpu_percent}% | RAM: {memory_percent}% ({memory_available_gb}GB libre)")
            print(f"     Disque: {disk_percent}% ({disk_available_gb}GB libre)")
            
        except Exception as e:
            self.report['system'] = {'error': str(e), 'status': 'error'}
            print(f"  ❌ Erreur système: {e}")
            self.issues_count += 1

    def check_vm_status(self):
        """Vérification de l'état des VMs"""
        print("\n🖥️ Vérification de l'état des VMs...")
        
        # Liste des VMs à surveiller
        all_vms = {
            'pfSense': 'pfSense-Firewall',
            'Kali': 'Kali-Attacker', 
            'DC': 'DC-Server',
            'SIEM': 'Ubuntu-SIEM',
            'DVWA': 'DVWA-Target'
        }
        
        self.report['vms'] = {}
        
        try:
            # Récupération de la liste des VMs actives
            result = subprocess.run(['vmrun', 'list'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                raise Exception("Impossible d'accéder à VMware")
                
            running_vms = result.stdout
            
            # Vérification de chaque VM
            for vm_name, vm_displayname in all_vms.items():
                is_running = vm_displayname in running_vms
                is_critical = vm_name in self.critical_vms
                
                vm_status = {
                    'status': 'running' if is_running else 'stopped',
                    'critical': is_critical,
                    'displayname': vm_displayname
                }
                
                self.report['vms'][vm_name] = vm_status
                
                # Affichage et comptage des problèmes
                if is_running:
                    icon = "✅"
                    status_text = "En cours"
                elif is_critical:
                    icon = "❌"
                    status_text = "ARRÊTÉE (CRITIQUE)"
                    self.issues_count += 1
                else:
                    icon = "⚠️"
                    status_text = "Arrêtée"
                
                print(f"  {icon} {vm_name}: {status_text}")
            
            # Résumé
            running_count = sum(1 for vm in self.report['vms'].values() if vm['status'] == 'running')
            total_count = len(all_vms)
            print(f"\n  📊 VMs actives: {running_count}/{total_count}")
                    
        except Exception as e:
            self.report['vms'] = {'error': str(e)}
            print(f"  ❌ Erreur VMs: {e}")
            self.issues_count += 1

    def check_network_connectivity(self):
        """Test de connectivité réseau"""
        print("\n🌐 Test de connectivité réseau...")
        
        self.report['network'] = {}
        reachable_count = 0
        
        for name, ip in self.network_targets.items():
            try:
                # Test ping avec timeout
                result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                      capture_output=True, timeout=5)
                
                is_reachable = result.returncode == 0
                
                self.report['network'][name] = {
                    'ip': ip,
                    'status': 'reachable' if is_reachable else 'unreachable',
                    'critical': name in ['pfSense_LAN', 'DC_Server']
                }
                
                if is_reachable:
                    print(f"  ✅ {name} ({ip}): Accessible")
                    reachable_count += 1
                else:
                    icon = "❌" if self.report['network'][name]['critical'] else "⚠️"
                    print(f"  {icon} {name} ({ip}): Inaccessible")
                    if self.report['network'][name]['critical']:
                        self.issues_count += 1
                        
            except Exception as e:
                self.report['network'][name] = {
                    'ip': ip,
                    'status': f'error: {str(e)}',
                    'critical': name in ['pfSense_LAN', 'DC_Server']
                }
                print(f"  ❌ {name} ({ip}): Erreur - {e}")
                if self.report['network'][name]['critical']:
                    self.issues_count += 1
        
        # Résumé
        total_targets = len(self.network_targets)
        print(f"\n  📊 Connectivité: {reachable_count}/{total_targets} cibles accessibles")

    def check_services(self):
        """Vérification des services critiques"""
        print("\n🔧 Vérification des services...")
        
        self.report['services'] = {}
        available_count = 0
        
        for service, (host, port) in self.services.items():
            try:
                # Test de connexion socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                is_available = result == 0
                
                self.report['services'][service] = {
                    'host': host,
                    'port': port,
                    'status': 'available' if is_available else 'unavailable'
                }
                
                if is_available:
                    print(f"  ✅ {service}: Disponible ({host}:{port})")
                    available_count += 1
                else:
                    print(f"  ⚠️ {service}: Indisponible ({host}:{port})")
                    
            except Exception as e:
                self.report['services'][service] = {
                    'host': host,
                    'port': port,
                    'status': f'error: {str(e)}'
                }
                print(f"  ❌ {service}: Erreur - {e}")
        
        # Résumé
        total_services = len(self.services)
        print(f"\n  📊 Services: {available_count}/{total_services} disponibles")

    def generate_report(self):
        """Génération du rapport final"""
        print("\n📄 Génération du rapport...")
        
        # Métadonnées du rapport
        self.report['metadata'] = {
            'timestamp': self.timestamp,
            'lab_version': '1.0',
            'total_issues': self.issues_count,
            'overall_status': 'healthy' if self.issues_count == 0 else 'issues_detected'
        }
        
        # Sauvegarde JSON
        timestamp_str = datetime.now().strftime('%Y%m%d-%H%M%S')
        report_file = self.lab_dir / 'logs' / f'health-check-{timestamp_str}.json'
        
        # Création du répertoire si nécessaire
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=2, ensure_ascii=False)
            
            print(f"  ✅ Rapport sauvegardé: {report_file}")
            
        except Exception as e:
            print(f"  ❌ Erreur sauvegarde: {e}")

    def print_summary(self):
        """Affichage du résumé final"""
        print("\n" + "="*62)
        print("📊 RÉSUMÉ HEALTH CHECK")
        print("="*62)
        
        # État général
        if self.issues_count == 0:
            status_icon = "🟢"
            status_text = "LABORATOIRE EN BON ÉTAT"
        elif self.issues_count <= 2:
            status_icon = "🟡"
            status_text = "PROBLÈMES MINEURS DÉTECTÉS"
        else:
            status_icon = "🔴"
            status_text = "PROBLÈMES CRITIQUES DÉTECTÉS"
        
        print(f"{status_icon} {status_text}")
        print(f"   Issues détectées: {self.issues_count}")
        
        # Détails par catégorie
        if 'vms' in self.report:
            running_vms = sum(1 for vm in self.report['vms'].values() 
                            if isinstance(vm, dict) and vm.get('status') == 'running')
            total_vms = len([vm for vm in self.report['vms'].values() if isinstance(vm, dict)])
            print(f"   VMs actives: {running_vms}/{total_vms}")
        
        if 'services' in self.report:
            available_services = sum(1 for svc in self.report['services'].values() 
                                   if isinstance(svc, dict) and svc.get('status') == 'available')
            total_services = len([svc for svc in self.report['services'].values() if isinstance(svc, dict)])
            print(f"   Services disponibles: {available_services}/{total_services}")
        
        if 'network' in self.report:
            reachable_targets = sum(1 for net in self.report['network'].values() 
                                  if isinstance(net, dict) and net.get('status') == 'reachable')
            total_targets = len([net for net in self.report['network'].values() if isinstance(net, dict)])
            print(f"   Connectivité réseau: {reachable_targets}/{total_targets}")
        
        print("\n✅ Health Check terminé !")
        
        # Recommandations si problèmes détectés
        if self.issues_count > 0:
            print("\n🔧 ACTIONS RECOMMANDÉES:")
            if self.issues_count >= 3:
                print("   • Vérifier les ressources système")
                print("   • Redémarrer les VMs critiques")
                print("   • Consulter les logs d'erreur")
            print("   • Exécuter: vmrun list")
            print("   • Vérifier la configuration réseau")

    def run_full_check(self):
        """Exécution du check complet"""
        self.print_header()
        
        try:
            self.check_system_resources()
            self.check_vm_status()
            self.check_network_connectivity()
            self.check_services()
            self.generate_report()
            self.print_summary()
            
        except KeyboardInterrupt:
            print("\n⚠️ Health Check interrompu par l'utilisateur")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Erreur fatale: {e}")
            sys.exit(1)

def main():
    """Fonction principale"""
    try:
        checker = LabHealthChecker()
        checker.run_full_check()
        
        # Code de sortie basé sur le nombre d'issues
        sys.exit(0 if checker.issues_count == 0 else 1)
        
    except Exception as e:
        print(f"❌ Erreur d'initialisation: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
