# 🏠 Projet 01 : Laboratoire de Cybersécurité à Domicile

## 🎯 Objectifs Pédagogiques
- Construire un environnement de test sécurisé et isolé
- Maîtriser la virtualisation pour la cybersécurité
- Implémenter une architecture réseau segmentée
- Configurer des outils de monitoring et de détection
- Créer un environnement reproductible et documenté

## 📌 Contexte Professionnel
Dans le domaine de la cybersécurité, disposer d'un laboratoire personnel est essentiel pour :
- **Formation continue** : Tester nouvelles techniques et outils
- **Recherche** : Analyser malwares et vulnérabilités en sécurité
- **Développement** : Créer et valider des solutions de sécurité
- **Certification** : Préparer OSCP, CEH, CISSP
- **Démonstration** : Présenter compétences techniques aux employeurs

## ✅ Prérequis

### 💻 Matériel Recommandé
- **CPU** : Intel i5/i7 ou AMD Ryzen 5/7 (support virtualisation)
- **RAM** : 16 GB minimum (32 GB recommandé)
- **Stockage** : 500 GB SSD disponible
- **Réseau** : Connexion stable pour téléchargements

### 🧠 Compétences Nécessaires
- Bases de l'administration système (Windows/Linux)
- Concepts réseaux (TCP/IP, VLAN, routage)
- Utilisation basique de la ligne de commande
- Notions de virtualisation

### 🛠️ Outils Requis
- **Hyperviseur** : VMware Workstation Pro, VirtualBox, ou Hyper-V
- **Images ISO** : 
  - Kali Linux (pentest)
  - Ubuntu Server (services)
  - Windows Server 2019/2022 (AD)
  - pfSense (pare-feu)
  - DVWA, Metasploitable (cibles)

## 🏗️ Architecture du Laboratoire

### 📊 Topologie Réseau
```
Internet
    |
[Router Physique] (192.168.1.1/24)
    |
[pfSense VM] (Gateway)
    |
├── DMZ (172.16.1.0/24)
│   ├── Web Server (172.16.1.10)
│   └── Mail Server (172.16.1.20)
│
├── LAN Interne (192.168.100.0/24)
│   ├── Domain Controller (192.168.100.10)
│   ├── File Server (192.168.100.20)
│   └── Workstations (192.168.100.50-99)
│
├── Red Team Network (10.0.0.0/24)
│   ├── Kali Linux (10.0.0.10)
│   ├── Cobalt Strike (10.0.0.20)
│   └── C2 Server (10.0.0.30)
│
└── Blue Team Network (172.16.2.0/24)
    ├── SIEM (172.16.2.10)
    ├── IDS/IPS (172.16.2.20)
    └── SOC Tools (172.16.2.30)
```

## 🛠️ Plan d'Action Structuré

### Phase 1 : Préparation (Semaine 1)
1. **Installation hyperviseur** et configuration réseau
2. **Téléchargement ISOs** et création structure
3. **Tests initialisation** environnement

### Phase 2 : Infrastructure (Semaine 2)  
4. **Déploiement pfSense** et segmentation réseau
5. **Installation Active Directory** et services Windows
6. **Configuration monitoring** ELK Stack

### Phase 3 : Sécurité (Semaine 3)
7. **Déploiement Kali Linux** et outils pentest
8. **Installation DVWA/Metasploitable** (cibles)
9. **Configuration IDS/IPS** et détection

### Phase 4 : Validation (Semaine 4)
10. **Tests connectivité** et isolation
11. **Validation sécurité** et performance
12. **Documentation finale** et présentation

## 💻 Scripts d'Automatisation

### 🚀 Script de Déploiement Principal
```bash
#!/bin/bash
# deploy-lab.sh

set -e

echo "🏗️ Déploiement du laboratoire cybersécurité..."

# Vérification prérequis
check_requirements() {
    echo "🔍 Vérification des prérequis..."
    
    if ! command -v vmrun &> /dev/null; then
        echo "❌ VMware Workstation non détecté"
        exit 1
    fi
    
    AVAILABLE_SPACE=$(df -h ~ | awk 'NR==2{print $4}' | sed 's/G//')
    if [ $AVAILABLE_SPACE -lt 500 ]; then
        echo "❌ Espace disque insuffisant (500GB requis)"
        exit 1
    fi
    
    echo "✅ Prérequis validés"
}

# Création structure
create_structure() {
    echo "📁 Création de la structure..."
    mkdir -p ~/lab/{vms,isos,configs,scripts,evidence}
    echo "✅ Structure créée"
}

# Téléchargement ISOs
download_isos() {
    echo "⬇️ Téléchargement des images ISO..."
    cd ~/lab/isos
    
    if [ ! -f "kali-linux.iso" ]; then
        wget -O kali-linux.iso "https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso"
    fi
    
    if [ ! -f "ubuntu-server.iso" ]; then
        wget -O ubuntu-server.iso "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso"
    fi
    
    echo "✅ ISOs téléchargés"
}

# Exécution principale
main() {
    check_requirements
    create_structure
    download_isos
    
    echo "🎉 Laboratoire déployé avec succès !"
    echo "📋 Prochaines étapes :"
    echo "1. Configurer pfSense via interface web"
    echo "2. Installer Active Directory"
    echo "3. Déployer ELK Stack"
    echo "4. Configurer Kali Linux"
    echo "5. Lancer tests de validation"
}

main "$@"
```

### 🔧 Script de Monitoring
```python
#!/usr/bin/env python3
# health-check.py

import subprocess
import socket
import psutil
from datetime import datetime

class LabHealthChecker:
    def __init__(self):
        self.report = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def check_system_resources(self):
        """Vérification ressources système"""
        print("🖥️ Vérification ressources système...")
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        self.report.append(f"CPU Usage: {cpu_percent}%")
        self.report.append(f"RAM Usage: {memory.percent}%")
        self.report.append(f"Disk Usage: {(disk.used/disk.total)*100:.1f}%")
        
        print("✅ Ressources système vérifiées")
    
    def check_vm_status(self):
        """Vérification état des VMs"""
        print("🖥️ Vérification état des VMs...")
        
        vms = ["pfSense", "Kali-Attacker", "DC-Server", "Ubuntu-SIEM", "DVWA-Target"]
        
        for vm in vms:
            try:
                result = subprocess.run(["vmrun", "list"], capture_output=True, text=True)
                if vm in result.stdout:
                    self.report.append(f"VM {vm}: ✅ Running")
                else:
                    self.report.append(f"VM {vm}: ❌ Stopped")
            except Exception as e:
                self.report.append(f"VM {vm}: ❌ Error - {e}")
        
        print("✅ État des VMs vérifié")
    
    def check_network_connectivity(self):
        """Test connectivité réseau"""
        print("🌐 Test connectivité réseau...")
        
        targets = {
            "pfSense LAN": "192.168.100.1",
            "Domain Controller": "192.168.100.10", 
            "SIEM Server": "172.16.2.10",
            "DMZ Web": "172.16.1.10"
        }
        
        for name, ip in targets.items():
            try:
                result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    self.report.append(f"Network {name} ({ip}): ✅ Reachable")
                else:
                    self.report.append(f"Network {name} ({ip}): ❌ Unreachable")
            except Exception as e:
                self.report.append(f"Network {name} ({ip}): ❌ Error - {e}")
        
        print("✅ Connectivité réseau testée")
    
    def generate_report(self):
        """Génération rapport final"""
        print("\n" + "="*50)
        print(f"🔍 RAPPORT HEALTH CHECK - {self.timestamp}")
        print("="*50)
        
        for item in self.report:
            print(item)
        
        # Sauvegarde rapport
        filename = f"health-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(f"Health Check Report - {self.timestamp}\n")
            f.write("="*50 + "\n")
            for item in self.report:
                f.write(item + "\n")
        
        print(f"\n✅ Rapport sauvegardé: {filename}")
    
    def run_full_check(self):
        """Exécution check complet"""
        print("🚀 Démarrage Health Check complet...\n")
        
        self.check_system_resources()
        self.check_vm_status()
        self.check_network_connectivity()
        self.generate_report()
        
        print("\n🎉 Health Check terminé !")

if __name__ == "__main__":
    checker = LabHealthChecker()
    checker.run_full_check()
```

## 🔐 Analyse des Risques & Contre-mesures

### ⚠️ Risques Identifiés

| Risque | Impact | Probabilité | Contre-mesure |
|--------|--------|-------------|---------------|
| **Exposition accidentelle sur Internet** | Critique | Faible | Isolation réseau, pas de port forwarding |
| **Malware échappant de la VM** | Élevé | Faible | Snapshots, réseau isolé, antivirus host |
| **Fuite de données de test** | Moyen | Moyen | Données anonymisées uniquement |
| **Surcharge ressources système** | Faible | Élevé | Monitoring, allocation dynamique |
| **Accès non autorisé au lab** | Moyen | Faible | Chiffrement VMs, mots de passe forts |

### 🛡️ Mesures de Sécurité Implémentées

#### 1. Isolation Réseau
```bash
# Configuration pfSense - Règles strictes
# Bloquer tout trafic par défaut
# DMZ isolée du LAN
# Red Team isolé du Blue Team
# Logs de toutes les connexions
```

#### 2. Chiffrement et Authentification
```bash
# Chiffrement des VMs
vmware-vdiskmanager -e -k "AES-256" virtual-disk.vmdk

# Mots de passe complexes
# Admin: 16+ caractères, spéciaux
# Services: Clés SSH, certificats
```

#### 3. Sauvegarde et Récupération
```bash
#!/bin/bash
# backup-lab.sh

BACKUP_DIR="/backup/lab-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Snapshot des VMs critiques
vmrun snapshot ~/lab/vms/pfSense.vmx "backup-$(date +%Y%m%d)"
vmrun snapshot ~/lab/vms/DC-Server.vmx "backup-$(date +%Y%m%d)"

# Sauvegarde configurations
cp -r ~/lab/configs "$BACKUP_DIR/"
cp -r ~/lab/scripts "$BACKUP_DIR/"

echo "✅ Sauvegarde terminée: $BACKUP_DIR"
```

## ✅ Bonnes Pratiques Professionnelles

### 🎯 Standards de Documentation
- **Nomenclature** : Convention de nommage claire (VM-Role-Version)
- **Versioning** : Git pour scripts et configurations
- **Changelog** : Traçabilité des modifications
- **Architecture** : Diagrammes à jour

### 🔒 Sécurité Opérationnelle
- **Principle of Least Privilege** sur tous les comptes
- **Network Segmentation** stricte entre environnements
- **Regular Patching** des systèmes et outils
- **Incident Response** : procédures documentées

### 📈 Performance et Optimisation
```bash
# Optimisation VMware
# Allocation RAM dynamique
# Disques SSD pour VMs critiques
# CPU affinity pour isolation

# Monitoring proactif
# Alertes ressources > 80%
# Health checks automatisés
# Métriques performance
```

### 🎓 Formation Continue
- **Documentation** : Wiki interne avec procédures
- **Labs Scenarios** : Exercices pratiques réguliers
- **Knowledge Sharing** : Sessions techniques équipe
- **Veille Technologique** : Suivi nouvelles menaces

## 📂 Structure Git Recommandée

```
01-home-lab-setup/
├── README.md                    # Documentation principale
├── CHANGELOG.md                 # Historique modifications
├── docs/
│   ├── architecture.md          # Architecture détaillée
│   ├── network-diagram.png      # Schéma réseau
│   ├── vm-specifications.md     # Specs des VMs
│   ├── troubleshooting.md       # Guide dépannage
│   └── security-hardening.md    # Durcissement sécurité
├── scripts/
│   ├── setup/
│   │   ├── deploy-lab.sh        # Déploiement automatique
│   │   ├── configure-network.sh # Configuration réseau
│   │   ├── install-tools.sh     # Installation outils
│   │   └── create-vms.sh        # Création VMs
│   ├── monitoring/
│   │   ├── health-check.py      # Vérification santé
│   │   ├── resource-monitor.sh  # Monitoring ressources
│   │   └── network-test.py      # Tests réseau
│   └── maintenance/
│       ├── backup-lab.sh        # Sauvegarde
│       ├── cleanup.sh           # Nettoyage
│       └── update-systems.sh    # Mises à jour
├── configs/
│   ├── pfsense/
│   │   ├── firewall-rules.xml   # Règles pare-feu
│   │   └── vpn-config.xml       # Configuration VPN
│   ├── elk/
│   │   ├── elasticsearch.yml    # Config Elasticsearch
│   │   ├── logstash.conf        # Config Logstash
│   │   └── kibana.yml           # Config Kibana
│   ├── windows/
│   │   ├── gpo-settings.xml     # Politiques de groupe
│   │   └── ad-schema.ldif       # Schéma Active Directory
│   └── kali/
│       ├── tools-list.txt       # Liste outils installés
│       └── custom-aliases.sh    # Aliases personnalisés
├── evidence/
│   ├── screenshots/
│   │   ├── pfsense-dashboard.png
│   │   ├── kibana-dashboard.png
│   │   └── network-topology.png
│   ├── logs/
│   │   ├── health-checks/       # Logs surveillance
│   │   └── deployment/          # Logs déploiement
│   └── reports/
│       ├── performance-analysis.pdf
│       ├── security-assessment.pdf
│       └── lessons-learned.md
├── tests/
│   ├── unit-tests/
│   │   └── test-scripts.py      # Tests unitaires scripts
│   ├── integration-tests/
│   │   └── test-connectivity.sh # Tests intégration
│   └── security-tests/
│       └── vulnerability-scan.py # Tests sécurité
└── presentations/
    ├── lab-overview.pptx        # Présentation générale
    ├── technical-details.pdf    # Détails techniques
    └── demo-scenarios.md        # Scénarios de démonstration
```

## 📜 Références

### 📚 Documentation Officielle
- **VMware Workstation** : [Documentation VMware](https://docs.vmware.com/en/VMware-Workstation-Pro/)
- **pfSense** : [pfSense Documentation](https://docs.netgate.com/pfsense/)
- **Kali Linux** : [Kali Documentation](https://www.kali.org/docs/)
- **ELK Stack** : [Elastic Documentation](https://www.elastic.co/guide/)

### 🔒 Standards de Sécurité
- **NIST Cybersecurity Framework** : [NIST CSF](https://www.nist.gov/cyberframework)
- **ISO 27001** : Management de la sécurité de l'information
- **CIS Controls** : [Center for Internet Security](https://www.cisecurity.org/controls/)
- **OWASP** : [OWASP Guidelines](https://owasp.org/)

### 🎓 Ressources d'Apprentissage
- **SANS Institute** : [SANS Training](https://www.sans.org/)
- **Cybrary** : [Free Cybersecurity Training](https://www.cybrary.it/)
- **VulnHub** : [Vulnerable VMs](https://www.vulnhub.com/)
- **TryHackMe** : [Hands-on Learning](https://tryhackme.com/)

---

## 🎯 Livrables du Projet

### ✅ Checklist de Validation
- [ ] Infrastructure déployée et fonctionnelle
- [ ] Tous les réseaux configurés et isolés
- [ ] VMs opérationnelles avec services
- [ ] Monitoring et alerting actifs
- [ ] Documentation complète rédigée
- [ ] Scripts testés et validés
- [ ] Sauvegardes configurées
- [ ] Tests de sécurité réalisés
- [ ] Présentation technique préparée
- [ ] Repository Git organisé et poussé

### 📊 Métriques de Succès
- **Temps de déploiement** : < 4 heures (automatisé)
- **Disponibilité** : 99.5% uptime
- **Performance** : < 2s réponse services web
- **Sécurité** : 0 vulnérabilité critique détectée
- **Documentation** : 100% procédures couvertes

### 🏆 Compétences Démontrées
- Architecture réseau sécurisée
- Virtualisation et isolation
- Scripting et automatisation
- Monitoring et supervision
- Documentation technique
- Gestion de projet cybersécurité

---

**📞 Support** : En cas de problème, consulter le guide de dépannage ou créer une issue sur le repository GitHub.

**🔄 Mise à jour** : Ce laboratoire évolue régulièrement. Vérifier les mises à jour dans CHANGELOG.md.