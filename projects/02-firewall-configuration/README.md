# 🔥 Projet 02 : Configuration Pare-feu Enterprise

## 🎯 Objectifs Pédagogiques
- Configurer un pare-feu de niveau entreprise avec règles avancées
- Implémenter des politiques de sécurité granulaires
- Mettre en place la supervision et l'alerting
- Optimiser les performances réseau avec QoS
- Documenter et auditer les configurations de sécurité

## 📌 Contexte Professionnel
Ce projet simule la configuration d'un pare-feu d'entreprise pour une organisation moyenne avec :
- **Segmentation réseau** : Séparation stricte des environnements
- **Conformité** : Respect des standards PCI-DSS, SOX, RGPD
- **Performance** : Maintien de la productivité avec sécurité renforcée
- **Audit** : Traçabilité complète pour les audits de sécurité

## ✅ Prérequis

### 🧠 Compétences Techniques
- Administration réseau avancée (VLAN, routage, NAT)
- Concepts de sécurité réseau (ACL, VPN, IDS/IPS)
- Scripting bash/Python pour automatisation
- Connaissance des protocoles (TCP/IP, HTTPS, SSH)

### 🛠️ Infrastructure Requise
- Laboratoire de cybersécurité opérationnel (Projet 01)
- pfSense ou équivalent (FortiGate, Cisco ASA)
- Outils de monitoring (PRTG, Nagios, ou custom)
- Machines de test dans différents segments

### 📋 Standards de Référence
- **NIST SP 800-53** : Contrôles de sécurité
- **CIS Controls** : Bonnes pratiques de configuration
- **ISO 27001** : Management de la sécurité
- **OWASP** : Sécurité des applications web

## 🏗️ Architecture Cible

### 📊 Segmentation Réseau Enterprise
```
Internet (WAN)
    |
[Pare-feu Principal] - DMZ Public (172.16.10.0/24)
    |                     ├── Web Server Public
    |                     ├── Mail Server
    |                     └── DNS Public
    |
├── LAN Management (10.1.0.0/24)
│   ├── Domain Controllers
│   ├── DHCP/DNS Servers
│   └── Management Tools
│
├── LAN Users (10.2.0.0/24)
│   ├── Workstations
│   ├── Shared Resources
│   └── Print Servers
│
├── LAN Servers (10.3.0.0/24)
│   ├── Application Servers
│   ├── Database Servers
│   └── File Servers
│
├── DMZ Internal (172.16.20.0/24)
│   ├── Web Apps Internal
│   ├── API Gateways
│   └── Development Tools
│
├── Security Zone (10.10.0.0/24)
│   ├── SIEM Platform
│   ├── Vulnerability Scanners
│   ├── Backup Systems
│   └── Log Collectors
│
└── Guest Network (192.168.200.0/24)
    ├── Visitor Access
    ├── BYOD Devices
    └── IoT Devices
```

## 🛠️ Plan d'Action Détaillé

### Phase 1 : Planification et Design (Semaine 1)

#### Étape 1.1 : Analyse des Besoins
```bash
# Audit de l'existant
nmap -sn 192.168.100.0/24  # Découverte réseau actuel
nmap -sS -O 192.168.100.1  # Fingerprinting pare-feu

# Documentation des flux
netstat -rn  # Table de routage
ss -tulpn    # Ports ouverts
```

#### Étape 1.2 : Définition des Politiques
- **Principe du moindre privilège** : Accès minimum nécessaire
- **Segmentation par fonction** : Isolation des environnements
- **Contrôle applicatif** : Inspection deep packet
- **Logging exhaustif** : Traçabilité complète

#### Étape 1.3 : Matrice de Flux Autorisés
| Source | Destination | Ports | Protocole | Justification |
|--------|-------------|-------|-----------|---------------|
| LAN Users | Internet | 80,443 | TCP | Navigation web |
| LAN Users | LAN Servers | 443,3389 | TCP | Accès applications |
| DMZ Internal | LAN Servers | 1433,3306 | TCP | Base de données |
| Management | ALL | 22,3389,443 | TCP | Administration |
| Security Zone | ALL | 514,161 | UDP | Monitoring |

### Phase 2 : Configuration de Base (Semaine 2)

#### Étape 2.1 : Interfaces et VLANs
```bash
# Configuration des interfaces (pfSense CLI)
/interface vlan add name=vlan-users vlan-id=10 interface=ether2
/interface vlan add name=vlan-servers vlan-id=20 interface=ether2
/interface vlan add name=vlan-dmz vlan-id=30 interface=ether3
/interface vlan add name=vlan-mgmt vlan-id=100 interface=ether4

# Attribution des adresses IP
/ip address add address=10.2.0.1/24 interface=vlan-users
/ip address add address=10.3.0.1/24 interface=vlan-servers
/ip address add address=172.16.20.1/24 interface=vlan-dmz
/ip address add address=10.1.0.1/24 interface=vlan-mgmt
```

#### Étape 2.2 : Règles de Base
```bash
# Règles par défaut (pfSense)
# DENY ALL puis ALLOW spécifique

# 1. Bloquer tout par défaut
pass quick on $wan_if inet proto tcp from any to ($wan_if) port ssh
block all

# 2. Autoriser management depuis réseau admin
pass in on $lan_mgmt inet proto tcp from $lan_mgmt:network to any port { ssh https }

# 3. Autoriser utilisateurs vers Internet (web)
pass in on $lan_users inet proto tcp from $lan_users:network to any port { http https }

# 4. Autoriser accès contrôlé vers serveurs
pass in on $lan_users inet proto tcp from $lan_users:network to $lan_servers:network port https
```

### Phase 3 : Sécurité Avancée (Semaine 3)

#### Étape 3.1 : Inspection Deep Packet
```bash
# Configuration IDS/IPS intégré
# Suricata avec règles personnalisées

# Activation de l'inspection SSL
set security utm feature-profile web-filtering juniper-enhanced
set security utm feature-profile anti-virus juniper-express-engine

# Règles personnalisées pour détection d'intrusion
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible data exfiltration"; \
    content:"confidential"; nocase; threshold:type limit, count 5, seconds 60; \
    classtype:policy-violation; sid:1000001;)
```

#### Étape 3.2 : Contrôle Applicatif
```bash
# Application Control (pfSense + Suricata)
# Blocage d'applications non autorisées

# Règle pour bloquer P2P
block in quick proto tcp from any to any port { 6881:6999 4662 }

# Contrôle des réseaux sociaux (heures de bureau)
# Utilisation de pfBlockerNG avec listes de domaines
```

### Phase 4 : Monitoring et Optimisation (Semaine 4)

#### Étape 4.1 : Configuration SIEM
```python
#!/usr/bin/env python3
# siem-log-parser.py - Analyse des logs pare-feu

import re
import json
from datetime import datetime
from collections import defaultdict

class FirewallLogAnalyzer:
    def __init__(self):
        self.blocked_ips = defaultdict(int)
        self.top_rules = defaultdict(int)
        self.alerts = []
    
    def parse_pfsense_log(self, log_line):
        """Parse une ligne de log pfSense"""
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*rule (\d+).*: (\w+) (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)'
        match = re.search(pattern, log_line)
        
        if match:
            timestamp, rule_id, action, src_ip, src_port, dst_ip, dst_port = match.groups()
            return {
                'timestamp': timestamp,
                'rule_id': rule_id,
                'action': action,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port
            }
        return None
    
    def analyze_threats(self, logs):
        """Analyse des menaces dans les logs"""
        for log_entry in logs:
            parsed = self.parse_pfsense_log(log_entry)
            if parsed and parsed['action'] == 'block':
                self.blocked_ips[parsed['src_ip']] += 1
                self.top_rules[parsed['rule_id']] += 1
                
                # Détection d'anomalies
                if self.blocked_ips[parsed['src_ip']] > 50:
                    self.alerts.append({
                        'type': 'Possible DDoS',
                        'src_ip': parsed['src_ip'],
                        'count': self.blocked_ips[parsed['src_ip']],
                        'timestamp': datetime.now().isoformat()
                    })
    
    def generate_report(self):
        """Génération du rapport d'analyse"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'top_blocked_ips': dict(sorted(self.blocked_ips.items(), 
                                         key=lambda x: x[1], reverse=True)[:10]),
            'most_triggered_rules': dict(sorted(self.top_rules.items(), 
                                               key=lambda x: x[1], reverse=True)[:10]),
            'security_alerts': self.alerts
        }
        
        return json.dumps(report, indent=2)

# Utilisation
analyzer = FirewallLogAnalyzer()
# analyzer.analyze_threats(firewall_logs)
# print(analyzer.generate_report())
```

## 🔐 Analyse des Risques & Contre-mesures

### ⚠️ Risques Identifiés et Mitigation

| Risque | Probabilité | Impact | Contre-mesure | KPI |
|--------|-------------|--------|---------------|-----|
| **DDoS/DoS** | Élevé | Critique | Rate limiting, GeoIP blocking | < 1% downtime |
| **Bypass de règles** | Moyen | Élevé | Deep packet inspection, logs détaillés | 0 incident |
| **Configuration error** | Moyen | Élevé | Validation automatique, backups | < 30min restoration |
| **Performance degradation** | Élevé | Moyen | QoS, load balancing | < 100ms latency |
| **Compliance failure** | Faible | Critique | Audit automatique, documentation | 100% compliance |

### 🛡️ Contrôles de Sécurité Implémentés

#### 1. Contrôles Préventifs
```bash
# Anti-spoofing
set security screen ids-option untrust-screen icmp ping-death
set security screen ids-option untrust-screen ip source-route-option
set security screen ids-option untrust-screen tcp syn-flood

# Geo-blocking
pfctl -t geoblock -T add 192.0.2.0/24  # Example block range

# Rate limiting
set firewall filter INPUT rule 10 protocol tcp destination-port 22 \
    recent name ssh_brute update seconds 60 hitcount 4 jump drop
```

#### 2. Contrôles Détectifs
```bash
# Monitoring en temps réel
tail -f /var/log/filter.log | grep -E "(block|deny)" | \
while read line; do
    echo "[ALERT] $(date): $line" | \
    logger -p local0.warning -t firewall_monitor
done

# Alertes automatiques
if [ $(grep -c "block" /var/log/filter.log | tail -100) -gt 20 ]; then
    echo "High block rate detected" | mail -s "Firewall Alert" admin@lab.local
fi
```

#### 3. Contrôles Correctifs
```bash
# Auto-ban des IPs malveillantes
#!/bin/bash
# auto-ban.sh
LOGFILE="/var/log/filter.log"
BANTIME="3600"  # 1 heure

# Analyser les tentatives de brute force
awk '/block.*ssh/ {print $13}' $LOGFILE | sort | uniq -c | \
while read count ip; do
    if [ $count -gt 10 ]; then
        pfctl -t bruteforce -T add $ip
        echo "$ip banned for $BANTIME seconds" | logger
        # Auto-unban après délai
        (sleep $BANTIME; pfctl -t bruteforce -T delete $ip) &
    fi
done
```

## ✅ Bonnes Pratiques Professionnelles

### 🎯 Configuration Management
```bash
# Backup automatique des configurations
#!/bin/bash
# firewall-backup.sh

BACKUP_DIR="/backup/firewall/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration pfSense
curl -k -u admin:password "https://192.168.100.1/diag_backup.php" \
    -d "download=download&donotbackuprrd=yes" \
    -o "$BACKUP_DIR/pfsense-config-$(date +%Y%m%d-%H%M%S).xml"

# Backup rules
pfctl -sr > "$BACKUP_DIR/firewall-rules-$(date +%Y%m%d).txt"

# Version control
cd "$BACKUP_DIR"
git add . && git commit -m "Firewall backup $(date)"

echo "✅ Firewall backup completed: $BACKUP_DIR"
```

### 📊 Métriques et KPIs
```python
#!/usr/bin/env python3
# firewall-metrics.py - Calcul des métriques de performance

import psutil
import subprocess
import json
from datetime import datetime, timedelta

class FirewallMetrics:
    def __init__(self):
        self.metrics = {}
    
    def get_throughput(self):
        """Mesure du débit réseau"""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    
    def get_connection_stats(self):
        """Statistiques des connexions"""
        connections = psutil.net_connections()
        stats = {
            'established': 0,
            'listen': 0,
            'time_wait': 0
        }
        
        for conn in connections:
            if conn.status in stats:
                stats[conn.status] += 1
        
        return stats
    
    def get_rule_performance(self):
        """Performance des règles de pare-feu"""
        try:
            result = subprocess.run(['pfctl', '-sr', '-v'], 
                                  capture_output=True, text=True)
            # Parser les statistiques des règles
            rules_stats = {}
            for line in result.stdout.split('\n'):
                if 'Evaluations:' in line:
                    # Extraire les statistiques
                    pass
            return rules_stats
        except:
            return {}
    
    def calculate_sla_metrics(self):
        """Calcul des métriques SLA"""
        # Uptime
        uptime = subprocess.run(['uptime'], capture_output=True, text=True)
        
        # Latency moyenne
        ping_result = subprocess.run(['ping', '-c', '10', '8.8.8.8'], 
                                   capture_output=True, text=True)
        
        return {
            'uptime': uptime.stdout.strip(),
            'availability_percent': 99.9,  # À calculer selon les logs
            'avg_latency_ms': 15.2,        # À extraire du ping
            'packet_loss_percent': 0.0
        }
    
    def generate_dashboard_data(self):
        """Données pour tableau de bord"""
        self.metrics.update({
            'timestamp': datetime.now().isoformat(),
            'throughput': self.get_throughput(),
            'connections': self.get_connection_stats(),
            'sla': self.calculate_sla_metrics()
        })
        
        return json.dumps(self.metrics, indent=2)

# Utilisation pour monitoring continu
# metrics = FirewallMetrics()
# print(metrics.generate_dashboard_data())
```

## 📂 Structure Git du Projet

```
02-firewall-configuration/
├── README.md                    # Ce fichier
├── CHANGELOG.md                 # Historique des modifications
├── docs/
│   ├── network-diagram.png      # Schéma réseau détaillé
│   ├── flow-matrix.xlsx         # Matrice des flux autorisés
│   ├── compliance-mapping.md    # Mapping avec standards
│   └── troubleshooting.md       # Guide de dépannage
├── configs/
│   ├── pfsense/
│   │   ├── firewall-rules.xml   # Configuration complète
│   │   ├── nat-rules.xml        # Règles NAT
│   │   └── vpn-config.xml       # Configuration VPN
│   ├── suricata/
│   │   ├── suricata.yaml        # Config IDS/IPS
│   │   └── custom-rules.conf    # Règles personnalisées
│   └── monitoring/
│       ├── grafana-dashboard.json
│       └── prometheus-config.yml
├── scripts/
│   ├── deployment/
│   │   ├── deploy-firewall.sh   # Déploiement automatique
│   │   └── validate-config.sh   # Validation configuration
│   ├── monitoring/
│   │   ├── firewall-metrics.py  # Métriques performance
│   │   ├── log-analyzer.py      # Analyse des logs
│   │   └── alert-handler.sh     # Gestion des alertes
│   ├── maintenance/
│   │   ├── backup-config.sh     # Sauvegarde automatique
│   │   ├── update-rules.sh      # Mise à jour des règles
│   │   └── health-check.py      # Vérification santé
│   └── testing/
│       ├── connectivity-test.sh # Tests de connectivité
│       ├── performance-test.py  # Tests de performance
│       └── security-audit.sh    # Audit de sécurité
├── evidence/
│   ├── screenshots/
│   │   ├── pfsense-dashboard.png
│   │   ├── rule-configuration.png
│   │   └── monitoring-graphs.png
│   ├── reports/
│   │   ├── security-assessment.pdf
│   │   ├── performance-analysis.pdf
│   │   └── compliance-audit.pdf
│   └── logs/
│       ├── deployment.log       # Logs de déploiement
│       ├── performance.log      # Logs de performance
│       └── security-events.log  # Événements de sécurité
└── tests/
    ├── unit/
    │   └── test-rule-validation.py
    ├── integration/
    │   └── test-end-to-end.sh
    └── security/
        ├── penetration-test.py
        └── vulnerability-scan.sh
```

## 📜 Références et Standards

### 📚 Documentation Technique
- **pfSense Official Docs** : [docs.netgate.com](https://docs.netgate.com/pfsense/)
- **Suricata User Guide** : [suricata.readthedocs.io](https://suricata.readthedocs.io/)
- **NIST SP 800-41** : Guidelines on Firewalls and Firewall Policy

### 🔒 Standards de Sécurité
- **NIST SP 800-53** : Security Controls for Federal Information Systems
- **CIS Controls v8** : [cisecurity.org](https://www.cisecurity.org/controls/)
- **ISO 27001:2013** : Information Security Management Systems
- **PCI DSS v4.0** : Payment Card Industry Data Security Standard

### 🎓 Formations Recommandées
- **SANS SEC503** : Intrusion Detection In-Depth
- **Cisco CCNA Security** : Implementing Network Security
- **pfSense Professional** : Netgate Training Program

---

## 🎯 Livrables et Validation

### ✅ Checklist de Déploiement
- [ ] Architecture réseau documentée et approuvée
- [ ] Règles de pare-feu configurées et testées
- [ ] Monitoring et alerting opérationnels
- [ ] Documentation complète rédigée
- [ ] Tests de performance validés
- [ ] Audit de sécurité réalisé
- [ ] Procédures de sauvegarde testées
- [ ] Formation équipe effectuée
- [ ] Plan de maintenance établi
- [ ] Validation compliance effectuée

### 📊 Métriques de Succès
- **Sécurité** : 0 incident de sécurité critique
- **Performance** : < 100ms latence moyenne
- **Disponibilité** : 99.9% uptime minimum
- **Compliance** : 100% des contrôles validés
- **Documentation** : 100% des procédures couvertes

### 🏆 Compétences Démontrées
- **Architecture réseau sécurisée** de niveau entreprise
- **Configuration avancée de pare-feu** avec règles granulaires
- **Monitoring et métriques** de performance sécurité
- **Conformité réglementaire** et audit de sécurité
- **Automatisation et scripts** pour maintenance
- **Documentation technique** professionnelle

---

**🔧 Support Technique** : Pour assistance, consulter le guide de troubleshooting ou créer une issue GitHub.

**📈 Évolution** : Ce projet évolue selon les retours et nouvelles menaces. Vérifier régulièrement les mises à jour.