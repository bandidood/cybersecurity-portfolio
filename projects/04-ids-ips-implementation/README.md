# 🛡️ Projet 04 : Implémentation IDS/IPS Enterprise

## 🎯 Objectifs Pédagogiques
- Maîtriser les technologies de détection et prévention d'intrusion
- Implémenter une architecture IDS/IPS multicouche sécurisée
- Développer des signatures de détection personnalisées
- Intégrer les systèmes de détection avec une stack SIEM
- Automatiser la réponse aux incidents de sécurité
- Mesurer et optimiser les performances de détection

## 📌 Contexte Professionnel
Dans un environnement de cybersécurité moderne, les systèmes IDS/IPS constituent la première ligne de défense contre les cyberattaques. Ce projet démontre :
- **Détection Temps Réel** : Identification instantanée des menaces réseau
- **Prévention Active** : Blocage automatique des attaques en cours
- **Corrélation Intelligente** : Analyse comportementale et signatures avancées
- **Conformité Réglementaire** : Respect des standards ISO 27001, NIST CSF
- **Intégration SOC** : Centralisation des alertes et gestion d'incidents

## ✅ Prérequis

### 💻 Infrastructure Requise
- **Laboratoire Project 01** : Infrastructure de base déployée
- **Network Segmentation** : VLANs configurés et isolés
- **Ressources VM** : 8 GB RAM minimum pour les sondes IDS/IPS
- **Stockage** : 100 GB disponible pour logs et captures

### 🧠 Compétences Nécessaires
- Concepts réseaux avancés (TCP/IP, routage, switching)
- Administration systèmes Linux (Ubuntu/CentOS)
- Analyse de trafic réseau (Wireshark, tcpdump)
- Bases des signatures de détection (regex, patterns)

### 🛠️ Technologies Utilisées
- **Suricata** : IDS/IPS open source multi-threadé
- **Snort** : IDS/IPS legacy avec règles communautaires
- **ELK Stack** : Centralisation et analyse des logs
- **Elasticsearch** : Moteur de recherche et analytics
- **Kibana** : Visualisation et dashboards
- **Logstash** : Pipeline de traitement des logs

## 🏗️ Architecture IDS/IPS

### 📊 Topologie de Sécurité
```
                    Internet
                        |
                [pfSense Firewall] ← IPS Integration
                        |
        ┌───────────────┼───────────────┐
        |               |               |
    [DMZ IDS]       [LAN IDS]      [Critical IDS]
   172.16.1.0/24   192.168.100.0/24  10.0.10.0/24
        |               |               |
    Web Servers     Workstations   Industrial IoT
                        |
            [SIEM Correlation Engine]
                 172.16.2.10
```

### 🔍 Composants de Détection

#### 1. **Network-Based IDS (NIDS)**
- **Suricata Cluster** : 3 sondes haute performance
- **Snort Legacy** : Compatibilité règles existantes
- **Positions stratégiques** : Points de convergence réseau
- **Mode monitoring** : Analyse passive sans interruption

#### 2. **Network-Based IPS (NIPS)**
- **Inline Deployment** : Trafic en transit analysé
- **Blocage Automatique** : Règles de prévention active
- **Load Balancing** : Haute disponibilité des sondes
- **Bypass Matériel** : Continuité en cas de panne

#### 3. **Correlation Engine**
- **Multi-Source Analysis** : Fusion des événements
- **Behavioral Analytics** : Détection d'anomalies comportementales
- **Threat Intelligence** : IOCs et feeds externes
- **False Positive Reduction** : Filtrage intelligent

## 🛠️ Plan d'Action Structuré

### Phase 1 : Infrastructure IDS (Semaine 1)
1. **Déploiement Suricata Cluster**
   - Installation sur 3 VMs Ubuntu 22.04 LTS
   - Configuration interfaces monitoring TAP/SPAN
   - Optimisation performances multi-thread
   
2. **Configuration Snort Legacy**
   - Installation Snort 2.9.19+ avec DAQ
   - Configuration base de règles Emerging Threats
   - Tests compatibilité règles personnalisées

### Phase 2 : Intégration SIEM (Semaine 2)
3. **ELK Stack Deployment**
   - Elasticsearch cluster 3 nodes
   - Logstash pipelines spécialisés IDS/IPS
   - Kibana dashboards temps réel
   
4. **Corrélation et Alerting**
   - Configuration Elastalert pour notifications
   - Règles de corrélation multi-sources
   - Intégration API externes (Threat Intelligence)

### Phase 3 : Signatures Avancées (Semaine 3)
5. **Règles Personnalisées**
   - Signatures détection APT
   - Patterns spécifiques infrastructure
   - Optimisation performances règles
   
6. **Machine Learning Integration**
   - Détection anomalies comportementales
   - Classification automatique menaces
   - Réduction false positives par IA

### Phase 4 : Automatisation et Tests (Semaine 4)
7. **Response Automation**
   - Scripts de réponse automatique
   - Intégration pfSense pour blocage IP
   - Quarantaine automatique endpoints suspects
   
8. **Validation et Métriques**
   - Tests de pénétration contrôlés
   - Mesure temps de détection (MTTD)
   - Benchmark performances et précision

## 💻 Scripts d'Automatisation

### 🚀 Script de Déploiement Principal
```bash
#!/bin/bash
# deploy-ids-ips.sh - Déploiement automatique IDS/IPS

set -euo pipefail

echo "🛡️ Déploiement de l'infrastructure IDS/IPS..."

# Variables configuration
SURICATA_VERSION="6.0.10"
SNORT_VERSION="2.9.19"
ELK_VERSION="8.10.0"
LAB_NETWORK="192.168.100.0/24"

# Vérification prérequis
check_prerequisites() {
    echo "🔍 Vérification des prérequis..."
    
    # Vérification ressources
    AVAILABLE_RAM=$(free -g | awk '/^Mem:/{print $7}')
    if [ $AVAILABLE_RAM -lt 8 ]; then
        echo "❌ RAM insuffisante (8GB requis, ${AVAILABLE_RAM}GB disponible)"
        exit 1
    fi
    
    # Vérification interfaces réseau
    if ! ip addr show | grep -q "192.168.100"; then
        echo "❌ Interface lab non configurée"
        exit 1
    fi
    
    echo "✅ Prérequis validés"
}

# Installation Suricata
install_suricata() {
    echo "📦 Installation Suricata ${SURICATA_VERSION}..."
    
    # Installation dépendances
    apt-get update
    apt-get install -y software-properties-common
    add-apt-repository ppa:oisf/suricata-stable
    apt-get update
    
    # Installation Suricata
    apt-get install -y suricata
    
    # Configuration interfaces
    cat > /etc/suricata/suricata.yaml << EOF
vars:
  address-groups:
    HOME_NET: "${LAB_NETWORK}"
    EXTERNAL_NET: "!${LAB_NETWORK}"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    threads: 4
    use-mmap: yes
    ring-size: 2048

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow:
        - stats:
            totals: yes
            threads: yes

rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/emerging-threats.rules
  - /etc/suricata/rules/custom.rules
EOF

    # Mise à jour des règles
    suricata-update
    
    # Démarrage service
    systemctl enable suricata
    systemctl start suricata
    
    echo "✅ Suricata installé et configuré"
}

# Installation Snort
install_snort() {
    echo "📦 Installation Snort ${SNORT_VERSION}..."
    
    # Installation dépendances
    apt-get install -y build-essential libdnet-dev libdumbnet-dev
    apt-get install -y bison flex libpcap-dev libpcre3-dev
    apt-get install -y libdumbnet-dev libluajit-5.1-dev
    
    # Téléchargement et compilation Snort
    cd /tmp
    wget https://snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz
    tar -xzf snort-${SNORT_VERSION}.tar.gz
    cd snort-${SNORT_VERSION}
    
    ./configure --enable-sourcefire --enable-open-appid
    make -j$(nproc)
    make install
    
    # Configuration
    mkdir -p /etc/snort/{rules,preproc_rules,lib,log}
    mkdir -p /var/log/snort
    
    # Configuration de base
    cat > /etc/snort/snort.conf << 'EOF'
var HOME_NET 192.168.100.0/24
var EXTERNAL_NET !$HOME_NET
var DNS_SERVERS $HOME_NET
var SMTP_SERVERS $HOME_NET
var HTTP_SERVERS $HOME_NET
var SQL_SERVERS $HOME_NET
var TELNET_SERVERS $HOME_NET

preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy windows, ports both all
preprocessor stream5_udp: ignore_any_rules

include $RULE_PATH/emerging-threats.rules
include $RULE_PATH/custom.rules

output alert_syslog: LOG_AUTH LOG_ALERT
output log_tcpdump: /var/log/snort/snort.log
EOF

    echo "✅ Snort installé et configuré"
}

# Configuration ELK Stack
setup_elk_stack() {
    echo "📊 Configuration ELK Stack..."
    
    # Installation Elasticsearch
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
    
    apt-get update
    apt-get install -y elasticsearch logstash kibana
    
    # Configuration Elasticsearch
    cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: lab-security-cluster
node.name: ids-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 172.16.2.10
http.port: 9200
discovery.seed_hosts: ["172.16.2.10"]
cluster.initial_master_nodes: ["ids-node-1"]
xpack.security.enabled: false
EOF

    # Configuration Logstash pipeline IDS
    cat > /etc/logstash/conf.d/suricata.conf << 'EOF'
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
    type => "suricata"
  }
}

filter {
  if [type] == "suricata" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [event_type] == "alert" {
      mutate {
        add_field => { "severity" => "high" }
      }
      
      if [alert][category] == "Trojan" {
        mutate {
          add_field => { "threat_type" => "malware" }
        }
      }
    }
    
    geoip {
      source => "src_ip"
      target => "geoip_src"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "ids-alerts-%{+YYYY.MM.dd}"
  }
}
EOF

    # Démarrage services
    systemctl enable elasticsearch logstash kibana
    systemctl start elasticsearch
    sleep 30
    systemctl start logstash kibana
    
    echo "✅ ELK Stack configuré"
}

# Configuration monitoring
setup_monitoring() {
    echo "📈 Configuration monitoring..."
    
    # Script de surveillance performances
    cat > /usr/local/bin/ids-monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Monitoring IDS/IPS Performance
"""
import psutil
import subprocess
import json
import time
from datetime import datetime

def get_suricata_stats():
    """Récupération statistiques Suricata"""
    try:
        result = subprocess.run(['suricatasc', '-c', 'dump-counters'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except:
        pass
    return {}

def monitor_performance():
    """Monitoring performance système"""
    stats = {
        'timestamp': datetime.now().isoformat(),
        'system': {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict(),
            'network_io': psutil.net_io_counters()._asdict()
        },
        'suricata': get_suricata_stats()
    }
    
    # Calcul des métriques clés
    if stats['suricata']:
        packets_processed = stats['suricata'].get('decoder.pkts', 0)
        alerts_generated = stats['suricata'].get('detect.alert', 0)
        
        if packets_processed > 0:
            alert_rate = (alerts_generated / packets_processed) * 100
            stats['metrics'] = {
                'packets_per_second': packets_processed,
                'alert_rate_percent': alert_rate,
                'detection_efficiency': 100 - alert_rate if alert_rate < 10 else 90
            }
    
    return stats

if __name__ == "__main__":
    while True:
        stats = monitor_performance()
        print(json.dumps(stats, indent=2))
        
        # Alertes critiques
        if stats['system']['cpu_percent'] > 80:
            print("🚨 ALERT: High CPU usage detected!")
        if stats['system']['memory_percent'] > 90:
            print("🚨 ALERT: High memory usage detected!")
            
        time.sleep(60)
EOF

    chmod +x /usr/local/bin/ids-monitor.py
    
    echo "✅ Monitoring configuré"
}

# Déploiement principal
main() {
    check_prerequisites
    install_suricata
    install_snort
    setup_elk_stack
    setup_monitoring
    
    echo ""
    echo "🎉 INFRASTRUCTURE IDS/IPS DÉPLOYÉE AVEC SUCCÈS !"
    echo ""
    echo "📊 Interfaces disponibles:"
    echo "- Kibana Dashboard: http://172.16.2.10:5601"
    echo "- Elasticsearch API: http://172.16.2.10:9200"
    echo "- Suricata Logs: /var/log/suricata/eve.json"
    echo "- Snort Logs: /var/log/snort/"
    echo ""
    echo "🔧 Commandes utiles:"
    echo "- systemctl status suricata"
    echo "- systemctl status snort"
    echo "- python3 /usr/local/bin/ids-monitor.py"
    echo "- tail -f /var/log/suricata/eve.json"
    echo ""
    echo "📋 Prochaines étapes:"
    echo "1. Configurer les règles personnalisées"
    echo "2. Tester la détection avec du trafic malveillant"
    echo "3. Optimiser les performances selon le trafic"
    echo "4. Configurer les alertes automatiques"
}

main "$@"
```

## 🔐 Analyse des Risques & Sécurité

### ⚠️ Risques Identifiés

| Risque | Impact | Probabilité | Contre-mesure |
|--------|--------|-------------|---------------|
| **Contournement IDS** | Critique | Moyen | Multi-layer detection, behavioral analysis |
| **False Positives** | Élevé | Élevé | Machine learning, rule tuning, whitelist |
| **Performance Impact** | Moyen | Élevé | Hardware acceleration, load balancing |
| **Blind Spots** | Critique | Moyen | Network segmentation, multiple sensor placement |
| **Evasion Techniques** | Élevé | Moyen | Advanced signatures, protocol analysis |

### 🛡️ Mesures de Sécurité

#### 1. **Defense in Depth**
```bash
# Configuration multicouche
# Niveau 1: Firewall rules
# Niveau 2: IPS inline blocking
# Niveau 3: IDS monitoring
# Niveau 4: SIEM correlation
# Niveau 5: Response automation
```

#### 2. **Détection Avancée**
```yaml
# Signatures comportementales
advanced_detection:
  behavioral_analysis: true
  ml_anomaly_detection: true
  threat_intelligence: true
  encrypted_traffic_analysis: true
```

#### 3. **Haute Disponibilité**
```bash
# Clustering IDS/IPS
cluster_config:
  primary_node: "ids-01.lab.local"
  backup_nodes: ["ids-02.lab.local", "ids-03.lab.local"]
  failover_time: "< 30s"
  load_balancing: "round_robin"
```

## ✅ Validation et Tests

### 🎯 Tests de Détection
- **Signature Testing** : Validation règles custom avec payloads connus
- **Evasion Testing** : Tests résistance techniques d'évasion
- **Performance Testing** : Mesure impact latence et throughput
- **False Positive Testing** : Validation précision détection

### 📊 Métriques de Succès
- **MTTD (Mean Time To Detect)** : < 30 secondes
- **False Positive Rate** : < 2%
- **Network Performance Impact** : < 5%
- **Coverage** : 95% des attaques MITRE ATT&CK

### 🔧 Checklist de Validation
- [ ] IDS/IPS déployés sur tous segments critiques
- [ ] Règles de détection personnalisées activées
- [ ] Intégration SIEM opérationnelle
- [ ] Alertes automatiques configurées
- [ ] Tests de pénétration réussis
- [ ] Documentation technique complète
- [ ] Formation équipe SOC effectuée
- [ ] Procédures de réponse validées

## 📂 Structure du Projet

```
04-ids-ips-implementation/
├── README.md                    # Documentation principale
├── CHANGELOG.md                 # Historique des modifications
├── configs/                    # Configurations IDS/IPS
│   ├── suricata/              # Configuration Suricata
│   ├── snort/                 # Configuration Snort
│   ├── eve-json/              # Format logs JSON
│   └── signatures/            # Signatures personnalisées
├── scripts/                   # Scripts d'automatisation
│   ├── setup/                 # Scripts installation
│   ├── monitoring/            # Scripts surveillance
│   ├── analysis/              # Scripts analyse logs
│   └── testing/               # Scripts de test
├── docs/                      # Documentation technique
│   ├── architecture/          # Architecture détaillée
│   ├── guides/                # Guides d'utilisation
│   └── troubleshooting/       # Dépannage
├── evidence/                  # Preuves et résultats
│   ├── screenshots/           # Captures d'écran
│   ├── logs/                  # Logs d'exemple
│   ├── reports/               # Rapports d'analyse
│   └── pcaps/                 # Captures réseau
├── tests/                     # Tests et validation
│   ├── unit-tests/           # Tests unitaires
│   ├── integration-tests/     # Tests d'intégration
│   └── performance-tests/     # Tests de performance
├── rules/                     # Règles de détection
│   ├── custom/                # Règles personnalisées
│   ├── emerging-threats/      # Règles Emerging Threats
│   └── community/             # Règles communautaires
├── dashboards/                # Tableaux de bord
│   ├── kibana/                # Dashboards Kibana
│   └── grafana/               # Dashboards Grafana
└── tools/                     # Outils spécialisés
    ├── generators/            # Générateurs de trafic
    ├── parsers/               # Parseurs de logs
    └── alerts/                # Gestion alertes
```

## 🎓 Compétences Démontrées
- Architecture de sécurité réseau multicouche
- Maîtrise des technologies IDS/IPS (Suricata, Snort)
- Développement de signatures de détection personnalisées
- Intégration SIEM et corrélation d'événements
- Automatisation de la réponse aux incidents
- Analyse de performance et optimisation systèmes
- Tests de sécurité et validation d'efficacité

---

**📞 Support** : Consulter la documentation technique ou créer une issue sur le repository.

**🔄 Évolution** : Ce projet évolue avec les nouvelles menaces. Mise à jour régulière des signatures et règles.