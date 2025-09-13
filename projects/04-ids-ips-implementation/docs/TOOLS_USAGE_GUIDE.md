# 🛠️ Guide d'Utilisation des Outils IDS/IPS

## Vue d'Ensemble

Ce projet inclut une suite complète d'outils développés pour l'analyse, le monitoring et les tests de votre système IDS/IPS. Ce guide détaille l'utilisation de chaque outil.

## 📋 Table des Matières

1. [Script de Déploiement](#script-de-déploiement)
2. [Analyseur de Logs Avancé](#analyseur-de-logs-avancé)
3. [Dashboard de Monitoring](#dashboard-de-monitoring)
4. [Générateur de Trafic Malveillant](#générateur-de-trafic-malveillant)
5. [Script de Validation Automatisée](#script-de-validation-automatisée)
6. [Tests de Performance](#tests-de-performance)

---

## 1. Script de Déploiement

### 📂 Fichier: `scripts/setup/deploy-ids-ips.sh`

**Description**: Script d'installation automatisée complète du système IDS/IPS avec Suricata, Snort et la stack ELK.

### Utilisation

```bash
# Installation complète (recommandé)
sudo bash scripts/setup/deploy-ids-ips.sh

# Installation avec options
sudo bash scripts/setup/deploy-ids-ips.sh --network 10.0.0.0/24 --monitoring-interface eth1
```

### Fonctionnalités

- ✅ Vérification automatique des prérequis
- ✅ Installation Suricata avec configuration optimisée
- ✅ Installation Snort avec règles Emerging Threats
- ✅ Déploiement ELK Stack (Elasticsearch, Logstash, Kibana)
- ✅ Configuration des dashboards Kibana
- ✅ Scripts de monitoring système
- ✅ Tests de connectivité post-installation

### Prérequis

- Ubuntu 20.04+ ou CentOS 8+
- 16GB RAM minimum
- 100GB espace disque
- Accès internet pour téléchargements
- Droits administrateur

---

## 2. Analyseur de Logs Avancé

### 📂 Fichier: `tools/analysis/ids-log-analyzer.py`

**Description**: Outil d'analyse sophistiqué des logs IDS/IPS avec corrélation d'événements, détection de patterns d'attaque et intégration de Threat Intelligence.

### Utilisation

#### Mode Temps Réel
```bash
# Analyse temps réel avec corrélation
python3 tools/analysis/ids-log-analyzer.py --mode realtime --correlation

# Analyse avec seuils personnalisés
python3 tools/analysis/ids-log-analyzer.py --mode realtime --brute-force-threshold 20 --port-scan-threshold 50
```

#### Mode Batch (Analyse Historique)
```bash
# Analyse des dernières 24h
python3 tools/analysis/ids-log-analyzer.py --mode batch --timeframe 24h

# Analyse d'une période spécifique
python3 tools/analysis/ids-log-analyzer.py --mode batch --start-date 2024-01-01 --end-date 2024-01-31
```

#### Options Avancées
```bash
# Export vers Elasticsearch
python3 tools/analysis/ids-log-analyzer.py --mode batch --export-elasticsearch --es-index security-analysis

# Génération de rapport PDF
python3 tools/analysis/ids-log-analyzer.py --mode batch --generate-report --format pdf

# Intégration Threat Intelligence
python3 tools/analysis/ids-log-analyzer.py --mode realtime --threat-intelligence --ioc-feeds feeds.json
```

### Fonctionnalités

- **Corrélation Multi-Sources**: Fusion des événements Suricata/Snort
- **Détection de Patterns**: Brute force, port scanning, lateral movement
- **Threat Intelligence**: Intégration d'IOCs et feeds externes
- **Classification MITRE ATT&CK**: Mapping automatique des tactiques
- **GeoIP Enrichment**: Géolocalisation des adresses IP
- **Alerting Avancé**: Notifications multi-canaux (Slack, email, webhook)

---

## 3. Dashboard de Monitoring

### 📂 Fichier: `tools/dashboard/ids-dashboard.py`

**Description**: Interface web moderne de monitoring temps réel avec visualisations interactives et métriques de performance.

### Utilisation

#### Démarrage Standard
```bash
# Dashboard sur port par défaut
python3 tools/dashboard/ids-dashboard.py

# Configuration personnalisée
python3 tools/dashboard/ids-dashboard.py --host 0.0.0.0 --port 8080 --config dashboard_config.json
```

#### Configuration Avancée
```bash
# Mode debug avec logs verbeux
python3 tools/dashboard/ids-dashboard.py --debug --verbose

# Dashboard avec authentification
python3 tools/dashboard/ids-dashboard.py --auth --users users.json
```

### Accès

Une fois démarré, le dashboard est accessible via :
- **URL**: http://localhost:5000
- **Authentification**: Selon configuration
- **Compatibilité**: Navigateurs modernes (Chrome, Firefox, Safari)

### Fonctionnalités

#### Visualisations Temps Réel
- 📊 **Métriques principales**: Total alertes, alertes/minute
- 🎯 **Top attaques**: Classification par type et fréquence
- 🌐 **Géolocalisation**: Origine géographique des attaques
- 📈 **Graphiques d'évolution**: Tendances temporelles
- 💻 **Monitoring système**: CPU, RAM, disque, réseau

#### API REST
```bash
# Métriques actuelles
curl http://localhost:5000/api/metrics

# Alertes récentes
curl http://localhost:5000/api/alerts?limit=100

# Historique des statistiques
curl http://localhost:5000/api/stats
```

---

## 4. Générateur de Trafic Malveillant

### 📂 Fichier: `tools/generators/malicious-traffic-generator.py`

**Description**: Générateur avancé de trafic d'attaque pour tester et valider l'efficacité des systèmes de détection.

### ⚠️ IMPORTANTE SÉCURITÉ
**Ce script doit être utilisé EXCLUSIVEMENT dans des environnements de test contrôlés. L'utilisation sur des systèmes en production ou externes est interdite.**

### Utilisation

#### Attaques Individuelles
```bash
# Scan de ports TCP
python3 tools/generators/malicious-traffic-generator.py --attack port_scan --target 192.168.100.10

# Attaque brute force SSH
python3 tools/generators/malicious-traffic-generator.py --attack brute_force --target 192.168.100.10 --service ssh --duration 60

# Attaques web (SQL injection, XSS, LFI)
python3 tools/generators/malicious-traffic-generator.py --attack web_attacks --target 192.168.100.10 --port 80

# Simulation DDoS
python3 tools/generators/malicious-traffic-generator.py --attack ddos --target 192.168.100.10 --threads 5 --duration 30
```

#### Scénarios d'Attaque Complets
```bash
# Reconnaissance réseau
python3 tools/generators/malicious-traffic-generator.py --scenario reconnaissance --targets 192.168.100.10,192.168.100.20

# Chaîne d'attaque complète (Kill Chain)
python3 tools/generators/malicious-traffic-generator.py --scenario full_attack_chain --duration 300

# Simulation APT
python3 tools/generators/malicious-traffic-generator.py --scenario lateral --targets 192.168.100.10,192.168.100.20,192.168.100.30
```

### Types d'Attaques Supportées

1. **Reconnaissance**
   - Port scanning (TCP/UDP/SYN)
   - Service enumeration
   - Banner grabbing

2. **Initial Access**
   - Brute force (SSH, HTTP, FTP)
   - Web exploitation (SQLi, XSS, LFI)
   - Protocol exploitation

3. **Lateral Movement**
   - SMB enumeration
   - RDP connections
   - WMI exploitation

4. **Data Exfiltration**
   - HTTP POST exfiltration
   - DNS tunneling
   - FTP uploads

### Sécurités Intégrées

- ✅ Restriction aux réseaux privés uniquement
- ✅ Rate limiting configurable
- ✅ Limitations de durée et volume
- ✅ Logging complet des activités

---

## 5. Script de Validation Automatisée

### 📂 Fichier: `scripts/testing/validate-ids-ips.py`

**Description**: Solution complète de validation automatisée avec génération d'attaques, vérification de détections et rapports détaillés.

### Utilisation

#### Suites de Tests
```bash
# Suite basique (rapide)
python3 scripts/testing/validate-ids-ips.py --test-suite basic

# Suite complète (recommandée)
python3 scripts/testing/validate-ids-ips.py --test-suite comprehensive --output validation_report.json

# Tests de performance
python3 scripts/testing/validate-ids-ips.py --test-suite performance --duration 600
```

#### Vérifications Préliminaires
```bash
# Vérification des prérequis seulement
python3 scripts/testing/validate-ids-ips.py --check-only

# Test avec configuration personnalisée
python3 scripts/testing/validate-ids-ips.py --config validation_config.json --verbose
```

### Types de Tests

#### Suite Basic (15 minutes)
- Port scan detection
- SSH brute force
- Web attacks (SQLi, XSS)

#### Suite Comprehensive (45 minutes)
- Tous les tests basic
- Multiple brute force services
- DDoS simulation
- Data exfiltration
- Lateral movement

#### Suite Performance (60+ minutes)
- High-volume DDoS
- Concurrent attacks
- Full kill chain scenarios

### Rapports Générés

#### Format JSON
- Métriques détaillées par test
- Statistiques de détection
- Temps de réponse
- Recommandations d'optimisation

#### Format HTML
- Visualisations graphiques
- Tableaux de résultats
- Recommandations interactives
- Export et partage faciles

---

## 6. Tests de Performance

### 📂 Fichier: `scripts/testing/performance-test.py`

**Description**: Suite de benchmarks pour évaluer les performances, limites et stabilité du système IDS/IPS.

### Utilisation

#### Tests de Throughput
```bash
# Test de débit par niveaux
python3 scripts/testing/performance-test.py --test-type throughput --pps-levels 100,500,1000,2000 --duration 60

# Test haute performance
python3 scripts/testing/performance-test.py --test-type throughput --pps-levels 5000,10000 --duration 120
```

#### Tests de Latence
```bash
# Mesure latence de détection
python3 scripts/testing/performance-test.py --test-type latency --duration 300

# Test avec attaques spécifiques
python3 scripts/testing/performance-test.py --test-type latency --attacks port_scan,brute_force,web_attacks
```

#### Tests de Stress
```bash
# Test de charge maximale
python3 scripts/testing/performance-test.py --test-type stress --max-pps 10000 --duration 600

# Stress test avec monitoring
python3 scripts/testing/performance-test.py --test-type stress --max-pps 5000 --duration 300 --verbose
```

#### Tests de Scalabilité
```bash
# Test connexions simultanées
python3 scripts/testing/performance-test.py --test-type scalability --connections 50,100,200,500

# Test montée en charge progressive
python3 scripts/testing/performance-test.py --test-type scalability --connections 10,50,100 --duration 180
```

#### Suite Complète
```bash
# Benchmark complet (2+ heures)
python3 scripts/testing/performance-test.py --test-type full --duration 300 --output benchmark_report.json
```

### Métriques Collectées

#### Performance
- **Throughput**: Paquets/seconde, Mbits/seconde
- **Latence**: Moyenne, P95, P99 des temps de détection
- **Efficacité**: Ratio traitement vs génération

#### Ressources Système
- **CPU**: Utilisation moyenne et pics
- **Mémoire**: Consommation RAM et swap
- **Disque**: I/O et espace utilisé
- **Réseau**: Bande passante et latence

#### Qualité de Détection
- **Taux de détection**: Pourcentage d'alertes générées
- **Faux positifs**: Alertes non pertinentes
- **Temps de réponse**: Délai entre attaque et alerte
- **Stabilité système**: Évaluation de la robustesse

### Notes de Performance

Le système attribue une note globale (A+ à F) basée sur :
- **Throughput** (30% du score)
- **Latence** (25% du score) 
- **Ressources** (25% du score)
- **Stabilité** (20% du score)

---

## 🔧 Configuration Globale

### Fichiers de Configuration

#### Dashboard Config (`dashboard_config.json`)
```json
{
    "suricata_log_path": "/var/log/suricata/eve.json",
    "snort_log_path": "/var/log/snort/alert",
    "elasticsearch_url": "http://localhost:9200",
    "monitor_suricata": true,
    "monitor_snort": true,
    "monitor_elasticsearch": true,
    "dashboard_host": "0.0.0.0",
    "dashboard_port": 5000
}
```

#### Validation Config (`validation_config.json`)
```json
{
    "test_network": "192.168.100.0/24",
    "test_targets": ["192.168.100.10", "192.168.100.20"],
    "test_duration": 30,
    "expected_detection_rates": {
        "port_scan": 0.9,
        "brute_force": 0.85,
        "web_attacks": 0.8,
        "ddos": 0.95
    }
}
```

### Variables d'Environnement

```bash
# Configuration des chemins
export SURICATA_LOG="/var/log/suricata/eve.json"
export SNORT_LOG="/var/log/snort/alert"
export ES_URL="http://localhost:9200"

# Configuration réseau de test
export TEST_NETWORK="192.168.100.0/24"
export TEST_TARGETS="192.168.100.10,192.168.100.20"

# Paramètres de performance
export MAX_PPS="5000"
export TEST_DURATION="300"
```

---

## 🚀 Workflows Recommandés

### 1. Déploiement Initial Complet
```bash
# 1. Installation système
sudo bash scripts/setup/deploy-ids-ips.sh

# 2. Vérification déploiement
python3 scripts/testing/validate-ids-ips.py --check-only

# 3. Tests fonctionnels
python3 scripts/testing/validate-ids-ips.py --test-suite basic

# 4. Lancement monitoring
python3 tools/dashboard/ids-dashboard.py &
```

### 2. Tests de Validation Réguliers
```bash
# Tests hebdomadaires automatisés
python3 scripts/testing/validate-ids-ips.py --test-suite comprehensive --output "weekly_$(date +%Y%m%d).json"

# Génération d'attaques contrôlées
python3 tools/generators/malicious-traffic-generator.py --scenario reconnaissance --duration 120

# Analyse des résultats
python3 tools/analysis/ids-log-analyzer.py --mode batch --timeframe 1h --generate-report
```

### 3. Benchmarking Performance Mensuel
```bash
# Tests de performance complets
python3 scripts/testing/performance-test.py --test-type full --duration 600 --output "benchmark_$(date +%Y%m).json"

# Analyse des tendances
python3 tools/analysis/ids-log-analyzer.py --mode batch --timeframe 1month --export-elasticsearch
```

---

## 📞 Support et Troubleshooting

### Logs et Débogage

```bash
# Activation du mode debug pour tous les outils
export DEBUG=1

# Logs détaillés
python3 <tool> --verbose --log-level DEBUG

# Vérification des services
sudo systemctl status suricata snort elasticsearch
```

### Problèmes Courants

#### 1. **Dashboard ne démarre pas**
```bash
# Vérification des ports
sudo netstat -tulnp | grep :5000

# Vérification des logs
python3 tools/dashboard/ids-dashboard.py --debug
```

#### 2. **Tests de performance échouent**
```bash
# Vérification ressources système
free -h && df -h

# Vérification réseau
ping -c 4 192.168.100.10
```

#### 3. **Pas de détections**
```bash
# Vérification des services IDS/IPS
sudo tail -f /var/log/suricata/suricata.log
sudo tail -f /var/log/snort/snort.log

# Test de génération manuelle
python3 tools/generators/malicious-traffic-generator.py --attack port_scan --target 127.0.0.1
```

---

## 📚 Ressources Supplémentaires

### Documentation Technique
- [Architecture Détaillée](ARCHITECTURE.md)
- [Guide de Configuration](CONFIGURATION.md)
- [Procédures de Maintenance](MAINTENANCE.md)

### APIs et Intégrations
- [API Documentation](API.md)
- [Elasticsearch Integration](ELASTICSEARCH.md)
- [SIEM Integration](SIEM.md)

### Développement
- [Contribution Guidelines](CONTRIBUTING.md)
- [Custom Rules Development](RULES.md)
- [Plugin Development](PLUGINS.md)

---

*Dernière mise à jour: Décembre 2024*
*Version: 1.0.0*