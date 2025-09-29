# DevSecOps Security Dashboard

Interface web complète pour la gestion et le monitoring de la plateforme DevSecOps. Ce dashboard offre une interface utilisateur moderne pour visualiser les scans de sécurité, gérer les alertes, surveiller les métriques système et contrôler l'orchestrateur de sécurité.

## 🚀 Fonctionnalités Principales

### Interface Utilisateur
- **Dashboard en temps réel** : Métriques et graphiques interactifs
- **Gestion des projets** : Vue d'ensemble et historique des scans
- **Monitoring système** : CPU, mémoire, disque en temps réel
- **Alertes actives** : Gestion et résolution des alertes de sécurité
- **Historique des scans** : Consultation détaillée des résultats
- **Rapports téléchargeables** : Export en multiple formats

### Technologies Intégrées
- **Flask** : Framework web Python moderne
- **Socket.IO** : Mises à jour en temps réel
- **Plotly** : Graphiques interactifs avancés
- **Bootstrap 5** : Interface responsive moderne
- **SQLite/PostgreSQL** : Stockage des métriques et configurations

### Fonctionnalités Avancées
- **WebSocket en temps réel** : Notifications instantanées
- **API RESTful complète** : Intégration programmatique
- **Système d'alertes** : Notifications multi-canal
- **Monitoring système** : Métriques détaillées
- **Export de données** : JSON, CSV, PDF
- **Sécurité intégrée** : CORS, CSP, rate limiting

## 📋 Architecture

```
dashboard/
├── web_dashboard.py      # Application Flask principale
├── templates/           # Templates HTML Jinja2
│   └── dashboard.html   # Interface principale
├── static/             # Assets statiques (CSS, JS, images)
├── requirements.txt    # Dépendances Python
└── README.md          # Documentation

config/
└── dashboard-config.yaml  # Configuration complète

run_dashboard.py       # Script de lancement
```

## 🛠️ Installation et Configuration

### 1. Prérequis
```bash
# Python 3.8+ requis
python --version

# Installer les dépendances
pip install -r dashboard/requirements.txt
```

### 2. Configuration
Copier et personnaliser le fichier de configuration :
```bash
cp config/dashboard-config.yaml config/my-dashboard.yaml
```

Éditer les paramètres importants :
```yaml
# Sécurité (OBLIGATOIRE en production)
secret_key: "your-secret-key-here"

# Base de données
database_path: "./monitoring/metrics.db"

# Alertes
alerts:
  enabled: true
  notification_channels:
    email:
      enabled: true
      smtp_server: "smtp.company.com"
      recipients:
        - "security@company.com"
```

### 3. Lancement du Dashboard

#### Lancement Simple
```bash
python run_dashboard.py
```

#### Lancement avec Configuration Personnalisée
```bash
python run_dashboard.py --config config/my-dashboard.yaml
```

#### Lancement en Mode Debug
```bash
python run_dashboard.py --debug --port 8080
```

#### Options de Lancement Complètes
```bash
python run_dashboard.py \
  --config config/production.yaml \
  --host 0.0.0.0 \
  --port 8080 \
  --debug
```

## 📊 API REST Documentation

### Endpoints Principaux

#### Dashboard Data
```http
GET /api/dashboard/data?hours=24
```
Récupère les métriques du dashboard pour les dernières N heures.

#### Gestion des Projets
```http
GET /api/projects
GET /api/projects/{project_name}/scans?hours=168
```

#### Gestion des Scans
```http
POST /api/scans/start
GET /api/scans/{scan_id}/status
```

Exemple de démarrage de scan :
```json
{
  "project_path": "/path/to/project",
  "project_name": "my-app",
  "mode": "standard",
  "stage": "pre_build"
}
```

#### Gestion des Alertes
```http
GET /api/alerts?resolved=false&hours=168
POST /api/alerts/{alert_id}/resolve
```

#### Santé du Système
```http
GET /api/system/health
```

#### Graphiques
```http
GET /api/charts/scans-timeline?hours=24
GET /api/charts/system-metrics?hours=24
```

#### Téléchargement de Rapports
```http
GET /api/reports/{report_id}
```

### Réponses d'API Standards

#### Succès
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2023-12-07T10:30:00Z"
}
```

#### Erreur
```json
{
  "status": "error",
  "error": "Error message",
  "code": 400,
  "timestamp": "2023-12-07T10:30:00Z"
}
```

## 🔄 WebSocket Events

### Événements Client → Serveur
- `connect` : Connexion au serveur
- `subscribe_scans` : S'abonner aux mises à jour de scans

### Événements Serveur → Client
- `scan_started` : Nouveau scan démarré
- `scan_progress` : Progression du scan
- `scan_completed` : Scan terminé avec succès
- `scan_error` : Erreur dans le scan
- `alert_resolved` : Alerte résolue

### Exemple d'Utilisation WebSocket (JavaScript)
```javascript
const socket = io();

socket.on('connect', function() {
    console.log('Connected to dashboard');
    socket.emit('subscribe_scans');
});

socket.on('scan_started', function(data) {
    console.log('New scan started:', data);
    updateScanList(data);
});

socket.on('scan_completed', function(data) {
    console.log('Scan completed:', data);
    refreshDashboard();
});
```

## 📈 Monitoring et Métriques

### Métriques Système Collectées
- **CPU Usage** : Utilisation processeur en %
- **Memory Usage** : Utilisation mémoire en %
- **Disk Usage** : Utilisation disque en %
- **Active Scans** : Nombre de scans en cours
- **Network I/O** : Trafic réseau (optionnel)

### Métriques de Scan
- **Scan Duration** : Durée d'exécution
- **Issues Found** : Nombre de problèmes détectés
- **Risk Score** : Score de risque global
- **Success Rate** : Taux de succès des scans
- **Issues by Severity** : Répartition par criticité

### Export des Métriques

#### Prometheus (Optionnel)
```yaml
monitoring:
  prometheus:
    enabled: true
    port: 9090
    metrics_path: "/metrics"
```

#### InfluxDB (Optionnel)
```yaml
monitoring:
  influxdb:
    enabled: true
    url: "http://localhost:8086"
    token: "your-token"
    org: "devsecops"
    bucket: "security-metrics"
```

## 🚨 Système d'Alertes

### Types d'Alertes Supportées
- **High CPU Usage** : CPU > 80% pendant 5+ minutes
- **High Memory Usage** : Mémoire > 85% pendant 5+ minutes  
- **Critical Vulnerabilities** : 1+ vulnérabilité critique détectée
- **Scan Failures** : 3+ échecs consécutifs
- **Disk Space Low** : Disque > 90% pendant 10+ minutes

### Canaux de Notification

#### Email (SMTP)
```yaml
alerts:
  notification_channels:
    email:
      enabled: true
      smtp_server: "smtp.gmail.com"
      smtp_port: 587
      use_tls: true
      from_email: "devsecops@company.com"
      recipients:
        - "team@company.com"
```

#### Slack
```yaml
alerts:
  notification_channels:
    slack:
      enabled: true
      webhook_url: "https://hooks.slack.com/services/..."
      channel: "#security-alerts"
```

#### Microsoft Teams
```yaml
alerts:
  notification_channels:
    teams:
      enabled: true
      webhook_url: "https://outlook.office.com/webhook/..."
```

#### Webhook Générique
```yaml
alerts:
  notification_channels:
    webhook:
      enabled: true
      url: "https://api.company.com/security-alerts"
      method: "POST"
      headers:
        Authorization: "Bearer API_TOKEN"
```

## 🔒 Sécurité

### Fonctionnalités de Sécurité
- **CORS** : Protection cross-origin configurable
- **CSP** : Content Security Policy
- **Rate Limiting** : Protection contre les abus
- **Session Management** : Gestion sécurisée des sessions
- **Input Validation** : Validation stricte des entrées
- **SQL Injection Protection** : Requêtes paramétrées

### Configuration de Production
```yaml
security:
  require_auth: true
  allowed_hosts:
    - "dashboard.company.com"
  cors_origins:
    - "https://company.com"
  security_headers:
    enabled: true
    force_https: true
  rate_limiting:
    enabled: true
    requests_per_minute: 60
```

### Headers de Sécurité
```yaml
security_headers:
  enabled: true
  force_https: true
  hsts_max_age: 31536000
  content_security_policy: "default-src 'self'"
```

## 🔧 Développement et Tests

### Mode Développement
```bash
python run_dashboard.py --debug --port 8080
```

### Tests Unitaires
```bash
# Installation des dépendances de test
pip install pytest pytest-flask pytest-cov

# Exécution des tests
pytest dashboard/tests/ -v

# Avec couverture de code
pytest dashboard/tests/ --cov=dashboard --cov-report=html
```

### Tests d'API
```bash
# Test de l'API avec curl
curl -X GET http://localhost:8080/api/system/health
curl -X GET http://localhost:8080/api/dashboard/data

# Test WebSocket
python dashboard/tests/test_websocket.py
```

### Structure des Tests
```
dashboard/tests/
├── test_web_dashboard.py    # Tests de l'application Flask
├── test_api.py             # Tests des endpoints API
├── test_websocket.py       # Tests WebSocket
├── test_metrics.py         # Tests du système de métriques
└── conftest.py            # Configuration pytest
```

## 🐳 Déploiement Docker

### Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8080

CMD ["python", "run_dashboard.py", "--host", "0.0.0.0", "--port", "8080"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  dashboard:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
      - ./monitoring:/app/monitoring
      - ./security-reports:/app/security-reports
    environment:
      - FLASK_ENV=production
```

## 📚 Extensions et Personnalisation

### Ajout de Nouveaux Graphiques
```python
@self.app.route('/api/charts/custom-metric')
def custom_metric_chart():
    # Récupérer les données
    data = get_custom_data()
    
    # Créer le graphique Plotly
    fig = go.Figure(data=[...])
    
    return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
```

### Nouveaux Endpoints API
```python
@self.app.route('/api/custom/endpoint')
def custom_endpoint():
    return jsonify({
        'custom_data': get_custom_data()
    })
```

### Templates Personnalisés
```html
<!-- dashboard/templates/custom.html -->
{% extends "dashboard.html" %}

{% block custom_content %}
<div class="custom-section">
    <!-- Contenu personnalisé -->
</div>
{% endblock %}
```

## 📋 Troubleshooting

### Problèmes Courants

#### Dashboard ne démarre pas
```bash
# Vérifier les dépendances
python run_dashboard.py --check-deps

# Vérifier les logs
tail -f dashboard.log
```

#### Problèmes de connexion WebSocket
```bash
# Vérifier le port et les CORS
netstat -tlnp | grep 8080

# Tester la connexion
curl -X GET http://localhost:8080/api/system/health
```

#### Base de données corrompue
```bash
# Sauvegarder et recréer
cp monitoring/metrics.db monitoring/metrics.db.backup
rm monitoring/metrics.db
python run_dashboard.py  # Créera une nouvelle DB
```

#### Métriques manquantes
```bash
# Vérifier le collecteur de métriques
python -c "from monitoring.metrics_collector import MetricsCollector; c = MetricsCollector({}); c.start()"
```

### Logs et Debugging
```bash
# Logs principaux
tail -f logs/dashboard.log

# Logs d'erreurs
tail -f logs/error.log

# Logs d'accès
tail -f logs/access.log

# Mode debug
python run_dashboard.py --debug
```

## 🤝 Contribution

### Guidelines
1. Fork le repository
2. Créer une branche feature (`git checkout -b feature/amazing-feature`)
3. Commit les changements (`git commit -m 'Add amazing feature'`)
4. Push vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

### Standards de Code
- **PEP 8** : Style de code Python
- **Type Hints** : Annotations de types
- **Docstrings** : Documentation des fonctions
- **Tests** : Couverture de code > 80%

## 📄 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](../LICENSE) pour plus de détails.

## 📞 Support

- **Documentation** : [Wiki du projet](../../wiki)
- **Issues** : [GitHub Issues](../../issues)
- **Discussions** : [GitHub Discussions](../../discussions)
- **Email** : security-team@company.com