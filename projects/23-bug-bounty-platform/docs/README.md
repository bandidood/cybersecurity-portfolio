# Bug Bounty Platform & Automated Vulnerability Discovery

## 📖 Guide d'utilisation complet

### Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Installation et configuration](#installation-et-configuration)
3. [Architecture](#architecture)
4. [API Documentation](#api-documentation)
5. [Utilisation des scanners](#utilisation-des-scanners)
6. [Gestion des programmes](#gestion-des-programmes)
7. [Soumission de rapports](#soumission-de-rapports)
8. [Exemples d'utilisation](#exemples-dutilisation)
9. [Déploiement](#déploiement)
10. [Troubleshooting](#troubleshooting)

---

## Vue d'ensemble

Cette plateforme combine les fonctionnalités d'un programme de bug bounty traditionnel avec des capacités de scan automatisé de vulnérabilités. Elle permet aux organisations de :

- **Lancer des programmes de bug bounty** avec gestion complète des récompenses
- **Scanner automatiquement leurs actifs** pour identifier proactivement les vulnérabilités
- **Gérer le cycle de vie complet** des rapports de vulnérabilités
- **Suivre les métriques** et l'efficacité de leurs programmes de sécurité

### Fonctionnalités principales

#### 🎯 Gestion des programmes de bug bounty
- Création et configuration de programmes publics/privés
- Définition du scope et des règles d'engagement
- Structure de récompenses flexible par niveau de sévérité
- Invitation de chercheurs pour programmes privés

#### 🔍 Scan automatisé de vulnérabilités
- **Scanner web** : Détection OWASP Top 10, injection SQL, XSS, XXE, etc.
- **Scanner réseau** : Découverte d'hôtes, analyse de ports, services vulnérables
- **Moteur unifié** : Orchestration et planification de scans multiples
- **Corrélation intelligente** : Élimination des faux positifs

#### 📊 Gestion des rapports
- Soumission structurée avec validation automatique
- Workflow d'approbation avec assignment aux triagers
- Système de commentaires et pièces jointes
- Détection automatique des doublons
- Calcul automatique des récompenses

#### 📈 Analytics et reporting
- Métriques détaillées par programme et chercheur
- Tableaux de bord temps réel
- Export de rapports (PDF, JSON, XML)
- KPIs de performance et ROI

---

## Installation et configuration

### Prérequis

- **Python 3.9+**
- **PostgreSQL 13+** (optionnel, SQLite par défaut)
- **Redis 6+** (pour les tâches asynchrones)
- **Nmap** (pour le scan réseau)
- **Git**

### Installation

```bash
# Cloner le repository
git clone https://github.com/votre-org/bug-bounty-platform.git
cd bug-bounty-platform

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r requirements.txt

# Configuration initiale
cp config/config.example.yaml config/config.yaml
```

### Configuration

Éditez `config/config.yaml` :

```yaml
# Configuration de la base de données
database:
  type: "postgresql"  # ou "sqlite"
  host: "localhost"
  port: 5432
  name: "bugbounty_db"
  user: "bugbounty_user"
  password: "your_secure_password"

# Configuration Redis
redis:
  host: "localhost"
  port: 6379
  db: 0

# Configuration API
api:
  host: "0.0.0.0"
  port: 8000
  secret_key: "your-super-secret-key-change-in-production"
  cors_origins:
    - "http://localhost:3000"
    - "https://your-domain.com"

# Configuration des scans
scanning:
  max_concurrent_scans: 5
  default_timeout: 30
  max_scan_duration: 3600  # 1 heure
  
# Configuration email (pour notifications)
email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  username: "your-email@gmail.com"
  password: "your-app-password"

# Configuration sécurité
security:
  jwt_expiry: 86400  # 24 heures
  password_min_length: 8
  rate_limiting:
    enabled: true
    requests_per_minute: 60
```

### Initialisation de la base de données

```bash
# Créer les tables
python scripts/init_db.py

# Créer un utilisateur admin
python scripts/create_admin.py --username admin --email admin@example.com
```

---

## Architecture

### Vue d'ensemble des composants

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (React)                        │
├─────────────────────────────────────────────────────────────┤
│                    API REST (FastAPI)                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Programme     │  │    Rapports     │  │   Scanners   │ │
│  │   Manager       │  │   Manager       │  │   Engine     │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   PostgreSQL    │  │     Redis       │  │   Celery     │ │
│  │   Database      │  │     Cache       │  │   Tasks      │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Modules principaux

1. **platform/bounty_program.py** - Gestion des programmes de bug bounty
2. **platform/vulnerability_reports.py** - Gestion des rapports de vulnérabilités
3. **scanners/web_scanner.py** - Scanner de vulnérabilités web
4. **scanners/network_scanner.py** - Scanner de vulnérabilités réseau
5. **scanners/scan_engine.py** - Orchestrateur de scans
6. **api/main_api.py** - API REST principale

---

## API Documentation

### Authentification

Toutes les requêtes API (sauf `/health` et `/auth/login`) nécessitent un token d'authentification Bearer.

```bash
# Login
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Réponse
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "user": {
    "user_id": "admin_1",
    "username": "admin",
    "role": "admin",
    "permissions": ["all"]
  }
}

# Utilisation du token
curl -X GET "http://localhost:8000/programs" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Endpoints principaux

#### Gestion des programmes

```bash
# Créer un programme
POST /programs
{
  "name": "Programme Web Sécurité",
  "organization_id": "org_123",
  "description": "Programme de bug bounty pour notre application web",
  "total_budget": 50000.0,
  "private_program": false,
  "contact_email": "security@example.com"
}

# Lister les programmes
GET /programs?status=active&public_only=true

# Obtenir un programme
GET /programs/{program_id}

# Activer un programme
POST /programs/{program_id}/activate

# Ajouter un élément au scope
POST /programs/{program_id}/scope
{
  "scope_type": "web_application",
  "target": "https://app.example.com",
  "description": "Application web principale",
  "max_severity": "critical"
}
```

#### Gestion des rapports

```bash
# Soumettre un rapport
POST /reports
{
  "program_id": "prog_123",
  "title": "Injection SQL dans le formulaire de login",
  "description": "Le paramètre username est vulnérable...",
  "vulnerability_type": "sql_injection",
  "severity": "high",
  "affected_url": "https://app.example.com/login",
  "affected_parameter": "username",
  "proof_of_concept": "' OR 1=1 --"
}

# Lister les rapports
GET /reports?program_id=prog_123&status=submitted&limit=50

# Obtenir un rapport
GET /reports/{report_id}

# Valider un rapport
POST /reports/{report_id}/validate
{
  "result": "confirmed",
  "notes": "Vulnérabilité confirmée avec impact élevé",
  "step_name": "technical_validation"
}

# Ajouter un commentaire
POST /reports/{report_id}/comments
{
  "content": "Merci pour ce rapport détaillé",
  "is_internal": false
}
```

#### Gestion des scans

```bash
# Lancer un scan
POST /scans
{
  "scan_type": "web",
  "target": "https://example.com",
  "name": "Scan sécurité hebdomadaire",
  "web_depth": 3,
  "web_max_pages": 100
}

# Lister les scans
GET /scans?limit=20

# Obtenir le statut d'un scan
GET /scans/{scan_id}

# Obtenir le rapport de scan
GET /scans/{scan_id}/report?format=json
```

#### Statistiques

```bash
# Statistiques d'un programme
GET /stats/programs/{program_id}

# Statistiques d'un chercheur
GET /stats/researchers/{researcher_id}
```

#### Recherche

```bash
# Rechercher des programmes
GET /search/programs?q=web&min_reward=1000

# Rechercher des rapports
GET /search/reports?q=injection&severity=high&limit=20
```

---

## Utilisation des scanners

### Scanner Web

Le scanner web détecte automatiquement les vulnérabilités OWASP Top 10 :

```python
from scanners.web_scanner import WebScanner, ScanTarget

# Configuration du scan
target = ScanTarget(
    url="https://example.com",
    depth=3,
    max_pages=100,
    include_subdomains=True,
    custom_headers={"User-Agent": "BugBountyScanner/1.0"}
)

# Exécution du scan
scanner = WebScanner()
vulnerabilities = await scanner.scan_target(target)

# Génération du rapport
report = scanner.generate_report("json")
```

### Scanner Réseau

Le scanner réseau effectue la découverte d'hôtes et l'analyse des services :

```python
from scanners.network_scanner import NetworkScanner, NetworkTarget

# Configuration du scan
target = NetworkTarget(
    target="192.168.1.0/24",
    ports=[22, 80, 443, 3389],
    service_detection=True,
    version_detection=True
)

# Exécution du scan
scanner = NetworkScanner()
services, vulnerabilities = await scanner.scan_network(target)
```

### Moteur de Scan Unifié

Le moteur de scan orchestre plusieurs types de scans :

```python
from scanners.scan_engine import ScanEngine, ScanConfiguration, ScanType

# Démarrage du moteur
engine = ScanEngine()
await engine.start_engine()

# Configuration d'un scan combiné
config = ScanConfiguration(
    scan_id="scan_001",
    scan_type=ScanType.COMBINED,
    target="example.com",
    web_depth=2,
    service_detection=True
)

# Soumission du scan
scan_id = await engine.submit_scan(config)

# Suivi du scan
result = await engine.get_scan_status(scan_id)
```

---

## Gestion des programmes

### Création d'un programme complet

```python
from platform.bounty_program import (
    ProgramManager, ScopeItem, ScopeType, 
    VulnSeverity, RewardTier
)
from decimal import Decimal

manager = ProgramManager()

# 1. Créer le programme
program = manager.create_program(
    name="Programme Sécurité Web Acme",
    organization_id="org_acme",
    description="Programme de bug bounty pour tous nos actifs web",
    total_budget=Decimal('100000.00'),
    contact_email="security@acme.com"
)

# 2. Définir le scope
web_scope = ScopeItem(
    scope_id="",
    scope_type=ScopeType.WEB_APPLICATION,
    target="*.acme.com",
    description="Toutes les applications web du domaine acme.com",
    max_severity=VulnSeverity.CRITICAL
)

api_scope = ScopeItem(
    scope_id="",
    scope_type=ScopeType.API,
    target="api.acme.com",
    description="API REST principale",
    max_severity=VulnSeverity.HIGH,
    excluded_vulnerabilities=["rate_limiting"]
)

manager.add_scope_item(program.program_id, web_scope)
manager.add_scope_item(program.program_id, api_scope)

# 3. Configurer les récompenses
manager.update_reward_tier(
    program.program_id, 
    VulnSeverity.CRITICAL, 
    Decimal('10000.00'), 
    Decimal('25000.00')
)

# 4. Activer le programme
manager.activate_program(program.program_id)
```

### Métriques et analytics

```python
# Obtenir les métriques du programme
metrics = manager.get_program_metrics(program_id)
print(f"Taux de validité: {metrics['validity_rate']:.2%}")
print(f"Budget utilisé: {metrics['budget_utilization']:.2%}")
print(f"Temps de réponse moyen: {metrics['average_response_time']:.1f}h")

# Recherche de programmes
results = manager.search_programs("web", {"min_reward": 5000})
for program in results:
    print(f"{program.name}: {program.total_submissions} soumissions")
```

---

## Soumission de rapports

### Cycle de vie d'un rapport

```python
from platform.vulnerability_reports import (
    ReportManager, VulnerabilityType, Severity, 
    ValidationResult
)

manager = ReportManager()

# 1. Soumission du rapport
report = manager.submit_report(
    program_id="prog_123",
    researcher_id="researcher_456",
    title="Injection SQL critique",
    description="Vulnérabilité d'injection SQL...",
    vulnerability_type=VulnerabilityType.SQL_INJECTION,
    severity=Severity.CRITICAL,
    affected_url="https://example.com/login",
    proof_of_concept="' OR 1=1 --"
)

# 2. Assignment à un triager
manager.assign_triager(report.report_id, "triager_789")

# 3. Ajout de commentaires
manager.add_comment(
    report.report_id,
    "triager_789",
    "triager",
    "Reproduction en cours..."
)

# 4. Validation
manager.validate_report(
    report.report_id,
    "triager_789",
    ValidationResult.CONFIRMED,
    "Vulnérabilité confirmée avec impact critique"
)

# 5. Attribution de récompense
manager.set_reward(report.report_id, Decimal('15000.00'))
manager.pay_reward(report.report_id, "admin_1")
```

### Statistiques des chercheurs

```python
# Obtenir les statistiques d'un chercheur
stats = manager.get_researcher_stats("researcher_456")

print(f"Rapports total: {stats['total_reports']}")
print(f"Rapports valides: {stats['valid_reports']}")
print(f"Taux de validité: {stats['validity_rate']:.2%}")
print(f"Récompenses totales: ${stats['total_rewards']}")
print(f"Récompense moyenne: ${stats['average_reward']}")

# Répartition par sévérité
for severity, count in stats['severity_breakdown'].items():
    print(f"{severity.title()}: {count} rapports")
```

---

## Exemples d'utilisation

### Cas d'usage 1: Scan automatisé quotidien

```python
import asyncio
from datetime import datetime, timedelta
from scanners.scan_engine import ScanEngine, ScanConfiguration, ScanType

async def daily_security_scan():
    """Scan automatisé quotidien des actifs critiques"""
    engine = ScanEngine()
    await engine.start_engine()
    
    # Assets critiques à scanner
    critical_assets = [
        "https://app.example.com",
        "https://api.example.com", 
        "https://admin.example.com"
    ]
    
    scan_ids = []
    for asset in critical_assets:
        config = ScanConfiguration(
            scan_id=f"daily_{asset.split('//')[1]}_{datetime.now().strftime('%Y%m%d')}",
            scan_type=ScanType.WEB,
            target=asset,
            name=f"Scan quotidien {asset}",
            web_depth=2,
            web_max_pages=50,
            # Programmer pour 2h du matin
            scheduled_time=datetime.now().replace(hour=2, minute=0, second=0) + timedelta(days=1),
            recurring=True,
            recurring_interval=timedelta(days=1)
        )
        
        scan_id = await engine.submit_scan(config)
        scan_ids.append(scan_id)
    
    print(f"Programmé {len(scan_ids)} scans quotidiens")
    return scan_ids

# Exécution
asyncio.run(daily_security_scan())
```

### Cas d'usage 2: Programme de bug bounty avec validation automatique

```python
from platform.bounty_program import ProgramManager, ScopeItem, ScopeType
from platform.vulnerability_reports import ReportManager
from scanners.scan_engine import ScanEngine

async def automated_bug_bounty_program():
    """Programme de bug bounty avec validation automatique"""
    
    # 1. Créer le programme
    prog_manager = ProgramManager()
    program = prog_manager.create_program(
        name="Programme FinTech Sécurisé",
        organization_id="fintech_corp",
        description="Bug bounty pour notre plateforme financière",
        total_budget=Decimal('200000.00'),
        auto_validate_scans=True,  # Validation auto des scans
        allow_automated_scanning=True
    )
    
    # 2. Configurer le scope avec scan automatique
    api_scope = ScopeItem(
        scope_id="",
        scope_type=ScopeType.API,
        target="api.fintech.com",
        description="API de trading avec scan automatique quotidien"
    )
    prog_manager.add_scope_item(program.program_id, api_scope)
    
    # 3. Lancer scan de baseline
    scan_engine = ScanEngine()
    await scan_engine.start_engine()
    
    baseline_config = ScanConfiguration(
        scan_id="baseline_api_scan",
        scan_type=ScanType.COMBINED,
        target="api.fintech.com",
        name="Scan de baseline API"
    )
    
    scan_id = await scan_engine.submit_scan(baseline_config)
    
    # 4. Attendre les résultats et créer des rapports automatiques
    await asyncio.sleep(60)  # Attendre la fin du scan
    
    scan_result = await scan_engine.get_scan_status(scan_id)
    if scan_result and scan_result.status == ScanStatus.COMPLETED:
        
        report_manager = ReportManager()
        
        # Créer des rapports automatiques pour les vulnérabilités critiques
        for vuln in scan_result.web_vulnerabilities:
            if vuln.severity == "Critical":
                report = report_manager.submit_report(
                    program_id=program.program_id,
                    researcher_id="auto_scanner",
                    title=f"[AUTO] {vuln.name}",
                    description=vuln.description,
                    vulnerability_type=VulnerabilityType.OTHER,  # Mapping requis
                    severity=Severity.CRITICAL,
                    affected_url=vuln.url,
                    proof_of_concept=vuln.payload,
                    auto_scan_generated=True,
                    scan_correlation_id=scan_id
                )
                
                # Auto-assignment au triager principal
                report_manager.assign_triager(report.report_id, "senior_triager")
    
    print(f"Programme lancé: {program.program_id}")
    print(f"Scan baseline: {scan_id}")

asyncio.run(automated_bug_bounty_program())
```

### Cas d'usage 3: Dashboard de métriques temps réel

```python
import asyncio
from datetime import datetime, timedelta

async def security_dashboard():
    """Dashboard de métriques de sécurité temps réel"""
    
    prog_manager = ProgramManager()
    report_manager = ReportManager()
    scan_engine = ScanEngine()
    
    # Récupérer toutes les données
    programs = prog_manager.list_programs(status=ProgramStatus.ACTIVE)
    
    dashboard_data = {
        "timestamp": datetime.now().isoformat(),
        "programs": [],
        "global_stats": {
            "total_programs": len(programs),
            "total_reports": 0,
            "total_rewards": 0,
            "active_scans": 0
        },
        "recent_activity": []
    }
    
    # Analyser chaque programme
    for program in programs:
        prog_stats = report_manager.get_program_stats(program.program_id)
        prog_metrics = prog_manager.get_program_metrics(program.program_id)
        
        program_data = {
            "program_id": program.program_id,
            "name": program.name,
            "status": program.status.value,
            "reports": prog_stats.get('total_reports', 0),
            "valid_reports": prog_stats.get('valid_reports', 0),
            "rewards_paid": float(program.total_rewards_paid),
            "budget_remaining": float(program.budget_remaining or 0),
            "response_time": prog_metrics.get('average_response_time', 0)
        }
        
        dashboard_data["programs"].append(program_data)
        dashboard_data["global_stats"]["total_reports"] += program_data["reports"]
        dashboard_data["global_stats"]["total_rewards"] += program_data["rewards_paid"]
    
    # Scans actifs
    active_scans = await scan_engine.list_active_scans()
    dashboard_data["global_stats"]["active_scans"] = len(active_scans)
    
    # Activité récente (dernières 24h)
    yesterday = datetime.now() - timedelta(hours=24)
    for program in programs:
        recent_reports = report_manager.list_reports(
            program_id=program.program_id,
            limit=10
        )
        
        for report in recent_reports:
            if report.submitted_date >= yesterday:
                dashboard_data["recent_activity"].append({
                    "type": "report_submitted",
                    "program": program.name,
                    "title": report.title,
                    "severity": report.severity.value,
                    "timestamp": report.submitted_date.isoformat()
                })
    
    # Trier l'activité récente
    dashboard_data["recent_activity"].sort(
        key=lambda x: x["timestamp"], 
        reverse=True
    )
    
    return dashboard_data

# Utilisation avec mise à jour automatique
async def live_dashboard():
    """Dashboard avec mise à jour automatique"""
    while True:
        try:
            data = await security_dashboard()
            print(f"\n🔒 SECURITY DASHBOARD - {data['timestamp']}")
            print("=" * 50)
            
            print(f"📊 Programmes actifs: {data['global_stats']['total_programs']}")
            print(f"📝 Rapports totaux: {data['global_stats']['total_reports']}")
            print(f"💰 Récompenses payées: ${data['global_stats']['total_rewards']:,.2f}")
            print(f"🔍 Scans actifs: {data['global_stats']['active_scans']}")
            
            print(f"\n📈 TOP PROGRAMMES:")
            for prog in sorted(data['programs'], key=lambda x: x['reports'], reverse=True)[:3]:
                print(f"  • {prog['name']}: {prog['reports']} rapports, ${prog['rewards_paid']:,.2f}")
            
            print(f"\n⚡ ACTIVITÉ RÉCENTE:")
            for activity in data['recent_activity'][:5]:
                print(f"  • {activity['program']}: {activity['title']} ({activity['severity']})")
            
            # Attendre 30 secondes avant la prochaine mise à jour
            await asyncio.sleep(30)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Erreur dashboard: {e}")
            await asyncio.sleep(5)

# Lancement du dashboard
asyncio.run(live_dashboard())
```

---

## Déploiement

### Déploiement avec Docker

Créez un `Dockerfile` :

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier l'application
COPY . .

# Exposer le port
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "api.main_api:app", "--host", "0.0.0.0", "--port", "8000"]
```

Et un `docker-compose.yml` :

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://bugbounty:password@db:5432/bugbounty_db
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./config:/app/config

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=bugbounty_db
      - POSTGRES_USER=bugbounty
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    volumes:
      - redis_data:/data

  worker:
    build: .
    command: celery -A api.main_api worker --loglevel=info
    depends_on:
      - db
      - redis
    volumes:
      - ./config:/app/config

volumes:
  postgres_data:
  redis_data:
```

### Déploiement sur AWS/Cloud

```bash
# Build et push de l'image
docker build -t bugbounty-platform .
docker tag bugbounty-platform your-registry/bugbounty-platform:latest
docker push your-registry/bugbounty-platform:latest

# Déploiement avec Kubernetes
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

### Configuration de production

```yaml
# config/production.yaml
api:
  debug: false
  cors_origins:
    - "https://yourdomain.com"
  rate_limiting:
    enabled: true
    requests_per_minute: 30

security:
  jwt_secret: "your-production-secret-key-very-long-and-secure"
  password_min_length: 12
  require_2fa: true

logging:
  level: "INFO"
  file: "/var/log/bugbounty/app.log"
  
monitoring:
  sentry_dsn: "https://your-sentry-dsn"
  prometheus_enabled: true
```

---

## Troubleshooting

### Problèmes courants

#### Erreur de connexion à la base de données

```bash
# Vérifier la connexion PostgreSQL
pg_isready -h localhost -p 5432

# Tester la connexion
psql -h localhost -U bugbounty -d bugbounty_db -c "SELECT 1;"

# Vérifier les logs
tail -f /var/log/postgresql/postgresql-15-main.log
```

#### Problèmes de scan réseau

```bash
# Vérifier que nmap est installé
nmap --version

# Tester un scan simple
nmap -sn 127.0.0.1

# Permissions pour scan réseau (si nécessaire)
sudo setcap cap_net_raw+eip /usr/bin/nmap
```

#### Problèmes de performance

```bash
# Monitoring des ressources
htop
iotop

# Monitoring de l'API
curl http://localhost:8000/health

# Logs de l'application
tail -f logs/app.log

# Statistiques Redis
redis-cli info stats
```

### Logs et monitoring

Configuration des logs structurés :

```python
import logging
from pythonjsonlogger import jsonlogger

# Configuration des logs JSON
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)
```

### Métriques Prometheus

Ajout de métriques personnalisées :

```python
from prometheus_client import Counter, Histogram, start_http_server

# Métriques personnalisées
SCAN_COUNTER = Counter('scans_total', 'Total scans executed', ['scan_type'])
SCAN_DURATION = Histogram('scan_duration_seconds', 'Scan duration')
REPORT_COUNTER = Counter('reports_total', 'Total reports submitted', ['severity'])

# Démarrer le serveur de métriques
start_http_server(8001)
```

---

## Support et contribution

### Signaler un bug

1. Vérifiez que le bug n'est pas déjà signalé dans les [Issues](https://github.com/votre-org/bug-bounty-platform/issues)
2. Créez une nouvelle issue avec :
   - Description détaillée du problème
   - Étapes pour reproduire
   - Logs d'erreur
   - Environnement (OS, Python version, etc.)

### Contribuer

1. Fork le repository
2. Créez une branche feature (`git checkout -b feature/amazing-feature`)
3. Committez vos changements (`git commit -m 'Add amazing feature'`)
4. Pushez vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrez une Pull Request

### Tests

```bash
# Lancer tous les tests
pytest

# Tests avec couverture
pytest --cov=. --cov-report=html

# Tests d'intégration
pytest tests/integration/

# Tests de performance
pytest tests/performance/
```

---

## Licence et sécurité

### Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

### Sécurité

- **Divulgation responsable** : Signalez les vulnérabilités de sécurité à security@example.com
- **Chiffrement** : Toutes les données sensibles sont chiffrées en base
- **Audit** : Tous les accès sont loggés et auditables
- **Conformité** : Conforme GDPR et CCPA

### Support commercial

Pour un support commercial, une formation ou des services de consultation :
- Email : contact@example.com
- Website : https://example.com/bug-bounty-platform

---

*Documentation générée automatiquement - Version 1.0.0*