# Guide d'Utilisation - Simulation d'Ingénierie Sociale

## Table des Matières

1. [Introduction](#introduction)
2. [Installation et Configuration](#installation-et-configuration)
3. [Interface Utilisateur](#interface-utilisateur)
4. [Gestion des Campagnes](#gestion-des-campagnes)
5. [Reconnaissance OSINT](#reconnaissance-osint)
6. [Templates et Personnalisation](#templates-et-personnalisation)
7. [Rapports et Analytics](#rapports-et-analytics)
8. [Bonnes Pratiques](#bonnes-pratiques)
9. [Dépannage](#dépannage)

## Introduction

La plateforme de simulation d'ingénierie sociale est un outil éducatif conçu pour sensibiliser aux techniques d'attaque sociale et tester la résilience des organisations. Ce guide vous accompagnera dans l'utilisation complète de la plateforme.

### Objectifs Pédagogiques

- **Sensibilisation** : Comprendre les mécaniques de l'ingénierie sociale
- **Formation** : Développer les réflexes de sécurité
- **Évaluation** : Mesurer le niveau de sensibilisation
- **Amélioration** : Identifier les axes de progrès

## Installation et Configuration

### Prérequis

```bash
# Vérifier Python
python3 --version  # >= 3.8

# Vérifier Git
git --version

# Vérifier Docker (optionnel)
docker --version
docker-compose --version
```

### Installation Standard

```bash
# 1. Cloner le projet
git clone https://github.com/cybersecurity-portfolio/social-engineering-simulation.git
cd social-engineering-simulation

# 2. Installation des dépendances
make setup

# 3. Configuration initiale
cp config/example.env .env
nano .env  # Configurer les variables
```

### Installation avec Docker

```bash
# Lancement complet avec Docker Compose
docker-compose up -d

# Vérification des services
docker-compose ps
```

### Configuration des Variables

```env
# Base de données
DATABASE_URL=postgresql://user:password@localhost:5432/social_engineering

# Email SMTP
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# GoPhish
GOPHISH_URL=http://localhost:3333
GOPHISH_API_KEY=your-api-key

# Sécurité
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret
```

## Interface Utilisateur

### Dashboard Principal

Le tableau de bord offre une vue d'ensemble :

- **Campagnes actives** : Statut en temps réel
- **Métriques globales** : Taux de succès, tendances
- **Alertes** : Notifications importantes
- **Raccourcis** : Actions fréquentes

### Navigation

```
┌─ Dashboard
├─ Campagnes
│  ├─ Nouvelle campagne
│  ├─ Campagnes actives
│  └─ Historique
├─ OSINT
│  ├─ Reconnaissance
│  └─ Profils cibles
├─ Templates
│  ├─ Emails
│  ├─ Pages de destination
│  └─ Documents
└─ Rapports
   ├─ Analytics
   └─ Exports
```

## Gestion des Campagnes

### Création d'une Campagne

#### 1. Via l'Interface Web

```http
POST /api/campaigns
Content-Type: application/json

{
  "name": "Campagne Sensibilisation Q1",
  "type": "phishing",
  "targets": [
    {
      "email": "john.doe@company.com",
      "first_name": "John",
      "last_name": "Doe",
      "position": "Manager"
    }
  ],
  "template_id": "template-001",
  "schedule": "2024-02-01T09:00:00Z"
}
```

#### 2. Via la Ligne de Commande

```bash
# Création interactive
make campaign-create

# Création avec paramètres
python src/phishing/campaign_manager.py \
  --create \
  --name "Test Campaign" \
  --type phishing \
  --targets targets.csv \
  --template email-template.json
```

### Types de Campagnes

#### Phishing Email

```python
# Configuration spécialisée
campaign_config = {
    "type": "phishing",
    "sender": {
        "name": "IT Support",
        "email": "support@company.com"
    },
    "template": "urgent-update",
    "landing_page": "fake-login",
    "tracking": {
        "email_open": True,
        "link_click": True,
        "credential_harvest": True
    }
}
```

#### Vishing (Voice Phishing)

```python
# Configuration pour campagne téléphonique
vishing_config = {
    "type": "vishing",
    "scenario": "it-support-password-reset",
    "caller_id": "+1-555-IT-HELP",
    "script": "scripts/it-support-reset.txt",
    "success_criteria": ["personal_info", "credentials", "remote_access"]
}
```

#### Campagne Combinée

```python
# Multi-vecteur
combined_config = {
    "type": "combined",
    "phases": [
        {
            "phase": 1,
            "type": "osint",
            "duration": "2 days"
        },
        {
            "phase": 2,
            "type": "phishing",
            "trigger": "osint_complete"
        },
        {
            "phase": 3,
            "type": "vishing",
            "trigger": "email_clicked"
        }
    ]
}
```

### Gestion des Cibles

#### Import en Lot

```csv
# targets.csv
email,first_name,last_name,position,department,phone
john.doe@company.com,John,Doe,Manager,IT,+1234567890
jane.smith@company.com,Jane,Smith,Analyst,Finance,+1234567891
```

```python
# Import programmatique
from src.phishing.campaign_manager import CampaignManager

manager = CampaignManager()
targets = manager.import_targets_from_csv("targets.csv")
```

#### Segmentation

```python
# Groupes de cibles
target_groups = {
    "executives": {
        "filter": {"position": ["CEO", "CTO", "CFO"]},
        "template": "executive-template",
        "priority": "high"
    },
    "it_staff": {
        "filter": {"department": "IT"},
        "template": "technical-template",
        "exclusions": ["admin", "security"]
    },
    "general": {
        "filter": {},
        "template": "general-template"
    }
}
```

## Reconnaissance OSINT

### Collecte d'Informations

#### Profil d'Entreprise

```bash
# Via la ligne de commande
make osint-company
# Saisir: example.com

# Via Python
python src/osint/social_recon.py \
  --company \
  --domain example.com \
  --output results/company_profile.json
```

#### Profil Personnel

```bash
# Reconnaissance individuelle
python src/osint/social_recon.py \
  --person \
  --name "John Doe" \
  --company "Example Corp" \
  --linkedin-profile "john-doe-123456" \
  --output results/john_doe_profile.json
```

### Sources d'Information

#### Réseaux Sociaux

```python
# Configuration LinkedIn
linkedin_config = {
    "api_key": "your-api-key",
    "search_params": {
        "company": "target-company",
        "keywords": ["manager", "director", "VP"],
        "location": "New York"
    }
}

# Configuration Twitter
twitter_config = {
    "api_key": "your-api-key",
    "search_terms": ["@company", "#company", "company employees"],
    "filters": ["verified", "location", "bio_keywords"]
}
```

#### Sites Web

```python
# Scraping configuré
web_scraping = {
    "targets": [
        "https://company.com/about",
        "https://company.com/team",
        "https://company.com/news"
    ],
    "extract": {
        "employees": {
            "selector": ".team-member",
            "fields": ["name", "position", "email", "bio"]
        },
        "contact_info": {
            "selector": ".contact-info",
            "fields": ["phone", "email", "address"]
        }
    }
}
```

### Analyse et Enrichissement

```python
# Pipeline d'enrichissement
enrichment_pipeline = [
    {
        "stage": "email_discovery",
        "sources": ["website", "social_media", "public_directories"]
    },
    {
        "stage": "social_mapping",
        "sources": ["linkedin", "twitter", "facebook"]
    },
    {
        "stage": "relationship_analysis",
        "algorithm": "social_graph"
    },
    {
        "stage": "vulnerability_assessment",
        "checks": ["public_info", "social_habits", "security_awareness"]
    }
]
```

## Templates et Personnalisation

### Templates d'Email

#### Structure Basique

```json
{
  "name": "Mise à jour urgente",
  "subject": "Action requise : Mise à jour de sécurité",
  "sender": {
    "name": "IT Security Team",
    "email": "security@{{company_domain}}"
  },
  "html_content": "templates/security-update.html",
  "text_content": "templates/security-update.txt",
  "variables": {
    "user_name": "{{first_name}}",
    "company_name": "{{company}}",
    "urgency_level": "High"
  },
  "attachments": [
    {
      "name": "Security_Update.pdf",
      "type": "application/pdf",
      "malicious": false
    }
  ]
}
```

#### Template HTML Avancé

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{{subject}}</title>
    <style>
        .header { background: #0066cc; color: white; padding: 20px; }
        .urgent { color: #ff0000; font-weight: bold; }
        .button { 
            background: #ff6600; 
            color: white; 
            padding: 15px 30px; 
            text-decoration: none; 
            border-radius: 5px; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{company_name}} IT Security</h1>
    </div>
    
    <p>Bonjour {{first_name}},</p>
    
    <p class="urgent">
        URGENT: Votre compte nécessite une mise à jour de sécurité immédiate.
    </p>
    
    <p>
        Nous avons détecté une activité suspecte sur votre compte. 
        Pour votre sécurité, veuillez cliquer sur le lien ci-dessous 
        pour vérifier votre identité dans les <strong>24 heures</strong>.
    </p>
    
    <p style="text-align: center; margin: 30px 0;">
        <a href="{{phishing_link}}?user={{email}}&token={{tracking_token}}" 
           class="button">
            VÉRIFIER MON COMPTE
        </a>
    </p>
    
    <p style="font-size: 12px; color: #666;">
        Ce message est automatique. Si vous avez des questions, 
        contactez le support IT à {{support_email}}.
    </p>
    
    <img src="{{tracking_pixel}}" width="1" height="1" style="display:none;">
</body>
</html>
```

### Pages de Destination

#### Page de Collecte de Credentials

```html
<!DOCTYPE html>
<html>
<head>
    <title>Connexion Sécurisée - {{company_name}}</title>
    <link rel="stylesheet" href="styles/corporate.css">
</head>
<body>
    <div class="login-container">
        <div class="company-logo">
            <img src="images/{{company_logo}}" alt="{{company_name}}">
        </div>
        
        <form id="loginForm" action="/capture" method="post">
            <h2>Vérification de Sécurité Requise</h2>
            
            <div class="alert">
                <strong>Attention :</strong> Activité suspecte détectée sur votre compte.
            </div>
            
            <div class="form-group">
                <label>Email Professionnel</label>
                <input type="email" name="username" required 
                       value="{{target_email}}" readonly>
            </div>
            
            <div class="form-group">
                <label>Mot de Passe</label>
                <input type="password" name="password" required>
            </div>
            
            <div class="form-group">
                <label>Code de Vérification (si activé)</label>
                <input type="text" name="mfa_code" placeholder="123456">
            </div>
            
            <button type="submit" class="verify-btn">
                VÉRIFIER ET SÉCURISER
            </button>
            
            <input type="hidden" name="campaign_id" value="{{campaign_id}}">
            <input type="hidden" name="target_id" value="{{target_id}}">
            <input type="hidden" name="timestamp" value="{{timestamp}}">
        </form>
    </div>
    
    <script src="js/capture.js"></script>
</body>
</html>
```

### Personnalisation Avancée

#### Variables Dynamiques

```python
# Générateur de variables contextuelles
context_generator = {
    "company_info": {
        "domain": "auto_detect",
        "logo": "scraped_from_website",
        "colors": "brand_colors_api",
        "terminology": "company_specific_terms"
    },
    "personal_info": {
        "name": "target_database",
        "position": "linkedin_profile",
        "manager": "org_chart_analysis",
        "interests": "social_media_analysis"
    },
    "temporal": {
        "current_date": "auto",
        "business_hours": "timezone_aware",
        "recent_events": "news_api"
    }
}
```

## Rapports et Analytics

### Dashboard Temps Réel

#### Métriques Principales

```python
# KPIs en temps réel
real_time_metrics = {
    "campaign_status": {
        "active_campaigns": 5,
        "total_targets": 250,
        "emails_sent": 180,
        "pending": 70
    },
    "engagement_rates": {
        "email_open_rate": 0.73,
        "link_click_rate": 0.45,
        "credential_harvest_rate": 0.12,
        "awareness_rate": 0.31  # Utilisateurs ayant signalé
    },
    "security_posture": {
        "vulnerability_score": 6.5,  # Sur 10
        "improvement_trend": "+15%",
        "risk_level": "Medium"
    }
}
```

#### Visualisations

```python
# Configuration des graphiques
dashboard_charts = {
    "timeline": {
        "type": "line_chart",
        "data": "campaign_progress",
        "x_axis": "time",
        "y_axis": ["emails_sent", "clicks", "reports"],
        "real_time": True
    },
    "demographic_breakdown": {
        "type": "pie_chart",
        "data": "target_segments",
        "categories": ["department", "seniority", "location"]
    },
    "success_heatmap": {
        "type": "heatmap",
        "data": "success_by_criteria",
        "dimensions": ["time_of_day", "day_of_week", "campaign_type"]
    }
}
```

### Rapports Détaillés

#### Rapport de Campagne

```python
# Génération de rapport
report_config = {
    "campaign_id": "CAMP-2024-001",
    "format": "html",  # ou "pdf", "json"
    "sections": [
        "executive_summary",
        "campaign_details",
        "target_analysis",
        "timeline",
        "metrics_breakdown",
        "vulnerabilities_identified",
        "recommendations",
        "appendices"
    ],
    "include_charts": True,
    "anonymize_targets": False  # Pour rapports internes
}
```

#### Templates de Rapport

```html
<!-- Résumé Exécutif -->
<section id="executive-summary">
    <h2>Résumé Exécutif</h2>
    
    <div class="key-metrics">
        <div class="metric">
            <h3>{{success_rate}}%</h3>
            <p>Taux de succès global</p>
        </div>
        <div class="metric">
            <h3>{{targets_compromised}}</h3>
            <p>Utilisateurs vulnérables</p>
        </div>
        <div class="metric">
            <h3>{{awareness_level}}%</h3>
            <p>Niveau de sensibilisation</p>
        </div>
    </div>
    
    <div class="risk-assessment">
        <h3>Évaluation des Risques</h3>
        <p>
            L'organisation présente un niveau de risque <strong>{{risk_level}}</strong> 
            face aux attaques d'ingénierie sociale. Les points critiques identifiés 
            nécessitent une attention immédiate.
        </p>
    </div>
</section>
```

### Export et Intégration

#### Formats d'Export

```bash
# Export CSV pour analyse
python tools/export_results.py \
  --campaign CAMP-2024-001 \
  --format csv \
  --output results/campaign_data.csv

# Export JSON pour intégrations
python tools/export_results.py \
  --campaign CAMP-2024-001 \
  --format json \
  --include-metadata \
  --output api/campaign_results.json
```

#### Intégration SIEM

```python
# Envoi vers SIEM
siem_integration = {
    "endpoint": "https://siem.company.com/api/events",
    "format": "CEF",  # Common Event Format
    "events": [
        {
            "timestamp": "2024-01-28T10:30:00Z",
            "severity": "High",
            "category": "Social Engineering",
            "event_type": "Credential Harvest",
            "source_ip": "192.168.1.100",
            "user": "john.doe@company.com",
            "details": {
                "campaign_id": "CAMP-2024-001",
                "target_group": "managers",
                "success": True
            }
        }
    ]
}
```

## Bonnes Pratiques

### Considérations Éthiques

#### Consentement et Autorisation

```python
# Framework de consentement
consent_framework = {
    "required_approvals": [
        "management_authorization",
        "hr_approval",
        "legal_review",
        "ethics_committee"
    ],
    "participant_rights": {
        "informed_consent": True,
        "opt_out_mechanism": True,
        "data_protection": "GDPR_compliant",
        "result_anonymization": True
    },
    "documentation": {
        "authorization_form": "docs/authorization.pdf",
        "consent_process": "docs/consent_procedure.md",
        "data_handling": "docs/data_policy.md"
    }
}
```

#### Limites et Restrictions

```yaml
# Configuration des limites
campaign_limits:
  max_targets_per_campaign: 500
  max_concurrent_campaigns: 10
  cooling_off_period: "30 days"
  
target_protection:
  exclude_sensitive_roles:
    - "HR Director"
    - "Legal Counsel" 
    - "Executive Assistant"
  
  vulnerable_groups:
    - "New employees (< 30 days)"
    - "Medical leave returnees"
    - "High-stress departments"

content_restrictions:
  prohibited_themes:
    - "Medical emergencies"
    - "Legal threats"
    - "Family emergencies"
    - "Financial penalties"
```

### Sécurité Opérationnelle

#### Protection des Données

```python
# Chiffrement et protection
data_protection = {
    "encryption": {
        "at_rest": "AES-256",
        "in_transit": "TLS 1.3",
        "key_management": "HSM"
    },
    "access_control": {
        "authentication": "multi_factor",
        "authorization": "role_based",
        "session_management": "secure_tokens"
    },
    "audit_logging": {
        "all_actions": True,
        "retention_period": "7 years",
        "tamper_protection": True
    }
}
```

#### Isolation de l'Environnement

```bash
# Environnement isolé
docker network create --driver bridge social-eng-isolated

# Configuration réseau
iptables -A OUTPUT -p tcp --dport 25 -j DROP  # Bloquer SMTP sortant
iptables -A OUTPUT -p tcp --dport 587 -j DROP # Bloquer SMTP TLS
iptables -A OUTPUT -p tcp --dport 465 -j DROP # Bloquer SMTP SSL
```

### Gestion des Incidents

#### Réponse aux Signalements

```python
# Workflow de signalement
incident_response = {
    "detection": {
        "user_reports": "automatic_handling",
        "suspicious_activity": "alert_security_team",
        "system_anomalies": "immediate_investigation"
    },
    "classification": {
        "false_positive": "update_training",
        "legitimate_concern": "security_review", 
        "actual_breach": "incident_response_plan"
    },
    "escalation": {
        "severity_levels": ["Low", "Medium", "High", "Critical"],
        "notification_matrix": "stakeholder_matrix.yaml",
        "response_times": "sla_definitions.yaml"
    }
}
```

## Dépannage

### Problèmes Courants

#### Échecs d'Envoi d'Email

```bash
# Diagnostic SMTP
python tools/test_smtp.py --config config/email.yaml

# Vérification des logs
tail -f logs/email_sender.log

# Test de connectivité
telnet smtp.gmail.com 587
```

#### Problèmes de Base de Données

```bash
# Test de connexion
python -c "from src.database import test_connection; test_connection()"

# Migration de schéma
alembic upgrade head

# Réparation d'index
python tools/repair_database.py --rebuild-indexes
```

#### Problèmes de Performance

```bash
# Monitoring des ressources
python tools/performance_monitor.py --duration 300

# Optimisation de la base de données
python tools/optimize_database.py --analyze --vacuum

# Nettoyage des logs
find logs/ -name "*.log" -mtime +30 -delete
```

### Support et Contact

#### Ressources d'Aide

- **Documentation** : [docs/](docs/)
- **FAQ** : [docs/faq.md](docs/faq.md)
- **Tickets** : GitHub Issues
- **Email** : support@cybersecurity-portfolio.com

#### Logs de Débogage

```bash
# Activation du mode debug
export FLASK_DEBUG=1
export LOG_LEVEL=DEBUG

# Collecte des logs pour support
python tools/collect_logs.py --package-for-support
```

---

**Note de Sécurité** : Cette plateforme est exclusivement destinée à des fins éducatives et de formation en cybersécurité dans un cadre légal et éthique. Toute utilisation malveillante est strictement interdite.