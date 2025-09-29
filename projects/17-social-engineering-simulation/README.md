# 🎭 Projet 17 - Social Engineering Simulation

## 📋 Vue d'Ensemble

**Plateforme complète de simulation d'ingénierie sociale pour la sensibilisation et l'évaluation de la sécurité humaine**

Ce projet développe un environnement complet de simulation d'attaques d'ingénierie sociale, incluant des campagnes de phishing, vishing, prétexting et sensibilisation à la sécurité. Il combine des outils professionnels comme GoPhish et SET avec des modules personnalisés pour créer des scénarios réalistes et mesurer la résilience humaine face aux techniques de manipulation sociale.

### 🎯 Objectifs
- Développer une plateforme complète de simulation d'ingénierie sociale
- Créer des campagnes de sensibilisation personnalisées et réalistes
- Mesurer et analyser la vulnérabilité humaine aux attaques sociales
- Automatiser les tests de phishing, vishing et prétexting
- Générer des rapports détaillés et des recommandations d'amélioration
- Former les équipes aux techniques de détection et de prévention

### 🔬 Domaines Couverts
- **Phishing Campaigns** : Email, SMS, et campagnes web personnalisées
- **Vishing Attacks** : Simulation d'appels d'ingénierie sociale
- **Physical Security** : Tests d'accès physique et badge cloning
- **Pretexting Scenarios** : Création de fausses identités et scénarios
- **Social Media OSINT** : Reconnaissance sur réseaux sociaux
- **Awareness Training** : Modules de formation interactive
- **Psychological Profiling** : Analyse des vulnérabilités psychologiques
- **Incident Response** : Procédures de réaction aux attaques sociales

## 🏗️ Architecture du Projet

```
17-social-engineering-simulation/
├── README.md                    # Documentation principale
├── src/                         # Code source des outils
│   ├── phishing/               # Modules de phishing
│   │   ├── campaign_manager.py # Gestionnaire de campagnes
│   │   ├── template_engine.py  # Générateur de templates
│   │   ├── target_profiler.py  # Profilage des cibles
│   │   └── metrics_analyzer.py # Analyse des métriques
│   ├── vishing/                # Simulation d'appels
│   │   ├── voice_synthesizer.py # Synthèse vocale
│   │   ├── script_generator.py # Génération de scripts
│   │   └── call_simulator.py   # Simulation d'appels
│   ├── pretexting/             # Scénarios de prétexte
│   │   ├── persona_builder.py  # Construction d'identités
│   │   ├── scenario_engine.py  # Moteur de scénarios
│   │   └── credential_faker.py # Génération de faux documents
│   ├── osint/                  # Reconnaissance sociale
│   │   ├── social_recon.py     # Reconnaissance réseaux sociaux
│   │   ├── email_harvester.py  # Collecte d'adresses email
│   │   └── company_profiler.py # Profilage d'entreprises
│   ├── training/               # Modules de formation
│   │   ├── awareness_builder.py # Création de modules
│   │   ├── quiz_generator.py   # Génération de quiz
│   │   └── simulation_runner.py # Exécution de simulations
│   └── reporting/              # Génération de rapports
│       ├── report_generator.py # Générateur principal
│       ├── dashboard_builder.py # Tableaux de bord
│       └── metrics_collector.py # Collecte de métriques
├── docs/                       # Documentation technique
│   ├── methodologies/          # Méthodologies d'ingénierie sociale
│   ├── legal-compliance/       # Conformité légale et éthique
│   ├── campaign-guides/        # Guides de campagnes
│   └── training-materials/     # Matériaux de formation
├── examples/                   # Exemples et cas d'usage
│   ├── phishing-templates/     # Templates d'emails
│   ├── vishing-scripts/        # Scripts d'appels
│   ├── pretexting-scenarios/   # Scénarios de prétexte
│   └── training-modules/       # Modules de formation
├── tools/                      # Outils d'automation
│   ├── gophish-manager/        # Interface GoPhish
│   ├── set-automation/         # Automation SET
│   ├── template-builder/       # Constructeur de templates
│   └── metrics-dashboard/      # Dashboard de métriques
├── tests/                      # Tests et validation
│   ├── unit-tests/            # Tests unitaires
│   ├── integration-tests/     # Tests d'intégration
│   └── campaign-validation/   # Validation de campagnes
├── campaigns/                 # Campagnes actives
│   ├── phishing/              # Campagnes de phishing
│   ├── vishing/               # Campagnes de vishing
│   └── combined/              # Campagnes mixtes
├── templates/                 # Templates et ressources
│   ├── email-templates/       # Templates d'emails
│   ├── landing-pages/         # Pages d'atterrissage
│   ├── documents/             # Faux documents
│   └── media/                 # Ressources multimédia
└── reports/                   # Rapports générés
    ├── campaign-results/      # Résultats de campagnes
    ├── awareness-metrics/     # Métriques de sensibilisation
    └── recommendations/       # Recommandations d'amélioration
```

## 🚀 Technologies Utilisées

### 🛠️ Frameworks et Outils Principaux
- **GoPhish** - Plateforme de phishing professionelle
- **SET (Social Engineer Toolkit)** - Framework d'ingénierie sociale
- **King Phisher** - Framework de campagnes de phishing
- **Evilginx2** - Proxy de phishing avancé
- **BeEF** - Browser Exploitation Framework
- **SpiderFoot** - Reconnaissance automatisée
- **theHarvester** - Collecte d'informations OSINT

### 🎨 Développement Web et Templates
- **Python Flask/FastAPI** - Applications web personnalisées
- **HTML/CSS/JavaScript** - Templates d'emails et pages web
- **Jinja2** - Moteur de templates avancé
- **Bootstrap** - Framework CSS responsive
- **Chart.js** - Visualisation de données
- **D3.js** - Graphiques interactifs avancés

### 🧠 Intelligence Artificielle et NLP
- **OpenAI GPT** - Génération de contenu personnalisé
- **spaCy** - Traitement du langage naturel
- **NLTK** - Analyse linguistique avancée
- **Transformers** - Modèles de langage pré-entraînés
- **TTS (Text-to-Speech)** - Synthèse vocale réaliste

### 📊 Analyse de Données et Reporting
- **Pandas** - Manipulation et analyse de données
- **NumPy** - Calculs numériques
- **Matplotlib/Seaborn** - Visualisation de données
- **Plotly** - Graphiques interactifs
- **Jupyter** - Notebooks d'analyse
- **Elasticsearch** - Stockage et recherche de logs

### 🔐 Sécurité et Anonymisation
- **Tor** - Navigation anonyme
- **VPN Integration** - Connexions sécurisées
- **Encryption Libraries** - Chiffrement des données
- **Secure Headers** - Protection des communications
- **Data Anonymization** - Anonymisation des PII

## 📚 Modules d'Apprentissage

### 1. 📧 **Phishing Campaign Management**
- Création de templates d'emails réalistes
- Personnalisation basée sur OSINT
- Tracking avancé des interactions
- A/B testing de campagnes
- Bypass des filtres anti-spam

### 2. 📞 **Vishing Simulation**
- Génération de scripts d'appels
- Synthèse vocale personnalisée
- Simulation de centres d'appels
- Recording et analyse des appels
- Formation aux techniques de vishing

### 3. 🎪 **Pretexting Scenarios**
- Construction d'identités fictives
- Scénarios d'attaque contextuels
- Génération de faux documents
- Tests d'accès physique
- Social engineering psychologique

### 4. 🕵️ **OSINT et Reconnaissance**
- Profilage automatisé de cibles
- Collecte d'informations publiques
- Analyse des réseaux sociaux
- Cartographie des relations
- Identification des vulnérabilités

### 5. 🎓 **Awareness Training**
- Modules de formation interactifs
- Simulations en temps réel
- Gamification de l'apprentissage
- Évaluation des compétences
- Certification de sensibilisation

### 6. 📈 **Analytics et Reporting**
- Métriques de performance détaillées
- Dashboards en temps réel
- Analyse comportementale
- Tendances et patterns
- ROI de la sensibilisation

### 7. ⚖️ **Compliance et Éthique**
- Conformité RGPD et légale
- Processus de consentement
- Anonymisation des données
- Audits de campagnes
- Bonnes pratiques éthiques

### 8. 🛡️ **Defense Mechanisms**
- Détection d'attaques sociales
- Systèmes d'alerte automatisés
- Formation des équipes SOC
- Incident response procedures
- Contre-mesures techniques

## 🛠️ Outils Développés

### 1. **SocialEngineer Pro** - Plateforme unifiée
```python
# Gestionnaire de campagnes d'ingénierie sociale
from socialengineer_pro import CampaignManager, TargetProfiler

campaign = CampaignManager()
campaign.create_phishing_campaign(
    name="Q4 Security Awareness Test",
    targets=["employees@company.com"],
    template="urgent_security_update",
    schedule="2024-02-01 09:00"
)

profiler = TargetProfiler()
profile = profiler.analyze_target("john.doe@company.com")
```

### 2. **PhishCraft** - Générateur de templates intelligent
```python
# Génération automatique de templates personnalisés
from phishcraft import TemplateGenerator, OSINTIntegration

generator = TemplateGenerator()
template = generator.create_email_template(
    target_company="TechCorp Inc",
    campaign_type="credential_harvesting",
    urgency_level="high",
    personalization=True
)
```

### 3. **VishingBot** - Automatisation d'appels
```python
# Simulation automatisée d'appels d'ingénierie sociale
from vishingbot import CallSimulator, ScriptGenerator

simulator = CallSimulator()
script = ScriptGenerator.create_it_support_script()
simulator.schedule_call(
    target_phone="+1234567890",
    script=script,
    voice_profile="male_professional"
)
```

### 4. **OSINT Harvester** - Collecte d'informations automatisée
```python
# Reconnaissance automatisée pour ciblage
from osint_harvester import SocialRecon, CompanyProfiler

recon = SocialRecon()
employees = recon.find_employees("techcorp.com")
profiles = recon.analyze_social_media(employees)

profiler = CompanyProfiler()
company_info = profiler.analyze_company("techcorp.com")
```

## 📖 Guides Pratiques

### 🎯 **Guide de Démarrage Rapide**
1. **Installation et configuration** de l'environnement
2. **Première campagne** de phishing basique
3. **Configuration GoPhish** et intégration
4. **Analyse des résultats** et métriques
5. **Formation des utilisateurs** ciblés

### 📋 **Méthodologies**
- **NIST Cybersecurity Framework** - Approche structurée
- **MITRE ATT&CK** - Techniques d'ingénierie sociale
- **OWASP Testing Guide** - Tests de sécurité humaine
- **Social Engineering Framework** - Méthodologie complète
- **Responsible Disclosure** - Divulgation éthique des résultats

### 🔒 **Considérations Légales et Éthiques**
- **Autorisation écrite** obligatoire pour tous les tests
- **Conformité RGPD** et protection des données
- **Consentement éclairé** des participants
- **Anonymisation** des résultats et PII
- **Usage professionnel** uniquement

## 🧪 Laboratoires Pratiques

### **Lab 1: Basic Phishing Campaign**
- Configuration de GoPhish
- Création de template simple
- Ciblage d'un groupe test
- Analyse des métriques de base

### **Lab 2: Advanced Email Spoofing**
- Configuration SPF/DKIM bypass
- Templates ultra-réalistes
- Personnalisation avancée
- Évitement des filtres anti-spam

### **Lab 3: Vishing Simulation**
- Setup d'infrastructure d'appels
- Scripts de conversation réalistes
- Enregistrement et analyse
- Formation anti-vishing

### **Lab 4: Physical Pretexting**
- Scénarios d'accès physique
- Faux badges et documents
- Tests de réception
- Formation du personnel d'accueil

### **Lab 5: Combined Attack Simulation**
- Campagne multi-vecteurs
- Coordination phishing + vishing
- Escalation d'attaques
- Response et mitigation

## 📊 Métriques et Objectifs

### 🎯 **KPIs de Campagnes**
- **Taux d'ouverture** d'emails : >30%
- **Taux de clic** sur liens : <10% (objectif de réduction)
- **Saisie de credentials** : <5% (objectif de réduction)
- **Signalement d'attaques** : >50% (objectif d'amélioration)
- **Temps de réaction** : <1h pour signalement

### 📈 **Métriques de Sensibilisation**
- **Amélioration des scores** de formation : +25%
- **Réduction des incidents** : -40% sur 6 mois
- **Temps de détection** : <5 minutes
- **Participation aux formations** : >90%
- **Certification** du personnel : 100%

## 🔗 Intégrations

### 🛠️ **Avec Autres Projets**
- **Projet 16** (Exploit Development) - Payloads d'exploitation
- **Projet 15** (Red Team Operations) - Intégration dans campagnes
- **Projet 14** (Digital Forensics) - Analyse d'incidents
- **Projet 10** (Threat Intelligence) - Enrichissement de contexte

### 🌐 **APIs et Services**
- **MISP** - Partage d'indicateurs
- **STIX/TAXII** - Threat intelligence
- **Office 365** - Intégration email
- **Active Directory** - Gestion des utilisateurs
- **SIEM Solutions** - Corrélation d'événements

## 📚 Ressources et Formation

### 📖 **Documentation de Référence**
- [Phishing Campaign Guide](docs/guides/phishing-campaign-guide.md)
- [Vishing Simulation Manual](docs/guides/vishing-simulation-manual.md)
- [OSINT Reconnaissance Guide](docs/guides/osint-reconnaissance-guide.md)
- [Legal Compliance Manual](docs/legal-compliance/compliance-manual.md)
- [Awareness Training Development](docs/training-materials/training-development.md)

### 🎓 **Certifications Recommandées**
- **SANS SEC505** - Securing Windows and PowerShell Automation
- **SEC504** - Hacker Tools, Techniques, Exploits and Incident Handling
- **Social Engineering Professional** - Social Engineer LLC
- **CISSP** - Information Security Professional
- **CEH** - Certified Ethical Hacker

### 📚 **Lectures Essentielles**
- "The Art of Deception" - Kevin Mitnick
- "Social Engineering: The Science of Human Hacking" - Christopher Hadnagy
- "Phishing Dark Waters" - Michele Fincher
- "The Psychology of Social Engineering" - Christopher Hadnagy
- "Security Awareness For Dummies" - Ira Winkler

## 🚀 Déploiement et Usage

### ⚙️ **Installation Rapide**
```bash
# Clone du repository
git clone https://github.com/your-username/social-engineering-simulation.git
cd 17-social-engineering-simulation

# Setup de l'environnement
./scripts/setup.sh

# Installation des dépendances
pip install -r requirements.txt
sudo apt-get install -f dependencies.txt

# Configuration des services
./scripts/configure-services.sh

# Démarrage des services
docker-compose up -d
```

### 🎯 **Utilisation Basique**
```python
# Exemple d'utilisation de la plateforme
from src.phishing.campaign_manager import CampaignManager
from src.osint.social_recon import SocialRecon

# Reconnaissance de la cible
recon = SocialRecon()
target_info = recon.profile_company("example.com")

# Création de campagne
campaign = CampaignManager()
campaign.create_campaign(
    name="Q1 Security Test",
    targets=target_info.employees,
    type="credential_harvesting",
    urgency="medium"
)

# Lancement et monitoring
campaign.launch()
results = campaign.get_metrics()
```

### 📋 **Commandes Principales**
```bash
# Gestion des campagnes
./tools/campaign-manager.py --create --name "Test Campaign"
./tools/campaign-manager.py --launch --id 12345
./tools/campaign-manager.py --status --all

# Templates et contenu
./tools/template-builder.py --type email --theme urgent
./tools/content-generator.py --company "TechCorp" --personalize

# Analytics et rapports
./tools/metrics-analyzer.py --campaign 12345 --export pdf
./tools/dashboard.py --start --port 8080

# Tests et validation
./scripts/validate-campaign.sh --campaign-id 12345
./scripts/compliance-check.sh --gdpr --template-id 67890
```

## 🏆 Réalisations et Certifications

### 🎖️ **Badges de Compétences**
- **Social Engineering Expert** - Maîtrise complète des techniques
- **Phishing Campaign Master** - Gestion experte de campagnes
- **Awareness Training Developer** - Création de programmes de formation
- **OSINT Specialist** - Reconnaissance et profilage avancé
- **Compliance Manager** - Conformité légale et éthique

### 📜 **Certifications Visées**
- **Social Engineering Professional** - Social Engineer LLC
- **SANS SEC504** - Incident Handling and Hacker Techniques
- **CISSP** - Information Security Professional
- **CISA** - Information Systems Auditor

## 🤝 Contribution et Communauté

### 🌟 **Comment Contribuer**
1. **Fork** du repository
2. **Création** d'une branche feature
3. **Développement** de nouveaux modules
4. **Tests** complets de validation
5. **Documentation** détaillée
6. **Pull Request** avec exemples d'usage

### 📧 **Support et Contact**
- **Issues GitHub** pour les bugs et suggestions
- **Discussions** pour les questions techniques
- **Discord** pour le support communautaire
- **Email sécurisé** pour les rapports de sécurité

---

## ⚠️ Avertissement Légal et Éthique

**USAGE STRICTEMENT AUTORISÉ ET PROFESSIONNEL**

Cette plateforme est destinée exclusivement à :
- Les tests de sécurité autorisés par écrit
- La sensibilisation à la sécurité en entreprise
- La recherche académique en cybersécurité
- La formation professionnelle en sécurité

### 🚨 **Interdictions Absolues**
- Tests sans autorisation écrite explicite
- Collecte non autorisée de données personnelles
- Harcèlement ou manipulation malveillante
- Violation des lois sur la protection des données
- Usage à des fins criminelles ou malveillantes

### 📋 **Responsabilités Légales**
L'utilisateur assume l'entière responsabilité de :
- L'obtention des autorisations nécessaires
- La conformité aux lois locales et internationales
- La protection des données personnelles collectées
- L'usage éthique et professionnel de la plateforme
- Le respect des droits des personnes testées

### 🛡️ **Protection des Données**
- **Anonymisation** automatique des PII
- **Chiffrement** de toutes les données sensibles
- **Suppression automatique** après campagnes
- **Conformité RGPD** et réglementations locales
- **Audits de sécurité** réguliers

---

## 📄 Licence

**MIT License avec clauses de responsabilité renforcées** - Voir [LICENSE](LICENSE) pour les détails complets.

**Usage éducatif et professionnel uniquement** - Attribution requise pour tous usages dérivés.

---

*Dernière mise à jour : $(date)*
*Version du projet : 1.0.0*
*Mainteneur : [Votre nom]*
*Classification : Outil de sécurité professionnel - Usage autorisé uniquement*