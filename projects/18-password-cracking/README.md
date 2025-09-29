# 🔐 Projet 18 - Password Cracking & Analysis

## 📖 Vue d'Ensemble

Ce projet explore les techniques avancées de cassage de mots de passe dans un contexte éthique et éducatif. Il implémente une suite complète d'outils pour l'audit de sécurité des mots de passe, utilisant les technologies les plus performantes comme **Hashcat** et **John the Ripper**.

### 🎯 Objectifs

- **🔍 Audit de Sécurité** : Évaluer la robustesse des mots de passe organisationnels
- **⚡ Optimisation** : Maximiser l'efficacité des attaques par dictionnaire et brute force
- **📊 Analyse** : Comprendre les patterns et faiblesses des mots de passe
- **🛡️ Prévention** : Sensibiliser aux bonnes pratiques de création de mots de passe
- **🧪 Recherche** : Développer de nouvelles techniques d'attaque et de défense

## 🏗️ Architecture du Projet

```
18-password-cracking/
├── 📋 README.md                    # Documentation principale
├── ⚙️ requirements.txt             # Dépendances Python
├── 🐳 docker-compose.yml          # Environnement conteneurisé
├── 🛠️ Makefile                     # Automatisation des tâches
├── 
├── src/                            # Code source principal
│   ├── hashcat/                    # Modules Hashcat
│   │   ├── hashcat_manager.py      # Gestionnaire Hashcat
│   │   ├── attack_modes.py         # Modes d'attaque
│   │   └── optimization.py         # Optimisations GPU/CPU
│   │
│   ├── john/                       # Modules John the Ripper
│   │   ├── john_manager.py         # Gestionnaire John
│   │   ├── rule_generator.py       # Générateur de règles
│   │   └── formats.py              # Formats de hash
│   │
│   ├── analysis/                   # Modules d'analyse
│   │   ├── hash_analyzer.py        # Analyseur de hashs
│   │   ├── password_analyzer.py    # Analyseur de mots de passe
│   │   ├── pattern_detector.py     # Détecteur de patterns
│   │   └── stats_generator.py      # Générateur de statistiques
│   │
│   ├── wordlist-generator/         # Génération de listes
│   │   ├── wordlist_builder.py     # Constructeur de listes
│   │   ├── osint_integration.py    # Intégration OSINT
│   │   ├── mutation_engine.py      # Moteur de mutations
│   │   └── custom_generator.py     # Générateur personnalisé
│   │
│   └── hybrid-attacks/             # Attaques hybrides
│       ├── combinator.py           # Combinateur d'attaques
│       ├── mask_generator.py       # Générateur de masques
│       └── smart_attack.py         # Attaque intelligente
│
├── tools/                          # Outils utilitaires
│   ├── hash-identifier/            # Identification de hashs
│   ├── password-policy/            # Vérification de politiques
│   ├── benchmark/                  # Tests de performance
│   └── converter/                  # Convertisseurs de formats
│
├── wordlists/                      # Dictionnaires
│   ├── common/                     # Listes communes
│   ├── custom/                     # Listes personnalisées
│   ├── rules/                      # Règles de mutation
│   └── masks/                      # Masques d'attaque
│
├── hashes/                         # Exemples de hashs
│   ├── test-hashes/                # Hashs de test
│   ├── formats/                    # Différents formats
│   └── samples/                    # Échantillons réels
│
├── examples/                       # Exemples d'utilisation
│   ├── basic-cracking/             # Cassage basique
│   ├── advanced-attacks/           # Attaques avancées
│   ├── benchmarking/               # Tests de performance
│   └── case-studies/               # Études de cas
│
├── tests/                          # Tests et validation
│   ├── unit-tests/                 # Tests unitaires
│   ├── integration-tests/          # Tests d'intégration
│   └── performance-tests/          # Tests de performance
│
├── config/                         # Configuration
│   ├── hashcat.conf               # Configuration Hashcat
│   ├── john.conf                  # Configuration John
│   └── profiles.yaml              # Profils d'attaque
│
├── docs/                          # Documentation
│   ├── user-guide.md             # Guide utilisateur
│   ├── technical-guide.md        # Guide technique
│   ├── best-practices.md         # Bonnes pratiques
│   └── ethical-guidelines.md     # Guidelines éthiques
│
└── results/                       # Résultats d'analyse
    ├── cracked/                   # Mots de passe cassés
    ├── reports/                   # Rapports d'audit
    └── statistics/                # Statistiques
```

## 🚀 Fonctionnalités Principales

### 🔧 Gestionnaires d'Outils

#### Hashcat Manager
- **🎯 Modes d'Attaque** : Dictionary, Brute-force, Hybrid, Rule-based
- **⚡ Optimisation GPU** : Support CUDA et OpenCL
- **📊 Monitoring** : Suivi temps réel des performances
- **🔄 Reprise** : Restauration des sessions interrompues
- **📈 Benchmarking** : Tests de performance automatisés

#### John the Ripper Manager
- **🔍 Détection Auto** : Identification automatique des formats
- **📝 Règles Personnalisées** : Génération de règles de mutation
- **🔄 Mode Incremental** : Attaques par force brute intelligente
- **📊 Statistiques** : Analyse des résultats en temps réel

### 📈 Analyse Avancée

#### Analyseur de Mots de Passe
```python
# Exemple d'analyse de patterns
password_stats = {
    "length_distribution": {
        "6-8": 45,
        "9-12": 35,
        "13+": 20
    },
    "character_sets": {
        "lowercase_only": 25,
        "mixed_case": 40,
        "alphanumeric": 30,
        "special_chars": 5
    },
    "common_patterns": {
        "dates": 15,
        "names": 20,
        "dictionary_words": 35,
        "keyboard_walks": 10
    }
}
```

#### Détecteur de Patterns
- **📅 Patterns Temporels** : Dates, années, mois
- **👤 Patterns Personnels** : Noms, prénoms, lieux
- **⌨️ Patterns Clavier** : Séquences clavier (qwerty, azerty)
- **🔢 Patterns Numériques** : Séquences numériques, dates de naissance

### 🧠 Attaques Intelligentes

#### Moteur de Mutations
```python
# Règles de mutation avancées
mutation_rules = {
    "capitalization": ["capitalize", "uppercase", "lowercase", "toggle_case"],
    "substitution": ["@->a", "3->e", "1->i", "0->o", "$->s"],
    "insertion": ["append_year", "prepend_symbol", "insert_number"],
    "transformation": ["reverse", "leet_speak", "keyboard_shift"]
}
```

#### Générateur de Listes Personnalisées
- **🔍 Intégration OSINT** : Utilisation d'informations publiques
- **🏢 Contexte Organisationnel** : Noms d'entreprise, produits, services
- **🌍 Localisation** : Adaptation culturelle et linguistique
- **📱 Sources Modernes** : Réseaux sociaux, sites web, databases

## 💻 Technologies Utilisées

### 🔨 Outils de Cassage
- **Hashcat 6.2+** : Cassage GPU haute performance
- **John the Ripper** : Cassage CPU et détection de formats
- **Hydra** : Attaques de services réseau
- **Medusa** : Alternative à Hydra pour certains services

### 🐍 Langages et Frameworks
- **Python 3.9+** : Logique principale et intégration
- **CUDA/OpenCL** : Accélération GPU
- **NumPy/Pandas** : Analyse statistique
- **Matplotlib/Seaborn** : Visualisation des données

### 🗄️ Formats de Hash Supportés
```python
supported_formats = {
    "md5": {"hashcat": 0, "john": "Raw-MD5"},
    "sha1": {"hashcat": 100, "john": "Raw-SHA1"},
    "sha256": {"hashcat": 1400, "john": "Raw-SHA256"},
    "bcrypt": {"hashcat": 3200, "john": "bcrypt"},
    "ntlm": {"hashcat": 1000, "john": "NT"},
    "linux_sha512": {"hashcat": 1800, "john": "sha512crypt"},
    "windows_lm": {"hashcat": 3000, "john": "LM"},
    "wordpress": {"hashcat": 400, "john": "phpass"},
    "mysql": {"hashcat": 300, "john": "mysql-sha1"},
    "postgres": {"hashcat": 12, "john": "postgres"}
}
```

## 🎯 Cas d'Usage

### 1. Audit de Sécurité Organisationnel
```bash
# Audit complet d'une base de hashs Windows
python src/analysis/password_analyzer.py \
  --input hashes/ntlm_dump.txt \
  --format ntlm \
  --wordlists wordlists/corporate/ \
  --output results/audit_report.html
```

### 2. Test de Politiques de Mots de Passe
```bash
# Validation d'une politique de mot de passe
python tools/password-policy/policy_checker.py \
  --policy config/corporate_policy.json \
  --passwords results/cracked/passwords.txt \
  --report results/policy_compliance.pdf
```

### 3. Recherche en Sécurité
```bash
# Benchmark de performance sur différents GPUs
python tools/benchmark/gpu_benchmark.py \
  --algorithms md5,sha1,sha256,bcrypt \
  --wordlist wordlists/common/rockyou.txt \
  --output results/benchmark_results.json
```

### 4. Formation et Sensibilisation
```bash
# Génération de rapport de sensibilisation
python src/analysis/awareness_report.py \
  --cracked-passwords results/cracked/ \
  --template docs/templates/awareness.html \
  --output results/awareness_presentation.html
```

## 📊 Métriques et KPIs

### Performance de Cassage
```python
cracking_metrics = {
    "hash_rate": "2.5 GH/s",  # Hashs par seconde
    "success_rate": 0.65,      # Taux de succès
    "avg_crack_time": 156,     # Temps moyen (secondes)
    "gpu_utilization": 0.95,   # Utilisation GPU
    "memory_usage": "8.2 GB",  # Utilisation mémoire
    "power_consumption": "350W" # Consommation électrique
}
```

### Analyse des Mots de Passe
```python
password_analysis = {
    "total_analyzed": 10000,
    "cracked": 6500,
    "avg_length": 8.2,
    "entropy_avg": 42.5,
    "common_patterns": {
        "password123": 150,
        "company_name": 89,
        "season_year": 67
    },
    "complexity_distribution": {
        "weak": 0.45,
        "medium": 0.35,
        "strong": 0.20
    }
}
```

## 🔐 Sécurité et Éthique

### ⚖️ Considérations Légales
- **✅ Usage Autorisé** : Uniquement sur systèmes possédés ou autorisés
- **📄 Documentation** : Maintien de logs d'audit complets
- **🔒 Confidentialité** : Protection des données sensibles
- **⏰ Limitation Temporelle** : Destruction des données après audit

### 🛡️ Mesures de Sécurité
```python
security_measures = {
    "data_encryption": "AES-256-GCM",
    "access_control": "Role-based authentication",
    "audit_logging": "Complete activity tracking",
    "data_retention": "30 days maximum",
    "secure_deletion": "DOD 5220.22-M standard",
    "network_isolation": "Airgapped environment recommended"
}
```

### 📋 Checklist de Conformité
- [ ] Autorisation écrite du propriétaire du système
- [ ] Définition claire du scope d'audit
- [ ] Mise en place de mesures de protection des données
- [ ] Formation de l'équipe sur les aspects légaux
- [ ] Plan de gestion des incidents
- [ ] Procédure de destruction sécurisée des données

## 🚀 Installation et Configuration

### Prérequis Système
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake git
sudo apt install -y ocl-icd-opencl-dev opencl-headers
sudo apt install -y nvidia-opencl-dev  # Pour GPU NVIDIA

# Python et dépendances
python3 -m pip install -r requirements.txt
```

### Installation Hashcat
```bash
# Installation depuis les sources
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
sudo make install
```

### Installation John the Ripper
```bash
# Installation depuis les sources
git clone https://github.com/openwall/john.git
cd john/src
./configure && make
```

### Configuration GPU
```bash
# Vérification des drivers GPU
nvidia-smi  # Pour NVIDIA
clinfo      # Pour OpenCL

# Test de performance
hashcat -b  # Benchmark Hashcat
```

## 🎮 Exemples d'Utilisation

### Cassage Basique
```python
from src.hashcat.hashcat_manager import HashcatManager

# Initialisation
hc = HashcatManager()

# Attaque par dictionnaire simple
result = hc.dictionary_attack(
    hash_file="hashes/md5_hashes.txt",
    wordlist="wordlists/rockyou.txt",
    hash_type="md5"
)

print(f"Cracked: {result.cracked_count}/{result.total_hashes}")
```

### Attaque Hybride Avancée
```python
from src.hybrid_attacks.smart_attack import SmartAttack

# Configuration d'attaque intelligente
attack = SmartAttack()
attack.configure({
    "target_hashes": "hashes/corporate_ntlm.txt",
    "osint_data": "data/company_info.json",
    "max_runtime": 3600,  # 1 heure
    "gpu_enabled": True
})

# Lancement de l'attaque multi-phase
results = attack.execute()
```

### Analyse de Patterns
```python
from src.analysis.pattern_detector import PatternDetector

# Analyse des mots de passe crackés
detector = PatternDetector()
patterns = detector.analyze_passwords(
    "results/cracked_passwords.txt"
)

# Génération de recommandations
recommendations = detector.generate_recommendations(patterns)
```

## 📈 Roadmap et Évolutions

### Version 1.0 (Actuelle)
- ✅ Intégration Hashcat et John the Ripper
- ✅ Analyse basique des mots de passe
- ✅ Génération de rapports simples
- ✅ Interface en ligne de commande

### Version 1.1 (À venir)
- 🔄 Interface web intuitive
- 🔄 API REST pour intégration
- 🔄 Support des attaques distribuées
- 🔄 Intégration SIEM

### Version 2.0 (Futur)
- ⏳ Intelligence artificielle pour attaques prédictives
- ⏳ Support des mots de passe quantiques
- ⏳ Blockchain pour audit trail
- ⏳ Détection comportementale avancée

## 📚 Ressources et Références

### Documentation Technique
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)
- [OWASP Password Security](https://owasp.org/www-project-password-security/)

### Recherches Académiques
- ["Password Security: A Case History"](https://www.cs.utah.edu/~morris/papers/password-security.pdf)
- ["The Science of Password Selection"](https://research.microsoft.com/pubs/227130/WhyDoesMyPasswordLookLikeADog.pdf)

### Bases de Données de Référence
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
- [Hashcat Rules](https://github.com/hashcat/hashcat/tree/master/rules)
- [Have I Been Pwned](https://haveibeenpwned.com/Passwords)

## 🤝 Contribution et Support

### Comment Contribuer
1. **🍴 Fork** le repository
2. **🌿 Créer** une branche feature
3. **💻 Développer** avec tests unitaires
4. **📝 Documenter** les changements
5. **🚀 Soumettre** une pull request

### Guidelines de Contribution
- Respecter les standards de code Python (PEP 8)
- Inclure des tests pour toute nouvelle fonctionnalité
- Maintenir la compatibilité avec les versions existantes
- Documenter les APIs publiques

### Support
- **📧 Email** : security@example.com
- **💬 Discord** : [Serveur de la communauté]
- **🐛 Issues** : GitHub Issues pour les bugs
- **💡 Discussions** : GitHub Discussions pour les idées

---

## ⚠️ Avertissement Légal

**USAGE STRICTEMENT ÉTHIQUE ET LÉGAL**

Ce projet est développé exclusivement à des fins éducatives et d'audit de sécurité autorisé. Toute utilisation malveillante, non autorisée ou illégale est strictement interdite et relève de la seule responsabilité de l'utilisateur.

### 📋 Conditions d'Utilisation
- ✅ Tests sur vos propres systèmes
- ✅ Audits de sécurité autorisés
- ✅ Recherche académique
- ✅ Formation en cybersécurité
- ❌ Attaques non autorisées
- ❌ Violation de systèmes tiers
- ❌ Activités illégales

**Les auteurs déclinent toute responsabilité en cas d'usage inapproprié.**

---

**Développé avec 🔐 pour la communauté cybersécurité**

*Version 1.0.0 - Dernière mise à jour : Janvier 2024*