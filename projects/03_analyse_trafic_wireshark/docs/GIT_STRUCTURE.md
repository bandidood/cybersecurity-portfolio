│   └── custom/                      # Outils développés
│
├── examples/                        # Exemples d'utilisation
│   ├── basic_analysis/             # Analyse de base
│   │   ├── http_traffic_analysis.md
│   │   ├── dns_investigation.md
│   │   └── tcp_session_analysis.md
│   ├── incident_scenarios/         # Scénarios d'incident
│   │   ├── malware_detection.md
│   │   ├── data_exfiltration.md
│   │   └── web_attack_analysis.md
│   └── automation/                 # Exemples d'automatisation
│       ├── automated_reporting.py
│       └── continuous_monitoring.sh
│
├── training/                       # Matériel de formation
│   ├── workshops/                  # Ateliers pratiques
│   │   ├── workshop_01_basics.md
│   │   ├── workshop_02_advanced.md
│   │   └── workshop_03_forensics.md
│   ├── exercises/                  # Exercices pratiques
│   │   ├── exercise_port_scan.md
│   │   ├── exercise_web_attack.md
│   │   └── exercise_malware_comm.md
│   └── solutions/                  # Solutions des exercices
│       ├── solution_port_scan.md
│       └── solution_web_attack.md
│
└── research/                       # Recherche et développement
    ├── papers/                     # Articles et recherches
    ├── prototypes/                 # Prototypes d'outils
    └── benchmarks/                 # Tests de performance
```

## 📝 Fichiers de Configuration Git

### .gitignore
```gitignore
# Fichiers de capture (sensibles et volumineux)
captures/*.pcap
captures/*.pcapng
captures/*.cap
captures/real_incidents/
captures/sensitive/

# Logs d'exécution
logs/
*.log
*.log.*

# Fichiers temporaires
temp/
tmp/
*.tmp
*.temp

# Données sensibles
configs/threat_feeds/private/
configs/credentials/
*.key
*.pem
*.p12

# Fichiers système
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.sublime-project
*.sublime-workspace

# Rapports générés automatiquement
reports/generated/
reports/auto_*

# Archives et sauvegardes
*.zip
*.tar.gz
*.rar
*.backup

# Fichiers volumineux (>100MB)
*.pcap
*.pcapng
*.dump

# Configuration locale
configs/local/
.env
.env.local
```

### CHANGELOG.md
```markdown
# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Non publié]

### Ajouté
- Script de génération de trafic test
- Analyseur avancé avec détection d'anomalies
- Support pour export HTML des rapports

### Modifié
- Amélioration des performances de l'analyseur Python
- Mise à jour de la bibliothèque de filtres

### Corrigé
- Correction bug parsing DNS avec pyshark
- Fix permissions script de configuration

## [2.0.0] - 2024-07-19

### Ajouté
- Analyseur Python avancé avec détection automatique
- Templates de rapports HTML professionnels
- Scripts d'automatisation pour capture et analyse
- Support pour corrélation threat intelligence
- Profils Wireshark spécialisés (SOC, IR, Pentest)
- Documentation complète avec méthodologie

### Modifié
- Restructuration complète du projet
- Amélioration de la documentation
- Optimisation des scripts de capture

## [1.0.0] - 2024-01-15

### Ajouté
- Configuration initiale Wireshark
- Scripts de base pour capture
- Documentation basique
- Première version des filtres
```

### CONTRIBUTING.md
```markdown
# Guide de Contribution

Merci de votre intérêt pour contribuer à ce projet d'analyse de trafic réseau !

## Comment Contribuer

### Rapporter des Bugs
1. Vérifiez que le bug n'a pas déjà été rapporté
2. Créez une issue avec le template approprié
3. Incluez les informations de version et d'environnement
4. Fournissez un exemple reproductible si possible

### Proposer des Améliorations
1. Ouvrez une issue pour discuter de l'amélioration
2. Décrivez clairement la valeur ajoutée
3. Proposez une implémentation si possible

### Soumettre du Code
1. Forkez le repository
2. Créez une branche feature (`git checkout -b feature/nom-feature`)
3. Commitez vos changements (`git commit -am 'Ajout nouvelle feature'`)
4. Pushez sur la branche (`git push origin feature/nom-feature`)
5. Ouvrez une Pull Request

## Standards de Code

### Python
- Respecter PEP 8
- Documenter les fonctions avec docstrings
- Inclure des tests unitaires
- Utiliser type hints quand approprié

### Bash
- Utiliser `set -euo pipefail`
- Commenter les sections importantes
- Valider avec shellcheck

### Documentation
- Markdown pour toute la documentation
- Inclure des exemples d'utilisation
- Maintenir la cohérence avec le style existant

## Tests
- Tous les nouveaux scripts doivent inclure des tests
- Les tests doivent passer avant soumission
- Inclure des tests pour les cas d'erreur

## Sécurité
- Ne jamais commiter de données sensibles
- Chiffrer les exemples de captures si nécessaire
- Respecter les principes de sécurité défensive
```

## 🔧 Scripts de Gestion Git

### setup_git_hooks.sh
```bash
#!/bin/bash
# Configuration des hooks Git pour le projet

# Pre-commit hook pour vérifier la qualité du code
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook pour vérifications

echo "🔍 Vérifications pre-commit..."

# Vérifier qu'aucun fichier sensible n'est commité
if git diff --cached --name-only | grep -E "\.(pcap|pcapng|key|pem)$"; then
    echo "❌ Fichiers sensibles détectés dans le commit!"
    echo "Utiliser git-crypt ou exclure ces fichiers."
    exit 1
fi

# Vérifier la syntaxe Python
python_files=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')
if [ -n "$python_files" ]; then
    echo "🐍 Vérification syntaxe Python..."
    for file in $python_files; do
        python -m py_compile "$file"
        if [ $? -ne 0 ]; then
            echo "❌ Erreur syntaxe dans $file"
            exit 1
        fi
    done
fi

# Vérifier la syntaxe Bash
bash_files=$(git diff --cached --name-only --diff-filter=ACM | grep '\.sh$')
if [ -n "$bash_files" ]; then
    echo "🐚 Vérification syntaxe Bash..."
    for file in $bash_files; do
        bash -n "$file"
        if [ $? -ne 0 ]; then
            echo "❌ Erreur syntaxe dans $file"
            exit 1
        fi
    done
fi

echo "✅ Toutes les vérifications passées"
EOF

chmod +x .git/hooks/pre-commit

# Pre-push hook pour tests
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
# Pre-push hook pour exécuter les tests

echo "🧪 Exécution des tests avant push..."

# Exécuter les tests Python si ils existent
if [ -d "tests/" ]; then
    python -m pytest tests/ -v
    if [ $? -ne 0 ]; then
        echo "❌ Tests échoués!"
        exit 1
    fi
fi

echo "✅ Tous les tests passés"
EOF

chmod +x .git/hooks/pre-push

echo "✅ Hooks Git configurés"
```

## 📊 Templates de Commits

### Conventional Commits
```
feat: ajout analyseur de malware communication
fix: correction parsing DNS avec caractères spéciaux
docs: mise à jour guide installation Wireshark
style: amélioration formatage code Python
refactor: restructuration module de filtres
test: ajout tests unitaires pour parser TCP
chore: mise à jour dépendances Python
```

## 🏷️ Stratégie de Versioning

### Semantic Versioning (SemVer)
- **MAJOR.MINOR.PATCH** (ex: 2.1.3)
- **MAJOR**: Changements incompatibles
- **MINOR**: Nouvelles fonctionnalités compatibles
- **PATCH**: Corrections de bugs

### Tags Git
```bash
# Créer un tag pour une release
git tag -a v2.0.0 -m "Version 2.0.0 - Analyseur avancé"
git push origin v2.0.0

# Lister les tags
git tag -l

# Checkout d'une version spécifique
git checkout v2.0.0
```

## 🔒 Gestion des Données Sensibles

### Git-Crypt (Recommandé)
```bash
# Installation git-crypt
sudo apt install git-crypt

# Initialisation
git-crypt init

# Configuration fichiers à chiffrer (.gitattributes)
captures/real_incidents/** filter=git-crypt diff=git-crypt
configs/credentials/** filter=git-crypt diff=git-crypt
*.key filter=git-crypt diff=git-crypt

# Ajout d'une clé utilisateur
git-crypt add-gpg-user user@company.com

# Verrouillage/déverrouillage
git-crypt lock
git-crypt unlock
```

### LFS pour Gros Fichiers
```bash
# Installation Git LFS
git lfs install

# Tracking des gros fichiers
git lfs track "*.pcap"
git lfs track "captures/training/*.pcapng"

# Commit du .gitattributes
git add .gitattributes
git commit -m "chore: configuration Git LFS"
```

## 🤝 Workflow Collaboratif

### GitFlow
```
main (production)
├── develop (développement)
│   ├── feature/new-analyzer
│   ├── feature/improved-filters
│   └── feature/api-integration
├── release/v2.1.0
└── hotfix/critical-bug-fix
```

### Protection des Branches
```bash
# Protection branche main
# - Require pull request reviews
# - Require status checks
# - Require branches to be up to date
# - Include administrators
```

## 📈 Métriques et Monitoring

### GitHub Actions (CI/CD)
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest
    - name: Run tests
      run: pytest tests/
    - name: Lint code
      run: |
        pip install flake8
        flake8 scripts/ --max-line-length=88
```

## 📁 Structure de Branches

```
main                    # Production stable
├── develop            # Intégration développement
├── feature/
│   ├── advanced-ml-detection
│   ├── real-time-analysis
│   └── api-endpoints
├── release/
│   ├── v2.1.0
│   └── v2.2.0
└── hotfix/
    └── security-patch
```

---

*Cette structure Git garantit une organisation professionnelle du code, une collaboration efficace et une traçabilité complète des modifications. Elle peut être adaptée selon les besoins spécifiques de l'équipe et de l'organisation.*