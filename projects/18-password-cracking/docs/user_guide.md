# 🛡️ Guide Utilisateur - Password Cracking Platform

## 📋 Table des Matières

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Utilisation de Base](#utilisation-de-base)
5. [Modules Principaux](#modules-principaux)
6. [Cas d'Usage Avancés](#cas-dusage-avancés)
7. [Exemples Pratiques](#exemples-pratiques)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)
10. [Support et Contribution](#support-et-contribution)

---

## 🔍 Introduction

La **Password Cracking Platform** est une suite complète d'outils professionnels pour l'audit de sécurité des mots de passe. Elle combine l'analyse de patterns, la génération de wordlists personnalisées, et l'intégration avec des outils de cracking populaires comme Hashcat et John the Ripper.

### ✨ Fonctionnalités Principales

- **🔍 Analyse Avancée de Patterns** : Détection automatique de faiblesses dans les mots de passe
- **📝 Génération de Wordlists Intelligente** : Création de listes ciblées basées sur OSINT et profils
- **⚡ Intégration Hashcat/John** : Gestion simplifiée des attaques de cracking
- **📊 Reporting Complet** : Rapports détaillés avec visualisations et recommandations
- **🚀 API REST** : Interface programmatique pour l'intégration dans des workflows
- **🎯 Audit Ciblé** : Outils spécialisés pour l'audit d'entreprise

### ⚠️ Avertissements Légaux et Éthiques

> **IMPORTANT** : Cette plateforme est conçue exclusivement pour :
> - Les tests de pénétration autorisés
> - L'audit de sécurité sur vos propres systèmes
> - La formation en cybersécurité
> 
> L'utilisation non autorisée sur des systèmes tiers est strictement interdite et illégale.

---

## 🚀 Installation

### Prérequis Système

- **Python 3.8+** (recommandé : Python 3.10+)
- **Système d'exploitation** : Linux, Windows, macOS
- **Mémoire** : Minimum 4GB RAM (recommandé : 8GB+)
- **Espace disque** : 2GB minimum pour les wordlists et résultats

### Installation Automatique

```bash
# Clone du repository
git clone https://github.com/votre-username/password-cracking-platform.git
cd password-cracking-platform/projects/18-password-cracking

# Installation des dépendances Python
pip install -r requirements.txt

# Installation des outils externes (optionnel)
./scripts/install_tools.sh
```

### Installation Manuelle

#### 1. Dépendances Python

```bash
pip install pandas numpy matplotlib seaborn requests beautifulsoup4
pip install colorama tqdm plotly hashlib argparse flask
pip install selenium webdriver-manager nltk psutil
```

#### 2. Hashcat (Optionnel mais Recommandé)

**Linux/Ubuntu :**
```bash
sudo apt update
sudo apt install hashcat
```

**Windows :**
```powershell
# Télécharger depuis https://hashcat.net/hashcat/
# Ajouter hashcat.exe au PATH
```

**macOS :**
```bash
brew install hashcat
```

#### 3. John the Ripper (Optionnel)

**Linux/Ubuntu :**
```bash
sudo apt install john
```

**Windows :**
```powershell
# Télécharger depuis https://www.openwall.com/john/
# Ajouter john.exe au PATH
```

### Vérification de l'Installation

```bash
# Test de l'environnement Python
python src/analysis/password_analyzer.py

# Test des outils externes
hashcat --version
john --version
```

---

## ⚙️ Configuration

### Configuration de Base

Créez un fichier `config/settings.json` :

```json
{
  "general": {
    "output_dir": "./results",
    "wordlist_dir": "./wordlists",
    "temp_dir": "./temp",
    "max_threads": 4,
    "verbose": true
  },
  "hashcat": {
    "binary_path": "hashcat",
    "workload_profile": 3,
    "gpu_accel": true,
    "opencl_device_types": "1,2"
  },
  "analysis": {
    "min_entropy_threshold": 25,
    "pattern_detection": true,
    "generate_plots": true,
    "export_formats": ["json", "csv", "html"]
  },
  "wordlist_generation": {
    "max_mutations": 1000,
    "enable_leetspeak": true,
    "enable_case_variations": true,
    "min_word_length": 3,
    "max_word_length": 20
  },
  "osint": {
    "user_agent": "Mozilla/5.0 (Research Bot)",
    "request_delay": 1.0,
    "max_pages": 50,
    "respect_robots": true
  }
}
```

### Variables d'Environnement

```bash
# Optionnel : configuration via variables d'environnement
export PASSWORD_CRACKING_CONFIG_PATH="/path/to/config"
export PASSWORD_CRACKING_OUTPUT_DIR="/path/to/results"
export PASSWORD_CRACKING_WORDLIST_DIR="/path/to/wordlists"
```

---

## 💡 Utilisation de Base

### Analyse Simple d'un Mot de Passe

```python
from src.analysis.password_analyzer import PasswordAnalyzer

# Initialisation
analyzer = PasswordAnalyzer()

# Analyse d'un mot de passe
stats = analyzer.analyze("MyP@ssw0rd123")

print(f"Force: {stats.strength}")
print(f"Entropie: {stats.entropy:.2f} bits")
print(f"Patterns détectés: {', '.join(stats.patterns)}")
```

### Analyse d'un Dataset

```python
# Liste de mots de passe à analyser
passwords = [
    "password123",
    "admin",
    "qwerty",
    "MyStr0ng_P@ssw0rd!",
    "company2023"
]

# Analyse complète du dataset
analysis = analyzer.analyze_dataset(passwords)

print(f"Total: {analysis.total_passwords}")
print(f"Uniques: {analysis.unique_passwords}")
print(f"Taux de duplication: {analysis.duplicate_rate:.1%}")

# Export des résultats
analyzer.export_analysis(analysis, output_dir="./results")
```

### Génération de Wordlist Simple

```python
from src.wordlist_generator.wordlist_builder import WordlistBuilder, TargetProfile

# Initialisation du constructeur
builder = WordlistBuilder()

# Profil cible basique
profile = TargetProfile(
    first_names=["john", "jane"],
    last_names=["smith", "doe"],
    company_names=["acme", "example"],
    birthdates=["1990", "1995"]
)

# Génération de la wordlist
wordlist = builder.build_from_profile(profile, enable_mutations=True)

# Export
builder.export_wordlist(wordlist, "custom_wordlist", format_type="txt")
```

---

## 🔧 Modules Principaux

### 1. Password Analyzer (`src/analysis/`)

#### Fonctionnalités

- **Calcul d'entropie** : Mesure de la complexité cryptographique
- **Détection de patterns** : Identification de faiblesses communes
- **Scoring de force** : Classification en 5 niveaux (très faible à très fort)
- **Analyse statistique** : Métriques complètes sur des datasets

#### Exemple d'Utilisation Avancée

```python
from src.analysis.password_analyzer import PasswordAnalyzer

analyzer = PasswordAnalyzer()

# Analyse individuelle avec détails
stats = analyzer.analyze("Tr0ub4dor&3")
print(f"""
📊 Analyse Détaillée:
   Longueur: {stats.length}
   Entropie: {stats.entropy:.2f} bits
   Force: {stats.strength}
   
🔍 Caractères:
   Minuscules: {stats.has_lowercase}
   Majuscules: {stats.has_uppercase}
   Chiffres: {stats.has_digits}
   Symboles: {stats.has_symbols}
   Uniques: {stats.unique_chars}
   
🎭 Patterns Détectés:
   {', '.join(stats.patterns) if stats.patterns else 'Aucun pattern détecté'}
""")
```

#### Détecteurs de Patterns Disponibles

1. **KeyboardPatternDetector** : Séquences de clavier (qwerty, azerty, etc.)
2. **CommonSubstitutionDetector** : Substitutions leetspeak (@ pour a, 3 pour e)
3. **DatePatternDetector** : Dates et années
4. **DictionaryWordDetector** : Mots de dictionnaire courants
5. **NumberSequenceDetector** : Séquences numériques

### 2. Wordlist Builder (`src/wordlist_generator/`)

#### Stratégies de Génération

- **Profil Personnel** : Basé sur noms, dates, intérêts
- **Profil d'Entreprise** : Informations corporate, secteur, localisation
- **OSINT** : Extraction de mots-clés depuis sites web
- **Hybride** : Combinaison de plusieurs sources

#### Exemple Complet

```python
from src.wordlist_generator.wordlist_builder import WordlistBuilder, TargetProfile

builder = WordlistBuilder()

# Profil détaillé pour une entreprise tech
profile = TargetProfile(
    first_names=["alice", "bob", "charlie", "diana"],
    last_names=["anderson", "brown", "clark", "davis"],
    company_names=["techcorp", "innovate", "solutions"],
    job_titles=["developer", "manager", "analyst", "engineer"],
    departments=["it", "dev", "ops", "security"],
    interests=["coding", "python", "docker", "kubernetes"],
    birthdates=["1985", "1990", "1995", "2000"],
    locations=["paris", "london", "berlin", "madrid"]
)

# Génération avec mutations avancées
wordlist = builder.build_from_profile(
    profile=profile,
    enable_mutations=True,
    max_words=5000
)

print(f"Wordlist générée: {len(wordlist)} mots")

# Export en multiple formats
builder.export_wordlist(wordlist, "enterprise_wordlist", "txt")
builder.export_wordlist(wordlist, "enterprise_wordlist", "json")
```

#### OSINT Integration

```python
# Génération basée sur scraping web (exemple éducatif)
osint_wordlist = builder.build_from_osint(
    domains=["example-company.com"],
    max_words=2000
)

# Combinaison avec d'autres sources
combined_wordlist = builder.combine_wordlists([
    wordlist,
    osint_wordlist,
    ["custom", "words", "here"]
])
```

### 3. Hashcat Manager (`src/hashcat/`)

#### Configuration d'Attaque

```python
from src.hashcat.hashcat_manager import HashcatManager, HashType, AttackConfig

# Initialisation
manager = HashcatManager(
    outfile_dir="./results/cracked",
    session_dir="./results/sessions"
)

# Configuration d'attaque
config = AttackConfig(
    hash_file="./hashes/target_hashes.txt",
    hash_type=HashType.SHA256,
    wordlists=["./wordlists/custom.txt", "./wordlists/rockyou.txt"],
    session_name="audit_2024_01",
    runtime_limit=3600,  # 1 heure
    workload_profile=3   # Haute performance
)

# Lancement de l'attaque par dictionnaire
result = manager.dictionary_attack(config)
print(f"Succès: {result.success_rate:.1%}")
print(f"Hashs crackés: {result.cracked_hashes}")
```

#### Monitoring en Temps Réel

```python
def progress_callback(line):
    if "Progress" in line:
        print(f"📊 {line.strip()}")

def monitor_callback(data):
    print(f"⏱️ Runtime: {data['runtime']}s, GPU: {data['gpu_utilization']:.1f}%")

# Configuration des callbacks
manager.set_callback("progress", progress_callback)
manager.set_callback("monitor", monitor_callback)
```

---

## 🎯 Cas d'Usage Avancés

### Audit d'Entreprise Complet

```python
#!/usr/bin/env python3
"""
Exemple d'audit complet pour une entreprise
"""
import sys
from pathlib import Path

# Import des modules
sys.path.append(str(Path(__file__).parent / 'src'))

from analysis.password_analyzer import PasswordAnalyzer
from wordlist_generator.wordlist_builder import WordlistBuilder, TargetProfile
from hashcat.hashcat_manager import HashcatManager, HashType, AttackConfig

class CorporateAudit:
    def __init__(self, company_name, industry, location):
        self.company_name = company_name
        self.industry = industry
        self.location = location
        
        # Initialisation des outils
        self.analyzer = PasswordAnalyzer()
        self.wordlist_builder = WordlistBuilder()
        self.hashcat_manager = HashcatManager()
    
    def generate_targeted_wordlist(self):
        """Génère une wordlist ciblée pour l'entreprise"""
        print(f"🎯 Génération de wordlist pour {self.company_name}")
        
        # Wordlist basée sur l'entreprise
        company_wordlist = self.wordlist_builder.build_from_company_info(
            company_name=self.company_name,
            industry=self.industry,
            location=self.location,
            max_words=3000
        )
        
        # Export
        wordlist_file = f"./wordlists/{self.company_name.lower()}_targeted.txt"
        self.wordlist_builder.export_wordlist(
            company_wordlist, 
            wordlist_file.replace('.txt', ''),
            'txt'
        )
        
        return wordlist_file
    
    def run_audit(self, hash_file):
        """Lance un audit complet"""
        print(f"🔍 Audit de sécurité pour {self.company_name}")
        
        # 1. Génération de wordlist ciblée
        targeted_wordlist = self.generate_targeted_wordlist()
        
        # 2. Configuration de l'attaque
        config = AttackConfig(
            hash_file=hash_file,
            hash_type=HashType.SHA256,
            wordlists=[targeted_wordlist, "./wordlists/common_passwords.txt"],
            session_name=f"audit_{self.company_name}_{datetime.now().strftime('%Y%m%d')}",
            runtime_limit=7200  # 2 heures
        )
        
        # 3. Lancement de l'attaque
        result = self.hashcat_manager.dictionary_attack(config)
        
        # 4. Analyse des résultats
        if result.cracked_passwords:
            analysis = self.analyzer.analyze_dataset(result.cracked_passwords)
            
            # Export du rapport
            self.analyzer.export_analysis(
                analysis, 
                output_dir=f"./results/audit_{self.company_name}"
            )
        
        return result

# Utilisation
audit = CorporateAudit("TechCorp", "technology", "San Francisco")
result = audit.run_audit("./hashes/employee_hashes.txt")
```

### Pipeline d'Analyse Automatisé

```python
#!/usr/bin/env python3
"""
Pipeline d'analyse automatisé avec intégration CI/CD
"""
import json
import logging
from datetime import datetime
from pathlib import Path

class PasswordSecurityPipeline:
    def __init__(self, config_file="./config/pipeline_config.json"):
        with open(config_file) as f:
            self.config = json.load(f)
        
        self.setup_logging()
        self.analyzer = PasswordAnalyzer()
    
    def setup_logging(self):
        """Configuration des logs"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"./logs/pipeline_{datetime.now():%Y%m%d}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def analyze_password_dump(self, dump_file):
        """Analyse un dump de mots de passe"""
        self.logger.info(f"🔍 Analyse du dump: {dump_file}")
        
        # Chargement des mots de passe
        with open(dump_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        # Analyse
        analysis = self.analyzer.analyze_dataset(passwords)
        
        # Vérification des seuils de sécurité
        security_score = self.calculate_security_score(analysis)
        
        # Export des résultats
        output_dir = Path(f"./results/pipeline_{datetime.now():%Y%m%d_%H%M%S}")
        self.analyzer.export_analysis(analysis, output_dir)
        
        # Génération du rapport de conformité
        compliance_report = self.generate_compliance_report(analysis, security_score)
        
        with open(output_dir / "compliance_report.json", 'w') as f:
            json.dump(compliance_report, f, indent=2)
        
        return compliance_report
    
    def calculate_security_score(self, analysis):
        """Calcule un score de sécurité global"""
        score = 100
        
        # Pénalités
        if analysis.duplicate_rate > 0.1:  # Plus de 10% de doublons
            score -= 20
        
        weak_ratio = (analysis.strength_distribution.get('very_weak', 0) + 
                     analysis.strength_distribution.get('weak', 0)) / analysis.total_passwords
        if weak_ratio > 0.3:  # Plus de 30% de mots de passe faibles
            score -= 30
        
        if analysis.average_length < 8:  # Longueur moyenne < 8
            score -= 15
        
        if len(analysis.top_patterns) > 10:  # Trop de patterns communs
            score -= 10
        
        return max(0, score)
    
    def generate_compliance_report(self, analysis, security_score):
        """Génère un rapport de conformité"""
        return {
            "timestamp": datetime.now().isoformat(),
            "security_score": security_score,
            "compliance_level": self.get_compliance_level(security_score),
            "total_passwords": analysis.total_passwords,
            "unique_passwords": analysis.unique_passwords,
            "duplicate_rate": analysis.duplicate_rate,
            "strength_distribution": analysis.strength_distribution,
            "recommendations": analysis.recommendations[:5],
            "action_required": security_score < self.config["min_security_score"]
        }
    
    def get_compliance_level(self, score):
        """Détermine le niveau de conformité"""
        if score >= 80:
            return "EXCELLENT"
        elif score >= 60:
            return "GOOD"
        elif score >= 40:
            return "ACCEPTABLE"
        else:
            return "CRITICAL"

# Utilisation dans un pipeline CI/CD
pipeline = PasswordSecurityPipeline()
report = pipeline.analyze_password_dump("./data/user_passwords.txt")

if report["action_required"]:
    print("⚠️ Action immédiate requise!")
    exit(1)
else:
    print("✅ Conformité acceptable")
    exit(0)
```

---

## 📝 Exemples Pratiques

### Exemple 1 : Audit Rapide

```bash
#!/bin/bash
# Script d'audit rapide
echo "🚀 Démarrage de l'audit rapide..."

# Génération de hashes de test
echo -e "password\n123456\nadmin\nqwerty" | while read pwd; do
    echo -n "$pwd" | sha256sum | cut -d' ' -f1 >> test_hashes.txt
done

# Analyse avec Python
python3 -c "
from src.analysis.password_analyzer import PasswordAnalyzer
analyzer = PasswordAnalyzer()
passwords = ['password', '123456', 'admin', 'qwerty']
analysis = analyzer.analyze_dataset(passwords)
print(f'Score sécurité: {100 - (analysis.strength_distribution.get(\"very_weak\", 0) + analysis.strength_distribution.get(\"weak\", 0)) / analysis.total_passwords * 100:.1f}%')
"
```

### Exemple 2 : Génération de Wordlist Personnalisée

```python
#!/usr/bin/env python3
"""
Génération de wordlist pour pentest
"""
from src.wordlist_generator.wordlist_builder import WordlistBuilder, TargetProfile

def generate_pentest_wordlist(target_info):
    """Génère une wordlist pour un test de pénétration"""
    builder = WordlistBuilder()
    
    # Profil basé sur les informations de reconnaissance
    profile = TargetProfile(
        first_names=target_info.get("employees", []),
        company_names=target_info.get("company_names", []),
        locations=target_info.get("locations", []),
        interests=target_info.get("technologies", [])
    )
    
    # Génération de la wordlist
    wordlist = builder.build_from_profile(profile, enable_mutations=True)
    
    # Ajout de mots spécifiques au secteur
    industry_words = {
        "finance": ["bank", "money", "credit", "loan", "investment"],
        "healthcare": ["health", "medical", "patient", "hospital", "care"],
        "tech": ["code", "software", "data", "cloud", "api"],
        "education": ["student", "school", "university", "learning", "academic"]
    }
    
    if target_info.get("industry") in industry_words:
        wordlist.extend(industry_words[target_info["industry"]])
    
    # Export
    filename = f"pentest_{target_info.get('company_name', 'target')}_wordlist"
    builder.export_wordlist(wordlist, filename, "txt")
    
    return f"{filename}.txt"

# Configuration pour un test
target_info = {
    "company_name": "ExampleCorp",
    "industry": "tech",
    "employees": ["john", "jane", "mike", "sarah"],
    "company_names": ["examplecorp", "example", "corp"],
    "locations": ["newyork", "london", "tokyo"],
    "technologies": ["python", "docker", "aws", "kubernetes"]
}

wordlist_file = generate_pentest_wordlist(target_info)
print(f"✅ Wordlist générée: {wordlist_file}")
```

### Exemple 3 : Monitoring de Cracking

```python
#!/usr/bin/env python3
"""
Monitoring avancé d'une session de cracking
"""
import time
import json
import threading
from datetime import datetime
from src.hashcat.hashcat_manager import HashcatManager, HashType, AttackConfig

class CrackingMonitor:
    def __init__(self):
        self.stats = {
            "start_time": None,
            "current_speed": 0,
            "total_hashes": 0,
            "cracked_count": 0,
            "progress": 0,
            "eta": "Unknown"
        }
        self.running = False
    
    def progress_callback(self, line):
        """Callback pour les mises à jour de progression"""
        if "Progress" in line:
            # Parsing de la ligne de progression Hashcat
            parts = line.split()
            for i, part in enumerate(parts):
                if "%" in part:
                    try:
                        self.stats["progress"] = float(part.replace("%", ""))
                    except ValueError:
                        pass
                elif "H/s" in part and i > 0:
                    try:
                        speed_str = parts[i-1].replace(",", "")
                        self.stats["current_speed"] = float(speed_str)
                    except ValueError:
                        pass
    
    def monitor_callback(self, data):
        """Callback pour les données de monitoring système"""
        self.stats.update(data)
        
        # Sauvegarde périodique des stats
        if int(time.time()) % 30 == 0:  # Toutes les 30 secondes
            self.save_stats()
    
    def save_stats(self):
        """Sauvegarde les statistiques"""
        with open(f"monitoring_{datetime.now():%Y%m%d}.json", "w") as f:
            json.dump({
                **self.stats,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
    
    def run_monitored_attack(self, config):
        """Lance une attaque avec monitoring"""
        manager = HashcatManager()
        manager.set_callback("progress", self.progress_callback)
        manager.set_callback("monitor", self.monitor_callback)
        
        self.stats["start_time"] = datetime.now().isoformat()
        self.running = True
        
        try:
            result = manager.dictionary_attack(config)
            return result
        finally:
            self.running = False
            self.save_stats()

# Utilisation
monitor = CrackingMonitor()

config = AttackConfig(
    hash_file="./hashes/target.txt",
    hash_type=HashType.SHA256,
    wordlists=["./wordlists/custom.txt"],
    session_name="monitored_session",
    runtime_limit=3600
)

result = monitor.run_monitored_attack(config)
print(f"✅ Attaque terminée: {result.success_rate:.1%} de succès")
```

---

## 🔧 Troubleshooting

### Problèmes Courants

#### 1. **Erreur d'import des modules**

```
ImportError: No module named 'analysis.password_analyzer'
```

**Solution :**
```bash
# Vérifiez le PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Ou utilisez l'installation en mode développement
pip install -e .
```

#### 2. **Hashcat non trouvé**

```
FileNotFoundError: [Errno 2] No such file or directory: 'hashcat'
```

**Solutions :**
- Installer Hashcat : `sudo apt install hashcat` (Ubuntu/Debian)
- Ajouter au PATH : `export PATH="${PATH}:/path/to/hashcat"`
- Spécifier le chemin complet dans la configuration

#### 3. **Problèmes de performance GPU**

```
No OpenCL compatible platform found
```

**Solutions :**
- Installer les drivers GPU appropriés
- Installer les SDK OpenCL (NVIDIA CUDA, AMD APP SDK)
- Utiliser le mode CPU : `workload_profile=1` dans la config

#### 4. **Erreurs de mémoire sur gros datasets**

```
MemoryError: Unable to allocate array
```

**Solutions :**
- Traiter les datasets par chunks
- Augmenter la mémoire virtuelle
- Utiliser des générateurs au lieu de listes

```python
# Traitement par chunks
def process_large_dataset(file_path, chunk_size=10000):
    with open(file_path, 'r') as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

# Utilisation
for chunk in process_large_dataset("large_passwords.txt"):
    analysis = analyzer.analyze_dataset(chunk)
    # Traiter chunk par chunk
```

#### 5. **Problèmes d'encodage**

```
UnicodeDecodeError: 'utf-8' codec can't decode
```

**Solution :**
```python
# Lecture avec gestion d'erreurs
with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Ou détection automatique d'encodage
import chardet

with open(file_path, 'rb') as f:
    raw_data = f.read()
    encoding = chardet.detect(raw_data)['encoding']

with open(file_path, 'r', encoding=encoding) as f:
    content = f.read()
```

### Logs et Débogage

#### Activation du mode verbeux

```python
import logging

# Configuration des logs détaillés
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Utilisation avec l'analyseur
analyzer = PasswordAnalyzer(verbose=True)
```

#### Diagnostic système

```bash
#!/bin/bash
# Script de diagnostic

echo "=== DIAGNOSTIC SYSTÈME ==="
echo "Python version: $(python3 --version)"
echo "Pip packages:"
pip list | grep -E "(pandas|numpy|matplotlib|requests)"

echo -e "\n=== OUTILS EXTERNES ==="
which hashcat && echo "Hashcat: ✅" || echo "Hashcat: ❌"
which john && echo "John: ✅" || echo "John: ❌"

echo -e "\n=== GPU INFO ==="
nvidia-smi 2>/dev/null || echo "NVIDIA GPU non détecté"
lspci | grep -i amd

echo -e "\n=== ESPACE DISQUE ==="
df -h .
```

---

## ❓ FAQ

### **Q: Peut-on utiliser cette plateforme pour cracker des mots de passe sans autorisation ?**
**R:** Non, absolument pas. Cette plateforme est exclusivement conçue pour des audits de sécurité autorisés, des tests de pénétration légaux, et de la formation. L'utilisation non autorisée est illégale.

### **Q: Quels types de hashs sont supportés ?**
**R:** La plateforme supporte tous les types de hashs compatibles avec Hashcat et John the Ripper, incluant MD5, SHA-1, SHA-256, SHA-512, bcrypt, scrypt, NTLM, et de nombreux autres.

### **Q: Combien de temps faut-il pour cracker un mot de passe ?**
**R:** Cela dépend de nombreux facteurs : complexité du mot de passe, type de hash, puissance de calcul, qualité de la wordlist. Un mot de passe simple peut être cracké en secondes, tandis qu'un mot de passe complexe peut prendre des années.

### **Q: Puis-je utiliser cette plateforme sans GPU ?**
**R:** Oui, mais les performances seront considérablement réduites. Un CPU moderne peut traiter des millions de hashs par seconde, tandis qu'un GPU peut en traiter des milliards.

### **Q: Comment optimiser les performances de cracking ?**
**R:** 
- Utilisez des GPU modernes (RTX 30xx/40xx, RX 6000/7000)
- Optimisez vos wordlists (supprimez les doublons, triez par probabilité)
- Utilisez des règles de mutation intelligentes
- Configurez correctement les profils de charge de travail

### **Q: Les wordlists générées sont-elles efficaces ?**
**R:** Oui, très efficaces pour des cibles spécifiques. Les wordlists personnalisées basées sur OSINT et profils ciblés ont souvent de meilleurs taux de succès que les wordlists génériques.

### **Q: Peut-on intégrer cette plateforme dans des outils existants ?**
**R:** Absolument. La plateforme propose une API REST, des modules Python importables, et des formats d'export standards (JSON, CSV) pour faciliter l'intégration.

### **Q: Comment interpréter les scores d'entropie ?**
**R:**
- **< 20 bits** : Très faible (crackable instantanément)
- **20-35 bits** : Faible (crackable rapidement)
- **35-60 bits** : Moyen (résistant aux attaques basiques)
- **60-80 bits** : Fort (résistant aux attaques avancées)
- **> 80 bits** : Très fort (pratiquement incrackable)

### **Q: La plateforme stocke-t-elle les mots de passe ?**
**R:** Non, par défaut la plateforme ne stocke que les hashs et les métadonnées d'analyse. Les mots de passe en clair ne sont stockés que temporairement pendant les analyses et peuvent être immédiatement supprimés.

---

## 🤝 Support et Contribution

### Support

- **Documentation** : [docs/](./docs/)
- **Issues** : [GitHub Issues](https://github.com/votre-repo/issues)
- **Discussions** : [GitHub Discussions](https://github.com/votre-repo/discussions)
- **Email** : cybersecurity-portfolio@example.com

### Contribution

Nous accueillons les contributions ! Voici comment participer :

#### Signalement de Bugs

1. Vérifiez que le bug n'a pas déjà été signalé
2. Créez une issue avec :
   - Description détaillée du problème
   - Étapes pour reproduire
   - Environnement (OS, Python version, etc.)
   - Logs d'erreur

#### Propositions d'Améliorations

1. Créez une issue "Feature Request"
2. Décrivez clairement l'amélioration souhaitée
3. Expliquez le cas d'usage et les bénéfices

#### Code Contributions

```bash
# 1. Fork du repository
git clone https://github.com/votre-username/password-cracking-platform.git
cd password-cracking-platform

# 2. Création d'une branche
git checkout -b feature/nouvelle-fonctionnalite

# 3. Développement et tests
python -m pytest tests/

# 4. Commit et push
git commit -m "feat: ajout de nouvelle fonctionnalité"
git push origin feature/nouvelle-fonctionnalite

# 5. Création d'une Pull Request
```

#### Guidelines de Contribution

- **Code Style** : Suivez PEP 8 pour Python
- **Tests** : Ajoutez des tests pour toute nouvelle fonctionnalité
- **Documentation** : Mettez à jour la documentation si nécessaire
- **Commits** : Utilisez des messages de commit explicites

### Roadmap

#### Version 2.0 (Planifiée)

- **Interface Web** : Dashboard interactif avec Flask/Django
- **API REST complète** : Endpoints pour toutes les fonctionnalités
- **Support distribué** : Cracking sur plusieurs machines
- **Machine Learning** : Prédiction de patterns avec IA
- **Intégration Cloud** : Support AWS/Azure/GCP

#### Améliorations Continues

- **Performance** : Optimisations algorithmiques
- **Nouveaux détecteurs** : Patterns émergents
- **Export formats** : Nouveaux formats de rapport
- **Sécurité** : Renforcement de la sécurité des données

---

## 📄 Licence et Conformité

Ce projet est distribué sous licence MIT. Voir [LICENSE](../LICENSE) pour plus de détails.

### Utilisation Éthique

En utilisant cette plateforme, vous acceptez de :

1. **Respecter les lois locales** en matière de cybersécurité
2. **Obtenir des autorisations explicites** avant tout test
3. **Protéger les données** traitées pendant les analyses
4. **Signaler responsablement** les vulnérabilités découvertes
5. **Utiliser uniquement à des fins légitimes** (audit, formation, recherche)

### Clause de Non-Responsabilité

Les auteurs de cette plateforme ne sont pas responsables de l'utilisation malveillante ou non autorisée de ces outils. L'utilisateur assume l'entière responsabilité de l'usage conforme à la législation applicable.

---

*Dernière mise à jour : Janvier 2024*
*Version du guide : 1.0.0*