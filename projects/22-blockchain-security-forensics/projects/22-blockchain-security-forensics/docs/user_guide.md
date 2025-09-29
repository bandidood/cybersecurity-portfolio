# Blockchain Security & Cryptocurrency Forensics - Guide d'Utilisation

## 📖 Table des Matières
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Analyse de Transactions](#analyse-de-transactions)
5. [Investigations Forensiques](#investigations-forensiques)
6. [Analyse de Smart Contracts](#analyse-de-smart-contracts)
7. [Interface Web](#interface-web)
8. [Cas d'Usage](#cas-dusage)
9. [API Reference](#api-reference)
10. [Dépannage](#dépannage)

## Introduction

Cette plateforme fournit des outils avancés pour l'analyse de sécurité blockchain, les investigations de crimes liés aux cryptomonnaies, et l'audit de smart contracts. Elle s'adresse aux professionnels de la cybersécurité, aux enquêteurs, aux auditeurs de smart contracts, et aux institutions financières.

### Fonctionnalités Principales

- **Analyse Multi-Chaînes**: Support pour Bitcoin, Ethereum, BSC, Polygon, et autres blockchains
- **Forensique Cryptographique**: Investigation de ransomwares, blanchiment d'argent, fraudes
- **Audit de Smart Contracts**: Détection de vulnérabilités et exploits DeFi
- **Surveillance Temps Réel**: Monitoring des activités suspectes
- **Interface Web Interactive**: Dashboard pour visualiser les analyses

## Installation

### Méthode 1: Installation Standard

```bash
# Cloner le dépôt
git clone <repository-url>
cd blockchain-security-forensics

# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Installer les modèles NLP requis
python -m spacy download en_core_web_sm
```

### Méthode 2: Docker

```bash
# Construire l'image Docker
docker build -t blockchain-security .

# Lancer le conteneur
docker run -p 5000:5000 -p 8000:8000 blockchain-security
```

### Dépendances Système

- **Python 3.9+**
- **Node.js 16+** (pour l'interface web avancée)
- **Redis** (pour le cache et sessions)
- **PostgreSQL** (optionnel, pour stockage persistant)

## Configuration

### Configuration des API

Créer un fichier `config/api_keys.json`:

```json
{
  "etherscan_key": "YOUR_ETHERSCAN_API_KEY",
  "infura_key": "YOUR_INFURA_PROJECT_ID",
  "moralis_key": "YOUR_MORALIS_API_KEY",
  "blockcypher_token": "YOUR_BLOCKCYPHER_TOKEN",
  "chainanalysis_key": "YOUR_CHAINANALYSIS_API_KEY"
}
```

### Configuration des Seuils

Fichier `config/thresholds.json`:

```json
{
  "large_transaction": 10.0,
  "rapid_transfers": {
    "count": 10,
    "timeframe": 3600
  },
  "round_amounts": 0.001,
  "structuring_amount": 10000,
  "mixing_confidence": 0.8
}
```

## Analyse de Transactions

### Analyser une Transaction Unique

```python
from src.blockchain.transaction_analyzer import BlockchainAnalyzer

# Initialiser l'analyseur
analyzer = BlockchainAnalyzer('config/api_keys.json')

# Analyser une transaction Ethereum
tx_hash = "0x1234567890abcdef..."
tx_info = analyzer.analyze_transaction(tx_hash, 'ethereum')

print(f"Montant: {tx_info.amount} ETH")
print(f"Score de risque: {tx_info.risk_score}")
print(f"Tags: {', '.join(tx_info.tags)}")
```

### Tracer les Flux de Fonds

```python
# Tracer les flux sur 5 hops maximum
flow_results = analyzer.trace_transaction_flow(tx_hash, 'ethereum', max_hops=5)

print(f"Total tracé: {flow_results['total_amount_traced']} ETH")
print(f"Adresses uniques: {flow_results['unique_addresses']}")

# Visualiser le graphe de flux
import networkx as nx
import matplotlib.pyplot as plt

G = flow_results['flow_graph']
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_color='lightblue', 
        node_size=1500, font_size=8, font_weight='bold')
plt.show()
```

### Analyser un Profil d'Adresse

```python
# Analyser le profil complet d'une adresse
address = "0x742d35Cc6634C0532925a3b8D0baa8A8b4D3e3b"
profile = analyzer.analyze_address_profile(address, 'ethereum')

print(f"Solde: {profile.balance} ETH")
print(f"Nombre de transactions: {profile.transaction_count}")
print(f"Niveau de risque: {profile.risk_level}")
print(f"Classifications: {', '.join(profile.classifications)}")
```

## Investigations Forensiques

### Créer un Cas d'Investigation

```python
from src.forensics.crypto_investigator import CryptocurrencyForensics
from datetime import datetime

# Initialiser l'investigateur
investigator = CryptocurrencyForensics()

# Créer un cas de ransomware
victim_addresses = [
    '1VictimAddress123456789',
    '3AnotherVictimAddress987654321'
]

case_id = investigator.create_case(
    case_type='ransomware',
    victim_addresses=victim_addresses,
    crime_date=datetime.now(),
    estimated_loss=5.0,
    currency='BTC'
)

print(f"Cas créé: {case_id}")
```

### Enquête sur des Paiements de Ransomware

```python
# Investiguer les paiements de rançon
results = investigator.investigate_ransomware_payments(victim_addresses, case_id)

print(f"Paiements trouvés: {len(results['payments_found'])}")
print(f"Montant total payé: {results['total_paid']} BTC")
print(f"Famille de ransomware: {results['ransomware_family']}")

# Opportunités de récupération
for recovery in results['recovery_addresses']:
    print(f"Type: {recovery['type']}")
    print(f"Montant: {recovery['amount']} BTC")
    print(f"Faisabilité: {recovery['feasibility']}")
```

### Détection de Blanchiment d'Argent

```python
# Analyser une adresse pour des patterns de blanchiment
address = "1SuspiciousAddress123456789"
aml_results = investigator.detect_money_laundering(address, timeframe_days=30)

print(f"Niveau de risque: {aml_results['risk_level']}")
print(f"Patterns détectés: {', '.join(aml_results['patterns_detected'])}")
print(f"Score de risque: {aml_results['risk_score']}")

# Recommandations de conformité
for recommendation in aml_results['recommendations']:
    print(f"- {recommendation}")
```

### Filtrage contre les Listes de Sanctions

```python
# Vérifier des adresses contre les listes de sanctions
test_addresses = [
    '1NormalAddress123456789',
    '1SanctionedAddress987654321'
]

sanctions_result = investigator.screen_sanctions_lists(test_addresses)
print(f"Statut de conformité: {sanctions_result['compliance_status']}")

for match in sanctions_result['matches']:
    print(f"Adresse: {match['address']}")
    print(f"Liste: {match['sanctions_list']}")
    print(f"Action requise: {match['action_required']}")
```

## Analyse de Smart Contracts

### Scanner un Contrat pour les Vulnérabilités

```python
from src.smart_contracts.vulnerability_scanner import SmartContractScanner

# Initialiser le scanner
scanner = SmartContractScanner()

# Code Solidity à analyser
contract_code = """
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // Vulnérable à la réentrance
        msg.sender.call{value: amount}("");
        
        balances[msg.sender] -= amount;
    }
}
"""

# Analyser le contrat
analysis = scanner.scan_contract(contract_code, "TestContract", "0x123...")

print(f"Vulnérabilités trouvées: {len(analysis.vulnerabilities)}")
print(f"Score de risque global: {analysis.overall_risk_score}/10")
```

### Générer un Rapport de Sécurité

```python
# Générer un rapport complet
report = scanner.generate_report(analysis)

print(f"Niveau de risque: {report['security_summary']['risk_level']}")
print(f"Recommandation: {report['security_summary']['recommendation']}")

# Afficher les vulnérabilités par sévérité
for finding in report['detailed_findings']:
    print(f"\n{finding['title']}")
    print(f"Sévérité: {finding['severity']}")
    print(f"Ligne: {finding['location']['line']}")
    print(f"Recommandation: {finding['recommendation']}")
```

### Analyser les Patterns DeFi

```python
# Le scanner détecte automatiquement les patterns DeFi spécifiques
defi_contract = """
pragma solidity ^0.8.0;

contract DeFiProtocol {
    function flashLoan(uint256 amount) external {
        // Pattern de flash loan détecté
        // Vérifications de sécurité recommandées
    }
    
    function getPrice() external view returns (uint256) {
        // Utilisation d'oracle - risque de manipulation
        return oracle.latestPrice();
    }
}
"""

analysis = scanner.scan_contract(defi_contract, "DeFiProtocol")
# Le scanner identifiera automatiquement les risques DeFi
```

## Interface Web

### Lancer le Dashboard

```bash
# Démarrer l'interface web
cd src/web_interface
python app.py
```

Accéder au dashboard: `http://localhost:5000`

### Fonctionnalités du Dashboard

1. **Vue d'ensemble**: Statistiques globales et métriques clés
2. **Analyse de transactions**: Interface pour analyser des transactions individuelles
3. **Forensique**: Gestion des cas d'investigation
4. **Smart Contracts**: Upload et analyse de contrats
5. **Monitoring**: Surveillance temps réel des activités suspectes

### API REST

```bash
# Analyser une transaction via API
curl -X POST http://localhost:5000/api/analyze-transaction \
  -H "Content-Type: application/json" \
  -d '{"tx_hash": "0x123...", "blockchain": "ethereum"}'

# Créer un cas d'investigation
curl -X POST http://localhost:5000/api/create-case \
  -H "Content-Type: application/json" \
  -d '{
    "case_type": "ransomware",
    "victim_addresses": ["1Address123..."],
    "estimated_loss": 5.0,
    "currency": "BTC"
  }'
```

## Cas d'Usage

### Cas d'Usage 1: Investigation de Ransomware

**Scenario**: Une entreprise a été victime d'un ransomware et a payé la rançon. Vous devez tracer les fonds et identifier les opportunités de récupération.

```python
# 1. Créer le cas
case_id = investigator.create_case(
    case_type='ransomware',
    victim_addresses=['1CompanyWallet123...'],
    crime_date=datetime(2024, 1, 15),
    estimated_loss=10.0,
    currency='BTC'
)

# 2. Investiguer les paiements
results = investigator.investigate_ransomware_payments(
    ['1CompanyWallet123...'], case_id
)

# 3. Tracer les fonds
for payment in results['payments_found']:
    flow = analyzer.trace_transaction_flow(
        payment['tx_hash'], 'bitcoin', max_hops=10
    )
    
# 4. Générer le rapport
report = investigator.generate_forensic_report(case_id)
investigator.export_case_data(case_id, 'json')
```

### Cas d'Usage 2: Audit de Smart Contract DeFi

**Scenario**: Audit de sécurité d'un nouveau protocole DeFi avant le lancement.

```python
# 1. Charger le code du contrat
with open('defi_protocol.sol', 'r') as f:
    contract_code = f.read()

# 2. Analyser le contrat
analysis = scanner.scan_contract(
    contract_code, 
    "DeFiProtocol", 
    "0xProtocolAddress..."
)

# 3. Générer le rapport de sécurité
report = scanner.generate_report(analysis)

# 4. Exporter pour l'équipe de développement
filename = scanner.export_report(report, 'json')
print(f"Rapport sauvegardé: {filename}")

# 5. Vérifier les issues critiques
critical_issues = [
    vuln for vuln in analysis.vulnerabilities 
    if vuln.severity.value == 'critical'
]

if critical_issues:
    print("❌ Issues critiques trouvées - NE PAS DÉPLOYER")
    for issue in critical_issues:
        print(f"- {issue.title} (ligne {issue.location['line']})")
```

### Cas d'Usage 3: Conformité AML

**Scenario**: Vérification de conformité pour un exchange de cryptomonnaies.

```python
# 1. Listes d'adresses de clients à vérifier
client_addresses = [
    '1ClientAddress1...',
    '1ClientAddress2...',
    # ... plus d'adresses
]

# 2. Screening contre les sanctions
for address in client_addresses:
    # Vérification des sanctions
    sanctions_result = investigator.screen_sanctions_lists([address])
    
    if sanctions_result['matches']:
        print(f"⚠️ ALERTE: {address} sur liste de sanctions")
        # Actions immédiates requises
        
    # Analyse des patterns de blanchiment
    aml_result = investigator.detect_money_laundering(address)
    
    if aml_result['risk_level'] in ['HIGH', 'CRITICAL']:
        print(f"🚨 Risque élevé détecté: {address}")
        print(f"Patterns: {', '.join(aml_result['patterns_detected'])}")
```

## API Reference

### Classe BlockchainAnalyzer

#### `analyze_transaction(tx_hash: str, blockchain: str) -> TransactionInfo`
Analyse une transaction unique.

**Paramètres:**
- `tx_hash`: Hash de la transaction
- `blockchain`: Nom de la blockchain ('bitcoin', 'ethereum', etc.)

**Retour:** Objet `TransactionInfo` avec les détails d'analyse

#### `trace_transaction_flow(start_tx: str, blockchain: str, max_hops: int) -> Dict`
Trace le flux des fonds à travers plusieurs transactions.

**Paramètres:**
- `start_tx`: Transaction de départ
- `blockchain`: Blockchain à analyser  
- `max_hops`: Nombre maximum de sauts à suivre

### Classe CryptocurrencyForensics

#### `create_case(case_type: str, victim_addresses: List[str], crime_date: datetime) -> str`
Crée un nouveau cas d'investigation.

#### `investigate_ransomware_payments(victim_addresses: List[str], case_id: str) -> Dict`
Investigate les paiements de ransomware.

#### `detect_money_laundering(address: str, timeframe_days: int) -> Dict`
Détecte les patterns de blanchiment d'argent.

### Classe SmartContractScanner

#### `scan_contract(source_code: str, contract_name: str, contract_address: str) -> ContractAnalysis`
Analyse un smart contract pour les vulnérabilités.

#### `generate_report(analysis: ContractAnalysis) -> Dict`
Génère un rapport de sécurité complet.

## Dépannage

### Problèmes Courants

#### Erreur: "API key not configured"
**Solution**: Vérifier que les clés API sont correctement configurées dans `config/api_keys.json`

#### Erreur: "Rate limit exceeded"
**Solution**: 
- Ajouter des délais entre les requêtes
- Utiliser plusieurs clés API pour la rotation
- Implémenter un système de cache

#### Performance lente sur l'analyse de flux
**Solution**:
- Réduire le nombre de hops (`max_hops`)
- Utiliser le cache Redis
- Analyser par petits lots

#### Erreurs de mémoire avec de gros contrats
**Solution**:
- Augmenter la mémoire allouée
- Analyser le contrat par sections
- Optimiser les patterns de regex

### Logs et Debugging

```python
import logging

# Activer les logs détaillés
logging.basicConfig(level=logging.DEBUG)

# Logs spécifiques par module
logging.getLogger('blockchain_analyzer').setLevel(logging.DEBUG)
logging.getLogger('crypto_forensics').setLevel(logging.INFO)
```

### Support et Contact

- **Documentation**: Voir `/docs/` pour plus de détails
- **Issues**: Rapporter les bugs sur GitHub
- **Support**: Contacter l'équipe via email

---

**Version**: 1.0.0  
**Dernière mise à jour**: Janvier 2024  
**Auteur**: Équipe Blockchain Security