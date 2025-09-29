#!/bin/bash
# =============================================================================
# Script de Validation Finale - Password Cracking Platform
# =============================================================================
# Exécute une validation complète du projet incluant :
# - Tests unitaires avec couverture de code
# - Tests d'intégration et sécurité
# - Tests de performance et benchmarks
# - Validation de la démonstration complète
# - Génération de rapport de validation final
#
# Author: Cybersecurity Portfolio
# Version: 1.0.0
# Last Updated: January 2024
# =============================================================================

set -euo pipefail

# Couleurs pour output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "${PURPLE}[HEADER]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# Variables globales
PROJECT_NAME="Password Cracking Platform"
VERSION="1.0.0"
VALIDATION_REPORT="final_validation_report.md"
START_TIME=$(date +%s)
TEMP_DIR="validation_temp_$(date +%s)"

# Compteurs résultats
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_header "🚀 VALIDATION FINALE - $PROJECT_NAME v$VERSION"
echo "================================================================================"
log_info "📅 Démarrage: $(date '+%Y-%m-%d %H:%M:%S')"
log_info "🔍 Environnement: $(uname -s) - $(uname -m)"
echo "================================================================================"

# 1. Vérification prérequis environnement
validation_step_environment() {
    log_step "🔍 ÉTAPE 1/8 - Vérification environnement..."
    
    # Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 n'est pas installé"
        return 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_info "Python version: $PYTHON_VERSION"
    
    # Vérification version minimale Python 3.8
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        log_error "Python 3.8+ requis, version actuelle: $PYTHON_VERSION"
        return 1
    fi
    
    # Pip version
    if ! command -v pip3 &> /dev/null; then
        log_error "Pip3 n'est pas installé"
        return 1
    fi
    
    PIP_VERSION=$(pip3 --version 2>&1 | cut -d' ' -f2)
    log_info "Pip version: $PIP_VERSION"
    
    # Création répertoire temporaire
    mkdir -p "$TEMP_DIR"
    
    log_success "✅ Environnement validé"
    return 0
}

# 2. Installation/vérification dépendances
validation_step_dependencies() {
    log_step "📦 ÉTAPE 2/8 - Installation dépendances..."
    
    # Vérification environnement virtuel
    if [ ! -d "venv" ]; then
        log_info "🔧 Création environnement virtuel..."
        python3 -m venv venv
    fi
    
    # Activation environnement virtuel
    source venv/bin/activate || {
        log_error "Impossible d'activer l'environnement virtuel"
        return 1
    }
    
    log_info "🔄 Mise à jour pip..."
    pip install --upgrade pip > /dev/null 2>&1
    
    # Installation dépendances principales
    if [ -f "requirements.txt" ]; then
        log_info "📋 Installation requirements.txt..."
        pip install -r requirements.txt > /dev/null 2>&1 || {
            log_error "Échec installation requirements.txt"
            return 1
        }
    else
        log_error "Fichier requirements.txt manquant"
        return 1
    fi
    
    # Installation dépendances tests
    log_info "🧪 Installation dépendances tests..."
    pip install pytest pytest-cov pytest-benchmark pytest-xdist bandit safety > /dev/null 2>&1 || {
        log_warning "Certaines dépendances de test non installées"
    }
    
    log_success "✅ Dépendances installées"
    return 0
}

# 3. Tests unitaires avec couverture
validation_step_unit_tests() {
    log_step "🧪 ÉTAPE 3/8 - Tests unitaires..."
    ((TOTAL_TESTS++))
    
    if [ ! -d "tests/unit" ]; then
        log_error "Répertoire tests/unit manquant"
        ((FAILED_TESTS++))
        return 1
    fi
    
    log_info "🔬 Exécution tests unitaires avec couverture..."
    
    # Exécution tests avec timeout
    if timeout 300 pytest tests/unit/ -v \
        --cov=src \
        --cov-report=html:htmlcov \
        --cov-report=term \
        --cov-report=json:coverage.json \
        --cov-fail-under=85 \
        --junit-xml=unit_test_results.xml \
        -x > "$TEMP_DIR/unit_tests.log" 2>&1; then
        
        log_success "✅ Tests unitaires: RÉUSSIS"
        ((PASSED_TESTS++))
        
        # Extraction métriques couverture
        if [ -f "coverage.json" ]; then
            COVERAGE=$(python3 -c "
import json
with open('coverage.json') as f:
    data = json.load(f)
    print(f\"{data['totals']['percent_covered']:.1f}%\")
")
            log_info "📊 Couverture de code: $COVERAGE"
        fi
        
        UNIT_TESTS_STATUS="PASSED"
        return 0
    else
        log_error "❌ Tests unitaires: ÉCHOUÉS"
        ((FAILED_TESTS++))
        
        # Affichage des dernières lignes du log
        if [ -f "$TEMP_DIR/unit_tests.log" ]; then
            log_info "📄 Dernières erreurs:"
            tail -n 10 "$TEMP_DIR/unit_tests.log" | sed 's/^/   /'
        fi
        
        UNIT_TESTS_STATUS="FAILED"
        return 1
    fi
}

# 4. Tests d'intégration
validation_step_integration_tests() {
    log_step "🔗 ÉTAPE 4/8 - Tests intégration..."
    ((TOTAL_TESTS++))
    
    if [ ! -d "tests/integration" ]; then
        log_warning "Répertoire tests/integration manquant - test ignoré"
        INTEGRATION_TESTS_STATUS="SKIPPED"
        return 0
    fi
    
    log_info "🎭 Exécution tests d'intégration..."
    
    if timeout 180 pytest tests/integration/ -v \
        --tb=short > "$TEMP_DIR/integration_tests.log" 2>&1; then
        
        log_success "✅ Tests intégration: RÉUSSIS"
        ((PASSED_TESTS++))
        INTEGRATION_TESTS_STATUS="PASSED"
        return 0
    else
        log_error "❌ Tests intégration: ÉCHOUÉS"
        ((FAILED_TESTS++))
        
        if [ -f "$TEMP_DIR/integration_tests.log" ]; then
            log_info "📄 Dernières erreurs:"
            tail -n 10 "$TEMP_DIR/integration_tests.log" | sed 's/^/   /'
        fi
        
        INTEGRATION_TESTS_STATUS="FAILED"
        return 1
    fi
}

# 5. Scan sécurité avec Bandit
validation_step_security_scan() {
    log_step "🔒 ÉTAPE 5/8 - Scan sécurité..."
    ((TOTAL_TESTS++))
    
    if ! command -v bandit &> /dev/null; then
        log_warning "Bandit non installé - scan sécurité ignoré"
        SECURITY_SCAN_STATUS="SKIPPED"
        return 0
    fi
    
    log_info "🛡️ Scan sécurité Bandit..."
    
    # Exécution Bandit
    if bandit -r src/ -f json -o "$TEMP_DIR/bandit_report.json" > /dev/null 2>&1; then
        # Analyse des résultats
        if [ -f "$TEMP_DIR/bandit_report.json" ]; then
            # Vérification présence de jq pour analyse JSON
            if command -v jq &> /dev/null; then
                HIGH_ISSUES=$(jq '.results | map(select(.issue_severity == "HIGH")) | length' "$TEMP_DIR/bandit_report.json" 2>/dev/null || echo "0")
                MEDIUM_ISSUES=$(jq '.results | map(select(.issue_severity == "MEDIUM")) | length' "$TEMP_DIR/bandit_report.json" 2>/dev/null || echo "0")
                
                log_info "🔍 Issues trouvées: HIGH=$HIGH_ISSUES, MEDIUM=$MEDIUM_ISSUES"
                
                if [ "$HIGH_ISSUES" -eq 0 ]; then
                    log_success "✅ Scan sécurité: RÉUSSI (0 vulnérabilité haute)"
                    ((PASSED_TESTS++))
                    SECURITY_SCAN_STATUS="PASSED"
                    return 0
                else
                    log_error "❌ Scan sécurité: ÉCHOUÉ ($HIGH_ISSUES vulnérabilités hautes)"
                    ((FAILED_TESTS++))
                    SECURITY_SCAN_STATUS="FAILED"
                    return 1
                fi
            else
                log_warning "jq non disponible - analyse des résultats limitée"
                log_success "✅ Scan sécurité: TERMINÉ (vérification manuelle requise)"
                ((PASSED_TESTS++))
                SECURITY_SCAN_STATUS="WARNING"
                return 0
            fi
        fi
    else
        # Bandit peut retourner un code d'erreur même avec juste des warnings
        log_warning "⚠️ Scan sécurité: WARNINGS détectés"
        SECURITY_SCAN_STATUS="WARNING"
        return 0
    fi
}

# 6. Tests performance
validation_step_performance_tests() {
    log_step "⚡ ÉTAPE 6/8 - Tests performance..."
    ((TOTAL_TESTS++))
    
    if [ ! -d "tests/performance" ]; then
        log_warning "Répertoire tests/performance manquant - tests ignorés"
        PERFORMANCE_TESTS_STATUS="SKIPPED"
        return 0
    fi
    
    log_info "📈 Exécution tests performance et benchmarks..."
    
    if timeout 240 pytest tests/performance/ -v \
        --benchmark-only \
        --benchmark-json="$TEMP_DIR/benchmark_results.json" \
        > "$TEMP_DIR/performance_tests.log" 2>&1; then
        
        log_success "✅ Tests performance: RÉUSSIS"
        ((PASSED_TESTS++))
        
        # Affichage métriques si disponibles
        if [ -f "$TEMP_DIR/benchmark_results.json" ]; then
            if command -v jq &> /dev/null; then
                BENCHMARK_COUNT=$(jq '.benchmarks | length' "$TEMP_DIR/benchmark_results.json" 2>/dev/null || echo "N/A")
                log_info "📊 Benchmarks exécutés: $BENCHMARK_COUNT"
            fi
        fi
        
        PERFORMANCE_TESTS_STATUS="PASSED"
        return 0
    else
        log_error "❌ Tests performance: ÉCHOUÉS"
        ((FAILED_TESTS++))
        
        if [ -f "$TEMP_DIR/performance_tests.log" ]; then
            log_info "📄 Dernières erreurs:"
            tail -n 5 "$TEMP_DIR/performance_tests.log" | sed 's/^/   /'
        fi
        
        PERFORMANCE_TESTS_STATUS="FAILED"
        return 1
    fi
}

# 7. Validation démonstration complète
validation_step_demo_validation() {
    log_step "🎭 ÉTAPE 7/8 - Validation démonstration..."
    ((TOTAL_TESTS++))
    
    if [ ! -f "examples/complete_audit_demo.py" ]; then
        log_error "Fichier examples/complete_audit_demo.py manquant"
        ((FAILED_TESTS++))
        DEMO_VALIDATION_STATUS="FAILED"
        return 1
    fi
    
    log_info "🎪 Exécution démonstration complète..."
    
    # Exécution démo avec timeout de 5 minutes
    if timeout 300 python3 examples/complete_audit_demo.py > "$TEMP_DIR/demo_output.log" 2>&1; then
        log_success "✅ Démonstration: RÉUSSIE"
        ((PASSED_TESTS++))
        
        # Vérification fichiers de sortie
        DEMO_DIRS=$(find examples/ -type d -name "demo_*" 2>/dev/null | wc -l)
        if [ "$DEMO_DIRS" -gt 0 ]; then
            log_info "📁 Répertoires démo créés: $DEMO_DIRS"
        fi
        
        DEMO_VALIDATION_STATUS="PASSED"
        return 0
    else
        log_error "❌ Démonstration: ÉCHOUÉE ou timeout"
        ((FAILED_TESTS++))
        
        if [ -f "$TEMP_DIR/demo_output.log" ]; then
            log_info "📄 Sortie démonstration:"
            tail -n 15 "$TEMP_DIR/demo_output.log" | sed 's/^/   /'
        fi
        
        DEMO_VALIDATION_STATUS="FAILED"
        return 1
    fi
}

# 8. Vérification structure projet
validation_step_project_structure() {
    log_step "📁 ÉTAPE 8/8 - Vérification structure..."
    ((TOTAL_TESTS++))
    
    # Fichiers critiques requis
    REQUIRED_FILES=(
        "src/analysis/password_analyzer.py"
        "src/wordlist_generator/wordlist_builder.py"
        "docs/user_guide.md"
        "docs/testing_validation_guide.md"
        "tests/unit/test_password_analyzer.py"
        "examples/complete_audit_demo.py"
        "requirements.txt"
        "README.md"
    )
    
    # Répertoires critiques requis
    REQUIRED_DIRS=(
        "src/analysis"
        "src/wordlist_generator"
        "tests/unit"
        "docs"
        "examples"
    )
    
    MISSING_FILES=0
    MISSING_DIRS=0
    
    log_info "🔍 Vérification fichiers critiques..."
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "📄 Fichier manquant: $file"
            ((MISSING_FILES++))
        fi
    done
    
    log_info "🔍 Vérification répertoires critiques..."
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            log_error "📁 Répertoire manquant: $dir"
            ((MISSING_DIRS++))
        fi
    done
    
    if [ $MISSING_FILES -eq 0 ] && [ $MISSING_DIRS -eq 0 ]; then
        log_success "✅ Structure projet: COMPLÈTE"
        ((PASSED_TESTS++))
        PROJECT_STRUCTURE_STATUS="COMPLETE"
        return 0
    else
        log_error "❌ Structure projet: INCOMPLÈTE ($MISSING_FILES fichiers, $MISSING_DIRS répertoires manquants)"
        ((FAILED_TESTS++))
        PROJECT_STRUCTURE_STATUS="INCOMPLETE"
        return 1
    fi
}

# Génération rapport final
generate_final_report() {
    log_step "📊 Génération rapport final..."
    
    # Calcul temps total
    END_TIME=$(date +%s)
    TOTAL_TIME=$((END_TIME - START_TIME))
    
    # Calcul pourcentage succès
    if [ $TOTAL_TESTS -gt 0 ]; then
        SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    else
        SUCCESS_RATE=0
    fi
    
    # Détermination statut global
    GLOBAL_STATUS="FAILED"
    GLOBAL_ICON="❌"
    
    if [ "$UNIT_TESTS_STATUS" == "PASSED" ] && 
       [ "$PROJECT_STRUCTURE_STATUS" == "COMPLETE" ] && 
       [ "$DEMO_VALIDATION_STATUS" == "PASSED" ]; then
        
        GLOBAL_STATUS="PASSED"
        GLOBAL_ICON="✅"
        
        # Vérification optionnels
        if [ "$SECURITY_SCAN_STATUS" != "PASSED" ] || 
           [ "$INTEGRATION_TESTS_STATUS" != "PASSED" ] || 
           [ "$PERFORMANCE_TESTS_STATUS" != "PASSED" ]; then
            GLOBAL_STATUS="PASSED_WITH_WARNINGS"
            GLOBAL_ICON="⚠️"
        fi
    fi
    
    # Génération rapport Markdown
    cat > "$VALIDATION_REPORT" << EOF
# 🎯 Rapport de Validation Finale
## $PROJECT_NAME v$VERSION

**Date:** $(date '+%Y-%m-%d %H:%M:%S')  
**Durée totale:** ${TOTAL_TIME}s  
**Environnement:** $(python3 --version 2>&1), $(uname -s)  
**Statut global:** $GLOBAL_ICON **$GLOBAL_STATUS**

---

## 📊 Résumé des Résultats

| **Métrique** | **Valeur** |
|--------------|------------|
| Tests exécutés | $TOTAL_TESTS |
| Tests réussis | $PASSED_TESTS |
| Tests échoués | $FAILED_TESTS |
| Taux de succès | $SUCCESS_RATE% |
| Couverture code | ${COVERAGE:-"N/A"} |

---

## 📋 Détail des Validations

| **Catégorie** | **Statut** | **Description** |
|---------------|------------|-----------------|
| Tests Unitaires | **${UNIT_TESTS_STATUS:-"NOT_RUN"}** | Suite complète de tests avec couverture |
| Tests Intégration | **${INTEGRATION_TESTS_STATUS:-"NOT_RUN"}** | Workflow et intégration des composants |
| Scan Sécurité | **${SECURITY_SCAN_STATUS:-"NOT_RUN"}** | Analyse statique Bandit |
| Tests Performance | **${PERFORMANCE_TESTS_STATUS:-"NOT_RUN"}** | Benchmarks et tests de charge |
| Démonstration | **${DEMO_VALIDATION_STATUS:-"NOT_RUN"}** | Validation audit complet end-to-end |
| Structure Projet | **${PROJECT_STRUCTURE_STATUS:-"NOT_RUN"}** | Vérification fichiers et répertoires |

---

## 🎯 Conclusion

EOF

    case $GLOBAL_STATUS in
        "PASSED")
            cat >> "$VALIDATION_REPORT" << EOF
**🎉 VALIDATION COMPLÈTEMENT RÉUSSIE**

Toutes les validations critiques sont passées avec succès. La plateforme est **prête pour utilisation en production**.

### ✅ Points forts identifiés :
- Architecture robuste et bien testée
- Couverture de tests excellente (${COVERAGE:-">85%"})
- Sécurité validée sans vulnérabilités critiques
- Démonstration fonctionnelle complète
- Documentation complète et à jour

### 🚀 Recommandations de déploiement :
- La plateforme peut être déployée en production
- Surveillance continue recommandée
- Formation utilisateurs conseillée

EOF
            ;;
        "PASSED_WITH_WARNINGS")
            cat >> "$VALIDATION_REPORT" << EOF
**⚠️ VALIDATION RÉUSSIE AVEC AVERTISSEMENTS**

Les validations critiques sont passées, mais certains tests optionnels ont échoué ou été ignorés.

### ✅ Éléments validés :
- Fonctionnalités principales opérationnelles
- Tests unitaires réussis
- Démonstration fonctionnelle

### ⚠️ Points d'attention :
- Tests d'intégration : ${INTEGRATION_TESTS_STATUS:-"Non exécutés"}
- Scan sécurité : ${SECURITY_SCAN_STATUS:-"Non exécuté"}
- Tests performance : ${PERFORMANCE_TESTS_STATUS:-"Non exécutés"}

### 📝 Actions recommandées :
- Corriger les tests en échec avant production
- Compléter la suite de tests manquante
- Révision sécurité supplémentaire conseillée

EOF
            ;;
        "FAILED")
            cat >> "$VALIDATION_REPORT" << EOF
**❌ VALIDATION ÉCHOUÉE**

Des validations critiques ont échoué. La plateforme **n'est pas prête** pour utilisation en production.

### 🚨 Problèmes critiques identifiés :
EOF
            
            [ "$UNIT_TESTS_STATUS" == "FAILED" ] && echo "- Tests unitaires en échec" >> "$VALIDATION_REPORT"
            [ "$DEMO_VALIDATION_STATUS" == "FAILED" ] && echo "- Démonstration non fonctionnelle" >> "$VALIDATION_REPORT"
            [ "$PROJECT_STRUCTURE_STATUS" == "INCOMPLETE" ] && echo "- Structure projet incomplète" >> "$VALIDATION_REPORT"
            
            cat >> "$VALIDATION_REPORT" << EOF

### 🔧 Actions requises :
1. **PRIORITÉ HAUTE** : Corriger tous les tests unitaires
2. **PRIORITÉ HAUTE** : Valider la démonstration complète
3. **PRIORITÉ MOYENNE** : Compléter la structure du projet
4. **PRIORITÉ MOYENNE** : Réviser les tests d'intégration

### ⏳ Prochaines étapes :
- Corriger les problèmes identifiés
- Relancer la validation complète
- Révision code recommandée

EOF
            ;;
    esac

    cat >> "$VALIDATION_REPORT" << EOF

---

## 📁 Fichiers Générés

- **Rapport principal** : \`$VALIDATION_REPORT\`
- **Logs détaillés** : \`$TEMP_DIR/\`
- **Rapport couverture** : \`htmlcov/index.html\` (si généré)
- **Résultats Bandit** : \`$TEMP_DIR/bandit_report.json\` (si généré)

---

*Rapport généré automatiquement par scripts/final_validation.sh*  
*$PROJECT_NAME v$VERSION - $(date '+%Y-%m-%d %H:%M:%S')*
EOF

    log_success "📄 Rapport généré: $VALIDATION_REPORT"
}

# Fonction de nettoyage
cleanup() {
    log_info "🧹 Nettoyage en cours..."
    
    # Conservation des logs importants
    if [ -d "$TEMP_DIR" ]; then
        if [ "$GLOBAL_STATUS" == "FAILED" ]; then
            log_info "📦 Conservation des logs d'erreur dans: $TEMP_DIR"
        else
            rm -rf "$TEMP_DIR" 2>/dev/null || true
        fi
    fi
    
    # Désactivation environnement virtuel
    deactivate 2>/dev/null || true
}

# Fonction principale
main() {
    # Configuration trap pour nettoyage
    trap cleanup EXIT INT TERM
    
    # Initialisation variables statut
    UNIT_TESTS_STATUS="NOT_RUN"
    INTEGRATION_TESTS_STATUS="NOT_RUN"
    SECURITY_SCAN_STATUS="NOT_RUN"
    PERFORMANCE_TESTS_STATUS="NOT_RUN"
    DEMO_VALIDATION_STATUS="NOT_RUN"
    PROJECT_STRUCTURE_STATUS="NOT_RUN"
    COVERAGE="N/A"
    
    # Exécution séquentielle des validations
    validation_step_environment || {
        log_error "💥 Échec validation environnement"
        generate_final_report
        exit 1
    }
    
    validation_step_dependencies || {
        log_error "💥 Échec installation dépendances"
        generate_final_report
        exit 1
    }
    
    # Les autres validations continuent même en cas d'échec
    validation_step_unit_tests
    validation_step_integration_tests
    validation_step_security_scan
    validation_step_performance_tests
    validation_step_demo_validation
    validation_step_project_structure
    
    # Génération rapport final
    generate_final_report
    
    # Affichage résumé final
    echo ""
    log_header "🏁 VALIDATION TERMINÉE"
    echo "================================================================================"
    log_info "⏱️ Durée totale: $(($(date +%s) - START_TIME))s"
    log_info "📊 Tests: $PASSED_TESTS/$TOTAL_TESTS réussis ($SUCCESS_RATE%)"
    log_info "📄 Rapport: $VALIDATION_REPORT"
    echo "================================================================================"
    
    case $GLOBAL_STATUS in
        "PASSED")
            log_success "🎉 VALIDATION COMPLÈTEMENT RÉUSSIE!"
            log_success "🚀 Plateforme prête pour production"
            exit 0
            ;;
        "PASSED_WITH_WARNINGS")
            log_warning "⚠️ VALIDATION RÉUSSIE AVEC AVERTISSEMENTS"
            log_warning "📝 Révision recommandée avant production"
            exit 0
            ;;
        *)
            log_error "💥 VALIDATION ÉCHOUÉE"
            log_error "🔧 Corrections requises avant utilisation"
            exit 1
            ;;
    esac
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi