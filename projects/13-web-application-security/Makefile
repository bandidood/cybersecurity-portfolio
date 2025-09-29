# Web Application Security Testing Framework - Makefile Avancé
# Projet 13 : Framework complet de test de sécurité des applications web
# Version : 1.0.0

# Configuration du projet
PROJECT_NAME := web-application-security
PROJECT_VERSION := 1.0.0
BUILD_DATE := $(shell date +"%Y-%m-%d")
BUILD_TIME := $(shell date +"%H:%M:%S")

# Structure des répertoires
PROJECT_ROOT := $(shell pwd)
SCRIPTS_DIR := $(PROJECT_ROOT)/scripts
TOOLS_DIR := $(PROJECT_ROOT)/tools
CONFIGS_DIR := $(PROJECT_ROOT)/configs
REPORTS_DIR := $(PROJECT_ROOT)/reports
EVIDENCE_DIR := $(PROJECT_ROOT)/evidence
LAB_DIR := $(PROJECT_ROOT)/lab
DOCS_DIR := $(PROJECT_ROOT)/docs
TESTS_DIR := $(PROJECT_ROOT)/tests
FRAMEWORKS_DIR := $(PROJECT_ROOT)/frameworks

# Configuration Docker
DOCKER_COMPOSE := docker-compose
DOCKER_NETWORK := websec-network
DOCKER_PROJECT := websec-lab

# Configuration des cibles (peut être surchargée via ligne de commande)
TARGET_URL ?= http://localhost:3000
TARGET_DOMAIN ?= localhost
TARGET_IPS ?= 127.0.0.1
SCAN_DEPTH ?= comprehensive
SCAN_THREADS ?= 20

# Configuration de test
TEST_TYPE ?= owasp-top10
ASVS_LEVEL ?= 2
OUTPUT_FORMAT ?= json
REPORT_TYPE ?= technical
SESSION_ID ?= websec-$(shell date +"%Y%m%d-%H%M%S")

# Python et environnement virtuel
PYTHON := python3
VENV_DIR := venv
PIP := $(VENV_DIR)/bin/pip
PYTHON_VENV := $(VENV_DIR)/bin/python

# Couleurs pour l'affichage
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
NC := \033[0m # No Color

# Cible d'aide (par défaut)
.PHONY: help
help:
	@echo "$(BLUE)===========================================$(NC)"
	@echo "$(BLUE) Framework de Test de Sécurité Web v$(PROJECT_VERSION)$(NC)"
	@echo "$(BLUE)===========================================$(NC)"
	@echo ""
	@echo "$(GREEN)Installation & Configuration :$(NC)"
	@echo "  make install                   Installer toutes les dépendances et configurer l'environnement"
	@echo "  make install-tools             Installer les outils de test de sécurité web"
	@echo "  make install-python            Installer les dépendances Python"
	@echo "  make setup-environment         Configurer l'environnement de test"
	@echo "  make clean-install             Nettoyer et réinstaller"
	@echo ""
	@echo "$(GREEN)Laboratoire d'Applications :$(NC)"
	@echo "  make lab-deploy                Déployer le laboratoire complet de sécurité web"
	@echo "  make lab-start                 Démarrer les services du laboratoire"
	@echo "  make lab-stop                  Arrêter les services du laboratoire"
	@echo "  make lab-restart               Redémarrer le laboratoire"
	@echo "  make lab-status                Afficher le statut du laboratoire"
	@echo "  make lab-logs                  Afficher les logs du laboratoire"
	@echo "  make lab-cleanup               Nettoyer le laboratoire"
	@echo ""
	@echo "$(GREEN)Tests OWASP Top 10 2021 :$(NC)"
	@echo "  make owasp-full-test           Test complet OWASP Top 10"
	@echo "  make owasp-a01-test            A01:2021 - Broken Access Control"
	@echo "  make owasp-a02-test            A02:2021 - Cryptographic Failures"
	@echo "  make owasp-a03-test            A03:2021 - Injection"
	@echo "  make owasp-a04-test            A04:2021 - Insecure Design"
	@echo "  make owasp-a05-test            A05:2021 - Security Misconfiguration"
	@echo "  make owasp-a06-test            A06:2021 - Vulnerable Components"
	@echo "  make owasp-a07-test            A07:2021 - Authentication Failures"
	@echo "  make owasp-a08-test            A08:2021 - Software Integrity Failures"
	@echo "  make owasp-a09-test            A09:2021 - Logging Failures"
	@echo "  make owasp-a10-test            A10:2021 - Server-Side Request Forgery"
	@echo ""
	@echo "$(GREEN)Tests ASVS 4.0 :$(NC)"
	@echo "  make asvs-level1-test          Test ASVS Niveau 1 (Opportuniste)"
	@echo "  make asvs-level2-test          Test ASVS Niveau 2 (Standard)"
	@echo "  make asvs-level3-test          Test ASVS Niveau 3 (Avancé)"
	@echo "  make asvs-architecture         V1: Architecture & Threat Modeling"
	@echo "  make asvs-authentication       V2: Authentication Verification"
	@echo "  make asvs-session              V3: Session Management"
	@echo "  make asvs-access-control       V4: Access Control Verification"
	@echo "  make asvs-validation           V5: Validation & Encoding"
	@echo ""
	@echo "$(GREEN)Analyse de Sécurité :$(NC)"
	@echo "  make sast-scan                 Analyse statique (SAST)"
	@echo "  make dast-scan                 Analyse dynamique (DAST)"
	@echo "  make iast-scan                 Analyse interactive (IAST)"
	@echo "  make sca-scan                  Analyse de composition (SCA)"
	@echo "  make comprehensive-scan        Analyse complète multi-outils"
	@echo ""
	@echo "$(GREEN)Tests de Reconnaissance :$(NC)"
	@echo "  make recon-passive             Reconnaissance passive"
	@echo "  make recon-active              Reconnaissance active"
	@echo "  make recon-subdomain           Énumération de sous-domaines"
	@echo "  make recon-technology          Détection de stack technologique"
	@echo "  make recon-content             Découverte de contenu"
	@echo ""
	@echo "$(GREEN)Tests d'Exploitation :$(NC)"
	@echo "  make exploit-sqli              Exploitation SQL Injection"
	@echo "  make exploit-xss               Exploitation Cross-Site Scripting"
	@echo "  make exploit-csrf              Exploitation CSRF"
	@echo "  make exploit-upload            Exploitation upload de fichiers"
	@echo "  make exploit-custom            Exploitation personnalisée"
	@echo ""
	@echo "$(GREEN)Tests API :$(NC)"
	@echo "  make api-rest-test             Test sécurité API REST"
	@echo "  make api-graphql-test          Test sécurité API GraphQL"
	@echo "  make api-auth-test             Test authentification API"
	@echo "  make api-rate-limit-test       Test limitation de taux API"
	@echo ""
	@echo "$(GREEN)Tests Spécialisés :$(NC)"
	@echo "  make spa-security-test         Test sécurité Single Page App"
	@echo "  make mobile-web-test           Test sécurité applications mobile web"
	@echo "  make cloud-web-test            Test sécurité applications cloud"
	@echo "  make devsecops-integration     Intégration pipeline DevSecOps"
	@echo ""
	@echo "$(GREEN)Génération de Rapports :$(NC)"
	@echo "  make report-executive          Rapport exécutif"
	@echo "  make report-technical          Rapport technique détaillé"
	@echo "  make report-owasp              Rapport conformité OWASP"
	@echo "  make report-asvs               Rapport conformité ASVS"
	@echo "  make report-compliance         Rapport conformité réglementaire"
	@echo ""
	@echo "$(GREEN)Monitoring & Analyse :$(NC)"
	@echo "  make monitor-start             Démarrer monitoring"
	@echo "  make monitor-stop              Arrêter monitoring"
	@echo "  make logs-analyze              Analyser les logs de test"
	@echo "  make metrics-dashboard         Dashboard métriques"
	@echo "  make security-metrics          Métriques de sécurité"
	@echo ""
	@echo "$(GREEN)Maintenance & Santé :$(NC)"
	@echo "  make health-check              Vérification de santé système"
	@echo "  make security-check            Validation sécurité framework"
	@echo "  make update-tools              Mise à jour outils sécurité"
	@echo "  make backup-create             Créer sauvegarde système"
	@echo ""
	@echo "$(GREEN)Exemples d'usage :$(NC)"
	@echo "  make owasp-full-test TARGET_URL=https://example.com"
	@echo "  make asvs-level2-test TARGET_URL=https://app.example.com"
	@echo "  make comprehensive-scan TARGET_DOMAIN=example.com"
	@echo "  make report-technical SESSION_ID=websec-20240128"
	@echo ""
	@echo "$(YELLOW)Variables :$(NC)"
	@echo "  TARGET_URL=URL            URL cible (défaut: $(TARGET_URL))"
	@echo "  TARGET_DOMAIN=DOMAIN      Domaine cible (défaut: $(TARGET_DOMAIN))"
	@echo "  SESSION_ID=ID             ID session test (défaut: auto-généré)"
	@echo "  ASVS_LEVEL=LEVEL          Niveau ASVS (défaut: $(ASVS_LEVEL))"
	@echo "  SCAN_DEPTH=DEPTH          Profondeur scan (défaut: $(SCAN_DEPTH))"

# ===================================
# INSTALLATION & CONFIGURATION
# ===================================

.PHONY: install install-tools install-python setup-environment clean-install

install: install-python install-tools setup-environment
	@echo "$(GREEN)✓ Installation terminée avec succès$(NC)"
	@echo "$(YELLOW)Prochaines étapes : Exécutez 'make lab-deploy' pour configurer le laboratoire$(NC)"

install-python:
	@echo "$(BLUE)Installation des dépendances Python...$(NC)"
	@$(PYTHON) -m venv $(VENV_DIR)
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Dépendances Python installées$(NC)"

install-tools:
	@echo "$(BLUE)Installation des outils de test de sécurité web...$(NC)"
	@sudo apt-get update && sudo apt-get install -y \
		burpsuite zaproxy nikto sqlmap wapiti gobuster \
		nmap masscan nuclei sublist3r amass \
		socat netcat-openbsd curl wget \
		jq xmlstarlet html-xml-utils \
		docker.io docker-compose \
		git python3-pip nodejs npm \
		default-jre default-jdk maven gradle
	@echo "$(GREEN)✓ Outils de test de sécurité installés$(NC)"

setup-environment:
	@echo "$(BLUE)Configuration de l'environnement de test...$(NC)"
	@mkdir -p $(REPORTS_DIR) $(EVIDENCE_DIR) $(CONFIGS_DIR) $(TOOLS_DIR)
	@mkdir -p $(REPORTS_DIR)/{templates,examples,automated,compliance}
	@mkdir -p $(EVIDENCE_DIR)/{screenshots,logs,payloads,findings}
	@mkdir -p $(TESTS_DIR)/{owasp-top10,asvs,custom,regression}
	@chmod +x $(SCRIPTS_DIR)/**/*.py $(SCRIPTS_DIR)/**/*.sh
	@docker network create $(DOCKER_NETWORK) 2>/dev/null || true
	@echo "$(GREEN)✓ Configuration environnement terminée$(NC)"

clean-install:
	@echo "$(YELLOW)Nettoyage installation précédente...$(NC)"
	@rm -rf $(VENV_DIR)
	@docker system prune -f
	@make install

# ===================================
# LABORATOIRE D'APPLICATIONS
# ===================================

.PHONY: lab-deploy lab-start lab-stop lab-restart lab-status lab-logs lab-cleanup

lab-deploy: setup-environment
	@echo "$(BLUE)Déploiement du laboratoire de sécurité web...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) build
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) up -d
	@echo "$(GREEN)✓ Laboratoire déployé$(NC)"
	@echo "$(YELLOW)URLs d'accès :$(NC)"
	@echo "  OWASP Juice Shop : http://localhost:3000"
	@echo "  DVWA            : http://localhost:8080"
	@echo "  WebGoat         : http://localhost:8081"
	@echo "  Mutillidae      : http://localhost:8082"
	@echo "  bWAPP           : http://localhost:8083"
	@echo "  Kibana          : http://localhost:5601"
	@echo "  Grafana         : http://localhost:3001"

lab-start:
	@echo "$(BLUE)Démarrage du laboratoire...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) start
	@echo "$(GREEN)✓ Laboratoire démarré$(NC)"

lab-stop:
	@echo "$(BLUE)Arrêt du laboratoire...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) stop
	@echo "$(GREEN)✓ Laboratoire arrêté$(NC)"

lab-restart: lab-stop lab-start

lab-status:
	@echo "$(BLUE)Statut du Laboratoire :$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) ps

lab-logs:
	@echo "$(BLUE)Logs du Laboratoire :$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) logs --tail=50

lab-cleanup:
	@echo "$(YELLOW)Nettoyage du laboratoire...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) down -v
	@docker system prune -f
	@echo "$(GREEN)✓ Laboratoire nettoyé$(NC)"

# ===================================
# TESTS OWASP TOP 10 2021
# ===================================

.PHONY: owasp-full-test owasp-a01-test owasp-a02-test owasp-a03-test owasp-a04-test owasp-a05-test owasp-a06-test owasp-a07-test owasp-a08-test owasp-a09-test owasp-a10-test

owasp-full-test:
	@echo "$(BLUE)Test OWASP Top 10 2021 complet...$(NC)"
	@echo "$(YELLOW)URL cible : $(TARGET_URL)$(NC)"
	@echo "$(YELLOW)Session : $(SESSION_ID)$(NC)"
	@mkdir -p $(REPORTS_DIR)/$(SESSION_ID)
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/owasp_top10_full_test.py \
		--url $(TARGET_URL) \
		--session $(SESSION_ID) \
		--output $(REPORTS_DIR)/$(SESSION_ID) \
		--format $(OUTPUT_FORMAT)
	@make report-owasp SESSION_ID=$(SESSION_ID)
	@echo "$(GREEN)✓ Test OWASP Top 10 complet terminé$(NC)"

owasp-a01-test:
	@echo "$(BLUE)Test A01:2021 - Broken Access Control...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/access_control_test.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(EVIDENCE_DIR)/owasp-a01-$(SESSION_ID).json

owasp-a02-test:
	@echo "$(BLUE)Test A02:2021 - Cryptographic Failures...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/crypto_failures_test.py \
		--url $(TARGET_URL) \
		--ssl --encryption \
		--output $(EVIDENCE_DIR)/owasp-a02-$(SESSION_ID).json

owasp-a03-test:
	@echo "$(BLUE)Test A03:2021 - Injection...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/injection_test.py \
		--url $(TARGET_URL) \
		--all-types \
		--output $(EVIDENCE_DIR)/owasp-a03-$(SESSION_ID).json

owasp-a04-test:
	@echo "$(BLUE)Test A04:2021 - Insecure Design...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/insecure_design_test.py \
		--url $(TARGET_URL) \
		--business-logic \
		--output $(EVIDENCE_DIR)/owasp-a04-$(SESSION_ID).json

owasp-a05-test:
	@echo "$(BLUE)Test A05:2021 - Security Misconfiguration...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/misconfig_test.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(EVIDENCE_DIR)/owasp-a05-$(SESSION_ID).json

owasp-a06-test:
	@echo "$(BLUE)Test A06:2021 - Vulnerable and Outdated Components...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/vulnerable_components_test.py \
		--url $(TARGET_URL) \
		--dependency-check \
		--output $(EVIDENCE_DIR)/owasp-a06-$(SESSION_ID).json

owasp-a07-test:
	@echo "$(BLUE)Test A07:2021 - Identification and Authentication Failures...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/auth_failures_test.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(EVIDENCE_DIR)/owasp-a07-$(SESSION_ID).json

owasp-a08-test:
	@echo "$(BLUE)Test A08:2021 - Software and Data Integrity Failures...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/integrity_failures_test.py \
		--url $(TARGET_URL) \
		--ci-cd-check \
		--output $(EVIDENCE_DIR)/owasp-a08-$(SESSION_ID).json

owasp-a09-test:
	@echo "$(BLUE)Test A09:2021 - Security Logging and Monitoring Failures...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/logging_failures_test.py \
		--url $(TARGET_URL) \
		--monitoring-check \
		--output $(EVIDENCE_DIR)/owasp-a09-$(SESSION_ID).json

owasp-a10-test:
	@echo "$(BLUE)Test A10:2021 - Server-Side Request Forgery (SSRF)...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/ssrf_test.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(EVIDENCE_DIR)/owasp-a10-$(SESSION_ID).json

# ===================================
# TESTS ASVS 4.0
# ===================================

.PHONY: asvs-level1-test asvs-level2-test asvs-level3-test asvs-architecture asvs-authentication asvs-session asvs-access-control asvs-validation

asvs-level1-test:
	@echo "$(BLUE)Test ASVS Niveau 1 (Opportuniste)...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/asvs_level1_test.py \
		--url $(TARGET_URL) \
		--output $(REPORTS_DIR)/asvs-l1-$(SESSION_ID).json

asvs-level2-test:
	@echo "$(BLUE)Test ASVS Niveau 2 (Standard)...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/asvs_level2_test.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(REPORTS_DIR)/asvs-l2-$(SESSION_ID).json

asvs-level3-test:
	@echo "$(BLUE)Test ASVS Niveau 3 (Avancé)...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/asvs_level3_test.py \
		--url $(TARGET_URL) \
		--advanced-checks \
		--output $(REPORTS_DIR)/asvs-l3-$(SESSION_ID).json

asvs-architecture:
	@echo "$(BLUE)Test V1: Architecture, Design and Threat Modeling...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/v1_architecture.py \
		--url $(TARGET_URL) \
		--level $(ASVS_LEVEL)

asvs-authentication:
	@echo "$(BLUE)Test V2: Authentication Verification Requirements...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/v2_authentication.py \
		--url $(TARGET_URL) \
		--comprehensive

asvs-session:
	@echo "$(BLUE)Test V3: Session Management Verification Requirements...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/v3_session.py \
		--url $(TARGET_URL) \
		--advanced

asvs-access-control:
	@echo "$(BLUE)Test V4: Access Control Verification Requirements...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/v4_access_control.py \
		--url $(TARGET_URL) \
		--rbac

asvs-validation:
	@echo "$(BLUE)Test V5: Validation, Sanitization and Encoding...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/asvs/v5_validation.py \
		--url $(TARGET_URL) \
		--input-validation

# ===================================
# ANALYSE DE SÉCURITÉ
# ===================================

.PHONY: sast-scan dast-scan iast-scan sca-scan comprehensive-scan

sast-scan:
	@echo "$(BLUE)Analyse statique de sécurité (SAST)...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/static_analysis.py \
		--source-path $(SOURCE_PATH) \
		--language $(LANGUAGE) \
		--output $(EVIDENCE_DIR)/sast-$(SESSION_ID).json

dast-scan:
	@echo "$(BLUE)Analyse dynamique de sécurité (DAST)...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/dynamic_analysis.py \
		--url $(TARGET_URL) \
		--deep-scan \
		--output $(EVIDENCE_DIR)/dast-$(SESSION_ID).json

iast-scan:
	@echo "$(BLUE)Analyse interactive de sécurité (IAST)...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/interactive_analysis.py \
		--app-url $(TARGET_URL) \
		--agent-config $(CONFIGS_DIR)/iast/agent.conf \
		--output $(EVIDENCE_DIR)/iast-$(SESSION_ID).json

sca-scan:
	@echo "$(BLUE)Analyse de composition logicielle (SCA)...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/composition_analysis.py \
		--project-path $(PROJECT_PATH) \
		--check-licenses \
		--output $(EVIDENCE_DIR)/sca-$(SESSION_ID).json

comprehensive-scan:
	@echo "$(BLUE)Analyse de sécurité complète...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/comprehensive_scan.py \
		--url $(TARGET_URL) \
		--all-scanners \
		--output $(EVIDENCE_DIR)/comprehensive-$(SESSION_ID).json

# ===================================
# TESTS DE RECONNAISSANCE
# ===================================

.PHONY: recon-passive recon-active recon-subdomain recon-technology recon-content

recon-passive:
	@echo "$(BLUE)Reconnaissance passive...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/web_recon.py \
		--domain $(TARGET_DOMAIN) \
		--passive \
		--output $(EVIDENCE_DIR)/recon-passive-$(SESSION_ID).json

recon-active:
	@echo "$(BLUE)Reconnaissance active...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/web_recon.py \
		--url $(TARGET_URL) \
		--active \
		--output $(EVIDENCE_DIR)/recon-active-$(SESSION_ID).json

recon-subdomain:
	@echo "$(BLUE)Énumération de sous-domaines...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/subdomain_enum.py \
		--domain $(TARGET_DOMAIN) \
		--sources all \
		--output $(EVIDENCE_DIR)/subdomains-$(SESSION_ID).json

recon-technology:
	@echo "$(BLUE)Détection de stack technologique...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/tech_stack_detection.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(EVIDENCE_DIR)/tech-stack-$(SESSION_ID).json

recon-content:
	@echo "$(BLUE)Découverte de contenu...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/endpoint_discovery.py \
		--url $(TARGET_URL) \
		--wordlist $(CONFIGS_DIR)/wordlists/comprehensive.txt \
		--output $(EVIDENCE_DIR)/content-discovery-$(SESSION_ID).json

# ===================================
# TESTS D'EXPLOITATION
# ===================================

.PHONY: exploit-sqli exploit-xss exploit-csrf exploit-upload exploit-custom

exploit-sqli:
	@echo "$(BLUE)Test exploitation SQL Injection...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/sqli_exploit.py \
		--url $(TARGET_URL) \
		--payload union \
		--output $(EVIDENCE_DIR)/sqli-exploit-$(SESSION_ID).json

exploit-xss:
	@echo "$(BLUE)Test exploitation Cross-Site Scripting...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/xss_exploit.py \
		--url $(TARGET_URL) \
		--type reflected \
		--output $(EVIDENCE_DIR)/xss-exploit-$(SESSION_ID).json

exploit-csrf:
	@echo "$(BLUE)Test exploitation CSRF...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/csrf_exploit.py \
		--url $(TARGET_URL) \
		--generate-poc \
		--output $(EVIDENCE_DIR)/csrf-exploit-$(SESSION_ID).json

exploit-upload:
	@echo "$(BLUE)Test exploitation upload de fichiers...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/file_upload_exploit.py \
		--url $(TARGET_URL)/upload \
		--bypass-filters \
		--output $(EVIDENCE_DIR)/upload-exploit-$(SESSION_ID).json

exploit-custom:
	@echo "$(BLUE)Test exploitation personnalisée...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/custom_exploit.py \
		--config $(EXPLOIT_CONFIG) \
		--url $(TARGET_URL) \
		--output $(EVIDENCE_DIR)/custom-exploit-$(SESSION_ID).json

# ===================================
# TESTS API
# ===================================

.PHONY: api-rest-test api-graphql-test api-auth-test api-rate-limit-test

api-rest-test:
	@echo "$(BLUE)Test sécurité API REST...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/api/rest_security_test.py \
		--openapi-spec $(API_SPEC) \
		--endpoint $(API_ENDPOINT) \
		--output $(EVIDENCE_DIR)/api-rest-$(SESSION_ID).json

api-graphql-test:
	@echo "$(BLUE)Test sécurité API GraphQL...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/api/graphql_security_test.py \
		--endpoint $(GRAPHQL_ENDPOINT) \
		--introspection \
		--output $(EVIDENCE_DIR)/api-graphql-$(SESSION_ID).json

api-auth-test:
	@echo "$(BLUE)Test authentification API...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/api/api_auth_test.py \
		--api-key $(API_KEY) \
		--jwt-token $(JWT_TOKEN) \
		--endpoint $(API_ENDPOINT) \
		--output $(EVIDENCE_DIR)/api-auth-$(SESSION_ID).json

api-rate-limit-test:
	@echo "$(BLUE)Test limitation de taux API...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/api/rate_limit_test.py \
		--endpoint $(API_ENDPOINT) \
		--requests $(RATE_LIMIT_REQUESTS) \
		--output $(EVIDENCE_DIR)/api-rate-limit-$(SESSION_ID).json

# ===================================
# GÉNÉRATION DE RAPPORTS
# ===================================

.PHONY: report-executive report-technical report-owasp report-asvs report-compliance

report-executive:
	@echo "$(BLUE)Génération rapport exécutif...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/executive_report.py \
		--session $(SESSION_ID) \
		--template $(REPORTS_DIR)/templates/executive.html \
		--output $(REPORTS_DIR)/$(SESSION_ID)/rapport-executif.pdf

report-technical:
	@echo "$(BLUE)Génération rapport technique...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/technical_report.py \
		--session $(SESSION_ID) \
		--findings high,critical \
		--output $(REPORTS_DIR)/$(SESSION_ID)/rapport-technique.pdf

report-owasp:
	@echo "$(BLUE)Génération rapport conformité OWASP...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/owasp_compliance_report.py \
		--session $(SESSION_ID) \
		--top10-version 2021 \
		--output $(REPORTS_DIR)/$(SESSION_ID)/rapport-owasp.pdf

report-asvs:
	@echo "$(BLUE)Génération rapport conformité ASVS...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/asvs_compliance_report.py \
		--session $(SESSION_ID) \
		--level $(ASVS_LEVEL) \
		--output $(REPORTS_DIR)/$(SESSION_ID)/rapport-asvs.pdf

report-compliance:
	@echo "$(BLUE)Génération rapport conformité réglementaire...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/compliance_report.py \
		--session $(SESSION_ID) \
		--standards $(COMPLIANCE_STANDARDS) \
		--output $(REPORTS_DIR)/$(SESSION_ID)/rapport-conformite.pdf

# ===================================
# MONITORING & ANALYSE
# ===================================

.PHONY: monitor-start monitor-stop logs-analyze metrics-dashboard security-metrics

monitor-start:
	@echo "$(BLUE)Démarrage monitoring...$(NC)"
	@$(DOCKER_COMPOSE) -f docker-compose.monitoring.yml up -d
	@echo "$(GREEN)✓ Services de monitoring démarrés$(NC)"

monitor-stop:
	@echo "$(BLUE)Arrêt monitoring...$(NC)"
	@$(DOCKER_COMPOSE) -f docker-compose.monitoring.yml down

logs-analyze:
	@echo "$(BLUE)Analyse des logs de test...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/log_analyzer.py \
		--logs $(EVIDENCE_DIR)/logs/ \
		--session $(SESSION_ID) \
		--output $(REPORTS_DIR)/analyse-logs-$(SESSION_ID).json

metrics-dashboard:
	@echo "$(BLUE)Dashboard métriques...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/monitoring/metrics_dashboard.py \
		--session $(SESSION_ID) \
		--port 8090

security-metrics:
	@echo "$(BLUE)Métriques de sécurité...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/monitoring/security_metrics.py \
		--timeframe $(TIMEFRAME) \
		--output $(REPORTS_DIR)/security-metrics-$(BUILD_DATE).json

# ===================================
# MAINTENANCE & SANTÉ
# ===================================

.PHONY: health-check security-check update-tools backup-create

health-check:
	@echo "$(BLUE)Vérification de santé système...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/maintenance/health_check.py \
		--comprehensive \
		--output $(REPORTS_DIR)/health-check-$(BUILD_DATE).json

security-check:
	@echo "$(BLUE)Validation sécurité framework...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/maintenance/security_check.py \
		--framework-path $(PROJECT_ROOT) \
		--output $(REPORTS_DIR)/security-check-$(BUILD_DATE).json

update-tools:
	@echo "$(BLUE)Mise à jour outils sécurité...$(NC)"
	@sudo apt-get update && sudo apt-get upgrade -y
	@$(PIP) install --upgrade -r requirements.txt
	@docker pull bkimminich/juice-shop:latest
	@docker pull vulnerables/web-dvwa:latest
	@echo "$(GREEN)✓ Outils mis à jour avec succès$(NC)"

backup-create:
	@echo "$(BLUE)Création sauvegarde système...$(NC)"
	@mkdir -p backups/
	@tar -czf backups/websec-backup-$(BUILD_DATE).tar.gz \
		--exclude='backups' \
		--exclude='evidence' \
		--exclude='venv' \
		$(PROJECT_ROOT)
	@echo "$(GREEN)✓ Sauvegarde créée : backups/websec-backup-$(BUILD_DATE).tar.gz$(NC)"

# ===================================
# NETTOYAGE & MAINTENANCE
# ===================================

.PHONY: clean clean-reports clean-evidence clean-logs clean-all

clean:
	@echo "$(BLUE)Nettoyage fichiers temporaires...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type f -name "*.tmp" -delete

clean-reports:
	@echo "$(YELLOW)Nettoyage anciens rapports...$(NC)"
	@find $(REPORTS_DIR) -type f -mtime +30 -delete

clean-evidence:
	@echo "$(YELLOW)Nettoyage anciennes preuves...$(NC)"
	@find $(EVIDENCE_DIR) -type f -mtime +90 -delete

clean-logs:
	@echo "$(BLUE)Nettoyage anciens logs...$(NC)"
	@find $(EVIDENCE_DIR)/logs -type f -mtime +7 -delete

clean-all: clean clean-reports clean-evidence clean-logs lab-cleanup
	@echo "$(GREEN)✓ Nettoyage complet terminé$(NC)"

# ===================================
# CIBLES UTILITAIRES
# ===================================

.PHONY: version info requirements-update docker-build

version:
	@echo "$(BLUE)Framework de Test de Sécurité Web$(NC)"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Date de build: $(BUILD_DATE)"
	@echo "Heure de build: $(BUILD_TIME)"

info:
	@echo "$(BLUE)Information Projet :$(NC)"
	@echo "Racine projet: $(PROJECT_ROOT)"
	@echo "Version Python: $(shell $(PYTHON) --version)"
	@echo "Version Docker: $(shell docker --version)"
	@echo "Espace disque disponible: $(shell df -h . | tail -1 | awk '{print $$4}')"
	@echo "Usage mémoire: $(shell free -h | grep Mem | awk '{print $$3 \"/\" $$2}')"

requirements-update:
	@echo "$(BLUE)Mise à jour requirements.txt...$(NC)"
	@$(PIP) freeze > requirements.txt
	@echo "$(GREEN)✓ Requirements mis à jour$(NC)"

docker-build:
	@echo "$(BLUE)Construction images Docker...$(NC)"
	@docker build -t $(PROJECT_NAME):$(PROJECT_VERSION) .
	@docker build -t $(PROJECT_NAME):latest .

# Empêcher make d'interpréter ces cibles comme des fichiers
.PHONY: all
all: install lab-deploy health-check

# Cible par défaut quand aucune cible n'est spécifiée
.DEFAULT_GOAL := help