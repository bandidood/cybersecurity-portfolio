# ============================================================================
# Makefile - Social Engineering Simulation Platform
# ============================================================================
# Automatisation complète pour la simulation d'ingénierie sociale,
# campagnes de phishing, OSINT et sensibilisation à la sécurité.
#
# Author: Cybersecurity Portfolio
# Version: 1.0.0
# Last Updated: January 28, 2024
# ============================================================================

# Variables de configuration
PROJECT_NAME := social-engineering-simulation
VERSION := 1.0.0
PYTHON := python3
PIP := pip3

# Chemins principaux
PROJECT_ROOT := $(shell pwd)
SRC_DIR := $(PROJECT_ROOT)/src
DOCS_DIR := $(PROJECT_ROOT)/docs
EXAMPLES_DIR := $(PROJECT_ROOT)/examples
TOOLS_DIR := $(PROJECT_ROOT)/tools
TESTS_DIR := $(PROJECT_ROOT)/tests
CAMPAIGNS_DIR := $(PROJECT_ROOT)/campaigns
TEMPLATES_DIR := $(PROJECT_ROOT)/templates
REPORTS_DIR := $(PROJECT_ROOT)/reports

# Chemins de sortie
OUTPUT_DIR := $(PROJECT_ROOT)/output
RESULTS_DIR := $(OUTPUT_DIR)/results
ANALYTICS_DIR := $(OUTPUT_DIR)/analytics
LOGS_DIR := $(OUTPUT_DIR)/logs

# Configuration des outils
GOPHISH_PATH := /opt/gophish
SET_PATH := /opt/setoolkit
METASPLOIT_PATH := /opt/metasploit-framework

# Couleurs pour l'affichage
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

# ============================================================================
# AIDE ET DOCUMENTATION
# ============================================================================

.PHONY: help
help: ## Affiche cette aide
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE)  Social Engineering Simulation$(NC)"
	@echo "$(BLUE)  Version: $(VERSION)$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Commandes principales:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)  %-20s$(NC) %s\n", $$1, $$2}'

# ============================================================================
# INSTALLATION ET CONFIGURATION
# ============================================================================

.PHONY: setup
setup: install-deps create-dirs configure-services ## Installation complète
	@echo "$(GREEN)✓ Setup completed successfully$(NC)"

.PHONY: install-deps
install-deps: ## Installe les dépendances Python
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install gophish-api selenium beautifulsoup4 dnspython
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

.PHONY: create-dirs
create-dirs: ## Crée la structure des dossiers
	@echo "$(YELLOW)Creating directory structure...$(NC)"
	@mkdir -p $(OUTPUT_DIR) $(RESULTS_DIR) $(ANALYTICS_DIR) $(LOGS_DIR)
	@mkdir -p $(CAMPAIGNS_DIR)/{phishing,vishing,combined}
	@mkdir -p $(TEMPLATES_DIR)/{email-templates,landing-pages,documents,media}
	@mkdir -p $(REPORTS_DIR)/{campaign-results,awareness-metrics,recommendations}
	@echo "$(GREEN)✓ Directory structure created$(NC)"

# ============================================================================
# GESTION DES CAMPAGNES
# ============================================================================

.PHONY: campaign-create
campaign-create: ## Crée une nouvelle campagne
	@echo "$(YELLOW)Creating new campaign...$(NC)"
	@read -p "Campaign name: " name; \
	read -p "Campaign type (phishing/vishing/combined): " type; \
	read -p "Target file (CSV): " targets; \
	$(PYTHON) $(SRC_DIR)/phishing/campaign_manager.py \
		--create --name "$$name" --type "$$type" --targets "$$targets"

.PHONY: campaign-launch
campaign-launch: ## Lance une campagne
	@echo "$(YELLOW)Launching campaign...$(NC)"
	@read -p "Campaign ID: " campaign_id; \
	$(PYTHON) $(SRC_DIR)/phishing/campaign_manager.py \
		--launch --id "$$campaign_id"

.PHONY: campaign-status
campaign-status: ## Affiche le statut des campagnes
	@echo "$(YELLOW)Campaign status:$(NC)"
	$(PYTHON) $(SRC_DIR)/phishing/campaign_manager.py --status --all

# ============================================================================
# RECONNAISSANCE OSINT
# ============================================================================

.PHONY: osint-company
osint-company: ## Profile une entreprise
	@echo "$(YELLOW)Starting company profiling...$(NC)"
	@read -p "Target domain: " domain; \
	$(PYTHON) $(SRC_DIR)/osint/social_recon.py \
		--company --domain "$$domain" \
		--output $(RESULTS_DIR)/"$$domain"_profile.json

.PHONY: osint-person
osint-person: ## Profile une personne
	@echo "$(YELLOW)Starting person profiling...$(NC)"
	@read -p "Target name: " name; \
	read -p "Company (optional): " company; \
	$(PYTHON) $(SRC_DIR)/osint/social_recon.py \
		--person --name "$$name" --company "$$company" \
		--output $(RESULTS_DIR)/"$$name"_profile.json

# ============================================================================
# TESTS ET VALIDATION
# ============================================================================

.PHONY: test
test: test-unit test-integration ## Lance tous les tests

.PHONY: test-unit
test-unit: ## Tests unitaires
	@echo "$(YELLOW)Running unit tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/unit-tests/ -v
	@echo "$(GREEN)✓ Unit tests completed$(NC)"

.PHONY: test-campaign
test-campaign: ## Teste une campagne
	@echo "$(YELLOW)Testing campaign...$(NC)"
	@read -p "Campaign ID: " campaign_id; \
	$(PYTHON) $(TESTS_DIR)/campaign-validation/test_campaign.py \
		--campaign-id "$$campaign_id"

# ============================================================================
# RAPPORTS ET ANALYTICS
# ============================================================================

.PHONY: report-generate
report-generate: ## Génère un rapport de campagne
	@echo "$(YELLOW)Generating campaign report...$(NC)"
	@read -p "Campaign ID: " campaign_id; \
	$(PYTHON) $(SRC_DIR)/reporting/report_generator.py \
		--campaign "$$campaign_id" \
		--output $(REPORTS_DIR)/campaign_report.html

.PHONY: analytics
analytics: ## Lance le dashboard d'analytics
	@echo "$(YELLOW)Starting analytics dashboard...$(NC)"
	$(PYTHON) $(TOOLS_DIR)/metrics-dashboard/dashboard.py --port 8080

# ============================================================================
# NETTOYAGE
# ============================================================================

.PHONY: clean
clean: ## Nettoie les fichiers temporaires
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup completed$(NC)"

# Variables d'environnement
export SOCIAL_ENG_HOME := $(PROJECT_ROOT)
export PYTHONPATH := $(SRC_DIR):$(PYTHONPATH)