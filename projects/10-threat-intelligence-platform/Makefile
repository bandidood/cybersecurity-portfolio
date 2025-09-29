# ==============================================================================
# Threat Intelligence Platform Automation Framework
# ==============================================================================
# A comprehensive Makefile for automating threat intelligence collection,
# analysis, correlation, hunting, and reporting across multiple feeds and
# data sources with ML-powered analytics and STIX/TAXII integration.
# ==============================================================================

# Project Configuration
PROJECT_NAME := threat-intelligence-platform
VERSION := 1.0.0
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)
USER := $(shell whoami)

# Directory Structure
PROJECT_DIR := $(shell pwd)
FEEDS_DIR := $(PROJECT_DIR)/feeds
ANALYSIS_DIR := $(PROJECT_DIR)/analysis
DATABASE_DIR := $(PROJECT_DIR)/databases
STIX_TAXII_DIR := $(PROJECT_DIR)/stix-taxii
ML_MODELS_DIR := $(PROJECT_DIR)/ml-models
APIS_DIR := $(PROJECT_DIR)/apis
REPORTS_DIR := $(PROJECT_DIR)/reports
TOOLS_DIR := $(PROJECT_DIR)/tools
SCRIPTS_DIR := $(PROJECT_DIR)/scripts

# Docker Configuration
DOCKER_NETWORK := threat-intel-net
DOCKER_COMPOSE_FILE := docker-compose.yml
DOCKER_COMPOSE_OVERRIDE := docker-compose.override.yml

# Platform Configuration
MISP_URL ?= http://localhost:8080
OPENCTI_URL ?= http://localhost:8081
THEHIVE_URL ?= http://localhost:8082
ELASTICSEARCH_URL ?= http://localhost:9200
API_BASE_URL ?= http://localhost:4000

# Threat Intelligence Configuration
FEED_REFRESH_INTERVAL := 3600
IOC_RETENTION_DAYS := 90
ML_MODEL_RETRAIN_INTERVAL := 168
CONFIDENCE_THRESHOLD := 0.75
TLP_LEVEL := WHITE

# API Keys (configure via environment or .env file)
VIRUSTOTAL_API_KEY ?= $(VT_API_KEY)
OTX_API_KEY ?= $(OTX_API_KEY)
SHODAN_API_KEY ?= $(SHODAN_API_KEY)
XFORCE_API_KEY ?= $(XFORCE_API_KEY)

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
NC := \033[0m # No Color

# Default target
.PHONY: help
help: ## Display available commands
	@echo "$(BLUE)=================================================================================="
	@echo "                    Threat Intelligence Platform Framework"
	@echo "=================================================================================="$(NC)
	@echo ""
	@echo "$(GREEN)INSTALLATION & SETUP:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^install|^setup|^configure/) printf "  $(YELLOW)%-25s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)PLATFORM MANAGEMENT:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^platform-|^deploy-|^start-|^stop-/) printf "  $(CYAN)%-25s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)THREAT FEED OPERATIONS:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^feed-|^ingest-|^sync-/) printf "  $(PURPLE)%-25s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)ANALYSIS & HUNTING:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^analyze-|^hunt-|^correlate-|^enrich-/) printf "  $(RED)%-25s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)MACHINE LEARNING:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^ml-|^train-|^predict-/) printf "  $(WHITE)%-25s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""

# ==============================================================================
# INSTALLATION & SETUP
# ==============================================================================

.PHONY: install install-core install-python install-node install-tools check-deps
install: check-deps install-core install-python install-node install-tools ## Install all dependencies and tools
	@echo "$(GREEN)✓ Threat Intelligence Platform installation completed!$(NC)"

check-deps: ## Check system dependencies
	@echo "$(BLUE)Checking system dependencies...$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)❌ Docker is required but not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(RED)❌ Docker Compose is required$(NC)"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)❌ Python 3.9+ is required$(NC)"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "$(RED)❌ Node.js 18+ is required$(NC)"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "$(RED)❌ Git is required$(NC)"; exit 1; }
	@echo "$(GREEN)✓ All system dependencies are available$(NC)"

install-core: ## Install core system packages
	@echo "$(BLUE)Installing core packages...$(NC)"
	
	# Install PostgreSQL client
	@if ! command -v psql >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y postgresql-client; \
	fi
	
	# Install Elasticsearch client
	@pip3 install --user elasticsearch
	
	# Install Redis client
	@pip3 install --user redis
	
	@echo "$(GREEN)✓ Core packages installed$(NC)"

install-python: ## Install Python dependencies for threat intelligence
	@echo "$(BLUE)Installing Python threat intelligence libraries...$(NC)"
	@pip3 install --user -r requirements.txt
	
	# Additional threat intelligence specific packages
	@pip3 install --user pymisp stix2 taxii2-client
	@pip3 install --user OTXv2 shodan virustotal-api
	@pip3 install --user yara-python pandas scikit-learn tensorflow
	@pip3 install --user networkx matplotlib seaborn
	
	@echo "$(GREEN)✓ Python threat intelligence libraries installed$(NC)"

install-node: ## Install Node.js dependencies
	@echo "$(BLUE)Installing Node.js dependencies...$(NC)"
	@if [ -f "package.json" ]; then npm install; fi
	@echo "$(GREEN)✓ Node.js dependencies installed$(NC)"

install-tools: ## Install threat intelligence tools
	@echo "$(BLUE)Installing threat intelligence tools...$(NC)"
	@mkdir -p $(TOOLS_DIR)
	
	# Install YARA
	@if ! command -v yara >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y yara; \
	fi
	
	# Install Volatility (memory analysis)
	@pip3 install --user volatility3
	
	# Install CyberChef
	@if [ ! -d "$(TOOLS_DIR)/CyberChef" ]; then \
		git clone https://github.com/gchq/CyberChef.git $(TOOLS_DIR)/CyberChef; \
	fi
	
	# Install ThreatHunter-Playbook
	@if [ ! -d "$(TOOLS_DIR)/ThreatHunter-Playbook" ]; then \
		git clone https://github.com/OTRF/ThreatHunter-Playbook.git $(TOOLS_DIR)/ThreatHunter-Playbook; \
	fi
	
	@echo "$(GREEN)✓ Threat intelligence tools installed$(NC)"

.PHONY: setup-environment configure-feeds configure-apis init-databases
setup-environment: ## Setup development environment
	@echo "$(BLUE)Setting up threat intelligence environment...$(NC)"
	@mkdir -p {data,logs,cache,models,reports}
	
	# Create .env file if it doesn't exist
	@if [ ! -f ".env" ]; then \
		cp .env.example .env; \
		echo "$(YELLOW)⚠ Please configure .env file with your API keys$(NC)"; \
	fi
	
	@echo "$(GREEN)✓ Environment setup completed$(NC)"

configure-feeds: ## Configure threat intelligence feeds
	@echo "$(BLUE)Configuring threat intelligence feeds...$(NC)"
	
	# Validate API keys
	@if [ -z "$(VIRUSTOTAL_API_KEY)" ]; then echo "$(YELLOW)⚠ VirusTotal API key not configured$(NC)"; fi
	@if [ -z "$(OTX_API_KEY)" ]; then echo "$(YELLOW)⚠ AlienVault OTX API key not configured$(NC)"; fi
	@if [ -z "$(SHODAN_API_KEY)" ]; then echo "$(YELLOW)⚠ Shodan API key not configured$(NC)"; fi
	
	# Test API connections
	@python3 $(SCRIPTS_DIR)/test_feeds.py
	
	@echo "$(GREEN)✓ Threat intelligence feeds configured$(NC)"

configure-apis: ## Configure platform APIs and services
	@echo "$(BLUE)Configuring platform APIs...$(NC)"
	
	# Generate API tokens
	@python3 $(SCRIPTS_DIR)/generate_api_tokens.py
	
	# Setup STIX/TAXII server configuration
	@python3 $(SCRIPTS_DIR)/setup_taxii_server.py
	
	@echo "$(GREEN)✓ Platform APIs configured$(NC)"

init-databases: ## Initialize databases and indices
	@echo "$(BLUE)Initializing databases and search indices...$(NC)"
	
	# Initialize PostgreSQL schemas
	@python3 $(SCRIPTS_DIR)/init_postgres.py
	
	# Initialize Elasticsearch indices
	@python3 $(SCRIPTS_DIR)/init_elasticsearch.py
	
	# Initialize Neo4j graph database
	@python3 $(SCRIPTS_DIR)/init_neo4j.py
	
	@echo "$(GREEN)✓ Databases and indices initialized$(NC)"

# ==============================================================================
# PLATFORM MANAGEMENT
# ==============================================================================

.PHONY: platform-start platform-stop platform-restart platform-status platform-logs
platform-start: ## Start the threat intelligence platform
	@echo "$(BLUE)Starting Threat Intelligence Platform...$(NC)"
	@docker network create $(DOCKER_NETWORK) 2>/dev/null || true
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "$(GREEN)✓ Platform started successfully!$(NC)"
	@echo ""
	@echo "$(CYAN)🎯 Access Points:$(NC)"
	@echo "• MISP Platform: $(MISP_URL) (admin@admin.test/admin)"
	@echo "• OpenCTI Platform: $(OPENCTI_URL) (admin@opencti.io/admin)"
	@echo "• TheHive Platform: $(THEHIVE_URL) (admin@thehive.local/secret)"
	@echo "• Platform API: $(API_BASE_URL)/api/v1"
	@echo "• GraphQL API: $(API_BASE_URL)/graphql"
	@echo "• TAXII Server: $(API_BASE_URL)/taxii2/"
	@echo "• Swagger UI: $(API_BASE_URL)/docs"

platform-stop: ## Stop the platform
	@echo "$(BLUE)Stopping Threat Intelligence Platform...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down
	@echo "$(GREEN)✓ Platform stopped$(NC)"

platform-restart: platform-stop platform-start ## Restart the platform
	@echo "$(GREEN)✓ Platform restarted$(NC)"

platform-status: ## Show platform status
	@echo "$(BLUE)Threat Intelligence Platform Status:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) ps

platform-logs: ## Show platform logs
	@echo "$(BLUE)Threat Intelligence Platform Logs:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=100

deploy-platform: setup-environment configure-feeds init-databases platform-start ## Deploy complete platform
	@echo "$(GREEN)✓ Threat Intelligence Platform deployed successfully!$(NC)"

# ==============================================================================
# THREAT FEED OPERATIONS
# ==============================================================================

.PHONY: feed-ingest-all feed-ingest-misp feed-ingest-otx feed-ingest-vt feed-sync-all
feed-ingest-all: feed-ingest-misp feed-ingest-otx feed-ingest-vt feed-ingest-shodan ## Ingest from all threat feeds
	@echo "$(GREEN)✓ All threat feeds ingested successfully!$(NC)"

feed-ingest-misp: ## Ingest MISP threat intelligence
	@echo "$(BLUE)Ingesting MISP threat intelligence...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/misp_ingester.py \
		--output data/misp_indicators_$(TIMESTAMP).json \
		--days 7 \
		--confidence $(CONFIDENCE_THRESHOLD)
	@echo "$(GREEN)✓ MISP intelligence ingested$(NC)"

feed-ingest-otx: ## Ingest AlienVault OTX indicators
	@echo "$(BLUE)Ingesting AlienVault OTX indicators...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/otx_ingester.py \
		--api-key $(OTX_API_KEY) \
		--output data/otx_indicators_$(TIMESTAMP).json \
		--since 7d
	@echo "$(GREEN)✓ OTX indicators ingested$(NC)"

feed-ingest-vt: ## Ingest VirusTotal intelligence
	@echo "$(BLUE)Ingesting VirusTotal intelligence...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/virustotal_ingester.py \
		--api-key $(VIRUSTOTAL_API_KEY) \
		--output data/vt_intelligence_$(TIMESTAMP).json \
		--batch-size 100
	@echo "$(GREEN)✓ VirusTotal intelligence ingested$(NC)"

feed-ingest-shodan: ## Ingest Shodan intelligence
	@echo "$(BLUE)Ingesting Shodan intelligence...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/shodan_ingester.py \
		--api-key $(SHODAN_API_KEY) \
		--output data/shodan_intelligence_$(TIMESTAMP).json \
		--queries malware,botnet,apt
	@echo "$(GREEN)✓ Shodan intelligence ingested$(NC)"

ingest-custom-feed: ## Ingest custom threat feed (specify FEED_URL)
	@echo "$(BLUE)Ingesting custom threat feed...$(NC)"
	@if [ -z "$(FEED_URL)" ]; then echo "$(RED)❌ Please specify FEED_URL$(NC)"; exit 1; fi
	@python3 $(SCRIPTS_DIR)/feeds/custom_ingester.py \
		--url $(FEED_URL) \
		--format $(FEED_FORMAT) \
		--output data/custom_feed_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Custom feed ingested$(NC)"

sync-stix-feeds: ## Synchronize STIX feeds via TAXII
	@echo "$(BLUE)Synchronizing STIX feeds via TAXII...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/stix_sync.py \
		--collections indicators,malware-analysis \
		--output data/stix_feed_$(TIMESTAMP).json
	@echo "$(GREEN)✓ STIX feeds synchronized$(NC)"

feed-normalize: ## Normalize all ingested feeds to STIX format
	@echo "$(BLUE)Normalizing threat feeds to STIX format...$(NC)"
	@python3 $(SCRIPTS_DIR)/feeds/normalize_feeds.py \
		--input-dir data \
		--output data/normalized_stix_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Threat feeds normalized$(NC)"

# ==============================================================================
# ANALYSIS & CORRELATION
# ==============================================================================

.PHONY: analyze-iocs analyze-malware correlate-threats enrich-intelligence
analyze-iocs: ## Analyze indicators of compromise
	@echo "$(BLUE)Analyzing indicators of compromise...$(NC)"
	@mkdir -p reports/ioc-analysis
	@python3 $(SCRIPTS_DIR)/analysis/ioc_analyzer.py \
		--input data/normalized_stix_$(shell date +%Y%m%d)*.json \
		--output reports/ioc-analysis/ioc_analysis_$(TIMESTAMP).json \
		--confidence-threshold $(CONFIDENCE_THRESHOLD)
	@echo "$(GREEN)✓ IOC analysis completed$(NC)"

analyze-malware: ## Analyze malware samples and families
	@echo "$(BLUE)Analyzing malware samples...$(NC)"
	@mkdir -p reports/malware-analysis
	@python3 $(SCRIPTS_DIR)/analysis/malware_analyzer.py \
		--samples-dir samples/ \
		--output reports/malware-analysis/malware_analysis_$(TIMESTAMP).json \
		--yara-rules rules/
	@echo "$(GREEN)✓ Malware analysis completed$(NC)"

correlate-threats: ## Correlate threats across different sources
	@echo "$(BLUE)Correlating threats across sources...$(NC)"
	@mkdir -p reports/correlation
	@python3 $(SCRIPTS_DIR)/analysis/threat_correlator.py \
		--input-dir data/ \
		--output reports/correlation/threat_correlation_$(TIMESTAMP).json \
		--similarity-threshold 0.8
	@echo "$(GREEN)✓ Threat correlation completed$(NC)"

enrich-intelligence: ## Enrich threat intelligence with additional context
	@echo "$(BLUE)Enriching threat intelligence...$(NC)"
	@python3 $(SCRIPTS_DIR)/analysis/intelligence_enricher.py \
		--input reports/ioc-analysis/ioc_analysis_$(shell ls -t reports/ioc-analysis/ | head -1) \
		--output reports/enriched_intelligence_$(TIMESTAMP).json \
		--sources virustotal,shodan,whois
	@echo "$(GREEN)✓ Intelligence enrichment completed$(NC)"

analyze-campaigns: ## Analyze threat campaigns and attribution
	@echo "$(BLUE)Analyzing threat campaigns...$(NC)"
	@mkdir -p reports/campaign-analysis
	@python3 $(SCRIPTS_DIR)/analysis/campaign_analyzer.py \
		--input-dir data/ \
		--output reports/campaign-analysis/campaigns_$(TIMESTAMP).json \
		--mitre-attack-mapping
	@echo "$(GREEN)✓ Campaign analysis completed$(NC)"

# ==============================================================================
# THREAT HUNTING
# ==============================================================================

.PHONY: hunt-iocs hunt-behavioral hunt-network hunt-endpoints hunt-all
hunt-all: hunt-iocs hunt-behavioral hunt-network hunt-endpoints ## Run all hunting queries
	@echo "$(GREEN)✓ Comprehensive threat hunting completed!$(NC)"

hunt-iocs: ## Hunt for IOCs across data sources
	@echo "$(BLUE)Hunting for IOCs...$(NC)"
	@mkdir -p reports/hunting
	@python3 $(SCRIPTS_DIR)/hunting/ioc_hunter.py \
		--indicators reports/ioc-analysis/ioc_analysis_$(shell ls -t reports/ioc-analysis/ | head -1) \
		--elasticsearch-url $(ELASTICSEARCH_URL) \
		--indices "logs-*,network-*,endpoint-*" \
		--output reports/hunting/ioc_hunting_$(TIMESTAMP).json
	@echo "$(GREEN)✓ IOC hunting completed$(NC)"

hunt-behavioral: ## Hunt for behavioral anomalies
	@echo "$(BLUE)Hunting for behavioral anomalies...$(NC)"
	@python3 $(SCRIPTS_DIR)/hunting/behavioral_hunter.py \
		--model models/behavioral_anomaly_model.pkl \
		--timerange 24h \
		--output reports/hunting/behavioral_hunting_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Behavioral hunting completed$(NC)"

hunt-network: ## Hunt for network-based threats
	@echo "$(BLUE)Hunting for network threats...$(NC)"
	@python3 $(SCRIPTS_DIR)/hunting/network_hunter.py \
		--pcap-dir network_captures/ \
		--rules rules/network_hunting.yaml \
		--output reports/hunting/network_hunting_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Network hunting completed$(NC)"

hunt-endpoints: ## Hunt for endpoint-based threats
	@echo "$(BLUE)Hunting for endpoint threats...$(NC)"
	@python3 $(SCRIPTS_DIR)/hunting/endpoint_hunter.py \
		--sysmon-logs logs/sysmon/ \
		--hunting-queries queries/endpoint_hunting.sql \
		--output reports/hunting/endpoint_hunting_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Endpoint hunting completed$(NC)"

hunt-ttps: ## Hunt for MITRE ATT&CK TTPs
	@echo "$(BLUE)Hunting for MITRE ATT&CK TTPs...$(NC)"
	@python3 $(SCRIPTS_DIR)/hunting/ttp_hunter.py \
		--attack-matrix data/mitre_attack.json \
		--techniques T1055,T1059,T1105,T1204 \
		--output reports/hunting/ttp_hunting_$(TIMESTAMP).json
	@echo "$(GREEN)✓ TTP hunting completed$(NC)"

# ==============================================================================
# MACHINE LEARNING
# ==============================================================================

.PHONY: ml-train-all ml-train-classifier ml-train-clustering ml-predict ml-evaluate
ml-train-all: ml-train-classifier ml-train-clustering ml-train-anomaly ## Train all ML models
	@echo "$(GREEN)✓ All ML models trained successfully!$(NC)"

ml-train-classifier: ## Train malware classification model
	@echo "$(BLUE)Training malware classification model...$(NC)"
	@mkdir -p models/classification
	@python3 $(SCRIPTS_DIR)/ml/train_classifier.py \
		--training-data data/malware_samples/ \
		--model-output models/classification/malware_classifier_$(TIMESTAMP).pkl \
		--features pe_headers,imports,strings \
		--algorithm random_forest
	@echo "$(GREEN)✓ Classification model trained$(NC)"

ml-train-clustering: ## Train threat actor clustering model
	@echo "$(BLUE)Training threat actor clustering model...$(NC)"
	@mkdir -p models/clustering
	@python3 $(SCRIPTS_DIR)/ml/train_clustering.py \
		--campaigns-data data/campaigns/ \
		--model-output models/clustering/actor_clustering_$(TIMESTAMP).pkl \
		--features ttps,infrastructure,targets \
		--algorithm dbscan
	@echo "$(GREEN)✓ Clustering model trained$(NC)"

ml-train-anomaly: ## Train behavioral anomaly detection model
	@echo "$(BLUE)Training anomaly detection model...$(NC)"
	@mkdir -p models/anomaly
	@python3 $(SCRIPTS_DIR)/ml/train_anomaly_detector.py \
		--normal-behavior data/baseline_behavior/ \
		--model-output models/anomaly/anomaly_detector_$(TIMESTAMP).pkl \
		--algorithm isolation_forest
	@echo "$(GREEN)✓ Anomaly detection model trained$(NC)"

ml-predict: ## Make predictions using trained models
	@echo "$(BLUE)Making ML predictions...$(NC)"
	@mkdir -p reports/predictions
	@python3 $(SCRIPTS_DIR)/ml/predictor.py \
		--models models/ \
		--input-data data/recent_samples/ \
		--output reports/predictions/ml_predictions_$(TIMESTAMP).json
	@echo "$(GREEN)✓ ML predictions completed$(NC)"

ml-evaluate: ## Evaluate ML model performance
	@echo "$(BLUE)Evaluating ML models...$(NC)"
	@mkdir -p reports/ml-evaluation
	@python3 $(SCRIPTS_DIR)/ml/evaluate_models.py \
		--models models/ \
		--test-data data/test_set/ \
		--output reports/ml-evaluation/model_evaluation_$(TIMESTAMP).json
	@echo "$(GREEN)✓ ML model evaluation completed$(NC)"

ml-retrain: ## Retrain models with new data
	@echo "$(BLUE)Retraining ML models with new data...$(NC)"
	@python3 $(SCRIPTS_DIR)/ml/retrain_models.py \
		--new-data data/recent_data/ \
		--existing-models models/ \
		--output models/retrained/
	@echo "$(GREEN)✓ ML models retrained$(NC)"

train-attribution-model: ## Train threat actor attribution model
	@echo "$(BLUE)Training threat actor attribution model...$(NC)"
	@mkdir -p models/attribution
	@python3 $(SCRIPTS_DIR)/ml/train_attribution.py \
		--campaigns data/attributed_campaigns/ \
		--model-output models/attribution/attribution_model_$(TIMESTAMP).pkl \
		--features network_infrastructure,malware_families,ttps
	@echo "$(GREEN)✓ Attribution model trained$(NC)"

# ==============================================================================
# REPORTING & INTELLIGENCE PRODUCTS
# ==============================================================================

.PHONY: report-tactical report-strategic report-ioc report-campaign report-trends
report-tactical: ## Generate tactical intelligence report
	@echo "$(BLUE)Generating tactical intelligence report...$(NC)"
	@mkdir -p reports/tactical
	@python3 $(SCRIPTS_DIR)/reporting/tactical_report.py \
		--indicators reports/ioc-analysis/ \
		--hunting-results reports/hunting/ \
		--timeframe 7d \
		--output reports/tactical/tactical_report_$(TIMESTAMP).pdf \
		--format pdf
	@echo "$(GREEN)✓ Tactical report generated$(NC)"

report-strategic: ## Generate strategic intelligence report
	@echo "$(BLUE)Generating strategic intelligence report...$(NC)"
	@mkdir -p reports/strategic
	@python3 $(SCRIPTS_DIR)/reporting/strategic_report.py \
		--campaigns reports/campaign-analysis/ \
		--trends reports/trend-analysis/ \
		--predictions reports/predictions/ \
		--output reports/strategic/strategic_report_$(TIMESTAMP).pdf \
		--executive-summary
	@echo "$(GREEN)✓ Strategic report generated$(NC)"

report-ioc: ## Generate IOC intelligence report
	@echo "$(BLUE)Generating IOC intelligence report...$(NC)"
	@mkdir -p reports/ioc
	@python3 $(SCRIPTS_DIR)/reporting/ioc_report.py \
		--iocs reports/ioc-analysis/ \
		--format stix2,json,csv \
		--output reports/ioc/ioc_report_$(TIMESTAMP) \
		--confidence-filter $(CONFIDENCE_THRESHOLD)
	@echo "$(GREEN)✓ IOC report generated$(NC)"

report-campaign: ## Generate campaign analysis report
	@echo "$(BLUE)Generating campaign analysis report...$(NC)"
	@mkdir -p reports/campaigns
	@python3 $(SCRIPTS_DIR)/reporting/campaign_report.py \
		--campaigns reports/campaign-analysis/ \
		--attribution models/attribution/ \
		--mitre-mapping \
		--output reports/campaigns/campaign_report_$(TIMESTAMP).pdf
	@echo "$(GREEN)✓ Campaign report generated$(NC)"

report-trends: ## Generate threat trends analysis
	@echo "$(BLUE)Generating threat trends report...$(NC)"
	@mkdir -p reports/trends
	@python3 $(SCRIPTS_DIR)/reporting/trends_report.py \
		--historical-data data/historical/ \
		--timeframe 90d \
		--predictions reports/predictions/ \
		--output reports/trends/trends_report_$(TIMESTAMP).html \
		--interactive-charts
	@echo "$(GREEN)✓ Trends report generated$(NC)"

generate-all-reports: report-tactical report-strategic report-ioc report-campaign report-trends ## Generate all intelligence reports
	@echo "$(GREEN)✓ All intelligence reports generated!$(NC)"

# ==============================================================================
# STIX/TAXII OPERATIONS
# ==============================================================================

.PHONY: stix-export stix-import taxii-publish taxii-collect
stix-export: ## Export intelligence as STIX objects
	@echo "$(BLUE)Exporting intelligence as STIX objects...$(NC)"
	@mkdir -p exports/stix
	@python3 $(SCRIPTS_DIR)/stix-taxii/stix_exporter.py \
		--input-dir reports/ \
		--output exports/stix/stix_export_$(TIMESTAMP).json \
		--stix-version 2.1 \
		--confidence-threshold $(CONFIDENCE_THRESHOLD)
	@echo "$(GREEN)✓ STIX export completed$(NC)"

stix-import: ## Import STIX objects into platform
	@echo "$(BLUE)Importing STIX objects...$(NC)"
	@if [ -z "$(STIX_FILE)" ]; then echo "$(RED)❌ Please specify STIX_FILE$(NC)"; exit 1; fi
	@python3 $(SCRIPTS_DIR)/stix-taxii/stix_importer.py \
		--stix-file $(STIX_FILE) \
		--validate \
		--deduplicate
	@echo "$(GREEN)✓ STIX import completed$(NC)"

taxii-publish: ## Publish intelligence via TAXII server
	@echo "$(BLUE)Publishing intelligence via TAXII...$(NC)"
	@python3 $(SCRIPTS_DIR)/stix-taxii/taxii_publisher.py \
		--collection indicators \
		--stix-data exports/stix/ \
		--server-url $(API_BASE_URL)/taxii2/
	@echo "$(GREEN)✓ TAXII publishing completed$(NC)"

taxii-collect: ## Collect intelligence from TAXII servers
	@echo "$(BLUE)Collecting intelligence from TAXII servers...$(NC)"
	@python3 $(SCRIPTS_DIR)/stix-taxii/taxii_collector.py \
		--servers-config config/taxii_servers.yaml \
		--collections indicators,malware-analysis \
		--output data/taxii_collected_$(TIMESTAMP).json
	@echo "$(GREEN)✓ TAXII collection completed$(NC)"

# ==============================================================================
# AUTOMATION & SCHEDULING
# ==============================================================================

.PHONY: schedule-feeds schedule-analysis schedule-reports automation-status
schedule-feeds: ## Schedule automated feed ingestion
	@echo "$(BLUE)Scheduling automated feed ingestion...$(NC)"
	@python3 $(SCRIPTS_DIR)/automation/scheduler.py \
		--task feed-ingestion \
		--interval $(FEED_REFRESH_INTERVAL) \
		--command "make feed-ingest-all"
	@echo "$(GREEN)✓ Feed ingestion scheduled$(NC)"

schedule-analysis: ## Schedule automated threat analysis
	@echo "$(BLUE)Scheduling automated analysis...$(NC)"
	@python3 $(SCRIPTS_DIR)/automation/scheduler.py \
		--task threat-analysis \
		--interval 7200 \
		--command "make analyze-iocs correlate-threats"
	@echo "$(GREEN)✓ Analysis scheduling configured$(NC)"

schedule-reports: ## Schedule automated report generation
	@echo "$(BLUE)Scheduling automated reporting...$(NC)"
	@python3 $(SCRIPTS_DIR)/automation/scheduler.py \
		--task intelligence-reporting \
		--interval 86400 \
		--command "make report-tactical report-ioc"
	@echo "$(GREEN)✓ Reporting scheduling configured$(NC)"

automation-status: ## Show automation and scheduling status
	@echo "$(BLUE)Automation Status:$(NC)"
	@python3 $(SCRIPTS_DIR)/automation/status.py

# ==============================================================================
# TESTING & VALIDATION
# ==============================================================================

.PHONY: test-all test-feeds test-analysis test-ml test-apis
test-all: test-feeds test-analysis test-ml test-apis ## Run all tests
	@echo "$(GREEN)✓ All tests completed successfully!$(NC)"

test-feeds: ## Test threat feed integrations
	@echo "$(BLUE)Testing threat feed integrations...$(NC)"
	@python3 -m pytest tests/test_feeds.py -v
	@echo "$(GREEN)✓ Feed tests completed$(NC)"

test-analysis: ## Test analysis engines
	@echo "$(BLUE)Testing analysis engines...$(NC)"
	@python3 -m pytest tests/test_analysis.py -v
	@echo "$(GREEN)✓ Analysis tests completed$(NC)"

test-ml: ## Test machine learning models
	@echo "$(BLUE)Testing ML models...$(NC)"
	@python3 -m pytest tests/test_ml_models.py -v
	@echo "$(GREEN)✓ ML tests completed$(NC)"

test-apis: ## Test platform APIs
	@echo "$(BLUE)Testing platform APIs...$(NC)"
	@python3 -m pytest tests/test_apis.py -v
	@echo "$(GREEN)✓ API tests completed$(NC)"

validate-stix: ## Validate STIX objects
	@echo "$(BLUE)Validating STIX objects...$(NC)"
	@python3 $(SCRIPTS_DIR)/validation/stix_validator.py \
		--input exports/stix/ \
		--schema schemas/stix2.1/
	@echo "$(GREEN)✓ STIX validation completed$(NC)"

# ==============================================================================
# MAINTENANCE & CLEANUP
# ==============================================================================

.PHONY: cleanup-data cleanup-reports cleanup-logs cleanup-all maintenance
cleanup-data: ## Clean up old data files
	@echo "$(BLUE)Cleaning up old data files...$(NC)"
	@find data/ -name "*.json" -mtime +$(IOC_RETENTION_DAYS) -delete 2>/dev/null || true
	@find data/ -name "*.csv" -mtime +$(IOC_RETENTION_DAYS) -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Data cleanup completed$(NC)"

cleanup-reports: ## Clean up old reports
	@echo "$(BLUE)Cleaning up old reports...$(NC)"
	@find reports/ -name "*.pdf" -mtime +30 -delete 2>/dev/null || true
	@find reports/ -name "*.html" -mtime +30 -delete 2>/dev/null || true
	@find reports/ -name "*.json" -mtime +30 -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Reports cleanup completed$(NC)"

cleanup-logs: ## Clean up old log files
	@echo "$(BLUE)Cleaning up old log files...$(NC)"
	@find logs/ -name "*.log" -mtime +7 -delete 2>/dev/null || true
	@docker system prune -f --volumes
	@echo "$(GREEN)✓ Logs cleanup completed$(NC)"

cleanup-all: cleanup-data cleanup-reports cleanup-logs ## Clean up all old files
	@echo "$(GREEN)✓ Complete cleanup finished$(NC)"

maintenance: ## Run platform maintenance tasks
	@echo "$(BLUE)Running platform maintenance...$(NC)"
	@python3 $(SCRIPTS_DIR)/maintenance/database_maintenance.py
	@python3 $(SCRIPTS_DIR)/maintenance/index_optimization.py
	@python3 $(SCRIPTS_DIR)/maintenance/cache_cleanup.py
	@echo "$(GREEN)✓ Platform maintenance completed$(NC)"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

.PHONY: version status logs requirements backup restore
version: ## Show version information
	@echo "$(BLUE)Threat Intelligence Platform$(NC)"
	@echo "Version: $(VERSION)"
	@echo "Timestamp: $(TIMESTAMP)"
	@echo "User: $(USER)"

status: ## Show platform status
	@echo "$(BLUE)Platform Status Overview:$(NC)"
	@python3 $(SCRIPTS_DIR)/utils/platform_status.py

logs: ## Show recent platform logs
	@echo "$(BLUE)Recent platform logs:$(NC)"
	@tail -n 100 logs/platform.log

requirements: ## Generate requirements.txt
	@echo "$(BLUE)Generating requirements.txt...$(NC)"
	@cat > requirements.txt << 'EOF'
# Threat Intelligence Platform Dependencies
# Core Libraries
requests>=2.31.0
urllib3>=2.0.0
python-dateutil>=2.8.2
pyyaml>=6.0.1
jinja2>=3.1.2

# Threat Intelligence
pymisp>=2.4.170
stix2>=3.0.1
taxii2-client>=2.3.0
OTXv2>=1.5.12
shodan>=1.30.0
virustotal-api>=1.1.11

# Data Processing
pandas>=2.1.0
numpy>=1.24.0
elasticsearch>=8.11.0
redis>=5.0.0
psycopg2-binary>=2.9.7

# Machine Learning
scikit-learn>=1.3.0
tensorflow>=2.13.0
torch>=2.0.0
transformers>=4.30.0
xgboost>=1.7.5

# Network Analysis
networkx>=3.1.0
pypcap>=1.2.3
scapy>=2.5.0

# Malware Analysis
yara-python>=4.3.0
pefile>=2023.2.7
volatility3>=2.5.0

# Visualization
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.15.0

# Web Framework
fastapi>=0.103.0
uvicorn>=0.23.0
graphene>=3.3.0
aiohttp>=3.8.5

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-mock>=3.11.0
pytest-cov>=4.1.0
EOF
	@echo "$(GREEN)✓ requirements.txt generated$(NC)"

backup: ## Create platform backup
	@echo "$(BLUE)Creating platform backup...$(NC)"
	@mkdir -p backups
	@tar -czf backups/threat-intel-backup-$(TIMESTAMP).tar.gz \
		data/ models/ config/ reports/
	@echo "$(GREEN)✓ Backup created: backups/threat-intel-backup-$(TIMESTAMP).tar.gz$(NC)"

restore: ## Restore from backup (specify BACKUP_FILE=filename)
	@echo "$(BLUE)Restoring from backup: $(BACKUP_FILE)$(NC)"
	@if [ -z "$(BACKUP_FILE)" ]; then echo "$(RED)❌ Please specify BACKUP_FILE=filename$(NC)"; exit 1; fi
	@tar -xzf backups/$(BACKUP_FILE)
	@echo "$(GREEN)✓ Backup restored successfully$(NC)"

# This will allow make to work with file targets that might not exist
%: 
	@:

.DEFAULT_GOAL := help