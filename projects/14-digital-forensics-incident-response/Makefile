# ============================================================================
# Makefile - Digital Forensics & Incident Response Framework
# ============================================================================
# Professional-grade automation for digital forensic analysis and incident response
# Supports NIST, SANS, and international forensic standards
# Version: 1.0.0
# Last Updated: January 28, 2024
# ============================================================================

.PHONY: help setup clean deploy start stop restart status logs shell backup restore \
        forensic-setup incident-setup analysis-setup lab-setup monitoring-setup \
        evidence-acquire evidence-process evidence-analyze evidence-report \
        incident-detect incident-contain incident-eradicate incident-recover \
        forensic-disk forensic-memory forensic-network forensic-mobile \
        malware-setup malware-analyze malware-sandbox malware-report \
        timeline-create timeline-analyze timeline-correlate timeline-visualize \
        threat-intel threat-feed threat-hunt threat-ioc threat-mitre \
        case-create case-manage case-document case-close case-audit \
        compliance-check compliance-report compliance-iso compliance-nist \
        training-setup training-scenarios training-validate training-certify \
        security-harden security-audit security-monitor security-respond \
        integration-test integration-validate integration-deploy integration-monitor

# ============================================================================
# CONFIGURATION AND VARIABLES
# ============================================================================

# Project Configuration
PROJECT_NAME := digital-forensics-ir
PROJECT_VERSION := 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_USER := $(shell whoami)
BUILD_HOST := $(shell hostname)

# Directory Structure
BASE_DIR := $(shell pwd)
SCRIPTS_DIR := $(BASE_DIR)/scripts
TOOLS_DIR := $(BASE_DIR)/tools
EVIDENCE_DIR := $(BASE_DIR)/evidence
CASES_DIR := $(BASE_DIR)/cases
REPORTS_DIR := $(BASE_DIR)/reports
DOCS_DIR := $(BASE_DIR)/documentation
LAB_DIR := $(BASE_DIR)/lab
BACKUP_DIR := $(BASE_DIR)/backup
LOGS_DIR := $(BASE_DIR)/logs
CONFIG_DIR := $(BASE_DIR)/configs

# Docker Configuration
COMPOSE_FILE := docker-compose.yml
COMPOSE_PROJECT := forensics-lab
COMPOSE_ENV := .env
DOCKER_REGISTRY := forensics-registry.local
DOCKER_TAG := $(PROJECT_VERSION)

# Security Configuration
SSL_CERT_DIR := $(CONFIG_DIR)/ssl
SECRETS_DIR := $(CONFIG_DIR)/secrets
VAULT_ADDR := https://vault.forensics.local:8200
VAULT_TOKEN_FILE := $(SECRETS_DIR)/.vault-token

# Forensic Tools Configuration
SLEUTHKIT_VERSION := 4.12.0
AUTOPSY_VERSION := 4.20.0
VOLATILITY_VERSION := 3.2.1
PLASO_VERSION := 20231218
YARA_VERSION := 4.4.0
WIRESHARK_VERSION := 4.2.0

# Network Configuration
FORENSIC_NETWORK := forensic-isolated
ANALYSIS_NETWORK := analysis-secure
MONITORING_NETWORK := monitoring-net
INTERNET_NETWORK := internet-access

# Performance Configuration
MEMORY_LIMIT := 32g
CPU_LIMIT := 16
DISK_SPACE := 500g
SWAP_SIZE := 64g

# Compliance Standards
ISO_STANDARD := 27037,27041,27042,27043
NIST_FRAMEWORK := 800-86,800-61
SANS_METHODOLOGY := GCFA,GCIH,GREM
ACPO_GUIDELINES := v4.0

# ============================================================================
# HELP AND INFORMATION
# ============================================================================

help: ## Show this help message with all available targets
	@echo "============================================================================"
	@echo "Digital Forensics & Incident Response Framework - Makefile"
	@echo "============================================================================"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build User: $(BUILD_USER)@$(BUILD_HOST)"
	@echo "============================================================================"
	@echo ""
	@echo "MAIN TARGETS:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "FORENSIC ANALYSIS:"
	@echo "  forensic-setup           Setup forensic analysis environment"
	@echo "  forensic-disk            Disk forensic analysis"
	@echo "  forensic-memory          Memory forensic analysis"
	@echo "  forensic-network         Network forensic analysis"
	@echo "  forensic-mobile          Mobile device forensics"
	@echo ""
	@echo "INCIDENT RESPONSE:"
	@echo "  incident-setup           Setup incident response environment"
	@echo "  incident-detect          Detection and identification"
	@echo "  incident-contain         Containment procedures"
	@echo "  incident-eradicate       Eradication and remediation"
	@echo "  incident-recover         Recovery and lessons learned"
	@echo ""
	@echo "EVIDENCE HANDLING:"
	@echo "  evidence-acquire         Evidence acquisition"
	@echo "  evidence-process         Evidence processing"
	@echo "  evidence-analyze         Evidence analysis"
	@echo "  evidence-report          Evidence reporting"
	@echo ""
	@echo "MALWARE ANALYSIS:"
	@echo "  malware-setup            Malware analysis lab setup"
	@echo "  malware-analyze          Static and dynamic analysis"
	@echo "  malware-sandbox          Sandbox environment"
	@echo "  malware-report           Malware analysis report"
	@echo ""
	@echo "TIMELINE ANALYSIS:"
	@echo "  timeline-create          Create timeline from evidence"
	@echo "  timeline-analyze         Analyze timeline events"
	@echo "  timeline-correlate       Correlate multiple timelines"
	@echo "  timeline-visualize       Timeline visualization"
	@echo ""
	@echo "THREAT INTELLIGENCE:"
	@echo "  threat-intel             Threat intelligence integration"
	@echo "  threat-feed              Update threat feeds"
	@echo "  threat-hunt              Threat hunting operations"
	@echo "  threat-ioc               IoC management"
	@echo "  threat-mitre             MITRE ATT&CK mapping"
	@echo ""
	@echo "CASE MANAGEMENT:"
	@echo "  case-create              Create new forensic case"
	@echo "  case-manage              Manage active cases"
	@echo "  case-document            Document case activities"
	@echo "  case-close               Close and archive case"
	@echo "  case-audit               Audit case procedures"
	@echo ""
	@echo "COMPLIANCE & STANDARDS:"
	@echo "  compliance-check         Check compliance status"
	@echo "  compliance-report        Generate compliance report"
	@echo "  compliance-iso           ISO 27041-27043 compliance"
	@echo "  compliance-nist          NIST 800-86 compliance"
	@echo ""
	@echo "For detailed usage: make <target> HELP=1"
	@echo "============================================================================"

version: ## Display version information
	@echo "Digital Forensics & Incident Response Framework"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build User: $(BUILD_USER)@$(BUILD_HOST)"
	@echo "Docker Tag: $(DOCKER_TAG)"
	@echo "Base Directory: $(BASE_DIR)"

# ============================================================================
# ENVIRONMENT SETUP AND INITIALIZATION
# ============================================================================

setup: ## Initialize complete forensic environment
	@echo "Setting up Digital Forensics & Incident Response environment..."
	@mkdir -p $(EVIDENCE_DIR)/{disk-images,memory-dumps,network-captures,mobile-extracts,documents}
	@mkdir -p $(CASES_DIR)/{active,closed,templates,workflows}
	@mkdir -p $(REPORTS_DIR)/{forensic,incident,compliance,executive}
	@mkdir -p $(DOCS_DIR)/{procedures,guidelines,templates,standards}
	@mkdir -p $(LAB_DIR)/{malware,sandbox,analysis,testing}
	@mkdir -p $(BACKUP_DIR)/{evidence,cases,configs,database}
	@mkdir -p $(LOGS_DIR)/{forensic,incident,audit,system}
	@mkdir -p $(CONFIG_DIR)/{forensic-tools,incident-response,monitoring}
	@mkdir -p $(SSL_CERT_DIR)
	@mkdir -p $(SECRETS_DIR)
	@chmod 700 $(SECRETS_DIR)
	@chmod 755 $(EVIDENCE_DIR) $(CASES_DIR) $(REPORTS_DIR)
	@echo "Environment setup completed successfully"

forensic-setup: setup ## Setup forensic analysis environment
	@echo "Setting up forensic analysis environment..."
	@$(SCRIPTS_DIR)/forensic/setup-forensic-env.sh
	@$(SCRIPTS_DIR)/forensic/install-sleuthkit.sh $(SLEUTHKIT_VERSION)
	@$(SCRIPTS_DIR)/forensic/install-autopsy.sh $(AUTOPSY_VERSION)
	@$(SCRIPTS_DIR)/forensic/install-volatility.sh $(VOLATILITY_VERSION)
	@$(SCRIPTS_DIR)/forensic/install-plaso.sh $(PLASO_VERSION)
	@$(SCRIPTS_DIR)/forensic/configure-forensic-tools.sh
	@$(SCRIPTS_DIR)/forensic/validate-forensic-setup.sh
	@echo "Forensic analysis environment ready"

incident-setup: setup ## Setup incident response environment
	@echo "Setting up incident response environment..."
	@$(SCRIPTS_DIR)/incident/setup-ir-env.sh
	@$(SCRIPTS_DIR)/incident/install-ir-tools.sh
	@$(SCRIPTS_DIR)/incident/configure-soar.sh
	@$(SCRIPTS_DIR)/incident/setup-playbooks.sh
	@$(SCRIPTS_DIR)/incident/configure-threat-intel.sh
	@$(SCRIPTS_DIR)/incident/validate-ir-setup.sh
	@echo "Incident response environment ready"

analysis-setup: ## Setup analysis tools and environments
	@echo "Setting up analysis environment..."
	@$(SCRIPTS_DIR)/analysis/setup-analysis-env.sh
	@$(SCRIPTS_DIR)/analysis/install-yara.sh $(YARA_VERSION)
	@$(SCRIPTS_DIR)/analysis/install-wireshark.sh $(WIRESHARK_VERSION)
	@$(SCRIPTS_DIR)/analysis/configure-analysis-tools.sh
	@$(SCRIPTS_DIR)/analysis/setup-sandbox.sh
	@echo "Analysis environment ready"

lab-setup: ## Setup complete forensic laboratory
	@echo "Setting up forensic laboratory..."
	@$(SCRIPTS_DIR)/lab/setup-lab-environment.sh
	@$(SCRIPTS_DIR)/lab/configure-isolated-networks.sh
	@$(SCRIPTS_DIR)/lab/setup-evidence-storage.sh
	@$(SCRIPTS_DIR)/lab/configure-chain-of-custody.sh
	@$(SCRIPTS_DIR)/lab/validate-lab-setup.sh
	@echo "Forensic laboratory ready"

monitoring-setup: ## Setup monitoring and logging
	@echo "Setting up monitoring and logging..."
	@$(SCRIPTS_DIR)/monitoring/setup-elk-stack.sh
	@$(SCRIPTS_DIR)/monitoring/configure-forensic-logging.sh
	@$(SCRIPTS_DIR)/monitoring/setup-audit-trail.sh
	@$(SCRIPTS_DIR)/monitoring/configure-alerts.sh
	@echo "Monitoring and logging configured"

# ============================================================================
# DOCKER CONTAINER MANAGEMENT
# ============================================================================

deploy: ## Deploy complete forensic lab infrastructure
	@echo "Deploying forensic lab infrastructure..."
	@docker network create $(FORENSIC_NETWORK) --driver bridge --subnet 172.20.0.0/16 || true
	@docker network create $(ANALYSIS_NETWORK) --driver bridge --subnet 172.21.0.0/16 || true
	@docker network create $(MONITORING_NETWORK) --driver bridge --subnet 172.22.0.0/16 || true
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) up -d
	@echo "Forensic lab infrastructure deployed"

start: ## Start all forensic services
	@echo "Starting forensic services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) start
	@$(SCRIPTS_DIR)/monitoring/check-services.sh
	@echo "All forensic services started"

stop: ## Stop all forensic services
	@echo "Stopping forensic services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) stop
	@echo "All forensic services stopped"

restart: ## Restart all forensic services
	@echo "Restarting forensic services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) restart
	@echo "All forensic services restarted"

status: ## Check status of all services
	@echo "Checking forensic services status..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) ps
	@$(SCRIPTS_DIR)/monitoring/service-health-check.sh

logs: ## View logs from all services
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) logs -f --tail=100

shell: ## Access forensic analysis shell
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) exec forensic-workstation /bin/bash

# ============================================================================
# EVIDENCE HANDLING AND PROCESSING
# ============================================================================

evidence-acquire: ## Acquire digital evidence with chain of custody
ifdef HELP
	@echo "Evidence Acquisition Options:"
	@echo "  make evidence-acquire DEVICE=/dev/sdb CASE=case001 TYPE=disk"
	@echo "  make evidence-acquire HOST=192.168.1.100 CASE=case001 TYPE=memory"
	@echo "  make evidence-acquire INTERFACE=eth0 CASE=case001 TYPE=network"
	@echo "  make evidence-acquire DEVICE=/dev/ttyUSB0 CASE=case001 TYPE=mobile"
else
	@echo "Starting evidence acquisition..."
	@$(SCRIPTS_DIR)/evidence/acquire-evidence.sh \
		--case=$(CASE) \
		--type=$(TYPE) \
		--device=$(DEVICE) \
		--output=$(EVIDENCE_DIR)/$(CASE) \
		--hash-algorithm=SHA256 \
		--chain-of-custody \
		--documentation
	@$(SCRIPTS_DIR)/evidence/validate-acquisition.sh $(EVIDENCE_DIR)/$(CASE)
	@echo "Evidence acquisition completed for case $(CASE)"
endif

evidence-process: ## Process and validate acquired evidence
ifdef HELP
	@echo "Evidence Processing Options:"
	@echo "  make evidence-process CASE=case001 EVIDENCE=disk001.dd"
	@echo "  make evidence-process CASE=case001 EVIDENCE=memory001.mem"
else
	@echo "Processing evidence for case $(CASE)..."
	@$(SCRIPTS_DIR)/evidence/process-evidence.sh \
		--case=$(CASE) \
		--evidence=$(EVIDENCE) \
		--hash-verify \
		--metadata-extract \
		--timeline-create
	@$(SCRIPTS_DIR)/evidence/generate-evidence-report.sh $(CASE) $(EVIDENCE)
	@echo "Evidence processing completed"
endif

evidence-analyze: ## Analyze processed evidence
ifdef HELP
	@echo "Evidence Analysis Options:"
	@echo "  make evidence-analyze CASE=case001 TYPE=filesystem"
	@echo "  make evidence-analyze CASE=case001 TYPE=registry"
	@echo "  make evidence-analyze CASE=case001 TYPE=browser"
	@echo "  make evidence-analyze CASE=case001 TYPE=email"
else
	@echo "Analyzing evidence for case $(CASE)..."
	@$(SCRIPTS_DIR)/analysis/analyze-evidence.sh \
		--case=$(CASE) \
		--type=$(TYPE) \
		--keywords="$(KEYWORDS)" \
		--output=$(REPORTS_DIR)/$(CASE)
	@$(SCRIPTS_DIR)/analysis/correlate-findings.sh $(CASE)
	@echo "Evidence analysis completed"
endif

evidence-report: ## Generate comprehensive evidence report
	@echo "Generating evidence report for case $(CASE)..."
	@$(SCRIPTS_DIR)/reporting/generate-evidence-report.sh \
		--case=$(CASE) \
		--template=forensic-standard \
		--format=pdf \
		--output=$(REPORTS_DIR)/$(CASE)
	@$(SCRIPTS_DIR)/reporting/validate-report.sh $(REPORTS_DIR)/$(CASE)
	@echo "Evidence report generated"

# ============================================================================
# INCIDENT RESPONSE WORKFLOWS
# ============================================================================

incident-detect: ## Detection and identification phase
ifdef HELP
	@echo "Incident Detection Options:"
	@echo "  make incident-detect INCIDENT=INC001 TYPE=malware"
	@echo "  make incident-detect INCIDENT=INC001 TYPE=breach"
	@echo "  make incident-detect INCIDENT=INC001 TYPE=insider"
else
	@echo "Starting incident detection for $(INCIDENT)..."
	@$(SCRIPTS_DIR)/incident/detect-incident.sh \
		--incident=$(INCIDENT) \
		--type=$(TYPE) \
		--severity=$(SEVERITY) \
		--automated-analysis
	@$(SCRIPTS_DIR)/incident/classify-incident.sh $(INCIDENT)
	@$(SCRIPTS_DIR)/incident/notify-stakeholders.sh $(INCIDENT)
	@echo "Incident detection phase completed"
endif

incident-contain: ## Containment and short-term recovery
	@echo "Starting incident containment for $(INCIDENT)..."
	@$(SCRIPTS_DIR)/incident/contain-incident.sh \
		--incident=$(INCIDENT) \
		--isolation-level=$(ISOLATION) \
		--preserve-evidence \
		--document-actions
	@$(SCRIPTS_DIR)/incident/validate-containment.sh $(INCIDENT)
	@echo "Incident containment completed"

incident-eradicate: ## Eradication and long-term recovery
	@echo "Starting incident eradication for $(INCIDENT)..."
	@$(SCRIPTS_DIR)/incident/eradicate-threat.sh \
		--incident=$(INCIDENT) \
		--remediation-plan \
		--vulnerability-patch \
		--security-hardening
	@$(SCRIPTS_DIR)/incident/validate-eradication.sh $(INCIDENT)
	@echo "Incident eradication completed"

incident-recover: ## Recovery and lessons learned
	@echo "Starting incident recovery for $(INCIDENT)..."
	@$(SCRIPTS_DIR)/incident/recover-systems.sh \
		--incident=$(INCIDENT) \
		--restore-plan \
		--monitoring-enhanced \
		--user-communication
	@$(SCRIPTS_DIR)/incident/lessons-learned.sh $(INCIDENT)
	@$(SCRIPTS_DIR)/incident/update-procedures.sh $(INCIDENT)
	@echo "Incident recovery completed"

# ============================================================================
# FORENSIC ANALYSIS SPECIALIZATIONS
# ============================================================================

forensic-disk: ## Disk and filesystem forensic analysis
ifdef HELP
	@echo "Disk Forensic Analysis Options:"
	@echo "  make forensic-disk CASE=case001 IMAGE=disk001.dd"
	@echo "  make forensic-disk CASE=case001 IMAGE=disk001.dd FILESYSTEM=ntfs"
else
	@echo "Starting disk forensic analysis..."
	@$(SCRIPTS_DIR)/forensic/disk-analysis.sh \
		--case=$(CASE) \
		--image=$(IMAGE) \
		--filesystem=$(FILESYSTEM) \
		--deleted-recovery \
		--timeline-creation \
		--hash-analysis
	@$(SCRIPTS_DIR)/forensic/extract-artifacts.sh $(CASE) disk
	@echo "Disk forensic analysis completed"
endif

forensic-memory: ## Memory forensic analysis
ifdef HELP
	@echo "Memory Forensic Analysis Options:"
	@echo "  make forensic-memory CASE=case001 DUMP=memory001.mem"
	@echo "  make forensic-memory CASE=case001 DUMP=memory001.mem OS=windows"
else
	@echo "Starting memory forensic analysis..."
	@$(SCRIPTS_DIR)/forensic/memory-analysis.sh \
		--case=$(CASE) \
		--dump=$(DUMP) \
		--os=$(OS) \
		--process-analysis \
		--network-connections \
		--malware-detection
	@$(SCRIPTS_DIR)/forensic/extract-artifacts.sh $(CASE) memory
	@echo "Memory forensic analysis completed"
endif

forensic-network: ## Network forensic analysis
ifdef HELP
	@echo "Network Forensic Analysis Options:"
	@echo "  make forensic-network CASE=case001 CAPTURE=network001.pcap"
	@echo "  make forensic-network CASE=case001 CAPTURE=network001.pcap PROTOCOL=http"
else
	@echo "Starting network forensic analysis..."
	@$(SCRIPTS_DIR)/forensic/network-analysis.sh \
		--case=$(CASE) \
		--capture=$(CAPTURE) \
		--protocol=$(PROTOCOL) \
		--flow-analysis \
		--content-extraction \
		--threat-detection
	@$(SCRIPTS_DIR)/forensic/extract-artifacts.sh $(CASE) network
	@echo "Network forensic analysis completed"
endif

forensic-mobile: ## Mobile device forensic analysis
ifdef HELP
	@echo "Mobile Forensic Analysis Options:"
	@echo "  make forensic-mobile CASE=case001 DEVICE=android EXTRACT=device001.tar"
	@echo "  make forensic-mobile CASE=case001 DEVICE=ios EXTRACT=device001.ipsw"
else
	@echo "Starting mobile forensic analysis..."
	@$(SCRIPTS_DIR)/forensic/mobile-analysis.sh \
		--case=$(CASE) \
		--device=$(DEVICE) \
		--extract=$(EXTRACT) \
		--app-analysis \
		--communication-recovery \
		--location-analysis
	@$(SCRIPTS_DIR)/forensic/extract-artifacts.sh $(CASE) mobile
	@echo "Mobile forensic analysis completed"
endif

# ============================================================================
# MALWARE ANALYSIS
# ============================================================================

malware-setup: ## Setup malware analysis environment
	@echo "Setting up malware analysis environment..."
	@$(SCRIPTS_DIR)/malware/setup-malware-lab.sh
	@$(SCRIPTS_DIR)/malware/configure-sandbox.sh
	@$(SCRIPTS_DIR)/malware/install-analysis-tools.sh
	@$(SCRIPTS_DIR)/malware/setup-isolated-network.sh
	@echo "Malware analysis environment ready"

malware-analyze: ## Static and dynamic malware analysis
ifdef HELP
	@echo "Malware Analysis Options:"
	@echo "  make malware-analyze SAMPLE=malware001.exe TYPE=static"
	@echo "  make malware-analyze SAMPLE=malware001.exe TYPE=dynamic"
	@echo "  make malware-analyze SAMPLE=malware001.exe TYPE=both"
else
	@echo "Starting malware analysis for $(SAMPLE)..."
	@$(SCRIPTS_DIR)/malware/analyze-malware.sh \
		--sample=$(SAMPLE) \
		--type=$(TYPE) \
		--sandbox-time=300 \
		--yara-rules \
		--behavior-analysis
	@$(SCRIPTS_DIR)/malware/generate-iocs.sh $(SAMPLE)
	@echo "Malware analysis completed"
endif

malware-sandbox: ## Execute malware in controlled sandbox
	@echo "Executing malware in sandbox..."
	@$(SCRIPTS_DIR)/malware/sandbox-execute.sh \
		--sample=$(SAMPLE) \
		--timeout=600 \
		--network-capture \
		--system-monitoring \
		--memory-dump
	@$(SCRIPTS_DIR)/malware/analyze-sandbox-results.sh $(SAMPLE)
	@echo "Sandbox analysis completed"

malware-report: ## Generate malware analysis report
	@echo "Generating malware analysis report..."
	@$(SCRIPTS_DIR)/malware/generate-malware-report.sh \
		--sample=$(SAMPLE) \
		--template=malware-standard \
		--include-iocs \
		--include-mitre-mapping
	@echo "Malware analysis report generated"

# ============================================================================
# TIMELINE ANALYSIS
# ============================================================================

timeline-create: ## Create comprehensive timeline from evidence
ifdef HELP
	@echo "Timeline Creation Options:"
	@echo "  make timeline-create CASE=case001 SOURCE=all"
	@echo "  make timeline-create CASE=case001 SOURCE=filesystem"
	@echo "  make timeline-create CASE=case001 SOURCE=registry"
else
	@echo "Creating timeline for case $(CASE)..."
	@$(SCRIPTS_DIR)/timeline/create-timeline.sh \
		--case=$(CASE) \
		--source=$(SOURCE) \
		--output=$(REPORTS_DIR)/$(CASE)/timeline \
		--format=plaso \
		--time-zone=$(TIMEZONE)
	@$(SCRIPTS_DIR)/timeline/validate-timeline.sh $(CASE)
	@echo "Timeline creation completed"
endif

timeline-analyze: ## Analyze timeline for patterns and anomalies
	@echo "Analyzing timeline for case $(CASE)..."
	@$(SCRIPTS_DIR)/timeline/analyze-timeline.sh \
		--case=$(CASE) \
		--keywords="$(KEYWORDS)" \
		--time-range="$(TIME_RANGE)" \
		--anomaly-detection
	@$(SCRIPTS_DIR)/timeline/generate-timeline-report.sh $(CASE)
	@echo "Timeline analysis completed"

timeline-correlate: ## Correlate multiple timelines
	@echo "Correlating timelines for case $(CASE)..."
	@$(SCRIPTS_DIR)/timeline/correlate-timelines.sh \
		--case=$(CASE) \
		--sources="$(SOURCES)" \
		--correlation-window=300 \
		--output-format=json
	@echo "Timeline correlation completed"

timeline-visualize: ## Create timeline visualizations
	@echo "Creating timeline visualizations..."
	@$(SCRIPTS_DIR)/timeline/visualize-timeline.sh \
		--case=$(CASE) \
		--type=$(VIS_TYPE) \
		--output=$(REPORTS_DIR)/$(CASE)/visualizations
	@echo "Timeline visualizations created"

# ============================================================================
# THREAT INTELLIGENCE INTEGRATION
# ============================================================================

threat-intel: ## Initialize threat intelligence integration
	@echo "Setting up threat intelligence integration..."
	@$(SCRIPTS_DIR)/threat-intel/setup-misp.sh
	@$(SCRIPTS_DIR)/threat-intel/configure-feeds.sh
	@$(SCRIPTS_DIR)/threat-intel/setup-opencti.sh
	@$(SCRIPTS_DIR)/threat-intel/validate-threat-intel.sh
	@echo "Threat intelligence integration ready"

threat-feed: ## Update threat intelligence feeds
	@echo "Updating threat intelligence feeds..."
	@$(SCRIPTS_DIR)/threat-intel/update-feeds.sh
	@$(SCRIPTS_DIR)/threat-intel/validate-indicators.sh
	@$(SCRIPTS_DIR)/threat-intel/correlate-with-cases.sh
	@echo "Threat feeds updated"

threat-hunt: ## Proactive threat hunting operations
ifdef HELP
	@echo "Threat Hunting Options:"
	@echo "  make threat-hunt TYPE=apt TIMEFRAME=30d"
	@echo "  make threat-hunt TYPE=malware INDICATORS=hash-list.txt"
else
	@echo "Starting threat hunting operation..."
	@$(SCRIPTS_DIR)/threat-intel/threat-hunt.sh \
		--type=$(TYPE) \
		--timeframe=$(TIMEFRAME) \
		--indicators="$(INDICATORS)" \
		--automated-analysis
	@$(SCRIPTS_DIR)/threat-intel/analyze-hunt-results.sh
	@echo "Threat hunting operation completed"
endif

threat-ioc: ## Manage Indicators of Compromise (IoCs)
	@echo "Managing IoCs..."
	@$(SCRIPTS_DIR)/threat-intel/manage-iocs.sh \
		--action=$(ACTION) \
		--source=$(SOURCE) \
		--confidence=$(CONFIDENCE) \
		--sharing-level=$(SHARING)
	@echo "IoC management completed"

threat-mitre: ## Map findings to MITRE ATT&CK framework
	@echo "Mapping to MITRE ATT&CK framework..."
	@$(SCRIPTS_DIR)/threat-intel/mitre-mapping.sh \
		--case=$(CASE) \
		--auto-mapping \
		--confidence-scoring \
		--report-generation
	@echo "MITRE ATT&CK mapping completed"

# ============================================================================
# CASE MANAGEMENT
# ============================================================================

case-create: ## Create new forensic case
ifdef HELP
	@echo "Case Creation Options:"
	@echo "  make case-create CASE=case001 TYPE=cybercrime PRIORITY=high"
	@echo "  make case-create CASE=case001 TYPE=incident PRIORITY=medium"
else
	@echo "Creating new forensic case $(CASE)..."
	@$(SCRIPTS_DIR)/case-mgmt/create-case.sh \
		--case=$(CASE) \
		--type=$(TYPE) \
		--priority=$(PRIORITY) \
		--investigator="$(INVESTIGATOR)" \
		--description="$(DESCRIPTION)"
	@$(SCRIPTS_DIR)/case-mgmt/setup-case-structure.sh $(CASE)
	@$(SCRIPTS_DIR)/case-mgmt/initialize-chain-of-custody.sh $(CASE)
	@echo "Case $(CASE) created successfully"
endif

case-manage: ## Manage active forensic cases
	@echo "Managing forensic cases..."
	@$(SCRIPTS_DIR)/case-mgmt/list-cases.sh --status=active
	@$(SCRIPTS_DIR)/case-mgmt/update-case-status.sh
	@$(SCRIPTS_DIR)/case-mgmt/generate-case-dashboard.sh
	@echo "Case management dashboard updated"

case-document: ## Document case activities and findings
	@echo "Documenting case activities for $(CASE)..."
	@$(SCRIPTS_DIR)/case-mgmt/document-activity.sh \
		--case=$(CASE) \
		--activity="$(ACTIVITY)" \
		--timestamp=$(shell date -Iseconds) \
		--investigator="$(INVESTIGATOR)"
	@$(SCRIPTS_DIR)/case-mgmt/update-case-log.sh $(CASE)
	@echo "Case documentation updated"

case-close: ## Close and archive forensic case
	@echo "Closing forensic case $(CASE)..."
	@$(SCRIPTS_DIR)/case-mgmt/validate-case-completion.sh $(CASE)
	@$(SCRIPTS_DIR)/case-mgmt/generate-final-report.sh $(CASE)
	@$(SCRIPTS_DIR)/case-mgmt/archive-case.sh $(CASE)
	@$(SCRIPTS_DIR)/case-mgmt/cleanup-workspace.sh $(CASE)
	@echo "Case $(CASE) closed and archived"

case-audit: ## Audit case procedures and compliance
	@echo "Auditing case procedures for $(CASE)..."
	@$(SCRIPTS_DIR)/case-mgmt/audit-case.sh \
		--case=$(CASE) \
		--standards=$(ISO_STANDARD) \
		--check-chain-of-custody \
		--validate-procedures
	@$(SCRIPTS_DIR)/case-mgmt/generate-audit-report.sh $(CASE)
	@echo "Case audit completed"

# ============================================================================
# COMPLIANCE AND STANDARDS
# ============================================================================

compliance-check: ## Check compliance with forensic standards
	@echo "Checking compliance with forensic standards..."
	@$(SCRIPTS_DIR)/compliance/check-iso-compliance.sh $(ISO_STANDARD)
	@$(SCRIPTS_DIR)/compliance/check-nist-compliance.sh $(NIST_FRAMEWORK)
	@$(SCRIPTS_DIR)/compliance/check-sans-compliance.sh $(SANS_METHODOLOGY)
	@$(SCRIPTS_DIR)/compliance/check-acpo-compliance.sh $(ACPO_GUIDELINES)
	@echo "Compliance check completed"

compliance-report: ## Generate comprehensive compliance report
	@echo "Generating compliance report..."
	@$(SCRIPTS_DIR)/compliance/generate-compliance-report.sh \
		--standards="$(ISO_STANDARD),$(NIST_FRAMEWORK)" \
		--period=$(PERIOD) \
		--output=$(REPORTS_DIR)/compliance \
		--format=pdf
	@echo "Compliance report generated"

compliance-iso: ## ISO 27041-27043 specific compliance
	@echo "Checking ISO 27041-27043 compliance..."
	@$(SCRIPTS_DIR)/compliance/iso-27041-check.sh  # Evidence identification
	@$(SCRIPTS_DIR)/compliance/iso-27042-check.sh  # Analysis and interpretation
	@$(SCRIPTS_DIR)/compliance/iso-27043-check.sh  # Investigation principles
	@$(SCRIPTS_DIR)/compliance/iso-27037-check.sh  # Collection and preservation
	@echo "ISO compliance check completed"

compliance-nist: ## NIST 800-86 specific compliance
	@echo "Checking NIST 800-86 compliance..."
	@$(SCRIPTS_DIR)/compliance/nist-800-86-check.sh
	@$(SCRIPTS_DIR)/compliance/nist-incident-response-check.sh
	@$(SCRIPTS_DIR)/compliance/nist-cybersecurity-framework-check.sh
	@echo "NIST compliance check completed"

# ============================================================================
# TRAINING AND CERTIFICATION
# ============================================================================

training-setup: ## Setup forensic training environment
	@echo "Setting up forensic training environment..."
	@$(SCRIPTS_DIR)/training/setup-training-lab.sh
	@$(SCRIPTS_DIR)/training/create-training-scenarios.sh
	@$(SCRIPTS_DIR)/training/setup-practice-cases.sh
	@$(SCRIPTS_DIR)/training/configure-training-monitoring.sh
	@echo "Forensic training environment ready"

training-scenarios: ## Execute training scenarios
ifdef HELP
	@echo "Training Scenario Options:"
	@echo "  make training-scenarios SCENARIO=disk-analysis LEVEL=beginner"
	@echo "  make training-scenarios SCENARIO=incident-response LEVEL=advanced"
else
	@echo "Executing training scenario $(SCENARIO)..."
	@$(SCRIPTS_DIR)/training/run-scenario.sh \
		--scenario=$(SCENARIO) \
		--level=$(LEVEL) \
		--student="$(STUDENT)" \
		--time-limit=$(TIME_LIMIT)
	@$(SCRIPTS_DIR)/training/evaluate-performance.sh $(SCENARIO) $(STUDENT)
	@echo "Training scenario completed"
endif

training-validate: ## Validate training completion and competency
	@echo "Validating training completion..."
	@$(SCRIPTS_DIR)/training/validate-competency.sh \
		--student="$(STUDENT)" \
		--certification=$(CERT_TYPE) \
		--practical-exam \
		--theory-exam
	@$(SCRIPTS_DIR)/training/generate-certificate.sh $(STUDENT)
	@echo "Training validation completed"

training-certify: ## Generate training certificates
	@echo "Generating training certificates..."
	@$(SCRIPTS_DIR)/training/generate-certificates.sh \
		--batch=$(BATCH) \
		--certification=$(CERT_TYPE) \
		--validity-period=2years
	@echo "Training certificates generated"

# ============================================================================
# SECURITY AND MONITORING
# ============================================================================

security-harden: ## Harden forensic environment security
	@echo "Hardening forensic environment security..."
	@$(SCRIPTS_DIR)/security/harden-systems.sh
	@$(SCRIPTS_DIR)/security/configure-access-controls.sh
	@$(SCRIPTS_DIR)/security/setup-audit-logging.sh
	@$(SCRIPTS_DIR)/security/configure-encryption.sh
	@$(SCRIPTS_DIR)/security/validate-hardening.sh
	@echo "Security hardening completed"

security-audit: ## Security audit of forensic environment
	@echo "Performing security audit..."
	@$(SCRIPTS_DIR)/security/audit-security.sh
	@$(SCRIPTS_DIR)/security/vulnerability-scan.sh
	@$(SCRIPTS_DIR)/security/compliance-check.sh
	@$(SCRIPTS_DIR)/security/generate-security-report.sh
	@echo "Security audit completed"

security-monitor: ## Monitor security of forensic systems
	@echo "Starting security monitoring..."
	@$(SCRIPTS_DIR)/security/start-monitoring.sh
	@$(SCRIPTS_DIR)/security/configure-alerts.sh
	@$(SCRIPTS_DIR)/security/setup-intrusion-detection.sh
	@echo "Security monitoring active"

security-respond: ## Respond to security incidents
	@echo "Responding to security incident..."
	@$(SCRIPTS_DIR)/security/incident-response.sh \
		--incident=$(SECURITY_INCIDENT) \
		--severity=$(SEVERITY) \
		--automated-containment
	@$(SCRIPTS_DIR)/security/forensic-analysis.sh $(SECURITY_INCIDENT)
	@echo "Security incident response completed"

# ============================================================================
# BACKUP AND RECOVERY
# ============================================================================

backup: ## Backup forensic evidence and case data
	@echo "Starting forensic data backup..."
	@$(SCRIPTS_DIR)/backup/backup-evidence.sh \
		--destination=$(BACKUP_DIR) \
		--compression \
		--encryption \
		--verification
	@$(SCRIPTS_DIR)/backup/backup-cases.sh
	@$(SCRIPTS_DIR)/backup/backup-configs.sh
	@$(SCRIPTS_DIR)/backup/validate-backups.sh
	@echo "Forensic data backup completed"

restore: ## Restore forensic data from backup
ifdef HELP
	@echo "Restore Options:"
	@echo "  make restore TYPE=evidence CASE=case001"
	@echo "  make restore TYPE=full TIMESTAMP=2024-01-28"
else
	@echo "Starting forensic data restore..."
	@$(SCRIPTS_DIR)/backup/restore-data.sh \
		--type=$(TYPE) \
		--case=$(CASE) \
		--timestamp=$(TIMESTAMP) \
		--verify-integrity
	@$(SCRIPTS_DIR)/backup/validate-restore.sh
	@echo "Forensic data restore completed"
endif

# ============================================================================
# INTEGRATION AND TESTING
# ============================================================================

integration-test: ## Run integration tests for forensic framework
	@echo "Running integration tests..."
	@$(SCRIPTS_DIR)/testing/test-evidence-acquisition.sh
	@$(SCRIPTS_DIR)/testing/test-forensic-analysis.sh
	@$(SCRIPTS_DIR)/testing/test-incident-response.sh
	@$(SCRIPTS_DIR)/testing/test-malware-analysis.sh
	@$(SCRIPTS_DIR)/testing/test-timeline-creation.sh
	@$(SCRIPTS_DIR)/testing/generate-test-report.sh
	@echo "Integration testing completed"

integration-validate: ## Validate integration with external systems
	@echo "Validating external integrations..."
	@$(SCRIPTS_DIR)/integration/validate-misp-integration.sh
	@$(SCRIPTS_DIR)/integration/validate-soar-integration.sh
	@$(SCRIPTS_DIR)/integration/validate-siem-integration.sh
	@$(SCRIPTS_DIR)/integration/validate-threat-intel-feeds.sh
	@echo "Integration validation completed"

integration-deploy: ## Deploy integrated forensic environment
	@echo "Deploying integrated forensic environment..."
	@$(SCRIPTS_DIR)/integration/deploy-full-stack.sh
	@$(SCRIPTS_DIR)/integration/configure-integrations.sh
	@$(SCRIPTS_DIR)/integration/validate-deployment.sh
	@$(SCRIPTS_DIR)/integration/generate-deployment-report.sh
	@echo "Integrated forensic environment deployed"

integration-monitor: ## Monitor integration health and performance
	@echo "Monitoring integration health..."
	@$(SCRIPTS_DIR)/integration/monitor-integrations.sh
	@$(SCRIPTS_DIR)/integration/check-api-connectivity.sh
	@$(SCRIPTS_DIR)/integration/validate-data-flows.sh
	@echo "Integration monitoring active"

# ============================================================================
# CLEANUP AND MAINTENANCE
# ============================================================================

clean: ## Clean temporary files and logs
	@echo "Cleaning temporary files and logs..."
	@find $(LOGS_DIR) -name "*.log" -mtime +30 -delete
	@find $(BASE_DIR) -name "*.tmp" -delete
	@find $(BASE_DIR) -name "*.temp" -delete
	@docker system prune -f
	@echo "Cleanup completed"

maintenance: ## Perform system maintenance tasks
	@echo "Performing system maintenance..."
	@$(SCRIPTS_DIR)/maintenance/update-forensic-tools.sh
	@$(SCRIPTS_DIR)/maintenance/rotate-logs.sh
	@$(SCRIPTS_DIR)/maintenance/cleanup-old-cases.sh
	@$(SCRIPTS_DIR)/maintenance/validate-evidence-integrity.sh
	@$(SCRIPTS_DIR)/maintenance/generate-maintenance-report.sh
	@echo "System maintenance completed"

# ============================================================================
# HELP TARGETS FOR SPECIFIC CATEGORIES
# ============================================================================

help-forensic: ## Show forensic analysis help
	@echo "============================================================================"
	@echo "FORENSIC ANALYSIS HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Available forensic analysis commands:"
	@echo ""
	@echo "forensic-disk CASE=<case> IMAGE=<image> [FILESYSTEM=<fs>]"
	@echo "  Analyze disk images with filesystem recovery"
	@echo ""
	@echo "forensic-memory CASE=<case> DUMP=<dump> [OS=<os>]"
	@echo "  Analyze memory dumps for processes and malware"
	@echo ""
	@echo "forensic-network CASE=<case> CAPTURE=<pcap> [PROTOCOL=<proto>]"
	@echo "  Analyze network traffic and communications"
	@echo ""
	@echo "forensic-mobile CASE=<case> DEVICE=<type> EXTRACT=<file>"
	@echo "  Analyze mobile device extractions"
	@echo ""
	@echo "============================================================================"

help-incident: ## Show incident response help
	@echo "============================================================================"
	@echo "INCIDENT RESPONSE HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Incident Response Phases:"
	@echo ""
	@echo "1. incident-detect INCIDENT=<id> TYPE=<type> [SEVERITY=<level>]"
	@echo "   Detection and identification of security incidents"
	@echo ""
	@echo "2. incident-contain INCIDENT=<id> [ISOLATION=<level>]"
	@echo "   Containment and short-term recovery"
	@echo ""
	@echo "3. incident-eradicate INCIDENT=<id>"
	@echo "   Eradication and long-term recovery"
	@echo ""
	@echo "4. incident-recover INCIDENT=<id>"
	@echo "   Recovery and lessons learned"
	@echo ""
	@echo "============================================================================"

help-malware: ## Show malware analysis help
	@echo "============================================================================"
	@echo "MALWARE ANALYSIS HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Malware Analysis Commands:"
	@echo ""
	@echo "malware-analyze SAMPLE=<file> TYPE=<static|dynamic|both>"
	@echo "  Comprehensive malware analysis"
	@echo ""
	@echo "malware-sandbox SAMPLE=<file> [TIMEOUT=<seconds>]"
	@echo "  Execute malware in controlled sandbox"
	@echo ""
	@echo "malware-report SAMPLE=<file>"
	@echo "  Generate detailed analysis report"
	@echo ""
	@echo "============================================================================"

# ============================================================================
# DEFAULT TARGET
# ============================================================================

.DEFAULT_GOAL := help

# ============================================================================
# END OF MAKEFILE
# ============================================================================