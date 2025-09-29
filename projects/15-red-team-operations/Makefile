# ============================================================================
# Makefile - Red Team Operations & Penetration Testing Framework
# ============================================================================
# Professional-grade automation for red team operations and penetration testing
# Supports PTES, OWASP, NIST, and MITRE ATT&CK methodologies
# Version: 1.0.0
# Last Updated: January 28, 2024
# ============================================================================

.PHONY: help setup clean deploy start stop restart status logs shell backup restore \
        redteam-setup pentest-setup target-setup c2-setup monitoring-setup \
        recon-osint recon-network recon-web recon-dns recon-full \
        exploit-web exploit-network exploit-windows exploit-linux exploit-auto \
        postexploit-persistence postexploit-privesc postexploit-lateral postexploit-exfil \
        c2-deploy c2-listeners c2-agents c2-cleanup c2-monitor \
        payload-windows payload-linux payload-web payload-mobile payload-custom \
        campaign-start campaign-execute campaign-monitor campaign-report campaign-cleanup \
        training-setup training-scenarios training-ctf training-validate \
        opsec-check opsec-monitor opsec-cleanup opsec-validate \
        report-generate report-executive report-technical report-compliance \
        evasion-av evasion-edr evasion-network evasion-attribution \
        target-setup target-deploy target-validate target-cleanup \
        vuln-scan vuln-assess vuln-exploit vuln-report \
        social-phishing social-vishing social-pretexting social-osint

# ============================================================================
# CONFIGURATION AND VARIABLES
# ============================================================================

# Project Configuration
PROJECT_NAME := red-team-operations
PROJECT_VERSION := 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_USER := $(shell whoami)
BUILD_HOST := $(shell hostname)

# Directory Structure
BASE_DIR := $(shell pwd)
SCRIPTS_DIR := $(BASE_DIR)/scripts
TOOLS_DIR := $(BASE_DIR)/tools
TARGETS_DIR := $(BASE_DIR)/targets
PAYLOADS_DIR := $(BASE_DIR)/payloads
EXPLOITS_DIR := $(BASE_DIR)/exploits
CAMPAIGNS_DIR := $(BASE_DIR)/campaigns
INFRA_DIR := $(BASE_DIR)/infrastructure
REPORTS_DIR := $(BASE_DIR)/reports
LOGS_DIR := $(BASE_DIR)/logs
BACKUP_DIR := $(BASE_DIR)/backup

# Docker Configuration
COMPOSE_FILE := docker-compose.yml
COMPOSE_PROJECT := redteam-lab
COMPOSE_ENV := .env
DOCKER_REGISTRY := redteam-registry.local
DOCKER_TAG := $(PROJECT_VERSION)

# Red Team Configuration
CAMPAIGN_NAME := operation_red_dawn
TARGET_DOMAIN := target.local
TARGET_NETWORK := 192.168.100.0/24
C2_SERVER := c2.redteam.local
C2_PORT := 443
TEAM_SERVER := teamserver.redteam.local

# Network Configuration
REDTEAM_NETWORK := redteam-ops
TARGET_NETWORK_NAME := target-environment
C2_NETWORK := command-control
MONITORING_NETWORK := monitoring-net
ISOLATION_NETWORK := isolated-lab

# Tool Versions
KALI_VERSION := 2024.1
METASPLOIT_VERSION := 6.3.0
COBALTSTRIKE_VERSION := 4.8
BURPSUITE_VERSION := 2023.12
ZAP_VERSION := 2.14.0
NMAP_VERSION := 7.94

# Performance Configuration
MEMORY_LIMIT := 16g
CPU_LIMIT := 8
DISK_SPACE := 200g
CONCURRENT_SESSIONS := 10

# Operational Security
OPSEC_LEVEL := high
ATTRIBUTION_AVOIDANCE := enabled
TRAFFIC_OBFUSCATION := enabled
LOG_ANONYMIZATION := enabled

# ============================================================================
# HELP AND INFORMATION
# ============================================================================

help: ## Show this help message with all available targets
	@echo "============================================================================"
	@echo "Red Team Operations & Penetration Testing Framework - Makefile"
	@echo "============================================================================"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build User: $(BUILD_USER)@$(BUILD_HOST)"
	@echo "Current Campaign: $(CAMPAIGN_NAME)"
	@echo "Target Domain: $(TARGET_DOMAIN)"
	@echo "C2 Server: $(C2_SERVER)"
	@echo "============================================================================"
	@echo ""
	@echo "MAIN TARGETS:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "RECONNAISSANCE:"
	@echo "  recon-osint              OSINT gathering and target profiling"
	@echo "  recon-network            Network discovery and port scanning"
	@echo "  recon-web                Web application enumeration"
	@echo "  recon-dns                DNS enumeration and zone transfers"
	@echo "  recon-full               Complete reconnaissance workflow"
	@echo ""
	@echo "EXPLOITATION:"
	@echo "  exploit-web              Web application exploitation"
	@echo "  exploit-network          Network service exploitation"
	@echo "  exploit-windows          Windows-specific exploitation"
	@echo "  exploit-linux            Linux-specific exploitation"
	@echo "  exploit-auto             Automated exploitation workflow"
	@echo ""
	@echo "POST-EXPLOITATION:"
	@echo "  postexploit-persistence  Establish persistence mechanisms"
	@echo "  postexploit-privesc      Privilege escalation techniques"
	@echo "  postexploit-lateral      Lateral movement and pivoting"
	@echo "  postexploit-exfil        Data exfiltration methods"
	@echo ""
	@echo "COMMAND & CONTROL:"
	@echo "  c2-deploy                Deploy C2 infrastructure"
	@echo "  c2-listeners             Start C2 listeners"
	@echo "  c2-agents                Manage C2 agents and beacons"
	@echo "  c2-cleanup               Cleanup C2 infrastructure"
	@echo ""
	@echo "CAMPAIGN MANAGEMENT:"
	@echo "  campaign-start           Start new red team campaign"
	@echo "  campaign-execute         Execute campaign phases"
	@echo "  campaign-monitor         Monitor campaign progress"
	@echo "  campaign-report          Generate campaign reports"
	@echo "  campaign-cleanup         Cleanup campaign artifacts"
	@echo ""
	@echo "OPERATIONAL SECURITY:"
	@echo "  opsec-check              Check operational security"
	@echo "  opsec-monitor            Monitor OPSEC indicators"
	@echo "  opsec-cleanup            Clean OPSEC artifacts"
	@echo "  evasion-av               AV evasion techniques"
	@echo "  evasion-edr              EDR evasion techniques"
	@echo ""
	@echo "For detailed usage: make <target> HELP=1"
	@echo "============================================================================"

version: ## Display version information
	@echo "Red Team Operations & Penetration Testing Framework"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build User: $(BUILD_USER)@$(BUILD_HOST)"
	@echo "Docker Tag: $(DOCKER_TAG)"
	@echo "Base Directory: $(BASE_DIR)"

# ============================================================================
# ENVIRONMENT SETUP AND INITIALIZATION
# ============================================================================

setup: ## Initialize complete red team environment
	@echo "Setting up Red Team Operations environment..."
	@mkdir -p $(SCRIPTS_DIR)/{reconnaissance,exploitation,post-exploitation,persistence,pivoting,reporting}
	@mkdir -p $(TOOLS_DIR)/{custom-exploits,payload-generators,c2-frameworks,evasion,enumeration}
	@mkdir -p $(TARGETS_DIR)/{practice-environments,vulnerable-apps,ctf-challenges,test-networks}
	@mkdir -p $(PAYLOADS_DIR)/{windows,linux,web,mobile,reverse-shells,backdoors}
	@mkdir -p $(EXPLOITS_DIR)/{web-exploits,buffer-overflows,privilege-escalation,zero-days}
	@mkdir -p $(CAMPAIGNS_DIR)/{planning,execution,reporting,lessons-learned}
	@mkdir -p $(INFRA_DIR)/{c2-servers,redirectors,phishing-infrastructure,cloud-setup}
	@mkdir -p $(REPORTS_DIR)/{executive,technical,compliance,evidence}
	@mkdir -p $(LOGS_DIR)/{campaigns,exploitation,c2-activity,opsec}
	@mkdir -p $(BACKUP_DIR)/{campaigns,tools,configurations,intelligence}
	@chmod 700 $(CAMPAIGNS_DIR) $(INFRA_DIR) $(LOGS_DIR)
	@echo "Red Team Operations environment setup completed"

redteam-setup: setup ## Setup red team operations infrastructure
	@echo "Setting up red team operations infrastructure..."
	@$(SCRIPTS_DIR)/setup/setup-redteam-env.sh
	@$(SCRIPTS_DIR)/setup/install-redteam-tools.sh
	@$(SCRIPTS_DIR)/setup/configure-c2-infrastructure.sh
	@$(SCRIPTS_DIR)/setup/setup-opsec-framework.sh
	@$(SCRIPTS_DIR)/setup/configure-team-collaboration.sh
	@$(SCRIPTS_DIR)/setup/validate-redteam-setup.sh
	@echo "Red team operations infrastructure ready"

pentest-setup: setup ## Setup penetration testing environment
	@echo "Setting up penetration testing environment..."
	@$(SCRIPTS_DIR)/setup/setup-pentest-env.sh
	@$(SCRIPTS_DIR)/setup/install-pentest-tools.sh
	@$(SCRIPTS_DIR)/setup/configure-scanning-tools.sh
	@$(SCRIPTS_DIR)/setup/setup-exploitation-framework.sh
	@$(SCRIPTS_DIR)/setup/validate-pentest-setup.sh
	@echo "Penetration testing environment ready"

target-setup: ## Setup target practice environments
	@echo "Setting up target practice environments..."
	@$(SCRIPTS_DIR)/targets/setup-vulnerable-apps.sh
	@$(SCRIPTS_DIR)/targets/deploy-test-networks.sh
	@$(SCRIPTS_DIR)/targets/configure-ctf-challenges.sh
	@$(SCRIPTS_DIR)/targets/setup-ad-environment.sh
	@$(SCRIPTS_DIR)/targets/validate-targets.sh
	@echo "Target practice environments ready"

c2-setup: ## Setup command and control infrastructure
	@echo "Setting up C2 infrastructure..."
	@$(SCRIPTS_DIR)/c2/setup-c2-servers.sh
	@$(SCRIPTS_DIR)/c2/configure-domain-fronting.sh
	@$(SCRIPTS_DIR)/c2/setup-redirectors.sh
	@$(SCRIPTS_DIR)/c2/configure-covert-channels.sh
	@$(SCRIPTS_DIR)/c2/validate-c2-setup.sh
	@echo "C2 infrastructure ready"

monitoring-setup: ## Setup monitoring and logging
	@echo "Setting up monitoring and logging..."
	@$(SCRIPTS_DIR)/monitoring/setup-elk-stack.sh
	@$(SCRIPTS_DIR)/monitoring/configure-redteam-logging.sh
	@$(SCRIPTS_DIR)/monitoring/setup-opsec-monitoring.sh
	@$(SCRIPTS_DIR)/monitoring/configure-alerting.sh
	@echo "Monitoring and logging configured"

# ============================================================================
# DOCKER CONTAINER MANAGEMENT
# ============================================================================

deploy: ## Deploy complete red team lab infrastructure
	@echo "Deploying red team lab infrastructure..."
	@docker network create $(REDTEAM_NETWORK) --driver bridge --subnet 172.30.0.0/16 || true
	@docker network create $(TARGET_NETWORK_NAME) --driver bridge --subnet 172.31.0.0/16 || true
	@docker network create $(C2_NETWORK) --driver bridge --subnet 172.32.0.0/16 || true
	@docker network create $(MONITORING_NETWORK) --driver bridge --subnet 172.33.0.0/16 || true
	@docker network create $(ISOLATION_NETWORK) --driver bridge --subnet 172.34.0.0/16 || true
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) up -d
	@echo "Red team lab infrastructure deployed"

start: ## Start all red team services
	@echo "Starting red team services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) start
	@$(SCRIPTS_DIR)/monitoring/check-services.sh
	@echo "All red team services started"

stop: ## Stop all red team services
	@echo "Stopping red team services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) stop
	@echo "All red team services stopped"

restart: ## Restart all red team services
	@echo "Restarting red team services..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) restart
	@echo "All red team services restarted"

status: ## Check status of all services
	@echo "Checking red team services status..."
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) ps
	@$(SCRIPTS_DIR)/monitoring/service-health-check.sh

logs: ## View logs from all services
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) logs -f --tail=100

shell: ## Access red team command shell
	@docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) exec kali-redteam /bin/bash

# ============================================================================
# RECONNAISSANCE OPERATIONS
# ============================================================================

recon-osint: ## OSINT gathering and target profiling
ifdef HELP
	@echo "OSINT Reconnaissance Options:"
	@echo "  make recon-osint TARGET=company.com DEPTH=deep"
	@echo "  make recon-osint TARGET=individual@company.com TYPE=person"
	@echo "  make recon-osint TARGET=company.com SOURCES=all"
else
	@echo "Starting OSINT reconnaissance for $(TARGET)..."
	@$(SCRIPTS_DIR)/reconnaissance/osint-gather.sh \
		--target=$(TARGET) \
		--depth=$(DEPTH) \
		--output=$(REPORTS_DIR)/reconnaissance/osint-$(TARGET) \
		--sources="theHarvester,shodan,censys,maltego" \
		--anonymize
	@$(SCRIPTS_DIR)/reconnaissance/analyze-osint-results.sh $(TARGET)
	@echo "OSINT reconnaissance completed for $(TARGET)"
endif

recon-network: ## Network discovery and port scanning
ifdef HELP
	@echo "Network Reconnaissance Options:"
	@echo "  make recon-network TARGET=192.168.1.0/24 SCAN=full"
	@echo "  make recon-network TARGET=example.com SCAN=stealth"
	@echo "  make recon-network TARGET=10.0.0.1-254 SCAN=fast"
else
	@echo "Starting network reconnaissance for $(TARGET)..."
	@$(SCRIPTS_DIR)/reconnaissance/network-discovery.sh \
		--target=$(TARGET) \
		--scan-type=$(SCAN) \
		--threads=100 \
		--output=$(REPORTS_DIR)/reconnaissance/network-$(TARGET) \
		--evasion-mode \
		--timing-template=2
	@$(SCRIPTS_DIR)/reconnaissance/service-enumeration.sh $(TARGET)
	@$(SCRIPTS_DIR)/reconnaissance/analyze-network-results.sh $(TARGET)
	@echo "Network reconnaissance completed for $(TARGET)"
endif

recon-web: ## Web application enumeration
ifdef HELP
	@echo "Web Reconnaissance Options:"
	@echo "  make recon-web TARGET=https://example.com DEPTH=deep"
	@echo "  make recon-web TARGET=https://example.com WORDLIST=custom"
else
	@echo "Starting web reconnaissance for $(TARGET)..."
	@$(SCRIPTS_DIR)/reconnaissance/web-enumeration.sh \
		--target=$(TARGET) \
		--depth=$(DEPTH) \
		--wordlist=$(WORDLIST) \
		--output=$(REPORTS_DIR)/reconnaissance/web-$(TARGET) \
		--spider-crawl \
		--directory-bruteforce
	@$(SCRIPTS_DIR)/reconnaissance/technology-detection.sh $(TARGET)
	@$(SCRIPTS_DIR)/reconnaissance/analyze-web-results.sh $(TARGET)
	@echo "Web reconnaissance completed for $(TARGET)"
endif

recon-dns: ## DNS enumeration and zone transfers
ifdef HELP
	@echo "DNS Reconnaissance Options:"
	@echo "  make recon-dns TARGET=example.com TYPE=full"
	@echo "  make recon-dns TARGET=example.com TYPE=subdomain"
else
	@echo "Starting DNS reconnaissance for $(TARGET)..."
	@$(SCRIPTS_DIR)/reconnaissance/dns-enumeration.sh \
		--target=$(TARGET) \
		--type=$(TYPE) \
		--output=$(REPORTS_DIR)/reconnaissance/dns-$(TARGET) \
		--zone-transfer \
		--subdomain-brute
	@$(SCRIPTS_DIR)/reconnaissance/dns-analysis.sh $(TARGET)
	@echo "DNS reconnaissance completed for $(TARGET)"
endif

recon-full: ## Complete reconnaissance workflow
	@echo "Starting complete reconnaissance workflow for $(TARGET)..."
	@make recon-osint TARGET=$(TARGET) DEPTH=deep
	@make recon-network TARGET=$(TARGET) SCAN=full
	@make recon-web TARGET=$(TARGET) DEPTH=deep
	@make recon-dns TARGET=$(TARGET) TYPE=full
	@$(SCRIPTS_DIR)/reconnaissance/correlate-results.sh $(TARGET)
	@$(SCRIPTS_DIR)/reconnaissance/generate-target-profile.sh $(TARGET)
	@echo "Complete reconnaissance workflow completed for $(TARGET)"

# ============================================================================
# EXPLOITATION OPERATIONS
# ============================================================================

exploit-web: ## Web application exploitation
ifdef HELP
	@echo "Web Exploitation Options:"
	@echo "  make exploit-web TARGET=https://example.com TYPE=sqli"
	@echo "  make exploit-web TARGET=https://example.com TYPE=xss"
	@echo "  make exploit-web TARGET=https://example.com TYPE=all"
else
	@echo "Starting web exploitation for $(TARGET)..."
	@$(SCRIPTS_DIR)/exploitation/web-exploit.sh \
		--target=$(TARGET) \
		--exploit-type=$(TYPE) \
		--output=$(REPORTS_DIR)/exploitation/web-$(TARGET) \
		--automated-testing \
		--payload-generation
	@$(SCRIPTS_DIR)/exploitation/validate-web-exploits.sh $(TARGET)
	@echo "Web exploitation completed for $(TARGET)"
endif

exploit-network: ## Network service exploitation
ifdef HELP
	@echo "Network Exploitation Options:"
	@echo "  make exploit-network TARGET=192.168.1.100 SERVICE=smb"
	@echo "  make exploit-network TARGET=10.0.0.50 SERVICE=ssh"
else
	@echo "Starting network exploitation for $(TARGET)..."
	@$(SCRIPTS_DIR)/exploitation/network-exploit.sh \
		--target=$(TARGET) \
		--service=$(SERVICE) \
		--output=$(REPORTS_DIR)/exploitation/network-$(TARGET) \
		--automated-exploit \
		--payload-delivery
	@$(SCRIPTS_DIR)/exploitation/validate-network-exploits.sh $(TARGET)
	@echo "Network exploitation completed for $(TARGET)"
endif

exploit-windows: ## Windows-specific exploitation
ifdef HELP
	@echo "Windows Exploitation Options:"
	@echo "  make exploit-windows TARGET=192.168.1.100 METHOD=eternalblue"
	@echo "  make exploit-windows TARGET=win-server.local METHOD=psexec"
else
	@echo "Starting Windows exploitation for $(TARGET)..."
	@$(SCRIPTS_DIR)/exploitation/windows-exploit.sh \
		--target=$(TARGET) \
		--method=$(METHOD) \
		--output=$(REPORTS_DIR)/exploitation/windows-$(TARGET) \
		--persistence-setup \
		--privilege-escalation
	@$(SCRIPTS_DIR)/exploitation/validate-windows-exploits.sh $(TARGET)
	@echo "Windows exploitation completed for $(TARGET)"
endif

exploit-linux: ## Linux-specific exploitation
ifdef HELP
	@echo "Linux Exploitation Options:"
	@echo "  make exploit-linux TARGET=192.168.1.101 METHOD=shellshock"
	@echo "  make exploit-linux TARGET=linux-server.local METHOD=dirtycow"
else
	@echo "Starting Linux exploitation for $(TARGET)..."
	@$(SCRIPTS_DIR)/exploitation/linux-exploit.sh \
		--target=$(TARGET) \
		--method=$(METHOD) \
		--output=$(REPORTS_DIR)/exploitation/linux-$(TARGET) \
		--persistence-setup \
		--privilege-escalation
	@$(SCRIPTS_DIR)/exploitation/validate-linux-exploits.sh $(TARGET)
	@echo "Linux exploitation completed for $(TARGET)"
endif

exploit-auto: ## Automated exploitation workflow
	@echo "Starting automated exploitation workflow for $(TARGET_NETWORK)..."
	@$(SCRIPTS_DIR)/exploitation/auto-exploit.sh \
		--target=$(TARGET_NETWORK) \
		--exploits="all" \
		--output=$(REPORTS_DIR)/exploitation/auto-$(TARGET_NETWORK) \
		--aggressive-mode \
		--post-exploitation
	@$(SCRIPTS_DIR)/exploitation/correlate-exploits.sh $(TARGET_NETWORK)
	@echo "Automated exploitation workflow completed"

# ============================================================================
# POST-EXPLOITATION OPERATIONS
# ============================================================================

postexploit-persistence: ## Establish persistence mechanisms
ifdef HELP
	@echo "Persistence Options:"
	@echo "  make postexploit-persistence SESSION=shell_1 TYPE=registry"
	@echo "  make postexploit-persistence SESSION=meterpreter_1 TYPE=service"
else
	@echo "Establishing persistence for session $(SESSION)..."
	@$(SCRIPTS_DIR)/post-exploitation/establish-persistence.sh \
		--session=$(SESSION) \
		--type=$(TYPE) \
		--stealth-mode \
		--backup-mechanisms
	@$(SCRIPTS_DIR)/post-exploitation/validate-persistence.sh $(SESSION)
	@echo "Persistence established for session $(SESSION)"
endif

postexploit-privesc: ## Privilege escalation techniques
ifdef HELP
	@echo "Privilege Escalation Options:"
	@echo "  make postexploit-privesc SESSION=shell_1 OS=windows"
	@echo "  make postexploit-privesc SESSION=shell_2 OS=linux"
else
	@echo "Starting privilege escalation for session $(SESSION)..."
	@$(SCRIPTS_DIR)/post-exploitation/privilege-escalation.sh \
		--session=$(SESSION) \
		--os=$(OS) \
		--automated-enumeration \
		--exploit-suggestions
	@$(SCRIPTS_DIR)/post-exploitation/validate-privesc.sh $(SESSION)
	@echo "Privilege escalation completed for session $(SESSION)"
endif

postexploit-lateral: ## Lateral movement and pivoting
ifdef HELP
	@echo "Lateral Movement Options:"
	@echo "  make postexploit-lateral SESSION=shell_1 TARGET=192.168.1.50"
	@echo "  make postexploit-lateral SESSION=beacon_1 METHOD=psexec"
else
	@echo "Starting lateral movement from session $(SESSION)..."
	@$(SCRIPTS_DIR)/post-exploitation/lateral-movement.sh \
		--session=$(SESSION) \
		--target=$(TARGET) \
		--method=$(METHOD) \
		--credential-reuse \
		--network-pivoting
	@$(SCRIPTS_DIR)/post-exploitation/validate-lateral-movement.sh $(SESSION)
	@echo "Lateral movement completed for session $(SESSION)"
endif

postexploit-exfil: ## Data exfiltration methods
ifdef HELP
	@echo "Data Exfiltration Options:"
	@echo "  make postexploit-exfil SESSION=shell_1 DATA=/path/to/data"
	@echo "  make postexploit-exfil SESSION=beacon_1 METHOD=dns"
else
	@echo "Starting data exfiltration for session $(SESSION)..."
	@$(SCRIPTS_DIR)/post-exploitation/data-exfiltration.sh \
		--session=$(SESSION) \
		--data=$(DATA) \
		--method=$(METHOD) \
		--stealth-mode \
		--encryption
	@$(SCRIPTS_DIR)/post-exploitation/validate-exfiltration.sh $(SESSION)
	@echo "Data exfiltration completed for session $(SESSION)"
endif

# ============================================================================
# COMMAND & CONTROL OPERATIONS
# ============================================================================

c2-deploy: ## Deploy C2 infrastructure
	@echo "Deploying C2 infrastructure..."
	@$(SCRIPTS_DIR)/c2/deploy-c2-servers.sh
	@$(SCRIPTS_DIR)/c2/setup-domain-fronting.sh
	@$(SCRIPTS_DIR)/c2/configure-redirectors.sh
	@$(SCRIPTS_DIR)/c2/validate-c2-deployment.sh
	@echo "C2 infrastructure deployed"

c2-listeners: ## Start C2 listeners
ifdef HELP
	@echo "C2 Listener Options:"
	@echo "  make c2-listeners PROTOCOL=https PORT=443"
	@echo "  make c2-listeners PROTOCOL=dns DOMAIN=evil.com"
else
	@echo "Starting C2 listeners..."
	@$(SCRIPTS_DIR)/c2/start-listeners.sh \
		--protocol=$(PROTOCOL) \
		--port=$(PORT) \
		--domain=$(DOMAIN) \
		--ssl-certificate \
		--traffic-obfuscation
	@$(SCRIPTS_DIR)/c2/validate-listeners.sh
	@echo "C2 listeners started"
endif

c2-agents: ## Manage C2 agents and beacons
ifdef HELP
	@echo "C2 Agent Management Options:"
	@echo "  make c2-agents ACTION=list"
	@echo "  make c2-agents ACTION=interact AGENT=beacon_1"
else
	@echo "Managing C2 agents..."
	@$(SCRIPTS_DIR)/c2/manage-agents.sh \
		--action=$(ACTION) \
		--agent=$(AGENT) \
		--interactive-mode
	@echo "C2 agent management completed"
endif

c2-cleanup: ## Cleanup C2 infrastructure
	@echo "Cleaning up C2 infrastructure..."
	@$(SCRIPTS_DIR)/c2/cleanup-agents.sh
	@$(SCRIPTS_DIR)/c2/remove-persistence.sh
	@$(SCRIPTS_DIR)/c2/cleanup-redirectors.sh
	@$(SCRIPTS_DIR)/c2/validate-cleanup.sh
	@echo "C2 infrastructure cleaned up"

c2-monitor: ## Monitor C2 activity
	@echo "Monitoring C2 activity..."
	@$(SCRIPTS_DIR)/c2/monitor-activity.sh \
		--real-time \
		--log-analysis \
		--alert-on-detection
	@echo "C2 monitoring active"

# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

payload-windows: ## Generate Windows payloads
ifdef HELP
	@echo "Windows Payload Options:"
	@echo "  make payload-windows TYPE=meterpreter LHOST=10.0.0.5"
	@echo "  make payload-windows TYPE=beacon LHOST=c2.evil.com"
else
	@echo "Generating Windows payload..."
	@$(SCRIPTS_DIR)/payloads/generate-windows-payload.sh \
		--type=$(TYPE) \
		--lhost=$(LHOST) \
		--lport=$(LPORT) \
		--format=$(FORMAT) \
		--evasion-techniques \
		--encryption
	@echo "Windows payload generated"
endif

payload-linux: ## Generate Linux payloads
ifdef HELP
	@echo "Linux Payload Options:"
	@echo "  make payload-linux TYPE=reverse_shell LHOST=10.0.0.5"
	@echo "  make payload-linux TYPE=bind_shell LPORT=4444"
else
	@echo "Generating Linux payload..."
	@$(SCRIPTS_DIR)/payloads/generate-linux-payload.sh \
		--type=$(TYPE) \
		--lhost=$(LHOST) \
		--lport=$(LPORT) \
		--format=$(FORMAT) \
		--stealth-mode
	@echo "Linux payload generated"
endif

payload-web: ## Generate web payloads
ifdef HELP
	@echo "Web Payload Options:"
	@echo "  make payload-web TYPE=webshell LANGUAGE=php"
	@echo "  make payload-web TYPE=xss PAYLOAD=custom"
else
	@echo "Generating web payload..."
	@$(SCRIPTS_DIR)/payloads/generate-web-payload.sh \
		--type=$(TYPE) \
		--language=$(LANGUAGE) \
		--payload=$(PAYLOAD) \
		--obfuscation
	@echo "Web payload generated"
endif

payload-mobile: ## Generate mobile payloads
ifdef HELP
	@echo "Mobile Payload Options:"
	@echo "  make payload-mobile PLATFORM=android TYPE=meterpreter"
	@echo "  make payload-mobile PLATFORM=ios TYPE=agent"
else
	@echo "Generating mobile payload..."
	@$(SCRIPTS_DIR)/payloads/generate-mobile-payload.sh \
		--platform=$(PLATFORM) \
		--type=$(TYPE) \
		--lhost=$(LHOST) \
		--stealth-features
	@echo "Mobile payload generated"
endif

payload-custom: ## Generate custom payloads
ifdef HELP
	@echo "Custom Payload Options:"
	@echo "  make payload-custom TEMPLATE=custom.template"
	@echo "  make payload-custom LANGUAGE=python TYPE=backdoor"
else
	@echo "Generating custom payload..."
	@$(SCRIPTS_DIR)/payloads/generate-custom-payload.sh \
		--template=$(TEMPLATE) \
		--language=$(LANGUAGE) \
		--type=$(TYPE) \
		--advanced-features
	@echo "Custom payload generated"
endif

# ============================================================================
# CAMPAIGN MANAGEMENT
# ============================================================================

campaign-start: ## Start new red team campaign
ifdef HELP
	@echo "Campaign Start Options:"
	@echo "  make campaign-start NAME=operation_red_dawn TARGET=corp.com"
	@echo "  make campaign-start NAME=pentest_2024 TARGET=192.168.1.0/24"
else
	@echo "Starting new red team campaign $(NAME)..."
	@$(SCRIPTS_DIR)/campaigns/create-campaign.sh \
		--name=$(NAME) \
		--target=$(TARGET) \
		--team-size=$(TEAM_SIZE) \
		--duration=$(DURATION) \
		--objectives="$(OBJECTIVES)"
	@$(SCRIPTS_DIR)/campaigns/setup-campaign-infrastructure.sh $(NAME)
	@$(SCRIPTS_DIR)/campaigns/initialize-roe.sh $(NAME)
	@echo "Campaign $(NAME) started successfully"
endif

campaign-execute: ## Execute campaign phases
ifdef HELP
	@echo "Campaign Execution Options:"
	@echo "  make campaign-execute CAMPAIGN=red_dawn PHASE=initial_access"
	@echo "  make campaign-execute CAMPAIGN=red_dawn PHASE=persistence"
else
	@echo "Executing campaign phase $(PHASE) for $(CAMPAIGN)..."
	@$(SCRIPTS_DIR)/campaigns/execute-phase.sh \
		--campaign=$(CAMPAIGN) \
		--phase=$(PHASE) \
		--automated-execution \
		--real-time-monitoring
	@$(SCRIPTS_DIR)/campaigns/validate-phase-completion.sh $(CAMPAIGN) $(PHASE)
	@echo "Campaign phase $(PHASE) executed for $(CAMPAIGN)"
endif

campaign-monitor: ## Monitor campaign progress
	@echo "Monitoring campaign progress for $(CAMPAIGN)..."
	@$(SCRIPTS_DIR)/campaigns/monitor-campaign.sh \
		--campaign=$(CAMPAIGN) \
		--real-time-dashboard \
		--team-collaboration \
		--opsec-monitoring
	@echo "Campaign monitoring active for $(CAMPAIGN)"

campaign-report: ## Generate campaign reports
ifdef HELP
	@echo "Campaign Reporting Options:"
	@echo "  make campaign-report CAMPAIGN=red_dawn FORMAT=executive"
	@echo "  make campaign-report CAMPAIGN=red_dawn FORMAT=technical"
else
	@echo "Generating campaign report for $(CAMPAIGN)..."
	@$(SCRIPTS_DIR)/campaigns/generate-report.sh \
		--campaign=$(CAMPAIGN) \
		--format=$(FORMAT) \
		--output=$(REPORTS_DIR)/campaigns/$(CAMPAIGN) \
		--include-evidence \
		--mitre-mapping
	@$(SCRIPTS_DIR)/campaigns/validate-report.sh $(CAMPAIGN)
	@echo "Campaign report generated for $(CAMPAIGN)"
endif

campaign-cleanup: ## Cleanup campaign artifacts
	@echo "Cleaning up campaign $(CAMPAIGN)..."
	@$(SCRIPTS_DIR)/campaigns/cleanup-campaign.sh \
		--campaign=$(CAMPAIGN) \
		--remove-persistence \
		--cleanup-infrastructure \
		--secure-deletion
	@$(SCRIPTS_DIR)/campaigns/archive-campaign.sh $(CAMPAIGN)
	@$(SCRIPTS_DIR)/campaigns/lessons-learned.sh $(CAMPAIGN)
	@echo "Campaign $(CAMPAIGN) cleanup completed"

# ============================================================================
# OPERATIONAL SECURITY (OPSEC)
# ============================================================================

opsec-check: ## Check operational security
	@echo "Checking operational security..."
	@$(SCRIPTS_DIR)/opsec/check-attribution.sh
	@$(SCRIPTS_DIR)/opsec/validate-traffic-obfuscation.sh
	@$(SCRIPTS_DIR)/opsec/check-log-anonymization.sh
	@$(SCRIPTS_DIR)/opsec/validate-infrastructure-opsec.sh
	@echo "OPSEC check completed"

opsec-monitor: ## Monitor OPSEC indicators
	@echo "Monitoring OPSEC indicators..."
	@$(SCRIPTS_DIR)/opsec/monitor-indicators.sh \
		--real-time-alerting \
		--threat-intelligence \
		--attribution-analysis
	@echo "OPSEC monitoring active"

opsec-cleanup: ## Clean OPSEC artifacts
	@echo "Cleaning OPSEC artifacts..."
	@$(SCRIPTS_DIR)/opsec/cleanup-artifacts.sh \
		--secure-deletion \
		--log-sanitization \
		--metadata-removal
	@echo "OPSEC artifacts cleaned"

opsec-validate: ## Validate OPSEC measures
	@echo "Validating OPSEC measures..."
	@$(SCRIPTS_DIR)/opsec/validate-opsec.sh \
		--comprehensive-check \
		--blue-team-perspective \
		--detection-testing
	@echo "OPSEC validation completed"

# ============================================================================
# EVASION TECHNIQUES
# ============================================================================

evasion-av: ## AV evasion techniques
ifdef HELP
	@echo "AV Evasion Options:"
	@echo "  make evasion-av PAYLOAD=payload.exe METHOD=encryption"
	@echo "  make evasion-av PAYLOAD=shell.ps1 METHOD=obfuscation"
else
	@echo "Applying AV evasion to $(PAYLOAD)..."
	@$(SCRIPTS_DIR)/evasion/av-evasion.sh \
		--payload=$(PAYLOAD) \
		--method=$(METHOD) \
		--testing-enabled \
		--multiple-engines
	@echo "AV evasion applied to $(PAYLOAD)"
endif

evasion-edr: ## EDR evasion techniques
ifdef HELP
	@echo "EDR Evasion Options:"
	@echo "  make evasion-edr TECHNIQUE=process_hollowing"
	@echo "  make evasion-edr TECHNIQUE=dll_sideloading"
else
	@echo "Applying EDR evasion technique $(TECHNIQUE)..."
	@$(SCRIPTS_DIR)/evasion/edr-evasion.sh \
		--technique=$(TECHNIQUE) \
		--advanced-methods \
		--behavior-masking
	@echo "EDR evasion technique $(TECHNIQUE) applied"
endif

evasion-network: ## Network evasion techniques
	@echo "Applying network evasion techniques..."
	@$(SCRIPTS_DIR)/evasion/network-evasion.sh \
		--traffic-obfuscation \
		--protocol-tunneling \
		--timing-randomization
	@echo "Network evasion techniques applied"

evasion-attribution: ## Attribution avoidance techniques
	@echo "Applying attribution avoidance techniques..."
	@$(SCRIPTS_DIR)/evasion/attribution-avoidance.sh \
		--infrastructure-rotation \
		--ttp-variation \
		--false-flag-indicators
	@echo "Attribution avoidance techniques applied"

# ============================================================================
# VULNERABILITY ASSESSMENT
# ============================================================================

vuln-scan: ## Automated vulnerability scanning
ifdef HELP
	@echo "Vulnerability Scanning Options:"
	@echo "  make vuln-scan TARGET=192.168.1.0/24 TYPE=network"
	@echo "  make vuln-scan TARGET=https://example.com TYPE=web"
else
	@echo "Starting vulnerability scan for $(TARGET)..."
	@$(SCRIPTS_DIR)/vulnerability/vuln-scan.sh \
		--target=$(TARGET) \
		--type=$(TYPE) \
		--comprehensive-scan \
		--output=$(REPORTS_DIR)/vulnerability/scan-$(TARGET)
	@$(SCRIPTS_DIR)/vulnerability/analyze-results.sh $(TARGET)
	@echo "Vulnerability scan completed for $(TARGET)"
endif

vuln-assess: ## Vulnerability assessment and prioritization
	@echo "Performing vulnerability assessment..."
	@$(SCRIPTS_DIR)/vulnerability/assess-vulnerabilities.sh \
		--input=$(SCAN_RESULTS) \
		--risk-scoring \
		--business-impact \
		--exploit-availability
	@echo "Vulnerability assessment completed"

vuln-exploit: ## Exploit identified vulnerabilities
ifdef HELP
	@echo "Vulnerability Exploitation Options:"
	@echo "  make vuln-exploit TARGET=192.168.1.100 CVE=CVE-2024-1234"
	@echo "  make vuln-exploit TARGET=app.example.com VULN=sqli"
else
	@echo "Exploiting vulnerability $(VULN) on $(TARGET)..."
	@$(SCRIPTS_DIR)/vulnerability/exploit-vulnerability.sh \
		--target=$(TARGET) \
		--vulnerability=$(VULN) \
		--automated-exploitation \
		--post-exploitation
	@echo "Vulnerability exploitation completed"
endif

vuln-report: ## Generate vulnerability report
	@echo "Generating vulnerability report..."
	@$(SCRIPTS_DIR)/vulnerability/generate-report.sh \
		--input=$(VULN_DATA) \
		--format=comprehensive \
		--executive-summary \
		--technical-details \
		--remediation-guidance
	@echo "Vulnerability report generated"

# ============================================================================
# SOCIAL ENGINEERING
# ============================================================================

social-phishing: ## Phishing campaign management
ifdef HELP
	@echo "Phishing Campaign Options:"
	@echo "  make social-phishing CAMPAIGN=exec_phish TARGET=executives.list"
	@echo "  make social-phishing CAMPAIGN=bulk_phish TARGET=employees.csv"
else
	@echo "Starting phishing campaign $(CAMPAIGN)..."
	@$(SCRIPTS_DIR)/social-engineering/phishing-campaign.sh \
		--campaign=$(CAMPAIGN) \
		--targets=$(TARGET) \
		--template=$(TEMPLATE) \
		--tracking-enabled \
		--credential-harvesting
	@echo "Phishing campaign $(CAMPAIGN) started"
endif

social-vishing: ## Voice phishing (vishing) operations
ifdef HELP
	@echo "Vishing Options:"
	@echo "  make social-vishing TARGET=+1234567890 PRETEXT=it_support"
	@echo "  make social-vishing CAMPAIGN=help_desk TARGETS=phone_list.txt"
else
	@echo "Starting vishing operation..."
	@$(SCRIPTS_DIR)/social-engineering/vishing-operation.sh \
		--target=$(TARGET) \
		--pretext=$(PRETEXT) \
		--call-recording \
		--information-gathering
	@echo "Vishing operation completed"
endif

social-pretexting: ## Physical pretexting scenarios
ifdef HELP
	@echo "Pretexting Options:"
	@echo "  make social-pretexting SCENARIO=delivery LOCATION=office_lobby"
	@echo "  make social-pretexting SCENARIO=it_support DEPARTMENT=accounting"
else
	@echo "Executing pretexting scenario $(SCENARIO)..."
	@$(SCRIPTS_DIR)/social-engineering/pretexting-scenario.sh \
		--scenario=$(SCENARIO) \
		--location=$(LOCATION) \
		--documentation \
		--evidence-collection
	@echo "Pretexting scenario $(SCENARIO) executed"
endif

social-osint: ## Social media intelligence gathering
ifdef HELP
	@echo "Social OSINT Options:"
	@echo "  make social-osint TARGET=john.doe@company.com"
	@echo "  make social-osint TARGET=@company_official PLATFORM=twitter"
else
	@echo "Gathering social media intelligence for $(TARGET)..."
	@$(SCRIPTS_DIR)/social-engineering/social-osint.sh \
		--target=$(TARGET) \
		--platforms="linkedin,twitter,facebook,instagram" \
		--deep-analysis \
		--relationship-mapping
	@echo "Social media intelligence gathering completed"
endif

# ============================================================================
# TRAINING AND CERTIFICATION
# ============================================================================

training-setup: ## Setup training environments
	@echo "Setting up training environments..."
	@$(SCRIPTS_DIR)/training/setup-training-lab.sh
	@$(SCRIPTS_DIR)/training/deploy-practice-targets.sh
	@$(SCRIPTS_DIR)/training/configure-challenge-environments.sh
	@echo "Training environments ready"

training-scenarios: ## Execute training scenarios
ifdef HELP
	@echo "Training Scenario Options:"
	@echo "  make training-scenarios SCENARIO=web_exploitation LEVEL=beginner"
	@echo "  make training-scenarios SCENARIO=red_team_ops LEVEL=advanced"
else
	@echo "Executing training scenario $(SCENARIO)..."
	@$(SCRIPTS_DIR)/training/run-scenario.sh \
		--scenario=$(SCENARIO) \
		--level=$(LEVEL) \
		--student="$(STUDENT)" \
		--guided-mode
	@$(SCRIPTS_DIR)/training/evaluate-performance.sh $(SCENARIO) $(STUDENT)
	@echo "Training scenario $(SCENARIO) completed"
endif

training-ctf: ## Capture The Flag challenges
ifdef HELP
	@echo "CTF Challenge Options:"
	@echo "  make training-ctf CATEGORY=web DIFFICULTY=medium"
	@echo "  make training-ctf CATEGORY=binary DIFFICULTY=hard"
else
	@echo "Starting CTF challenge..."
	@$(SCRIPTS_DIR)/training/ctf-challenge.sh \
		--category=$(CATEGORY) \
		--difficulty=$(DIFFICULTY) \
		--time-limit=$(TIME_LIMIT) \
		--hints-available
	@echo "CTF challenge started"
endif

training-validate: ## Validate training completion
	@echo "Validating training completion for $(STUDENT)..."
	@$(SCRIPTS_DIR)/training/validate-competency.sh \
		--student="$(STUDENT)" \
		--certification=$(CERT_TYPE) \
		--practical-assessment \
		--theory-examination
	@$(SCRIPTS_DIR)/training/generate-certificate.sh $(STUDENT)
	@echo "Training validation completed"

# ============================================================================
# REPORTING AND ANALYTICS
# ============================================================================

report-generate: ## Generate comprehensive reports
ifdef HELP
	@echo "Report Generation Options:"
	@echo "  make report-generate CAMPAIGN=red_dawn TYPE=comprehensive"
	@echo "  make report-generate SESSION=pentest_2024 TYPE=executive"
else
	@echo "Generating $(TYPE) report..."
	@$(SCRIPTS_DIR)/reporting/generate-report.sh \
		--campaign=$(CAMPAIGN) \
		--session=$(SESSION) \
		--type=$(TYPE) \
		--output=$(REPORTS_DIR)/$(TYPE) \
		--include-evidence \
		--mitre-mapping
	@echo "$(TYPE) report generated"
endif

report-executive: ## Generate executive summary report
	@echo "Generating executive summary report..."
	@$(SCRIPTS_DIR)/reporting/executive-report.sh \
		--campaign=$(CAMPAIGN) \
		--business-risk-focus \
		--roi-analysis \
		--recommendations \
		--output=$(REPORTS_DIR)/executive
	@echo "Executive summary report generated"

report-technical: ## Generate technical report
	@echo "Generating technical report..."
	@$(SCRIPTS_DIR)/reporting/technical-report.sh \
		--campaign=$(CAMPAIGN) \
		--detailed-findings \
		--proof-of-concept \
		--remediation-steps \
		--output=$(REPORTS_DIR)/technical
	@echo "Technical report generated"

report-compliance: ## Generate compliance report
	@echo "Generating compliance report..."
	@$(SCRIPTS_DIR)/reporting/compliance-report.sh \
		--standards="$(STANDARDS)" \
		--assessment-results \
		--gap-analysis \
		--remediation-plan \
		--output=$(REPORTS_DIR)/compliance
	@echo "Compliance report generated"

# ============================================================================
# BACKUP AND RECOVERY
# ============================================================================

backup: ## Backup campaign data and configurations
	@echo "Starting backup of campaign data..."
	@$(SCRIPTS_DIR)/backup/backup-campaigns.sh \
		--destination=$(BACKUP_DIR) \
		--encryption \
		--compression \
		--verification
	@$(SCRIPTS_DIR)/backup/backup-tools.sh
	@$(SCRIPTS_DIR)/backup/backup-configurations.sh
	@$(SCRIPTS_DIR)/backup/validate-backups.sh
	@echo "Backup completed successfully"

restore: ## Restore from backup
ifdef HELP
	@echo "Restore Options:"
	@echo "  make restore TYPE=campaign CAMPAIGN=red_dawn"
	@echo "  make restore TYPE=full TIMESTAMP=2024-01-28"
else
	@echo "Starting restore operation..."
	@$(SCRIPTS_DIR)/backup/restore-data.sh \
		--type=$(TYPE) \
		--campaign=$(CAMPAIGN) \
		--timestamp=$(TIMESTAMP) \
		--verify-integrity
	@$(SCRIPTS_DIR)/backup/validate-restore.sh
	@echo "Restore operation completed"
endif

# ============================================================================
# CLEANUP AND MAINTENANCE
# ============================================================================

clean: ## Clean temporary files and logs
	@echo "Cleaning temporary files and logs..."
	@find $(LOGS_DIR) -name "*.log" -mtime +30 -delete
	@find $(BASE_DIR) -name "*.tmp" -delete
	@find $(BASE_DIR) -name "*.temp" -delete
	@$(SCRIPTS_DIR)/maintenance/secure-delete-artifacts.sh
	@docker system prune -f
	@echo "Cleanup completed"

maintenance: ## Perform system maintenance tasks
	@echo "Performing system maintenance..."
	@$(SCRIPTS_DIR)/maintenance/update-tools.sh
	@$(SCRIPTS_DIR)/maintenance/rotate-logs.sh
	@$(SCRIPTS_DIR)/maintenance/cleanup-old-campaigns.sh
	@$(SCRIPTS_DIR)/maintenance/validate-infrastructure.sh
	@$(SCRIPTS_DIR)/maintenance/generate-maintenance-report.sh
	@echo "System maintenance completed"

# ============================================================================
# HELP TARGETS FOR SPECIFIC CATEGORIES
# ============================================================================

help-recon: ## Show reconnaissance help
	@echo "============================================================================"
	@echo "RECONNAISSANCE HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Available reconnaissance commands:"
	@echo ""
	@echo "recon-osint TARGET=<domain/email> [DEPTH=<shallow|deep>]"
	@echo "  OSINT gathering using multiple sources"
	@echo ""
	@echo "recon-network TARGET=<ip/range> [SCAN=<fast|full|stealth>]"
	@echo "  Network discovery and port scanning"
	@echo ""
	@echo "recon-web TARGET=<url> [DEPTH=<shallow|deep>]"
	@echo "  Web application enumeration and technology detection"
	@echo ""
	@echo "recon-dns TARGET=<domain> [TYPE=<full|subdomain|zone>]"
	@echo "  DNS enumeration and zone transfer attempts"
	@echo ""
	@echo "============================================================================"

help-exploit: ## Show exploitation help
	@echo "============================================================================"
	@echo "EXPLOITATION HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Available exploitation commands:"
	@echo ""
	@echo "exploit-web TARGET=<url> [TYPE=<sqli|xss|csrf|all>]"
	@echo "  Web application exploitation and testing"
	@echo ""
	@echo "exploit-network TARGET=<ip> [SERVICE=<smb|ssh|rdp|ftp>]"
	@echo "  Network service exploitation"
	@echo ""
	@echo "exploit-windows TARGET=<ip> [METHOD=<eternalblue|psexec>]"
	@echo "  Windows-specific exploitation techniques"
	@echo ""
	@echo "exploit-linux TARGET=<ip> [METHOD=<shellshock|dirtycow>]"
	@echo "  Linux-specific exploitation techniques"
	@echo ""
	@echo "============================================================================"

help-campaign: ## Show campaign management help
	@echo "============================================================================"
	@echo "CAMPAIGN MANAGEMENT HELP"
	@echo "============================================================================"
	@echo ""
	@echo "Campaign Management Workflow:"
	@echo ""
	@echo "1. campaign-start NAME=<campaign> TARGET=<target>"
	@echo "   Initialize new red team campaign"
	@echo ""
	@echo "2. campaign-execute CAMPAIGN=<name> PHASE=<phase>"
	@echo "   Execute specific campaign phases"
	@echo ""
	@echo "3. campaign-monitor CAMPAIGN=<name>"
	@echo "   Monitor campaign progress and team activity"
	@echo ""
	@echo "4. campaign-report CAMPAIGN=<name> FORMAT=<executive|technical>"
	@echo "   Generate comprehensive campaign reports"
	@echo ""
	@echo "5. campaign-cleanup CAMPAIGN=<name>"
	@echo "   Cleanup campaign artifacts and infrastructure"
	@echo ""
	@echo "============================================================================"

# ============================================================================
# DEFAULT TARGET
# ============================================================================

.DEFAULT_GOAL := help

# ============================================================================
# END OF MAKEFILE
# ============================================================================