# Penetration Testing Framework - Advanced Makefile
# Project 12: Comprehensive penetration testing automation and lab management
# Version: 1.0.0

# Project Configuration
PROJECT_NAME := penetration-testing-framework
PROJECT_VERSION := 1.0.0
BUILD_DATE := $(shell date +"%Y-%m-%d")
BUILD_TIME := $(shell date +"%H:%M:%S")

# Directory Structure
PROJECT_ROOT := $(shell pwd)
SCRIPTS_DIR := $(PROJECT_ROOT)/scripts
TOOLS_DIR := $(PROJECT_ROOT)/tools
CONFIGS_DIR := $(PROJECT_ROOT)/configs
REPORTS_DIR := $(PROJECT_ROOT)/reports
EVIDENCE_DIR := $(PROJECT_ROOT)/evidence
LAB_DIR := $(PROJECT_ROOT)/lab
DOCS_DIR := $(PROJECT_ROOT)/docs

# Docker Configuration
DOCKER_COMPOSE := docker-compose
DOCKER_NETWORK := pentest-network
DOCKER_PROJECT := pentest-lab

# Target Configuration (can be overridden via command line)
TARGET ?= 192.168.1.10
TARGET_URL ?= http://localhost
TARGET_RANGE ?= 192.168.1.0/24
SCAN_PORTS ?= 1-65535
SCAN_THREADS ?= 50

# Testing Configuration
TEST_TYPE ?= comprehensive
FRAMEWORK ?= owasp-top10
OUTPUT_FORMAT ?= json
REPORT_TYPE ?= technical
SESSION_ID ?= pentest-$(shell date +"%Y%m%d-%H%M%S")

# Python and Virtual Environment
PYTHON := python3
VENV_DIR := venv
PIP := $(VENV_DIR)/bin/pip
PYTHON_VENV := $(VENV_DIR)/bin/python

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Help target (default)
.PHONY: help
help:
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE) Penetration Testing Framework v$(PROJECT_VERSION)$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@echo "$(GREEN)Installation & Setup:$(NC)"
	@echo "  make install              Install all dependencies and setup environment"
	@echo "  make install-tools        Install penetration testing tools"
	@echo "  make install-python       Install Python dependencies"
	@echo "  make setup-environment    Configure testing environment"
	@echo "  make clean-install        Clean installation and reinstall"
	@echo ""
	@echo "$(GREEN)Lab Environment:$(NC)"
	@echo "  make lab-deploy           Deploy complete penetration testing lab"
	@echo "  make lab-start            Start lab environment services"
	@echo "  make lab-stop             Stop lab environment services"
	@echo "  make lab-restart          Restart lab environment"
	@echo "  make lab-status           Show lab environment status"
	@echo "  make lab-logs             Show lab environment logs"
	@echo "  make lab-cleanup          Clean up lab environment"
	@echo ""
	@echo "$(GREEN)Penetration Testing:$(NC)"
	@echo "  make pentest-full         Run comprehensive penetration test"
	@echo "  make pentest-web          Web application penetration test"
	@echo "  make pentest-network      Network penetration test"
	@echo "  make pentest-wireless     Wireless penetration test"
	@echo "  make pentest-mobile       Mobile application penetration test"
	@echo "  make pentest-custom       Custom penetration test with parameters"
	@echo ""
	@echo "$(GREEN)Reconnaissance:$(NC)"
	@echo "  make recon-passive        Passive reconnaissance and OSINT"
	@echo "  make recon-active         Active reconnaissance and scanning"
	@echo "  make recon-network        Network discovery and enumeration"
	@echo "  make recon-web            Web application reconnaissance"
	@echo "  make recon-social         Social engineering intelligence"
	@echo ""
	@echo "$(GREEN)Vulnerability Assessment:$(NC)"
	@echo "  make vuln-scan            Automated vulnerability scanning"
	@echo "  make vuln-web             Web application vulnerability testing"
	@echo "  make vuln-network         Network vulnerability assessment"
	@echo "  make vuln-database        Database security assessment"
	@echo "  make vuln-custom          Custom vulnerability testing"
	@echo ""
	@echo "$(GREEN)Exploitation:$(NC)"
	@echo "  make exploit-auto         Automated exploitation"
	@echo "  make exploit-manual       Manual exploitation framework"
	@echo "  make exploit-build        Build custom exploits"
	@echo "  make payload-generate     Generate payloads"
	@echo "  make payload-encode       Encode payloads for evasion"
	@echo ""
	@echo "$(GREEN)Post-Exploitation:$(NC)"
	@echo "  make post-exploit         Post-exploitation automation"
	@echo "  make privilege-escalation Privilege escalation testing"
	@echo "  make lateral-movement     Lateral movement simulation"
	@echo "  make persistence          Persistence mechanism testing"
	@echo "  make data-exfiltration    Data exfiltration simulation"
	@echo ""
	@echo "$(GREEN)Framework Testing:$(NC)"
	@echo "  make owasp-test           OWASP Top 10 testing"
	@echo "  make ptes-test            PTES methodology testing"
	@echo "  make nist-test            NIST SP 800-115 testing"
	@echo "  make compliance-test      Compliance framework testing"
	@echo ""
	@echo "$(GREEN)Reporting & Evidence:$(NC)"
	@echo "  make report-generate      Generate penetration test report"
	@echo "  make report-executive     Generate executive summary"
	@echo "  make report-technical     Generate technical report"
	@echo "  make report-compliance    Generate compliance report"
	@echo "  make evidence-collect     Collect and organize evidence"
	@echo "  make evidence-archive     Archive evidence securely"
	@echo ""
	@echo "$(GREEN)Monitoring & Analysis:$(NC)"
	@echo "  make monitor-start        Start monitoring services"
	@echo "  make monitor-stop         Stop monitoring services"
	@echo "  make logs-analyze         Analyze testing logs"
	@echo "  make traffic-analyze      Network traffic analysis"
	@echo ""
	@echo "$(GREEN)Maintenance & Health:$(NC)"
	@echo "  make health-check         Run system health check"
	@echo "  make security-check       Security validation of framework"
	@echo "  make update-tools         Update penetration testing tools"
	@echo "  make backup-create        Create system backup"
	@echo "  make backup-restore       Restore from backup"
	@echo ""
	@echo "$(GREEN)Usage Examples:$(NC)"
	@echo "  make pentest-full TARGET=192.168.1.10"
	@echo "  make pentest-web TARGET_URL=https://example.com"
	@echo "  make vuln-scan TARGET_RANGE=192.168.1.0/24"
	@echo "  make report-generate SESSION_ID=pentest-20240128"
	@echo ""
	@echo "$(YELLOW)Variables:$(NC)"
	@echo "  TARGET=IP_ADDRESS         Target IP address (default: $(TARGET))"
	@echo "  TARGET_URL=URL           Target URL (default: $(TARGET_URL))"
	@echo "  TARGET_RANGE=CIDR        Target IP range (default: $(TARGET_RANGE))"
	@echo "  SESSION_ID=ID            Testing session ID (default: auto-generated)"
	@echo "  FRAMEWORK=TYPE           Testing framework (default: $(FRAMEWORK))"
	@echo "  REPORT_TYPE=TYPE         Report type (default: $(REPORT_TYPE))"

# ===================================
# INSTALLATION & SETUP
# ===================================

.PHONY: install install-tools install-python setup-environment clean-install

install: install-python install-tools setup-environment
	@echo "$(GREEN)✓ Installation completed successfully$(NC)"
	@echo "$(YELLOW)Next steps: Run 'make lab-deploy' to setup lab environment$(NC)"

install-python:
	@echo "$(BLUE)Installing Python dependencies...$(NC)"
	@$(PYTHON) -m venv $(VENV_DIR)
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Python dependencies installed$(NC)"

install-tools:
	@echo "$(BLUE)Installing penetration testing tools...$(NC)"
	@sudo apt-get update && sudo apt-get install -y \
		nmap masscan gobuster nikto sqlmap \
		metasploit-framework burpsuite zaproxy \
		john hashcat hydra medusa \
		wireshark tcpdump aircrack-ng \
		binwalk foremost exiftool \
		docker.io docker-compose \
		git curl wget python3-pip \
		build-essential
	@echo "$(GREEN)✓ Penetration testing tools installed$(NC)"

setup-environment:
	@echo "$(BLUE)Setting up testing environment...$(NC)"
	@mkdir -p $(REPORTS_DIR) $(EVIDENCE_DIR) $(CONFIGS_DIR) $(TOOLS_DIR)
	@mkdir -p $(REPORTS_DIR)/{templates,examples,automated}
	@mkdir -p $(EVIDENCE_DIR)/{screenshots,logs,payloads}
	@chmod +x $(SCRIPTS_DIR)/*/
	@docker network create $(DOCKER_NETWORK) 2>/dev/null || true
	@echo "$(GREEN)✓ Environment setup completed$(NC)"

clean-install:
	@echo "$(YELLOW)Cleaning previous installation...$(NC)"
	@rm -rf $(VENV_DIR)
	@docker system prune -f
	@make install

# ===================================
# LAB ENVIRONMENT MANAGEMENT
# ===================================

.PHONY: lab-deploy lab-start lab-stop lab-restart lab-status lab-logs lab-cleanup

lab-deploy: setup-environment
	@echo "$(BLUE)Deploying penetration testing lab...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) build
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) up -d
	@echo "$(GREEN)✓ Lab environment deployed$(NC)"
	@echo "$(YELLOW)Access URLs:$(NC)"
	@echo "  DVWA: http://localhost:8080"
	@echo "  WebGoat: http://localhost:8081"
	@echo "  Mutillidae: http://localhost:8082"
	@echo "  Kibana: http://localhost:5601"
	@echo "  Grafana: http://localhost:3000"

lab-start:
	@echo "$(BLUE)Starting lab environment...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) start
	@echo "$(GREEN)✓ Lab environment started$(NC)"

lab-stop:
	@echo "$(BLUE)Stopping lab environment...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) stop
	@echo "$(GREEN)✓ Lab environment stopped$(NC)"

lab-restart: lab-stop lab-start

lab-status:
	@echo "$(BLUE)Lab Environment Status:$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) ps

lab-logs:
	@echo "$(BLUE)Lab Environment Logs:$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) logs --tail=100

lab-cleanup:
	@echo "$(YELLOW)Cleaning up lab environment...$(NC)"
	@$(DOCKER_COMPOSE) -p $(DOCKER_PROJECT) down -v
	@docker system prune -f
	@echo "$(GREEN)✓ Lab environment cleaned$(NC)"

# ===================================
# PENETRATION TESTING
# ===================================

.PHONY: pentest-full pentest-web pentest-network pentest-wireless pentest-mobile pentest-custom

pentest-full: 
	@echo "$(BLUE)Starting comprehensive penetration test...$(NC)"
	@echo "$(YELLOW)Target: $(TARGET)$(NC)"
	@echo "$(YELLOW)Session: $(SESSION_ID)$(NC)"
	@mkdir -p $(REPORTS_DIR)/$(SESSION_ID)
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/comprehensive_test.py \
		--target $(TARGET) \
		--session $(SESSION_ID) \
		--output $(REPORTS_DIR)/$(SESSION_ID) \
		--format $(OUTPUT_FORMAT)
	@make report-generate SESSION_ID=$(SESSION_ID)
	@echo "$(GREEN)✓ Comprehensive penetration test completed$(NC)"

pentest-web:
	@echo "$(BLUE)Starting web application penetration test...$(NC)"
	@echo "$(YELLOW)Target URL: $(TARGET_URL)$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/web_test.py \
		--url $(TARGET_URL) \
		--framework $(FRAMEWORK) \
		--output $(REPORTS_DIR)/$(SESSION_ID)
	@echo "$(GREEN)✓ Web application test completed$(NC)"

pentest-network:
	@echo "$(BLUE)Starting network penetration test...$(NC)"
	@echo "$(YELLOW)Target Range: $(TARGET_RANGE)$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/network_test.py \
		--range $(TARGET_RANGE) \
		--ports $(SCAN_PORTS) \
		--threads $(SCAN_THREADS) \
		--output $(REPORTS_DIR)/$(SESSION_ID)
	@echo "$(GREEN)✓ Network penetration test completed$(NC)"

pentest-wireless:
	@echo "$(BLUE)Starting wireless penetration test...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/wireless_test.py \
		--interface wlan0 \
		--output $(REPORTS_DIR)/$(SESSION_ID)
	@echo "$(GREEN)✓ Wireless penetration test completed$(NC)"

pentest-mobile:
	@echo "$(BLUE)Starting mobile application penetration test...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/mobile_test.py \
		--app-path $(APP_PATH) \
		--platform $(PLATFORM) \
		--output $(REPORTS_DIR)/$(SESSION_ID)
	@echo "$(GREEN)✓ Mobile application test completed$(NC)"

pentest-custom:
	@echo "$(BLUE)Starting custom penetration test...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/testing/custom_test.py \
		--config $(CONFIGS_DIR)/custom/$(TEST_CONFIG) \
		--output $(REPORTS_DIR)/$(SESSION_ID)

# ===================================
# RECONNAISSANCE
# ===================================

.PHONY: recon-passive recon-active recon-network recon-web recon-social

recon-passive:
	@echo "$(BLUE)Starting passive reconnaissance...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reconnaissance/passive_recon.py \
		--domain $(TARGET) \
		--output $(EVIDENCE_DIR)/recon/passive-$(SESSION_ID).json

recon-active:
	@echo "$(BLUE)Starting active reconnaissance...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reconnaissance/active_recon.py \
		--target $(TARGET) \
		--output $(EVIDENCE_DIR)/recon/active-$(SESSION_ID).json

recon-network:
	@echo "$(BLUE)Starting network reconnaissance...$(NC)"
	@nmap -sn $(TARGET_RANGE) | tee $(EVIDENCE_DIR)/recon/network-discovery-$(SESSION_ID).txt
	@nmap -sV -O $(TARGET_RANGE) | tee $(EVIDENCE_DIR)/recon/network-scan-$(SESSION_ID).txt

recon-web:
	@echo "$(BLUE)Starting web reconnaissance...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reconnaissance/web_recon.py \
		--url $(TARGET_URL) \
		--output $(EVIDENCE_DIR)/recon/web-$(SESSION_ID).json

recon-social:
	@echo "$(BLUE)Starting social engineering reconnaissance...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reconnaissance/social_recon.py \
		--company "$(COMPANY)" \
		--output $(EVIDENCE_DIR)/recon/social-$(SESSION_ID).json

# ===================================
# VULNERABILITY ASSESSMENT
# ===================================

.PHONY: vuln-scan vuln-web vuln-network vuln-database vuln-custom

vuln-scan:
	@echo "$(BLUE)Starting comprehensive vulnerability scan...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/comprehensive_scan.py \
		--target $(TARGET) \
		--output $(EVIDENCE_DIR)/vulns/scan-$(SESSION_ID).json

vuln-web:
	@echo "$(BLUE)Starting web application vulnerability assessment...$(NC)"
	@nikto -h $(TARGET_URL) -o $(EVIDENCE_DIR)/vulns/nikto-$(SESSION_ID).txt
	@sqlmap -u "$(TARGET_URL)" --batch --output-dir $(EVIDENCE_DIR)/vulns/sqlmap-$(SESSION_ID)

vuln-network:
	@echo "$(BLUE)Starting network vulnerability assessment...$(NC)"
	@nmap --script vuln $(TARGET) | tee $(EVIDENCE_DIR)/vulns/nmap-vuln-$(SESSION_ID).txt

vuln-database:
	@echo "$(BLUE)Starting database vulnerability assessment...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/database_scan.py \
		--target $(TARGET) \
		--output $(EVIDENCE_DIR)/vulns/database-$(SESSION_ID).json

vuln-custom:
	@echo "$(BLUE)Starting custom vulnerability assessment...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/scanning/custom_scan.py \
		--config $(VULN_CONFIG) \
		--target $(TARGET) \
		--output $(EVIDENCE_DIR)/vulns/custom-$(SESSION_ID).json

# ===================================
# EXPLOITATION
# ===================================

.PHONY: exploit-auto exploit-manual exploit-build payload-generate payload-encode

exploit-auto:
	@echo "$(BLUE)Starting automated exploitation...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/auto_exploit.py \
		--target $(TARGET) \
		--vulns $(EVIDENCE_DIR)/vulns/scan-$(SESSION_ID).json \
		--output $(EVIDENCE_DIR)/exploitation/auto-$(SESSION_ID).json

exploit-manual:
	@echo "$(BLUE)Starting manual exploitation framework...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/exploitation/manual_exploit.py \
		--interactive \
		--session $(SESSION_ID)

exploit-build:
	@echo "$(BLUE)Building custom exploit...$(NC)"
	@$(PYTHON_VENV) $(TOOLS_DIR)/custom/exploit_builder.py \
		--vuln $(VULN_TYPE) \
		--target $(TARGET_ARCH) \
		--output $(TOOLS_DIR)/custom/exploits/

payload-generate:
	@echo "$(BLUE)Generating payloads...$(NC)"
	@msfvenom -p $(PAYLOAD_TYPE) LHOST=$(LHOST) LPORT=$(LPORT) \
		-f $(PAYLOAD_FORMAT) -o $(EVIDENCE_DIR)/payloads/payload-$(SESSION_ID).$(PAYLOAD_FORMAT)

payload-encode:
	@echo "$(BLUE)Encoding payloads for evasion...$(NC)"
	@$(PYTHON_VENV) $(TOOLS_DIR)/custom/payload_encoder.py \
		--input $(PAYLOAD_FILE) \
		--encoder $(ENCODER_TYPE) \
		--iterations $(ENCODE_ITERATIONS) \
		--output $(EVIDENCE_DIR)/payloads/encoded/

# ===================================
# POST-EXPLOITATION
# ===================================

.PHONY: post-exploit privilege-escalation lateral-movement persistence data-exfiltration

post-exploit:
	@echo "$(BLUE)Starting post-exploitation activities...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/post-exploitation/auto_post_exploit.py \
		--session $(EXPLOIT_SESSION) \
		--objectives $(POST_EXPLOIT_OBJECTIVES) \
		--output $(EVIDENCE_DIR)/post-exploitation/

privilege-escalation:
	@echo "$(BLUE)Testing privilege escalation...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/post-exploitation/privilege_escalation.py \
		--os $(TARGET_OS) \
		--session $(EXPLOIT_SESSION)

lateral-movement:
	@echo "$(BLUE)Testing lateral movement...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/post-exploitation/lateral_movement.py \
		--method $(LATERAL_METHOD) \
		--targets $(LATERAL_TARGETS)

persistence:
	@echo "$(BLUE)Testing persistence mechanisms...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/post-exploitation/persistence.py \
		--method $(PERSIST_METHOD) \
		--os $(TARGET_OS)

data-exfiltration:
	@echo "$(BLUE)Simulating data exfiltration...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/post-exploitation/data_exfiltration.py \
		--method $(EXFIL_METHOD) \
		--data-type $(DATA_TYPE)

# ===================================
# FRAMEWORK TESTING
# ===================================

.PHONY: owasp-test ptes-test nist-test compliance-test

owasp-test:
	@echo "$(BLUE)Running OWASP Top 10 testing...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/owasp/owasp_testing.py \
		--url $(TARGET_URL) \
		--comprehensive \
		--output $(REPORTS_DIR)/owasp-$(SESSION_ID).json

ptes-test:
	@echo "$(BLUE)Running PTES methodology testing...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/ptes/ptes_testing.py \
		--target $(TARGET) \
		--phase $(PTES_PHASE) \
		--output $(REPORTS_DIR)/ptes-$(SESSION_ID).json

nist-test:
	@echo "$(BLUE)Running NIST SP 800-115 testing...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/nist/nist_testing.py \
		--target $(TARGET) \
		--controls $(NIST_CONTROLS) \
		--output $(REPORTS_DIR)/nist-$(SESSION_ID).json

compliance-test:
	@echo "$(BLUE)Running compliance framework testing...$(NC)"
	@$(PYTHON_VENV) $(FRAMEWORKS_DIR)/compliance/compliance_testing.py \
		--framework $(COMPLIANCE_FRAMEWORK) \
		--target $(TARGET) \
		--output $(REPORTS_DIR)/compliance-$(SESSION_ID).json

# ===================================
# REPORTING & EVIDENCE
# ===================================

.PHONY: report-generate report-executive report-technical report-compliance evidence-collect evidence-archive

report-generate:
	@echo "$(BLUE)Generating penetration test report...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/generate_report.py \
		--session $(SESSION_ID) \
		--type $(REPORT_TYPE) \
		--template $(REPORTS_DIR)/templates/$(REPORT_TYPE).html \
		--output $(REPORTS_DIR)/$(SESSION_ID)/report-$(REPORT_TYPE).pdf
	@echo "$(GREEN)✓ Report generated: $(REPORTS_DIR)/$(SESSION_ID)/report-$(REPORT_TYPE).pdf$(NC)"

report-executive:
	@echo "$(BLUE)Generating executive summary report...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/executive_report.py \
		--session $(SESSION_ID) \
		--output $(REPORTS_DIR)/$(SESSION_ID)/executive-summary.pdf

report-technical:
	@echo "$(BLUE)Generating technical report...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/technical_report.py \
		--session $(SESSION_ID) \
		--findings high,critical \
		--output $(REPORTS_DIR)/$(SESSION_ID)/technical-report.pdf

report-compliance:
	@echo "$(BLUE)Generating compliance report...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/compliance_report.py \
		--session $(SESSION_ID) \
		--standard $(COMPLIANCE_STANDARD) \
		--output $(REPORTS_DIR)/$(SESSION_ID)/compliance-report.pdf

evidence-collect:
	@echo "$(BLUE)Collecting and organizing evidence...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/reporting/evidence_collector.py \
		--session $(SESSION_ID) \
		--output $(EVIDENCE_DIR)/$(SESSION_ID)/

evidence-archive:
	@echo "$(BLUE)Archiving evidence securely...$(NC)"
	@tar -czf $(EVIDENCE_DIR)/archive/evidence-$(SESSION_ID).tar.gz \
		$(EVIDENCE_DIR)/$(SESSION_ID)/
	@gpg --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 \
		--s2k-digest-algo SHA512 --s2k-count 65536 --symmetric \
		$(EVIDENCE_DIR)/archive/evidence-$(SESSION_ID).tar.gz

# ===================================
# MONITORING & ANALYSIS
# ===================================

.PHONY: monitor-start monitor-stop logs-analyze traffic-analyze

monitor-start:
	@echo "$(BLUE)Starting monitoring services...$(NC)"
	@$(DOCKER_COMPOSE) -f docker-compose.monitoring.yml up -d
	@echo "$(GREEN)✓ Monitoring services started$(NC)"

monitor-stop:
	@echo "$(BLUE)Stopping monitoring services...$(NC)"
	@$(DOCKER_COMPOSE) -f docker-compose.monitoring.yml down

logs-analyze:
	@echo "$(BLUE)Analyzing testing logs...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/log_analyzer.py \
		--logs $(EVIDENCE_DIR)/logs/ \
		--session $(SESSION_ID) \
		--output $(REPORTS_DIR)/analysis/

traffic-analyze:
	@echo "$(BLUE)Analyzing network traffic...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/analysis/traffic_analyzer.py \
		--pcap $(EVIDENCE_DIR)/traffic/capture-$(SESSION_ID).pcap \
		--output $(REPORTS_DIR)/analysis/traffic-$(SESSION_ID).json

# ===================================
# MAINTENANCE & HEALTH
# ===================================

.PHONY: health-check security-check update-tools backup-create backup-restore

health-check:
	@echo "$(BLUE)Running system health check...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/maintenance/health_check.py \
		--comprehensive \
		--output $(REPORTS_DIR)/health/health-check-$(BUILD_DATE).json

security-check:
	@echo "$(BLUE)Running security validation...$(NC)"
	@$(PYTHON_VENV) $(SCRIPTS_DIR)/maintenance/security_check.py \
		--framework-path $(PROJECT_ROOT) \
		--output $(REPORTS_DIR)/security/security-check-$(BUILD_DATE).json

update-tools:
	@echo "$(BLUE)Updating penetration testing tools...$(NC)"
	@sudo apt-get update && sudo apt-get upgrade -y
	@$(PIP) install --upgrade -r requirements.txt
	@docker pull kalilinux/kali-rolling
	@echo "$(GREEN)✓ Tools updated successfully$(NC)"

backup-create:
	@echo "$(BLUE)Creating system backup...$(NC)"
	@mkdir -p backups/
	@tar -czf backups/framework-backup-$(BUILD_DATE).tar.gz \
		--exclude='backups' \
		--exclude='evidence' \
		--exclude='venv' \
		$(PROJECT_ROOT)
	@echo "$(GREEN)✓ Backup created: backups/framework-backup-$(BUILD_DATE).tar.gz$(NC)"

backup-restore:
	@echo "$(YELLOW)Restoring from backup...$(NC)"
	@tar -xzf $(BACKUP_FILE) -C $(RESTORE_PATH)
	@echo "$(GREEN)✓ Backup restored successfully$(NC)"

# ===================================
# CLEANUP & MAINTENANCE
# ===================================

.PHONY: clean clean-reports clean-evidence clean-logs clean-all

clean:
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type f -name "*.tmp" -delete

clean-reports:
	@echo "$(YELLOW)Cleaning old reports...$(NC)"
	@find $(REPORTS_DIR) -type f -mtime +30 -delete

clean-evidence:
	@echo "$(YELLOW)Cleaning old evidence...$(NC)"
	@find $(EVIDENCE_DIR) -type f -mtime +90 -delete

clean-logs:
	@echo "$(BLUE)Cleaning old logs...$(NC)"
	@find $(EVIDENCE_DIR)/logs -type f -mtime +7 -delete

clean-all: clean clean-reports clean-evidence clean-logs lab-cleanup
	@echo "$(GREEN)✓ Complete cleanup finished$(NC)"

# ===================================
# UTILITY TARGETS
# ===================================

.PHONY: version info requirements-update docker-build docker-push

version:
	@echo "$(BLUE)Penetration Testing Framework$(NC)"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build Time: $(BUILD_TIME)"

info:
	@echo "$(BLUE)Project Information:$(NC)"
	@echo "Project Root: $(PROJECT_ROOT)"
	@echo "Python Version: $(shell $(PYTHON) --version)"
	@echo "Docker Version: $(shell docker --version)"
	@echo "Available Disk Space: $(shell df -h . | tail -1 | awk '{print $$4}')"
	@echo "Memory Usage: $(shell free -h | grep Mem | awk '{print $$3 "/" $$2}')"

requirements-update:
	@echo "$(BLUE)Updating requirements.txt...$(NC)"
	@$(PIP) freeze > requirements.txt
	@echo "$(GREEN)✓ Requirements updated$(NC)"

docker-build:
	@echo "$(BLUE)Building Docker images...$(NC)"
	@docker build -t $(PROJECT_NAME):$(PROJECT_VERSION) .
	@docker build -t $(PROJECT_NAME):latest .

docker-push:
	@echo "$(BLUE)Pushing Docker images...$(NC)"
	@docker push $(PROJECT_NAME):$(PROJECT_VERSION)
	@docker push $(PROJECT_NAME):latest

# ===================================
# SPECIAL TARGETS
# ===================================

# Prevent make from interpreting these as files
.PHONY: all
all: install lab-deploy health-check

# Default target when no target is specified
.DEFAULT_GOAL := help