# WiFi Security & WPA3 Implementation Project Makefile
# Comprehensive automation for wireless security lab deployment and testing

.PHONY: help install clean setup lab-deploy lab-destroy configure-infrastructure deploy-wpa3 deploy-monitoring
.PHONY: security-validation penetration-test compliance-report dashboard demo-start demo-stop 
.PHONY: backup restore status logs test-all security-tests performance-tests
.PHONY: docs-build docs-serve vagrant-up vagrant-destroy docker-build docker-clean

# Default target
help: ## Display this help message
	@echo "🔐 WiFi Security & WPA3 Implementation - Project Automation"
	@echo "=========================================================="
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "🚀 Quick Start:"
	@echo "  make install          # Install dependencies"
	@echo "  make lab-deploy       # Deploy wireless lab"
	@echo "  make demo-start       # Start complete demo"
	@echo "  make security-tests   # Run security validation"
	@echo ""

# Project configuration
PROJECT_NAME := wifi-security
PROJECT_VERSION := 1.0.0
PROJECT_DIR := $(shell pwd)
DOCKER_COMPOSE_FILE := docker-compose.yml
VAGRANT_FILE := vagrant/Vagrantfile

# Directory structure
DOCS_DIR := docs
SRC_DIR := src
INFRASTRUCTURE_DIR := infrastructure
TESTS_DIR := tests
MONITORING_DIR := monitoring
TOOLS_DIR := tools
EXAMPLES_DIR := examples

# Docker and Vagrant configuration
DOCKER_NETWORK := wireless-security-net
DOCKER_SUBNET := 172.30.0.0/16
VAGRANT_BOX := kalilinux/rolling

# Wireless security configuration
RADIUS_SERVER_IP := 172.30.1.10
WLC_IP := 172.30.1.20
MONITORING_IP := 172.30.1.30
GATEWAY_IP := 172.30.1.1

# Certificate and PKI configuration
CA_COMMON_NAME := "Wireless Security Lab CA"
SERVER_COMMON_NAME := "radius.wifilab.local"
CERT_VALIDITY_DAYS := 365
KEY_SIZE := 2048

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

# Utility functions
define log_info
	@echo "$(CYAN)[INFO]$(NC) $(1)"
endef

define log_success
	@echo "$(GREEN)[SUCCESS]$(NC) $(1)"
endef

define log_warning
	@echo "$(YELLOW)[WARNING]$(NC) $(1)"
endef

define log_error
	@echo "$(RED)[ERROR]$(NC) $(1)"
endef

# ============================================================================
# Installation and Setup
# ============================================================================

install: ## Install all dependencies and setup environment
	$(call log_info,"Installing WiFi Security Lab dependencies...")
	@if command -v docker >/dev/null 2>&1; then \
		$(call log_success,"Docker is already installed"); \
	else \
		$(call log_error,"Docker is not installed. Please install Docker first."); \
		exit 1; \
	fi
	@if command -v docker-compose >/dev/null 2>&1; then \
		$(call log_success,"Docker Compose is already installed"); \
	else \
		$(call log_error,"Docker Compose is not installed. Please install Docker Compose first."); \
		exit 1; \
	fi
	@if command -v vagrant >/dev/null 2>&1; then \
		$(call log_success,"Vagrant is already installed"); \
	else \
		$(call log_warning,"Vagrant is not installed. Some features may not be available."); \
	fi
	@$(MAKE) setup-directories
	@$(MAKE) setup-certificates
	@$(MAKE) docker-build
	$(call log_success,"Installation completed successfully!")

setup-directories: ## Create all necessary project directories
	$(call log_info,"Creating project directory structure...")
	@mkdir -p $(DOCS_DIR)/{architecture,security,implementation,compliance}
	@mkdir -p $(SRC_DIR)/{configurations/{hostapd,freeradius,certificates,network},scripts/{deployment,monitoring,security,maintenance},policies}
	@mkdir -p $(INFRASTRUCTURE_DIR)/{lab-setup/{virtual-aps,radius-server,certificate-authority,monitoring},automation/{ansible,terraform,scripts},monitoring/{prometheus,grafana,elk}}
	@mkdir -p $(TESTS_DIR)/{security-validation/{wpa3-tests,eap-tests,isolation-tests,compliance-tests},penetration/{wireless-attacks,client-testing,rogue-ap-detection,social-engineering},compliance/{pci-dss-tests,hipaa-tests,nist-tests}}
	@mkdir -p $(MONITORING_DIR)/{wids-wips/{kismet-config,suricata-wireless,custom-detection},analytics/{client-behavior,performance-analytics,security-analytics},reporting/{compliance-reports,security-dashboards,performance-reports}}
	@mkdir -p $(TOOLS_DIR)/{pentest/{wifi-scanner,evil-twin,deauth-tool,wps-attack},analysis/{packet-analyzer,rf-analysis,client-profiler},automation/{cert-management,config-generator,health-checker}}
	@mkdir -p $(EXAMPLES_DIR)/{configs/{enterprise-wifi,guest-networks,iot-segmentation},scenarios/{attack-simulations,compliance-demos,performance-tests},reports/{security-assessment,penetration-test,compliance-audit}}
	@mkdir -p vagrant/provisioning
	@mkdir -p logs certificates backup
	$(call log_success,"Directory structure created")

setup-certificates: ## Generate PKI certificates for lab environment
	$(call log_info,"Generating PKI certificates for wireless security lab...")
	@mkdir -p certificates/{ca,server,client}
	# Generate CA private key
	@openssl genrsa -out certificates/ca/ca.key $(KEY_SIZE) 2>/dev/null
	# Generate CA certificate
	@openssl req -new -x509 -days $(CERT_VALIDITY_DAYS) -key certificates/ca/ca.key -out certificates/ca/ca.crt -subj "/CN=$(CA_COMMON_NAME)/O=WiFi Security Lab/C=US" 2>/dev/null
	# Generate RADIUS server private key
	@openssl genrsa -out certificates/server/server.key $(KEY_SIZE) 2>/dev/null
	# Generate RADIUS server certificate request
	@openssl req -new -key certificates/server/server.key -out certificates/server/server.csr -subj "/CN=$(SERVER_COMMON_NAME)/O=WiFi Security Lab/C=US" 2>/dev/null
	# Generate RADIUS server certificate
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in certificates/server/server.csr -CA certificates/ca/ca.crt -CAkey certificates/ca/ca.key -CAcreateserial -out certificates/server/server.crt 2>/dev/null
	# Generate client certificate template
	@openssl genrsa -out certificates/client/client.key $(KEY_SIZE) 2>/dev/null
	@openssl req -new -key certificates/client/client.key -out certificates/client/client.csr -subj "/CN=client.wifilab.local/O=WiFi Security Lab/C=US" 2>/dev/null
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in certificates/client/client.csr -CA certificates/ca/ca.crt -CAkey certificates/ca/ca.key -CAcreateserial -out certificates/client/client.crt 2>/dev/null
	# Set proper permissions
	@chmod 600 certificates/**/*.key
	@chmod 644 certificates/**/*.crt
	$(call log_success,"PKI certificates generated successfully")

clean: ## Clean up all generated files and containers
	$(call log_warning,"Cleaning up WiFi Security Lab environment...")
	@$(MAKE) docker-clean
	@$(MAKE) vagrant-destroy
	@rm -rf certificates logs backup
	@docker volume prune -f 2>/dev/null || true
	@docker network prune -f 2>/dev/null || true
	$(call log_success,"Environment cleaned up")

# ============================================================================
# Lab Environment Deployment
# ============================================================================

lab-deploy: ## Deploy complete wireless security lab environment
	$(call log_info,"Deploying WiFi Security Lab...")
	@$(MAKE) docker-build
	@$(MAKE) setup-network
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@sleep 30
	@$(MAKE) configure-infrastructure
	@$(MAKE) deploy-monitoring
	$(call log_success,"WiFi Security Lab deployed successfully!")
	@$(MAKE) status

lab-destroy: ## Destroy wireless security lab environment
	$(call log_warning,"Destroying WiFi Security Lab...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v
	@docker network rm $(DOCKER_NETWORK) 2>/dev/null || true
	$(call log_success,"Lab environment destroyed")

setup-network: ## Setup Docker network for lab environment
	$(call log_info,"Setting up Docker network...")
	@docker network inspect $(DOCKER_NETWORK) >/dev/null 2>&1 || \
		docker network create --driver bridge --subnet=$(DOCKER_SUBNET) $(DOCKER_NETWORK)
	$(call log_success,"Docker network configured")

configure-infrastructure: ## Configure wireless infrastructure components
	$(call log_info,"Configuring wireless infrastructure...")
	@$(MAKE) configure-radius
	@$(MAKE) configure-hostapd
	@$(MAKE) configure-monitoring
	$(call log_success,"Infrastructure configuration completed")

configure-radius: ## Configure FreeRADIUS server
	$(call log_info,"Configuring FreeRADIUS server...")
	@docker exec wifi-radius-server /bin/bash -c "chmod +x /etc/raddb/setup-radius.sh && /etc/raddb/setup-radius.sh"
	@sleep 5
	@docker exec wifi-radius-server systemctl restart freeradius
	$(call log_success,"FreeRADIUS server configured")

configure-hostapd: ## Configure hostapd access points
	$(call log_info,"Configuring hostapd access points...")
	@docker exec wifi-access-point-1 /bin/bash -c "chmod +x /etc/hostapd/setup-ap.sh && /etc/hostapd/setup-ap.sh"
	@docker exec wifi-access-point-2 /bin/bash -c "chmod +x /etc/hostapd/setup-ap.sh && /etc/hostapd/setup-ap.sh"
	$(call log_success,"Access points configured")

configure-monitoring: ## Configure monitoring and detection systems
	$(call log_info,"Configuring monitoring systems...")
	@docker exec wifi-monitoring /bin/bash -c "chmod +x /opt/monitoring/setup-monitoring.sh && /opt/monitoring/setup-monitoring.sh"
	@docker exec wifi-wids /bin/bash -c "chmod +x /opt/wids/setup-wids.sh && /opt/wids/setup-wids.sh"
	$(call log_success,"Monitoring systems configured")

# ============================================================================
# Security Deployment
# ============================================================================

deploy-wpa3: ## Deploy WPA3 security configuration
	$(call log_info,"Deploying WPA3 security configuration...")
	@docker exec wifi-access-point-1 /bin/bash -c "/etc/hostapd/deploy-wpa3.sh"
	@docker exec wifi-access-point-2 /bin/bash -c "/etc/hostapd/deploy-wpa3.sh"
	@sleep 10
	@$(MAKE) validate-wpa3
	$(call log_success,"WPA3 security deployed")

validate-wpa3: ## Validate WPA3 implementation
	$(call log_info,"Validating WPA3 implementation...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/validate-wpa3.sh"
	$(call log_success,"WPA3 validation completed")

deploy-monitoring: ## Deploy comprehensive monitoring solution
	$(call log_info,"Deploying monitoring and analytics...")
	@docker exec wifi-monitoring /bin/bash -c "systemctl start prometheus grafana-server"
	@docker exec wifi-wids /bin/bash -c "systemctl start kismet"
	@sleep 15
	$(call log_success,"Monitoring solution deployed")

# ============================================================================
# Testing and Validation
# ============================================================================

test-all: security-tests performance-tests compliance-tests ## Run all test suites
	$(call log_success,"All tests completed successfully!")

security-tests: ## Run comprehensive security validation tests
	$(call log_info,"Running security validation tests...")
	@$(MAKE) test-wpa3-security
	@$(MAKE) test-eap-authentication
	@$(MAKE) test-network-isolation
	@$(MAKE) test-rogue-detection
	$(call log_success,"Security tests completed")

test-wpa3-security: ## Test WPA3 security implementation
	$(call log_info,"Testing WPA3 security implementation...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/wpa3-security-tests.sh"

test-eap-authentication: ## Test EAP authentication methods
	$(call log_info,"Testing EAP authentication methods...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/eap-method-tests.sh"

test-network-isolation: ## Test network segmentation and isolation
	$(call log_info,"Testing network isolation...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/isolation-tests.sh"

test-rogue-detection: ## Test rogue AP detection capabilities
	$(call log_info,"Testing rogue AP detection...")
	@docker exec wifi-wids /bin/bash -c "/opt/tests/rogue-detection-tests.sh"

performance-tests: ## Run wireless performance tests
	$(call log_info,"Running performance tests...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/performance-tests.sh"

penetration-test: ## Run wireless penetration testing suite
	$(call log_warning,"Running wireless penetration tests...")
	@docker exec wifi-pentest /bin/bash -c "/opt/pentest/run-pentest-suite.sh"
	$(call log_success,"Penetration testing completed")

compliance-tests: ## Run compliance validation tests
	$(call log_info,"Running compliance validation...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/nist-compliance-tests.sh"
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/pci-dss-tests.sh"
	$(call log_success,"Compliance tests completed")

security-validation: ## Validate overall security posture
	$(call log_info,"Performing comprehensive security validation...")
	@$(MAKE) test-wpa3-security
	@$(MAKE) test-eap-authentication
	@$(MAKE) test-network-isolation
	@$(MAKE) validate-certificates
	@$(MAKE) validate-radius-config
	$(call log_success,"Security validation completed")

validate-certificates: ## Validate PKI certificate configuration
	$(call log_info,"Validating PKI certificates...")
	@docker exec wifi-radius-server /bin/bash -c "/opt/scripts/validate-certificates.sh"

validate-radius-config: ## Validate RADIUS server configuration
	$(call log_info,"Validating RADIUS configuration...")
	@docker exec wifi-radius-server /bin/bash -c "radiusd -X -f" &
	@sleep 5
	@docker exec wifi-test-client /bin/bash -c "/opt/tests/radius-validation.sh"

# ============================================================================
# Monitoring and Analytics
# ============================================================================

dashboard: ## Open monitoring dashboards
	$(call log_info,"Opening monitoring dashboards...")
	@echo "$(CYAN)Grafana Dashboard:$(NC) http://localhost:3000 (admin/admin)"
	@echo "$(CYAN)Prometheus:$(NC) http://localhost:9090"
	@echo "$(CYAN)Kismet:$(NC) http://localhost:2501"
	@if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open http://localhost:3000; \
	elif command -v open >/dev/null 2>&1; then \
		open http://localhost:3000; \
	fi

logs: ## Show logs for all services
	$(call log_info,"Displaying service logs...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=50

status: ## Show status of all lab components
	$(call log_info,"WiFi Security Lab Status:")
	@echo "$(CYAN)============================================$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) ps
	@echo ""
	@echo "$(CYAN)Network Status:$(NC)"
	@docker network inspect $(DOCKER_NETWORK) --format "{{.Name}}: {{.IPAM.Config}}" 2>/dev/null || echo "Network not found"
	@echo ""
	@echo "$(CYAN)Service Health:$(NC)"
	@docker exec wifi-radius-server systemctl is-active freeradius 2>/dev/null | sed 's/^/  RADIUS: /' || echo "  RADIUS: stopped"
	@docker exec wifi-monitoring systemctl is-active prometheus 2>/dev/null | sed 's/^/  Prometheus: /' || echo "  Prometheus: stopped"
	@docker exec wifi-monitoring systemctl is-active grafana-server 2>/dev/null | sed 's/^/  Grafana: /' || echo "  Grafana: stopped"
	@docker exec wifi-wids systemctl is-active kismet 2>/dev/null | sed 's/^/  Kismet: /' || echo "  Kismet: stopped"

# ============================================================================
# Reporting and Documentation
# ============================================================================

compliance-report: ## Generate comprehensive compliance report
	$(call log_info,"Generating compliance reports...")
	@mkdir -p reports/compliance
	@docker exec wifi-test-client /bin/bash -c "/opt/reports/generate-nist-report.sh > /opt/reports/nist-compliance-$(shell date +%Y%m%d).html"
	@docker exec wifi-test-client /bin/bash -c "/opt/reports/generate-pci-report.sh > /opt/reports/pci-dss-compliance-$(shell date +%Y%m%d).html"
	@docker cp wifi-test-client:/opt/reports/ ./reports/compliance/
	$(call log_success,"Compliance reports generated in ./reports/compliance/")

security-report: ## Generate security assessment report
	$(call log_info,"Generating security assessment report...")
	@mkdir -p reports/security
	@docker exec wifi-pentest /bin/bash -c "/opt/reports/generate-security-report.sh > /opt/reports/security-assessment-$(shell date +%Y%m%d).html"
	@docker cp wifi-pentest:/opt/reports/ ./reports/security/
	$(call log_success,"Security assessment report generated")

performance-report: ## Generate performance analysis report
	$(call log_info,"Generating performance report...")
	@mkdir -p reports/performance
	@docker exec wifi-monitoring /bin/bash -c "/opt/reports/generate-performance-report.sh > /opt/reports/performance-analysis-$(shell date +%Y%m%d).html"
	@docker cp wifi-monitoring:/opt/reports/ ./reports/performance/
	$(call log_success,"Performance report generated")

docs-build: ## Build project documentation
	$(call log_info,"Building project documentation...")
	@if command -v mkdocs >/dev/null 2>&1; then \
		mkdocs build; \
		$(call log_success,"Documentation built successfully"); \
	else \
		$(call log_warning,"MkDocs not installed. Skipping documentation build."); \
	fi

docs-serve: ## Serve documentation locally
	$(call log_info,"Starting documentation server...")
	@if command -v mkdocs >/dev/null 2>&1; then \
		mkdocs serve; \
	else \
		$(call log_warning,"MkDocs not installed. Cannot serve documentation."); \
	fi

# ============================================================================
# Demo and Examples
# ============================================================================

demo-start: ## Start complete wireless security demonstration
	$(call log_info,"Starting WiFi Security Lab demonstration...")
	@$(MAKE) lab-deploy
	@sleep 30
	@$(MAKE) deploy-wpa3
	@$(MAKE) demo-scenarios
	$(call log_success,"Demonstration environment ready!")
	@echo ""
	@echo "$(GREEN)🎯 Demo Environment Ready!$(NC)"
	@echo "$(CYAN)================================$(NC)"
	@echo "Access Points:"
	@echo "  • Enterprise WiFi (WPA3-Enterprise): SSID 'CorpWiFi-Secure'"
	@echo "  • Guest Network (WPA3-Personal): SSID 'Guest-WiFi'"
	@echo ""
	@echo "Management Interfaces:"
	@echo "  • Grafana Dashboard: http://localhost:3000"
	@echo "  • Prometheus Metrics: http://localhost:9090" 
	@echo "  • Kismet WIDS: http://localhost:2501"
	@echo ""
	@echo "Test Commands:"
	@echo "  • make security-tests     # Run security validation"
	@echo "  • make penetration-test   # Run penetration tests"
	@echo "  • make compliance-report  # Generate compliance reports"

demo-scenarios: ## Run demonstration scenarios
	$(call log_info,"Running demonstration scenarios...")
	@docker exec wifi-test-client /bin/bash -c "/opt/demo/enterprise-connection-demo.sh"
	@docker exec wifi-test-client /bin/bash -c "/opt/demo/guest-access-demo.sh"
	@docker exec wifi-wids /bin/bash -c "/opt/demo/rogue-ap-demo.sh"

demo-stop: ## Stop demonstration environment
	$(call log_warning,"Stopping demonstration...")
	@$(MAKE) lab-destroy
	$(call log_success,"Demonstration stopped")

# ============================================================================
# Backup and Restore
# ============================================================================

backup: ## Create backup of lab configuration
	$(call log_info,"Creating lab configuration backup...")
	@mkdir -p backup/$(shell date +%Y%m%d_%H%M%S)
	@docker exec wifi-radius-server /bin/bash -c "tar -czf /tmp/radius-backup.tar.gz /etc/raddb/"
	@docker cp wifi-radius-server:/tmp/radius-backup.tar.gz backup/$(shell date +%Y%m%d_%H%M%S)/
	@cp -r certificates backup/$(shell date +%Y%m%d_%H%M%S)/
	@cp $(DOCKER_COMPOSE_FILE) backup/$(shell date +%Y%m%d_%H%M%S)/
	$(call log_success,"Backup created in backup/$(shell date +%Y%m%d_%H%M%S)/")

restore: ## Restore lab configuration from backup
	$(call log_info,"Restoring lab configuration...")
	@if [ -z "$(BACKUP_DIR)" ]; then \
		echo "$(RED)Please specify BACKUP_DIR: make restore BACKUP_DIR=backup/20241227_120000$(NC)"; \
		exit 1; \
	fi
	@if [ ! -d "$(BACKUP_DIR)" ]; then \
		echo "$(RED)Backup directory $(BACKUP_DIR) not found$(NC)"; \
		exit 1; \
	fi
	@docker cp $(BACKUP_DIR)/radius-backup.tar.gz wifi-radius-server:/tmp/
	@docker exec wifi-radius-server /bin/bash -c "cd / && tar -xzf /tmp/radius-backup.tar.gz"
	@cp -r $(BACKUP_DIR)/certificates ./
	$(call log_success,"Configuration restored from $(BACKUP_DIR)")

# ============================================================================
# Docker and Container Management
# ============================================================================

docker-build: ## Build all Docker images for the lab
	$(call log_info,"Building Docker images...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) build --no-cache
	$(call log_success,"Docker images built successfully")

docker-clean: ## Clean up Docker containers and images
	$(call log_warning,"Cleaning up Docker containers and images...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v --remove-orphans
	@docker image prune -f
	@docker container prune -f
	$(call log_success,"Docker cleanup completed")

docker-logs: ## Show logs for specific service
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(RED)Please specify SERVICE: make docker-logs SERVICE=wifi-radius-server$(NC)"; \
		exit 1; \
	fi
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f $(SERVICE)

docker-shell: ## Get shell access to specific service container
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(RED)Please specify SERVICE: make docker-shell SERVICE=wifi-radius-server$(NC)"; \
		exit 1; \
	fi
	@docker exec -it $(SERVICE) /bin/bash

# ============================================================================
# Vagrant Virtual Machines
# ============================================================================

vagrant-up: ## Start Vagrant wireless security lab
	$(call log_info,"Starting Vagrant wireless lab...")
	@cd vagrant && vagrant up
	$(call log_success,"Vagrant lab started")

vagrant-destroy: ## Destroy Vagrant virtual machines
	$(call log_warning,"Destroying Vagrant VMs...")
	@cd vagrant && vagrant destroy -f
	$(call log_success,"Vagrant VMs destroyed")

vagrant-provision: ## Re-provision Vagrant VMs
	$(call log_info,"Re-provisioning Vagrant VMs...")
	@cd vagrant && vagrant provision
	$(call log_success,"Vagrant VMs reprovisioned")

vagrant-status: ## Show status of Vagrant VMs
	@cd vagrant && vagrant status

# ============================================================================
# Maintenance and Utilities
# ============================================================================

update: ## Update lab environment and dependencies
	$(call log_info,"Updating lab environment...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) pull
	@$(MAKE) docker-build
	$(call log_success,"Lab environment updated")

health-check: ## Perform comprehensive health check
	$(call log_info,"Performing health check...")
	@$(MAKE) status
	@echo ""
	@echo "$(CYAN)Certificate Validation:$(NC)"
	@openssl x509 -in certificates/ca/ca.crt -text -noout | grep "Not After" | sed 's/^/  CA Certificate: /'
	@openssl x509 -in certificates/server/server.crt -text -noout | grep "Not After" | sed 's/^/  Server Certificate: /'
	@echo ""
	@echo "$(CYAN)Service Connectivity:$(NC)"
	@docker exec wifi-test-client ping -c 1 $(RADIUS_SERVER_IP) > /dev/null 2>&1 && echo "  RADIUS Server: ✓ Reachable" || echo "  RADIUS Server: ✗ Unreachable"
	@docker exec wifi-test-client ping -c 1 $(MONITORING_IP) > /dev/null 2>&1 && echo "  Monitoring: ✓ Reachable" || echo "  Monitoring: ✗ Unreachable"

monitor-traffic: ## Monitor wireless traffic in real-time
	$(call log_info,"Starting wireless traffic monitoring...")
	@docker exec -it wifi-wids /bin/bash -c "kismet_capture --source=wlan0"

generate-client-cert: ## Generate client certificate for testing
	@if [ -z "$(CLIENT_NAME)" ]; then \
		echo "$(RED)Please specify CLIENT_NAME: make generate-client-cert CLIENT_NAME=test-device$(NC)"; \
		exit 1; \
	fi
	$(call log_info,"Generating client certificate for $(CLIENT_NAME)...")
	@openssl genrsa -out certificates/client/$(CLIENT_NAME).key $(KEY_SIZE)
	@openssl req -new -key certificates/client/$(CLIENT_NAME).key -out certificates/client/$(CLIENT_NAME).csr -subj "/CN=$(CLIENT_NAME).wifilab.local/O=WiFi Security Lab/C=US"
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in certificates/client/$(CLIENT_NAME).csr -CA certificates/ca/ca.crt -CAkey certificates/ca/ca.key -CAcreateserial -out certificates/client/$(CLIENT_NAME).crt
	@chmod 600 certificates/client/$(CLIENT_NAME).key
	@chmod 644 certificates/client/$(CLIENT_NAME).crt
	$(call log_success,"Client certificate generated for $(CLIENT_NAME)")

# ============================================================================
# Advanced Features
# ============================================================================

simulate-attack: ## Simulate wireless attack scenarios for testing
	$(call log_warning,"Simulating wireless attack scenarios...")
	@if [ -z "$(ATTACK_TYPE)" ]; then \
		echo "$(RED)Please specify ATTACK_TYPE: make simulate-attack ATTACK_TYPE=evil-twin$(NC)"; \
		echo "Available attacks: evil-twin, deauth, wps-attack, rogue-ap"; \
		exit 1; \
	fi
	@docker exec wifi-pentest /bin/bash -c "/opt/pentest/simulate-$(ATTACK_TYPE).sh"

analyze-spectrum: ## Perform RF spectrum analysis
	$(call log_info,"Performing RF spectrum analysis...")
	@docker exec wifi-wids /bin/bash -c "/opt/tools/spectrum-analyzer.sh"

client-profiling: ## Profile connected wireless clients
	$(call log_info,"Profiling wireless clients...")
	@docker exec wifi-wids /bin/bash -c "/opt/tools/client-profiler.sh"

generate-traffic: ## Generate test wireless traffic
	$(call log_info,"Generating test wireless traffic...")
	@docker exec wifi-test-client /bin/bash -c "/opt/tools/traffic-generator.sh"

# ============================================================================
# Help and Information
# ============================================================================

version: ## Display version information
	@echo "$(CYAN)WiFi Security & WPA3 Implementation Lab$(NC)"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Project Directory: $(PROJECT_DIR)"

requirements: ## Display system requirements
	@echo "$(CYAN)System Requirements:$(NC)"
	@echo "• Docker Engine 20.10+"
	@echo "• Docker Compose 2.0+"
	@echo "• 4GB RAM minimum (8GB recommended)"
	@echo "• 10GB disk space"
	@echo "• USB WiFi adapter for real testing (optional)"
	@echo "• Vagrant 2.2+ (optional)"

troubleshooting: ## Display common troubleshooting tips
	@echo "$(CYAN)Common Troubleshooting:$(NC)"
	@echo ""
	@echo "1. Container startup issues:"
	@echo "   make docker-clean && make lab-deploy"
	@echo ""
	@echo "2. Certificate issues:"
	@echo "   make clean && make setup-certificates"
	@echo ""
	@echo "3. Network connectivity:"
	@echo "   make setup-network"
	@echo ""
	@echo "4. Service logs:"
	@echo "   make docker-logs SERVICE=wifi-radius-server"
	@echo ""
	@echo "5. Complete reset:"
	@echo "   make clean && make install && make lab-deploy"