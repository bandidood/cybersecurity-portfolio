# Enterprise Identity & Access Management (IAM) Project Makefile
# Comprehensive automation for identity security, compliance, and governance

.PHONY: help install clean setup lab-deploy lab-destroy setup-ad-domain setup-sso setup-mfa setup-pam
.PHONY: validate-iam demo-start demo-stop test-authentication test-sso test-mfa compliance-report
.PHONY: security-tests penetration-test identity-scan privilege-audit access-review
.PHONY: backup restore status logs health-check dashboard monitoring-setup
.PHONY: docker-build docker-clean vagrant-up vagrant-destroy

# Default target
help: ## Display this help message
	@echo "🔐 Enterprise Identity & Access Management (IAM) - Project Automation"
	@echo "======================================================================="
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "🚀 Quick Start Commands:"
	@echo "  make install              # Install dependencies and setup environment"
	@echo "  make lab-deploy           # Deploy complete IAM lab environment"
	@echo "  make demo-start           # Start comprehensive IAM demonstration"
	@echo "  make security-tests       # Run complete security validation suite"
	@echo "  make compliance-report    # Generate multi-standard compliance reports"
	@echo ""

# Project configuration
PROJECT_NAME := enterprise-iam
PROJECT_VERSION := 2.0.0
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

# IAM service configuration
AD_DOMAIN := corp.iam-lab.local
LDAP_BASE_DN := dc=iam-lab,dc=local
KEYCLOAK_ADMIN_USER := admin
VAULT_ADDR := http://localhost:8200
GRAFANA_PORT := 3000
KEYCLOAK_PORT := 8080

# Network and security configuration
IAM_NETWORK := iam-security-net
IAM_SUBNET := 172.20.0.0/16
AD_SERVER_IP := 172.20.1.10
LDAP_SERVER_IP := 172.20.1.20
KEYCLOAK_IP := 172.20.1.30
VAULT_IP := 172.20.1.40
PAM_VAULT_IP := 172.20.1.50

# Certificate and PKI configuration
CA_COMMON_NAME := "IAM Security Lab CA"
CERT_VALIDITY_DAYS := 365
KEY_SIZE := 4096
CERT_DIR := certificates

# Compliance frameworks
COMPLIANCE_FRAMEWORKS := nist-800-63 sox gdpr iso-27001 hipaa

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

define log_security
	@echo "$(PURPLE)[SECURITY]$(NC) $(1)"
endef

# ============================================================================
# Installation and Environment Setup
# ============================================================================

install: ## Install all dependencies and setup IAM environment
	$(call log_info,"Installing Enterprise IAM dependencies...")
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
		$(call log_warning,"Vagrant is not installed. Advanced VM features may not be available."); \
	fi
	@$(MAKE) setup-directories
	@$(MAKE) setup-certificates
	@$(MAKE) setup-secrets
	@$(MAKE) docker-build
	$(call log_success,"IAM environment installation completed successfully!")

setup-directories: ## Create all necessary project directories
	$(call log_info,"Creating IAM project directory structure...")
	@mkdir -p $(DOCS_DIR)/{architecture,security,implementation,compliance}
	@mkdir -p $(SRC_DIR)/{configurations/{active-directory,ldap,saml-oauth,mfa,pam},scripts/{deployment,monitoring,security,maintenance},policies}
	@mkdir -p $(INFRASTRUCTURE_DIR)/{lab-setup/{active-directory,ldap-server,sso-providers,mfa-services,pam-solutions,monitoring},automation/{ansible,terraform,scripts},monitoring/{prometheus,grafana,elk}}
	@mkdir -p $(TESTS_DIR)/{security-validation/{authentication-tests,authorization-tests,sso-tests,mfa-tests,pam-tests,compliance-tests},penetration/{identity-attacks,privilege-escalation,sso-attacks,mfa-bypass,social-engineering},compliance/{nist-tests,iso27001-tests,sox-tests,gdpr-tests}}
	@mkdir -p $(MONITORING_DIR)/{identity-analytics/{user-behavior,access-patterns,risk-analytics,compliance-monitoring},reporting/{access-reports,compliance-dashboards,security-reports,audit-reports}}
	@mkdir -p $(TOOLS_DIR)/{identity-management/{user-provisioning,password-management,access-review,privilege-management},security/{identity-scanner,access-analyzer,privilege-auditor,compliance-checker},automation/{user-lifecycle,access-automation,compliance-automation}}
	@mkdir -p $(EXAMPLES_DIR)/{configs/{ad-configs,ldap-configs,sso-configs,mfa-configs,pam-configs},scenarios/{identity-lifecycle,access-scenarios,compliance-demos,security-incidents},reports/{identity-assessments,access-reviews,compliance-audits,penetration-tests}}
	@mkdir -p vagrant/provisioning
	@mkdir -p logs/{ad,ldap,keycloak,vault,mfa,pam,security,compliance} backup reports certificates secrets
	$(call log_success,"Directory structure created")

setup-certificates: ## Generate comprehensive PKI infrastructure for IAM
	$(call log_info,"Generating PKI certificates for IAM infrastructure...")
	@mkdir -p $(CERT_DIR)/{ca,server,client,ldap,saml,tls}
	# Root CA generation
	@openssl genrsa -out $(CERT_DIR)/ca/ca.key $(KEY_SIZE) 2>/dev/null
	@openssl req -new -x509 -days $(CERT_VALIDITY_DAYS) -key $(CERT_DIR)/ca/ca.key -out $(CERT_DIR)/ca/ca.crt -subj "/CN=$(CA_COMMON_NAME)/O=IAM Security Lab/C=US" 2>/dev/null
	# Intermediate CA for different services
	@openssl genrsa -out $(CERT_DIR)/ca/intermediate-ca.key $(KEY_SIZE) 2>/dev/null
	@openssl req -new -key $(CERT_DIR)/ca/intermediate-ca.key -out $(CERT_DIR)/ca/intermediate-ca.csr -subj "/CN=IAM Intermediate CA/O=IAM Security Lab/C=US" 2>/dev/null
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in $(CERT_DIR)/ca/intermediate-ca.csr -CA $(CERT_DIR)/ca/ca.crt -CAkey $(CERT_DIR)/ca/ca.key -CAcreateserial -out $(CERT_DIR)/ca/intermediate-ca.crt 2>/dev/null
	# Server certificates for different services
	@$(MAKE) generate-service-cert SERVICE=ad-server HOSTNAME=ad.$(AD_DOMAIN) IP=$(AD_SERVER_IP)
	@$(MAKE) generate-service-cert SERVICE=ldap-server HOSTNAME=ldap.$(AD_DOMAIN) IP=$(LDAP_SERVER_IP)
	@$(MAKE) generate-service-cert SERVICE=keycloak HOSTNAME=sso.$(AD_DOMAIN) IP=$(KEYCLOAK_IP)
	@$(MAKE) generate-service-cert SERVICE=vault HOSTNAME=vault.$(AD_DOMAIN) IP=$(VAULT_IP)
	@$(MAKE) generate-service-cert SERVICE=pam-vault HOSTNAME=pam.$(AD_DOMAIN) IP=$(PAM_VAULT_IP)
	# SAML signing certificates
	@openssl genrsa -out $(CERT_DIR)/saml/saml-signing.key $(KEY_SIZE) 2>/dev/null
	@openssl req -new -key $(CERT_DIR)/saml/saml-signing.key -out $(CERT_DIR)/saml/saml-signing.csr -subj "/CN=SAML Signing Certificate/O=IAM Security Lab/C=US" 2>/dev/null
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in $(CERT_DIR)/saml/saml-signing.csr -CA $(CERT_DIR)/ca/intermediate-ca.crt -CAkey $(CERT_DIR)/ca/intermediate-ca.key -CAcreateserial -out $(CERT_DIR)/saml/saml-signing.crt 2>/dev/null
	# Set proper permissions
	@chmod 600 $(CERT_DIR)/**/*.key
	@chmod 644 $(CERT_DIR)/**/*.crt
	$(call log_success,"PKI infrastructure generated successfully")

generate-service-cert: ## Generate certificate for specific service
	@openssl genrsa -out $(CERT_DIR)/server/$(SERVICE).key $(KEY_SIZE) 2>/dev/null
	@openssl req -new -key $(CERT_DIR)/server/$(SERVICE).key -out $(CERT_DIR)/server/$(SERVICE).csr -subj "/CN=$(HOSTNAME)/O=IAM Security Lab/C=US" 2>/dev/null
	@echo "subjectAltName=DNS:$(HOSTNAME),IP:$(IP)" > $(CERT_DIR)/server/$(SERVICE).ext
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in $(CERT_DIR)/server/$(SERVICE).csr -CA $(CERT_DIR)/ca/intermediate-ca.crt -CAkey $(CERT_DIR)/ca/intermediate-ca.key -CAcreateserial -out $(CERT_DIR)/server/$(SERVICE).crt -extensions v3_ca -extfile $(CERT_DIR)/server/$(SERVICE).ext 2>/dev/null
	@rm $(CERT_DIR)/server/$(SERVICE).ext

setup-secrets: ## Initialize secrets management for IAM services
	$(call log_info,"Setting up secrets management...")
	@mkdir -p secrets/{vault,keycloak,ad,ldap,database}
	@openssl rand -base64 32 > secrets/vault/vault-init-key
	@openssl rand -base64 32 > secrets/keycloak/admin-password
	@openssl rand -base64 32 > secrets/ad/admin-password
	@openssl rand -base64 32 > secrets/ldap/admin-password
	@openssl rand -base64 32 > secrets/database/postgres-password
	@chmod 600 secrets/**/*
	$(call log_success,"Secrets management initialized")

clean: ## Clean up all generated files and containers
	$(call log_warning,"Cleaning up IAM environment...")
	@$(MAKE) docker-clean
	@$(MAKE) vagrant-destroy
	@rm -rf certificates logs backup reports secrets
	@docker volume prune -f 2>/dev/null || true
	@docker network prune -f 2>/dev/null || true
	$(call log_success,"Environment cleaned up")

# ============================================================================
# IAM Lab Environment Deployment
# ============================================================================

lab-deploy: ## Deploy complete IAM lab environment
	$(call log_info,"Deploying Enterprise IAM Lab...")
	@$(MAKE) setup-network
	@$(MAKE) docker-build
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@sleep 45
	@$(MAKE) configure-services
	@$(MAKE) setup-monitoring
	@$(MAKE) validate-deployment
	$(call log_success,"IAM Lab deployed successfully!")
	@$(MAKE) status

lab-destroy: ## Destroy IAM lab environment
	$(call log_warning,"Destroying IAM Lab environment...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v
	@docker network rm $(IAM_NETWORK) 2>/dev/null || true
	$(call log_success,"Lab environment destroyed")

setup-network: ## Setup Docker network for IAM services
	$(call log_info,"Setting up IAM network...")
	@docker network inspect $(IAM_NETWORK) >/dev/null 2>&1 || \
		docker network create --driver bridge --subnet=$(IAM_SUBNET) $(IAM_NETWORK)
	$(call log_success,"IAM network configured")

configure-services: ## Configure all IAM services
	$(call log_info,"Configuring IAM services...")
	@$(MAKE) configure-ad
	@$(MAKE) configure-ldap
	@$(MAKE) configure-keycloak
	@$(MAKE) configure-vault
	@$(MAKE) configure-mfa
	@$(MAKE) configure-pam
	$(call log_success,"All IAM services configured")

# ============================================================================
# Active Directory Setup
# ============================================================================

setup-ad-domain: ## Setup Active Directory domain controller
	$(call log_info,"Setting up Active Directory domain...")
	@docker exec iam-ad-server /bin/bash -c "chmod +x /opt/scripts/setup-ad-domain.sh && /opt/scripts/setup-ad-domain.sh $(AD_DOMAIN)"
	@sleep 30
	@$(MAKE) validate-ad-domain
	$(call log_success,"Active Directory domain configured")

configure-ad: ## Configure Active Directory services
	$(call log_info,"Configuring Active Directory...")
	@docker exec iam-ad-server /bin/bash -c "/opt/scripts/configure-ad-security.sh"
	@docker exec iam-ad-server /bin/bash -c "/opt/scripts/setup-ad-users.sh"
	@docker exec iam-ad-server /bin/bash -c "/opt/scripts/configure-gpo.sh"
	$(call log_success,"Active Directory configured")

validate-ad-domain: ## Validate Active Directory domain setup
	$(call log_info,"Validating Active Directory domain...")
	@docker exec iam-ad-server /bin/bash -c "samba-tool domain level show"
	@docker exec iam-ad-server /bin/bash -c "samba-tool user list"

# ============================================================================
# LDAP Services Setup
# ============================================================================

configure-ldap: ## Configure LDAP directory services
	$(call log_info,"Configuring LDAP directory services...")
	@docker exec iam-ldap-server /bin/bash -c "/opt/scripts/setup-ldap-schema.sh"
	@docker exec iam-ldap-server /bin/bash -c "/opt/scripts/configure-ldap-security.sh"
	@docker exec iam-ldap-server /bin/bash -c "/opt/scripts/setup-ldap-replication.sh"
	$(call log_success,"LDAP services configured")

# ============================================================================
# Single Sign-On (SSO) Setup
# ============================================================================

setup-sso: ## Setup SSO with Keycloak
	$(call log_info,"Setting up Single Sign-On with Keycloak...")
	@$(MAKE) configure-keycloak
	@$(MAKE) setup-saml-providers
	@$(MAKE) setup-oauth-clients
	@$(MAKE) configure-federation
	$(call log_success,"SSO setup completed")

configure-keycloak: ## Configure Keycloak SSO provider
	$(call log_info,"Configuring Keycloak SSO provider...")
	@docker exec iam-keycloak /bin/bash -c "/opt/keycloak/bin/setup-keycloak.sh"
	@sleep 15
	@$(MAKE) validate-keycloak
	$(call log_success,"Keycloak configured")

setup-saml-providers: ## Setup SAML 2.0 identity providers
	$(call log_info,"Setting up SAML 2.0 identity providers...")
	@docker exec iam-keycloak /bin/bash -c "/opt/keycloak/bin/setup-saml-providers.sh"

setup-oauth-clients: ## Setup OAuth 2.0/OIDC clients
	$(call log_info,"Setting up OAuth 2.0/OIDC clients...")
	@docker exec iam-keycloak /bin/bash -c "/opt/keycloak/bin/setup-oauth-clients.sh"

configure-federation: ## Configure identity federation
	$(call log_info,"Configuring identity federation...")
	@docker exec iam-keycloak /bin/bash -c "/opt/keycloak/bin/setup-federation.sh"

validate-keycloak: ## Validate Keycloak configuration
	$(call log_info,"Validating Keycloak configuration...")
	@curl -f -s "http://localhost:$(KEYCLOAK_PORT)/auth/realms/master" > /dev/null
	$(call log_success,"Keycloak is responding")

# ============================================================================
# Multi-Factor Authentication (MFA) Setup
# ============================================================================

setup-mfa: ## Setup Multi-Factor Authentication
	$(call log_info,"Setting up Multi-Factor Authentication...")
	@$(MAKE) configure-mfa
	@$(MAKE) setup-totp
	@$(MAKE) setup-sms-gateway
	@$(MAKE) setup-hardware-tokens
	$(call log_success,"MFA setup completed")

configure-mfa: ## Configure MFA services
	$(call log_info,"Configuring MFA services...")
	@docker exec iam-mfa-server /bin/bash -c "/opt/scripts/setup-mfa-providers.sh"
	@docker exec iam-mfa-server /bin/bash -c "/opt/scripts/configure-mfa-policies.sh"

setup-totp: ## Setup TOTP (Time-based OTP) authentication
	$(call log_info,"Setting up TOTP authentication...")
	@docker exec iam-mfa-server /bin/bash -c "/opt/scripts/setup-totp-provider.sh"

setup-sms-gateway: ## Setup SMS gateway for OTP delivery
	$(call log_info,"Setting up SMS gateway...")
	@docker exec iam-mfa-server /bin/bash -c "/opt/scripts/setup-sms-gateway.sh"

setup-hardware-tokens: ## Setup hardware token support (FIDO2/U2F)
	$(call log_info,"Setting up hardware token support...")
	@docker exec iam-mfa-server /bin/bash -c "/opt/scripts/setup-fido2-support.sh"

# ============================================================================
# Privileged Access Management (PAM) Setup
# ============================================================================

setup-pam: ## Setup Privileged Access Management
	$(call log_info,"Setting up Privileged Access Management...")
	@$(MAKE) configure-pam-vault
	@$(MAKE) setup-session-management
	@$(MAKE) configure-approval-workflows
	@$(MAKE) setup-password-rotation
	$(call log_success,"PAM setup completed")

configure-pam-vault: ## Configure PAM vault for credential storage
	$(call log_info,"Configuring PAM vault...")
	@docker exec iam-pam-vault /bin/bash -c "/opt/scripts/setup-pam-vault.sh"
	@docker exec iam-pam-vault /bin/bash -c "/opt/scripts/configure-vault-policies.sh"

configure-vault: ## Configure HashiCorp Vault
	$(call log_info,"Configuring HashiCorp Vault...")
	@docker exec iam-vault /bin/bash -c "/opt/vault/scripts/init-vault.sh"
	@sleep 10
	@docker exec iam-vault /bin/bash -c "/opt/vault/scripts/configure-auth-methods.sh"
	@docker exec iam-vault /bin/bash -c "/opt/vault/scripts/setup-secret-engines.sh"

setup-session-management: ## Setup privileged session management
	$(call log_info,"Setting up privileged session management...")
	@docker exec iam-pam-vault /bin/bash -c "/opt/scripts/setup-session-recording.sh"

configure-approval-workflows: ## Configure approval workflows for privileged access
	$(call log_info,"Configuring approval workflows...")
	@docker exec iam-pam-vault /bin/bash -c "/opt/scripts/setup-approval-workflows.sh"

setup-password-rotation: ## Setup automatic password rotation
	$(call log_info,"Setting up password rotation...")
	@docker exec iam-pam-vault /bin/bash -c "/opt/scripts/setup-password-rotation.sh"

# ============================================================================
# Testing and Validation
# ============================================================================

test-all: security-tests performance-tests compliance-tests ## Run all test suites
	$(call log_success,"All tests completed successfully!")

security-tests: ## Run comprehensive security validation tests
	$(call log_security,"Running comprehensive security tests...")
	@$(MAKE) test-authentication
	@$(MAKE) test-authorization
	@$(MAKE) test-sso
	@$(MAKE) test-mfa
	@$(MAKE) test-pam-security
	@$(MAKE) identity-scan
	$(call log_success,"Security tests completed")

test-authentication: ## Test authentication mechanisms
	$(call log_info,"Testing authentication mechanisms...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/authentication-tests.sh"

test-authorization: ## Test authorization and access control
	$(call log_info,"Testing authorization mechanisms...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/authorization-tests.sh"

test-sso: ## Test Single Sign-On functionality
	$(call log_info,"Testing SSO functionality...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/sso-tests.sh"

test-mfa: ## Test Multi-Factor Authentication
	$(call log_info,"Testing MFA functionality...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/mfa-tests.sh"

test-pam-security: ## Test PAM security controls
	$(call log_info,"Testing PAM security controls...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/pam-security-tests.sh"

performance-tests: ## Run IAM performance tests
	$(call log_info,"Running performance tests...")
	@docker exec iam-test-client /bin/bash -c "/opt/tests/performance-tests.sh"

penetration-test: ## Run IAM penetration testing suite
	$(call log_warning,"Running IAM penetration tests...")
	@docker exec iam-pentest /bin/bash -c "/opt/pentest/identity-attacks.sh"
	@docker exec iam-pentest /bin/bash -c "/opt/pentest/privilege-escalation.sh"
	@docker exec iam-pentest /bin/bash -c "/opt/pentest/sso-attacks.sh"
	@docker exec iam-pentest /bin/bash -c "/opt/pentest/mfa-bypass.sh"
	$(call log_success,"Penetration testing completed")

compliance-tests: ## Run compliance validation tests
	$(call log_info,"Running compliance validation...")
	@for framework in $(COMPLIANCE_FRAMEWORKS); do \
		$(MAKE) test-compliance FRAMEWORK=$$framework; \
	done
	$(call log_success,"Compliance tests completed")

test-compliance: ## Test specific compliance framework
	$(call log_info,"Testing $(FRAMEWORK) compliance...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/test-$(FRAMEWORK).sh"

validate-iam: ## Validate complete IAM deployment
	$(call log_info,"Performing comprehensive IAM validation...")
	@$(MAKE) validate-ad-domain
	@$(MAKE) validate-keycloak
	@$(MAKE) validate-mfa
	@$(MAKE) validate-pam
	@$(MAKE) validate-compliance
	$(call log_success,"IAM deployment validation completed")

validate-deployment: ## Validate lab deployment
	$(call log_info,"Validating lab deployment...")
	@sleep 30
	@$(MAKE) validate-services
	@$(MAKE) health-check

validate-services: ## Validate all IAM services are running
	$(call log_info,"Validating IAM services...")
	@docker exec iam-ad-server systemctl is-active samba-ad-dc || echo "AD service not active"
	@docker exec iam-ldap-server systemctl is-active slapd || echo "LDAP service not active"
	@curl -f -s "http://localhost:$(KEYCLOAK_PORT)/auth/realms/master" >/dev/null || echo "Keycloak not responding"

validate-mfa: ## Validate MFA configuration
	$(call log_info,"Validating MFA configuration...")
	@docker exec iam-mfa-server /bin/bash -c "/opt/tests/validate-mfa.sh"

validate-pam: ## Validate PAM configuration
	$(call log_info,"Validating PAM configuration...")
	@docker exec iam-pam-vault /bin/bash -c "/opt/tests/validate-pam.sh"

validate-compliance: ## Validate compliance controls
	$(call log_info,"Validating compliance controls...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/validate-controls.sh"

# ============================================================================
# Security Analysis and Auditing
# ============================================================================

identity-scan: ## Perform identity security scanning
	$(call log_security,"Performing identity security scan...")
	@docker exec iam-security-scanner /bin/bash -c "/opt/scanner/identity-scan.sh"

privilege-audit: ## Audit privileged access and permissions
	$(call log_security,"Performing privilege audit...")
	@docker exec iam-privilege-auditor /bin/bash -c "/opt/auditor/privilege-audit.sh"

access-review: ## Perform access review and certification
	$(call log_info,"Performing access review...")
	@docker exec iam-access-reviewer /bin/bash -c "/opt/reviewer/access-review.sh"

security-assessment: ## Comprehensive security assessment
	$(call log_security,"Performing comprehensive security assessment...")
	@$(MAKE) identity-scan
	@$(MAKE) privilege-audit
	@$(MAKE) penetration-test
	@$(MAKE) compliance-assessment

compliance-assessment: ## Perform compliance assessment
	$(call log_info,"Performing compliance assessment...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/full-assessment.sh"

# ============================================================================
# Monitoring and Analytics
# ============================================================================

setup-monitoring: ## Setup IAM monitoring and analytics
	$(call log_info,"Setting up IAM monitoring...")
	@docker exec iam-prometheus /bin/bash -c "/opt/prometheus/setup-monitoring.sh"
	@docker exec iam-grafana /bin/bash -c "/opt/grafana/setup-dashboards.sh"
	@docker exec iam-elasticsearch /bin/bash -c "/opt/elasticsearch/setup-indices.sh"
	$(call log_success,"Monitoring setup completed")

dashboard: ## Open IAM monitoring dashboards
	$(call log_info,"Opening IAM dashboards...")
	@echo "$(CYAN)Grafana IAM Dashboard:$(NC) http://localhost:$(GRAFANA_PORT)"
	@echo "$(CYAN)Keycloak Admin Console:$(NC) http://localhost:$(KEYCLOAK_PORT)/auth/admin"
	@echo "$(CYAN)Vault UI:$(NC) http://localhost:8200/ui"
	@echo "$(CYAN)Kibana Analytics:$(NC) http://localhost:5601"
	@if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open http://localhost:$(GRAFANA_PORT); \
	elif command -v open >/dev/null 2>&1; then \
		open http://localhost:$(GRAFANA_PORT); \
	fi

logs: ## Show logs for all IAM services
	$(call log_info,"Displaying IAM service logs...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=50

status: ## Show status of all IAM components
	$(call log_info,"IAM Lab Status:")
	@echo "$(CYAN)================================================$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) ps
	@echo ""
	@echo "$(CYAN)Network Status:$(NC)"
	@docker network inspect $(IAM_NETWORK) --format "{{.Name}}: {{.IPAM.Config}}" 2>/dev/null || echo "Network not found"
	@echo ""
	@echo "$(CYAN)Service Health:$(NC)"
	@$(MAKE) validate-services

health-check: ## Perform comprehensive health check
	$(call log_info,"Performing comprehensive health check...")
	@$(MAKE) status
	@echo ""
	@echo "$(CYAN)Certificate Validation:$(NC)"
	@openssl x509 -in $(CERT_DIR)/ca/ca.crt -text -noout | grep "Not After" | sed 's/^/  CA Certificate: /' || echo "  CA Certificate: Not found"
	@echo ""
	@echo "$(CYAN)Service Connectivity:$(NC)"
	@docker exec iam-test-client ping -c 1 $(AD_SERVER_IP) > /dev/null 2>&1 && echo "  AD Server: ✓ Reachable" || echo "  AD Server: ✗ Unreachable"
	@docker exec iam-test-client ping -c 1 $(LDAP_SERVER_IP) > /dev/null 2>&1 && echo "  LDAP Server: ✓ Reachable" || echo "  LDAP Server: ✗ Unreachable"
	@docker exec iam-test-client ping -c 1 $(KEYCLOAK_IP) > /dev/null 2>&1 && echo "  Keycloak: ✓ Reachable" || echo "  Keycloak: ✗ Unreachable"

# ============================================================================
# Reporting and Documentation
# ============================================================================

compliance-report: ## Generate comprehensive compliance reports
	$(call log_info,"Generating compliance reports...")
	@mkdir -p reports/compliance
	@for framework in $(COMPLIANCE_FRAMEWORKS); do \
		docker exec iam-compliance-reporter /bin/bash -c "/opt/reports/generate-$(FRAMEWORK)-report.sh > /opt/reports/$(FRAMEWORK)-compliance-$(shell date +%Y%m%d).html"; \
	done
	@docker cp iam-compliance-reporter:/opt/reports/ ./reports/compliance/
	$(call log_success,"Compliance reports generated in ./reports/compliance/")

security-report: ## Generate comprehensive security report
	$(call log_info,"Generating security assessment report...")
	@mkdir -p reports/security
	@docker exec iam-security-reporter /bin/bash -c "/opt/reports/generate-security-report.sh > /opt/reports/security-assessment-$(shell date +%Y%m%d).html"
	@docker cp iam-security-reporter:/opt/reports/ ./reports/security/
	$(call log_success,"Security assessment report generated")

identity-report: ## Generate identity governance report
	$(call log_info,"Generating identity governance report...")
	@mkdir -p reports/identity
	@docker exec iam-identity-reporter /bin/bash -c "/opt/reports/generate-identity-report.sh > /opt/reports/identity-governance-$(shell date +%Y%m%d).html"
	@docker cp iam-identity-reporter:/opt/reports/ ./reports/identity/
	$(call log_success,"Identity governance report generated")

audit-report: ## Generate audit trail report
	$(call log_info,"Generating audit trail report...")
	@mkdir -p reports/audit
	@docker exec iam-audit-reporter /bin/bash -c "/opt/reports/generate-audit-report.sh > /opt/reports/audit-trail-$(shell date +%Y%m%d).html"
	@docker cp iam-audit-reporter:/opt/reports/ ./reports/audit/
	$(call log_success,"Audit trail report generated")

# ============================================================================
# Demo and Examples
# ============================================================================

demo-start: ## Start complete IAM demonstration
	$(call log_info,"Starting Enterprise IAM demonstration...")
	@$(MAKE) lab-deploy
	@sleep 45
	@$(MAKE) demo-scenarios
	$(call log_success,"IAM demonstration environment ready!")
	@echo ""
	@echo "$(GREEN)🎯 IAM Demo Environment Ready!$(NC)"
	@echo "$(CYAN)===========================================$(NC)"
	@echo "Identity Providers:"
	@echo "  • Active Directory: $(AD_DOMAIN)"
	@echo "  • LDAP Directory: $(LDAP_BASE_DN)"
	@echo "  • Keycloak SSO: http://localhost:$(KEYCLOAK_PORT)"
	@echo ""
	@echo "Management Interfaces:"
	@echo "  • Grafana Dashboard: http://localhost:$(GRAFANA_PORT)"
	@echo "  • Keycloak Admin: http://localhost:$(KEYCLOAK_PORT)/auth/admin"
	@echo "  • Vault UI: http://localhost:8200/ui"
	@echo "  • Kibana Analytics: http://localhost:5601"
	@echo ""
	@echo "Test Commands:"
	@echo "  • make security-tests        # Run security validation"
	@echo "  • make penetration-test      # Run penetration tests"
	@echo "  • make compliance-report     # Generate compliance reports"
	@echo "  • make access-review         # Perform access review"

demo-scenarios: ## Run demonstration scenarios
	$(call log_info,"Running IAM demonstration scenarios...")
	@docker exec iam-demo-runner /bin/bash -c "/opt/demo/identity-lifecycle-demo.sh"
	@docker exec iam-demo-runner /bin/bash -c "/opt/demo/sso-authentication-demo.sh"
	@docker exec iam-demo-runner /bin/bash -c "/opt/demo/mfa-enrollment-demo.sh"
	@docker exec iam-demo-runner /bin/bash -c "/opt/demo/privilege-access-demo.sh"

demo-stop: ## Stop demonstration environment
	$(call log_warning,"Stopping IAM demonstration...")
	@$(MAKE) lab-destroy
	$(call log_success,"Demonstration stopped")

# ============================================================================
# Backup and Restore
# ============================================================================

backup: ## Create backup of IAM configuration and data
	$(call log_info,"Creating IAM configuration backup...")
	@mkdir -p backup/$(shell date +%Y%m%d_%H%M%S)
	@docker exec iam-ad-server /bin/bash -c "tar -czf /tmp/ad-backup.tar.gz /var/lib/samba/"
	@docker exec iam-ldap-server /bin/bash -c "slapcat -l /tmp/ldap-backup.ldif"
	@docker exec iam-keycloak /bin/bash -c "/opt/keycloak/bin/standalone.sh -Djboss.socket.binding.port-offset=100 -Dkeycloak.migration.action=export -Dkeycloak.migration.provider=dir -Dkeycloak.migration.dir=/tmp/keycloak-backup"
	@docker cp iam-ad-server:/tmp/ad-backup.tar.gz backup/$(shell date +%Y%m%d_%H%M%S)/
	@docker cp iam-ldap-server:/tmp/ldap-backup.ldif backup/$(shell date +%Y%m%d_%H%M%S)/
	@docker cp iam-keycloak:/tmp/keycloak-backup backup/$(shell date +%Y%m%d_%H%M%S)/
	@cp -r certificates backup/$(shell date +%Y%m%d_%H%M%S)/
	@cp $(DOCKER_COMPOSE_FILE) backup/$(shell date +%Y%m%d_%H%M%S)/
	$(call log_success,"Backup created in backup/$(shell date +%Y%m%d_%H%M%S)/")

restore: ## Restore IAM configuration from backup
	$(call log_info,"Restoring IAM configuration...")
	@if [ -z "$(BACKUP_DIR)" ]; then \
		echo "$(RED)Please specify BACKUP_DIR: make restore BACKUP_DIR=backup/20241227_120000$(NC)"; \
		exit 1; \
	fi
	@if [ ! -d "$(BACKUP_DIR)" ]; then \
		echo "$(RED)Backup directory $(BACKUP_DIR) not found$(NC)"; \
		exit 1; \
	fi
	@docker cp $(BACKUP_DIR)/ad-backup.tar.gz iam-ad-server:/tmp/
	@docker cp $(BACKUP_DIR)/ldap-backup.ldif iam-ldap-server:/tmp/
	@docker cp $(BACKUP_DIR)/keycloak-backup iam-keycloak:/tmp/
	@docker exec iam-ad-server /bin/bash -c "cd / && tar -xzf /tmp/ad-backup.tar.gz"
	@docker exec iam-ldap-server /bin/bash -c "slapadd -l /tmp/ldap-backup.ldif"
	@cp -r $(BACKUP_DIR)/certificates ./
	$(call log_success,"Configuration restored from $(BACKUP_DIR)")

# ============================================================================
# Docker and Container Management
# ============================================================================

docker-build: ## Build all Docker images for IAM lab
	$(call log_info,"Building Docker images for IAM lab...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) build --no-cache
	$(call log_success,"Docker images built successfully")

docker-clean: ## Clean up Docker containers and images
	$(call log_warning,"Cleaning up Docker containers and images...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v --remove-orphans
	@docker image prune -f
	@docker container prune -f
	$(call log_success,"Docker cleanup completed")

docker-logs: ## Show logs for specific IAM service
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(RED)Please specify SERVICE: make docker-logs SERVICE=iam-keycloak$(NC)"; \
		exit 1; \
	fi
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f $(SERVICE)

docker-shell: ## Get shell access to specific IAM service container
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(RED)Please specify SERVICE: make docker-shell SERVICE=iam-keycloak$(NC)"; \
		exit 1; \
	fi
	@docker exec -it $(SERVICE) /bin/bash

# ============================================================================
# Vagrant Virtual Machines
# ============================================================================

vagrant-up: ## Start Vagrant IAM lab environment
	$(call log_info,"Starting Vagrant IAM lab...")
	@cd vagrant && vagrant up
	$(call log_success,"Vagrant IAM lab started")

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
# Advanced Features and Maintenance
# ============================================================================

update: ## Update IAM lab environment and dependencies
	$(call log_info,"Updating IAM lab environment...")
	@docker-compose -f $(DOCKER_COMPOSE_FILE) pull
	@$(MAKE) docker-build
	$(call log_success,"IAM lab environment updated")

rotate-secrets: ## Rotate all secrets and passwords
	$(call log_security,"Rotating secrets and passwords...")
	@docker exec iam-vault /bin/bash -c "/opt/vault/scripts/rotate-secrets.sh"
	@$(MAKE) setup-secrets
	$(call log_success,"Secrets rotation completed")

generate-user-cert: ## Generate client certificate for user authentication
	@if [ -z "$(USERNAME)" ]; then \
		echo "$(RED)Please specify USERNAME: make generate-user-cert USERNAME=john.doe$(NC)"; \
		exit 1; \
	fi
	$(call log_info,"Generating client certificate for $(USERNAME)...")
	@openssl genrsa -out $(CERT_DIR)/client/$(USERNAME).key $(KEY_SIZE)
	@openssl req -new -key $(CERT_DIR)/client/$(USERNAME).key -out $(CERT_DIR)/client/$(USERNAME).csr -subj "/CN=$(USERNAME)/O=IAM Security Lab/C=US"
	@openssl x509 -req -days $(CERT_VALIDITY_DAYS) -in $(CERT_DIR)/client/$(USERNAME).csr -CA $(CERT_DIR)/ca/intermediate-ca.crt -CAkey $(CERT_DIR)/ca/intermediate-ca.key -CAcreateserial -out $(CERT_DIR)/client/$(USERNAME).crt
	@chmod 600 $(CERT_DIR)/client/$(USERNAME).key
	@chmod 644 $(CERT_DIR)/client/$(USERNAME).crt
	$(call log_success,"Client certificate generated for $(USERNAME)")

simulate-attack: ## Simulate identity-based attack scenarios
	$(call log_warning,"Simulating identity attack scenarios...")
	@if [ -z "$(ATTACK_TYPE)" ]; then \
		echo "$(RED)Please specify ATTACK_TYPE: make simulate-attack ATTACK_TYPE=credential-stuffing$(NC)"; \
		echo "Available attacks: credential-stuffing, password-spray, kerberoasting, golden-ticket"; \
		exit 1; \
	fi
	@docker exec iam-attack-simulator /bin/bash -c "/opt/attacks/simulate-$(ATTACK_TYPE).sh"

user-lifecycle-demo: ## Demonstrate complete user lifecycle management
	$(call log_info,"Demonstrating user lifecycle management...")
	@docker exec iam-demo-runner /bin/bash -c "/opt/demo/complete-user-lifecycle.sh"

compliance-audit: ## Perform comprehensive compliance audit
	$(call log_info,"Performing comprehensive compliance audit...")
	@$(MAKE) compliance-tests
	@$(MAKE) compliance-report
	@$(MAKE) audit-report

# ============================================================================
# Help and Information
# ============================================================================

version: ## Display version information
	@echo "$(CYAN)Enterprise Identity & Access Management Lab$(NC)"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Project Directory: $(PROJECT_DIR)"

requirements: ## Display system requirements
	@echo "$(CYAN)System Requirements:$(NC)"
	@echo "• Docker Engine 20.10+ with at least 8GB RAM allocated"
	@echo "• Docker Compose 2.0+"
	@echo "• 16GB RAM minimum (32GB recommended for full lab)"
	@echo "• 50GB disk space for containers and data"
	@echo "• Vagrant 2.2+ (optional for VM-based lab)"
	@echo "• Active internet connection for container downloads"

services-info: ## Display information about IAM services
	@echo "$(CYAN)IAM Services Information:$(NC)"
	@echo "• Active Directory: Windows domain services and GPO management"
	@echo "• LDAP: Directory services with FreeIPA or 389DS"
	@echo "• Keycloak: SSO provider with SAML and OAuth support"
	@echo "• HashiCorp Vault: Secrets management and PKI"
	@echo "• MFA Services: TOTP, SMS, and hardware token support"
	@echo "• PAM Vault: Privileged access management and session recording"

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
	@echo "   make docker-logs SERVICE=iam-keycloak"
	@echo ""
	@echo "5. Health check:"
	@echo "   make health-check"
	@echo ""
	@echo "6. Complete reset:"
	@echo "   make clean && make install && make lab-deploy"

# ============================================================================
# Compliance and Security Standards
# ============================================================================

nist-compliance: ## Validate NIST 800-63 compliance
	$(call log_info,"Validating NIST 800-63 compliance...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/nist-800-63-validation.sh"

sox-compliance: ## Validate SOX compliance
	$(call log_info,"Validating SOX compliance...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/sox-validation.sh"

gdpr-compliance: ## Validate GDPR compliance
	$(call log_info,"Validating GDPR compliance...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/gdpr-validation.sh"

iso27001-compliance: ## Validate ISO 27001 compliance
	$(call log_info,"Validating ISO 27001 compliance...")
	@docker exec iam-compliance-checker /bin/bash -c "/opt/compliance/iso27001-validation.sh"

security-benchmarks: ## Run security benchmarking
	$(call log_security,"Running security benchmarks...")
	@docker exec iam-security-scanner /bin/bash -c "/opt/scanner/security-benchmarks.sh"