# ==============================================================================
# Cloud Security & Governance Automation Framework
# ==============================================================================
# A comprehensive Makefile for automating cloud security deployments,
# compliance checking, policy enforcement, and governance across multi-cloud
# environments (AWS, Azure, GCP).
# ==============================================================================

# Project Configuration
PROJECT_NAME := cloud-security-governance
VERSION := 1.0.0
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)
USER := $(shell whoami)

# Directory Structure
PROJECT_DIR := $(shell pwd)
SCRIPTS_DIR := $(PROJECT_DIR)/scripts
TERRAFORM_DIR := $(PROJECT_DIR)/terraform
K8S_DIR := $(PROJECT_DIR)/kubernetes
TOOLS_DIR := $(PROJECT_DIR)/tools
COMPLIANCE_DIR := $(PROJECT_DIR)/compliance
MONITORING_DIR := $(PROJECT_DIR)/monitoring
POLICIES_DIR := $(PROJECT_DIR)/policies

# Docker Configuration
DOCKER_NETWORK := cloud-security-net
DOCKER_COMPOSE_FILE := docker-compose.yml
DOCKER_COMPOSE_OVERRIDE := docker-compose.override.yml

# Cloud Configuration
AWS_REGION ?= us-east-1
AWS_PROFILE ?= default
AZURE_LOCATION ?= East US
GCP_PROJECT ?= your-project-id
GCP_REGION ?= us-central1
GCP_ZONE ?= us-central1-a

# Security Configuration
SECURITY_BASELINE := cis-benchmark
COMPLIANCE_FRAMEWORKS := soc2,iso27001,nist,pci-dss,hipaa
POLICY_ENGINE := opa
CSPM_TOOLS := prisma,cloudguard,scout-suite

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
	@echo "                    Cloud Security & Governance Framework"
	@echo "=================================================================================="$(NC)
	@echo ""
	@echo "$(GREEN)INSTALLATION & SETUP:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^install/) printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)CLOUD INFRASTRUCTURE:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^deploy-|^destroy-|^plan-/) printf "  $(CYAN)%-20s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)SECURITY & COMPLIANCE:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^scan-|^audit-|^compliance-|^security-/) printf "  $(RED)%-20s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)LAB ENVIRONMENT:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^lab-|^demo-/) printf "  $(PURPLE)%-20s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)MONITORING & DASHBOARDS:$(NC)"
	@awk '/^[a-zA-Z_-]+:.*?## .*$$/ { if (/^monitor-|^dashboard-|^alerts-/) printf "  $(WHITE)%-20s$(NC) %s\n", $$1, substr($$0, index($$0, "## ") + 3) }' $(MAKEFILE_LIST)
	@echo ""

# ==============================================================================
# INSTALLATION & SETUP
# ==============================================================================

.PHONY: install install-tools install-terraform install-k8s install-python check-deps
install: check-deps install-tools install-terraform install-k8s install-python ## Install all dependencies and tools
	@echo "$(GREEN)✓ Cloud Security & Governance framework installation completed!$(NC)"

check-deps: ## Check system dependencies
	@echo "$(BLUE)Checking system dependencies...$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)❌ Docker is required but not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(RED)❌ Docker Compose is required$(NC)"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)❌ Python 3 is required$(NC)"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "$(RED)❌ Git is required$(NC)"; exit 1; }
	@echo "$(GREEN)✓ All system dependencies are available$(NC)"

install-tools: ## Install security and cloud tools
	@echo "$(BLUE)Installing cloud security tools...$(NC)"
	@mkdir -p $(TOOLS_DIR)
	
	# Install AWS CLI
	@if ! command -v aws >/dev/null 2>&1; then \
		echo "Installing AWS CLI..."; \
		curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"; \
		cd /tmp && unzip awscliv2.zip && sudo ./aws/install; \
	fi
	
	# Install Azure CLI
	@if ! command -v az >/dev/null 2>&1; then \
		echo "Installing Azure CLI..."; \
		curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash; \
	fi
	
	# Install Google Cloud SDK
	@if ! command -v gcloud >/dev/null 2>&1; then \
		echo "Installing Google Cloud SDK..."; \
		curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-latest-linux-x86_64.tar.gz -o /tmp/gcloud.tar.gz; \
		cd /tmp && tar -xf gcloud.tar.gz && ./google-cloud-sdk/install.sh --quiet; \
	fi
	
	# Install Scout Suite (multi-cloud security auditing)
	@pip3 install --user scoutsuite
	
	# Install Prowler (AWS security assessment)
	@pip3 install --user prowler
	
	# Install TruffleHog (secrets detection)
	@pip3 install --user truffleHog
	
	@echo "$(GREEN)✓ Cloud security tools installed$(NC)"

install-terraform: ## Install Terraform and related tools
	@echo "$(BLUE)Installing Terraform and IaC tools...$(NC)"
	
	# Install Terraform
	@if ! command -v terraform >/dev/null 2>&1; then \
		TERRAFORM_VERSION=1.6.0; \
		wget https://releases.hashicorp.com/terraform/$${TERRAFORM_VERSION}/terraform_$${TERRAFORM_VERSION}_linux_amd64.zip -O /tmp/terraform.zip; \
		cd /tmp && unzip terraform.zip && sudo mv terraform /usr/local/bin/; \
	fi
	
	# Install Terragrunt
	@if ! command -v terragrunt >/dev/null 2>&1; then \
		TERRAGRUNT_VERSION=0.53.0; \
		wget https://github.com/gruntwork-io/terragrunt/releases/download/v$${TERRAGRUNT_VERSION}/terragrunt_linux_amd64 -O /tmp/terragrunt; \
		sudo mv /tmp/terragrunt /usr/local/bin/ && sudo chmod +x /usr/local/bin/terragrunt; \
	fi
	
	# Install TFLint (Terraform linter)
	@if ! command -v tflint >/dev/null 2>&1; then \
		curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash; \
	fi
	
	# Install Checkov (security scanner for IaC)
	@pip3 install --user checkov
	
	@echo "$(GREEN)✓ Terraform and IaC tools installed$(NC)"

install-k8s: ## Install Kubernetes tools
	@echo "$(BLUE)Installing Kubernetes tools...$(NC)"
	
	# Install kubectl
	@if ! command -v kubectl >/dev/null 2>&1; then \
		curl -LO "https://dl.k8s.io/release/$$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"; \
		sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl; \
	fi
	
	# Install Helm
	@if ! command -v helm >/dev/null 2>&1; then \
		curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; \
	fi
	
	# Install OPA (Open Policy Agent)
	@if ! command -v opa >/dev/null 2>&1; then \
		curl -L -o /tmp/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static; \
		sudo mv /tmp/opa /usr/local/bin/ && sudo chmod +x /usr/local/bin/opa; \
	fi
	
	# Install Falco CLI
	@curl -s https://falco.org/script/install | sudo bash
	
	@echo "$(GREEN)✓ Kubernetes tools installed$(NC)"

install-python: ## Install Python security libraries
	@echo "$(BLUE)Installing Python security libraries...$(NC)"
	@pip3 install --user -r requirements.txt
	@echo "$(GREEN)✓ Python security libraries installed$(NC)"

.PHONY: configure-credentials configure-aws configure-azure configure-gcp
configure-credentials: configure-aws configure-azure configure-gcp ## Configure all cloud provider credentials
	@echo "$(GREEN)✓ All cloud credentials configured$(NC)"

configure-aws: ## Configure AWS credentials and settings
	@echo "$(BLUE)Configuring AWS credentials...$(NC)"
	@aws configure list-profiles >/dev/null 2>&1 || aws configure
	@aws sts get-caller-identity >/dev/null 2>&1 && echo "$(GREEN)✓ AWS credentials validated$(NC)" || echo "$(RED)❌ AWS credentials invalid$(NC)"

configure-azure: ## Configure Azure credentials
	@echo "$(BLUE)Configuring Azure credentials...$(NC)"
	@az login --output none 2>/dev/null || echo "$(YELLOW)⚠ Please run 'az login' manually$(NC)"
	@az account show >/dev/null 2>&1 && echo "$(GREEN)✓ Azure credentials validated$(NC)" || echo "$(RED)❌ Azure credentials invalid$(NC)"

configure-gcp: ## Configure Google Cloud credentials
	@echo "$(BLUE)Configuring Google Cloud credentials...$(NC)"
	@gcloud auth list --format="value(account)" | head -1 >/dev/null 2>&1 || gcloud auth login
	@gcloud config set project $(GCP_PROJECT) 2>/dev/null || echo "$(YELLOW)⚠ Please set GCP_PROJECT variable$(NC)"
	@echo "$(GREEN)✓ Google Cloud credentials configured$(NC)"

# ==============================================================================
# CLOUD INFRASTRUCTURE DEPLOYMENT
# ==============================================================================

.PHONY: deploy-all deploy-aws deploy-azure deploy-gcp plan-all destroy-all
deploy-all: deploy-aws deploy-azure deploy-gcp ## Deploy security infrastructure to all cloud providers
	@echo "$(GREEN)✓ Multi-cloud security infrastructure deployed successfully!$(NC)"

plan-all: ## Plan infrastructure changes for all cloud providers
	@echo "$(BLUE)Planning infrastructure changes...$(NC)"
	@cd $(TERRAFORM_DIR)/aws && terraform plan -out=aws.tfplan
	@cd $(TERRAFORM_DIR)/azure && terraform plan -out=azure.tfplan
	@cd $(TERRAFORM_DIR)/gcp && terraform plan -out=gcp.tfplan
	@echo "$(GREEN)✓ Infrastructure plans generated$(NC)"

deploy-aws: ## Deploy AWS security infrastructure
	@echo "$(BLUE)Deploying AWS security infrastructure...$(NC)"
	@cd $(TERRAFORM_DIR)/aws && \
		terraform init && \
		terraform plan -out=aws.tfplan && \
		terraform apply aws.tfplan
	@echo "$(GREEN)✓ AWS security infrastructure deployed$(NC)"

deploy-azure: ## Deploy Azure security infrastructure
	@echo "$(BLUE)Deploying Azure security infrastructure...$(NC)"
	@cd $(TERRAFORM_DIR)/azure && \
		terraform init && \
		terraform plan -out=azure.tfplan && \
		terraform apply azure.tfplan
	@echo "$(GREEN)✓ Azure security infrastructure deployed$(NC)"

deploy-gcp: ## Deploy GCP security infrastructure
	@echo "$(BLUE)Deploying GCP security infrastructure...$(NC)"
	@cd $(TERRAFORM_DIR)/gcp && \
		terraform init && \
		terraform plan -out=gcp.tfplan && \
		terraform apply gcp.tfplan
	@echo "$(GREEN)✓ GCP security infrastructure deployed$(NC)"

destroy-all: ## Destroy all cloud infrastructure (USE WITH CAUTION!)
	@echo "$(RED)⚠ WARNING: This will destroy ALL cloud infrastructure!$(NC)"
	@echo "$(YELLOW)Press Ctrl+C to cancel, or wait 10 seconds to proceed...$(NC)"
	@sleep 10
	@cd $(TERRAFORM_DIR)/aws && terraform destroy -auto-approve
	@cd $(TERRAFORM_DIR)/azure && terraform destroy -auto-approve
	@cd $(TERRAFORM_DIR)/gcp && terraform destroy -auto-approve
	@echo "$(RED)✓ All cloud infrastructure destroyed$(NC)"

# ==============================================================================
# SECURITY SCANNING & COMPLIANCE
# ==============================================================================

.PHONY: scan-all scan-infrastructure scan-containers scan-secrets audit-compliance
scan-all: scan-infrastructure scan-containers scan-secrets ## Run all security scans
	@echo "$(GREEN)✓ Comprehensive security scanning completed!$(NC)"

scan-infrastructure: ## Scan infrastructure for security vulnerabilities
	@echo "$(BLUE)Scanning infrastructure for security issues...$(NC)"
	
	# Scan Terraform configurations with Checkov
	@mkdir -p reports/checkov
	@checkov -d $(TERRAFORM_DIR) --framework terraform --output json > reports/checkov/terraform_scan_$(TIMESTAMP).json
	@checkov -d $(K8S_DIR) --framework kubernetes --output json > reports/checkov/k8s_scan_$(TIMESTAMP).json
	
	# Scan with TFLint
	@mkdir -p reports/tflint
	@find $(TERRAFORM_DIR) -name "*.tf" -exec dirname {} \; | sort -u | while read dir; do \
		echo "Scanning $$dir with TFLint..."; \
		cd $$dir && tflint --format=json > $(PROJECT_DIR)/reports/tflint/$$(basename $$dir)_$(TIMESTAMP).json; \
	done
	
	# Run Scout Suite for multi-cloud assessment
	@mkdir -p reports/scout-suite
	@python3 -m ScoutSuite aws --report-dir reports/scout-suite/aws_$(TIMESTAMP) --no-browser || true
	@python3 -m ScoutSuite azure --report-dir reports/scout-suite/azure_$(TIMESTAMP) --no-browser || true
	@python3 -m ScoutSuite gcp --report-dir reports/scout-suite/gcp_$(TIMESTAMP) --no-browser || true
	
	@echo "$(GREEN)✓ Infrastructure security scanning completed$(NC)"

scan-containers: ## Scan container images for vulnerabilities
	@echo "$(BLUE)Scanning container images...$(NC)"
	@mkdir -p reports/container-scan
	
	# Scan Docker images with Trivy
	@if command -v trivy >/dev/null 2>&1; then \
		docker images --format "table {{.Repository}}:{{.Tag}}" | grep -v REPOSITORY | while read image; do \
			echo "Scanning $$image..."; \
			trivy image --format json --output reports/container-scan/$$(echo $$image | tr '/:' '_')_$(TIMESTAMP).json $$image; \
		done; \
	else \
		echo "$(YELLOW)⚠ Trivy not installed, skipping container scanning$(NC)"; \
	fi
	
	@echo "$(GREEN)✓ Container security scanning completed$(NC)"

scan-secrets: ## Scan codebase for secrets and sensitive information
	@echo "$(BLUE)Scanning for secrets and sensitive data...$(NC)"
	@mkdir -p reports/secrets
	
	# Scan with TruffleHog
	@python3 -m truffleHog --json --regex . > reports/secrets/truffleHog_$(TIMESTAMP).json
	
	# Scan with GitLeaks (if available)
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --source . --report-format json --report-path reports/secrets/gitleaks_$(TIMESTAMP).json; \
	fi
	
	@echo "$(GREEN)✓ Secrets scanning completed$(NC)"

audit-compliance: ## Run compliance audits against security frameworks
	@echo "$(BLUE)Running compliance audits...$(NC)"
	@mkdir -p reports/compliance
	
	# CIS Benchmark assessment
	@echo "Running CIS Benchmark assessment..."
	@python3 $(SCRIPTS_DIR)/compliance/cis_assessment.py --output reports/compliance/cis_$(TIMESTAMP).json
	
	# SOC 2 compliance check
	@echo "Running SOC 2 compliance assessment..."
	@python3 $(SCRIPTS_DIR)/compliance/soc2_assessment.py --output reports/compliance/soc2_$(TIMESTAMP).json
	
	# NIST Framework assessment
	@echo "Running NIST Framework assessment..."
	@python3 $(SCRIPTS_DIR)/compliance/nist_assessment.py --output reports/compliance/nist_$(TIMESTAMP).json
	
	@echo "$(GREEN)✓ Compliance auditing completed$(NC)"

.PHONY: security-baseline security-hardening policy-validation
security-baseline: ## Apply security baseline configurations
	@echo "$(BLUE)Applying security baseline configurations...$(NC)"
	
	# Apply AWS security baseline
	@cd $(TERRAFORM_DIR)/aws && terraform apply -var="security_baseline=enabled" -auto-approve
	
	# Apply Azure security baseline
	@cd $(TERRAFORM_DIR)/azure && terraform apply -var="security_baseline=enabled" -auto-approve
	
	# Apply GCP security baseline
	@cd $(TERRAFORM_DIR)/gcp && terraform apply -var="security_baseline=enabled" -auto-approve
	
	@echo "$(GREEN)✓ Security baseline applied across all environments$(NC)"

policy-validation: ## Validate security policies with OPA
	@echo "$(BLUE)Validating security policies...$(NC)"
	@mkdir -p reports/policy-validation
	
	# Test OPA policies
	@opa test $(POLICIES_DIR) --verbose --format json > reports/policy-validation/opa_tests_$(TIMESTAMP).json
	
	# Validate Kubernetes policies
	@find $(K8S_DIR) -name "*.yaml" -o -name "*.yml" | while read file; do \
		echo "Validating $$file against policies..."; \
		opa eval --data $(POLICIES_DIR) --input $$file "data.kubernetes.admission.deny[x]" || true; \
	done
	
	@echo "$(GREEN)✓ Policy validation completed$(NC)"

# ==============================================================================
# LAB ENVIRONMENT MANAGEMENT
# ==============================================================================

.PHONY: lab-start lab-stop lab-restart lab-status lab-logs demo-environment
lab-start: ## Start the cloud security lab environment
	@echo "$(BLUE)Starting Cloud Security & Governance Lab...$(NC)"
	@docker network create $(DOCKER_NETWORK) 2>/dev/null || true
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "$(GREEN)✓ Lab environment started successfully!$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Access Points:$(NC)"
	@echo "• Grafana Dashboard: http://localhost:3000 (admin/admin123)"
	@echo "• Prometheus Metrics: http://localhost:9090"
	@echo "• Elasticsearch: http://localhost:9200"
	@echo "• Kibana Dashboard: http://localhost:5601"
	@echo "• Jaeger Tracing: http://localhost:16686"
	@echo "• OPA Policy Server: http://localhost:8181"
	@echo "• Falco Dashboard: http://localhost:8080"

lab-stop: ## Stop the lab environment
	@echo "$(BLUE)Stopping Cloud Security & Governance Lab...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down
	@echo "$(GREEN)✓ Lab environment stopped$(NC)"

lab-restart: lab-stop lab-start ## Restart the lab environment
	@echo "$(GREEN)✓ Lab environment restarted$(NC)"

lab-status: ## Show lab environment status
	@echo "$(BLUE)Cloud Security & Governance Lab Status:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) ps

lab-logs: ## Show lab environment logs
	@echo "$(BLUE)Cloud Security & Governance Lab Logs:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=100

demo-environment: ## Deploy demo applications for security testing
	@echo "$(BLUE)Deploying demo applications...$(NC)"
	@kubectl apply -f $(K8S_DIR)/demo-apps/
	@echo "$(GREEN)✓ Demo applications deployed$(NC)"

# ==============================================================================
# MONITORING & DASHBOARDS
# ==============================================================================

.PHONY: monitor-start dashboard-open alerts-configure metrics-collect
monitor-start: ## Start monitoring stack
	@echo "$(BLUE)Starting monitoring infrastructure...$(NC)"
	@helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	@helm repo add grafana https://grafana.github.io/helm-charts
	@helm repo add elastic https://helm.elastic.co
	@helm repo update
	
	# Deploy Prometheus
	@helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
		--namespace monitoring --create-namespace \
		--values $(MONITORING_DIR)/prometheus-values.yaml
	
	# Deploy ELK Stack
	@helm upgrade --install elasticsearch elastic/elasticsearch \
		--namespace logging --create-namespace \
		--values $(MONITORING_DIR)/elasticsearch-values.yaml
	
	@helm upgrade --install kibana elastic/kibana \
		--namespace logging \
		--values $(MONITORING_DIR)/kibana-values.yaml
	
	@echo "$(GREEN)✓ Monitoring stack deployed$(NC)"

dashboard-open: ## Open security dashboards in browser
	@echo "$(BLUE)Opening security dashboards...$(NC)"
	@kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80 &
	@kubectl port-forward -n logging svc/kibana-kibana 5601:5601 &
	@kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &
	@sleep 5
	@echo "$(GREEN)✓ Dashboards accessible at:$(NC)"
	@echo "• Grafana: http://localhost:3000"
	@echo "• Kibana: http://localhost:5601"
	@echo "• Prometheus: http://localhost:9090"

alerts-configure: ## Configure security alerts and notifications
	@echo "$(BLUE)Configuring security alerts...$(NC)"
	@kubectl apply -f $(MONITORING_DIR)/alerts/
	@echo "$(GREEN)✓ Security alerts configured$(NC)"

metrics-collect: ## Collect and export security metrics
	@echo "$(BLUE)Collecting security metrics...$(NC)"
	@mkdir -p reports/metrics
	@python3 $(SCRIPTS_DIR)/metrics/collect_security_metrics.py \
		--output reports/metrics/security_metrics_$(TIMESTAMP).json
	@echo "$(GREEN)✓ Security metrics collected$(NC)"

# ==============================================================================
# TESTING & VALIDATION
# ==============================================================================

.PHONY: test-all test-policies test-infrastructure test-compliance
test-all: test-policies test-infrastructure test-compliance ## Run all tests
	@echo "$(GREEN)✓ All tests completed successfully!$(NC)"

test-policies: ## Test security policies and governance rules
	@echo "$(BLUE)Testing security policies...$(NC)"
	@python3 -m pytest $(SCRIPTS_DIR)/tests/test_policies.py -v
	@echo "$(GREEN)✓ Policy tests completed$(NC)"

test-infrastructure: ## Test infrastructure security configurations
	@echo "$(BLUE)Testing infrastructure security...$(NC)"
	@python3 -m pytest $(SCRIPTS_DIR)/tests/test_infrastructure.py -v
	@echo "$(GREEN)✓ Infrastructure tests completed$(NC)"

test-compliance: ## Test compliance framework implementations
	@echo "$(BLUE)Testing compliance frameworks...$(NC)"
	@python3 -m pytest $(SCRIPTS_DIR)/tests/test_compliance.py -v
	@echo "$(GREEN)✓ Compliance tests completed$(NC)"

# ==============================================================================
# BACKUP & RECOVERY
# ==============================================================================

.PHONY: backup-create backup-restore backup-list
backup-create: ## Create backup of security configurations and data
	@echo "$(BLUE)Creating security configuration backup...$(NC)"
	@mkdir -p backups
	@tar -czf backups/cloud-security-backup-$(TIMESTAMP).tar.gz \
		$(TERRAFORM_DIR) $(K8S_DIR) $(POLICIES_DIR) $(COMPLIANCE_DIR)
	@echo "$(GREEN)✓ Backup created: backups/cloud-security-backup-$(TIMESTAMP).tar.gz$(NC)"

backup-restore: ## Restore from backup (specify BACKUP_FILE=filename)
	@echo "$(BLUE)Restoring from backup: $(BACKUP_FILE)$(NC)"
	@if [ -z "$(BACKUP_FILE)" ]; then echo "$(RED)❌ Please specify BACKUP_FILE=filename$(NC)"; exit 1; fi
	@tar -xzf backups/$(BACKUP_FILE)
	@echo "$(GREEN)✓ Backup restored successfully$(NC)"

backup-list: ## List available backups
	@echo "$(BLUE)Available backups:$(NC)"
	@ls -la backups/ || echo "$(YELLOW)⚠ No backups found$(NC)"

# ==============================================================================
# CLEANUP & MAINTENANCE
# ==============================================================================

.PHONY: cleanup-reports cleanup-containers cleanup-all
cleanup-reports: ## Clean up old reports and logs
	@echo "$(BLUE)Cleaning up old reports...$(NC)"
	@find reports/ -name "*.json" -mtime +30 -delete 2>/dev/null || true
	@find reports/ -name "*.html" -mtime +30 -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Old reports cleaned up$(NC)"

cleanup-containers: ## Clean up unused Docker containers and images
	@echo "$(BLUE)Cleaning up Docker resources...$(NC)"
	@docker system prune -f
	@docker volume prune -f
	@echo "$(GREEN)✓ Docker resources cleaned up$(NC)"

cleanup-all: cleanup-reports cleanup-containers ## Clean up all temporary files and resources
	@echo "$(GREEN)✓ Complete cleanup finished$(NC)"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

.PHONY: version logs status requirements
version: ## Show version information
	@echo "$(BLUE)Cloud Security & Governance Framework$(NC)"
	@echo "Version: $(VERSION)"
	@echo "Timestamp: $(TIMESTAMP)"
	@echo "User: $(USER)"

logs: ## Show recent application logs
	@echo "$(BLUE)Recent application logs:$(NC)"
	@journalctl -u docker -n 50 --no-pager

status: ## Show overall system status
	@echo "$(BLUE)System Status Overview:$(NC)"
	@echo ""
	@echo "$(CYAN)Docker Status:$(NC)"
	@docker version --format "Client: {{.Client.Version}}, Server: {{.Server.Version}}"
	@echo ""
	@echo "$(CYAN)Cloud CLI Status:$(NC)"
	@aws --version 2>/dev/null || echo "AWS CLI: Not available"
	@az version --output tsv --query '"azure-cli"' 2>/dev/null || echo "Azure CLI: Not available"
	@gcloud version --format="value(Google Cloud SDK)" 2>/dev/null || echo "GCP SDK: Not available"
	@echo ""
	@echo "$(CYAN)Security Tools Status:$(NC)"
	@terraform version | head -1 2>/dev/null || echo "Terraform: Not available"
	@kubectl version --client --short 2>/dev/null || echo "kubectl: Not available"
	@opa version 2>/dev/null || echo "OPA: Not available"

requirements: ## Generate requirements.txt for Python dependencies
	@echo "$(BLUE)Generating requirements.txt...$(NC)"
	@cat > requirements.txt << 'EOF'
# Cloud Security & Governance Python Dependencies
# Security Scanning
scoutsuite>=5.12.0
prowler>=4.0.0
checkov>=3.0.0
bandit>=1.7.5
safety>=3.0.0

# Cloud SDKs
boto3>=1.34.0
azure-identity>=1.15.0
azure-mgmt-security>=5.0.0
google-cloud-security-center>=1.23.0

# Policy & Compliance
policyengine>=0.1.0
compliance-checker>=5.0.0

# Monitoring & Logging
prometheus-client>=0.19.0
elasticsearch>=8.11.0
grafana-api>=1.0.3

# Automation & Orchestration
ansible>=8.0.0
kubernetes>=28.0.0
docker>=6.1.0

# Data Analysis & Reporting
pandas>=2.1.0
matplotlib>=3.8.0
jinja2>=3.1.2
pyyaml>=6.0.1
requests>=2.31.0

# Testing
pytest>=7.4.0
pytest-mock>=3.12.0
pytest-cov>=4.1.0
EOF
	@echo "$(GREEN)✓ requirements.txt generated$(NC)"

# This will allow make to work with file targets that might not exist
%: 
	@:

.DEFAULT_GOAL := help