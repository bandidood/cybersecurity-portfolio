# Secure Network Design & Zero Trust Architecture - Makefile
# Project: 06-secure-network-design
# Description: Automation for network design, deployment, and security validation

.PHONY: help clean install lab-start lab-stop deploy-network validate-security

# Variables
COMPOSE_FILE := docker-compose.yml
GNS3_PROJECT := secure-network-lab
ANSIBLE_DIR := infrastructure/ansible
TERRAFORM_DIR := infrastructure/terraform
PYTHON_VENV := .venv
NETWORK_INVENTORY := infrastructure/ansible/inventories/lab.yml

# Default target
.DEFAULT_GOAL := help

## Help target - Display available targets
help:
	@echo "🛡️ Secure Network Design & Zero Trust Architecture"
	@echo "=================================================="
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "🏗️  Environment Setup:"
	@echo "  install                Install dependencies and setup environment"
	@echo "  clean                  Clean up generated files and lab environment"
	@echo "  check-deps            Check required dependencies"
	@echo ""
	@echo "🧪 Lab Environment:"
	@echo "  lab-start             Start GNS3/Docker network simulation lab"
	@echo "  lab-stop              Stop network simulation lab"
	@echo "  lab-restart           Restart lab environment"
	@echo "  lab-status            Show lab environment status"
	@echo "  lab-logs              Show lab environment logs"
	@echo ""
	@echo "🌐 Network Deployment:"
	@echo "  deploy-base-network   Deploy base network infrastructure"
	@echo "  configure-segmentation Configure VLAN segmentation"
	@echo "  deploy-zero-trust     Implement Zero Trust controls"
	@echo "  configure-security-policies Configure security policies"
	@echo "  deploy-monitoring     Deploy network monitoring stack"
	@echo ""
	@echo "🔐 Security & Compliance:"
	@echo "  validate-network      Validate network configuration and security"
	@echo "  security-scan         Run comprehensive security scanning"
	@echo "  compliance-check      Check compliance with frameworks"
	@echo "  penetration-test      Run penetration testing scenarios"
	@echo ""
	@echo "📊 Monitoring & Analysis:"
	@echo "  start-monitoring      Start monitoring and visibility stack"
	@echo "  stop-monitoring       Stop monitoring services"
	@echo "  network-topology      Generate network topology diagram"
	@echo "  traffic-analysis      Analyze network traffic patterns"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test                  Run all tests"
	@echo "  test-connectivity     Test network connectivity"
	@echo "  test-segmentation     Test VLAN segmentation"
	@echo "  test-policies         Test security policy enforcement"
	@echo "  test-performance      Test network performance"
	@echo ""
	@echo "📖 Documentation:"
	@echo "  docs-build            Build documentation"
	@echo "  docs-serve            Serve documentation locally"
	@echo "  generate-configs      Generate configuration examples"
	@echo ""

## Environment Setup
install:
	@echo "🔧 Installing dependencies and setting up environment..."
	# Create Python virtual environment
	python3 -m venv $(PYTHON_VENV)
	$(PYTHON_VENV)/bin/pip install --upgrade pip
	$(PYTHON_VENV)/bin/pip install -r requirements.txt
	# Install Ansible collections
	$(PYTHON_VENV)/bin/ansible-galaxy collection install -r infrastructure/ansible/requirements.yml
	# Install Terraform
	@if ! command -v terraform >/dev/null 2>&1; then \
		echo "Installing Terraform..."; \
		curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -; \
		sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"; \
		sudo apt-get update && sudo apt-get install terraform; \
	fi
	# Setup GNS3 if available
	@if command -v gns3 >/dev/null 2>&1; then \
		echo "✅ GNS3 found"; \
	else \
		echo "⚠️  GNS3 not found - using Docker simulation instead"; \
	fi
	@echo "✅ Environment setup complete!"

clean:
	@echo "🧹 Cleaning up environment..."
	# Stop and remove containers
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans 2>/dev/null || true
	# Clean generated files
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	rm -rf build/
	rm -rf dist/
	rm -rf logs/
	rm -rf outputs/
	# Clean Python cache
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	# Clean Terraform files
	find infrastructure/terraform -name "*.tfstate*" -delete
	find infrastructure/terraform -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete!"

check-deps:
	@echo "🔍 Checking required dependencies..."
	@echo "Python version:"
	@python3 --version
	@echo "Docker version:"
	@docker --version 2>/dev/null || echo "❌ Docker not found"
	@echo "Ansible version:"
	@which ansible >/dev/null && ansible --version | head -1 || echo "❌ Ansible not found"
	@echo "Terraform version:"
	@terraform version 2>/dev/null || echo "❌ Terraform not found"
	@echo "GNS3 status:"
	@which gns3 >/dev/null && echo "✅ GNS3 found" || echo "⚠️  GNS3 not found - Docker mode will be used"

## Lab Environment Management
lab-start:
	@echo "🚀 Starting network simulation lab..."
	# Create network simulation environment
	mkdir -p logs outputs
	# Start Docker-based network simulation
	docker-compose -f $(COMPOSE_FILE) up -d
	# Wait for services to be ready
	@echo "⏳ Waiting for lab services to start..."
	sleep 15
	# Verify lab status
	$(MAKE) lab-status
	@echo "✅ Lab environment is running!"
	@echo "🌐 Access points:"
	@echo "  - Network Management: http://localhost:8080"
	@echo "  - Monitoring Dashboard: http://localhost:3000"
	@echo "  - Network Topology: http://localhost:8081"

lab-stop:
	@echo "🛑 Stopping network simulation lab..."
	docker-compose -f $(COMPOSE_FILE) down
	@echo "✅ Lab environment stopped!"

lab-restart: lab-stop lab-start

lab-status:
	@echo "📊 Lab environment status:"
	@echo "=========================="
	@docker-compose -f $(COMPOSE_FILE) ps 2>/dev/null || echo "No containers running"
	@echo ""
	@echo "Network status:"
	@docker network ls | grep secure-network || echo "No custom networks found"

lab-logs:
	@echo "📋 Lab environment logs:"
	docker-compose -f $(COMPOSE_FILE) logs -f

## Network Deployment
deploy-base-network:
	@echo "🌐 Deploying base network infrastructure..."
	# Deploy base network using Ansible
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(NETWORK_INVENTORY) \
		playbooks/deploy-base-network.yml
	@echo "✅ Base network deployed!"

configure-segmentation:
	@echo "🔀 Configuring VLAN segmentation..."
	# Configure network segmentation
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(NETWORK_INVENTORY) \
		playbooks/configure-vlans.yml
	# Validate segmentation
	$(MAKE) test-segmentation
	@echo "✅ Network segmentation configured!"

deploy-zero-trust:
	@echo "🛡️ Deploying Zero Trust controls..."
	# Deploy Zero Trust architecture
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(NETWORK_INVENTORY) \
		playbooks/deploy-zero-trust.yml
	@echo "✅ Zero Trust controls deployed!"

configure-security-policies:
	@echo "🔐 Configuring security policies..."
	# Deploy security policies
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(NETWORK_INVENTORY) \
		playbooks/configure-security-policies.yml
	# Validate policies
	$(MAKE) test-policies
	@echo "✅ Security policies configured!"

deploy-monitoring:
	@echo "📊 Deploying network monitoring stack..."
	# Deploy monitoring infrastructure
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(NETWORK_INVENTORY) \
		playbooks/deploy-monitoring.yml
	@echo "✅ Network monitoring deployed!"

## Security & Compliance
validate-network:
	@echo "✅ Validating network configuration and security..."
	# Run network validation tests
	$(PYTHON_VENV)/bin/python -m pytest tests/validation/ -v
	# Run security validation
	$(PYTHON_VENV)/bin/python scripts/automation/compliance-check.py
	@echo "✅ Network validation complete!"

security-scan:
	@echo "🔒 Running comprehensive security scanning..."
	# Network security scanning
	$(PYTHON_VENV)/bin/python scripts/testing/security-test.py
	# Vulnerability assessment
	docker run --rm --network host nmap:latest -sS -O target_network || echo "Nmap not available"
	@echo "✅ Security scanning complete!"

compliance-check:
	@echo "📋 Checking compliance with security frameworks..."
	# NIST compliance check
	$(PYTHON_VENV)/bin/python -m pytest tests/compliance/test_nist_controls.py -v
	# ISO 27001 compliance check
	$(PYTHON_VENV)/bin/python -m pytest tests/compliance/test_iso27001.py -v
	# PCI-DSS compliance check
	$(PYTHON_VENV)/bin/python -m pytest tests/compliance/test_pci_dss.py -v
	@echo "✅ Compliance check complete!"

penetration-test:
	@echo "🎯 Running penetration testing scenarios..."
	# Lateral movement testing
	$(PYTHON_VENV)/bin/python -m pytest tests/penetration/test_lateral_movement.py -v
	# Privilege escalation testing
	$(PYTHON_VENV)/bin/python -m pytest tests/penetration/test_privilege_esc.py -v
	# Data exfiltration testing
	$(PYTHON_VENV)/bin/python -m pytest tests/penetration/test_data_exfil.py -v
	@echo "✅ Penetration testing complete!"

## Monitoring & Analysis
start-monitoring:
	@echo "📊 Starting monitoring and visibility stack..."
	# Start monitoring services
	docker-compose -f infrastructure/monitoring/docker-compose.monitoring.yml up -d
	@echo "✅ Monitoring stack started!"
	@echo "📈 Access dashboards:"
	@echo "  - Grafana: http://localhost:3000 (admin/admin)"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Kibana: http://localhost:5601"

stop-monitoring:
	@echo "🛑 Stopping monitoring services..."
	docker-compose -f infrastructure/monitoring/docker-compose.monitoring.yml down
	@echo "✅ Monitoring stack stopped!"

network-topology:
	@echo "🗺️ Generating network topology diagram..."
	$(PYTHON_VENV)/bin/python tools/topology-mapper/generate-topology.py \
		--output outputs/network-topology.png
	@echo "✅ Network topology generated: outputs/network-topology.png"

traffic-analysis:
	@echo "📈 Analyzing network traffic patterns..."
	$(PYTHON_VENV)/bin/python scripts/testing/performance-test.py \
		--analysis-mode traffic
	@echo "✅ Traffic analysis complete!"

## Testing
test: test-connectivity test-segmentation test-policies test-performance

test-connectivity:
	@echo "🌐 Testing network connectivity..."
	$(PYTHON_VENV)/bin/python -m pytest tests/validation/test_connectivity.py -v
	@echo "✅ Connectivity tests complete!"

test-segmentation:
	@echo "🔀 Testing VLAN segmentation..."
	$(PYTHON_VENV)/bin/python -m pytest tests/validation/test_segmentation.py -v
	@echo "✅ Segmentation tests complete!"

test-policies:
	@echo "🔐 Testing security policy enforcement..."
	$(PYTHON_VENV)/bin/python -m pytest tests/validation/test_policies.py -v
	@echo "✅ Policy tests complete!"

test-performance:
	@echo "⚡ Testing network performance..."
	$(PYTHON_VENV)/bin/python -m pytest tests/validation/test_performance.py -v
	@echo "✅ Performance tests complete!"

## Documentation
docs-build:
	@echo "📖 Building documentation..."
	$(PYTHON_VENV)/bin/mkdocs build
	@echo "✅ Documentation built in site/ directory!"

docs-serve:
	@echo "📚 Serving documentation locally..."
	$(PYTHON_VENV)/bin/mkdocs serve
	@echo "📖 Documentation available at http://localhost:8000"

generate-configs:
	@echo "⚙️ Generating configuration examples..."
	# Generate switch configurations
	$(PYTHON_VENV)/bin/python tools/config-generator/generate-switch-configs.py
	# Generate router configurations
	$(PYTHON_VENV)/bin/python tools/config-generator/generate-router-configs.py
	# Generate firewall rules
	$(PYTHON_VENV)/bin/python tools/config-generator/generate-firewall-rules.py
	@echo "✅ Configuration examples generated in outputs/"

## Production Deployment
prepare-production:
	@echo "🚀 Preparing production environment..."
	@if [ -z "$(ENVIRONMENT)" ]; then \
		echo "❌ Error: ENVIRONMENT variable is required"; \
		echo "Usage: make prepare-production ENVIRONMENT=prod"; \
		exit 1; \
	fi
	# Initialize Terraform for production
	cd $(TERRAFORM_DIR)/$(ENVIRONMENT) && terraform init
	# Plan infrastructure deployment
	cd $(TERRAFORM_DIR)/$(ENVIRONMENT) && terraform plan -out=deployment.tfplan
	@echo "✅ Production environment prepared!"

deploy-production:
	@echo "🚀 Deploying to production environment..."
	@if [ -z "$(ENVIRONMENT)" ]; then \
		echo "❌ Error: ENVIRONMENT variable is required"; \
		echo "Usage: make deploy-production ENVIRONMENT=prod"; \
		exit 1; \
	fi
	# Apply Terraform deployment
	cd $(TERRAFORM_DIR)/$(ENVIRONMENT) && terraform apply deployment.tfplan
	# Deploy network configuration
	cd $(ANSIBLE_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i inventories/$(ENVIRONMENT).yml \
		playbooks/deploy-production.yml
	@echo "✅ Production deployment complete!"

## Utility Targets
backup-configs:
	@echo "💾 Backing up network configurations..."
	$(PYTHON_VENV)/bin/python scripts/automation/config-backup.py \
		--output outputs/config-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz
	@echo "✅ Configuration backup complete!"

restore-configs:
	@echo "🔄 Restoring network configurations..."
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "❌ Error: BACKUP_FILE variable is required"; \
		echo "Usage: make restore-configs BACKUP_FILE=backup.tar.gz"; \
		exit 1; \
	fi
	$(PYTHON_VENV)/bin/python scripts/automation/config-restore.py \
		--backup $(BACKUP_FILE)
	@echo "✅ Configuration restore complete!"

network-discovery:
	@echo "🔍 Discovering network topology..."
	$(PYTHON_VENV)/bin/python scripts/automation/network-discovery.py \
		--output outputs/discovered-topology.json
	@echo "✅ Network discovery complete!"

version:
	@echo "📝 Version information:"
	@echo "Project: Secure Network Design & Zero Trust Architecture v0.1.0"
	@echo "Python: $(shell python3 --version)"
	@echo "Docker: $(shell docker --version)"
	@echo "Ansible: $(shell ansible --version 2>/dev/null | head -1 || echo 'Not installed')"
	@echo "Terraform: $(shell terraform version 2>/dev/null | head -1 || echo 'Not installed')"

status:
	@echo "📊 Project status:"
	@echo "=================="
	@echo "Lab environment:"
	@docker-compose -f $(COMPOSE_FILE) ps 2>/dev/null | head -10
	@echo ""
	@echo "Recent logs (last 10 lines):"
	@docker-compose -f $(COMPOSE_FILE) logs --tail=10 2>/dev/null || echo "No logs available"