# Enterprise VPN Management System - Makefile
# Project: 05-vpn-management
# Description: Automation for build, test, and deployment tasks

.PHONY: help clean install lab-up lab-down pki-init deploy-openvpn deploy-ipsec test lint security-scan

# Variables
COMPOSE_FILE := docker-compose.yml
ANSIBLE_PLAYBOOK_DIR := scripts/ansible
INVENTORY := inventories/lab.yml
PYTHON_VENV := .venv
DOCKER_NETWORK := vpn-lab-network

# Default target
.DEFAULT_GOAL := help

## Help target - Display available targets
help:
	@echo "🔐 Enterprise VPN Management System"
	@echo "======================================"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "🏗️  Environment Setup:"
	@echo "  install           Install dependencies and setup environment"
	@echo "  clean             Clean up generated files and containers"
	@echo ""
	@echo "🧪 Lab Environment:"
	@echo "  lab-up            Start lab environment with Docker Compose"
	@echo "  lab-down          Stop lab environment and cleanup"
	@echo "  lab-restart       Restart lab environment"
	@echo "  lab-logs          Show lab environment logs"
	@echo ""
	@echo "🔑 PKI Management:"
	@echo "  pki-init          Initialize PKI infrastructure"
	@echo "  pki-clean         Clean PKI certificates and keys"
	@echo "  ca-cert           Generate CA certificate"
	@echo "  server-cert       Generate server certificate"
	@echo ""
	@echo "🚀 Deployment:"
	@echo "  deploy-openvpn    Deploy OpenVPN server"
	@echo "  deploy-ipsec      Deploy IPSec/StrongSwan server"
	@echo "  deploy-all        Deploy both VPN solutions"
	@echo "  deploy-production Deploy to production (requires INVENTORY)"
	@echo ""
	@echo "👥 Client Management:"
	@echo "  client-cert       Generate client certificate (requires NAME and EMAIL)"
	@echo "  revoke-cert       Revoke client certificate (requires NAME)"
	@echo "  list-clients      List all client certificates"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run unit tests"
	@echo "  test-integration  Run integration tests"
	@echo "  test-security     Run security tests"
	@echo "  test-connectivity Test VPN connectivity"
	@echo ""
	@echo "🔍 Quality & Security:"
	@echo "  lint              Run linting on all files"
	@echo "  security-scan     Run security scans"
	@echo "  compliance-check  Check compliance requirements"
	@echo ""
	@echo "📊 Monitoring:"
	@echo "  monitor-start     Start monitoring stack"
	@echo "  monitor-stop      Stop monitoring stack"
	@echo "  metrics           Show current metrics"
	@echo ""
	@echo "📖 Documentation:"
	@echo "  docs-build        Build documentation"
	@echo "  docs-serve        Serve documentation locally"
	@echo ""

## Environment Setup
install:
	@echo "🔧 Installing dependencies..."
	# Create Python virtual environment
	python3 -m venv $(PYTHON_VENV)
	$(PYTHON_VENV)/bin/pip install --upgrade pip
	$(PYTHON_VENV)/bin/pip install -r requirements.txt
	# Install Ansible collections
	$(PYTHON_VENV)/bin/ansible-galaxy install -r scripts/ansible/requirements.yml
	# Install pre-commit hooks
	$(PYTHON_VENV)/bin/pre-commit install
	@echo "✅ Dependencies installed successfully!"

clean:
	@echo "🧹 Cleaning up..."
	# Stop and remove containers
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans 2>/dev/null || true
	# Remove generated files
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	rm -rf *.egg-info/
	rm -rf build/
	rm -rf dist/
	# Clean Python cache
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✅ Cleanup complete!"

## Lab Environment Management
lab-up:
	@echo "🚀 Starting lab environment..."
	# Create Docker network if it doesn't exist
	docker network create $(DOCKER_NETWORK) 2>/dev/null || true
	# Start services
	docker-compose -f $(COMPOSE_FILE) up -d
	# Wait for services to be ready
	@echo "⏳ Waiting for services to be ready..."
	sleep 10
	# Check service health
	docker-compose -f $(COMPOSE_FILE) ps
	@echo "✅ Lab environment is running!"
	@echo "🌐 Access points:"
	@echo "  - OpenVPN Server: localhost:1194"
	@echo "  - IPSec Server: localhost:500"
	@echo "  - Monitoring: http://localhost:3000"

lab-down:
	@echo "🛑 Stopping lab environment..."
	docker-compose -f $(COMPOSE_FILE) down -v
	@echo "✅ Lab environment stopped!"

lab-restart: lab-down lab-up

lab-logs:
	@echo "📋 Lab environment logs:"
	docker-compose -f $(COMPOSE_FILE) logs -f

## PKI Management
pki-init:
	@echo "🔑 Initializing PKI infrastructure..."
	# Create PKI directories
	mkdir -p configs/pki/{ca,certs,private,crl,issued}
	chmod 700 configs/pki/private
	# Initialize CA
	$(MAKE) ca-cert
	@echo "✅ PKI infrastructure initialized!"

pki-clean:
	@echo "🧹 Cleaning PKI certificates..."
	rm -rf configs/pki/
	@echo "✅ PKI certificates cleaned!"

ca-cert:
	@echo "🏛️ Generating CA certificate..."
	# Generate CA key and certificate
	openssl genrsa -out configs/pki/private/ca.key 4096
	chmod 400 configs/pki/private/ca.key
	openssl req -new -x509 -days 3650 -key configs/pki/private/ca.key \
		-out configs/pki/ca.crt -config configs/openssl.cnf
	@echo "✅ CA certificate generated!"

server-cert:
	@echo "🖥️ Generating server certificate..."
	# Generate server key and certificate signing request
	openssl genrsa -out configs/pki/private/server.key 2048
	chmod 400 configs/pki/private/server.key
	openssl req -new -key configs/pki/private/server.key \
		-out configs/pki/server.csr -config configs/openssl.cnf
	# Sign server certificate
	openssl x509 -req -days 365 -in configs/pki/server.csr \
		-CA configs/pki/ca.crt -CAkey configs/pki/private/ca.key \
		-CAcreateserial -out configs/pki/certs/server.crt
	@echo "✅ Server certificate generated!"

## Client Certificate Management
client-cert:
	@echo "👤 Generating client certificate for $(NAME)..."
	@if [ -z "$(NAME)" ] || [ -z "$(EMAIL)" ]; then \
		echo "❌ Error: NAME and EMAIL variables are required"; \
		echo "Usage: make client-cert NAME=john.doe EMAIL=john@company.com"; \
		exit 1; \
	fi
	# Generate client key and certificate
	openssl genrsa -out configs/pki/private/$(NAME).key 2048
	chmod 400 configs/pki/private/$(NAME).key
	openssl req -new -key configs/pki/private/$(NAME).key \
		-out configs/pki/$(NAME).csr -subj "/CN=$(NAME)/emailAddress=$(EMAIL)"
	openssl x509 -req -days 365 -in configs/pki/$(NAME).csr \
		-CA configs/pki/ca.crt -CAkey configs/pki/private/ca.key \
		-CAcreateserial -out configs/pki/certs/$(NAME).crt
	# Generate client configuration
	scripts/bash/generate-client-config.sh $(NAME)
	@echo "✅ Client certificate generated for $(NAME)!"

revoke-cert:
	@echo "🚫 Revoking certificate for $(NAME)..."
	@if [ -z "$(NAME)" ]; then \
		echo "❌ Error: NAME variable is required"; \
		echo "Usage: make revoke-cert NAME=john.doe"; \
		exit 1; \
	fi
	# Add to revocation list
	scripts/bash/revoke-certificate.sh $(NAME)
	@echo "✅ Certificate revoked for $(NAME)!"

list-clients:
	@echo "📋 Client certificates:"
	@ls -la configs/pki/certs/ | grep -v "server.crt" || echo "No client certificates found"

## Deployment
deploy-openvpn:
	@echo "🔐 Deploying OpenVPN server..."
	cd $(ANSIBLE_PLAYBOOK_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(INVENTORY) playbooks/deploy-openvpn.yml
	@echo "✅ OpenVPN server deployed!"

deploy-ipsec:
	@echo "🛡️ Deploying IPSec server..."
	cd $(ANSIBLE_PLAYBOOK_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i $(INVENTORY) playbooks/deploy-ipsec.yml
	@echo "✅ IPSec server deployed!"

deploy-all: deploy-openvpn deploy-ipsec

deploy-production:
	@echo "🚀 Deploying to production..."
	@if [ -z "$(INVENTORY)" ]; then \
		echo "❌ Error: INVENTORY variable is required"; \
		echo "Usage: make deploy-production INVENTORY=production"; \
		exit 1; \
	fi
	cd $(ANSIBLE_PLAYBOOK_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i inventories/$(INVENTORY).yml \
		playbooks/site.yml --check
	@echo "🤚 Review the dry-run output above. Continue? (y/N)"
	@read confirm && [ "$$confirm" = "y" ] || exit 1
	cd $(ANSIBLE_PLAYBOOK_DIR) && \
	$(PYTHON_VENV)/bin/ansible-playbook -i inventories/$(INVENTORY).yml \
		playbooks/site.yml
	@echo "✅ Production deployment complete!"

## Testing
test: test-unit test-integration test-security

test-unit:
	@echo "🧪 Running unit tests..."
	$(PYTHON_VENV)/bin/python -m pytest tests/unit/ -v --cov=src --cov-report=html
	@echo "✅ Unit tests complete!"

test-integration:
	@echo "🔗 Running integration tests..."
	$(PYTHON_VENV)/bin/python -m pytest tests/integration/ -v
	@echo "✅ Integration tests complete!"

test-security:
	@echo "🔒 Running security tests..."
	$(PYTHON_VENV)/bin/python -m pytest tests/security/ -v
	@echo "✅ Security tests complete!"

test-connectivity:
	@echo "🌐 Testing VPN connectivity..."
	scripts/bash/test-connectivity.sh
	@echo "✅ Connectivity tests complete!"

## Quality & Security
lint:
	@echo "🔍 Running linting..."
	# YAML linting
	$(PYTHON_VENV)/bin/yamllint .
	# Shell script linting
	find scripts/ -name "*.sh" -exec shellcheck {} \;
	# Ansible linting
	$(PYTHON_VENV)/bin/ansible-lint scripts/ansible/
	# Python linting
	$(PYTHON_VENV)/bin/flake8 src/ tests/
	@echo "✅ Linting complete!"

security-scan:
	@echo "🔒 Running security scans..."
	# Dependency vulnerability scan
	$(PYTHON_VENV)/bin/safety check
	# Container security scan
	docker run --rm -v $(PWD):/workspace aquasec/trivy fs /workspace
	@echo "✅ Security scans complete!"

compliance-check:
	@echo "📋 Checking compliance requirements..."
	scripts/bash/compliance-check.sh
	@echo "✅ Compliance check complete!"

## Monitoring
monitor-start:
	@echo "📊 Starting monitoring stack..."
	docker-compose -f docker-compose.monitoring.yml up -d
	@echo "✅ Monitoring stack started!"
	@echo "📈 Grafana: http://localhost:3000 (admin/admin)"

monitor-stop:
	@echo "🛑 Stopping monitoring stack..."
	docker-compose -f docker-compose.monitoring.yml down
	@echo "✅ Monitoring stack stopped!"

metrics:
	@echo "📊 Current metrics:"
	curl -s http://localhost:9090/api/v1/query?query=up | jq '.'

## Documentation
docs-build:
	@echo "📖 Building documentation..."
	$(PYTHON_VENV)/bin/mkdocs build
	@echo "✅ Documentation built!"

docs-serve:
	@echo "📖 Serving documentation..."
	$(PYTHON_VENV)/bin/mkdocs serve
	@echo "📚 Documentation available at http://localhost:8000"

# Utility targets
check-deps:
	@echo "🔍 Checking dependencies..."
	@which docker >/dev/null || (echo "❌ Docker not found" && exit 1)
	@which docker-compose >/dev/null || (echo "❌ Docker Compose not found" && exit 1)
	@which python3 >/dev/null || (echo "❌ Python 3 not found" && exit 1)
	@echo "✅ All dependencies found!"

version:
	@echo "📝 Version information:"
	@echo "Project: Enterprise VPN Management System v0.1.0"
	@echo "Docker: $(shell docker --version)"
	@echo "Docker Compose: $(shell docker-compose --version)"
	@echo "Python: $(shell python3 --version)"

status:
	@echo "📊 System status:"
	@echo "==================================="
	@echo "Docker containers:"
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@echo "Docker images:"
	@docker images | grep vpn
	@echo ""
	@echo "Network status:"
	@docker network ls | grep vpn