# Installation Guide

## 🚀 Enterprise VPN Management System Installation

This guide covers the complete installation and initial configuration of the Enterprise VPN Management System in various environments.

## 📋 Prerequisites

### System Requirements

#### Hardware Requirements (Minimum)
- **CPU**: 4 vCPU cores per VPN server
- **Memory**: 8 GB RAM per VPN server
- **Storage**: 100 GB SSD for OS and configurations
- **Network**: Gigabit Ethernet with dedicated interfaces

#### Hardware Requirements (Recommended)
- **CPU**: 8 vCPU cores per VPN server
- **Memory**: 16 GB RAM per VPN server  
- **Storage**: 500 GB SSD with separate volumes for logs
- **Network**: 10 Gigabit Ethernet with LACP bonding

#### Operating System Support
- **Ubuntu**: 20.04 LTS, 22.04 LTS
- **CentOS**: 8, Rocky Linux 8+
- **Debian**: 11 (Bullseye), 12 (Bookworm)
- **RHEL**: 8+

### Software Dependencies

#### Core Dependencies
- **Docker**: 20.10+ and Docker Compose V2
- **Python**: 3.8+ with pip
- **Ansible**: 6.0+ with community collections
- **OpenSSL**: 1.1.1+ for certificate operations
- **Git**: 2.30+ for version control

#### Optional Dependencies
- **Terraform**: 1.3+ for infrastructure provisioning
- **Vault**: 1.12+ for secrets management
- **Kubernetes**: 1.26+ for container orchestration
- **Helm**: 3.10+ for Kubernetes package management

### Network Requirements

#### Firewall Ports
```
# VPN Services
1194/udp    # OpenVPN UDP
1195/tcp    # OpenVPN TCP
500/udp     # IPSec IKE
4500/udp    # IPSec NAT-T

# Management Services
22/tcp      # SSH
80/tcp      # HTTP (redirect to HTTPS)
443/tcp     # HTTPS Management
8080/tcp    # Certificate Authority Web Interface

# Authentication Services
1812/udp    # RADIUS Authentication
1813/udp    # RADIUS Accounting
389/tcp     # LDAP
636/tcp     # LDAPS

# Monitoring (optional)
9090/tcp    # Prometheus
3000/tcp    # Grafana
3100/tcp    # Loki
```

#### Network Architecture
- **DMZ Network**: VPN servers isolated from internal network
- **Management Network**: Administrative access to all components
- **Internal Network**: Backend services and databases
- **Client Networks**: Assigned IP ranges for VPN clients

---

## 📦 Quick Installation (Docker Lab)

### Step 1: Clone Repository
```bash
# Clone the project repository
git clone https://github.com/your-org/cybersecurity-portfolio.git
cd cybersecurity-portfolio/projects/05-vpn-management

# Verify directory structure
ls -la
```

### Step 2: Install Dependencies
```bash
# Install Python dependencies
make install

# Verify installation
make check-deps
```

### Step 3: Start Lab Environment
```bash
# Start basic lab environment
make lab-up

# Check service status
make status

# View logs
make lab-logs
```

### Step 4: Initialize PKI
```bash
# Initialize Certificate Authority
make pki-init

# Generate server certificates
make server-cert

# Verify certificate creation
ls -la configs/pki/
```

### Step 5: Deploy VPN Services
```bash
# Deploy OpenVPN server
make deploy-openvpn

# Deploy IPSec server
make deploy-ipsec

# Test connectivity
make test-connectivity
```

### Step 6: Create First Client
```bash
# Generate client certificate
make client-cert NAME=test-user EMAIL=test@company.com

# Verify client configuration
ls -la configs/clients/
```

---

## 🏭 Production Installation

### Step 1: Infrastructure Preparation

#### Server Provisioning
```bash
# If using Terraform for infrastructure
cd scripts/terraform/

# Initialize Terraform
terraform init

# Plan infrastructure deployment
terraform plan -var-file=production.tfvars

# Apply infrastructure
terraform apply -var-file=production.tfvars
```

#### Manual Server Setup
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y docker.io docker-compose python3 python3-pip git openssl

# Configure Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Install Ansible
pip3 install ansible ansible-core
```

### Step 2: Security Hardening

#### System Hardening
```bash
# Apply CIS benchmarks
cd scripts/ansible/
ansible-playbook -i inventories/production.yml playbooks/system-hardening.yml

# Configure firewall
ansible-playbook -i inventories/production.yml playbooks/firewall-config.yml

# Enable SELinux/AppArmor
ansible-playbook -i inventories/production.yml playbooks/mandatory-access-control.yml
```

#### SSL/TLS Configuration
```bash
# Generate production certificates
ansible-playbook -i inventories/production.yml playbooks/ssl-certificates.yml

# Configure certificate renewal
ansible-playbook -i inventories/production.yml playbooks/cert-renewal.yml
```

### Step 3: High Availability Setup

#### Database Cluster
```bash
# Deploy PostgreSQL cluster
ansible-playbook -i inventories/production.yml playbooks/database-cluster.yml

# Configure replication
ansible-playbook -i inventories/production.yml playbooks/database-replication.yml

# Setup backup procedures
ansible-playbook -i inventories/production.yml playbooks/database-backup.yml
```

#### Load Balancer Configuration
```bash
# Deploy HAProxy load balancers
ansible-playbook -i inventories/production.yml playbooks/load-balancer.yml

# Configure health checks
ansible-playbook -i inventories/production.yml playbooks/health-checks.yml

# Setup SSL termination
ansible-playbook -i inventories/production.yml playbooks/ssl-termination.yml
```

### Step 4: VPN Server Deployment

#### OpenVPN Cluster
```bash
# Deploy OpenVPN servers
ansible-playbook -i inventories/production.yml playbooks/openvpn-cluster.yml

# Configure server redundancy
ansible-playbook -i inventories/production.yml playbooks/openvpn-ha.yml

# Setup monitoring
ansible-playbook -i inventories/production.yml playbooks/openvpn-monitoring.yml
```

#### IPSec Cluster
```bash
# Deploy StrongSwan servers
ansible-playbook -i inventories/production.yml playbooks/strongswan-cluster.yml

# Configure site-to-site tunnels
ansible-playbook -i inventories/production.yml playbooks/site-to-site.yml

# Setup mobile client access
ansible-playbook -i inventories/production.yml playbooks/mobile-clients.yml
```

### Step 5: Authentication Services

#### RADIUS Server
```bash
# Deploy FreeRADIUS cluster
ansible-playbook -i inventories/production.yml playbooks/radius-cluster.yml

# Configure LDAP integration
ansible-playbook -i inventories/production.yml playbooks/radius-ldap.yml

# Setup accounting and logging
ansible-playbook -i inventories/production.yml playbooks/radius-accounting.yml
```

#### Multi-Factor Authentication
```bash
# Deploy privacyIDEA server
ansible-playbook -i inventories/production.yml playbooks/mfa-server.yml

# Configure TOTP tokens
ansible-playbook -i inventories/production.yml playbooks/totp-setup.yml

# Integrate with RADIUS
ansible-playbook -i inventories/production.yml playbooks/mfa-integration.yml
```

### Step 6: Monitoring and Logging

#### Monitoring Stack
```bash
# Deploy Prometheus cluster
ansible-playbook -i inventories/production.yml playbooks/prometheus-cluster.yml

# Setup Grafana dashboards
ansible-playbook -i inventories/production.yml playbooks/grafana-dashboards.yml

# Configure alerting
ansible-playbook -i inventories/production.yml playbooks/alerting-rules.yml
```

#### Centralized Logging
```bash
# Deploy ELK stack
ansible-playbook -i inventories/production.yml playbooks/elk-cluster.yml

# Configure log forwarding
ansible-playbook -i inventories/production.yml playbooks/log-forwarding.yml

# Setup log retention
ansible-playbook -i inventories/production.yml playbooks/log-retention.yml
```

---

## ☁️ Cloud Deployment

### AWS Deployment

#### Prerequisites
```bash
# Configure AWS CLI
aws configure

# Verify permissions
aws sts get-caller-identity
```

#### Infrastructure Deployment
```bash
# Deploy VPC and networking
cd scripts/terraform/aws/
terraform init
terraform apply -var-file=production.tfvars

# Deploy EKS cluster
terraform apply -target=module.eks -var-file=production.tfvars

# Deploy RDS instances
terraform apply -target=module.rds -var-file=production.tfvars
```

#### Application Deployment
```bash
# Configure kubectl
aws eks update-kubeconfig --name vpn-management-cluster

# Deploy with Helm
helm install vpn-management charts/vpn-management \
  --namespace vpn-system \
  --create-namespace \
  -f values-production.yaml

# Verify deployment
kubectl get pods -n vpn-system
```

### Azure Deployment

#### Prerequisites
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "Your Subscription"
```

#### Infrastructure Deployment
```bash
# Deploy resource group
az group create --name vpn-management-rg --location eastus

# Deploy AKS cluster
cd scripts/terraform/azure/
terraform init
terraform apply -var-file=production.tfvars
```

### Google Cloud Deployment

#### Prerequisites
```bash
# Authenticate with GCP
gcloud auth login

# Set project
gcloud config set project your-project-id
```

#### Infrastructure Deployment
```bash
# Deploy GKE cluster
cd scripts/terraform/gcp/
terraform init
terraform apply -var-file=production.tfvars
```

---

## 🔧 Configuration

### Basic Configuration

#### Environment Variables
```bash
# Create environment file
cat > .env << EOF
# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/vpndb
REDIS_URL=redis://localhost:6379/0

# VPN Configuration
OPENVPN_SERVER_NAME=vpn.company.com
OPENVPN_NETWORK=10.8.0.0
OPENVPN_NETMASK=255.255.255.0

# Certificate Authority
CA_NAME=Company VPN CA
CA_COUNTRY=US
CA_STATE=California
CA_CITY=San Francisco
CA_ORG=Your Company
CA_EMAIL=admin@company.com

# Security Settings
SECRET_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF
```

#### Configuration Files
```bash
# Copy configuration templates
cp configs/templates/openvpn.conf.template configs/openvpn/server.conf
cp configs/templates/strongswan.conf.template configs/strongswan/strongswan.conf
cp configs/templates/radius.conf.template configs/radius/radiusd.conf

# Customize configurations
nano configs/openvpn/server.conf
nano configs/strongswan/strongswan.conf
nano configs/radius/radiusd.conf
```

### Advanced Configuration

#### Load Balancer Configuration
```bash
# Configure HAProxy
cat > configs/haproxy/haproxy.cfg << EOF
global
    daemon
    stats socket /var/run/haproxy.sock mode 660 level admin
    
defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend openvpn_frontend
    bind *:1194
    default_backend openvpn_servers

backend openvpn_servers
    balance roundrobin
    server ovpn1 10.0.1.10:1194 check
    server ovpn2 10.0.1.11:1194 check

frontend ipsec_frontend
    bind *:500
    default_backend ipsec_servers

backend ipsec_servers
    balance source
    server ipsec1 10.0.1.20:500 check
    server ipsec2 10.0.1.21:500 check
EOF
```

#### Database Configuration
```bash
# Configure PostgreSQL
sudo -u postgres psql << EOF
CREATE DATABASE vpnmanagement;
CREATE USER vpnadmin WITH PASSWORD 'securepassword';
GRANT ALL PRIVILEGES ON DATABASE vpnmanagement TO vpnadmin;
\q
EOF

# Initialize database schema
python3 scripts/init-database.py
```

---

## ✅ Post-Installation Verification

### System Health Checks
```bash
# Run comprehensive health check
make test

# Check specific components
make test-openvpn
make test-ipsec
make test-radius
make test-monitoring
```

### Security Validation
```bash
# Run security scan
make security-scan

# Check compliance
make compliance-check

# Verify SSL certificates
make verify-certificates
```

### Performance Testing
```bash
# Run performance tests
make test-performance

# Load testing
make test-load

# Benchmark VPN throughput
make benchmark-vpn
```

---

## 🔄 Initial User Setup

### Administrator Account
```bash
# Create admin user
python3 scripts/create-admin-user.py \
  --username admin \
  --email admin@company.com \
  --password-prompt

# Assign administrator role
python3 scripts/assign-role.py --user admin --role administrator
```

### First VPN User
```bash
# Create VPN user account
python3 scripts/create-vpn-user.py \
  --username john.doe \
  --email john.doe@company.com \
  --full-name "John Doe" \
  --department IT

# Generate client certificate
make client-cert NAME=john.doe EMAIL=john.doe@company.com

# Create client configuration
python3 scripts/generate-client-config.py --user john.doe
```

---

## 📚 Next Steps

### Documentation Review
1. Read the [Configuration Reference](configuration.md)
2. Review [Security Best Practices](../security/best-practices.md)
3. Study [Monitoring Setup](monitoring.md)
4. Understand [Troubleshooting Guide](troubleshooting.md)

### Production Readiness
1. Implement backup and disaster recovery procedures
2. Configure monitoring alerts and notifications  
3. Establish security incident response procedures
4. Create operational runbooks and documentation
5. Conduct security audit and penetration testing

### Training and Support
1. Train administrators on system operations
2. Create user training materials and documentation
3. Establish support procedures and escalation paths
4. Plan regular security reviews and updates

---

## 🆘 Troubleshooting

### Common Installation Issues

#### Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify docker access
docker run hello-world
```

#### Ansible Connection Issues
```bash
# Test SSH connectivity
ansible all -i inventories/production.yml -m ping

# Check SSH key configuration
ssh-keygen -t rsa -b 4096 -C "your_email@domain.com"
ssh-copy-id user@target-server
```

#### Certificate Generation Errors
```bash
# Check OpenSSL configuration
openssl version -a

# Verify PKI directory permissions
ls -la configs/pki/
chmod 700 configs/pki/private/
```

#### Service Startup Failures
```bash
# Check service logs
journalctl -u openvpn-server -f
journalctl -u strongswan -f

# Verify configuration syntax
openvpn --config configs/openvpn/server.conf --test
ipsec configtest
```

### Support Resources

#### Log Files
- System logs: `/var/log/syslog` or `journalctl`
- OpenVPN logs: `/var/log/openvpn/`
- StrongSwan logs: `/var/log/strongswan/`
- Application logs: `logs/` directory

#### Diagnostic Commands
```bash
# System information
make version
make status

# Network connectivity
make test-connectivity

# Certificate status
make list-clients
openssl x509 -in configs/pki/ca.crt -text -noout
```

For additional support, refer to the [Troubleshooting Guide](troubleshooting.md) or contact the system administrator.

---

**🎉 Installation Complete!**

Your Enterprise VPN Management System is now ready for use. Proceed with user training and operational procedures as documented in the administrator guides.