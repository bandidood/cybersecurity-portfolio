# SOC SOAR Platform Deployment & Orchestration

This directory contains deployment and orchestration scripts for the complete SOC SOAR platform, providing automated installation, configuration, and management of TheHive, Cortex, MISP, and associated monitoring infrastructure.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Scripts](#deployment-scripts)
- [Management Commands](#management-commands)
- [Configuration](#configuration)
- [Monitoring & Health Checks](#monitoring--health-checks)
- [Backup & Restore](#backup--restore)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

The deployment system provides:

- **Automated Installation**: Complete platform setup with a single command
- **Service Management**: Start, stop, restart, and monitor all services
- **Health Monitoring**: Continuous health checks and alerting
- **Backup & Restore**: Automated backup procedures and disaster recovery
- **Configuration Management**: Templated configurations and environment management
- **Security Hardening**: SSL/TLS configuration, firewall rules, and secrets management

## 🏗 Architecture

The platform includes the following components:

### Core SOAR Services
- **TheHive 5.2**: Case management and incident response
- **Cortex 3.1.7**: Security analyzers and automated responders
- **MISP**: Threat intelligence sharing platform

### Data Storage
- **Elasticsearch 8.10.4**: Search engine and data storage
- **Cassandra 4.0**: NoSQL database for TheHive
- **MySQL 8.0**: Relational database for MISP
- **Redis 7**: Caching and session storage

### Monitoring Stack
- **Prometheus**: Metrics collection and monitoring
- **Grafana**: Visualization and dashboards
- **Alertmanager**: Alert routing and notifications
- **Node Exporter**: System metrics collection
- **cAdvisor**: Container metrics collection

### Infrastructure
- **Traefik**: Reverse proxy and load balancer
- **Nginx**: Web server for custom interfaces
- **Filebeat**: Log aggregation and forwarding

## ✅ Prerequisites

### System Requirements
- **Operating System**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+
- **Memory**: 8GB RAM minimum (16GB+ recommended)
- **Storage**: 50GB available disk space minimum
- **CPU**: 4 cores minimum (8+ recommended)
- **Network**: Internet connectivity for package downloads

### Software Requirements
- **Docker**: Version 20.0.0+ (automatically installed if missing)
- **Docker Compose**: Version 2.0.0+ (automatically installed if missing)
- **Root Access**: Required for initial installation and system configuration

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone <repository-url>
cd cybersecurity-portfolio/projects/20-threat-hunting-soc
```

### 2. Run Installation
```bash
# Make scripts executable
chmod +x deploy/deploy-soar-platform.sh
chmod +x deploy/manage-soar.sh

# Install the platform (requires root)
sudo ./deploy/deploy-soar-platform.sh
```

### 3. Access Services
After successful installation, access the services at:
- **TheHive**: http://your-server:9000 (admin@thehive.local / secret)
- **Cortex**: http://your-server:9001 (admin@cortex.local / secret)
- **MISP**: http://your-server:8080 (admin@admin.test / admin-password-change-me)
- **Grafana**: http://your-server:3000 (admin / grafana-admin-password)
- **Kibana**: http://your-server:5601
- **Prometheus**: http://your-server:9090

## 📜 Deployment Scripts

### `deploy-soar-platform.sh`
Main deployment script that handles complete platform installation.

```bash
# Full installation
sudo ./deploy-soar-platform.sh

# Installation options
sudo ./deploy-soar-platform.sh --debug           # Enable debug output
sudo ./deploy-soar-platform.sh --skip-docker     # Skip Docker installation
sudo ./deploy-soar-platform.sh --config-only     # Only copy configuration files
sudo ./deploy-soar-platform.sh --help           # Show help
```

**Features:**
- System requirements validation
- Dependency installation (Docker, Docker Compose, Python packages)
- Directory structure creation
- Configuration file deployment
- SSL certificate generation
- System limits configuration
- Firewall setup
- Service deployment and health checks
- Monitoring setup
- Backup script creation

### `manage-soar.sh`
Platform management script for day-to-day operations.

```bash
# Platform management commands
./deploy/manage-soar.sh <command> [options]
```

## 🛠 Management Commands

### Service Management
```bash
./deploy/manage-soar.sh start           # Start all services
./deploy/manage-soar.sh stop            # Stop all services  
./deploy/manage-soar.sh restart         # Restart all services
./deploy/manage-soar.sh status          # Show service status
```

### Monitoring & Diagnostics
```bash
./deploy/manage-soar.sh health          # Run health checks
./deploy/manage-soar.sh logs            # Show all service logs
./deploy/manage-soar.sh logs thehive    # Show specific service logs
./deploy/manage-soar.sh urls            # Show access URLs
```

### Platform Maintenance
```bash
./deploy/manage-soar.sh update          # Update to latest versions
./deploy/manage-soar.sh cleanup         # Clean unused Docker resources
./deploy/manage-soar.sh backup          # Create backup
./deploy/manage-soar.sh restore <path>  # Restore from backup
```

### Configuration
```bash
./deploy/manage-soar.sh config env      # Generate environment template
```

## ⚙️ Configuration

### Environment Variables
The platform uses environment variables for configuration. Generate a template:

```bash
./deploy/manage-soar.sh config env
# Creates /opt/soc-soar/.env.example
```

Key configuration options:
```bash
# Network Configuration
COMPOSE_PROJECT_NAME=soc-soar
NETWORK_SUBNET=172.20.0.0/16

# Security (CHANGE IN PRODUCTION!)
ELASTICSEARCH_PASSWORD=changeme123
THEHIVE_SECRET=thehive-secret-change-in-production
MISP_ADMIN_PASSWORD=admin-password-change-me

# Service Versions
THEHIVE_VERSION=5.2
CORTEX_VERSION=3.1.7
ELASTICSEARCH_VERSION=8.10.4

# External Integrations
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
TEAMS_WEBHOOK_URL=https://outlook.office.com/...
EMAIL_SMTP_SERVER=smtp.company.com
```

### Directory Structure
```
/opt/soc-soar/              # Installation directory
├── docker-compose.yml      # Main compose file
├── .env                    # Environment variables
├── configs/                # Service configurations
├── analyzers/              # Cortex analyzers
├── responders/             # Cortex responders
├── integration/            # Integration scripts
└── logs/                   # Application logs

/etc/soc/                   # System configuration
├── thehive/               # TheHive configs
├── cortex/                # Cortex configs
├── ssl/                   # SSL certificates
└── grafana/               # Grafana dashboards

/var/log/soc/              # System logs
└── deployment.log         # Deployment logs

/var/lib/soc/              # Data directory
└── [service-data]/        # Service data volumes
```

## 📊 Monitoring & Health Checks

### Automated Monitoring
- **Health Checks**: Automated service health monitoring every 5 minutes
- **Metrics Collection**: Prometheus scrapes metrics from all services
- **Log Aggregation**: Centralized logging with Elasticsearch and Kibana
- **Alerting**: Configurable alerts via email, Slack, or Teams

### Manual Health Checks
```bash
# Check all services
./deploy/manage-soar.sh health

# Check specific components
curl http://localhost:9000/api/status    # TheHive
curl http://localhost:9001/api/health    # Cortex
curl http://localhost:9200/_cluster/health  # Elasticsearch
```

### Grafana Dashboards
Pre-configured dashboards for:
- System resource monitoring (CPU, memory, disk, network)
- Container metrics and performance
- Application-specific metrics (TheHive cases, Cortex jobs)
- Infrastructure health and uptime

## 💾 Backup & Restore

### Automated Backups
- **Daily Backups**: Automatically created at 2 AM
- **Retention**: 30 days by default
- **Location**: `/var/backups/soc-soar/`
- **Contents**: Docker volumes, configurations, and platform files

### Manual Backup
```bash
# Create backup with custom name
./deploy/manage-soar.sh backup backup-before-update

# Create backup with timestamp
./deploy/manage-soar.sh backup
```

### Restore Process
```bash
# List available backups
ls -la /var/backups/soc-soar/

# Restore from specific backup
./deploy/manage-soar.sh restore /var/backups/soc-soar/backup-20231215_143022
```

### Backup Contents
Each backup includes:
- **volumes.tar.gz**: All Docker volume data
- **configs.tar.gz**: Service configuration files
- **platform.tar.gz**: Platform installation files
- **manifest.txt**: Backup metadata and restore instructions

## 🔒 Security Considerations

### Default Security Measures
- **SSL/TLS**: Self-signed certificates generated automatically
- **Firewall**: Configurable rules for service access
- **Network Isolation**: Services run in isolated Docker network
- **User Access**: Configurable authentication and authorization

### Production Security Checklist
- [ ] Change all default passwords immediately
- [ ] Replace self-signed certificates with proper SSL certificates
- [ ] Configure proper firewall rules for your environment
- [ ] Set up LDAP/SSO integration for user authentication
- [ ] Review and update API keys and secrets
- [ ] Enable audit logging and monitoring
- [ ] Configure proper backup encryption
- [ ] Review and harden system configurations

### Security Configuration
```bash
# Generate new SSL certificates
openssl genrsa -out /etc/soc/ssl/server-key.pem 4096

# Update firewall rules
ufw allow from 10.0.0.0/8 to any port 9000  # Restrict TheHive access

# Configure authentication
# Edit /etc/soc/thehive/application.conf for LDAP integration
```

## 🔧 Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service logs
./deploy/manage-soar.sh logs <service-name>

# Check Docker status
docker ps -a
docker compose ps

# Restart specific service
docker compose restart <service-name>
```

#### Memory Issues
```bash
# Check memory usage
docker stats

# Increase Elasticsearch heap size
# Edit /opt/soc-soar/.env:
ES_JAVA_OPTS=-Xms4g -Xmx4g
```

#### Network Connectivity
```bash
# Test internal network
docker network inspect soc-soar_soar-network

# Test external connectivity
curl -I http://localhost:9000
telnet localhost 9200
```

#### Database Connection Issues
```bash
# Check Cassandra status
docker compose exec cassandra cqlsh -e "describe keyspaces"

# Check Elasticsearch status
curl localhost:9200/_cluster/health?pretty
```

### Log Locations
- **Deployment logs**: `/var/log/soc/deployment.log`
- **Service logs**: `docker compose logs <service>`
- **System logs**: `/var/log/syslog`
- **Application logs**: `/opt/soc-soar/logs/`

### Support Resources
- **Documentation**: Check service-specific documentation
- **Community**: TheHive, Cortex, and MISP community forums
- **Issues**: Create GitHub issues for platform-specific problems

### Recovery Procedures

#### Complete Platform Reset
```bash
# Stop all services
./deploy/manage-soar.sh stop

# Remove all containers and volumes (DATA LOSS!)
docker compose down -v --remove-orphans

# Reinstall platform
sudo ./deploy/deploy-soar-platform.sh
```

#### Service-Specific Recovery
```bash
# Reset specific service data
docker compose stop thehive
docker volume rm soc-soar_thehive_data
docker compose up -d thehive
```

## 📞 Support & Contributing

For support, feature requests, or contributions:
1. Check the troubleshooting section above
2. Review service-specific documentation
3. Create an issue with detailed information
4. Submit pull requests for improvements

## 📄 License

This deployment system is provided under the same license as the main project. See LICENSE file for details.

---

**⚠️ Important Security Notice**: This deployment system includes default passwords and configurations suitable for testing and development. Always change default credentials and review security settings before deploying in production environments.