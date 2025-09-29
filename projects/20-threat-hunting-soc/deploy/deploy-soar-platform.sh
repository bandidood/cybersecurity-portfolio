#!/bin/bash

# SOC SOAR Platform Deployment Script
# Automated deployment and configuration for TheHive, Cortex, MISP integration
# Author: SOC Team
# Version: 1.0.0

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALL_DIR="/opt/soc-soar"
LOG_DIR="/var/log/soc"
DATA_DIR="/var/lib/soc"
CONFIG_DIR="/etc/soc"

# Version information
DOCKER_COMPOSE_VERSION="3.8"
MIN_DOCKER_VERSION="20.0.0"
MIN_DOCKER_COMPOSE_VERSION="2.0.0"

# Default passwords (CHANGE IN PRODUCTION!)
DEFAULT_PASSWORDS=(
    "ELASTICSEARCH_PASSWORD=changeme123"
    "KIBANA_PASSWORD=changeme123"
    "THEHIVE_SECRET=thehive-secret-change-in-production"
    "CORTEX_SECRET=cortex-secret-change-in-production"
    "MISP_ADMIN_PASSWORD=admin-password-change-me"
    "MYSQL_ROOT_PASSWORD=root-password-change-me"
    "REDIS_PASSWORD=redis-password"
    "GRAFANA_ADMIN_PASSWORD=grafana-admin-password"
)

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_DIR/deployment.log"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_DIR/deployment.log"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_DIR/deployment.log"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" | tee -a "$LOG_DIR/deployment.log"
    fi
}

print_banner() {
    cat << "EOF"
    
    ███████╗ ██████╗  ██████╗    ███████╗ ██████╗  █████╗ ██████╗ 
    ██╔════╝██╔═══██╗██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██╔══██╗
    ███████╗██║   ██║██║         ███████╗██║   ██║███████║██████╔╝
    ╚════██║██║   ██║██║         ╚════██║██║   ██║██╔══██║██╔══██╗
    ███████║╚██████╔╝╚██████╗    ███████║╚██████╔╝██║  ██║██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    
    SOC SOAR Platform Deployment Script
    TheHive + Cortex + MISP + Elasticsearch + Monitoring
    
EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS version"
        exit 1
    fi
    
    . /etc/os-release
    log "Operating System: $PRETTY_NAME"
    
    # Check memory
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $mem_gb -lt 8 ]]; then
        warn "Recommended minimum memory is 8GB, found ${mem_gb}GB"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log "Memory check passed: ${mem_gb}GB"
    fi
    
    # Check disk space
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [[ $disk_gb -lt 50 ]]; then
        warn "Recommended minimum disk space is 50GB, found ${disk_gb}GB"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log "Disk space check passed: ${disk_gb}GB available"
    fi
    
    # Check network connectivity
    if ! curl -s --connect-timeout 5 https://google.com > /dev/null; then
        error "No internet connectivity detected"
        exit 1
    fi
    log "Network connectivity check passed"
}

install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package lists
    case "$ID" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y \
                curl \
                wget \
                git \
                unzip \
                jq \
                htop \
                vim \
                net-tools \
                ca-certificates \
                gnupg \
                lsb-release \
                software-properties-common \
                apt-transport-https
            ;;
        centos|rhel|fedora)
            if command -v dnf > /dev/null; then
                dnf install -y \
                    curl \
                    wget \
                    git \
                    unzip \
                    jq \
                    htop \
                    vim \
                    net-tools \
                    ca-certificates
            else
                yum install -y \
                    curl \
                    wget \
                    git \
                    unzip \
                    jq \
                    htop \
                    vim \
                    net-tools \
                    ca-certificates
            fi
            ;;
        *)
            error "Unsupported operating system: $ID"
            exit 1
            ;;
    esac
    
    log "System dependencies installed successfully"
}

install_docker() {
    log "Installing Docker..."
    
    # Check if Docker is already installed
    if command -v docker > /dev/null; then
        local docker_version=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
        log "Docker is already installed: version $docker_version"
        
        # Check if version is sufficient
        if docker --version | grep -qE "([2-9][0-9]|1[0-9]|[2-9][0-9]\.[0-9]+\.[0-9]+)"; then
            log "Docker version is sufficient"
        else
            warn "Docker version might be too old, continuing anyway..."
        fi
    else
        # Install Docker
        case "$ID" in
            ubuntu|debian)
                # Add Docker's official GPG key
                curl -fsSL https://download.docker.com/linux/$ID/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                
                # Add Docker repository
                echo \
                    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$ID \
                    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
                
                # Install Docker Engine
                apt-get update -qq
                apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
            centos|rhel)
                # Add Docker repository
                yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
            fedora)
                dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
                dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
        esac
        
        log "Docker installed successfully"
    fi
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Add current user to docker group if not root
    if [[ $SUDO_USER ]]; then
        usermod -aG docker $SUDO_USER
        log "Added $SUDO_USER to docker group"
    fi
    
    # Test Docker installation
    if docker run hello-world > /dev/null 2>&1; then
        log "Docker installation verified successfully"
    else
        error "Docker installation verification failed"
        exit 1
    fi
}

install_docker_compose() {
    log "Installing Docker Compose..."
    
    # Check if Docker Compose plugin is available
    if docker compose version > /dev/null 2>&1; then
        local compose_version=$(docker compose version | cut -d' ' -f4)
        log "Docker Compose plugin is already available: version $compose_version"
        return 0
    fi
    
    # Install standalone Docker Compose as fallback
    local compose_version="2.20.3"
    curl -L "https://github.com/docker/compose/releases/download/v${compose_version}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Create symlink for compatibility
    if [[ ! -e /usr/bin/docker-compose ]]; then
        ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
    
    # Verify installation
    if docker-compose --version > /dev/null 2>&1; then
        log "Docker Compose installed successfully"
    else
        error "Docker Compose installation failed"
        exit 1
    fi
}

create_directories() {
    log "Creating directory structure..."
    
    # Create main directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Create data subdirectories
    mkdir -p "$DATA_DIR"/{elasticsearch,cassandra,redis,thehive,cortex,misp,grafana,prometheus}
    
    # Create log subdirectories  
    mkdir -p "$LOG_DIR"/{elasticsearch,thehive,cortex,misp,integration}
    
    # Create config subdirectories
    mkdir -p "$CONFIG_DIR"/{thehive,cortex,misp,elasticsearch,kibana,grafana,prometheus}
    
    # Set permissions
    chown -R 1000:1000 "$DATA_DIR/elasticsearch"
    chown -R 472:472 "$DATA_DIR/grafana"
    chown -R 65534:65534 "$DATA_DIR/prometheus"
    
    log "Directory structure created successfully"
}

copy_configuration_files() {
    log "Copying configuration files..."
    
    # Copy Docker Compose files
    cp "$PROJECT_ROOT/configs/docker-compose.yml" "$INSTALL_DIR/"
    
    # Copy configuration files
    cp -r "$PROJECT_ROOT/configs/thehive"/* "$CONFIG_DIR/thehive/"
    cp -r "$PROJECT_ROOT/configs/cortex"/* "$CONFIG_DIR/cortex/"
    
    # Copy custom files if they exist
    if [[ -d "$PROJECT_ROOT/configs/elasticsearch" ]]; then
        cp -r "$PROJECT_ROOT/configs/elasticsearch"/* "$CONFIG_DIR/elasticsearch/"
    fi
    
    if [[ -d "$PROJECT_ROOT/configs/kibana" ]]; then
        cp -r "$PROJECT_ROOT/configs/kibana"/* "$CONFIG_DIR/kibana/"
    fi
    
    if [[ -d "$PROJECT_ROOT/configs/grafana" ]]; then
        cp -r "$PROJECT_ROOT/configs/grafana"/* "$CONFIG_DIR/grafana/"
    fi
    
    if [[ -d "$PROJECT_ROOT/configs/prometheus" ]]; then
        cp -r "$PROJECT_ROOT/configs/prometheus"/* "$CONFIG_DIR/prometheus/"
    fi
    
    # Copy analyzers and responders
    if [[ -d "$PROJECT_ROOT/analyzers" ]]; then
        mkdir -p "$INSTALL_DIR/analyzers"
        cp -r "$PROJECT_ROOT/analyzers"/* "$INSTALL_DIR/analyzers/"
    fi
    
    if [[ -d "$PROJECT_ROOT/responders" ]]; then
        mkdir -p "$INSTALL_DIR/responders"
        cp -r "$PROJECT_ROOT/responders"/* "$INSTALL_DIR/responders/"
    fi
    
    # Copy integration scripts
    if [[ -d "$PROJECT_ROOT/integration" ]]; then
        mkdir -p "$INSTALL_DIR/integration"
        cp -r "$PROJECT_ROOT/integration"/* "$INSTALL_DIR/integration/"
    fi
    
    # Copy playbooks
    if [[ -d "$PROJECT_ROOT/playbooks" ]]; then
        mkdir -p "$INSTALL_DIR/playbooks"
        cp -r "$PROJECT_ROOT/playbooks"/* "$INSTALL_DIR/playbooks/"
    fi
    
    log "Configuration files copied successfully"
}

generate_ssl_certificates() {
    log "Generating SSL certificates..."
    
    local ssl_dir="$CONFIG_DIR/ssl"
    mkdir -p "$ssl_dir"
    
    # Generate CA key and certificate
    openssl genrsa -out "$ssl_dir/ca-key.pem" 4096
    openssl req -new -x509 -days 365 -key "$ssl_dir/ca-key.pem" -out "$ssl_dir/ca-cert.pem" \
        -subj "/C=US/ST=CA/L=SOC/O=Security Operations/OU=IT Department/CN=SOC-CA"
    
    # Generate server key and certificate signing request
    openssl genrsa -out "$ssl_dir/server-key.pem" 4096
    openssl req -subj "/C=US/ST=CA/L=SOC/O=Security Operations/OU=IT Department/CN=soc.local" \
        -new -key "$ssl_dir/server-key.pem" -out "$ssl_dir/server-csr.pem"
    
    # Generate server certificate
    openssl x509 -req -days 365 -in "$ssl_dir/server-csr.pem" -CA "$ssl_dir/ca-cert.pem" \
        -CAkey "$ssl_dir/ca-key.pem" -CAcreateserial -out "$ssl_dir/server-cert.pem"
    
    # Generate keystore for Java applications (TheHive)
    if command -v keytool > /dev/null; then
        keytool -genkey -alias thehive -keyalg RSA -keystore "$ssl_dir/keystore.jks" \
            -storepass thehive-keystore-password -keypass thehive-keystore-password \
            -dname "CN=soc.local, OU=IT, O=SOC, L=City, S=State, C=US" -validity 365
        
        keytool -genkey -alias cortex -keyalg RSA -keystore "$ssl_dir/cortex-keystore.jks" \
            -storepass cortex-keystore-password -keypass cortex-keystore-password \
            -dname "CN=soc.local, OU=IT, O=SOC, L=City, S=State, C=US" -validity 365
    else
        warn "keytool not found, skipping Java keystore generation"
    fi
    
    # Set appropriate permissions
    chmod 600 "$ssl_dir"/*key*.pem
    chmod 644 "$ssl_dir"/*cert*.pem
    
    log "SSL certificates generated successfully"
}

create_environment_file() {
    log "Creating environment configuration..."
    
    local env_file="$INSTALL_DIR/.env"
    cat > "$env_file" << EOF
# SOC SOAR Platform Environment Configuration
# Generated on $(date)

# Directories
INSTALL_DIR=$INSTALL_DIR
LOG_DIR=$LOG_DIR
DATA_DIR=$DATA_DIR
CONFIG_DIR=$CONFIG_DIR

# Network Configuration
COMPOSE_PROJECT_NAME=soc-soar
NETWORK_SUBNET=172.20.0.0/16

# Security Configuration (CHANGE IN PRODUCTION!)
EOF
    
    # Add default passwords
    for password in "${DEFAULT_PASSWORDS[@]}"; do
        echo "$password" >> "$env_file"
    done
    
    cat >> "$env_file" << EOF

# Service Versions
THEHIVE_VERSION=5.2
CORTEX_VERSION=3.1.7
MISP_VERSION=core-latest
ELASTICSEARCH_VERSION=8.10.4
KIBANA_VERSION=8.10.4
GRAFANA_VERSION=latest
PROMETHEUS_VERSION=latest

# Resource Limits
ELASTICSEARCH_HEAP_SIZE=2g
THEHIVE_HEAP_SIZE=2g
CORTEX_HEAP_SIZE=1g
CASSANDRA_HEAP_SIZE=2g

# Feature Flags
ENABLE_SSL=true
ENABLE_MONITORING=true
ENABLE_INTEGRATION=true
ENABLE_BACKUP=true

EOF
    
    # Set restrictive permissions on environment file
    chmod 600 "$env_file"
    
    log "Environment configuration created successfully"
}

setup_system_limits() {
    log "Configuring system limits..."
    
    # Set vm.max_map_count for Elasticsearch
    echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
    sysctl -p > /dev/null
    
    # Set file descriptor limits
    cat >> /etc/security/limits.conf << EOF

# SOC SOAR Platform limits
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096

* soft nofile 65536
* hard nofile 65536

EOF
    
    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/soc-limits.conf << EOF
[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=4096
EOF
    
    systemctl daemon-reload
    
    log "System limits configured successfully"
}

setup_firewall() {
    log "Configuring firewall..."
    
    # Check if ufw is available (Ubuntu/Debian)
    if command -v ufw > /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # SSH access
        ufw allow 22/tcp
        
        # SOC platform services
        ufw allow 80/tcp    # Traefik HTTP
        ufw allow 443/tcp   # Traefik HTTPS  
        ufw allow 9000/tcp  # TheHive
        ufw allow 9001/tcp  # Cortex
        ufw allow 8080/tcp  # MISP
        ufw allow 5601/tcp  # Kibana
        ufw allow 3000/tcp  # Grafana
        ufw allow 9090/tcp  # Prometheus
        
        # Enable firewall
        ufw --force enable
        ufw status
        
    # Check if firewalld is available (CentOS/RHEL/Fedora)
    elif command -v firewall-cmd > /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=9000/tcp
        firewall-cmd --permanent --add-port=9001/tcp
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --permanent --add-port=5601/tcp
        firewall-cmd --permanent --add-port=3000/tcp
        firewall-cmd --permanent --add-port=9090/tcp
        firewall-cmd --reload
        
    else
        warn "No supported firewall found (ufw/firewalld). Please configure manually."
    fi
    
    log "Firewall configured successfully"
}

create_systemd_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/soc-soar.service << EOF
[Unit]
Description=SOC SOAR Platform
Documentation=https://github.com/soc-team/soar-platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose restart
TimeoutStartSec=0
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable soc-soar.service
    
    log "Systemd service created successfully"
}

install_python_dependencies() {
    log "Installing Python dependencies for integration scripts..."
    
    # Install pip if not available
    if ! command -v pip3 > /dev/null; then
        case "$ID" in
            ubuntu|debian)
                apt-get install -y python3-pip
                ;;
            centos|rhel|fedora)
                if command -v dnf > /dev/null; then
                    dnf install -y python3-pip
                else
                    yum install -y python3-pip
                fi
                ;;
        esac
    fi
    
    # Install required Python packages
    pip3 install --upgrade pip
    pip3 install \
        requests \
        pyyaml \
        schedule \
        asyncio \
        pymisp \
        thehive4py \
        elasticsearch \
        redis \
        paramiko \
        pywinrm \
        ldap3 \
        twilio \
        prometheus-client
    
    log "Python dependencies installed successfully"
}

deploy_platform() {
    log "Deploying SOC SOAR platform..."
    
    cd "$INSTALL_DIR"
    
    # Pull Docker images
    log "Pulling Docker images..."
    docker compose pull
    
    # Start the platform
    log "Starting services..."
    docker compose up -d
    
    # Wait for services to be ready
    log "Waiting for services to start..."
    sleep 30
    
    # Check service health
    local failed_services=()
    local services=("thehive" "cortex" "misp" "elasticsearch" "kibana" "grafana" "prometheus")
    
    for service in "${services[@]}"; do
        if ! docker compose ps "$service" | grep -q "Up"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log "All services started successfully"
    else
        error "Failed to start services: ${failed_services[*]}"
        log "Checking service logs..."
        for service in "${failed_services[@]}"; do
            echo "=== $service logs ==="
            docker compose logs --tail=20 "$service"
            echo
        done
    fi
    
    log "Platform deployment completed"
}

setup_monitoring() {
    log "Setting up monitoring and health checks..."
    
    # Create health check script
    cat > "$INSTALL_DIR/health-check.sh" << 'EOF'
#!/bin/bash

# SOC SOAR Platform Health Check Script

INSTALL_DIR="/opt/soc-soar"
LOG_FILE="/var/log/soc/health-check.log"

cd "$INSTALL_DIR"

echo "$(date): Starting health check..." >> "$LOG_FILE"

# Check Docker Compose services
services=(
    "thehive:9000"
    "cortex:9001" 
    "misp:80"
    "elasticsearch:9200"
    "kibana:5601"
    "grafana:3000"
    "prometheus:9090"
)

failed_checks=0

for service in "${services[@]}"; do
    service_name=$(echo "$service" | cut -d: -f1)
    service_port=$(echo "$service" | cut -d: -f2)
    
    if docker compose ps "$service_name" | grep -q "Up"; then
        if curl -f -s "http://localhost:$service_port" > /dev/null 2>&1; then
            echo "$(date): ✓ $service_name is healthy" >> "$LOG_FILE"
        else
            echo "$(date): ✗ $service_name is not responding on port $service_port" >> "$LOG_FILE"
            ((failed_checks++))
        fi
    else
        echo "$(date): ✗ $service_name container is not running" >> "$LOG_FILE"
        ((failed_checks++))
    fi
done

if [[ $failed_checks -eq 0 ]]; then
    echo "$(date): All services are healthy" >> "$LOG_FILE"
    exit 0
else
    echo "$(date): $failed_checks services failed health check" >> "$LOG_FILE"
    exit 1
fi
EOF
    
    chmod +x "$INSTALL_DIR/health-check.sh"
    
    # Create cron job for health checks
    (crontab -l 2>/dev/null; echo "*/5 * * * * $INSTALL_DIR/health-check.sh") | crontab -
    
    log "Monitoring and health checks configured successfully"
}

create_backup_script() {
    log "Creating backup script..."
    
    cat > "$INSTALL_DIR/backup.sh" << 'EOF'
#!/bin/bash

# SOC SOAR Platform Backup Script

INSTALL_DIR="/opt/soc-soar"
BACKUP_DIR="/var/backups/soc-soar"
LOG_FILE="/var/log/soc/backup.log"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

timestamp=$(date +"%Y%m%d_%H%M%S")
backup_path="$BACKUP_DIR/soc-soar-backup-$timestamp"

echo "$(date): Starting backup to $backup_path" >> "$LOG_FILE"

cd "$INSTALL_DIR"

# Create backup directory
mkdir -p "$backup_path"

# Stop services
echo "$(date): Stopping services for backup..." >> "$LOG_FILE"
docker compose stop

# Backup Docker volumes
echo "$(date): Backing up Docker volumes..." >> "$LOG_FILE"
docker run --rm \
    -v soc-soar_elasticsearch_data:/data/elasticsearch \
    -v soc-soar_cassandra_data:/data/cassandra \
    -v soc-soar_misp_data:/data/misp \
    -v "$backup_path:/backup" \
    busybox tar czf /backup/volumes.tar.gz /data/

# Backup configuration files
echo "$(date): Backing up configuration files..." >> "$LOG_FILE"
tar czf "$backup_path/configs.tar.gz" -C /etc soc/
tar czf "$backup_path/install.tar.gz" -C /opt soc-soar/

# Create backup manifest
cat > "$backup_path/manifest.txt" << EOL
SOC SOAR Platform Backup
========================
Backup Date: $(date)
Hostname: $(hostname)
Docker Version: $(docker --version)
Docker Compose Version: $(docker compose version)

Files:
- volumes.tar.gz: Docker volume data
- configs.tar.gz: Configuration files
- install.tar.gz: Installation directory
- manifest.txt: This file
EOL

# Restart services
echo "$(date): Restarting services..." >> "$LOG_FILE"
docker compose start

# Cleanup old backups
echo "$(date): Cleaning up old backups..." >> "$LOG_FILE"
find "$BACKUP_DIR" -name "soc-soar-backup-*" -type d -mtime +$RETENTION_DAYS -exec rm -rf {} +

echo "$(date): Backup completed successfully" >> "$LOG_FILE"
EOF
    
    chmod +x "$INSTALL_DIR/backup.sh"
    
    # Create daily backup cron job
    (crontab -l 2>/dev/null; echo "0 2 * * * $INSTALL_DIR/backup.sh") | crontab -
    
    log "Backup script created successfully"
}

print_access_information() {
    local server_ip=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
    
    cat << EOF

${GREEN}╔══════════════════════════════════════════════════════════════════╗
║                    DEPLOYMENT COMPLETED SUCCESSFULLY!               ║
╚══════════════════════════════════════════════════════════════════╝${NC}

${BLUE}Service Access Information:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔗 Traefik Dashboard:   http://$server_ip:8080
🔗 TheHive:             http://$server_ip:9000
🔗 Cortex:              http://$server_ip:9001  
🔗 MISP:                http://$server_ip:8080
🔗 Kibana:              http://$server_ip:5601
🔗 Grafana:             http://$server_ip:3000
🔗 Prometheus:          http://$server_ip:9090

${YELLOW}Default Credentials (CHANGE IMMEDIATELY!):${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TheHive:    admin@thehive.local / secret
Cortex:     admin@cortex.local / secret  
MISP:       admin@admin.test / admin-password-change-me
Grafana:    admin / grafana-admin-password

${BLUE}Important Files:${NC}
━━━━━━━━━━━━━━━━━━━━

Installation:     $INSTALL_DIR
Logs:            $LOG_DIR  
Configuration:   $CONFIG_DIR
Environment:     $INSTALL_DIR/.env

${BLUE}Management Commands:${NC}
━━━━━━━━━━━━━━━━━━━━━━━

Start:           systemctl start soc-soar
Stop:            systemctl stop soc-soar
Restart:         systemctl restart soc-soar  
Status:          systemctl status soc-soar
Health Check:    $INSTALL_DIR/health-check.sh
Backup:          $INSTALL_DIR/backup.sh

${RED}⚠️  SECURITY REMINDERS:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Change ALL default passwords immediately
2. Configure proper SSL certificates for production
3. Review firewall rules and network access
4. Set up proper backup and monitoring procedures
5. Configure proper authentication (LDAP/SSO)

${GREEN}For support and documentation, visit:${NC}
https://github.com/soc-team/soar-platform

EOF
}

cleanup_on_failure() {
    error "Deployment failed. Cleaning up..."
    
    # Stop any running services
    if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
        cd "$INSTALL_DIR"
        docker compose down > /dev/null 2>&1 || true
    fi
    
    # Remove systemd service
    systemctl stop soc-soar.service > /dev/null 2>&1 || true
    systemctl disable soc-soar.service > /dev/null 2>&1 || true
    rm -f /etc/systemd/system/soc-soar.service
    systemctl daemon-reload
    
    error "Cleanup completed. Check logs for more information."
    exit 1
}

main() {
    # Set up error handling
    trap cleanup_on_failure ERR
    
    # Parse command line options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG=true
                shift
                ;;
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --config-only)
                CONFIG_ONLY=true
                shift
                ;;
            --help)
                echo "SOC SOAR Platform Deployment Script"
                echo ""
                echo "Options:"
                echo "  --debug       Enable debug output"
                echo "  --skip-docker Skip Docker installation"
                echo "  --config-only Only copy configuration files"
                echo "  --help        Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR"
    
    log "Starting SOC SOAR Platform deployment..."
    log "Deployment started at $(date)"
    
    # Pre-deployment checks
    check_root
    check_system_requirements
    
    # Install dependencies
    install_dependencies
    
    if [[ "${SKIP_DOCKER:-false}" != "true" ]]; then
        install_docker
        install_docker_compose
    fi
    
    install_python_dependencies
    
    # Setup system
    create_directories
    setup_system_limits
    
    # Configuration
    copy_configuration_files
    generate_ssl_certificates
    create_environment_file
    
    if [[ "${CONFIG_ONLY:-false}" == "true" ]]; then
        log "Configuration-only mode: skipping deployment"
        exit 0
    fi
    
    # Deployment
    create_systemd_service
    deploy_platform
    setup_monitoring
    create_backup_script
    
    # Security (optional, can be disruptive)
    if [[ "${SKIP_FIREWALL:-false}" != "true" ]]; then
        setup_firewall
    fi
    
    log "Deployment completed successfully at $(date)"
    
    # Show access information
    print_access_information
}

# Execute main function
main "$@"