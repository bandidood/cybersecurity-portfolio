#!/bin/bash

# SOC SOAR Platform Management Script
# Provides simplified management commands for the SOAR platform
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
DOCKER_COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
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
    
    SOC SOAR Platform Management
    
EOF
}

check_prerequisites() {
    # Check if running as root for system operations
    if [[ "$1" =~ ^(install|uninstall|update-system)$ ]] && [[ $EUID -ne 0 ]]; then
        error "This operation must be run as root"
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker > /dev/null; then
        error "Docker is not installed"
        exit 1
    fi
    
    # Check if Docker Compose is available
    if ! docker compose version > /dev/null 2>&1; then
        if ! docker-compose --version > /dev/null 2>&1; then
            error "Docker Compose is not available"
            exit 1
        fi
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    # Check if installation directory exists for non-install operations
    if [[ "$1" != "install" ]] && [[ ! -d "$INSTALL_DIR" ]]; then
        error "SOC SOAR platform is not installed. Run 'install' first."
        exit 1
    fi
}

show_status() {
    log "Checking SOC SOAR Platform status..."
    
    if [[ ! -f "$DOCKER_COMPOSE_FILE" ]]; then
        error "Docker Compose file not found at $DOCKER_COMPOSE_FILE"
        return 1
    fi
    
    cd "$INSTALL_DIR"
    
    echo
    echo -e "${BLUE}=== Docker Compose Services ===${NC}"
    $COMPOSE_CMD ps
    
    echo
    echo -e "${BLUE}=== Service Health Status ===${NC}"
    local services=("thehive" "cortex" "misp" "elasticsearch" "kibana" "grafana" "prometheus")
    
    for service in "${services[@]}"; do
        if $COMPOSE_CMD ps "$service" 2>/dev/null | grep -q "Up"; then
            echo -e "${GREEN}✓${NC} $service: Running"
        else
            echo -e "${RED}✗${NC} $service: Not running"
        fi
    done
    
    echo
    echo -e "${BLUE}=== System Resources ===${NC}"
    echo "Memory Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -20
}

start_platform() {
    log "Starting SOC SOAR Platform..."
    
    cd "$INSTALL_DIR"
    $COMPOSE_CMD up -d
    
    log "Waiting for services to be ready..."
    sleep 30
    
    # Check if critical services are running
    local failed_services=()
    local services=("thehive" "cortex" "misp" "elasticsearch")
    
    for service in "${services[@]}"; do
        if ! $COMPOSE_CMD ps "$service" | grep -q "Up"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log "All critical services started successfully"
    else
        error "Failed to start services: ${failed_services[*]}"
        show_logs "${failed_services[@]}"
    fi
}

stop_platform() {
    log "Stopping SOC SOAR Platform..."
    
    cd "$INSTALL_DIR"
    $COMPOSE_CMD stop
    
    log "Platform stopped successfully"
}

restart_platform() {
    log "Restarting SOC SOAR Platform..."
    
    cd "$INSTALL_DIR"
    $COMPOSE_CMD restart
    
    log "Waiting for services to be ready..."
    sleep 30
    
    log "Platform restarted successfully"
}

show_logs() {
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        services=("thehive" "cortex" "misp" "elasticsearch" "kibana")
    fi
    
    log "Showing logs for services: ${services[*]}"
    
    cd "$INSTALL_DIR"
    
    for service in "${services[@]}"; do
        echo
        echo -e "${BLUE}=== $service logs ===${NC}"
        $COMPOSE_CMD logs --tail=50 "$service"
    done
}

update_platform() {
    log "Updating SOC SOAR Platform..."
    
    cd "$INSTALL_DIR"
    
    # Pull latest images
    log "Pulling latest Docker images..."
    $COMPOSE_CMD pull
    
    # Restart services with new images
    log "Restarting services with updated images..."
    $COMPOSE_CMD up -d
    
    # Remove unused images
    log "Cleaning up unused Docker images..."
    docker image prune -f
    
    log "Platform updated successfully"
}

backup_platform() {
    local backup_name="${1:-soc-backup-$(date +%Y%m%d_%H%M%S)}"
    local backup_dir="/var/backups/soc-soar"
    
    log "Creating backup: $backup_name"
    
    mkdir -p "$backup_dir"
    
    cd "$INSTALL_DIR"
    
    # Stop services for consistent backup
    log "Stopping services for backup..."
    $COMPOSE_CMD stop
    
    # Create backup directory
    local backup_path="$backup_dir/$backup_name"
    mkdir -p "$backup_path"
    
    # Backup Docker volumes
    log "Backing up Docker volumes..."
    docker run --rm \
        -v "${INSTALL_DIR##*/}_elasticsearch_data:/data/elasticsearch" \
        -v "${INSTALL_DIR##*/}_cassandra_data:/data/cassandra" \
        -v "${INSTALL_DIR##*/}_thehive_data:/data/thehive" \
        -v "${INSTALL_DIR##*/}_cortex_data:/data/cortex" \
        -v "${INSTALL_DIR##*/}_misp_data:/data/misp" \
        -v "${INSTALL_DIR##*/}_misp_db_data:/data/misp_db" \
        -v "${INSTALL_DIR##*/}_grafana_data:/data/grafana" \
        -v "${INSTALL_DIR##*/}_prometheus_data:/data/prometheus" \
        -v "$backup_path:/backup" \
        busybox tar czf /backup/volumes.tar.gz /data/
    
    # Backup configuration files
    log "Backing up configuration files..."
    tar czf "$backup_path/configs.tar.gz" -C "$INSTALL_DIR" config/
    tar czf "$backup_path/platform.tar.gz" -C "$INSTALL_DIR" .
    
    # Create backup manifest
    cat > "$backup_path/manifest.txt" << EOF
SOC SOAR Platform Backup
========================
Backup Date: $(date)
Backup Name: $backup_name
Hostname: $(hostname)
Platform Version: $(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo "unknown")

Files:
- volumes.tar.gz: Docker volume data
- configs.tar.gz: Configuration files  
- platform.tar.gz: Platform files
- manifest.txt: This file

Restore Instructions:
1. Stop the platform: $0 stop
2. Extract backups to installation directory
3. Start the platform: $0 start
EOF
    
    # Restart services
    log "Restarting services..."
    $COMPOSE_CMD start
    
    log "Backup completed successfully: $backup_path"
}

restore_platform() {
    local backup_path="$1"
    
    if [[ -z "$backup_path" ]]; then
        error "Please specify backup path"
        exit 1
    fi
    
    if [[ ! -d "$backup_path" ]]; then
        error "Backup directory not found: $backup_path"
        exit 1
    fi
    
    log "Restoring from backup: $backup_path"
    
    # Stop platform
    cd "$INSTALL_DIR"
    $COMPOSE_CMD down
    
    # Restore volumes
    if [[ -f "$backup_path/volumes.tar.gz" ]]; then
        log "Restoring Docker volumes..."
        docker run --rm \
            -v "${INSTALL_DIR##*/}_elasticsearch_data:/data/elasticsearch" \
            -v "${INSTALL_DIR##*/}_cassandra_data:/data/cassandra" \
            -v "${INSTALL_DIR##*/}_thehive_data:/data/thehive" \
            -v "${INSTALL_DIR##*/}_cortex_data:/data/cortex" \
            -v "${INSTALL_DIR##*/}_misp_data:/data/misp" \
            -v "${INSTALL_DIR##*/}_misp_db_data:/data/misp_db" \
            -v "${INSTALL_DIR##*/}_grafana_data:/data/grafana" \
            -v "${INSTALL_DIR##*/}_prometheus_data:/data/prometheus" \
            -v "$backup_path:/backup" \
            busybox tar xzf /backup/volumes.tar.gz -C /
    fi
    
    # Restore configuration files
    if [[ -f "$backup_path/configs.tar.gz" ]]; then
        log "Restoring configuration files..."
        tar xzf "$backup_path/configs.tar.gz" -C "$INSTALL_DIR"
    fi
    
    # Start platform
    log "Starting restored platform..."
    $COMPOSE_CMD up -d
    
    log "Restore completed successfully"
}

cleanup_platform() {
    log "Cleaning up SOC SOAR Platform..."
    
    cd "$INSTALL_DIR"
    
    # Stop and remove containers
    $COMPOSE_CMD down
    
    # Remove unused volumes (with confirmation)
    read -p "Remove all Docker volumes? This will DELETE ALL DATA! (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker volume prune -f
    fi
    
    # Remove unused images
    docker image prune -a -f
    
    # Remove unused networks
    docker network prune -f
    
    log "Cleanup completed"
}

show_urls() {
    local server_ip=$(ip route get 1 2>/dev/null | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p' || echo "localhost")
    
    cat << EOF

${GREEN}SOC SOAR Platform Access URLs:${NC}
════════════════════════════════════════

🔗 TheHive:             http://$server_ip:9000
🔗 Cortex:              http://$server_ip:9001  
🔗 MISP:                http://$server_ip:8080
🔗 Kibana:              http://$server_ip:5601
🔗 Grafana:             http://$server_ip:3000
🔗 Prometheus:          http://$server_ip:9090
🔗 Traefik Dashboard:   http://$server_ip:8080

EOF
}

install_platform() {
    log "Installing SOC SOAR Platform..."
    
    # Run the main deployment script
    local deploy_script="$SCRIPT_DIR/deploy-soar-platform.sh"
    
    if [[ ! -f "$deploy_script" ]]; then
        error "Deployment script not found: $deploy_script"
        exit 1
    fi
    
    bash "$deploy_script" "$@"
}

uninstall_platform() {
    warn "This will completely remove the SOC SOAR platform and all data!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Uninstall cancelled"
        exit 0
    fi
    
    log "Uninstalling SOC SOAR Platform..."
    
    # Stop and remove containers
    if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
        cd "$INSTALL_DIR"
        $COMPOSE_CMD down -v --remove-orphans
    fi
    
    # Remove systemd service
    systemctl stop soc-soar.service 2>/dev/null || true
    systemctl disable soc-soar.service 2>/dev/null || true
    rm -f /etc/systemd/system/soc-soar.service
    systemctl daemon-reload
    
    # Remove installation directory
    rm -rf "$INSTALL_DIR"
    
    # Remove log directory
    rm -rf "$LOG_DIR"
    
    # Remove configuration directory
    rm -rf "/etc/soc"
    
    # Remove data directory
    rm -rf "/var/lib/soc"
    
    # Remove cron jobs
    crontab -l 2>/dev/null | grep -v "/opt/soc-soar" | crontab - 2>/dev/null || true
    
    log "Platform uninstalled successfully"
}

run_health_check() {
    log "Running health check..."
    
    local health_check_script="$INSTALL_DIR/health-check.sh"
    
    if [[ -f "$health_check_script" ]]; then
        bash "$health_check_script"
    else
        # Simple health check
        cd "$INSTALL_DIR"
        local failed=0
        local services=("thehive:9000" "cortex:9001" "misp:80" "elasticsearch:9200" "kibana:5601" "grafana:3000")
        
        for service in "${services[@]}"; do
            local name=$(echo "$service" | cut -d: -f1)
            local port=$(echo "$service" | cut -d: -f2)
            
            if curl -f -s --max-time 5 "http://localhost:$port" > /dev/null 2>&1; then
                echo -e "${GREEN}✓${NC} $name is healthy"
            else
                echo -e "${RED}✗${NC} $name is not responding"
                ((failed++))
            fi
        done
        
        if [[ $failed -eq 0 ]]; then
            log "All services are healthy"
        else
            error "$failed services failed health check"
            exit 1
        fi
    fi
}

generate_config() {
    local config_type="$1"
    
    case "$config_type" in
        "env")
            log "Generating environment configuration..."
            cat > "$INSTALL_DIR/.env.example" << 'EOF'
# SOC SOAR Platform Environment Configuration
# Copy this file to .env and modify as needed

# Network Configuration
COMPOSE_PROJECT_NAME=soc-soar
NETWORK_SUBNET=172.20.0.0/16

# Security Configuration (CHANGE IN PRODUCTION!)
ELASTICSEARCH_PASSWORD=changeme123
KIBANA_PASSWORD=changeme123
THEHIVE_SECRET=thehive-secret-change-in-production
CORTEX_SECRET=cortex-secret-change-in-production
MISP_ADMIN_PASSWORD=admin-password-change-me
MYSQL_ROOT_PASSWORD=root-password-change-me
REDIS_PASSWORD=redis-password
GRAFANA_ADMIN_PASSWORD=grafana-admin-password

# Service Versions
THEHIVE_VERSION=5.2
CORTEX_VERSION=3.1.7
MISP_VERSION=core-latest
ELASTICSEARCH_VERSION=8.10.4

# API Keys (Generate these after initial setup)
MISP_API_KEY=
THEHIVE_API_KEY=
CORTEX_API_KEY=

# External Services
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
EMAIL_SMTP_SERVER=
EMAIL_USERNAME=
EMAIL_PASSWORD=
EOF
            log "Environment configuration template created at $INSTALL_DIR/.env.example"
            ;;
        *)
            error "Unknown configuration type: $config_type"
            exit 1
            ;;
    esac
}

show_help() {
    cat << EOF
SOC SOAR Platform Management Script

Usage: $0 <command> [options]

Commands:
  install              Install the SOC SOAR platform
  uninstall           Uninstall the platform completely  
  start               Start all platform services
  stop                Stop all platform services
  restart             Restart all platform services
  status              Show platform and service status
  logs [service...]   Show logs for specified services (or all)
  update              Update platform to latest versions
  backup [name]       Create a backup of the platform
  restore <path>      Restore from backup
  cleanup             Clean up unused Docker resources
  health              Run health check on all services
  urls                Show access URLs for all services
  config <type>       Generate configuration files

Options:
  --debug             Enable debug output
  --help              Show this help message

Examples:
  $0 install          # Install the platform
  $0 start            # Start all services
  $0 logs thehive cortex  # Show logs for TheHive and Cortex
  $0 backup backup-20231215  # Create named backup
  $0 health           # Check service health
  $0 config env       # Generate environment config template

For more information, visit:
https://github.com/soc-team/soar-platform
EOF
}

main() {
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    if [[ $# -eq 0 ]]; then
        print_banner
        show_help
        exit 1
    fi
    
    local command="$1"
    shift
    
    # Check prerequisites for the command
    check_prerequisites "$command"
    
    case "$command" in
        "install")
            install_platform "$@"
            ;;
        "uninstall")
            uninstall_platform
            ;;
        "start")
            start_platform
            ;;
        "stop")
            stop_platform
            ;;
        "restart")
            restart_platform
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs "$@"
            ;;
        "update")
            update_platform
            ;;
        "backup")
            backup_platform "$1"
            ;;
        "restore")
            restore_platform "$1"
            ;;
        "cleanup")
            cleanup_platform
            ;;
        "health")
            run_health_check
            ;;
        "urls")
            show_urls
            ;;
        "config")
            generate_config "$1"
            ;;
        *)
            error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"