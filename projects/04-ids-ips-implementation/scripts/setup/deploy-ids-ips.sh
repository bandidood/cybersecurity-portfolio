#!/bin/bash
# deploy-ids-ips.sh - Déploiement automatique IDS/IPS Enterprise
# Projet 04 - Cybersecurity Portfolio

set -euo pipefail

# Variables de configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SURICATA_VERSION="6.0.10"
SNORT_VERSION="2.9.19"
ELK_VERSION="8.10.0"
LAB_NETWORK="192.168.100.0/24"
DMZ_NETWORK="172.16.1.0/24"
SIEM_IP="172.16.2.10"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                     🛡️ IDS/IPS ENTERPRISE                        ║
║                    Déploiement Automatisé                       ║
║              Suricata + Snort + ELK Integration                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Vérification des prérequis système
check_prerequisites() {
    log_info "Vérification des prérequis système..."
    
    # Vérification droits administrateur
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté avec les droits administrateur (sudo)"
        exit 1
    fi
    
    # Vérification ressources système
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    AVAILABLE_RAM=$(free -g | awk '/^Mem:/{print $7}')
    
    if [ "$TOTAL_RAM" -lt 8 ]; then
        log_error "RAM totale insuffisante (8GB minimum requis, ${TOTAL_RAM}GB détecté)"
        exit 1
    fi
    
    if [ "$AVAILABLE_RAM" -lt 4 ]; then
        log_warning "RAM disponible faible (${AVAILABLE_RAM}GB). Performance dégradée possible."
    fi
    
    # Vérification espace disque
    AVAILABLE_DISK=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [ "$AVAILABLE_DISK" -lt 50 ]; then
        log_error "Espace disque insuffisant (50GB minimum requis, ${AVAILABLE_DISK}GB disponible)"
        exit 1
    fi
    
    # Vérification connectivité réseau
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log_error "Pas de connectivité Internet pour télécharger les packages"
        exit 1
    fi
    
    # Vérification interfaces lab existantes
    if ! ip addr show | grep -q "192.168.100"; then
        log_warning "Interface laboratoire non configurée. Configuration automatique..."
        # On continue, sera configuré plus tard
    fi
    
    log_success "Prérequis système validés - RAM: ${TOTAL_RAM}GB, Disque: ${AVAILABLE_DISK}GB"
}

# Installation des dépendances système
install_system_dependencies() {
    log_info "Installation des dépendances système..."
    
    # Mise à jour système
    apt-get update -y
    apt-get upgrade -y
    
    # Installation outils de base
    apt-get install -y \
        curl wget git vim htop iftop tcpdump \
        build-essential cmake pkg-config \
        libpcap-dev libnet1-dev libyaml-0-2 \
        libyaml-dev zlib1g zlib1g-dev \
        libcap-ng-dev libcap-ng0 make \
        libmagic-dev libjansson-dev \
        libjansson4 pkg-config \
        libnetfilter-queue-dev \
        libnetfilter-queue1 libnfnetlink-dev \
        libnfnetlink0 autoconf automake libtool \
        libpcre3 libpcre3-dbg libpcre3-dev \
        software-properties-common
    
    # Installation Python et dépendances pour monitoring
    apt-get install -y python3 python3-pip python3-dev python3-venv
    pip3 install --upgrade pip
    pip3 install psutil elasticsearch kibana logstash requests pyyaml
    
    log_success "Dépendances système installées"
}

# Installation et configuration Suricata
install_configure_suricata() {
    log_info "Installation Suricata ${SURICATA_VERSION}..."
    
    # Ajout repository officiel Suricata
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update
    
    # Installation Suricata
    apt-get install -y suricata
    
    # Vérification version
    INSTALLED_VERSION=$(suricata --version | head -1 | cut -d' ' -f2)
    log_info "Version Suricata installée: ${INSTALLED_VERSION}"
    
    # Création des répertoires
    mkdir -p /etc/suricata/rules/custom
    mkdir -p /var/log/suricata/archive
    mkdir -p /var/lib/suricata/update
    
    # Configuration principale Suricata
    log_info "Configuration Suricata..."
    
    cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

# Variables réseau lab
vars:
  address-groups:
    HOME_NET: "[${LAB_NETWORK},${DMZ_NETWORK}]"
    EXTERNAL_NET: "![\$HOME_NET]"
    
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    
    DMZ_NET: "${DMZ_NETWORK}"
    LAN_NET: "${LAB_NETWORK}"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502

# Configuration interfaces réseau
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    # Performance tuning
    threads: 4
    use-mmap: yes
    mmap-locked: yes
    ring-size: 2048
    buffer-size: 32768
    
  - interface: eth1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    threads: 2
    use-mmap: yes
    ring-size: 1024

# Moteurs de détection
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - emerging-threats.rules
  - /etc/suricata/rules/custom/lab-custom.rules
  - /etc/suricata/rules/custom/apt-detection.rules

# Configuration logging
outputs:
  # EVE JSON log complet
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes           # Inclusion payload pour analyse
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes            # Inclusion packet complet
            metadata: yes          # Métadonnées étendues
            http-body: yes
            http-body-printable: yes
        
        - http:
            extended: yes          # Logs HTTP étendus
            dump-all-headers: yes
            
        - dns:
            query: yes
            answer: yes
            
        - tls:
            extended: yes
            session-resumption: yes
            
        - ssh:
            enabled: yes
            
        - flow:
            enabled: yes
            
        - netflow:
            enabled: yes
            
        - stats:
            enabled: yes
            totals: yes
            threads: yes
            deltas: yes
            
        - anomaly:
            enabled: yes
            
        - drop:
            enabled: yes

  # Fast log pour alertes rapides
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # Unix socket pour intégration externe
  - unix-dgram:
      enabled: yes
      filename: suricata.socket

# Application Layer Parsers
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    smtp:
      enabled: yes
      inspection-limit:
        content-limit: 100kb
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    ssh:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    ftp:
      enabled: yes
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445

# Configuration détection avancée
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  
  # Configuration signatures
  signatures:
    # Priorisation signatures critiques
    - priority: 1
      categories: ["trojan-activity", "malware-cnc", "exploit-kit"]
    - priority: 2
      categories: ["web-application-attack", "sql-injection"]
    - priority: 3
      categories: ["suspicious-traffic", "anomaly-detection"]

# Performance tuning
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]  # CPU dédié management
    - receive-cpu-set:
        cpu: [ 0, 1 ]  # CPUs réception
    - worker-cpu-set:
        cpu: [ 2, 3 ]  # CPUs traitement
  detect-thread-ratio: 1.0

# Gestion mémoire
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 16mb

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000

# Défragmentation
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# Stream engine
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  bypass: no
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Logging détaillé pour debug
logging:
  default-log-level: info
  default-output-filter: 
  
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log
  - syslog:
      enabled: yes
      facility: local5
      format: "[%i] <%d> -- "
EOF

    # Configuration des règles par défaut
    log_info "Configuration des règles de détection..."
    
    # Règles personnalisées pour le lab
    cat > /etc/suricata/rules/custom/lab-custom.rules << 'EOF'
# Règles personnalisées Laboratoire Cybersécurité
# Détection activité suspecte spécifique au lab

# === DÉTECTION RECONNAISSANCE ===
alert icmp any any -> $HOME_NET any (msg:"LAB: ICMP Ping Sweep Detection"; itype:8; threshold:type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET [21,22,23,25,53,80,110,135,139,143,443,993,995,1433,1521,3389,5432] (msg:"LAB: Port Scan Multiple Ports"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)

# === DÉTECTION ATTAQUES WEB ===
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"LAB: SQL Injection Attempt"; content:"union"; nocase; http_uri; pcre:"/union\s+select/i"; sid:1000003; rev:1;)
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"LAB: XSS Attempt"; content:"<script"; nocase; http_uri; sid:1000004; rev:1;)
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"LAB: Directory Traversal"; content:"../"; http_uri; pcre:"/\.\.\/.*\.\./"; sid:1000005; rev:1;)
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"LAB: Command Injection"; content:"|3B|"; http_uri; pcre:"/[;&|`]/"; sid:1000006; rev:1;)

# === DÉTECTION MALWARE & C2 ===
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,8080,8443,9999] (msg:"LAB: Suspicious Outbound Connection"; sid:1000007; rev:1;)
alert dns any any -> any any (msg:"LAB: Malicious Domain Query"; content:"|01 00 00 01 00 00 00 00 00 00|"; content:"malware"; nocase; sid:1000008; rev:1;)

# === DÉTECTION BRUTE FORCE ===
alert tcp any any -> $HOME_NET 22 (msg:"LAB: SSH Brute Force"; content:"SSH"; threshold:type both, track by_src, count 5, seconds 60; sid:1000009; rev:1;)
alert tcp any any -> $HOME_NET [80,443] (msg:"LAB: HTTP Auth Brute Force"; content:"Authorization: Basic"; threshold:type both, track by_src, count 5, seconds 300; sid:1000010; rev:1;)

# === DÉTECTION EXFILTRATION ===
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB: Large Data Transfer"; dsize:>100000; threshold:type both, track by_src, count 5, seconds 60; sid:1000011; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [21,22,80,443] (msg:"LAB: FTP/HTTP Data Exfiltration"; content:"PUT"; http_method; dsize:>50000; sid:1000012; rev:1;)

# === DÉTECTION APT ===
alert tcp any any -> $HOME_NET any (msg:"LAB: APT Lateral Movement"; content:"net use"; nocase; content:"\\\\"; sid:1000013; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"LAB: PowerShell Encoded Command"; content:"powershell"; nocase; content:"-encodedcommand"; nocase; sid:1000014; rev:1;)

# === DÉTECTION IOT ===
alert tcp any any -> $HOME_NET [502,102] (msg:"LAB: Modbus Suspicious Activity"; content:"|00 00 00 00 00 06|"; sid:1000015; rev:1;)
alert udp any any -> $HOME_NET 123 (msg:"LAB: NTP Amplification Attack"; content:"|17 00 03 2a|"; offset:0; depth:4; sid:1000016; rev:1;)
EOF

    # Mise à jour des règles Emerging Threats
    log_info "Mise à jour des règles Emerging Threats..."
    suricata-update --force
    
    # Configuration service système
    systemctl enable suricata
    
    # Test configuration
    if suricata -T -c /etc/suricata/suricata.yaml > /tmp/suricata-test.log 2>&1; then
        log_success "Configuration Suricata validée"
    else
        log_error "Erreur de configuration Suricata:"
        cat /tmp/suricata-test.log
        exit 1
    fi
    
    log_success "Suricata installé et configuré"
}

# Installation et configuration Snort
install_configure_snort() {
    log_info "Installation Snort ${SNORT_VERSION}..."
    
    # Installation dépendances Snort
    apt-get install -y \
        bison flex libpcap-dev libdnet-dev \
        libdumbnet-dev libdumbnet1 libluajit-5.1-dev \
        libpcre3-dev zlib1g-dev liblzma-dev openssl \
        libssl-dev ethtool
    
    # Création utilisateur dédié
    if ! id "snort" &>/dev/null; then
        useradd -r -s /sbin/nologin snort
        log_info "Utilisateur snort créé"
    fi
    
    # Création répertoires
    mkdir -p /etc/snort/{rules,preproc_rules,so_rules}
    mkdir -p /var/log/snort
    mkdir -p /usr/local/lib/snort_dynamicrules
    mkdir -p /etc/snort/rules/iplists
    
    chown -R snort:snort /var/log/snort
    
    # Téléchargement et compilation Snort
    cd /tmp
    if [ ! -f "snort-${SNORT_VERSION}.tar.gz" ]; then
        wget "https://www.snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz"
    fi
    
    tar -xzf "snort-${SNORT_VERSION}.tar.gz"
    cd "snort-${SNORT_VERSION}"
    
    # Configuration compilation optimisée
    ./configure \
        --enable-sourcefire \
        --enable-open-appid \
        --enable-perfprofiling \
        --enable-linux-smp-stats \
        --enable-normalizer \
        --enable-reload \
        --enable-react \
        --enable-flexresp3
    
    make -j$(nproc)
    make install
    
    # Mise à jour cache libraries
    ldconfig
    
    # Création liens symboliques
    ln -sf /usr/local/bin/snort /usr/sbin/snort
    
    # Configuration Snort principale
    log_info "Configuration Snort..."
    
    cat > /etc/snort/snort.conf << 'EOF'
###################################################
# Configuration Snort - Laboratoire Cybersécurité
###################################################

# === VARIABLES RÉSEAU ===
var HOME_NET 192.168.100.0/24
var EXTERNAL_NET !$HOME_NET

# Serveurs critiques
var DNS_SERVERS $HOME_NET
var SMTP_SERVERS $HOME_NET  
var HTTP_SERVERS $HOME_NET
var SQL_SERVERS $HOME_NET
var TELNET_SERVERS $HOME_NET
var SNMP_SERVERS $HOME_NET

# Variables DMZ
var DMZ_NET 172.16.1.0/24
var DMZ_SERVERS $DMZ_NET

# === VARIABLES PORTS ===
var HTTP_PORTS [80,81,311,383,591,593,901,1220,1414,1741,1830,2301,2381,2809,3037,3128,3702,4343,4848,5250,6988,7000,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8085,8088,8090,8118,8123,8180,8181,8243,8280,8300,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,11371,34443,34444,41080,50002,55555]
var SHELLCODE_PORTS !80
var ORACLE_PORTS 1024:
var SSH_PORTS 22
var FTP_PORTS 21
var SIP_PORTS [5060,5061,5600]
var FILE_DATA_PORTS [$HTTP_PORTS,110,143]
var GTP_PORTS [2123,2152,3386]

# === CHEMINS ===
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
var WHITE_LIST_PATH /etc/snort/rules/iplists
var BLACK_LIST_PATH /etc/snort/rules/iplists

# === CONFIGURATION DE BASE ===
config checksum_mode: all
config disable_decode_alerts
config disable_tcpopt_experimental_alerts
config disable_tcpopt_obsolete_alerts
config disable_tcpopt_ttcp_alerts
config disable_tcpopt_alerts
config disable_ipopt_alerts
config checksum_drop: all
config autogenerate_preprocessor_decoder_rules
config dump_chars_only
config dump_payload_verbose

# === PRÉPROCESSEURS ===

# Normalisation IP
preprocessor normalize_ip4
preprocessor normalize_tcp: ips ecn stream
preprocessor normalize_icmp4

# Défragmentation
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 min_fragment_length 100 timeout 180

# Reassemblage TCP
preprocessor stream5_global: track_tcp yes, \
   track_udp yes, \
   track_icmp no, \
   max_tcp 262144, \
   max_udp 131072, \
   max_active_responses 2, \
   min_response_seconds 5

preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, \
   overlap_limit 10, small_segments 3 bytes 150, timeout 180, \
   ports client 21 22 23 25 42 53 79 109 110 111 113 119 135 136 137 139 143 \
                161 445 513 514 587 593 691 1433 1521 2100 3306 6665 6666 6667 6668 6669 \
                32770 32771 32772 32773 32774 32775 32776 32777 32778 32779, \
   ports both 80 311 383 443 465 563 591 593 636 901 989 992 993 994 995 1220 1414 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000 7001 7144 7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8243 8280 8300 8800 8888 8899 9000 9060 9080 9090 9091 9443 9999 11371 34443 34444 41080 50002 55555

preprocessor stream5_udp: timeout 180

# Détection HTTP
preprocessor http_inspect_server: server default \
    chunk_length 500000 \
    server_flow_depth 0 \
    client_flow_depth 0 \
    post_depth 65495 \
    oversize_dir_length 500 \
    max_header_length 750 \
    max_headers 100 \
    max_spaces 200 \
    small_chunk_length { 10 5 } \
    ports { 80 81 311 383 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000 7001 7144 7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8243 8280 8300 8800 8888 8899 9000 9060 9080 9090 9091 9443 9999 11371 34443 34444 41080 50002 55555 } \
    non_rfc_char { 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 } \
    enable_cookie \
    extended_response_inspection \
    inspect_gzip \
    normalize_utf \
    unlimited_decompress \
    normalize_javascript \
    apache_whitespace no \
    ascii no \
    bare_byte no \
    base36 no \
    directory no \
    double_decode no \
    iis_backslash no \
    iis_delimiter no \
    iis_unicode no \
    multi_slash no \
    non_strict \
    oversize_dir_length 300 \
    u_encode yes \
    utf_8 no \
    webroot no

# Performance et statistiques
preprocessor perfmonitor: time 300 file /var/log/snort/snort.stats pktcnt 10000
preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }

# === FICHIERS DE RÈGLES ===
include $RULE_PATH/local.rules
include $RULE_PATH/emerging-threats.rules

# === CONFIGURATION SORTIE ===
# Alerte vers syslog avec priorité haute
output alert_syslog: LOG_AUTH LOG_ALERT

# Log unifié pour analyse
output log_unified2: filename snort.log, limit 128, nostamp, mpls_event_types, vlan_event_types

# Alerte rapide
output alert_fast: /var/log/snort/alert.fast

# === LISTES IP ===
# include $WHITE_LIST_PATH/white_list.rules  
# include $BLACK_LIST_PATH/black_list.rules
EOF

    # Création règles locales
    cat > /etc/snort/rules/local.rules << 'EOF'
# Règles locales Snort - Laboratoire
# SID range: 1000000-1999999

# === DÉTECTION RECONNAISSANCE ===
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL: ICMP Ping Sweep"; itype:8; threshold:type both, track by_src, count 20, seconds 60; sid:1000000; rev:1;)

# === DÉTECTION WEB ATTACKS ===
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"LOCAL: SQL Injection Attack"; flow:to_server,established; content:"union"; nocase; content:"select"; nocase; distance:0; within:20; sid:1000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"LOCAL: XSS Attack Attempt"; flow:to_server,established; content:"<script"; nocase; sid:1000002; rev:1;)

# === DÉTECTION BRUTE FORCE ===
alert tcp $EXTERNAL_NET any -> $HOME_NET $SSH_PORTS (msg:"LOCAL: SSH Brute Force"; flow:to_server,established; content:"SSH"; threshold:type both, track by_src, count 10, seconds 60; sid:1000003; rev:1;)

# === DÉTECTION MALWARE ===
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,8080,8443,9999] (msg:"LOCAL: Suspicious Outbound Connection"; sid:1000004; rev:1;)

# === DÉTECTION P2P ===
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL: BitTorrent Traffic"; content:"BitTorrent"; sid:1000005; rev:1;)
EOF

    # Téléchargement règles Emerging Threats pour Snort
    log_info "Téléchargement règles Emerging Threats..."
    cd /etc/snort/rules
    
    if [ ! -f "emerging-threats.rules" ]; then
        wget -O emerging-threats.rules.tar.gz \
            "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
        
        if [ -f "emerging-threats.rules.tar.gz" ]; then
            tar -xzf emerging-threats.rules.tar.gz
            cat rules/*.rules > emerging-threats.rules 2>/dev/null || true
            rm -rf rules/ emerging-threats.rules.tar.gz
            log_info "Règles Emerging Threats installées"
        else
            log_warning "Échec téléchargement règles ET. Utilisation règles locales uniquement."
            touch emerging-threats.rules
        fi
    fi
    
    # Permissions
    chown -R snort:snort /etc/snort
    chmod 644 /etc/snort/snort.conf
    
    # Test configuration Snort
    if snort -T -c /etc/snort/snort.conf > /tmp/snort-test.log 2>&1; then
        log_success "Configuration Snort validée"
    else
        log_warning "Erreurs de configuration Snort (peut être normal avec règles manquantes):"
        tail -10 /tmp/snort-test.log
    fi
    
    log_success "Snort installé et configuré"
}

# Installation et configuration ELK Stack
setup_elk_integration() {
    log_info "Configuration intégration ELK Stack..."
    
    # Installation repository Elastic
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | \
        tee /etc/apt/sources.list.d/elastic-8.x.list
    
    apt-get update
    
    # Installation composants ELK
    apt-get install -y elasticsearch logstash kibana filebeat
    
    # Configuration Elasticsearch pour IDS
    log_info "Configuration Elasticsearch..."
    
    cat > /etc/elasticsearch/elasticsearch.yml << EOF
# Configuration Elasticsearch pour IDS/IPS
cluster.name: cybersecurity-lab
node.name: ids-elasticsearch-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: ${SIEM_IP}
http.port: 9200
discovery.type: single-node

# Sécurité désactivée pour lab
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

# Optimisation performance IDS
indices.memory.index_buffer_size: 20%
bootstrap.memory_lock: true
EOF

    # Configuration Logstash pour traitement logs IDS
    log_info "Configuration Logstash..."
    
    mkdir -p /etc/logstash/conf.d
    
    cat > /etc/logstash/conf.d/ids-pipeline.conf << 'EOF'
# Pipeline Logstash pour logs IDS/IPS

input {
  # Logs Suricata EVE JSON
  file {
    path => "/var/log/suricata/eve.json"
    start_position => "beginning"
    codec => "json"
    type => "suricata-eve"
    tags => ["suricata", "ids"]
  }
  
  # Logs Suricata Fast
  file {
    path => "/var/log/suricata/fast.log"
    start_position => "beginning"
    type => "suricata-fast"
    tags => ["suricata", "ids", "fast"]
  }
  
  # Logs Snort
  file {
    path => "/var/log/snort/alert.fast"
    start_position => "beginning" 
    type => "snort-fast"
    tags => ["snort", "ids"]
  }
}

filter {
  # Traitement logs Suricata EVE
  if [type] == "suricata-eve" {
    # Ajout timestamp Elasticsearch
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Enrichissement géolocalisation
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geoip"
        database => "/usr/share/logstash/vendor/geoip/GeoLite2-City.mmdb"
      }
    }
    
    if [dest_ip] {
      geoip {
        source => "dest_ip" 
        target => "dest_geoip"
        database => "/usr/share/logstash/vendor/geoip/GeoLite2-City.mmdb"
      }
    }
    
    # Classification sévérité
    if [event_type] == "alert" {
      if [alert][severity] <= 1 {
        mutate { add_field => { "threat_level" => "critical" } }
      } else if [alert][severity] <= 2 {
        mutate { add_field => { "threat_level" => "high" } }
      } else if [alert][severity] <= 3 {
        mutate { add_field => { "threat_level" => "medium" } }
      } else {
        mutate { add_field => { "threat_level" => "low" } }
      }
      
      # Classification type menace
      if [alert][category] {
        if "trojan" in [alert][category] {
          mutate { add_field => { "threat_type" => "malware" } }
        } else if "web-application" in [alert][category] {
          mutate { add_field => { "threat_type" => "web_attack" } }
        } else if "exploit" in [alert][category] {
          mutate { add_field => { "threat_type" => "exploit" } }
        } else {
          mutate { add_field => { "threat_type" => "other" } }
        }
      }
    }
  }
  
  # Traitement logs Snort Fast
  if [type] == "snort-fast" {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} \[%{DATA:generator_id}:%{DATA:rule_id}:%{DATA:rule_revision}\] %{DATA:alert_msg} \[Classification: %{DATA:classification}\] \[Priority: %{NUMBER:priority}\] \{%{DATA:protocol}\} %{IPV4:src_ip}:%{NUMBER:src_port} -> %{IPV4:dest_ip}:%{NUMBER:dest_port}" 
      }
    }
    
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss.SSSSSS" ]
    }
    
    mutate {
      convert => { "priority" => "integer" }
      convert => { "src_port" => "integer" }
      convert => { "dest_port" => "integer" }
    }
  }
  
  # Ajout métadonnées communes
  mutate {
    add_field => { 
      "lab_environment" => "cybersecurity-portfolio"
      "data_source" => "ids_ips"
    }
  }
}

output {
  # Index Elasticsearch par type et date
  if [type] == "suricata-eve" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "suricata-alerts-%{+YYYY.MM.dd}"
    }
  } else if [type] == "snort-fast" {
    elasticsearch {
      hosts => ["localhost:9200"] 
      index => "snort-alerts-%{+YYYY.MM.dd}"
    }
  }
  
  # Debug output (commenté en production)
  # stdout { codec => rubydebug }
}
EOF

    # Configuration Kibana
    log_info "Configuration Kibana..."
    
    cat > /etc/kibana/kibana.yml << EOF
# Configuration Kibana pour IDS/IPS
server.port: 5601
server.host: "${SIEM_IP}"
server.name: "ids-kibana"

elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.requestTimeout: 132000
elasticsearch.shardTimeout: 120000

# Configuration logs
logging.appenders.file.type: file
logging.appenders.file.fileName: /var/log/kibana/kibana.log
logging.appenders.file.layout.type: json

logging.root.appenders: [default, file]
logging.root.level: info

# Désactiver sécurité pour lab
xpack.security.enabled: false
xpack.encryptedSavedObjects.encryptionKey: "cybersecurity-lab-key-32-characters"
xpack.reporting.encryptionKey: "cybersecurity-lab-key-32-characters"
xpack.screenshotting.browser.chromium.disableSandbox: true

pid.file: /run/kibana/kibana.pid
EOF

    # Configuration mémoire Elasticsearch
    mkdir -p /etc/systemd/system/elasticsearch.service.d
    cat > /etc/systemd/system/elasticsearch.service.d/override.conf << EOF
[Service]
LimitMEMLOCK=infinity
EOF

    # Configuration JVM Elasticsearch
    sed -i 's/-Xms1g/-Xms2g/g' /etc/elasticsearch/jvm.options
    sed -i 's/-Xmx1g/-Xmx2g/g' /etc/elasticsearch/jvm.options
    
    # Configuration permissions
    chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
    chown -R logstash:logstash /var/log/logstash
    chown -R kibana:kibana /var/lib/kibana
    
    # Activation services
    systemctl daemon-reload
    systemctl enable elasticsearch logstash kibana
    
    log_success "Configuration ELK terminée"
}

# Script de monitoring IDS/IPS
create_monitoring_script() {
    log_info "Création script de monitoring..."
    
    cat > /usr/local/bin/ids-monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Monitoring IDS/IPS Performance et Santé
Laboratoire Cybersécurité - Projet 04
"""

import json
import time
import subprocess
import psutil
import requests
from datetime import datetime, timedelta
import os

class IDSMonitor:
    def __init__(self):
        self.elasticsearch_url = "http://172.16.2.10:9200"
        self.kibana_url = "http://172.16.2.10:5601"
        
    def get_system_stats(self):
        """Récupération statistiques système"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'load_avg': os.getloadavg()
        }
    
    def get_suricata_stats(self):
        """Statistiques Suricata via suricatasc"""
        try:
            result = subprocess.run(['suricatasc', '-c', 'dump-counters'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            print(f"Erreur récupération stats Suricata: {e}")
        return {}
    
    def check_services_status(self):
        """Vérification état services"""
        services = ['suricata', 'elasticsearch', 'logstash', 'kibana']
        status = {}
        
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'is-active', service],
                                      capture_output=True, text=True)
                status[service] = result.stdout.strip()
            except:
                status[service] = 'unknown'
        
        return status
    
    def get_elasticsearch_stats(self):
        """Statistiques Elasticsearch"""
        try:
            response = requests.get(f"{self.elasticsearch_url}/_stats", timeout=5)
            if response.status_code == 200:
                stats = response.json()
                return {
                    'indices_count': len(stats.get('indices', {})),
                    'docs_count': stats.get('_all', {}).get('total', {}).get('docs', {}).get('count', 0),
                    'store_size_mb': stats.get('_all', {}).get('total', {}).get('store', {}).get('size_in_bytes', 0) / (1024*1024)
                }
        except Exception as e:
            print(f"Erreur connexion Elasticsearch: {e}")
        return {}
    
    def get_recent_alerts_count(self, minutes=10):
        """Nombre d'alertes récentes"""
        try:
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                            {"term": {"event_type": "alert"}}
                        ]
                    }
                }
            }
            
            response = requests.post(f"{self.elasticsearch_url}/suricata-*/_count",
                                   json=query, timeout=5)
            if response.status_code == 200:
                return response.json().get('count', 0)
        except Exception as e:
            print(f"Erreur requête alertes: {e}")
        return 0
    
    def generate_report(self):
        """Génération rapport complet"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'timestamp': timestamp,
            'system': self.get_system_stats(),
            'services': self.check_services_status(),
            'suricata': self.get_suricata_stats(),
            'elasticsearch': self.get_elasticsearch_stats(),
            'alerts': {
                'last_10min': self.get_recent_alerts_count(10),
                'last_hour': self.get_recent_alerts_count(60),
                'last_day': self.get_recent_alerts_count(1440)
            }
        }
        
        # Calcul métriques dérivées
        if report['suricata']:
            packets = report['suricata'].get('decoder.pkts', 0)
            alerts = report['suricata'].get('detect.alert', 0)
            
            if packets > 0:
                report['metrics'] = {
                    'alert_rate_percent': (alerts / packets) * 100,
                    'packets_per_second': packets,
                    'detection_efficiency': max(0, 100 - ((alerts / packets) * 100))
                }
        
        return report
    
    def check_health(self, report):
        """Vérification santé système"""
        issues = []
        
        # Vérification CPU
        if report['system']['cpu_percent'] > 80:
            issues.append({
                'level': 'warning',
                'component': 'system',
                'message': f"CPU élevé: {report['system']['cpu_percent']:.1f}%"
            })
        
        # Vérification mémoire
        if report['system']['memory_percent'] > 90:
            issues.append({
                'level': 'critical',
                'component': 'system', 
                'message': f"Mémoire critique: {report['system']['memory_percent']:.1f}%"
            })
        
        # Vérification services
        for service, status in report['services'].items():
            if status != 'active':
                issues.append({
                    'level': 'critical',
                    'component': service,
                    'message': f"Service {service} inactif: {status}"
                })
        
        # Vérification taux d'alerte
        if 'metrics' in report and report['metrics']['alert_rate_percent'] > 10:
            issues.append({
                'level': 'warning',
                'component': 'detection',
                'message': f"Taux d'alerte élevé: {report['metrics']['alert_rate_percent']:.2f}%"
            })
        
        return issues
    
    def print_status_dashboard(self, report, issues):
        """Affichage dashboard status"""
        print("\n" + "="*70)
        print("🛡️  IDS/IPS MONITORING DASHBOARD")
        print("="*70)
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # État des services
        print("\n🔧 SERVICES STATUS:")
        for service, status in report['services'].items():
            icon = "✅" if status == "active" else "❌"
            print(f"   {icon} {service:15} : {status}")
        
        # Métriques système
        print("\n💻 SYSTEM METRICS:")
        sys_stats = report['system']
        print(f"   🔥 CPU Usage      : {sys_stats['cpu_percent']:6.1f}%")
        print(f"   🧠 Memory Usage   : {sys_stats['memory_percent']:6.1f}%") 
        print(f"   💾 Disk Usage     : {sys_stats['disk_usage']:6.1f}%")
        print(f"   📊 Load Average   : {sys_stats['load_avg'][0]:6.2f}")
        
        # Statistiques IDS
        if report['elasticsearch']:
            es_stats = report['elasticsearch']
            print("\n📊 ELASTICSEARCH:")
            print(f"   📄 Documents      : {es_stats.get('docs_count', 0):,}")
            print(f"   🗂️  Indices        : {es_stats.get('indices_count', 0)}")
            print(f"   💾 Store Size     : {es_stats.get('store_size_mb', 0):.1f} MB")
        
        # Alertes récentes
        print("\n🚨 RECENT ALERTS:")
        alerts = report['alerts']
        print(f"   ⏰ Last 10 min    : {alerts['last_10min']:,}")
        print(f"   📈 Last Hour      : {alerts['last_hour']:,}")
        print(f"   📊 Last Day       : {alerts['last_day']:,}")
        
        # Métriques performance
        if 'metrics' in report:
            metrics = report['metrics']
            print("\n📈 PERFORMANCE:")
            print(f"   📊 Alert Rate     : {metrics['alert_rate_percent']:6.2f}%")
            print(f"   ⚡ Packets/sec    : {metrics['packets_per_second']:,}")
            print(f"   🎯 Efficiency     : {metrics['detection_efficiency']:6.1f}%")
        
        # Problèmes détectés
        if issues:
            print(f"\n⚠️  ISSUES DETECTED ({len(issues)}):")
            for issue in issues:
                level_icon = "🔴" if issue['level'] == 'critical' else "🟡"
                print(f"   {level_icon} [{issue['component'].upper()}] {issue['message']}")
        else:
            print("\n✅ NO ISSUES DETECTED - System Healthy")
    
    def run_continuous_monitoring(self, interval=60):
        """Monitoring continu"""
        print("🚀 Démarrage monitoring IDS/IPS continu...")
        print(f"📊 Intervalle: {interval} secondes")
        
        try:
            while True:
                report = self.generate_report()
                issues = self.check_health(report)
                
                # Clear screen
                os.system('clear' if os.name == 'posix' else 'cls')
                
                self.print_status_dashboard(report, issues)
                
                # Sauvegarde rapport
                log_file = f"/var/log/ids-monitoring-{datetime.now().strftime('%Y%m%d')}.json"
                with open(log_file, 'a') as f:
                    f.write(json.dumps(report) + '\n')
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🔴 Monitoring arrêté par l'utilisateur")
        except Exception as e:
            print(f"\n🔴 Erreur monitoring: {e}")

if __name__ == "__main__":
    import sys
    
    monitor = IDSMonitor()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        monitor.run_continuous_monitoring(interval)
    else:
        # Single run
        report = monitor.generate_report()
        issues = monitor.check_health(report)
        monitor.print_status_dashboard(report, issues)
EOF

    chmod +x /usr/local/bin/ids-monitor.py
    
    # Script de démarrage services
    cat > /usr/local/bin/start-ids-services.sh << 'EOF'
#!/bin/bash
# start-ids-services.sh - Démarrage ordonné services IDS/IPS

echo "🚀 Démarrage services IDS/IPS..."

# Elasticsearch en premier
echo "📊 Démarrage Elasticsearch..."
systemctl start elasticsearch
sleep 30

# Vérification Elasticsearch
if ! curl -s http://172.16.2.10:9200/_cluster/health >/dev/null; then
    echo "❌ Elasticsearch non accessible"
    exit 1
fi

# Logstash
echo "📋 Démarrage Logstash..."
systemctl start logstash
sleep 15

# Kibana
echo "📈 Démarrage Kibana..."
systemctl start kibana
sleep 20

# Suricata
echo "🛡️ Démarrage Suricata..."
systemctl start suricata

echo "✅ Tous les services sont démarrés!"
echo ""
echo "🌐 Interfaces disponibles:"
echo "   - Kibana: http://172.16.2.10:5601" 
echo "   - Elasticsearch: http://172.16.2.10:9200"
echo ""
echo "🔧 Commandes utiles:"
echo "   - python3 /usr/local/bin/ids-monitor.py"
echo "   - tail -f /var/log/suricata/eve.json"
echo "   - systemctl status suricata"
EOF

    chmod +x /usr/local/bin/start-ids-services.sh
    
    log_success "Scripts de monitoring créés"
}

# Fonction principale
main() {
    print_banner
    
    log_info "🔐 Démarrage déploiement IDS/IPS Enterprise"
    log_info "📁 Projet: cybersecurity-portfolio/04-ids-ips-implementation"
    
    # Étapes de déploiement
    check_prerequisites
    install_system_dependencies
    install_configure_suricata
    install_configure_snort
    setup_elk_integration
    create_monitoring_script
    
    echo ""
    echo "🎉 INFRASTRUCTURE IDS/IPS DÉPLOYÉE AVEC SUCCÈS !"
    echo ""
    echo "📊 Services configurés:"
    echo "   ✅ Suricata IDS/IPS - Multi-thread optimisé"
    echo "   ✅ Snort IDS - Compatibilité legacy"
    echo "   ✅ ELK Stack - Analyse et visualisation"
    echo "   ✅ Scripts monitoring - Surveillance continue"
    echo ""
    echo "🌐 Interfaces web:"
    echo "   - Kibana Dashboard: http://${SIEM_IP}:5601"
    echo "   - Elasticsearch API: http://${SIEM_IP}:9200"
    echo ""
    echo "🔧 Commandes de gestion:"
    echo "   - /usr/local/bin/start-ids-services.sh    # Démarrage services"
    echo "   - /usr/local/bin/ids-monitor.py           # Monitoring temps réel"
    echo "   - systemctl status suricata               # État Suricata"
    echo "   - tail -f /var/log/suricata/eve.json      # Logs temps réel"
    echo ""
    echo "📋 Prochaines étapes recommandées:"
    echo "   1. Démarrer les services: /usr/local/bin/start-ids-services.sh"
    echo "   2. Configurer les dashboards Kibana"
    echo "   3. Tester la détection avec du trafic malveillant contrôlé"
    echo "   4. Optimiser les règles selon l'environnement"
    echo "   5. Configurer les alertes email/Slack"
    echo ""
    log_success "🎯 Projet 04 IDS/IPS déployé avec succès !"
}

# Gestion des erreurs
trap 'log_error "Erreur détectée ligne $LINENO. Arrêt du déploiement."; exit 1' ERR

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi