f"Large packet: {packet.ip.src} -> {packet.ip.dst} ({packet.length} bytes)")
        
        cap.close()
        
        # Affichage des résultats
        print("\n📊 Résultats de l'analyse:")
        print(f"Total protocoles: {len(protocols)}")
        print(f"Total conversations: {len(conversations)}")
        print(f"Éléments suspects: {len(suspicious)}")
        
        print("\n🔝 Top 5 protocoles:")
        for proto, count in protocols.most_common(5):
            print(f"  {proto}: {count}")
        
        print("\n🔝 Top 5 conversations:")
        for conv, count in Counter(conversations).most_common(5):
            print(f"  {conv}: {count} packets")
        
        if suspicious:
            print("\n⚠️  Éléments suspects:")
            for item in suspicious[:5]:
                print(f"  {item}")
    
    except Exception as e:
        print(f"❌ Erreur d'analyse: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 quick_analysis.py <pcap_file>")
        sys.exit(1)
    
    quick_analyze(sys.argv[1])
EOF

    # Rendre les scripts exécutables
    chmod +x "$WORK_DIR/scripts"/*.sh
    chmod +x "$WORK_DIR/scripts"/*.py
    
    log_success "Scripts d'analyse créés"
}

create_filter_library() {
    log_info "Création de la bibliothèque de filtres..."
    
    cat > "$WORK_DIR/configs/filters_library.txt" << 'EOF'
# ====================================================================
# 📚 Bibliothèque de Filtres Wireshark pour Cybersécurité
# ====================================================================

# === FILTRES DE CAPTURE ===

## Trafic Web
tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 8443

## Trafic Email
tcp port 25 or tcp port 110 or tcp port 143 or tcp port 993 or tcp port 995 or tcp port 587

## Trafic DNS
udp port 53 or tcp port 53

## Trafic Base de données
tcp port 1433 or tcp port 3306 or tcp port 5432 or tcp port 1521

## Trafic Windows (SMB/RDP/LDAP)
tcp port 139 or tcp port 445 or tcp port 3389 or tcp port 389 or tcp port 636

## Trafic SSH/Telnet
tcp port 22 or tcp port 23

# === FILTRES D'AFFICHAGE POUR DÉTECTION D'INTRUSION ===

## Scans de ports
tcp.flags.syn == 1 and tcp.flags.ack == 0

## Connexions échouées
tcp.flags.reset == 1

## Trafic ICMP suspect
icmp.type == 8 and data.len > 64

## Requêtes DNS suspectes
dns.qry_name contains "." and frame.len > 512
dns.flags.response == 0 and dns.qry_name matches "([a-z0-9]{20,}\.)+[a-z]{2,}"

## Attaques Web
http.request.uri contains "../"
http.request.uri contains "script"
http.request.uri contains "union"
http.request.uri contains "select"
http.request.uri contains "drop"
http.request.uri contains "exec"
http.request.uri contains "cmd"

## Exfiltration de données
tcp.len > 1460 and tcp.flags.push == 1
ftp-data or tftp.opcode == 3

## Trafic chiffré suspect
tls.handshake.type == 1 and tls.handshake.extensions_server_name contains "."
ssl.record.content_type == 23 and ssl.record.length > 16384

## Communication C2 (Command & Control)
http.user_agent contains "python"
http.user_agent contains "wget"
http.user_agent contains "curl"
http.user_agent == ""

## Tunneling
icmp.data.len > 64
dns.qry_name contains "base64"
tcp.payload contains "ssh"

# === FILTRES POUR FORENSIQUE ===

## Timeline spécifique
frame.time >= "2024-01-01 00:00:00" and frame.time <= "2024-01-01 23:59:59"

## Adresse IP spécifique
ip.addr == 192.168.1.100

## Sessions TCP complètes
tcp.stream eq 0

## Erreurs et anomalies
tcp.analysis.flags
icmp.type == 3
tcp.analysis.retransmission
tcp.analysis.duplicate_ack

# === FILTRES AVANCÉS ===

## Détection de malware
tcp.payload contains "MZ" or tcp.payload contains "PE"
tcp.payload matches "[\x00-\x08\x0E-\x1F\x7F-\xFF]{10,}"

## Analyse de protocoles propriétaires
tcp.port == 4444 or udp.port == 4444
tcp matches "custom_protocol_signature"

## Géolocalisation (nécessite GeoIP)
ip.geoip.src_country != "FR" and ip.geoip.dst_country == "FR"

## Analyse temporelle
frame.time_delta > 60
tcp.time_delta > 10

# === MACROS POUR ANALYSES SPÉCIALISÉES ===

## Investigation Web Attack
(http.request.method == "POST" and http.content_length > 1000) or 
(http.request.uri contains "admin" and http.response.code >= 400)

## Investigation Malware Communication
(tcp.payload contains "base64" or tcp.payload matches "[A-Za-z0-9+/]{20,}") and
(tcp.stream eq X and tcp.len > 100)

## Investigation Data Exfiltration  
(tcp.len > 1000 and tcp.flags.push == 1) or
(ftp.command.arg contains "/" and ftp.response.code == 226)

# === NOTES D'UTILISATION ===
# - Remplacer X par le numéro de stream TCP approprié
# - Adapter les adresses IP selon l'environnement
# - Combiner les filtres avec des opérateurs logiques (and, or, not)
# - Utiliser les parenthèses pour grouper les conditions complexes
EOF

    log_success "Bibliothèque de filtres créée"
}

configure_system_optimization() {
    log_info "Optimisation du système pour l'analyse réseau..."
    
    # Optimisations réseau
    cat > "/tmp/network_analysis_sysctl.conf" << 'EOF'
# Optimisations pour capture et analyse réseau
net.core.rmem_max = 134217728
net.core.rmem_default = 67108864
net.core.wmem_max = 134217728
net.core.wmem_default = 67108864
net.core.netdev_max_backlog = 30000
net.core.netdev_budget = 600
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
EOF

    sudo cp "/tmp/network_analysis_sysctl.conf" "/etc/sysctl.d/99-network-analysis.conf"
    sudo sysctl -p /etc/sysctl.d/99-network-analysis.conf
    
    # Augmentation des limites utilisateur
    cat > "/tmp/network_analysis_limits.conf" << 'EOF'
# Limites pour analyse réseau
* soft nofile 65536
* hard nofile 65536
* soft memlock unlimited
* hard memlock unlimited
EOF

    sudo cp "/tmp/network_analysis_limits.conf" "/etc/security/limits.d/99-network-analysis.conf"
    
    log_success "Optimisations système appliquées"
}

create_documentation() {
    log_info "Création de la documentation..."
    
    cat > "$WORK_DIR/README.md" << 'EOF'
# 🔍 Environnement d'Analyse Réseau

Environnement configuré automatiquement pour l'analyse de trafic réseau avec Wireshark.

## 📁 Structure

```
~/network_analysis/
├── captures/          # Fichiers de capture (.pcap)
├── reports/           # Rapports d'analyse
├── scripts/           # Scripts automatisés
├── configs/           # Configurations et filtres
├── temp/              # Fichiers temporaires
└── archive/           # Archives des anciennes analyses
```

## 🚀 Démarrage Rapide

### Capture rapide
```bash
cd ~/network_analysis/scripts
./quick_capture.sh eth0 300 ../captures
```

### Analyse rapide
```bash
python3 quick_analysis.py ../captures/capture.pcap
```

### Lancement Wireshark avec profil SOC
```bash
wireshark -C SOC_Analysis
```

## 📚 Ressources

- **Filtres** : `configs/filters_library.txt`
- **Profils configurés** : SOC_Analysis, Incident_Response, Pentest
- **Scripts** : Capture et analyse automatisées

## 🔧 Maintenance

### Nettoyage des fichiers temporaires
```bash
find temp/ -name "*.tmp" -mtime +7 -delete
```

### Archivage des anciennes captures
```bash
find captures/ -name "*.pcap" -mtime +30 -exec mv {} archive/ \;
```
EOF

    # Manuel de référence rapide
    cat > "$WORK_DIR/QUICK_REFERENCE.md" << 'EOF'
# 📖 Référence Rapide - Analyse Réseau

## Commandes Essentielles

### Capture
```bash
# Capture basique
tshark -i eth0 -w capture.pcap

# Capture avec filtre
tshark -i eth0 -f "port 80" -w web_traffic.pcap

# Capture avec rotation
tshark -i eth0 -b filesize:100000 -b files:5 -w rotating.pcap
```

### Analyse
```bash
# Informations générales
capinfos capture.pcap

# Statistiques protocoles
tshark -r capture.pcap -q -z prot,colinfo

# Top conversations
tshark -r capture.pcap -q -z conv,ip

# Extraction de champs
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport
```

### Filtres Courants
```
# Trafic HTTP
http

# Erreurs TCP
tcp.analysis.flags

# Scans de ports
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Trafic suspect
frame.len > 1500 or tcp.analysis.retransmission
```

## Raccourcis Wireshark

| Raccourci | Action |
|-----------|--------|
| Ctrl+K | Démarrer capture |
| Ctrl+E | Arrêter capture |
| Ctrl+F | Recherche |
| Ctrl+G | Aller à un paquet |
| Ctrl+M | Marquer un paquet |
| F3 | Suivre le flux TCP |

## Codes de Réponse HTTP

| Code | Signification | Investigation |
|------|---------------|---------------|
| 200 | OK | Normal |
| 301/302 | Redirection | Vérifier destination |
| 400 | Bad Request | Possible attaque |
| 401 | Unauthorized | Tentative d'accès |
| 403 | Forbidden | Scan ou attaque |
| 404 | Not Found | Reconnaissance |
| 500 | Server Error | Exploitation possible |
EOF

    log_success "Documentation créée"
}

create_validation_tests() {
    log_info "Création des tests de validation..."
    
    cat > "$WORK_DIR/scripts/validate_setup.sh" << 'EOF'
#!/bin/bash
# Test de validation de l'installation

echo "🧪 Tests de validation de l'environnement"

ERRORS=0

# Test 1: Wireshark installé
if command -v wireshark &> /dev/null; then
    echo "✅ Wireshark installé"
else
    echo "❌ Wireshark non installé"
    ((ERRORS++))
fi

# Test 2: tshark fonctionnel
if command -v tshark &> /dev/null; then
    echo "✅ tshark disponible"
else
    echo "❌ tshark non disponible"
    ((ERRORS++))
fi

# Test 3: Permissions de capture
if dumpcap -D &> /dev/null; then
    echo "✅ Permissions de capture configurées"
else
    echo "❌ Permissions de capture manquantes"
    ((ERRORS++))
fi

# Test 4: Profils Wireshark
if [[ -d "$HOME/.config/wireshark/profiles/SOC_Analysis" ]]; then
    echo "✅ Profils Wireshark configurés"
else
    echo "❌ Profils Wireshark manquants"
    ((ERRORS++))
fi

# Test 5: Python packages
if python3 -c "import pyshark" &> /dev/null; then
    echo "✅ pyshark installé"
else
    echo "❌ pyshark manquant"
    ((ERRORS++))
fi

# Test 6: Structure de répertoires
if [[ -d "$HOME/network_analysis/captures" ]]; then
    echo "✅ Structure de répertoires créée"
else
    echo "❌ Structure de répertoires manquante"
    ((ERRORS++))
fi

# Résumé
echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo "🎉 Tous les tests passés! Environnement prêt."
    exit 0
else
    echo "⚠️  $ERRORS erreur(s) détectée(s). Vérifiez l'installation."
    exit 1
fi
EOF

    chmod +x "$WORK_DIR/scripts/validate_setup.sh"
    
    log_success "Tests de validation créés"
}

# ====================================================================
# Fonction principale
# ====================================================================

main() {
    echo "======================================================================"
    echo "🔧 Configuration Automatisée de l'Environnement Wireshark"
    echo "======================================================================"
    echo "Ce script va configurer un environnement professionnel pour"
    echo "l'analyse de trafic réseau avec Wireshark."
    echo ""
    
    # Création du fichier de log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log_info "Début de la configuration - $(date)"
    
    # Étapes de configuration
    check_prerequisites
    create_directory_structure
    install_wireshark
    configure_wireshark_profiles
    configure_color_filters
    install_additional_tools
    create_analysis_scripts
    create_filter_library
    configure_system_optimization
    create_documentation
    create_validation_tests
    
    echo ""
    log_success "Configuration terminée avec succès!"
    echo ""
    echo "📋 Étapes suivantes:"
    echo "1. Redémarrez votre session (ou exécutez: newgrp wireshark)"
    echo "2. Exécutez le test de validation: $WORK_DIR/scripts/validate_setup.sh"
    echo "3. Lancez Wireshark avec un profil: wireshark -C SOC_Analysis"
    echo ""
    echo "📁 Répertoire de travail: $WORK_DIR"
    echo "📄 Log d'installation: $LOG_FILE"
    echo ""
    echo "🚀 Environnement prêt pour l'analyse réseau professionnelle!"
}

# ====================================================================
# Gestion des signaux et nettoyage
# ====================================================================

cleanup() {
    log_info "Nettoyage en cours..."
    # Suppression des fichiers temporaires
    rm -f /tmp/network_analysis_*.conf
    log_info "Configuration terminée (avec interruption)"
    exit 130
}

trap cleanup SIGINT SIGTERM

# ====================================================================
# Point d'entrée
# ====================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi