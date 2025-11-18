# 🛠️ Guide des Outils - Analyse de Trafic Réseau

## 🎯 Vue d'Ensemble

Ce guide présente l'écosystème complet d'outils pour l'analyse professionnelle de trafic réseau, depuis la capture jusqu'à la présentation des résultats.

## 📦 Outils Principaux

### 1. Wireshark (Interface Graphique)

#### Description
Analyseur de protocoles réseau leader, interface graphique intuitive pour l'analyse interactive.

#### Installation
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install wireshark

# CentOS/RHEL/Fedora  
sudo yum install wireshark wireshark-gnome

# macOS
brew install --cask wireshark

# Windows
# Télécharger depuis https://www.wireshark.org/download.html
```

#### Configuration Recommandée
```bash
# Ajout utilisateur au groupe
sudo usermod -a -G wireshark $USER

# Configuration permissions
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Redémarrage session nécessaire
newgrp wireshark
```

#### Profils Professionnels
- **SOC_Analysis**: Colonnes optimisées pour SOC
- **Incident_Response**: Timestamps absolus, pas de résolution DNS
- **Pentest**: Décodeurs activés, support SSL/TLS

#### Raccourcis Essentiels
| Raccourci | Action |
|-----------|--------|
| `Ctrl+K` | Démarrer capture |
| `Ctrl+E` | Arrêter capture |
| `Ctrl+F` | Recherche |
| `Ctrl+G` | Aller au paquet N |
| `Ctrl+M` | Marquer paquet |
| `F3` | Suivre flux TCP |
| `Ctrl+Shift+A` | Appliquer filtre |

### 2. tshark (Ligne de Commande)

#### Description
Version CLI de Wireshark, idéale pour l'automatisation et l'analyse de gros volumes.

#### Commandes Essentielles
```bash
# Capture basique
tshark -i eth0 -w capture.pcap

# Capture avec filtre
tshark -i eth0 -f "port 443" -w https_traffic.pcap

# Analyse offline
tshark -r capture.pcap

# Extraction de champs
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport

# Statistiques
tshark -r capture.pcap -q -z prot,colinfo
tshark -r capture.pcap -q -z conv,ip
tshark -r capture.pcap -q -z io,stat,60  # Stats par minute
```

#### Scripts d'Automatisation
```bash
#!/bin/bash
# Analyse automatique avec tshark

PCAP_FILE=$1
OUTPUT_DIR="./analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

# Extraction HTTP
tshark -r "$PCAP_FILE" -Y "http.request" -T fields \
    -e frame.time -e ip.src -e http.host -e http.request.uri \
    > "$OUTPUT_DIR/http_requests.csv"

# Extraction DNS
tshark -r "$PCAP_FILE" -Y "dns.qry_name" -T fields \
    -e frame.time -e ip.src -e dns.qry_name \
    > "$OUTPUT_DIR/dns_queries.csv"

# Top talkers
tshark -r "$PCAP_FILE" -q -z conv,ip | head -20 \
    > "$OUTPUT_DIR/top_conversations.txt"
```

### 3. dumpcap (Capture Optimisée)

#### Description
Moteur de capture de Wireshark, optimisé pour les performances et la stabilité.

#### Utilisation Avancée
```bash
# Capture haute performance
dumpcap -i eth0 -b filesize:100000 -b files:10 -w rotating.pcap

# Capture avec multiple interfaces
dumpcap -i eth0 -i wlan0 -w multi_interface.pcap

# Capture ring buffer
dumpcap -i eth0 -b duration:3600 -b files:24 -w hourly.pcap

# Capture avec privilèges minimaux
sudo dumpcap -i eth0 -w capture.pcap
sudo chown $USER:$USER capture.pcap
```

## 🔧 Outils Complémentaires

### 4. tcpdump (Capture Unix/Linux)

#### Description
Outil de capture standard Unix/Linux, léger et puissant.

#### Syntaxe et Exemples
```bash
# Capture basique
sudo tcpdump -i eth0 -w capture.pcap

# Filtres avancés
sudo tcpdump -i eth0 'host 192.168.1.1 and port 80' -w web_traffic.pcap
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -w syn_packets.pcap

# Analyse en temps réel
sudo tcpdump -i eth0 -n -c 100  # 100 paquets
sudo tcpdump -i eth0 -A  # Affichage ASCII

# Rotation des fichiers
sudo tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -G 3600 -Z $USER
```

#### Filtres Berkeley Packet Filter (BPF)
```bash
# Syntaxe: primitives + opérateurs logiques
host 192.168.1.1          # Trafic depuis/vers cette IP
net 192.168.0.0/24        # Trafic réseau
port 443                  # Port spécifique
tcp and port 80           # TCP sur port 80
not icmp                  # Exclure ICMP
src host 10.0.0.1         # Source spécifique
dst port 53               # Destination spécifique
```

### 5. Netstat / ss (Monitoring Connexions)

#### Description
Outils pour surveiller les connexions réseau actives et les ports en écoute.

#### Utilisation
```bash
# Netstat (traditionnel)
netstat -tuln           # TCP/UDP listening ports
netstat -an | grep :80  # Connexions port 80
netstat -i              # Statistiques interfaces

# ss (moderne, plus rapide)
ss -tuln               # TCP/UDP listening
ss -p                  # Avec processus
ss -s                  # Statistiques sommaires
ss state established   # Connexions établies
```

### 6. iftop / nethogs (Monitoring Temps Réel)

#### Description
Outils de monitoring en temps réel du trafic réseau.

#### Installation et Usage
```bash
# Installation
sudo apt install iftop nethogs

# iftop - Top des connexions
sudo iftop -i eth0
sudo iftop -n  # Pas de résolution DNS

# nethogs - Top par processus
sudo nethogs eth0
```

## 🐍 Outils Python pour l'Analyse

### 7. pyshark (Python Wireshark Wrapper)

#### Installation
```bash
pip3 install pyshark
```

#### Exemples d'Utilisation
```python
import pyshark

# Capture live
capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously(packet_count=10):
    print(packet)

# Analyse de fichier
cap = pyshark.FileCapture('capture.pcap')
for packet in cap:
    if hasattr(packet, 'http'):
        print(f"HTTP: {packet.http.host}")

# Filtres
cap = pyshark.FileCapture('capture.pcap', display_filter='http')
```

### 8. Scapy (Manipulation de Paquets)

#### Installation
```bash
pip3 install scapy
```

#### Capacités
```python
from scapy.all import *

# Lecture de capture
packets = rdpcap('capture.pcap')

# Création de paquets
packet = IP(dst="192.168.1.1")/TCP(dport=80)/"GET / HTTP/1.1\r\n\r\n"

# Envoi de paquets
send(packet)

# Analyse statistique
for packet in packets:
    if packet.haslayer(TCP):
        print(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
```

### 9. dpkt (Analyse Rapide)

#### Installation
```bash
pip3 install dpkt
```

#### Exemple d'Usage
```python
import dpkt
import socket

with open('capture.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            print(f"IP: {socket.inet_ntoa(ip.src)} -> {socket.inet_ntoa(ip.dst)}")
```

## 🔍 Outils d'Analyse Spécialisée

### 10. NetworkMiner (Analyse Forensique)

#### Description
Outil commercial/gratuit pour l'analyse forensique de trafic réseau.

#### Fonctionnalités
- Extraction automatique d'artefacts
- Reconstruction de fichiers transférés
- Analyse de sessions
- Géolocalisation des IPs

#### Installation
```bash
# Linux (Mono requis)
sudo apt install mono-complete
wget https://www.netresec.com/files/NetworkMiner_2-X-X_Free.zip
unzip NetworkMiner_2-X-X_Free.zip
cd NetworkMiner_2-X-X/
mono NetworkMiner.exe
```

### 11. Ntopng (Monitoring Réseau)

#### Description
Outil de monitoring réseau basé web, successeur de ntop.

#### Installation
```bash
# Ubuntu
sudo apt install ntopng

# Configuration
sudo nano /etc/ntopng/ntopng.conf
```

#### Configuration Type
```
-P=/var/lib/ntopng/ntopng.pid
-d=/var/lib/ntopng
-w=3000
-i=eth0
```

### 12. Suricata (IDS/IPS)

#### Description
Moteur IDS/IPS open source avec capacités d'analyse de trafic.

#### Installation et Configuration
```bash
# Installation
sudo apt install suricata

# Configuration basique
sudo nano /etc/suricata/suricata.yaml

# Mise à jour des règles
sudo suricata-update
sudo systemctl restart suricata
```

#### Analyse des Logs
```bash
# Logs JSON Suricata
tail -f /var/log/suricata/eve.json | jq .

# Filtrage des alertes
jq 'select(.event_type=="alert")' /var/log/suricata/eve.json
```

## 📊 Outils de Visualisation

### 13. Grafana + InfluxDB

#### Description
Stack de visualisation pour métriques réseau en temps réel.

#### Configuration
```bash
# InfluxDB
sudo apt install influxdb
sudo systemctl start influxdb

# Grafana
sudo apt install grafana
sudo systemctl start grafana-server
```

### 14. Kibana + Elasticsearch

#### Description
Stack ELK pour l'analyse de logs et visualisation.

#### Pipeline Logstash
```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
  }
}

filter {
  if [event_type] == "alert" {
    mutate {
      add_tag => ["suricata", "alert"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```

## ⚡ Scripts d'Automatisation

### 15. Script de Capture Automatisée

```bash
#!/bin/bash
# capture_scheduler.sh - Capture programmée

INTERFACE="eth0"
DURATION=3600  # 1 heure
STORAGE_DIR="/var/captures"
MAX_FILES=168  # 1 semaine

# Rotation des fichiers
find "$STORAGE_DIR" -name "*.pcap" -mtime +7 -delete

# Nouvelle capture
FILENAME="$STORAGE_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap"
timeout $DURATION tcpdump -i $INTERFACE -w "$FILENAME"

# Compression
gzip "$FILENAME"

# Notification
echo "Capture terminée: $FILENAME.gz" | mail -s "Capture réseau" admin@company.com
```

### 16. Script d'Analyse Batch

```bash
#!/bin/bash
# batch_analysis.sh - Analyse en lot

CAPTURE_DIR="./captures"
REPORT_DIR="./reports"

mkdir -p "$REPORT_DIR"

for pcap_file in "$CAPTURE_DIR"/*.pcap; do
    if [[ -f "$pcap_file" ]]; then
        echo "Analyse de $pcap_file"
        
        base_name=$(basename "$pcap_file" .pcap)
        report_file="$REPORT_DIR/${base_name}_report.txt"
        
        # Analyse avec tshark
        {
            echo "=== ANALYSE DE $pcap_file ==="
            echo "Date: $(date)"
            echo ""
            
            echo "=== STATISTIQUES GÉNÉRALES ==="
            capinfos "$pcap_file"
            echo ""
            
            echo "=== DISTRIBUTION PROTOCOLES ==="
            tshark -r "$pcap_file" -q -z prot,colinfo
            echo ""
            
            echo "=== TOP CONVERSATIONS ==="
            tshark -r "$pcap_file" -q -z conv,ip | head -20
            echo ""
            
            echo "=== REQUÊTES HTTP ==="
            tshark -r "$pcap_file" -Y "http.request" -T fields \
                -e frame.time -e ip.src -e http.host -e http.request.uri | head -20
            
        } > "$report_file"
        
        echo "Rapport généré: $report_file"
    fi
done
```

## 🔐 Outils de Sécurité et Conformité

### 17. Chiffrement des Captures

```bash
#!/bin/bash
# encrypt_captures.sh

CAPTURE_FILE=$1
GPG_RECIPIENT="security@company.com"

# Chiffrement
gpg --trust-model always --encrypt -r "$GPG_RECIPIENT" "$CAPTURE_FILE"

# Suppression original sécurisée
shred -vfz -n 3 "$CAPTURE_FILE"

echo "Capture chiffrée: ${CAPTURE_FILE}.gpg"
```

### 18. Audit et Traçabilité

```bash
#!/bin/bash
# audit_captures.sh

AUDIT_LOG="/var/log/network_analysis_audit.log"

log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $USER - $1" >> "$AUDIT_LOG"
}

# Utilisation
log_action "Début d'analyse de capture.pcap"
# ... analyse ...
log_action "Fin d'analyse de capture.pcap"
```

## 📚 Ressources et Documentation

### Documentations Officielles
- **Wireshark**: https://www.wireshark.org/docs/
- **tcpdump**: https://www.tcpdump.org/manpages/
- **Suricata**: https://suricata.readthedocs.io/

### Formations Recommandées
- **Wireshark Certified Network Analyst** (WCNA)
- **SANS FOR572**: Advanced Network Forensics
- **Coursera**: Network Security & Database Vulnerabilities

### Livres de Référence
- "Wireshark Network Analysis" - Laura Chappell
- "Practical Packet Analysis" - Chris Sanders
- "Network Forensics" - Sherri Davidoff

### Communautés
- **Wireshark Q&A**: https://ask.wireshark.org/
- **Reddit r/wireshark**: https://reddit.com/r/wireshark
- **Stack Overflow**: Tag "wireshark"

---

*Ce guide des outils constitue une référence complète pour l'analyse professionnelle de trafic réseau. Il doit être maintenu à jour avec les évolutions technologiques et les nouveaux outils.*