#!/bin/bash
# deploy-lab.sh - Script de déploiement automatique du laboratoire cybersécurité

set -e

# Configuration
LAB_DIR="$HOME/lab"
VM_DIR="$LAB_DIR/vms"
ISO_DIR="$LAB_DIR/isos"
CONFIG_DIR="$LAB_DIR/configs"
SCRIPT_DIR="$LAB_DIR/scripts"
EVIDENCE_DIR="$LAB_DIR/evidence"

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

# Vérification des prérequis
check_requirements() {
    log_info "Vérification des prérequis système..."
    
    # Vérification VMware Workstation
    if ! command -v vmrun &> /dev/null; then
        log_error "VMware Workstation non détecté. Veuillez l'installer."
        log_info "Téléchargement: https://www.vmware.com/products/workstation-pro.html"
        exit 1
    fi
    
    # Vérification de l'espace disque (minimum 500GB)
    AVAILABLE_SPACE=$(df -h "$HOME" | awk 'NR==2{print $4}' | sed 's/G//')
    if [ "$AVAILABLE_SPACE" -lt 500 ]; then
        log_error "Espace disque insuffisant. Requis: 500GB, Disponible: ${AVAILABLE_SPACE}GB"
        exit 1
    fi
    
    log_success "Prérequis validés - Disque: ${AVAILABLE_SPACE}GB"
}

# Création de la structure de répertoires
create_directory_structure() {
    log_info "Création de la structure de répertoires..."
    
    mkdir -p "$LAB_DIR"/{vms,isos,configs,scripts,evidence,logs,backups}
    mkdir -p "$CONFIG_DIR"/{pfsense,kali,windows,elk,dvwa}
    mkdir -p "$SCRIPT_DIR"/{setup,monitoring,maintenance,utils}
    mkdir -p "$EVIDENCE_DIR"/{screenshots,logs,reports,pcaps}
    mkdir -p "$LAB_DIR/templates"
    
    # Création des fichiers de configuration de base
    cat > "$LAB_DIR/.lab-config" << EOF
# Configuration du laboratoire cybersécurité
LAB_VERSION="1.0"
CREATED_DATE="$(date)"
HYPERVISOR="vmware"
NETWORK_PREFIX="192.168.100"
DMZ_PREFIX="172.16.1"
REDTEAM_PREFIX="10.0.0"
BLUETEAM_PREFIX="172.16.2"
EOF
    
    log_success "Structure de répertoires créée dans $LAB_DIR"
}

# Téléchargement des images ISO
download_isos() {
    log_info "Configuration pour téléchargement des ISOs..."
    
    cd "$ISO_DIR"
    
    # Création d'un script de téléchargement
    cat > download_isos.sh << 'EOF'
#!/bin/bash
# Script de téléchargement des ISOs

echo "📥 Démarrage du téléchargement des ISOs..."

# Kali Linux
if [ ! -f "kali-linux.iso" ]; then
    echo "⬇️ Téléchargement Kali Linux..."
    wget -O kali-linux.iso "https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso"
fi

# Ubuntu Server
if [ ! -f "ubuntu-server.iso" ]; then
    echo "⬇️ Téléchargement Ubuntu Server..."
    wget -O ubuntu-server.iso "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso"
fi

# pfSense
if [ ! -f "pfsense.iso" ]; then
    echo "⬇️ Téléchargement pfSense..."
    wget -O pfsense.iso.gz "https://files.netgate.com/file/pfSense-releases/2.7.0/pfSense-CE-2.7.0-RELEASE-amd64.iso.gz"
    gunzip pfsense.iso.gz
fi

echo "✅ Téléchargement terminé"
EOF
    
    chmod +x download_isos.sh
    log_success "Script de téléchargement ISO créé: $ISO_DIR/download_isos.sh"
}

# Fonction principale
main() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════╗
║       🏠 LABORATOIRE CYBERSÉCURITÉ v1.0              ║
║              Déploiement Automatique                  ║
╚══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log_info "Début du déploiement du laboratoire cybersécurité..."
    
    check_requirements
    create_directory_structure
    download_isos
    
    cat << EOF

🎉 LABORATOIRE CYBERSÉCURITÉ DÉPLOYÉ AVEC SUCCÈS !

📁 Répertoire principal: $LAB_DIR
🖥️ VMs disponibles: pfSense, Kali, DC-Server, Ubuntu-SIEM
🌐 Réseaux configurés: LAN, DMZ, Red Team, Blue Team

📋 PROCHAINES ÉTAPES:
1. Démarrer pfSense et configurer via https://192.168.100.1
2. Installer et configurer Windows Server (Active Directory)
3. Déployer la stack ELK pour le SIEM
4. Configurer Kali Linux avec les outils de pentest
5. Installer DVWA et Metasploitable comme cibles

🔧 COMMANDES UTILES:
- cd $LAB_DIR                 : Accéder au laboratoire
- ./isos/download_isos.sh     : Télécharger les ISOs
- vmrun list                  : Lister les VMs actives

📚 DOCUMENTATION:
- Logs          : $LAB_DIR/logs/
- Configurations: $LAB_DIR/configs/
- Scripts       : $LAB_DIR/scripts/

⚠️ IMPORTANT: Vérifiez que tous les réseaux sont bien isolés d'Internet !

Bonne exploration de la cybersécurité ! 🔐
EOF

    log_success "Déploiement terminé avec succès !"
}

# Gestion des erreurs
trap 'log_error "Erreur détectée à la ligne $LINENO. Arrêt du script."; exit 1' ERR

# Exécution du script principal
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi