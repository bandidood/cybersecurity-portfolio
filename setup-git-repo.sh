#!/bin/bash
# setup-git-repo.sh - Script d'initialisation et de push GitHub

# Configuration
REPO_DIR="C:/Users/joh_l/cybersecurity-portfolio"
GITHUB_USERNAME="YOUR_GITHUB_USERNAME"  # À remplacer
REPO_NAME="cybersecurity-portfolio"

# Couleurs pour l'affichage
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Initialisation du repository GitHub pour le portfolio cybersécurité${NC}"
echo "======================================================================"

# Vérification que nous sommes dans le bon répertoire
if [ ! -d "$REPO_DIR" ]; then
    echo -e "${RED}❌ Répertoire $REPO_DIR non trouvé${NC}"
    exit 1
fi

cd "$REPO_DIR"

# Initialisation Git si pas déjà fait
if [ ! -d ".git" ]; then
    echo -e "${BLUE}📁 Initialisation du repository Git...${NC}"
    git init
    echo -e "${GREEN}✅ Repository Git initialisé${NC}"
else
    echo -e "${YELLOW}⚠️ Repository Git déjà initialisé${NC}"
fi

# Vérification que .gitignore existe
if [ ! -f ".gitignore" ]; then
    echo -e "${RED}❌ Fichier .gitignore manquant. Veuillez le créer d'abord.${NC}"
    exit 1
fi

# Configuration Git (si pas déjà fait)
echo -e "${BLUE}⚙️ Configuration Git...${NC}"

# Vérifier si l'utilisateur est configuré
if [ -z "$(git config user.name)" ]; then
    read -p "Nom d'utilisateur Git: " git_username
    git config user.name "$git_username"
fi

if [ -z "$(git config user.email)" ]; then
    read -p "Email Git: " git_email
    git config user.email "$git_email"
fi

echo -e "${GREEN}✅ Configuration Git terminée${NC}"

# Ajout des fichiers
echo -e "${BLUE}📝 Ajout des fichiers au repository...${NC}"

# Ajout progressif pour éviter les fichiers trop volumineux
git add README.md
git add .gitignore
git add projects/01-home-lab-setup/

# Vérification de la taille des fichiers avant commit
echo -e "${BLUE}🔍 Vérification des fichiers à commiter...${NC}"
git status

# Premier commit
echo -e "${BLUE}💾 Création du commit initial...${NC}"
git commit -m "🎉 Initial commit: Cybersecurity Portfolio

✨ Features:
- Complete lab setup project (01-home-lab-setup)
- Automated deployment scripts
- Network segmentation architecture
- Health monitoring system
- Professional documentation structure

🏗️ Infrastructure:
- pfSense firewall configuration
- Segmented networks (LAN/DMZ/Red Team/Blue Team)
- VM templates for security testing
- Monitoring and alerting scripts

📚 Documentation:
- Comprehensive README with step-by-step guides
- Security best practices and risk analysis
- Professional Git structure
- Detailed CHANGELOG tracking

🔐 Security:
- Network isolation and segmentation
- Encrypted VM configurations
- Security hardening guidelines
- Backup and recovery procedures

Project ready for demonstration and professional use!"

echo -e "${GREEN}✅ Commit initial créé${NC}"

# Configuration de la branche principale
echo -e "${BLUE}🌿 Configuration de la branche principale...${NC}"
git branch -M main

# Instructions pour la liaison GitHub
cat << EOF

${YELLOW}📋 PROCHAINES ÉTAPES POUR GITHUB:${NC}

1️⃣ ${BLUE}Créer le repository sur GitHub:${NC}
   • Aller sur https://github.com/new
   • Nom du repository: ${REPO_NAME}
   • Description: "Professional Cybersecurity Portfolio - 50 hands-on projects"
   • Visibilité: Public (recommandé pour portfolio)
   • Ne pas initialiser avec README, .gitignore ou licence

2️⃣ ${BLUE}Lier le repository local:${NC}
   git remote add origin https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git

3️⃣ ${BLUE}Pousser vers GitHub:${NC}
   git push -u origin main

4️⃣ ${BLUE}Vérifier le repository:${NC}
   • Accéder à https://github.com/${GITHUB_USERNAME}/${REPO_NAME}
   • Vérifier que tous les fichiers sont présents
   • Configurer les GitHub Pages si souhaité

${GREEN}🎯 COMMANDES RAPIDES:${NC}

# Si vous avez déjà créé le repository GitHub:
git remote add origin https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git
git push -u origin main

# Pour les commits futurs:
git add .
git commit -m "feat: description des modifications"
git push

${YELLOW}📝 CONSEILS POUR LES COMMITS:${NC}

• Utiliser des messages descriptifs
• Préfixer avec le type: feat:, fix:, docs:, security:
• Mettre à jour CHANGELOG.md pour les modifications importantes
• Tester les scripts avant de commiter

${RED}⚠️ IMPORTANT - SÉCURITÉ:${NC}

• Vérifier que .gitignore fonctionne correctement
• Ne jamais commiter de données sensibles
• Anonymiser tous les logs et captures
• Utiliser des mots de passe fictifs dans la documentation

EOF

echo -e "${GREEN}🎉 Setup Git terminé avec succès !${NC}"
echo -e "${BLUE}📁 Repository local prêt dans: $REPO_DIR${NC}"
echo -e "${YELLOW}📖 Consulter le README.md pour les instructions détaillées${NC}"
