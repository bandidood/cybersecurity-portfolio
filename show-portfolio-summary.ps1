# show-portfolio-summary.ps1 - Affichage du résumé du portfolio créé
# Version PowerShell pour Windows

$PortfolioDir = "C:\Users\joh_l\cybersecurity-portfolio"

Clear-Host

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║                  🎉 PORTFOLIO CYBERSÉCURITÉ CRÉÉ               ║" -ForegroundColor Blue  
Write-Host "║                     Structure Complète Générée                  ║" -ForegroundColor Blue
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Blue

Write-Host ""
Write-Host "📁 STRUCTURE DU PORTFOLIO CRÉÉE:" -ForegroundColor Green
Write-Host "=================================="

Write-Host "🏠 Projet 01: Laboratoire de Cybersécurité à Domicile" -ForegroundColor Yellow
Write-Host "   ✅ Infrastructure de virtualisation complète"
Write-Host "   ✅ Scripts de déploiement automatique"
Write-Host "   ✅ Monitoring et health checks"
Write-Host "   ✅ Documentation professionnelle"
Write-Host "   ✅ Configuration réseau segmentée"
Write-Host ""
Write-Host "🔥 Projet 02: Configuration Pare-feu Enterprise" -ForegroundColor Yellow
Write-Host "   ✅ Architecture réseau d'entreprise"
Write-Host "   ✅ Règles de sécurité granulaires"
Write-Host "   ✅ Monitoring et métriques"
Write-Host "   ✅ Conformité et audit"
Write-Host "   ✅ Scripts d'automatisation"

Write-Host ""
Write-Host "🛠️ OUTILS ET SCRIPTS CRÉÉS:" -ForegroundColor Blue
Write-Host "=============================="

Write-Host "🚀 Scripts de Déploiement:"
Write-Host "   • deploy-lab.sh              - Déploiement automatique du laboratoire"
Write-Host "   • setup-git-repo.sh          - Initialisation Git et GitHub"
Write-Host ""
Write-Host "🔍 Scripts de Monitoring:"
Write-Host "   • health-check.py            - Surveillance état du laboratoire"
Write-Host "   • firewall-metrics.py        - Métriques de performance pare-feu"
Write-Host "   • log-analyzer.py            - Analyse des logs de sécurité"
Write-Host ""
Write-Host "⚙️ Fichiers de Configuration:"
Write-Host "   • firewall-rules.conf        - Règles de pare-feu pfSense"
Write-Host "   • .gitignore                 - Protection données sensibles"
Write-Host "   • VM templates               - Configurations machines virtuelles"

Write-Host ""
Write-Host "📚 DOCUMENTATION GÉNÉRÉE:" -ForegroundColor Green
Write-Host "=============================="

Write-Host "📄 Documentation Technique:"
Write-Host "   • README.md complets          - Guides pas-à-pas détaillés"
Write-Host "   • CHANGELOG.md               - Traçabilité des modifications"
Write-Host "   • Architecture diagrams       - Schémas réseau professionnels"
Write-Host "   • Security checklists         - Bonnes pratiques sécurité"
Write-Host ""
Write-Host "🏆 Standards Professionnels:"
Write-Host "   • Structure Git organisée     - Prêt pour GitHub"
Write-Host "   • Conventions de nommage      - Standards de l'industrie"
Write-Host "   • Documentation complète      - Niveau entreprise"
Write-Host "   • Conformité sécurité          - NIST, ISO 27001, OWASP"

Write-Host ""
Write-Host "🎯 PROCHAINES ÉTAPES:" -ForegroundColor Yellow
Write-Host "====================="

Write-Host "1️⃣ " -NoNewline -ForegroundColor Blue
Write-Host "Initialiser Git et GitHub:" -ForegroundColor Blue
Write-Host "   cd `"$PortfolioDir`""
Write-Host "   git init"
Write-Host "   git add ."
Write-Host "   git commit -m `"Initial commit: Cybersecurity Portfolio`""
Write-Host ""
Write-Host "2️⃣ " -NoNewline -ForegroundColor Blue  
Write-Host "Créer le repository GitHub:" -ForegroundColor Blue
Write-Host "   • Aller sur https://github.com/new"
Write-Host "   • Nom: cybersecurity-portfolio"
Write-Host "   • Description: Professional Cybersecurity Portfolio - 50 hands-on projects"
Write-Host "   • Public pour portfolio"
Write-Host ""
Write-Host "3️⃣ " -NoNewline -ForegroundColor Blue
Write-Host "Pousser vers GitHub:" -ForegroundColor Blue
Write-Host "   git remote add origin https://github.com/[USERNAME]/cybersecurity-portfolio.git"
Write-Host "   git branch -M main"
Write-Host "   git push -u origin main"

Write-Host ""
Write-Host "⚠️ POINTS IMPORTANTS:" -ForegroundColor Red
Write-Host "===================="

Write-Host "🔒 Sécurité:"
Write-Host "   • Vérifier l'isolation réseau avant démarrage"
Write-Host "   • Ne jamais exposer le laboratoire sur Internet"
Write-Host "   • Utiliser uniquement des données de test"
Write-Host "   • Changer tous les mots de passe par défaut"
Write-Host ""
Write-Host "📝 Personnalisation:"
Write-Host "   • Remplacer [Votre nom] dans les fichiers"
Write-Host "   • Adapter les URLs GitHub selon votre profil"
Write-Host "   • Ajouter vos informations de contact"
Write-Host "   • Documenter vos modifications"

Write-Host ""
Write-Host "📊 STATISTIQUES:" -ForegroundColor Cyan
Write-Host "================"

if (Test-Path $PortfolioDir) {
    $TotalFiles = (Get-ChildItem -Path $PortfolioDir -Recurse -File).Count
    $TotalDirs = (Get-ChildItem -Path $PortfolioDir -Recurse -Directory).Count
    $ReadmeFiles = (Get-ChildItem -Path $PortfolioDir -Recurse -Name "README.md").Count
    $ScriptFiles = (Get-ChildItem -Path $PortfolioDir -Recurse -Include "*.sh", "*.py", "*.ps1").Count
    
    Write-Host "📄 Fichiers totaux      : $TotalFiles"
    Write-Host "📁 Dossiers créés       : $TotalDirs"
    Write-Host "📝 Fichiers README      : $ReadmeFiles"  
    Write-Host "🔧 Scripts              : $ScriptFiles"
} else {
    Write-Host "❌ Répertoire portfolio non trouvé" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎆 FÉLICITATIONS !" -ForegroundColor Green
Write-Host "================="
Write-Host ""
Write-Host "Vous avez maintenant une base solide pour votre portfolio cybersécurité !"
Write-Host ""
Write-Host "💼 Ce portfolio démontre:" -ForegroundColor Cyan
Write-Host "   ✓ Maîtrise de l'architecture réseau sécurisée"
Write-Host "   ✓ Compétences en scripting et automatisation"  
Write-Host "   ✓ Connaissance des bonnes pratiques sécurité"
Write-Host "   ✓ Capacité à documenter professionnellement"
Write-Host "   ✓ Approche méthodique des projets cybersécurité"
Write-Host ""
Write-Host "🏆 Utilisations possibles:"
Write-Host "   • Entretiens d'embauche en cybersécurité"
Write-Host "   • Préparation aux certifications (OSCP, CEH, CISSP)"
Write-Host "   • Formation continue et veille technologique"
Write-Host "   • Démonstrations techniques aux clients"
Write-Host "   • Contribution à la communauté open source"
Write-Host ""
Write-Host "🚀 Prochaine étape: Créer votre repository GitHub et commencer l'aventure !" -ForegroundColor Blue
Write-Host ""
Write-Host "Happy Hacking! 🔐💻🎆" -ForegroundColor Magenta

Write-Host ""
Write-Host "📁 Répertoire du portfolio: $PortfolioDir" -ForegroundColor Yellow
Write-Host "🌐 Pour aide: https://docs.github.com/en/get-started" -ForegroundColor Yellow