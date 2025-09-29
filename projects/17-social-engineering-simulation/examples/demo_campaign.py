#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Demo Campaign - Social Engineering Simulation Platform
============================================================================
Script de démonstration complet montrant l'utilisation de la plateforme
pour créer, lancer et analyser une campagne de simulation d'ingénierie sociale.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 28, 2024
============================================================================
"""

import sys
import os
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

# Ajout du chemin src au PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

try:
    from phishing.campaign_manager import (
        CampaignManager, EmailTemplate, Target, 
        CampaignType, CampaignStatus
    )
    from osint.social_recon import SocialRecon, CompanyProfile, PersonProfile
except ImportError as e:
    print(f"❌ Erreur d'import: {e}")
    print("Assurez-vous que le projet est correctement configuré.")
    sys.exit(1)


class DemoCampaign:
    """
    Démonstration complète d'une campagne d'ingénierie sociale
    """
    
    def __init__(self):
        """Initialisation de la démonstration"""
        self.setup_demo_environment()
        self.campaign_manager = None
        self.recon_tool = None
        
    def setup_demo_environment(self):
        """Configuration de l'environnement de démonstration"""
        print("🔧 Configuration de l'environnement de démonstration...")
        
        # Configuration email pour la démo (utilise un serveur de test local)
        self.email_config = {
            'smtp_server': 'localhost',
            'smtp_port': 1025,  # MailHog SMTP port
            'username': 'demo@social-eng-simulation.local',
            'password': 'demo_password',
            'use_tls': False
        }
        
        # Configuration de la base de données de démo
        demo_db_path = project_root / 'examples' / 'demo.db'
        self.db_path = str(demo_db_path)
        
        print("✅ Environnement configuré")
    
    def initialize_tools(self):
        """Initialisation des outils"""
        print("🛠️  Initialisation des outils...")
        
        try:
            # Gestionnaire de campagnes
            self.campaign_manager = CampaignManager(
                db_path=self.db_path,
                email_config=self.email_config
            )
            
            # Outil OSINT
            self.recon_tool = SocialRecon()
            
            print("✅ Outils initialisés avec succès")
            
        except Exception as e:
            print(f"❌ Erreur lors de l'initialisation: {e}")
            return False
            
        return True
    
    def demonstrate_osint_reconnaissance(self):
        """Démonstration de la reconnaissance OSINT"""
        print("\n📡 === DÉMONSTRATION OSINT ===")
        
        # Profil d'entreprise fictive
        print("🔍 Collecte d'informations sur l'entreprise cible...")
        
        company_profile = CompanyProfile(
            domain="acmecorp-demo.com",
            name="ACME Corporation Demo",
            industry="Technology",
            size="500-1000 employees",
            locations=["New York", "San Francisco"],
            description="Société de démonstration pour les tests de sécurité"
        )
        
        # Simulation de données collectées
        company_profile.emails_found = [
            "john.doe@acmecorp-demo.com",
            "jane.smith@acmecorp-demo.com",
            "mike.wilson@acmecorp-demo.com",
            "sarah.connor@acmecorp-demo.com"
        ]
        
        company_profile.employees = [
            {
                "name": "John Doe",
                "position": "IT Manager",
                "email": "john.doe@acmecorp-demo.com",
                "linkedin": "https://linkedin.com/in/johndoe-demo"
            },
            {
                "name": "Jane Smith",
                "position": "Finance Director",
                "email": "jane.smith@acmecorp-demo.com",
                "linkedin": "https://linkedin.com/in/janesmith-demo"
            },
            {
                "name": "Mike Wilson",
                "position": "Software Developer",
                "email": "mike.wilson@acmecorp-demo.com",
                "linkedin": "https://linkedin.com/in/mikewilson-demo"
            },
            {
                "name": "Sarah Connor",
                "position": "HR Specialist",
                "email": "sarah.connor@acmecorp-demo.com",
                "linkedin": "https://linkedin.com/in/sarahconnor-demo"
            }
        ]
        
        print(f"✅ Informations collectées sur {company_profile.name}:")
        print(f"   📧 {len(company_profile.emails_found)} emails trouvés")
        print(f"   👥 {len(company_profile.employees)} employés identifiés")
        print(f"   🏢 Secteur: {company_profile.industry}")
        print(f"   📍 Localisations: {', '.join(company_profile.locations)}")
        
        return company_profile
    
    def create_email_templates(self):
        """Création des templates d'email de démonstration"""
        print("\n📧 === CRÉATION DES TEMPLATES ===")
        
        # Template phishing IT Support
        it_support_template = EmailTemplate(
            name="IT Support - Mise à jour sécurité",
            subject="URGENT: Mise à jour de sécurité requise - Action dans 24h",
            html_content="""
            <html>
            <head>
                <style>
                    .header { background: #0066cc; color: white; padding: 20px; text-align: center; }
                    .urgent { color: #ff0000; font-weight: bold; text-transform: uppercase; }
                    .content { padding: 20px; font-family: Arial, sans-serif; }
                    .button { 
                        background: #ff6600; 
                        color: white; 
                        padding: 15px 30px; 
                        text-decoration: none; 
                        border-radius: 5px;
                        display: inline-block;
                        margin: 20px 0;
                    }
                    .footer { font-size: 12px; color: #666; padding: 20px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🔒 ACME Corp IT Security</h1>
                </div>
                
                <div class="content">
                    <p>Bonjour {{first_name}},</p>
                    
                    <p class="urgent">⚠️ Action Urgente Requise ⚠️</p>
                    
                    <p>
                        Notre système de sécurité a détecté une tentative d'accès non autorisé 
                        sur votre compte {{email}}. Pour protéger vos données et celles de l'entreprise, 
                        une mise à jour immédiate de vos informations de sécurité est requise.
                    </p>
                    
                    <p>
                        <strong>Échéance:</strong> Cette action doit être complétée dans les <span class="urgent">24 heures</span> 
                        pour éviter la suspension temporaire de votre compte.
                    </p>
                    
                    <div style="text-align: center;">
                        <a href="{{phishing_link}}?user={{email}}&token={{tracking_token}}" class="button">
                            🔐 SÉCURISER MON COMPTE MAINTENANT
                        </a>
                    </div>
                    
                    <p>
                        Si vous n'effectuez pas cette action, votre accès aux systèmes ACME Corp 
                        sera temporairement suspendu pour des raisons de sécurité.
                    </p>
                    
                    <p>
                        Pour toute question, contactez immédiatement le support IT au 
                        <strong>+1-555-IT-HELP</strong>.
                    </p>
                </div>
                
                <div class="footer">
                    <p>
                        Ce message est généré automatiquement par le système de sécurité ACME Corp.<br>
                        © 2024 ACME Corporation - Service IT Sécurité
                    </p>
                </div>
                
                <img src="{{tracking_pixel}}" width="1" height="1" style="display:none;">
            </body>
            </html>
            """,
            text_content="""
URGENT: Mise à jour de sécurité requise - Action dans 24h

Bonjour {{first_name}},

⚠️ ACTION URGENTE REQUISE ⚠️

Notre système de sécurité a détecté une tentative d'accès non autorisé sur votre compte {{email}}.

Pour protéger vos données, cliquez sur le lien suivant dans les 24 heures:
{{phishing_link}}?user={{email}}&token={{tracking_token}}

Support IT: +1-555-IT-HELP

ACME Corp IT Security
            """,
            attachments=[]
        )
        
        print("✅ Template 'IT Support' créé")
        
        # Template phishing HR
        hr_template = EmailTemplate(
            name="RH - Politique de sécurité",
            subject="Nouvelle politique de sécurité - Signature obligatoire",
            html_content="""
            <html>
            <head>
                <style>
                    .header { background: #2d5aa0; color: white; padding: 20px; }
                    .content { padding: 20px; font-family: Arial, sans-serif; line-height: 1.6; }
                    .button { 
                        background: #28a745; 
                        color: white; 
                        padding: 12px 25px; 
                        text-decoration: none; 
                        border-radius: 4px;
                        display: inline-block;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>👥 ACME Corp Ressources Humaines</h1>
                </div>
                
                <div class="content">
                    <p>Cher {{first_name}},</p>
                    
                    <p>
                        Conformément aux nouvelles réglementations de sécurité informatique, 
                        tous les employés doivent signer électroniquement la mise à jour 
                        de notre politique de sécurité des données.
                    </p>
                    
                    <p>
                        <strong>Date limite:</strong> 31 janvier 2024<br>
                        <strong>Temps requis:</strong> 5-10 minutes
                    </p>
                    
                    <p>
                        Veuillez cliquer sur le lien ci-dessous pour accéder au document 
                        et procéder à la signature électronique:
                    </p>
                    
                    <p style="text-align: center;">
                        <a href="{{phishing_link}}?emp={{email}}&doc=security-policy-2024" class="button">
                            📄 SIGNER LE DOCUMENT
                        </a>
                    </p>
                    
                    <p>
                        Cette signature est obligatoire pour tous les employés. 
                        Le non-respect de cette exigence pourrait affecter votre statut d'emploi.
                    </p>
                    
                    <p>
                        Cordialement,<br>
                        <strong>Sarah Connor</strong><br>
                        Spécialiste RH - Conformité<br>
                        ACME Corporation
                    </p>
                </div>
            </body>
            </html>
            """,
            text_content="""
Nouvelle politique de sécurité - Signature obligatoire

Cher {{first_name}},

Tous les employés doivent signer la nouvelle politique de sécurité des données.

Date limite: 31 janvier 2024

Cliquez ici pour signer: {{phishing_link}}?emp={{email}}&doc=security-policy-2024

Cordialement,
Sarah Connor
Spécialiste RH - Conformité
ACME Corporation
            """
        )
        
        print("✅ Template 'RH - Politique' créé")
        
        return [it_support_template, hr_template]
    
    def create_demo_targets(self, company_profile):
        """Création des cibles de démonstration"""
        print("\n🎯 === CRÉATION DES CIBLES ===")
        
        targets = []
        
        for employee in company_profile.employees:
            target = Target(
                email=employee['email'],
                first_name=employee['name'].split()[0],
                last_name=' '.join(employee['name'].split()[1:]),
                position=employee['position'],
                department=self._get_department_from_position(employee['position']),
                company="ACME Corporation Demo"
            )
            targets.append(target)
        
        print(f"✅ {len(targets)} cibles créées:")
        for target in targets:
            print(f"   👤 {target.first_name} {target.last_name} ({target.position}) - {target.email}")
        
        return targets
    
    def _get_department_from_position(self, position):
        """Détermine le département basé sur le poste"""
        position_lower = position.lower()
        if 'it' in position_lower or 'software' in position_lower or 'developer' in position_lower:
            return 'IT'
        elif 'finance' in position_lower or 'accounting' in position_lower:
            return 'Finance'
        elif 'hr' in position_lower or 'human' in position_lower:
            return 'Human Resources'
        elif 'manager' in position_lower or 'director' in position_lower:
            return 'Management'
        else:
            return 'General'
    
    def create_and_launch_campaigns(self, templates, targets):
        """Création et lancement des campagnes de démonstration"""
        print("\n🚀 === CRÉATION ET LANCEMENT DES CAMPAGNES ===")
        
        campaigns_created = []
        
        # Campagne 1: IT Support (ciblant tous les employés)
        print("📧 Création de la campagne 'IT Support'...")
        
        campaign_it = self.campaign_manager.create_campaign(
            name="Demo IT Support - Mise à jour sécurité",
            campaign_type=CampaignType.PHISHING,
            targets=targets,
            description="Campagne de démonstration simulant un email d'IT Support urgent"
        )
        
        if campaign_it:
            print(f"✅ Campagne IT créée: {campaign_it.id}")
            campaigns_created.append(campaign_it)
        
        # Campagne 2: RH (ciblant uniquement les managers/directeurs)
        print("📧 Création de la campagne 'RH - Politique'...")
        
        management_targets = [t for t in targets if 'manager' in t.position.lower() or 'director' in t.position.lower()]
        
        campaign_hr = self.campaign_manager.create_campaign(
            name="Demo RH - Politique de sécurité",
            campaign_type=CampaignType.PHISHING,
            targets=management_targets,
            description="Campagne de démonstration ciblant les postes de direction avec un email RH"
        )
        
        if campaign_hr:
            print(f"✅ Campagne RH créée: {campaign_hr.id}")
            campaigns_created.append(campaign_hr)
        
        # Simulation du lancement (sans réellement envoyer d'emails)
        print("\n🎬 Simulation du lancement des campagnes...")
        
        for i, (campaign, template) in enumerate(zip(campaigns_created, templates)):
            print(f"   🚀 Lancement de la campagne '{campaign.name}'...")
            
            # Simulation des métriques au fil du temps
            self._simulate_campaign_progress(campaign.id, len(campaign.targets))
            
        return campaigns_created
    
    def _simulate_campaign_progress(self, campaign_id, num_targets):
        """Simulation du progrès d'une campagne avec des métriques réalistes"""
        
        # Simulation des emails envoyés
        emails_sent = num_targets
        self.campaign_manager.update_metrics(campaign_id, emails_sent=emails_sent)
        print(f"     📤 {emails_sent} emails envoyés")
        
        time.sleep(1)  # Simulation du temps
        
        # Simulation des ouvertures d'emails (70-85% en moyenne)
        import random
        open_rate = random.uniform(0.70, 0.85)
        emails_opened = int(emails_sent * open_rate)
        self.campaign_manager.update_metrics(campaign_id, emails_opened=emails_opened)
        print(f"     📖 {emails_opened} emails ouverts ({open_rate:.1%})")
        
        time.sleep(1)
        
        # Simulation des clics (40-60% de ceux qui ont ouvert)
        click_rate = random.uniform(0.40, 0.60)
        links_clicked = int(emails_opened * click_rate)
        self.campaign_manager.update_metrics(campaign_id, links_clicked=links_clicked)
        print(f"     🖱️  {links_clicked} liens cliqués ({click_rate:.1%} des ouvertures)")
        
        time.sleep(1)
        
        # Simulation des credentials soumis (20-40% de ceux qui ont cliqué)
        submit_rate = random.uniform(0.20, 0.40)
        credentials_submitted = int(links_clicked * submit_rate)
        self.campaign_manager.update_metrics(campaign_id, credentials_submitted=credentials_submitted)
        print(f"     🔐 {credentials_submitted} credentials collectés ({submit_rate:.1%} des clics)")
        
        # Calcul des taux finaux
        self.campaign_manager._calculate_rates(campaign_id)
        
        return {
            'emails_sent': emails_sent,
            'emails_opened': emails_opened, 
            'links_clicked': links_clicked,
            'credentials_submitted': credentials_submitted
        }
    
    def generate_campaign_reports(self, campaigns):
        """Génération des rapports de campagne"""
        print("\n📊 === GÉNÉRATION DES RAPPORTS ===")
        
        for campaign in campaigns:
            print(f"\n📈 Rapport pour '{campaign.name}':")
            
            # Récupération des métriques
            metrics = self.campaign_manager.get_campaign_metrics(campaign.id)
            
            if metrics:
                print(f"   📤 Emails envoyés: {metrics.emails_sent}")
                print(f"   📖 Emails ouverts: {metrics.emails_opened} ({metrics.open_rate:.1%})")
                print(f"   🖱️  Liens cliqués: {metrics.links_clicked} ({metrics.click_rate:.1%})")
                print(f"   🔐 Credentials: {metrics.credentials_submitted} ({metrics.success_rate:.1%})")
                
                # Évaluation du niveau de risque
                risk_score = metrics.success_rate * 10  # Score sur 10
                if risk_score >= 7:
                    risk_level = "🔴 ÉLEVÉ"
                elif risk_score >= 4:
                    risk_level = "🟡 MOYEN"
                else:
                    risk_level = "🟢 FAIBLE"
                
                print(f"   ⚠️  Niveau de risque: {risk_level} ({risk_score:.1f}/10)")
            else:
                print("   ❌ Aucune métrique disponible")
    
    def demonstrate_security_awareness(self):
        """Démonstration des fonctionnalités de sensibilisation"""
        print("\n🎓 === SENSIBILISATION À LA SÉCURITÉ ===")
        
        # Conseils de sécurité basés sur les résultats
        security_tips = [
            "🔍 Vérifiez toujours l'expéditeur d'un email urgent",
            "🔗 Survolez les liens avant de cliquer pour voir leur destination",
            "📞 Appelez directement le service IT en cas de doute",
            "🔐 Utilisez l'authentification multifacteur quand c'est possible",
            "📚 Participez aux formations de sensibilisation à la sécurité",
            "⚠️  Signalez les emails suspects à l'équipe de sécurité",
            "🕒 Méfiez-vous des messages créant un sentiment d'urgence",
            "🏢 Vérifiez les politiques d'entreprise via les canaux officiels"
        ]
        
        print("💡 Conseils de sécurité pour les employés:")
        for tip in security_tips:
            print(f"   {tip}")
        
        # Recommandations pour l'organisation
        print("\n🏢 Recommandations pour l'organisation:")
        org_recommendations = [
            "📋 Mettre en place des formations régulières de sensibilisation",
            "🎯 Organiser des campagnes de phishing internes périodiques", 
            "📞 Établir des procédures claires de signalement d'incidents",
            "🔧 Implémenter des solutions de filtrage d'emails avancées",
            "👥 Former les équipes IT à reconnaître les signalements",
            "📊 Mesurer régulièrement le niveau de sensibilisation",
            "🏆 Récompenser les bons comportements de sécurité",
            "📖 Maintenir une base de connaissances sur les menaces actuelles"
        ]
        
        for rec in org_recommendations:
            print(f"   {rec}")
    
    def cleanup_demo(self):
        """Nettoyage après la démonstration"""
        print("\n🧹 === NETTOYAGE ===")
        
        # Suppression de la base de données de démo
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            print("✅ Base de données de démo supprimée")
        
        print("✅ Nettoyage terminé")
    
    def run_full_demo(self):
        """Exécution complète de la démonstration"""
        print("🎭 DÉMONSTRATION COMPLÈTE - SIMULATION D'INGÉNIERIE SOCIALE")
        print("=" * 70)
        print("⚠️  AVERTISSEMENT: Ceci est une démonstration éducative uniquement")
        print("=" * 70)
        
        try:
            # 1. Initialisation
            if not self.initialize_tools():
                return False
            
            # 2. Reconnaissance OSINT
            company_profile = self.demonstrate_osint_reconnaissance()
            
            # 3. Création des templates
            templates = self.create_email_templates()
            
            # 4. Création des cibles
            targets = self.create_demo_targets(company_profile)
            
            # 5. Création et lancement des campagnes
            campaigns = self.create_and_launch_campaigns(templates, targets)
            
            # 6. Génération des rapports
            self.generate_campaign_reports(campaigns)
            
            # 7. Sensibilisation
            self.demonstrate_security_awareness()
            
            print("\n🎉 === DÉMONSTRATION TERMINÉE ===")
            print("✅ Tous les composants de la plateforme ont été démontrés avec succès!")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Erreur lors de la démonstration: {e}")
            return False
        
        finally:
            # Nettoyage
            self.cleanup_demo()


def main():
    """Point d'entrée principal"""
    print("🚀 Démarrage de la démonstration...")
    
    # Vérification de l'environnement
    if not check_environment():
        sys.exit(1)
    
    # Exécution de la démonstration
    demo = DemoCampaign()
    success = demo.run_full_demo()
    
    if success:
        print("\n🎯 La démonstration s'est terminée avec succès!")
        print("📖 Consultez la documentation dans docs/ pour plus d'informations.")
    else:
        print("\n❌ La démonstration a rencontré des erreurs.")
        sys.exit(1)


def check_environment():
    """Vérification de l'environnement avant la démonstration"""
    print("🔍 Vérification de l'environnement...")
    
    # Vérification de Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requis")
        return False
    
    # Vérification des dossiers nécessaires
    required_dirs = ['src', 'examples', 'docs']
    for dir_name in required_dirs:
        dir_path = project_root / dir_name
        if not dir_path.exists():
            print(f"❌ Dossier manquant: {dir_name}")
            return False
    
    print("✅ Environnement vérifié")
    return True


if __name__ == "__main__":
    main()