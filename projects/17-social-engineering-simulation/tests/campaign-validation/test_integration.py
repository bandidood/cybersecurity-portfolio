#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Integration Tests - Social Engineering Simulation Platform
============================================================================
Tests d'intégration complets pour valider le fonctionnement de bout en bout
de la plateforme de simulation d'ingénierie sociale.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 28, 2024
============================================================================
"""

import unittest
import tempfile
import os
import sys
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

# Configuration du chemin pour les imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / 'src'))

try:
    from phishing.campaign_manager import (
        CampaignManager, EmailTemplate, Target, 
        CampaignType, CampaignStatus
    )
    from osint.social_recon import SocialRecon, CompanyProfile
except ImportError as e:
    print(f"❌ Erreur d'import: {e}")
    print("Assurez-vous que le projet est correctement configuré.")
    sys.exit(1)


class TestSocialEngineeringIntegration(unittest.TestCase):
    """
    Tests d'intégration pour la plateforme complète
    """
    
    def setUp(self):
        """Configuration des tests d'intégration"""
        # Base de données temporaire
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        # Configuration email de test
        self.email_config = {
            'smtp_server': 'localhost',
            'smtp_port': 1025,
            'username': 'test@test.local',
            'password': 'test_password',
            'use_tls': False
        }
        
        # Initialisation du gestionnaire de campagnes
        self.campaign_manager = CampaignManager(
            db_path=self.temp_db.name,
            email_config=self.email_config
        )
        
        # Outil OSINT
        self.recon_tool = SocialRecon()
        
    def tearDown(self):
        """Nettoyage après les tests"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_complete_campaign_workflow(self):
        """Test du workflow complet d'une campagne"""
        print("\n🧪 Test: Workflow complet de campagne")
        
        # 1. Création des cibles
        targets = [
            Target(
                email="john.doe@test.com",
                first_name="John", 
                last_name="Doe",
                position="Manager",
                department="IT"
            ),
            Target(
                email="jane.smith@test.com",
                first_name="Jane",
                last_name="Smith", 
                position="Developer",
                department="IT"
            )
        ]
        
        # 2. Création du template
        template = EmailTemplate(
            name="Test Template",
            subject="Test Phishing Email",
            html_content="<html><body>Hello {{first_name}}, click <a href='{{phishing_link}}'>here</a></body></html>",
            text_content="Hello {{first_name}}, click here: {{phishing_link}}"
        )
        
        # 3. Création de la campagne
        campaign = self.campaign_manager.create_campaign(
            name="Integration Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets,
            description="Test d'intégration complet"
        )
        
        # Vérifications de base
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.name, "Integration Test Campaign")
        self.assertEqual(len(campaign.targets), 2)
        self.assertEqual(campaign.status, CampaignStatus.DRAFT)
        
        # 4. Vérification de la persistance en base
        retrieved_campaign = self.campaign_manager.get_campaign(campaign.id)
        self.assertIsNotNone(retrieved_campaign)
        self.assertEqual(retrieved_campaign.id, campaign.id)
        
        # 5. Mise à jour des métriques
        self.campaign_manager.update_metrics(
            campaign.id,
            emails_sent=2,
            emails_opened=1,
            links_clicked=1,
            credentials_submitted=0
        )
        
        # 6. Vérification des métriques
        metrics = self.campaign_manager.get_campaign_metrics(campaign.id)
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics.emails_sent, 2)
        self.assertEqual(metrics.emails_opened, 1)
        self.assertEqual(metrics.links_clicked, 1)
        
        # 7. Calcul des taux
        self.campaign_manager._calculate_rates(campaign.id)
        updated_metrics = self.campaign_manager.get_campaign_metrics(campaign.id)
        self.assertAlmostEqual(updated_metrics.open_rate, 0.5, places=2)
        self.assertAlmostEqual(updated_metrics.click_rate, 0.5, places=2)
        
        print("   ✅ Workflow complet testé avec succès")
    
    def test_multiple_campaigns_management(self):
        """Test de gestion de plusieurs campagnes simultanées"""
        print("\n🧪 Test: Gestion de campagnes multiples")
        
        # Création de plusieurs campagnes
        campaigns = []
        
        for i in range(3):
            targets = [
                Target(
                    email=f"user{i}@test{i}.com",
                    first_name=f"User{i}",
                    last_name=f"Test{i}",
                    position="Employee"
                )
            ]
            
            campaign = self.campaign_manager.create_campaign(
                name=f"Test Campaign {i+1}",
                campaign_type=CampaignType.PHISHING,
                targets=targets
            )
            
            campaigns.append(campaign)
        
        # Vérification que toutes les campagnes sont créées
        self.assertEqual(len(campaigns), 3)
        
        # Test de listage des campagnes
        all_campaigns = self.campaign_manager.list_campaigns()
        self.assertEqual(len(all_campaigns), 3)
        
        # Vérification que chaque campagne est unique
        campaign_ids = [c.id for c in all_campaigns]
        self.assertEqual(len(set(campaign_ids)), 3)  # Tous les IDs sont uniques
        
        # Test de récupération individuelle
        for campaign in campaigns:
            retrieved = self.campaign_manager.get_campaign(campaign.id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.id, campaign.id)
        
        print("   ✅ Gestion de campagnes multiples testée avec succès")
    
    def test_osint_integration(self):
        """Test d'intégration des fonctionnalités OSINT"""
        print("\n🧪 Test: Intégration OSINT")
        
        # Création d'un profil d'entreprise de test
        company_profile = CompanyProfile(
            domain="test-company.com",
            name="Test Company",
            industry="Technology",
            size="50-100 employees"
        )
        
        # Simulation de données collectées
        company_profile.emails_found = [
            "admin@test-company.com",
            "hr@test-company.com",
            "support@test-company.com"
        ]
        
        company_profile.employees = [
            {
                "name": "Test Admin",
                "position": "Administrator", 
                "email": "admin@test-company.com"
            },
            {
                "name": "Test HR",
                "position": "HR Manager",
                "email": "hr@test-company.com"
            }
        ]
        
        # Test de conversion en cibles
        targets = []
        for employee in company_profile.employees:
            target = Target(
                email=employee['email'],
                first_name=employee['name'].split()[0],
                last_name=' '.join(employee['name'].split()[1:]),
                position=employee['position'],
                company=company_profile.name
            )
            targets.append(target)
        
        # Vérifications
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].email, "admin@test-company.com")
        self.assertEqual(targets[0].first_name, "Test")
        self.assertEqual(targets[0].last_name, "Admin")
        self.assertEqual(targets[0].company, "Test Company")
        
        # Création d'une campagne avec ces cibles
        campaign = self.campaign_manager.create_campaign(
            name="OSINT Integration Test",
            campaign_type=CampaignType.PHISHING,
            targets=targets,
            description="Test d'intégration OSINT vers campagne"
        )
        
        self.assertIsNotNone(campaign)
        self.assertEqual(len(campaign.targets), 2)
        
        print("   ✅ Intégration OSINT testée avec succès")
    
    def test_template_personalization(self):
        """Test de personnalisation des templates"""
        print("\n🧪 Test: Personnalisation des templates")
        
        # Template avec variables
        template = EmailTemplate(
            name="Personalized Template",
            subject="Hello {{first_name}} from {{company}}",
            html_content="""
            <html>
                <body>
                    <h1>Hello {{first_name}} {{last_name}}</h1>
                    <p>We noticed you work at {{company}} as {{position}}.</p>
                    <p>Department: {{department}}</p>
                    <a href="{{phishing_link}}">Click here</a>
                    <img src="{{tracking_pixel}}" width="1" height="1">
                </body>
            </html>
            """,
            text_content="Hello {{first_name}} {{last_name}} from {{company}}"
        )
        
        # Cible avec toutes les informations
        target = Target(
            email="john.doe@example.com",
            first_name="John",
            last_name="Doe", 
            position="Senior Developer",
            department="Engineering",
            company="Example Corp"
        )
        
        # Test de personnalisation (simulation)
        personalized_subject = template.subject.replace("{{first_name}}", target.first_name)
        personalized_subject = personalized_subject.replace("{{company}}", target.company)
        
        expected_subject = "Hello John from Example Corp"
        self.assertEqual(personalized_subject, expected_subject)
        
        # Test du contenu HTML
        personalized_html = template.html_content.replace("{{first_name}}", target.first_name)
        personalized_html = personalized_html.replace("{{last_name}}", target.last_name)
        personalized_html = personalized_html.replace("{{company}}", target.company)
        personalized_html = personalized_html.replace("{{position}}", target.position)
        personalized_html = personalized_html.replace("{{department}}", target.department)
        
        self.assertIn("Hello John Doe", personalized_html)
        self.assertIn("Example Corp", personalized_html)
        self.assertIn("Senior Developer", personalized_html)
        self.assertIn("Engineering", personalized_html)
        
        print("   ✅ Personnalisation des templates testée avec succès")
    
    @patch('smtplib.SMTP')
    def test_email_sending_simulation(self, mock_smtp):
        """Test de simulation d'envoi d'emails"""
        print("\n🧪 Test: Simulation d'envoi d'emails")
        
        # Configuration du mock
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server
        mock_server.send_message.return_value = {}
        
        # Création d'une campagne et template
        target = Target(
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )
        
        template = EmailTemplate(
            name="Test Email",
            subject="Test Subject",
            html_content="<html><body>Test</body></html>",
            text_content="Test"
        )
        
        campaign = self.campaign_manager.create_campaign(
            name="Email Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=[target]
        )
        
        # Simulation du lancement
        result = self.campaign_manager.launch_campaign(campaign.id, template)
        
        # Vérifications
        self.assertTrue(result)
        
        # Vérification que le serveur SMTP a été appelé
        mock_smtp.assert_called()
        mock_server.starttls.assert_called()
        mock_server.login.assert_called()
        mock_server.send_message.assert_called()
        
        # Vérification du statut de la campagne
        updated_campaign = self.campaign_manager.get_campaign(campaign.id)
        self.assertEqual(updated_campaign.status, CampaignStatus.ACTIVE)
        
        print("   ✅ Simulation d'envoi d'emails testée avec succès")
    
    def test_metrics_calculation_accuracy(self):
        """Test de précision des calculs de métriques"""
        print("\n🧪 Test: Précision des calculs de métriques")
        
        # Création d'une campagne avec 10 cibles
        targets = [
            Target(
                email=f"user{i}@test.com",
                first_name=f"User{i}",
                last_name="Test"
            ) for i in range(10)
        ]
        
        campaign = self.campaign_manager.create_campaign(
            name="Metrics Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Simulation de métriques précises
        self.campaign_manager.update_metrics(
            campaign.id,
            emails_sent=10,
            emails_opened=8,  # 80% open rate
            links_clicked=6,  # 60% click rate (75% of opened)
            credentials_submitted=2  # 20% success rate (33% of clicked)
        )
        
        # Calcul des taux
        self.campaign_manager._calculate_rates(campaign.id)
        metrics = self.campaign_manager.get_campaign_metrics(campaign.id)
        
        # Vérifications de précision
        self.assertAlmostEqual(metrics.open_rate, 0.8, places=2)   # 8/10 = 0.8
        self.assertAlmostEqual(metrics.click_rate, 0.6, places=2)  # 6/10 = 0.6  
        self.assertAlmostEqual(metrics.success_rate, 0.2, places=2) # 2/10 = 0.2
        
        # Test avec des nombres plus complexes
        self.campaign_manager.update_metrics(
            campaign.id,
            emails_sent=23,
            emails_opened=17,
            links_clicked=11,
            credentials_submitted=3
        )
        
        self.campaign_manager._calculate_rates(campaign.id)
        metrics = self.campaign_manager.get_campaign_metrics(campaign.id)
        
        expected_open_rate = 17/23
        expected_click_rate = 11/23
        expected_success_rate = 3/23
        
        self.assertAlmostEqual(metrics.open_rate, expected_open_rate, places=3)
        self.assertAlmostEqual(metrics.click_rate, expected_click_rate, places=3)
        self.assertAlmostEqual(metrics.success_rate, expected_success_rate, places=3)
        
        print("   ✅ Précision des calculs de métriques testée avec succès")
    
    def test_database_consistency(self):
        """Test de cohérence de la base de données"""
        print("\n🧪 Test: Cohérence de la base de données")
        
        # Test des contraintes de base de données
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        
        # Vérification des tables créées
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['campaigns', 'targets', 'email_templates', 'campaign_metrics']
        for table in expected_tables:
            self.assertIn(table, tables)
        
        # Test d'intégrité référentielle
        # Création d'une campagne
        targets = [
            Target(email="test@consistency.com", first_name="Test", last_name="User")
        ]
        
        campaign = self.campaign_manager.create_campaign(
            name="Consistency Test",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Vérification que les données sont cohérentes
        cursor.execute("SELECT COUNT(*) FROM campaigns WHERE id = ?", (campaign.id,))
        campaign_count = cursor.fetchone()[0]
        self.assertEqual(campaign_count, 1)
        
        cursor.execute("SELECT COUNT(*) FROM targets WHERE campaign_id = ?", (campaign.id,))
        targets_count = cursor.fetchone()[0]
        self.assertEqual(targets_count, 1)
        
        cursor.execute("SELECT COUNT(*) FROM campaign_metrics WHERE campaign_id = ?", (campaign.id,))
        metrics_count = cursor.fetchone()[0]
        self.assertEqual(metrics_count, 1)
        
        conn.close()
        
        print("   ✅ Cohérence de la base de données testée avec succès")
    
    def test_error_handling(self):
        """Test de gestion des erreurs"""
        print("\n🧪 Test: Gestion des erreurs")
        
        # Test avec campagne inexistante
        non_existent_campaign = self.campaign_manager.get_campaign("fake-id-123")
        self.assertIsNone(non_existent_campaign)
        
        # Test avec cible invalide
        try:
            invalid_target = Target(
                email="invalid-email",  # Email invalide
                first_name="Test",
                last_name="User"
            )
            
            campaign = self.campaign_manager.create_campaign(
                name="Error Test",
                campaign_type=CampaignType.PHISHING,
                targets=[invalid_target]
            )
            
            # La campagne devrait être créée même avec un email invalide
            # (la validation email peut être faite au niveau applicatif)
            self.assertIsNotNone(campaign)
            
        except Exception as e:
            # Si une exception est levée, elle doit être gérée proprement
            self.assertIsInstance(e, (ValueError, TypeError))
        
        # Test de métriques sur campagne inexistante
        fake_metrics = self.campaign_manager.get_campaign_metrics("fake-id-456")
        self.assertIsNone(fake_metrics)
        
        print("   ✅ Gestion des erreurs testée avec succès")
    
    def test_campaign_lifecycle(self):
        """Test du cycle de vie complet d'une campagne"""
        print("\n🧪 Test: Cycle de vie complet d'une campagne")
        
        # 1. Création (état DRAFT)
        target = Target(email="lifecycle@test.com", first_name="Life", last_name="Cycle")
        campaign = self.campaign_manager.create_campaign(
            name="Lifecycle Test",
            campaign_type=CampaignType.PHISHING,
            targets=[target]
        )
        
        self.assertEqual(campaign.status, CampaignStatus.DRAFT)
        
        # 2. Template pour lancement
        template = EmailTemplate(
            name="Lifecycle Template",
            subject="Test",
            html_content="<html>Test</html>",
            text_content="Test"
        )
        
        # 3. Lancement (état ACTIVE) - avec mock pour éviter l'envoi réel
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            
            result = self.campaign_manager.launch_campaign(campaign.id, template)
            self.assertTrue(result)
            
            updated_campaign = self.campaign_manager.get_campaign(campaign.id)
            self.assertEqual(updated_campaign.status, CampaignStatus.ACTIVE)
        
        # 4. Progression des métriques
        self.campaign_manager.update_metrics(campaign.id, emails_sent=1)
        self.campaign_manager.update_metrics(campaign.id, emails_opened=1)
        self.campaign_manager.update_metrics(campaign.id, links_clicked=1)
        
        # 5. Finalisation (état COMPLETED)
        # Note: Dans une implémentation complète, il y aurait une méthode pour marquer comme terminée
        # Pour ce test, on simule en mettant à jour directement
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE campaigns SET status = ? WHERE id = ?", 
            (CampaignStatus.COMPLETED.value, campaign.id)
        )
        conn.commit()
        conn.close()
        
        final_campaign = self.campaign_manager.get_campaign(campaign.id)
        self.assertEqual(final_campaign.status, CampaignStatus.COMPLETED)
        
        print("   ✅ Cycle de vie complet d'une campagne testé avec succès")


class TestPerformanceIntegration(unittest.TestCase):
    """
    Tests de performance pour les opérations d'intégration
    """
    
    def setUp(self):
        """Configuration des tests de performance"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        self.email_config = {
            'smtp_server': 'localhost',
            'smtp_port': 1025,
            'username': 'test@test.local',
            'password': 'test_password',
            'use_tls': False
        }
        
        self.campaign_manager = CampaignManager(
            db_path=self.temp_db.name,
            email_config=self.email_config
        )
    
    def tearDown(self):
        """Nettoyage après les tests de performance"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_large_target_list_performance(self):
        """Test de performance avec une grande liste de cibles"""
        print("\n🧪 Test: Performance avec grande liste de cibles")
        
        import time
        
        # Création d'un grand nombre de cibles
        num_targets = 1000
        targets = [
            Target(
                email=f"user{i}@performance-test.com",
                first_name=f"User{i}",
                last_name="Test",
                position="Employee",
                department="Testing"
            ) for i in range(num_targets)
        ]
        
        # Mesure du temps de création de la campagne
        start_time = time.time()
        
        campaign = self.campaign_manager.create_campaign(
            name="Performance Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets,
            description="Test de performance avec 1000 cibles"
        )
        
        creation_time = time.time() - start_time
        
        # Vérifications
        self.assertIsNotNone(campaign)
        self.assertEqual(len(campaign.targets), num_targets)
        
        # La création doit être raisonnable (moins de 10 secondes)
        self.assertLess(creation_time, 10.0)
        
        # Test de récupération
        start_time = time.time()
        retrieved_campaign = self.campaign_manager.get_campaign(campaign.id)
        retrieval_time = time.time() - start_time
        
        self.assertIsNotNone(retrieved_campaign)
        self.assertEqual(len(retrieved_campaign.targets), num_targets)
        
        # La récupération doit être rapide (moins d'1 seconde)
        self.assertLess(retrieval_time, 1.0)
        
        print(f"   ✅ Performance testée: création={creation_time:.2f}s, récupération={retrieval_time:.2f}s")
    
    def test_concurrent_campaigns_performance(self):
        """Test de performance avec des campagnes concurrentes"""
        print("\n🧪 Test: Performance avec campagnes concurrentes")
        
        import time
        import threading
        
        results = []
        errors = []
        
        def create_campaign_thread(thread_id):
            """Fonction pour créer une campagne dans un thread"""
            try:
                targets = [
                    Target(
                        email=f"user{thread_id}@concurrent-test.com",
                        first_name=f"User{thread_id}",
                        last_name="Concurrent"
                    )
                ]
                
                campaign = self.campaign_manager.create_campaign(
                    name=f"Concurrent Campaign {thread_id}",
                    campaign_type=CampaignType.PHISHING,
                    targets=targets
                )
                
                results.append(campaign)
                
            except Exception as e:
                errors.append(str(e))
        
        # Lancement de plusieurs threads simultanément
        threads = []
        num_threads = 10
        
        start_time = time.time()
        
        for i in range(num_threads):
            thread = threading.Thread(target=create_campaign_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Attendre que tous les threads se terminent
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Vérifications
        self.assertEqual(len(errors), 0, f"Erreurs rencontrées: {errors}")
        self.assertEqual(len(results), num_threads)
        
        # Vérifier que toutes les campagnes sont différentes
        campaign_ids = [c.id for c in results]
        self.assertEqual(len(set(campaign_ids)), num_threads)
        
        # Le temps total doit être raisonnable
        self.assertLess(total_time, 30.0)
        
        print(f"   ✅ Performance concurrente testée: {num_threads} campagnes en {total_time:.2f}s")


if __name__ == '__main__':
    # Configuration des tests
    unittest.TestLoader.sortTestMethodsUsing = None
    
    # Création de la suite de tests
    test_suite = unittest.TestSuite()
    
    # Ajout des classes de tests
    test_classes = [
        TestSocialEngineeringIntegration,
        TestPerformanceIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Configuration du runner avec plus de détails
    runner = unittest.TextTestRunner(
        verbosity=2, 
        buffer=True,
        stream=sys.stdout
    )
    
    # Exécution des tests
    print("🧪 DÉMARRAGE DES TESTS D'INTÉGRATION")
    print("=" * 60)
    
    result = runner.run(test_suite)
    
    # Résumé final
    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ DES TESTS D'INTÉGRATION")
    print(f"✅ Tests réussis: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Tests échoués: {len(result.failures)}")
    print(f"💥 Erreurs: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ ÉCHECS:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 ERREURS:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback}")
    
    # Code de sortie
    exit_code = 0 if result.wasSuccessful() else 1
    print(f"\n🏁 Tests terminés avec le code de sortie: {exit_code}")
    
    sys.exit(exit_code)