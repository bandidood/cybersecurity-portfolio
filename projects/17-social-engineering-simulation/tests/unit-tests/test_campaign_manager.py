#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Test Campaign Manager - Social Engineering Simulation Platform
============================================================================
Tests unitaires complets pour le gestionnaire de campagnes de phishing
et d'ingénierie sociale.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 28, 2024
============================================================================
"""

import unittest
import tempfile
import os
import json
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

# Import du module à tester
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'phishing'))
from campaign_manager import (
    Campaign, Target, EmailTemplate, CampaignMetrics,
    CampaignStatus, CampaignType,
    EmailSender, CampaignManager
)


class TestCampaignDataClasses(unittest.TestCase):
    """Tests pour les dataclasses de campagne"""

    def test_campaign_creation(self):
        """Test création d'une campagne"""
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            status=CampaignStatus.DRAFT,
            created_at=datetime.now(),
            targets=[]
        )
        
        self.assertEqual(campaign.id, "test-001")
        self.assertEqual(campaign.name, "Test Campaign")
        self.assertEqual(campaign.campaign_type, CampaignType.PHISHING)
        self.assertEqual(campaign.status, CampaignStatus.DRAFT)
        self.assertIsInstance(campaign.targets, list)

    def test_target_creation(self):
        """Test création d'une cible"""
        target = Target(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            position="Manager"
        )
        
        self.assertEqual(target.email, "test@example.com")
        self.assertEqual(target.first_name, "John")
        self.assertEqual(target.last_name, "Doe")
        self.assertEqual(target.position, "Manager")

    def test_email_template_creation(self):
        """Test création d'un template d'email"""
        template = EmailTemplate(
            name="Test Template",
            subject="Test Subject",
            html_content="<html><body>Test</body></html>",
            text_content="Test",
            attachments=[]
        )
        
        self.assertEqual(template.name, "Test Template")
        self.assertEqual(template.subject, "Test Subject")
        self.assertIn("Test", template.html_content)
        self.assertEqual(template.text_content, "Test")

    def test_campaign_metrics_initialization(self):
        """Test initialisation des métriques"""
        metrics = CampaignMetrics()
        
        self.assertEqual(metrics.emails_sent, 0)
        self.assertEqual(metrics.emails_opened, 0)
        self.assertEqual(metrics.links_clicked, 0)
        self.assertEqual(metrics.credentials_submitted, 0)
        self.assertEqual(metrics.click_rate, 0.0)
        self.assertEqual(metrics.success_rate, 0.0)


class TestEmailSender(unittest.TestCase):
    """Tests pour l'envoyeur d'emails"""

    def setUp(self):
        """Configuration des tests"""
        self.config = {
            'smtp_server': 'smtp.test.com',
            'smtp_port': 587,
            'username': 'test@test.com',
            'password': 'password',
            'use_tls': True
        }
        self.sender = EmailSender(self.config)

    def test_email_sender_initialization(self):
        """Test initialisation de l'envoyeur d'emails"""
        self.assertEqual(self.sender.smtp_server, 'smtp.test.com')
        self.assertEqual(self.sender.smtp_port, 587)
        self.assertEqual(self.sender.username, 'test@test.com')
        self.assertTrue(self.sender.use_tls)

    @patch('smtplib.SMTP')
    def test_send_email_success(self, mock_smtp):
        """Test envoi d'email réussi"""
        # Configuration du mock
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server
        
        template = EmailTemplate(
            name="Test",
            subject="Test Subject",
            html_content="<html>Test</html>",
            text_content="Test"
        )
        
        target = Target(
            email="recipient@test.com",
            first_name="John",
            last_name="Doe"
        )
        
        # Test de l'envoi
        result = self.sender.send_email(target, template)
        
        # Vérifications
        self.assertTrue(result)
        mock_smtp.assert_called_once()
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.send_message.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_failure(self, mock_smtp):
        """Test échec d'envoi d'email"""
        # Configuration du mock pour lever une exception
        mock_smtp.side_effect = Exception("Connection failed")
        
        template = EmailTemplate(
            name="Test",
            subject="Test Subject",
            html_content="<html>Test</html>",
            text_content="Test"
        )
        
        target = Target(
            email="recipient@test.com",
            first_name="John",
            last_name="Doe"
        )
        
        # Test de l'envoi
        result = self.sender.send_email(target, template)
        
        # Vérifications
        self.assertFalse(result)


class TestCampaignManager(unittest.TestCase):
    """Tests pour le gestionnaire de campagnes"""

    def setUp(self):
        """Configuration des tests"""
        # Création d'une base de données temporaire
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        self.email_config = {
            'smtp_server': 'smtp.test.com',
            'smtp_port': 587,
            'username': 'test@test.com',
            'password': 'password',
            'use_tls': True
        }
        
        self.manager = CampaignManager(
            db_path=self.temp_db.name,
            email_config=self.email_config
        )

    def tearDown(self):
        """Nettoyage après les tests"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_database_initialization(self):
        """Test initialisation de la base de données"""
        # Vérifier que les tables sont créées
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['campaigns', 'targets', 'email_templates', 'campaign_metrics']
        for table in expected_tables:
            self.assertIn(table, tables)
        
        conn.close()

    def test_create_campaign(self):
        """Test création d'une campagne"""
        targets = [
            Target(email="test1@test.com", first_name="John", last_name="Doe"),
            Target(email="test2@test.com", first_name="Jane", last_name="Smith")
        ]
        
        campaign = self.manager.create_campaign(
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.name, "Test Campaign")
        self.assertEqual(campaign.campaign_type, CampaignType.PHISHING)
        self.assertEqual(campaign.status, CampaignStatus.DRAFT)
        self.assertEqual(len(campaign.targets), 2)

    def test_get_campaign(self):
        """Test récupération d'une campagne"""
        # Créer une campagne
        targets = [Target(email="test@test.com", first_name="Test", last_name="User")]
        campaign = self.manager.create_campaign(
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Récupérer la campagne
        retrieved_campaign = self.manager.get_campaign(campaign.id)
        
        self.assertIsNotNone(retrieved_campaign)
        self.assertEqual(retrieved_campaign.id, campaign.id)
        self.assertEqual(retrieved_campaign.name, "Test Campaign")

    def test_list_campaigns(self):
        """Test listage des campagnes"""
        # Créer plusieurs campagnes
        targets = [Target(email="test@test.com", first_name="Test", last_name="User")]
        
        campaign1 = self.manager.create_campaign("Campaign 1", CampaignType.PHISHING, targets)
        campaign2 = self.manager.create_campaign("Campaign 2", CampaignType.VISHING, targets)
        
        # Lister les campagnes
        campaigns = self.manager.list_campaigns()
        
        self.assertEqual(len(campaigns), 2)
        campaign_names = [c.name for c in campaigns]
        self.assertIn("Campaign 1", campaign_names)
        self.assertIn("Campaign 2", campaign_names)

    @patch('src.phishing.campaign_manager.EmailSender')
    def test_launch_campaign(self, mock_email_sender):
        """Test lancement d'une campagne"""
        # Configuration du mock
        mock_sender_instance = MagicMock()
        mock_sender_instance.send_email.return_value = True
        mock_email_sender.return_value = mock_sender_instance
        
        # Créer une campagne
        targets = [Target(email="test@test.com", first_name="Test", last_name="User")]
        campaign = self.manager.create_campaign(
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Créer un template
        template = EmailTemplate(
            name="Test Template",
            subject="Test Subject",
            html_content="<html>Test</html>",
            text_content="Test"
        )
        
        # Lancer la campagne
        result = self.manager.launch_campaign(campaign.id, template)
        
        # Vérifications
        self.assertTrue(result)
        updated_campaign = self.manager.get_campaign(campaign.id)
        self.assertEqual(updated_campaign.status, CampaignStatus.ACTIVE)

    def test_update_metrics(self):
        """Test mise à jour des métriques"""
        # Créer une campagne
        targets = [Target(email="test@test.com", first_name="Test", last_name="User")]
        campaign = self.manager.create_campaign(
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Mettre à jour les métriques
        self.manager.update_metrics(campaign.id, emails_opened=5, links_clicked=3)
        
        # Récupérer les métriques
        metrics = self.manager.get_campaign_metrics(campaign.id)
        
        self.assertEqual(metrics.emails_opened, 5)
        self.assertEqual(metrics.links_clicked, 3)

    def test_calculate_rates(self):
        """Test calcul des taux"""
        # Créer une campagne avec métriques
        targets = [Target(email=f"test{i}@test.com", first_name="Test", last_name="User") 
                  for i in range(10)]
        campaign = self.manager.create_campaign(
            name="Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Simuler des métriques
        self.manager.update_metrics(campaign.id, 
                                   emails_sent=10, 
                                   emails_opened=7, 
                                   links_clicked=5,
                                   credentials_submitted=2)
        
        # Calculer les taux
        self.manager._calculate_rates(campaign.id)
        
        # Vérifier les calculs
        metrics = self.manager.get_campaign_metrics(campaign.id)
        self.assertAlmostEqual(metrics.open_rate, 0.7, places=2)  # 7/10
        self.assertAlmostEqual(metrics.click_rate, 0.5, places=2)  # 5/10
        self.assertAlmostEqual(metrics.success_rate, 0.2, places=2)  # 2/10


class TestCampaignManagerIntegration(unittest.TestCase):
    """Tests d'intégration pour le gestionnaire de campagnes"""

    def setUp(self):
        """Configuration des tests d'intégration"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        self.email_config = {
            'smtp_server': 'smtp.test.com',
            'smtp_port': 587,
            'username': 'test@test.com',
            'password': 'password',
            'use_tls': True
        }
        
        self.manager = CampaignManager(
            db_path=self.temp_db.name,
            email_config=self.email_config
        )

    def tearDown(self):
        """Nettoyage après les tests"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_full_campaign_workflow(self):
        """Test workflow complet d'une campagne"""
        # 1. Créer une campagne
        targets = [
            Target(email="user1@test.com", first_name="John", last_name="Doe"),
            Target(email="user2@test.com", first_name="Jane", last_name="Smith")
        ]
        
        campaign = self.manager.create_campaign(
            name="Integration Test Campaign",
            campaign_type=CampaignType.PHISHING,
            targets=targets
        )
        
        # Vérifier la création
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.status, CampaignStatus.DRAFT)
        
        # 2. Récupérer la campagne
        retrieved_campaign = self.manager.get_campaign(campaign.id)
        self.assertEqual(retrieved_campaign.name, "Integration Test Campaign")
        
        # 3. Mettre à jour les métriques
        self.manager.update_metrics(campaign.id, emails_sent=2, emails_opened=1, links_clicked=1)
        
        # 4. Vérifier les métriques
        metrics = self.manager.get_campaign_metrics(campaign.id)
        self.assertEqual(metrics.emails_sent, 2)
        self.assertEqual(metrics.emails_opened, 1)
        self.assertEqual(metrics.links_clicked, 1)
        
        # 5. Calculer les taux
        self.manager._calculate_rates(campaign.id)
        updated_metrics = self.manager.get_campaign_metrics(campaign.id)
        self.assertAlmostEqual(updated_metrics.open_rate, 0.5, places=2)
        self.assertAlmostEqual(updated_metrics.click_rate, 0.5, places=2)


if __name__ == '__main__':
    # Configuration des tests
    unittest.TestLoader.sortTestMethodsUsing = None
    
    # Suite de tests
    test_suite = unittest.TestSuite()
    
    # Ajouter les classes de tests
    test_classes = [
        TestCampaignDataClasses,
        TestEmailSender,
        TestCampaignManager,
        TestCampaignManagerIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # Code de sortie basé sur le résultat
    exit_code = 0 if result.wasSuccessful() else 1
    exit(exit_code)