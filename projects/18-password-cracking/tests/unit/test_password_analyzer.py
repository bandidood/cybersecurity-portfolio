#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Tests Unitaires - Password Analyzer
============================================================================
Tests complets pour le module d'analyse de mots de passe incluant :
- Tests de détection de patterns
- Tests de calcul d'entropie
- Tests de scoring de force
- Tests d'analyse de datasets
- Tests d'export et de génération de rapports

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import unittest
import os
import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, mock_open

# Ajout du chemin src pour les imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / 'src'))

try:
    from analysis.password_analyzer import (
        PasswordAnalyzer, PasswordStats, DatasetAnalysis,
        KeyboardPatternDetector, CommonSubstitutionDetector,
        DatePatternDetector, DictionaryWordDetector,
        NumberSequenceDetector
    )
except ImportError as e:
    print(f"❌ Erreur d'import: {e}")
    sys.exit(1)


class TestKeyboardPatternDetector(unittest.TestCase):
    """Tests pour le détecteur de patterns de clavier"""
    
    def setUp(self):
        """Configuration initiale"""
        self.detector = KeyboardPatternDetector()
    
    def test_qwerty_patterns(self):
        """Test détection patterns QWERTY"""
        self.assertTrue(self.detector.detect("qwerty"))
        self.assertTrue(self.detector.detect("QWERTY"))
        self.assertTrue(self.detector.detect("qwerty123"))
        self.assertFalse(self.detector.detect("randomtext"))
    
    def test_azerty_patterns(self):
        """Test détection patterns AZERTY"""
        self.assertTrue(self.detector.detect("azerty"))
        self.assertTrue(self.detector.detect("AZERTY"))
        self.assertFalse(self.detector.detect("qwerty"))
    
    def test_number_rows(self):
        """Test détection rangées de chiffres"""
        self.assertTrue(self.detector.detect("123456"))
        self.assertTrue(self.detector.detect("987654321"))
        self.assertFalse(self.detector.detect("135792"))
    
    def test_case_sensitivity(self):
        """Test sensibilité à la casse"""
        self.assertTrue(self.detector.detect("qWeRtY"))
        self.assertTrue(self.detector.detect("AsD"))
    
    def test_minimum_length(self):
        """Test longueur minimale"""
        self.assertFalse(self.detector.detect("qw"))  # Trop court
        self.assertTrue(self.detector.detect("qwe"))  # Assez long


class TestCommonSubstitutionDetector(unittest.TestCase):
    """Tests pour le détecteur de substitutions communes"""
    
    def setUp(self):
        """Configuration initiale"""
        self.detector = CommonSubstitutionDetector()
    
    def test_common_substitutions(self):
        """Test substitutions communes"""
        self.assertTrue(self.detector.detect("p@ssw0rd"))
        self.assertTrue(self.detector.detect("h3ll0"))
        self.assertTrue(self.detector.detect("l3tm31n"))
        self.assertFalse(self.detector.detect("password"))
    
    def test_leetspeak(self):
        """Test détection leetspeak"""
        self.assertTrue(self.detector.detect("1337"))
        self.assertTrue(self.detector.detect("h4ck3r"))
        self.assertTrue(self.detector.detect("3l1t3"))
    
    def test_symbol_substitutions(self):
        """Test substitutions avec symboles"""
        self.assertTrue(self.detector.detect("@dmin"))
        self.assertTrue(self.detector.detect("u$er"))
        self.assertTrue(self.detector.detect("c@r"))
    
    def test_mixed_case(self):
        """Test casse mixte"""
        self.assertTrue(self.detector.detect("P@$$W0RD"))
        self.assertTrue(self.detector.detect("H3LL0"))


class TestDatePatternDetector(unittest.TestCase):
    """Tests pour le détecteur de patterns de dates"""
    
    def setUp(self):
        """Configuration initiale"""
        self.detector = DatePatternDetector()
    
    def test_year_patterns(self):
        """Test détection années"""
        self.assertTrue(self.detector.detect("2023"))
        self.assertTrue(self.detector.detect("1990"))
        self.assertTrue(self.detector.detect("2024"))
        self.assertFalse(self.detector.detect("1899"))  # Trop ancien
        self.assertFalse(self.detector.detect("2050"))  # Trop futur
    
    def test_date_formats(self):
        """Test formats de dates"""
        self.assertTrue(self.detector.detect("01/01/2023"))
        self.assertTrue(self.detector.detect("12-25-1990"))
        self.assertTrue(self.detector.detect("2023-01-01"))
        self.assertTrue(self.detector.detect("25/12/2022"))
    
    def test_month_day_patterns(self):
        """Test patterns mois/jour"""
        self.assertTrue(self.detector.detect("0101"))  # Jan 1
        self.assertTrue(self.detector.detect("1225"))  # Dec 25
        self.assertTrue(self.detector.detect("0314"))  # Mar 14
    
    def test_invalid_dates(self):
        """Test dates invalides"""
        self.assertFalse(self.detector.detect("1301"))  # Mois 13
        self.assertFalse(self.detector.detect("0032"))  # Jour 32
        self.assertFalse(self.detector.detect("randomtext"))


class TestDictionaryWordDetector(unittest.TestCase):
    """Tests pour le détecteur de mots de dictionnaire"""
    
    def setUp(self):
        """Configuration initiale"""
        self.detector = DictionaryWordDetector()
    
    def test_common_words(self):
        """Test mots communs"""
        self.assertTrue(self.detector.detect("password"))
        self.assertTrue(self.detector.detect("admin"))
        self.assertTrue(self.detector.detect("user"))
        self.assertTrue(self.detector.detect("welcome"))
    
    def test_case_insensitive(self):
        """Test insensibilité à la casse"""
        self.assertTrue(self.detector.detect("PASSWORD"))
        self.assertTrue(self.detector.detect("Admin"))
        self.assertTrue(self.detector.detect("WeLcOmE"))
    
    def test_word_variations(self):
        """Test variations de mots"""
        self.assertTrue(self.detector.detect("password123"))
        self.assertTrue(self.detector.detect("123password"))
        self.assertTrue(self.detector.detect("pass123word"))
    
    def test_non_dictionary_words(self):
        """Test mots non-dictionnaire"""
        self.assertFalse(self.detector.detect("xkjhgfds"))
        self.assertFalse(self.detector.detect("zxcvbnm"))
        self.assertFalse(self.detector.detect("qwertyuiop"))


class TestNumberSequenceDetector(unittest.TestCase):
    """Tests pour le détecteur de séquences numériques"""
    
    def setUp(self):
        """Configuration initiale"""
        self.detector = NumberSequenceDetector()
    
    def test_ascending_sequences(self):
        """Test séquences croissantes"""
        self.assertTrue(self.detector.detect("123456"))
        self.assertTrue(self.detector.detect("12345"))
        self.assertTrue(self.detector.detect("1234567890"))
    
    def test_descending_sequences(self):
        """Test séquences décroissantes"""
        self.assertTrue(self.detector.detect("987654321"))
        self.assertTrue(self.detector.detect("54321"))
        self.assertTrue(self.detector.detect("9876543210"))
    
    def test_repeated_numbers(self):
        """Test chiffres répétés"""
        self.assertTrue(self.detector.detect("1111"))
        self.assertTrue(self.detector.detect("777777"))
        self.assertTrue(self.detector.detect("000000"))
    
    def test_mixed_sequences(self):
        """Test séquences mixtes"""
        self.assertTrue(self.detector.detect("abc123def"))
        self.assertTrue(self.detector.detect("test1234"))
        self.assertFalse(self.detector.detect("abc135def"))
    
    def test_minimum_length(self):
        """Test longueur minimale"""
        self.assertFalse(self.detector.detect("12"))  # Trop court
        self.assertTrue(self.detector.detect("123"))  # Assez long


class TestPasswordAnalyzer(unittest.TestCase):
    """Tests pour l'analyseur de mots de passe principal"""
    
    def setUp(self):
        """Configuration initiale"""
        self.analyzer = PasswordAnalyzer()
    
    def test_entropy_calculation(self):
        """Test calcul d'entropie"""
        # Mots de passe simples
        stats1 = self.analyzer.analyze("password")
        self.assertLess(stats1.entropy, 20)
        
        # Mots de passe complexes
        stats2 = self.analyzer.analyze("Tr0ub4dor&3")
        self.assertGreater(stats2.entropy, 40)
        
        # Mots de passe très complexes
        stats3 = self.analyzer.analyze("X8$mN#9qL@4wZ!")
        self.assertGreater(stats3.entropy, 60)
    
    def test_strength_scoring(self):
        """Test scoring de force"""
        # Très faible
        stats1 = self.analyzer.analyze("123")
        self.assertEqual(stats1.strength, "very_weak")
        
        # Faible
        stats2 = self.analyzer.analyze("password")
        self.assertEqual(stats2.strength, "weak")
        
        # Moyen
        stats3 = self.analyzer.analyze("Password123")
        self.assertEqual(stats3.strength, "medium")
        
        # Fort
        stats4 = self.analyzer.analyze("MyStr0ng_P@ssw0rd!")
        self.assertIn(stats4.strength, ["strong", "very_strong"])
    
    def test_pattern_detection(self):
        """Test détection de patterns"""
        # Pattern clavier
        stats1 = self.analyzer.analyze("qwerty123")
        self.assertIn("keyboard", stats1.patterns)
        
        # Pattern date
        stats2 = self.analyzer.analyze("password2023")
        self.assertIn("date", stats2.patterns)
        
        # Pattern substitution
        stats3 = self.analyzer.analyze("p@ssw0rd")
        self.assertIn("substitution", stats3.patterns)
    
    def test_character_analysis(self):
        """Test analyse des caractères"""
        stats = self.analyzer.analyze("MyP@ssw0rd123!")
        
        self.assertTrue(stats.has_lowercase)
        self.assertTrue(stats.has_uppercase)
        self.assertTrue(stats.has_digits)
        self.assertTrue(stats.has_symbols)
        self.assertGreater(stats.unique_chars, 10)
    
    def test_dataset_analysis(self):
        """Test analyse de dataset"""
        passwords = [
            "password", "123456", "admin", "password",  # Duplicata
            "MyStr0ng_P@ss!", "Tr0ub4dor&3", "qwerty123",
            "password2023", "p@ssw0rd", "Welcome123"
        ]
        
        analysis = self.analyzer.analyze_dataset(passwords)
        
        # Vérifications de base
        self.assertEqual(analysis.total_passwords, len(passwords))
        self.assertLess(analysis.unique_passwords, analysis.total_passwords)
        self.assertGreater(analysis.duplicate_rate, 0)
        
        # Distribution des forces
        self.assertIn("weak", analysis.strength_distribution)
        self.assertIn("medium", analysis.strength_distribution)
        
        # Patterns populaires
        self.assertGreater(len(analysis.top_patterns), 0)
        
        # Recommandations
        self.assertGreater(len(analysis.recommendations), 0)
    
    def test_empty_password(self):
        """Test mot de passe vide"""
        stats = self.analyzer.analyze("")
        self.assertEqual(stats.length, 0)
        self.assertEqual(stats.strength, "very_weak")
        self.assertEqual(stats.entropy, 0)
    
    def test_very_long_password(self):
        """Test mot de passe très long"""
        long_password = "A" * 1000
        stats = self.analyzer.analyze(long_password)
        self.assertEqual(stats.length, 1000)
        self.assertLess(stats.entropy, 20)  # Répétition
    
    def test_unicode_password(self):
        """Test mot de passe Unicode"""
        unicode_password = "пароль123"
        stats = self.analyzer.analyze(unicode_password)
        self.assertEqual(stats.length, len(unicode_password))
        self.assertGreater(stats.entropy, 0)


class TestDatasetAnalysis(unittest.TestCase):
    """Tests pour l'analyse de datasets"""
    
    def setUp(self):
        """Configuration initiale"""
        self.analyzer = PasswordAnalyzer()
    
    def test_duplicate_detection(self):
        """Test détection de doublons"""
        passwords = ["password", "admin", "password", "user", "admin", "test"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.assertEqual(analysis.total_passwords, 6)
        self.assertEqual(analysis.unique_passwords, 4)
        self.assertAlmostEqual(analysis.duplicate_rate, 2/6, places=2)
    
    def test_length_distribution(self):
        """Test distribution des longueurs"""
        passwords = ["abc", "abcd", "abcde", "abcd", "abc"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.assertEqual(analysis.length_distribution[3], 2)
        self.assertEqual(analysis.length_distribution[4], 2)
        self.assertEqual(analysis.length_distribution[5], 1)
    
    def test_top_passwords(self):
        """Test mots de passe populaires"""
        passwords = ["password"] * 5 + ["admin"] * 3 + ["user"] * 2 + ["test"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.assertEqual(analysis.top_passwords[0], ("password", 5))
        self.assertEqual(analysis.top_passwords[1], ("admin", 3))
        self.assertEqual(analysis.top_passwords[2], ("user", 2))
    
    def test_recommendations_generation(self):
        """Test génération de recommandations"""
        weak_passwords = ["password", "123456", "admin", "qwerty"] * 10
        analysis = self.analyzer.analyze_dataset(weak_passwords)
        
        # Doit contenir des recommandations sur la force
        recommendations_text = " ".join(analysis.recommendations)
        self.assertIn("fort", recommendations_text.lower())
        
        # Doit contenir des recommandations sur la duplication
        self.assertGreater(analysis.duplicate_rate, 0.5)


class TestPasswordAnalyzerExport(unittest.TestCase):
    """Tests pour l'export de l'analyseur"""
    
    def setUp(self):
        """Configuration initiale"""
        self.analyzer = PasswordAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Nettoyage"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_json_export(self):
        """Test export JSON"""
        passwords = ["password", "admin", "123456"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.analyzer.export_analysis(analysis, output_dir=self.temp_dir)
        
        # Vérification fichier JSON
        json_file = Path(self.temp_dir) / "password_analysis.json"
        self.assertTrue(json_file.exists())
        
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertEqual(data['total_passwords'], 3)
            self.assertIn('strength_distribution', data)
    
    def test_csv_export(self):
        """Test export CSV"""
        passwords = ["password", "admin", "123456"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.analyzer.export_analysis(analysis, output_dir=self.temp_dir)
        
        # Vérification fichier CSV
        csv_file = Path(self.temp_dir) / "password_analysis.csv"
        self.assertTrue(csv_file.exists())
        
        # Lecture basique du CSV
        with open(csv_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('password', content)
            self.assertIn('strength', content)
    
    @patch('matplotlib.pyplot.savefig')
    @patch('matplotlib.pyplot.show')
    def test_plot_generation(self, mock_show, mock_savefig):
        """Test génération de graphiques"""
        passwords = ["password", "admin", "123456", "Password123", "Str0ng_P@ss"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.analyzer.export_analysis(analysis, output_dir=self.temp_dir)
        
        # Vérification que les plots ont été appelés
        self.assertTrue(mock_savefig.called)
    
    def test_html_report_generation(self):
        """Test génération du rapport HTML"""
        passwords = ["password", "admin", "123456"]
        analysis = self.analyzer.analyze_dataset(passwords)
        
        self.analyzer.export_analysis(analysis, output_dir=self.temp_dir)
        
        # Vérification fichier HTML
        html_file = Path(self.temp_dir) / "password_analysis_report.html"
        self.assertTrue(html_file.exists())
        
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('<html>', content)
            self.assertIn('Analyse de Sécurité', content)
            self.assertIn('password', content)


class TestPasswordAnalyzerEdgeCases(unittest.TestCase):
    """Tests pour les cas limites"""
    
    def setUp(self):
        """Configuration initiale"""
        self.analyzer = PasswordAnalyzer()
    
    def test_special_characters(self):
        """Test caractères spéciaux"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        stats = self.analyzer.analyze(special_chars)
        
        self.assertTrue(stats.has_symbols)
        self.assertFalse(stats.has_lowercase)
        self.assertFalse(stats.has_uppercase)
        self.assertFalse(stats.has_digits)
    
    def test_numeric_only_password(self):
        """Test mot de passe numérique uniquement"""
        stats = self.analyzer.analyze("1234567890")
        
        self.assertTrue(stats.has_digits)
        self.assertFalse(stats.has_lowercase)
        self.assertFalse(stats.has_uppercase)
        self.assertFalse(stats.has_symbols)
        self.assertIn("sequence", stats.patterns)
    
    def test_whitespace_handling(self):
        """Test gestion des espaces"""
        stats = self.analyzer.analyze("my password 123")
        
        self.assertEqual(stats.length, 15)
        self.assertTrue(stats.has_lowercase)
        self.assertTrue(stats.has_digits)
    
    def test_empty_dataset(self):
        """Test dataset vide"""
        analysis = self.analyzer.analyze_dataset([])
        
        self.assertEqual(analysis.total_passwords, 0)
        self.assertEqual(analysis.unique_passwords, 0)
        self.assertEqual(analysis.duplicate_rate, 0)
    
    def test_single_password_dataset(self):
        """Test dataset avec un seul mot de passe"""
        analysis = self.analyzer.analyze_dataset(["password"])
        
        self.assertEqual(analysis.total_passwords, 1)
        self.assertEqual(analysis.unique_passwords, 1)
        self.assertEqual(analysis.duplicate_rate, 0)
    
    def test_all_identical_passwords(self):
        """Test dataset avec mots de passe identiques"""
        analysis = self.analyzer.analyze_dataset(["password"] * 5)
        
        self.assertEqual(analysis.total_passwords, 5)
        self.assertEqual(analysis.unique_passwords, 1)
        self.assertEqual(analysis.duplicate_rate, 0.8)  # 4/5 = 0.8


class TestPasswordAnalyzerPerformance(unittest.TestCase):
    """Tests de performance"""
    
    def setUp(self):
        """Configuration initiale"""
        self.analyzer = PasswordAnalyzer()
    
    def test_large_dataset_performance(self):
        """Test performance sur large dataset"""
        import time
        
        # Génération d'un large dataset
        passwords = [f"password{i}" for i in range(1000)]
        
        start_time = time.time()
        analysis = self.analyzer.analyze_dataset(passwords)
        end_time = time.time()
        
        # Vérifications
        self.assertEqual(analysis.total_passwords, 1000)
        self.assertLess(end_time - start_time, 10)  # Moins de 10 secondes
    
    def test_very_long_password_performance(self):
        """Test performance sur mot de passe très long"""
        import time
        
        long_password = "A" * 10000
        
        start_time = time.time()
        stats = self.analyzer.analyze(long_password)
        end_time = time.time()
        
        # Vérifications
        self.assertEqual(stats.length, 10000)
        self.assertLess(end_time - start_time, 1)  # Moins d'1 seconde
    
    def test_complex_password_performance(self):
        """Test performance sur mot de passe complexe"""
        import time
        
        complex_password = "Tr0ub4dor&3" * 100  # Pattern répété
        
        start_time = time.time()
        stats = self.analyzer.analyze(complex_password)
        end_time = time.time()
        
        # Vérifications
        self.assertGreater(stats.entropy, 0)
        self.assertLess(end_time - start_time, 1)  # Moins d'1 seconde


def run_tests():
    """Lance tous les tests"""
    # Création de la suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajout des classes de tests
    test_classes = [
        TestKeyboardPatternDetector,
        TestCommonSubstitutionDetector,
        TestDatePatternDetector,
        TestDictionaryWordDetector,
        TestNumberSequenceDetector,
        TestPasswordAnalyzer,
        TestDatasetAnalysis,
        TestPasswordAnalyzerExport,
        TestPasswordAnalyzerEdgeCases,
        TestPasswordAnalyzerPerformance
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Exécution des tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé
    print(f"\n{'='*80}")
    print(f"📊 RÉSUMÉ DES TESTS")
    print(f"{'='*80}")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.failures:
        print(f"\n⚠️ ÉCHECS:")
        for test, trace in result.failures:
            print(f"  - {test}: {trace.splitlines()[-1]}")
    
    if result.errors:
        print(f"\n❌ ERREURS:")
        for test, trace in result.errors:
            print(f"  - {test}: {trace.splitlines()[-1]}")
    
    success_rate = (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100
    print(f"\n✅ Taux de succès: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("🧪 TESTS UNITAIRES - PASSWORD ANALYZER")
    print("=" * 80)
    
    success = run_tests()
    
    if success:
        print(f"\n🎉 Tous les tests ont réussi!")
        sys.exit(0)
    else:
        print(f"\n💥 Certains tests ont échoué!")
        sys.exit(1)