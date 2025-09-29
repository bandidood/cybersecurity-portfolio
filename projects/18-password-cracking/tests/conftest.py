#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Configuration Pytest Globale - Password Cracking Platform
============================================================================
Configuration centralisée pour tous les tests incluant :
- Fixtures communes réutilisables
- Configuration des markers de test
- Setup/teardown globaux
- Utilitaires de test partagés
- Configuration des plugins pytest

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import pytest
import tempfile
import shutil
import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from unittest.mock import MagicMock, patch

# Ajout du chemin src pour les imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

# Configuration logging pour tests
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# =============================================================================
# CONFIGURATION PYTEST
# =============================================================================

def pytest_configure(config):
    """Configuration globale pytest"""
    # Enregistrement des markers personnalisés
    config.addinivalue_line(
        "markers",
        "slow: marque les tests lents (peuvent prendre plusieurs secondes)"
    )
    config.addinivalue_line(
        "markers", 
        "integration: marque les tests d'intégration"
    )
    config.addinivalue_line(
        "markers",
        "security: marque les tests de sécurité" 
    )
    config.addinivalue_line(
        "markers",
        "performance: marque les tests de performance"
    )
    config.addinivalue_line(
        "markers",
        "stress: marque les tests de stress/charge"
    )
    config.addinivalue_line(
        "markers",
        "benchmark: marque les tests de benchmark"
    )

def pytest_collection_modifyitems(config, items):
    """Modification de la collection de tests"""
    # Ajout automatique du marker 'slow' pour tests longs
    for item in items:
        # Tests avec 'stress' ou 'benchmark' sont automatiquement 'slow'
        if any(mark in item.keywords for mark in ['stress', 'benchmark']):
            item.add_marker(pytest.mark.slow)

# =============================================================================
# FIXTURES DE BASE
# =============================================================================

@pytest.fixture
def temp_dir():
    """Répertoire temporaire nettoyé après usage"""
    temp_path = tempfile.mkdtemp(prefix='password_cracking_test_')
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def temp_file():
    """Fichier temporaire nettoyé après usage"""
    fd, temp_path = tempfile.mkstemp(prefix='password_cracking_test_', suffix='.txt')
    os.close(fd)
    yield Path(temp_path)
    try:
        os.unlink(temp_path)
    except (OSError, FileNotFoundError):
        pass

@pytest.fixture(scope="session")
def project_root_path():
    """Chemin racine du projet"""
    return project_root

@pytest.fixture
def clean_environment():
    """Environnement propre pour tests isolés"""
    # Sauvegarde variables d'environnement
    original_env = os.environ.copy()
    
    # Nettoyage variables de test potentielles
    test_vars = [
        'PASSWORD_CRACKING_CONFIG_PATH',
        'PASSWORD_CRACKING_OUTPUT_DIR', 
        'PASSWORD_CRACKING_WORDLIST_DIR'
    ]
    
    for var in test_vars:
        os.environ.pop(var, None)
    
    yield
    
    # Restauration environnement
    os.environ.clear()
    os.environ.update(original_env)

# =============================================================================
# FIXTURES DONNÉES DE TEST
# =============================================================================

@pytest.fixture
def sample_passwords() -> List[str]:
    """Dataset standard de mots de passe pour tests"""
    return [
        # Très faibles (score 0-20)
        "123456", "password", "admin", "qwerty", "letmein",
        "123", "abc", "test", "user", "guest",
        
        # Faibles avec patterns (score 20-40) 
        "password123", "admin2023", "qwerty456", "abc123",
        "password1", "admin123", "test123", "user2023",
        
        # Moyens (score 40-60)
        "Password1", "MyPass123", "Welcome2023", "Secret1!",
        "Admin@123", "User_2023", "Test$123", "Pass_word1",
        
        # Forts (score 60-80)
        "MyStr0ng_P@ssw0rd!", "Tr0ub4dor&3", "C0mpl3x_P@55",
        "Secur3_P@ssw0rd!", "MyC0mpl3x_123!", "Str0ng_Secur1ty!",
        
        # Très forts (score 80+)
        "X8$mN#9qL@4wZ!", "Zt7&mK9#nL2@wQ!", "P@55w0rd_V3ry_5tr0ng!",
        "My_V3ry_C0mpl3x_P@ssw0rd_2024!", "Ultr@_Secur3_P@55w0rd#123"
    ]

@pytest.fixture
def weak_passwords() -> List[str]:
    """Dataset de mots de passe faibles pour tests spécifiques"""
    return [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "qwerty", "abc123", "123123", "000000",
        "1234", "admin", "letmein", "welcome", "login",
        "master", "hello", "guest", "user", "test"
    ]

@pytest.fixture
def strong_passwords() -> List[str]:
    """Dataset de mots de passe forts pour tests spécifiques"""
    return [
        "MyStr0ng_P@ssw0rd_2024!",
        "Tr0ub4dor&3_V3ry_Secur3",
        "C0mpl3x_P@55w0rd_W1th_Numbers!",
        "X8$mN#9qL@4wZ!kP2&vR7",
        "Ultr@_Secur3_P@ssw0rd_123#",
        "My_V3ry_L0ng_@nd_C0mpl3x_P@ssw0rd_2024!",
        "Str0ng3st_P@ssw0rd_3v3r_Cr3@t3d!",
        "1nCr3d1bly_C0mpl3x_P@55w0rd_W1th_5ymb0l5!",
        "Th15_15_@_V3ry_L0ng_@nd_Secur3_P@ssw0rd_123!",
        "My_P@55w0rd_H@s_M@ny_Ch@r@ct3r5_@nd_1s_V3ry_Secur3!"
    ]

@pytest.fixture
def enterprise_passwords() -> List[str]:
    """Dataset typique d'environnement d'entreprise"""
    return [
        # Mots de passe d'employés typiques
        "company2023", "office123", "work_password", "business1",
        "enterprise123", "corporate2023", "team_password", "dept123",
        
        # Variations avec noms d'entreprise
        "acme123", "acme2023", "ACMEcorp", "acme_secure",
        "microsoft123", "google2023", "apple_pass", "amazon123",
        
        # Mots de passe IT/Admin 
        "admin_server", "root_password", "db_admin123", "sys_admin",
        "network_pass", "server_2023", "backup_pwd", "security123",
        
        # Patterns géographiques
        "paris_office", "london123", "newyork_2023", "tokyo_branch",
        "california1", "texas_office", "berlin_team", "sydney123",
        
        # Mots de passe techniques
        "database123", "api_key_pwd", "ssh_password", "vpn_access",
        "firewall_pass", "router123", "switch_pwd", "monitor123"
    ]

@pytest.fixture
def pattern_passwords() -> Dict[str, List[str]]:
    """Mots de passe organisés par type de pattern"""
    return {
        'keyboard': [
            "qwerty", "qwerty123", "QWERTY", "qWeRtY",
            "azerty", "AZERTY", "azerty123", 
            "123456", "1234567890", "0987654321",
            "asdf", "asdfgh", "zxcvbn", "qwertyuiop"
        ],
        'substitution': [
            "p@ssw0rd", "h3ll0", "l3tm31n", "@dm1n", 
            "u$3r", "h4ck3r", "3l1t3", "1337",
            "t3st", "w0rk", "0ff1c3", "c0mp@ny"
        ],
        'date': [
            "2023", "2024", "1990", "1995", "2000",
            "01/01/2023", "12-25-2023", "2023-01-01",
            "0101", "1225", "0314", "0704"
        ],
        'dictionary': [
            "password", "admin", "user", "test", "welcome",
            "hello", "world", "computer", "internet", "security",
            "login", "access", "system", "network", "database"
        ],
        'sequence': [
            "123456", "987654321", "abcdef", "ABCDEF",
            "111111", "222222", "aaaaaa", "ZZZZZZ",
            "123abc", "abc123", "test123", "user456"
        ]
    }

# =============================================================================
# FIXTURES MOCKS ET SIMULATIONS
# =============================================================================

@pytest.fixture
def mock_hashcat_output():
    """Simulation sortie Hashcat pour tests"""
    return {
        'session_name': 'test_session',
        'hash_type': '0',  # MD5
        'attack_mode': '0',  # Dictionary
        'total_hashes': 100,
        'cracked_hashes': 75,
        'success_rate': 0.75,
        'runtime_seconds': 300,
        'hash_rate': '1234.5 MH/s',
        'gpu_utilization': 85.2,
        'cracked_passwords': [
            'password', 'admin', '123456', 'qwerty', 'letmein'
        ],
        'status': 'Exhausted',
        'progress': 100.0
    }

@pytest.fixture
def mock_john_output():
    """Simulation sortie John the Ripper pour tests"""
    return {
        'format': 'Raw-MD5',
        'total_hashes': 50,
        'cracked_hashes': 30,
        'success_rate': 0.60,
        'runtime_seconds': 180,
        'cracked_passwords': [
            'test', 'user', 'welcome', 'hello'
        ],
        'rules_used': ['Single', 'Wordlist', 'Incremental'],
        'session_file': 'john_test.rec'
    }

@pytest.fixture
def mock_target_profile():
    """Profil cible simulé pour tests wordlist"""
    try:
        from src.wordlist_generator.wordlist_builder import TargetProfile
        return TargetProfile(
            first_names=['john', 'jane', 'mike', 'sarah', 'david', 'lisa'],
            last_names=['smith', 'doe', 'wilson', 'brown', 'davis', 'taylor'],
            company_names=['acme', 'test', 'example', 'demo', 'sample'],
            job_titles=['manager', 'developer', 'analyst', 'engineer', 'admin'],
            departments=['it', 'hr', 'finance', 'sales', 'marketing'],
            birthdates=['1985', '1990', '1995', '2000', '2005'],
            locations=['paris', 'london', 'newyork', 'tokyo', 'berlin'],
            interests=['tech', 'sports', 'music', 'travel', 'reading'],
            phone_numbers=['555-0123', '555-0456', '555-0789'],
            additional_info=['secure', 'access', 'login', 'account']
        )
    except ImportError:
        # Fallback si module pas disponible
        return {
            'first_names': ['john', 'jane', 'mike'],
            'last_names': ['smith', 'doe', 'wilson'],
            'company_names': ['acme', 'test', 'example'],
            'birthdates': ['1990', '1995', '2000']
        }

@pytest.fixture
def mock_osint_data():
    """Données OSINT simulées pour tests"""
    return {
        'domains': ['example.com', 'test.org', 'demo.net'],
        'keywords': [
            'company', 'business', 'enterprise', 'corporate',
            'team', 'office', 'work', 'professional',
            'secure', 'access', 'login', 'account',
            'technology', 'innovation', 'solution', 'service'
        ],
        'technologies': [
            'python', 'javascript', 'docker', 'kubernetes',
            'aws', 'azure', 'database', 'api',
            'security', 'encryption', 'firewall', 'vpn'
        ],
        'employees': [
            {'name': 'John Smith', 'role': 'Manager'},
            {'name': 'Jane Doe', 'role': 'Developer'},
            {'name': 'Mike Wilson', 'role': 'Analyst'}
        ],
        'metadata': {
            'industry': 'Technology',
            'size': '50-100 employees',
            'location': 'San Francisco, CA',
            'founded': '2010'
        }
    }

# =============================================================================
# FIXTURES UTILITAIRES DE TEST
# =============================================================================

@pytest.fixture
def test_config():
    """Configuration de test standardisée"""
    return {
        'analysis': {
            'min_entropy_threshold': 25,
            'pattern_detection': True,
            'generate_plots': False,  # Désactivé pour tests
            'export_formats': ['json']
        },
        'wordlist_generation': {
            'max_mutations': 100,  # Réduit pour tests
            'enable_leetspeak': True,
            'enable_case_variations': True,
            'min_word_length': 3,
            'max_word_length': 20
        },
        'performance': {
            'max_dataset_size': 1000,  # Limité pour tests
            'timeout_seconds': 30,
            'memory_limit_mb': 100
        },
        'security': {
            'enable_input_validation': True,
            'sanitize_outputs': True,
            'log_security_events': False  # Désactivé pour tests
        }
    }

@pytest.fixture
def password_file(temp_dir):
    """Fichier temporaire avec mots de passe pour tests"""
    def _create_password_file(passwords: List[str], filename: str = "passwords.txt"):
        file_path = temp_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            for password in passwords:
                f.write(f"{password}\n")
        return file_path
    return _create_password_file

@pytest.fixture
def hash_file(temp_dir):
    """Fichier temporaire avec hashs pour tests"""
    def _create_hash_file(passwords: List[str], hash_type: str = "md5", filename: str = "hashes.txt"):
        import hashlib
        
        file_path = temp_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            for password in passwords:
                if hash_type.lower() == "md5":
                    hash_value = hashlib.md5(password.encode()).hexdigest()
                elif hash_type.lower() == "sha256":
                    hash_value = hashlib.sha256(password.encode()).hexdigest()
                elif hash_type.lower() == "sha1":
                    hash_value = hashlib.sha1(password.encode()).hexdigest()
                else:
                    raise ValueError(f"Type de hash non supporté: {hash_type}")
                
                f.write(f"{hash_value}\n")
        
        return file_path, passwords
    return _create_hash_file

@pytest.fixture
def wordlist_file(temp_dir):
    """Fichier temporaire wordlist pour tests"""
    def _create_wordlist_file(words: List[str], filename: str = "wordlist.txt"):
        file_path = temp_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            for word in words:
                f.write(f"{word}\n")
        return file_path
    return _create_wordlist_file

# =============================================================================
# FIXTURES INTEGRATION ET PERFORMANCE
# =============================================================================

@pytest.fixture
def performance_monitor():
    """Moniteur de performance pour tests"""
    import psutil
    import time
    
    class PerformanceMonitor:
        def __init__(self):
            self.process = psutil.Process()
            self.start_time = None
            self.start_memory = None
            
        def start(self):
            """Démarre le monitoring"""
            self.start_time = time.time()
            self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            
        def stop(self):
            """Arrête le monitoring et retourne les métriques"""
            if self.start_time is None:
                raise RuntimeError("Monitor non démarré")
                
            end_time = time.time()
            end_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            
            return {
                'execution_time': end_time - self.start_time,
                'memory_usage': end_memory - self.start_memory,
                'peak_memory': self.process.memory_info().rss / 1024 / 1024
            }
    
    return PerformanceMonitor()

@pytest.fixture
def benchmark_runner():
    """Runner pour benchmarks personnalisés"""
    import time
    import statistics
    
    def _run_benchmark(func, *args, iterations: int = 5, **kwargs):
        """Exécute un benchmark avec statistiques"""
        times = []
        results = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            times.append(end_time - start_time)
            results.append(result)
        
        return {
            'mean_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_deviation': statistics.stdev(times) if len(times) > 1 else 0,
            'iterations': iterations,
            'results': results,
            'raw_times': times
        }
    
    return _run_benchmark

# =============================================================================
# FIXTURES SPÉCIFIQUES AUX MODULES
# =============================================================================

@pytest.fixture
def mock_password_analyzer():
    """Mock de l'analyseur de mots de passe"""
    with patch('src.analysis.password_analyzer.PasswordAnalyzer') as mock:
        # Configuration du mock
        mock_instance = MagicMock()
        mock.return_value = mock_instance
        
        # Configuration méthodes mock
        mock_instance.analyze.return_value = MagicMock(
            length=8,
            entropy=45.2,
            strength='medium',
            patterns=['dictionary'],
            has_lowercase=True,
            has_uppercase=True,
            has_digits=True,
            has_symbols=False,
            unique_chars=6
        )
        
        yield mock_instance

@pytest.fixture 
def mock_wordlist_builder():
    """Mock du constructeur de wordlists"""
    with patch('src.wordlist_generator.wordlist_builder.WordlistBuilder') as mock:
        mock_instance = MagicMock()
        mock.return_value = mock_instance
        
        # Configuration méthodes mock
        mock_instance.build_from_profile.return_value = [
            'john', 'jane', 'smith', 'doe', 'acme', 
            'john123', 'jane456', 'acme2023'
        ]
        
        mock_instance.export_wordlist.return_value = '/tmp/test_wordlist.txt'
        
        yield mock_instance

# =============================================================================
# HOOKS ET UTILITAIRES PYTEST
# =============================================================================

@pytest.fixture(autouse=True)
def reset_logging():
    """Reset configuration logging entre tests"""
    yield
    # Nettoyage handlers
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

def pytest_runtest_setup(item):
    """Setup avant chaque test"""
    # Configuration spéciale pour tests lents
    if 'slow' in item.keywords:
        # Timeout plus élevé pour tests lents
        if hasattr(item, 'timeout'):
            item.timeout = 120  # 2 minutes

def pytest_runtest_teardown(item, nextitem):
    """Teardown après chaque test"""
    # Nettoyage supplémentaire si nécessaire
    pass

# =============================================================================
# UTILITAIRES DE TEST PERSONNALISÉS
# =============================================================================

class TestHelpers:
    """Classe utilitaire avec méthodes d'aide pour tests"""
    
    @staticmethod
    def assert_password_strength(password: str, expected_strength: str):
        """Assertion personnalisée pour force mots de passe"""
        try:
            from src.analysis.password_analyzer import PasswordAnalyzer
            analyzer = PasswordAnalyzer()
            result = analyzer.analyze(password)
            assert result.strength == expected_strength, \
                f"Force attendue '{expected_strength}', obtenue '{result.strength}' pour '{password}'"
        except ImportError:
            pytest.skip("Module password_analyzer non disponible")
    
    @staticmethod
    def assert_pattern_detected(password: str, expected_pattern: str):
        """Assertion personnalisée pour détection patterns"""
        try:
            from src.analysis.password_analyzer import PasswordAnalyzer
            analyzer = PasswordAnalyzer()
            result = analyzer.analyze(password)
            assert expected_pattern in result.patterns, \
                f"Pattern '{expected_pattern}' non détecté dans '{password}'. Patterns: {result.patterns}"
        except ImportError:
            pytest.skip("Module password_analyzer non disponible")
    
    @staticmethod
    def create_test_dataset(size: int, pattern: str = 'random') -> List[str]:
        """Génère un dataset de test de taille spécifiée"""
        if pattern == 'random':
            import random
            import string
            return [
                ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 12)))
                for _ in range(size)
            ]
        elif pattern == 'weak':
            base_passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']
            return [f"{pwd}{i}" for i, pwd in enumerate(base_passwords * (size // len(base_passwords) + 1))][:size]
        elif pattern == 'strong':
            base_passwords = ['MyStr0ng_P@ss!', 'C0mpl3x_Secur1ty!', 'Ultr@_S@f3_P@ssw0rd!']
            return [f"{pwd}{i}" for i, pwd in enumerate(base_passwords * (size // len(base_passwords) + 1))][:size]
        else:
            raise ValueError(f"Pattern non supporté: {pattern}")

@pytest.fixture
def test_helpers():
    """Fixture pour accéder aux utilitaires de test"""
    return TestHelpers()