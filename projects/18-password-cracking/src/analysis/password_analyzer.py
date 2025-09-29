#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Password Analyzer - Advanced Pattern Detection & Statistical Analysis
============================================================================
Analyseur avancé de mots de passe avec détection de patterns,
analyse statistique et génération de recommandations de sécurité.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import re
import string
import math
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from pathlib import Path


@dataclass
class PasswordStats:
    """Statistiques d'un mot de passe"""
    password: str
    length: int
    character_sets: Dict[str, bool]
    entropy: float
    strength_score: int
    patterns: List[str]
    common_substitutions: List[str]
    keyboard_patterns: List[str]
    dictionary_words: List[str]
    dates_found: List[str]
    numbers_found: List[str]
    
    
@dataclass
class DatasetAnalysis:
    """Analyse complète d'un dataset de mots de passe"""
    total_passwords: int
    unique_passwords: int
    duplicate_rate: float
    length_distribution: Dict[int, int]
    character_set_distribution: Dict[str, int]
    entropy_distribution: Dict[str, int]
    strength_distribution: Dict[str, int]
    pattern_frequency: Dict[str, int]
    top_patterns: List[Tuple[str, int]]
    top_passwords: List[Tuple[str, int]]
    top_base_words: List[Tuple[str, int]]
    recommendations: List[str]
    

class PatternDetector:
    """Détecteur de patterns dans les mots de passe"""
    
    def __init__(self):
        """Initialisation du détecteur"""
        self.keyboard_patterns = {
            'qwerty_row1': 'qwertyuiop',
            'qwerty_row2': 'asdfghjkl', 
            'qwerty_row3': 'zxcvbnm',
            'azerty_row1': 'azertyuiop',
            'azerty_row2': 'qsdfghjklm',
            'azerty_row3': 'wxcvbn',
            'numbers': '1234567890',
            'symbols': '!@#$%^&*()_+-='
        }
        
        self.common_substitutions = {
            '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o',
            '$': 's', '5': 's', '7': 't', '+': 't', '4': 'a',
            '6': 'g', '8': 'b', '9': 'g', '2': 'z'
        }
        
        self.date_patterns = [
            r'\d{4}',  # Années (1900-2099)
            r'\d{2}/\d{2}',  # MM/DD ou DD/MM
            r'\d{2}-\d{2}',  # MM-DD ou DD-MM
            r'\d{6}',  # DDMMYY ou YYMMDD
            r'\d{8}',  # DDMMYYYY ou YYYYMMDD
        ]
        
        # Dictionnaire de mots communs
        self.common_words = self._load_common_words()
        
    def _load_common_words(self) -> set:
        """Charge un dictionnaire de mots communs"""
        # Mots communs basiques (à enrichir avec un vrai dictionnaire)
        common_words = {
            'password', 'admin', 'user', 'login', 'welcome', 'hello',
            'love', 'sex', 'god', 'secret', 'dragon', 'ninja', 'shadow',
            'master', 'killer', 'death', 'blood', 'power', 'money',
            'football', 'basketball', 'baseball', 'soccer', 'tennis',
            'music', 'rock', 'jazz', 'blues', 'metal', 'punk',
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
            'spring', 'summer', 'autumn', 'winter', 'fall',
            'red', 'blue', 'green', 'yellow', 'black', 'white', 'purple',
            'cat', 'dog', 'bird', 'fish', 'lion', 'tiger', 'bear', 'wolf',
            'house', 'home', 'family', 'mother', 'father', 'sister', 'brother',
            'work', 'school', 'computer', 'internet', 'phone', 'mobile'
        }
        return common_words
    
    def detect_keyboard_patterns(self, password: str) -> List[str]:
        """Détecte les patterns clavier"""
        patterns = []
        password_lower = password.lower()
        
        for pattern_name, pattern_str in self.keyboard_patterns.items():
            # Recherche de séquences de 3+ caractères consécutifs
            for i in range(len(pattern_str) - 2):
                for length in range(3, min(len(pattern_str) - i + 1, len(password) + 1)):
                    sequence = pattern_str[i:i + length]
                    if sequence in password_lower:
                        patterns.append(f"{pattern_name}:{sequence}")
                    
                    # Séquence inversée
                    sequence_rev = sequence[::-1]
                    if sequence_rev in password_lower:
                        patterns.append(f"{pattern_name}_reverse:{sequence_rev}")
        
        return list(set(patterns))
    
    def detect_substitutions(self, password: str) -> List[str]:
        """Détecte les substitutions communes"""
        substitutions = []
        
        for char in password:
            if char in self.common_substitutions:
                original = self.common_substitutions[char]
                substitutions.append(f"{char}→{original}")
        
        return substitutions
    
    def detect_dates(self, password: str) -> List[str]:
        """Détecte les patterns de dates"""
        dates = []
        
        for pattern in self.date_patterns:
            matches = re.findall(pattern, password)
            for match in matches:
                # Validation basique des dates
                if self._is_valid_date_pattern(match):
                    dates.append(match)
        
        return dates
    
    def _is_valid_date_pattern(self, date_str: str) -> bool:
        """Valide si un pattern ressemble à une date"""
        if len(date_str) == 4:  # Année
            year = int(date_str)
            return 1900 <= year <= 2030
        elif len(date_str) == 6:  # DDMMYY ou YYMMDD
            # Simplification - juste vérifier que c'est numérique
            return date_str.isdigit()
        elif len(date_str) == 8:  # DDMMYYYY ou YYYYMMDD
            return date_str.isdigit()
        return False
    
    def detect_dictionary_words(self, password: str) -> List[str]:
        """Détecte les mots du dictionnaire"""
        words = []
        password_lower = password.lower()
        
        # Suppression des chiffres et symboles pour l'analyse
        clean_password = ''.join([c for c in password_lower if c.isalpha()])
        
        for word in self.common_words:
            if len(word) >= 3 and word in clean_password:
                words.append(word)
        
        # Mots avec substitutions
        for word in self.common_words:
            word_with_subs = self._apply_reverse_substitutions(word)
            if len(word) >= 3 and word_with_subs in password_lower:
                words.append(f"{word}(substituted)")
        
        return list(set(words))
    
    def _apply_reverse_substitutions(self, word: str) -> str:
        """Applique les substitutions inverses à un mot"""
        result = word
        reverse_subs = {v: k for k, v in self.common_substitutions.items()}
        
        for original, sub in reverse_subs.items():
            result = result.replace(original, sub)
        
        return result
    
    def detect_numbers(self, password: str) -> List[str]:
        """Détecte les patterns numériques"""
        numbers = []
        
        # Séquences numériques
        number_matches = re.findall(r'\d+', password)
        for match in number_matches:
            if len(match) >= 2:
                numbers.append(match)
        
        # Séquences consécutives
        for i in range(len(password) - 2):
            if password[i:i+3].isdigit():
                seq = password[i:i+3]
                nums = [int(d) for d in seq]
                if (nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1) or \
                   (nums[1] == nums[0] - 1 and nums[2] == nums[1] - 1):
                    numbers.append(f"sequence:{seq}")
        
        return numbers


class PasswordAnalyzer:
    """Analyseur principal de mots de passe"""
    
    def __init__(self):
        """Initialisation de l'analyseur"""
        self.pattern_detector = PatternDetector()
        
    def calculate_entropy(self, password: str) -> float:
        """Calcule l'entropie d'un mot de passe"""
        if not password:
            return 0.0
        
        # Taille de l'alphabet
        alphabet_size = 0
        
        if any(c.islower() for c in password):
            alphabet_size += 26
        if any(c.isupper() for c in password):
            alphabet_size += 26
        if any(c.isdigit() for c in password):
            alphabet_size += 10
        if any(c in string.punctuation for c in password):
            alphabet_size += len(string.punctuation)
        
        # Entropie = longueur * log2(taille_alphabet)
        if alphabet_size == 0:
            return 0.0
        
        return len(password) * math.log2(alphabet_size)
    
    def get_character_sets(self, password: str) -> Dict[str, bool]:
        """Détermine les jeux de caractères utilisés"""
        return {
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digits': any(c.isdigit() for c in password),
            'symbols': any(c in string.punctuation for c in password),
            'spaces': ' ' in password
        }
    
    def calculate_strength_score(self, password: str) -> int:
        """Calcule un score de force (0-100)"""
        score = 0
        
        # Longueur (max 25 points)
        length_score = min(25, len(password) * 2)
        score += length_score
        
        # Diversité des caractères (max 25 points)
        char_sets = self.get_character_sets(password)
        diversity_score = sum(char_sets.values()) * 6
        score += min(25, diversity_score)
        
        # Entropie (max 25 points)
        entropy = self.calculate_entropy(password)
        entropy_score = min(25, entropy / 4)
        score += entropy_score
        
        # Pénalités pour patterns communs
        penalties = 0
        patterns = self.pattern_detector.detect_keyboard_patterns(password)
        penalties += len(patterns) * 5
        
        dict_words = self.pattern_detector.detect_dictionary_words(password)
        penalties += len(dict_words) * 10
        
        dates = self.pattern_detector.detect_dates(password)
        penalties += len(dates) * 8
        
        # Score final (max 25 points restants après pénalités)
        final_bonus = max(0, 25 - penalties)
        score += final_bonus
        
        return min(100, max(0, score))
    
    def analyze_password(self, password: str) -> PasswordStats:
        """Analyse complète d'un mot de passe"""
        return PasswordStats(
            password=password,
            length=len(password),
            character_sets=self.get_character_sets(password),
            entropy=self.calculate_entropy(password),
            strength_score=self.calculate_strength_score(password),
            patterns=self.pattern_detector.detect_keyboard_patterns(password),
            common_substitutions=self.pattern_detector.detect_substitutions(password),
            keyboard_patterns=self.pattern_detector.detect_keyboard_patterns(password),
            dictionary_words=self.pattern_detector.detect_dictionary_words(password),
            dates_found=self.pattern_detector.detect_dates(password),
            numbers_found=self.pattern_detector.detect_numbers(password)
        )
    
    def analyze_dataset(self, passwords: List[str]) -> DatasetAnalysis:
        """Analyse complète d'un dataset de mots de passe"""
        print(f"Analyzing {len(passwords)} passwords...")
        
        # Compteurs
        password_counter = Counter(passwords)
        length_counter = Counter()
        charset_counter = defaultdict(int)
        entropy_counter = defaultdict(int)
        strength_counter = defaultdict(int)
        pattern_counter = defaultdict(int)
        base_word_counter = Counter()
        
        # Analyse individuelle de chaque mot de passe
        for i, password in enumerate(passwords):
            if i % 1000 == 0:
                print(f"Progress: {i}/{len(passwords)}")
            
            stats = self.analyze_password(password)
            
            # Distributions
            length_counter[stats.length] += 1
            
            # Jeux de caractères
            charset_key = self._get_charset_key(stats.character_sets)
            charset_counter[charset_key] += 1
            
            # Entropie (par tranches)
            entropy_range = self._get_entropy_range(stats.entropy)
            entropy_counter[entropy_range] += 1
            
            # Force (par tranches)
            strength_range = self._get_strength_range(stats.strength_score)
            strength_counter[strength_range] += 1
            
            # Patterns
            for pattern in stats.patterns:
                pattern_counter[pattern] += 1
            
            # Mots de base (sans chiffres/symboles à la fin)
            base_word = self._extract_base_word(password)
            if base_word:
                base_word_counter[base_word] += 1
        
        # Calculs finaux
        total_passwords = len(passwords)
        unique_passwords = len(password_counter)
        duplicate_rate = 1.0 - (unique_passwords / total_passwords)
        
        # Top patterns et mots de passe
        top_patterns = pattern_counter.most_common(20)
        top_passwords = password_counter.most_common(50)
        top_base_words = base_word_counter.most_common(30)
        
        # Recommandations
        recommendations = self._generate_recommendations(
            total_passwords, duplicate_rate, 
            dict(length_counter), dict(charset_counter),
            dict(strength_counter), top_patterns
        )
        
        return DatasetAnalysis(
            total_passwords=total_passwords,
            unique_passwords=unique_passwords,
            duplicate_rate=duplicate_rate,
            length_distribution=dict(length_counter),
            character_set_distribution=dict(charset_counter),
            entropy_distribution=dict(entropy_counter),
            strength_distribution=dict(strength_counter),
            pattern_frequency=dict(pattern_counter),
            top_patterns=top_patterns,
            top_passwords=top_passwords,
            top_base_words=top_base_words,
            recommendations=recommendations
        )
    
    def _get_charset_key(self, char_sets: Dict[str, bool]) -> str:
        """Génère une clé pour le jeu de caractères"""
        parts = []
        if char_sets['lowercase']:
            parts.append('lower')
        if char_sets['uppercase']:
            parts.append('upper')
        if char_sets['digits']:
            parts.append('digits')
        if char_sets['symbols']:
            parts.append('symbols')
        if char_sets['spaces']:
            parts.append('spaces')
        
        return '+'.join(parts) if parts else 'none'
    
    def _get_entropy_range(self, entropy: float) -> str:
        """Détermine la tranche d'entropie"""
        if entropy < 20:
            return 'very_low'
        elif entropy < 40:
            return 'low'
        elif entropy < 60:
            return 'medium'
        elif entropy < 80:
            return 'high'
        else:
            return 'very_high'
    
    def _get_strength_range(self, strength: int) -> str:
        """Détermine la tranche de force"""
        if strength < 20:
            return 'very_weak'
        elif strength < 40:
            return 'weak'
        elif strength < 60:
            return 'medium'
        elif strength < 80:
            return 'strong'
        else:
            return 'very_strong'
    
    def _extract_base_word(self, password: str) -> Optional[str]:
        """Extrait le mot de base d'un mot de passe"""
        # Supprime les chiffres et symboles à la fin
        base = re.sub(r'[\d\W]+$', '', password)
        return base.lower() if len(base) >= 3 else None
    
    def _generate_recommendations(self, 
                                total_passwords: int,
                                duplicate_rate: float,
                                length_dist: Dict[int, int],
                                charset_dist: Dict[str, int],
                                strength_dist: Dict[str, int],
                                top_patterns: List[Tuple[str, int]]) -> List[str]:
        """Génère des recommandations de sécurité"""
        recommendations = []
        
        # Duplicatas
        if duplicate_rate > 0.1:
            recommendations.append(
                f"🔴 Taux de duplication élevé ({duplicate_rate:.1%}). "
                "Encourager l'utilisation de mots de passe uniques."
            )
        
        # Longueur
        short_passwords = sum(count for length, count in length_dist.items() if length < 8)
        if short_passwords > total_passwords * 0.2:
            recommendations.append(
                f"🔴 {short_passwords} mots de passe ({short_passwords/total_passwords:.1%}) "
                "ont moins de 8 caractères. Imposer une longueur minimum de 12 caractères."
            )
        
        # Complexité
        simple_passwords = charset_dist.get('lower', 0) + charset_dist.get('digits', 0)
        if simple_passwords > total_passwords * 0.3:
            recommendations.append(
                "🟡 Trop de mots de passe simples (minuscules seules ou chiffres seuls). "
                "Imposer l'utilisation de majuscules, minuscules, chiffres et symboles."
            )
        
        # Force
        weak_passwords = (strength_dist.get('very_weak', 0) + 
                         strength_dist.get('weak', 0))
        if weak_passwords > total_passwords * 0.4:
            recommendations.append(
                f"🔴 {weak_passwords} mots de passe ({weak_passwords/total_passwords:.1%}) "
                "sont faibles. Implémenter un vérificateur de force en temps réel."
            )
        
        # Patterns communs
        if top_patterns and top_patterns[0][1] > 10:
            recommendations.append(
                f"🟡 Pattern clavier détecté '{top_patterns[0][0]}' dans {top_patterns[0][1]} mots de passe. "
                "Sensibiliser aux dangers des séquences clavier."
            )
        
        # Recommandations générales
        recommendations.extend([
            "✅ Implémenter l'authentification multifacteur (2FA/MFA)",
            "✅ Encourager l'utilisation de gestionnaires de mots de passe",
            "✅ Mettre en place une politique de renouvellement périodique",
            "✅ Vérifier les mots de passe contre les bases de données de compromission",
            "✅ Former les utilisateurs aux bonnes pratiques de sécurité"
        ])
        
        return recommendations
    
    def export_analysis(self, analysis: DatasetAnalysis, output_dir: str = "results"):
        """Exporte l'analyse dans différents formats"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON
        json_file = output_path / f"password_analysis_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(analysis), f, indent=2, default=str)
        
        # CSV des statistiques principales
        csv_file = output_path / f"password_stats_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Passwords', analysis.total_passwords])
            writer.writerow(['Unique Passwords', analysis.unique_passwords])
            writer.writerow(['Duplicate Rate', f"{analysis.duplicate_rate:.2%}"])
            
            writer.writerow(['', ''])
            writer.writerow(['Length Distribution', ''])
            for length, count in sorted(analysis.length_distribution.items()):
                writer.writerow([f"Length {length}", count])
            
            writer.writerow(['', ''])
            writer.writerow(['Character Set Distribution', ''])
            for charset, count in analysis.character_set_distribution.items():
                writer.writerow([charset, count])
        
        # Graphiques
        self._generate_plots(analysis, output_path, timestamp)
        
        # Rapport HTML
        html_file = output_path / f"password_report_{timestamp}.html"
        html_content = self._generate_html_report(analysis)
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        print(f"Analysis exported to {output_path}")
        print(f"- JSON: {json_file}")
        print(f"- CSV: {csv_file}")
        print(f"- HTML: {html_file}")
    
    def _generate_plots(self, analysis: DatasetAnalysis, output_path: Path, timestamp: str):
        """Génère les graphiques d'analyse"""
        plt.style.use('seaborn-v0_8')
        
        # Distribution des longueurs
        plt.figure(figsize=(12, 8))
        
        plt.subplot(2, 2, 1)
        lengths = list(analysis.length_distribution.keys())
        counts = list(analysis.length_distribution.values())
        plt.bar(lengths, counts, color='skyblue')
        plt.title('Distribution des Longueurs')
        plt.xlabel('Longueur')
        plt.ylabel('Nombre de Mots de Passe')
        
        # Distribution des jeux de caractères
        plt.subplot(2, 2, 2)
        charsets = list(analysis.character_set_distribution.keys())
        charset_counts = list(analysis.character_set_distribution.values())
        plt.pie(charset_counts, labels=charsets, autopct='%1.1f%%')
        plt.title('Distribution des Jeux de Caractères')
        
        # Distribution de la force
        plt.subplot(2, 2, 3)
        strength_labels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
        strength_counts = [
            analysis.strength_distribution.get('very_weak', 0),
            analysis.strength_distribution.get('weak', 0),
            analysis.strength_distribution.get('medium', 0),
            analysis.strength_distribution.get('strong', 0),
            analysis.strength_distribution.get('very_strong', 0)
        ]
        colors = ['red', 'orange', 'yellow', 'lightgreen', 'green']
        plt.bar(strength_labels, strength_counts, color=colors)
        plt.title('Distribution de la Force des Mots de Passe')
        plt.xticks(rotation=45)
        
        # Top patterns
        plt.subplot(2, 2, 4)
        if analysis.top_patterns:
            patterns = [p[0][:10] for p in analysis.top_patterns[:10]]
            pattern_counts = [p[1] for p in analysis.top_patterns[:10]]
            plt.barh(patterns, pattern_counts, color='lightcoral')
            plt.title('Top 10 Patterns Détectés')
            plt.xlabel('Fréquence')
        
        plt.tight_layout()
        plot_file = output_path / f"password_analysis_{timestamp}.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"- Plots: {plot_file}")
    
    def _generate_html_report(self, analysis: DatasetAnalysis) -> str:
        """Génère un rapport HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Password Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .summary {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }}
        .metric {{ background: #ecf0f1; padding: 15px; border-radius: 5px; flex: 1; min-width: 200px; }}
        .metric h3 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .metric .value {{ font-size: 24px; font-weight: bold; color: #e74c3c; }}
        .section {{ margin-bottom: 30px; }}
        .recommendations {{ background: #f8f9fa; padding: 20px; border-left: 5px solid #28a745; }}
        .recommendation {{ margin: 10px 0; }}
        .top-list {{ background: #fff; border: 1px solid #ddd; border-radius: 5px; }}
        .top-item {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .top-item:last-child {{ border-bottom: none; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Password Analysis Report</h1>
        <p>Generated on {timestamp}</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Passwords</h3>
            <div class="value">{total_passwords:,}</div>
        </div>
        <div class="metric">
            <h3>Unique Passwords</h3>
            <div class="value">{unique_passwords:,}</div>
        </div>
        <div class="metric">
            <h3>Duplicate Rate</h3>
            <div class="value">{duplicate_rate:.1%}</div>
        </div>
        <div class="metric">
            <h3>Avg Length</h3>
            <div class="value">{avg_length:.1f}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Security Recommendations</h2>
        <div class="recommendations">
            {recommendations_html}
        </div>
    </div>
    
    <div class="section">
        <h2>Top Vulnerable Passwords</h2>
        <div class="top-list">
            {top_passwords_html}
        </div>
    </div>
    
    <div class="section">
        <h2>Most Common Patterns</h2>
        <div class="top-list">
            {top_patterns_html}
        </div>
    </div>
    
    <div class="section">
        <h2>Length Distribution</h2>
        <div class="top-list">
            {length_distribution_html}
        </div>
    </div>
</body>
</html>
        """
        
        # Calculs pour le template
        avg_length = sum(l * c for l, c in analysis.length_distribution.items()) / analysis.total_passwords
        
        recommendations_html = ''.join([
            f'<div class="recommendation">{rec}</div>' 
            for rec in analysis.recommendations
        ])
        
        top_passwords_html = ''.join([
            f'<div class="top-item"><strong>{pwd}</strong> - {count} occurrences</div>'
            for pwd, count in analysis.top_passwords[:20]
        ])
        
        top_patterns_html = ''.join([
            f'<div class="top-item"><strong>{pattern}</strong> - {count} occurrences</div>'
            for pattern, count in analysis.top_patterns[:20]
        ])
        
        length_distribution_html = ''.join([
            f'<div class="top-item">Length {length}: <strong>{count}</strong> passwords</div>'
            for length, count in sorted(analysis.length_distribution.items())
        ])
        
        return html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_passwords=analysis.total_passwords,
            unique_passwords=analysis.unique_passwords,
            duplicate_rate=analysis.duplicate_rate,
            avg_length=avg_length,
            recommendations_html=recommendations_html,
            top_passwords_html=top_passwords_html,
            top_patterns_html=top_patterns_html,
            length_distribution_html=length_distribution_html
        )


def main():
    """Fonction principale pour test"""
    analyzer = PasswordAnalyzer()
    
    # Test avec quelques mots de passe d'exemple
    test_passwords = [
        "password123", "123456", "qwerty", "admin", "letmein",
        "Password1", "password", "123456789", "welcome",
        "admin123", "root", "toor", "pass", "test",
        "guest", "info", "adm", "mysql", "oracle",
        "god", "love", "sex", "secret", "dragon",
        "password1", "password12", "password123", "password1234",
        "qwerty123", "qwerty12", "qwerty1", "azerty",
        "football", "basketball", "baseball", "soccer",
        "january", "february", "march", "april",
        "2023", "2022", "2021", "2020", "1234",
        "john123", "mary456", "david789", "sarah2022"
    ] * 20  # Multiplier pour avoir plus de données
    
    # Analyse du dataset
    analysis = analyzer.analyze_dataset(test_passwords)
    
    # Affichage des résultats
    print("\n" + "="*50)
    print("PASSWORD ANALYSIS RESULTS")
    print("="*50)
    print(f"Total passwords: {analysis.total_passwords}")
    print(f"Unique passwords: {analysis.unique_passwords}")
    print(f"Duplicate rate: {analysis.duplicate_rate:.1%}")
    
    print("\nTop 10 most common passwords:")
    for pwd, count in analysis.top_passwords[:10]:
        print(f"  {pwd}: {count}")
    
    print("\nTop 10 patterns:")
    for pattern, count in analysis.top_patterns[:10]:
        print(f"  {pattern}: {count}")
    
    print("\nRecommendations:")
    for rec in analysis.recommendations:
        print(f"  {rec}")
    
    # Export des résultats
    analyzer.export_analysis(analysis)


if __name__ == "__main__":
    main()