#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Wordlist Builder - Custom Password Dictionary Generator
============================================================================
Générateur de wordlists personnalisées basées sur des informations OSINT,
contexte organisationnel et techniques de mutation avancées.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import re
import json
import csv
import itertools
from datetime import datetime
from typing import List, Set, Dict, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TargetProfile:
    """Profil de la cible pour génération de wordlist"""
    # Informations personnelles
    first_names: List[str] = None
    last_names: List[str] = None
    nicknames: List[str] = None
    birthdates: List[str] = None
    phone_numbers: List[str] = None
    addresses: List[str] = None
    
    # Informations professionnelles
    company_names: List[str] = None
    job_titles: List[str] = None
    departments: List[str] = None
    colleagues: List[str] = None
    office_locations: List[str] = None
    
    # Intérêts et hobbies
    interests: List[str] = None
    sports: List[str] = None
    music: List[str] = None
    movies: List[str] = None
    books: List[str] = None
    
    # Informations techniques
    keywords: List[str] = None
    domain_names: List[str] = None
    technologies: List[str] = None
    
    def __post_init__(self):
        """Initialise les listes vides si None"""
        for field_name, field_type in self.__annotations__.items():
            if getattr(self, field_name) is None:
                setattr(self, field_name, [])


class MutationEngine:
    """Moteur de mutations pour la génération de variants"""
    
    def __init__(self):
        """Initialisation du moteur de mutations"""
        self.substitutions = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7', '+'],
            'g': ['6', '9'],
            'b': ['8'],
            'l': ['1', '|']
        }
        
        self.common_prefixes = ['', 'the', 'my', 'our', 'new', 'old']
        self.common_suffixes = ['', '1', '2', '3', '12', '123', '1234', 
                               '2021', '2022', '2023', '2024', '!', '!!', 
                               '?', '01', '007', '69', '99', '2k', '2k23']
        
        self.separators = ['', '-', '_', '.', '+']
        
    def apply_leetspeak(self, word: str, level: int = 1) -> List[str]:
        """
        Applique le leetspeak à un mot
        
        Args:
            word: Mot à transformer
            level: Niveau de transformation (1=basique, 2=avancé)
            
        Returns:
            Liste des variants leetspeak
        """
        variants = [word]
        
        if level >= 1:
            # Substitutions basiques
            for original, replacements in self.substitutions.items():
                new_variants = []
                for variant in variants:
                    for replacement in replacements:
                        new_variants.append(variant.replace(original, replacement))
                        new_variants.append(variant.replace(original.upper(), replacement))
                variants.extend(new_variants)
        
        if level >= 2:
            # Substitutions partielles (seulement quelques caractères)
            base_variants = variants.copy()
            for variant in base_variants[:50]:  # Limite pour éviter l'explosion
                for original, replacements in self.substitutions.items():
                    if original in variant.lower():
                        positions = [i for i, c in enumerate(variant.lower()) if c == original]
                        for pos in positions:
                            for replacement in replacements:
                                new_variant = list(variant)
                                new_variant[pos] = replacement
                                variants.append(''.join(new_variant))
        
        return list(set(variants))
    
    def apply_capitalization(self, word: str) -> List[str]:
        """
        Applique différentes règles de capitalisation
        
        Args:
            word: Mot à transformer
            
        Returns:
            Liste des variants de capitalisation
        """
        if not word:
            return []
        
        variants = [
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase()
        ]
        
        # Première et dernière lettre en majuscule
        if len(word) > 1:
            first_last = word[0].upper() + word[1:-1].lower() + word[-1].upper()
            variants.append(first_last)
        
        # Alternance majuscules/minuscules
        if len(word) > 2:
            alternating = ''.join([c.upper() if i % 2 == 0 else c.lower() 
                                 for i, c in enumerate(word)])
            variants.append(alternating)
        
        return list(set(variants))
    
    def add_common_additions(self, word: str) -> List[str]:
        """
        Ajoute des préfixes et suffixes communs
        
        Args:
            word: Mot de base
            
        Returns:
            Liste des variants avec additions
        """
        variants = []
        
        # Ajout de suffixes
        for suffix in self.common_suffixes:
            variants.append(word + suffix)
        
        # Ajout de préfixes
        for prefix in self.common_prefixes:
            if prefix:  # Skip empty prefix to avoid duplicates
                variants.append(prefix + word)
        
        # Combinaisons préfixes + suffixes (limitées)
        for prefix in self.common_prefixes[:3]:
            for suffix in self.common_suffixes[:5]:
                if prefix or suffix:  # Éviter le mot original
                    variants.append(prefix + word + suffix)
        
        return variants
    
    def apply_mutations(self, word: str, max_mutations: int = 100) -> Set[str]:
        """
        Applique toutes les mutations possibles à un mot
        
        Args:
            word: Mot à transformer
            max_mutations: Nombre maximum de mutations
            
        Returns:
            Ensemble des variants générés
        """
        all_variants = set()
        
        # Capitalisation
        cap_variants = self.apply_capitalization(word)
        all_variants.update(cap_variants[:20])  # Limite
        
        # Leetspeak
        leet_variants = self.apply_leetspeak(word, level=1)
        all_variants.update(leet_variants[:30])  # Limite
        
        # Additions
        addition_variants = self.add_common_additions(word)
        all_variants.update(addition_variants[:50])  # Limite
        
        # Combinaisons capitalisation + additions
        for cap_word in cap_variants[:5]:
            addition_vars = self.add_common_additions(cap_word)
            all_variants.update(addition_vars[:20])
        
        # Limitation du nombre total
        if len(all_variants) > max_mutations:
            all_variants = set(list(all_variants)[:max_mutations])
        
        return all_variants


class OSINTIntegrator:
    """Intégrateur OSINT pour collecte automatique d'informations"""
    
    def __init__(self):
        """Initialisation de l'intégrateur OSINT"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def extract_from_website(self, url: str, max_words: int = 100) -> List[str]:
        """
        Extrait des mots-clés d'un site web
        
        Args:
            url: URL du site à analyser
            max_words: Nombre maximum de mots à extraire
            
        Returns:
            Liste des mots-clés extraits
        """
        words = []
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Suppression des scripts et styles
            for script in soup(["script", "style"]):
                script.extract()
            
            # Extraction du texte
            text = soup.get_text()
            
            # Nettoyage et extraction des mots
            words = self._extract_words_from_text(text, max_words)
            
            # Extraction spécifique des métadonnées
            meta_words = self._extract_meta_keywords(soup)
            words.extend(meta_words)
            
            logger.info(f"Extracted {len(words)} words from {url}")
            
        except Exception as e:
            logger.error(f"Error extracting from {url}: {e}")
        
        return list(set(words))[:max_words]
    
    def _extract_words_from_text(self, text: str, max_words: int) -> List[str]:
        """Extrait les mots pertinents d'un texte"""
        # Nettoyage du texte
        text = re.sub(r'[^\w\s-]', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        
        # Extraction des mots
        words = text.split()
        
        # Filtrage
        filtered_words = []
        for word in words:
            word = word.strip().lower()
            
            # Critères de filtrage
            if (3 <= len(word) <= 20 and
                word.isalnum() and
                not word.isdigit() and
                word not in self._get_stop_words()):
                
                filtered_words.append(word)
        
        # Comptage et tri par fréquence
        word_count = defaultdict(int)
        for word in filtered_words:
            word_count[word] += 1
        
        # Retour des mots les plus fréquents
        sorted_words = sorted(word_count.items(), key=lambda x: x[1], reverse=True)
        return [word for word, count in sorted_words[:max_words]]
    
    def _extract_meta_keywords(self, soup: BeautifulSoup) -> List[str]:
        """Extrait les mots-clés des métadonnées"""
        keywords = []
        
        # Méta keywords
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords and meta_keywords.get('content'):
            keywords.extend([kw.strip().lower() for kw in meta_keywords['content'].split(',')])
        
        # Titre de la page
        title = soup.find('title')
        if title:
            title_words = self._extract_words_from_text(title.get_text(), 10)
            keywords.extend(title_words)
        
        # Description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc_words = self._extract_words_from_text(meta_desc['content'], 15)
            keywords.extend(desc_words)
        
        return keywords
    
    def _get_stop_words(self) -> Set[str]:
        """Retourne une liste de mots vides à ignorer"""
        return {
            'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
            'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had',
            'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might',
            'this', 'that', 'these', 'those', 'here', 'there', 'where', 'when',
            'what', 'who', 'why', 'how', 'all', 'any', 'some', 'many', 'much',
            'more', 'most', 'other', 'such', 'very', 'can', 'just', 'now', 'also',
            'about', 'after', 'before', 'through', 'during', 'above', 'below'
        }


class WordlistBuilder:
    """Constructeur principal de wordlists personnalisées"""
    
    def __init__(self):
        """Initialisation du constructeur"""
        self.mutation_engine = MutationEngine()
        self.osint_integrator = OSINTIntegrator()
        
    def build_from_profile(self, profile: TargetProfile, 
                          enable_mutations: bool = True,
                          max_words: int = 10000) -> List[str]:
        """
        Génère une wordlist basée sur un profil cible
        
        Args:
            profile: Profil de la cible
            enable_mutations: Activer les mutations
            max_words: Nombre maximum de mots
            
        Returns:
            Liste des mots de passe candidats
        """
        logger.info("Building wordlist from target profile...")
        
        base_words = set()
        
        # Collecte des mots de base
        base_words.update(profile.first_names)
        base_words.update(profile.last_names)
        base_words.update(profile.nicknames)
        base_words.update(profile.company_names)
        base_words.update(profile.job_titles)
        base_words.update(profile.departments)
        base_words.update(profile.interests)
        base_words.update(profile.keywords)
        
        # Nettoyage des mots de base
        clean_base_words = self._clean_words(base_words)
        logger.info(f"Collected {len(clean_base_words)} base words")
        
        # Génération de combinaisons
        combinations = self._generate_combinations(clean_base_words, profile)
        logger.info(f"Generated {len(combinations)} combinations")
        
        # Application des mutations si activées
        final_words = set(combinations)
        if enable_mutations:
            mutated_words = set()
            for word in list(final_words)[:1000]:  # Limite pour éviter l'explosion
                mutations = self.mutation_engine.apply_mutations(word, max_mutations=20)
                mutated_words.update(mutations)
            
            final_words.update(mutated_words)
            logger.info(f"Applied mutations, total words: {len(final_words)}")
        
        # Ajout de dates importantes
        date_words = self._generate_date_passwords(profile.birthdates)
        final_words.update(date_words)
        
        # Limitation et tri
        final_list = self._prioritize_words(list(final_words), max_words)
        
        logger.info(f"Final wordlist size: {len(final_list)}")
        return final_list
    
    def build_from_osint(self, domains: List[str], 
                        linkedin_profiles: List[str] = None,
                        max_words: int = 5000) -> List[str]:
        """
        Génère une wordlist basée sur la reconnaissance OSINT
        
        Args:
            domains: Liste des domaines à analyser
            linkedin_profiles: Profils LinkedIn (URLs)
            max_words: Nombre maximum de mots
            
        Returns:
            Liste des mots de passe candidats
        """
        logger.info("Building wordlist from OSINT sources...")
        
        all_words = set()
        
        # Extraction depuis les sites web
        for domain in domains:
            if not domain.startswith('http'):
                domain = f"https://{domain}"
            
            try:
                words = self.osint_integrator.extract_from_website(domain)
                all_words.update(words)
                logger.info(f"Extracted {len(words)} words from {domain}")
                
                # Tentative sur www et sous-domaines communs
                if not domain.startswith('https://www.'):
                    www_domain = domain.replace('https://', 'https://www.')
                    words = self.osint_integrator.extract_from_website(www_domain)
                    all_words.update(words)
                
            except Exception as e:
                logger.error(f"Failed to extract from {domain}: {e}")
        
        # Application de mutations basiques
        mutated_words = set()
        for word in list(all_words)[:500]:  # Limite
            mutations = self.mutation_engine.apply_mutations(word, max_mutations=10)
            mutated_words.update(mutations)
        
        all_words.update(mutated_words)
        
        # Limitation et tri
        final_list = self._prioritize_words(list(all_words), max_words)
        
        logger.info(f"OSINT wordlist size: {len(final_list)}")
        return final_list
    
    def build_from_company_info(self, company_name: str,
                               industry: str = None,
                               location: str = None,
                               max_words: int = 3000) -> List[str]:
        """
        Génère une wordlist basée sur les informations d'entreprise
        
        Args:
            company_name: Nom de l'entreprise
            industry: Secteur d'activité
            location: Localisation
            max_words: Nombre maximum de mots
            
        Returns:
            Liste des mots de passe candidats
        """
        logger.info(f"Building wordlist for company: {company_name}")
        
        base_words = set()
        
        # Variations du nom d'entreprise
        company_variations = self._generate_company_variations(company_name)
        base_words.update(company_variations)
        
        # Mots liés au secteur
        if industry:
            industry_words = self._get_industry_keywords(industry)
            base_words.update(industry_words)
        
        # Mots liés à la localisation
        if location:
            location_words = self._get_location_keywords(location)
            base_words.update(location_words)
        
        # Mots génériques d'entreprise
        corporate_words = [
            'admin', 'user', 'guest', 'test', 'demo', 'temp',
            'password', 'login', 'access', 'secure', 'system',
            'server', 'network', 'office', 'team', 'group',
            'company', 'corp', 'enterprise', 'business',
            'welcome', 'hello', 'start', 'begin', 'new'
        ]
        base_words.update(corporate_words)
        
        # Application des mutations
        final_words = set()
        for word in base_words:
            mutations = self.mutation_engine.apply_mutations(word, max_mutations=15)
            final_words.update(mutations)
        
        # Limitation et tri
        final_list = self._prioritize_words(list(final_words), max_words)
        
        logger.info(f"Company wordlist size: {len(final_list)}")
        return final_list
    
    def _clean_words(self, words: Set[str]) -> List[str]:
        """Nettoie et filtre la liste de mots"""
        clean_words = []
        
        for word in words:
            if not word:
                continue
            
            # Nettoyage basique
            word = str(word).strip().lower()
            word = re.sub(r'[^\w\s-]', '', word)
            word = re.sub(r'\s+', '', word)
            
            # Filtres
            if (2 <= len(word) <= 25 and
                not word.isdigit() and
                word.isascii()):
                clean_words.append(word)
        
        return list(set(clean_words))
    
    def _generate_combinations(self, base_words: List[str], profile: TargetProfile) -> List[str]:
        """Génère des combinaisons de mots"""
        combinations = set()
        
        # Mots simples
        combinations.update(base_words)
        
        # Combinaisons avec dates
        years = ['2020', '2021', '2022', '2023', '2024']
        for word in base_words[:50]:  # Limite
            for year in years:
                combinations.add(word + year)
                combinations.add(year + word)
        
        # Combinaisons avec chiffres communs
        numbers = ['1', '12', '123', '1234', '01', '007', '99']
        for word in base_words[:30]:
            for num in numbers:
                combinations.add(word + num)
                combinations.add(num + word)
        
        # Combinaisons de 2 mots (limitées)
        if len(base_words) > 1:
            for i, word1 in enumerate(base_words[:20]):
                for j, word2 in enumerate(base_words[:20]):
                    if i != j:
                        combinations.add(word1 + word2)
                        combinations.add(word1 + '_' + word2)
                        combinations.add(word1 + '-' + word2)
        
        return list(combinations)
    
    def _generate_date_passwords(self, birthdates: List[str]) -> Set[str]:
        """Génère des mots de passe basés sur les dates"""
        date_passwords = set()
        
        # Années courantes
        current_year = datetime.now().year
        years = [str(year) for year in range(current_year - 30, current_year + 2)]
        date_passwords.update(years)
        
        # Formats de dates communs
        for birthdate in birthdates:
            if birthdate:
                # Extraction de l'année, mois, jour si possible
                date_parts = re.findall(r'\d+', birthdate)
                for part in date_parts:
                    if len(part) >= 2:
                        date_passwords.add(part)
        
        # Dates et saisons
        seasons = ['spring2023', 'summer2023', 'autumn2023', 'winter2023',
                  'spring2024', 'summer2024', 'autumn2024', 'winter2024']
        date_passwords.update(seasons)
        
        return date_passwords
    
    def _generate_company_variations(self, company_name: str) -> List[str]:
        """Génère des variations du nom d'entreprise"""
        variations = [company_name.lower()]
        
        # Suppression des mots communs
        clean_name = re.sub(r'\b(inc|ltd|llc|corp|corporation|company|co)\b', '', 
                           company_name.lower()).strip()
        variations.append(clean_name)
        
        # Acronymes
        words = clean_name.split()
        if len(words) > 1:
            acronym = ''.join([w[0] for w in words if w])
            variations.append(acronym)
        
        # Variations avec espaces/tirets/underscores
        variations.extend([
            clean_name.replace(' ', ''),
            clean_name.replace(' ', '_'),
            clean_name.replace(' ', '-'),
            clean_name.replace(' ', '.')
        ])
        
        return list(set(variations))
    
    def _get_industry_keywords(self, industry: str) -> List[str]:
        """Obtient les mots-clés liés à un secteur"""
        industry_keywords = {
            'technology': ['tech', 'software', 'hardware', 'code', 'dev', 'system', 'data'],
            'finance': ['money', 'bank', 'credit', 'loan', 'invest', 'fund', 'finance'],
            'healthcare': ['health', 'medical', 'doctor', 'nurse', 'patient', 'care'],
            'education': ['school', 'student', 'teacher', 'learn', 'study', 'education'],
            'retail': ['shop', 'store', 'sale', 'customer', 'product', 'retail'],
            'manufacturing': ['factory', 'production', 'quality', 'process', 'build'],
            'consulting': ['consult', 'advice', 'solution', 'strategy', 'expert']
        }
        
        industry_lower = industry.lower()
        for key, keywords in industry_keywords.items():
            if key in industry_lower:
                return keywords
        
        return []
    
    def _get_location_keywords(self, location: str) -> List[str]:
        """Obtient les mots-clés liés à une localisation"""
        location_words = [location.lower()]
        
        # Extraction de mots individuels
        words = re.findall(r'\w+', location.lower())
        location_words.extend(words)
        
        # Codes de pays/états communs
        location_codes = {
            'united states': ['usa', 'us'],
            'united kingdom': ['uk', 'gb'],
            'california': ['ca', 'cal'],
            'new york': ['ny', 'nyc'],
            'texas': ['tx'],
            'florida': ['fl']
        }
        
        for key, codes in location_codes.items():
            if key in location.lower():
                location_words.extend(codes)
        
        return location_words
    
    def _prioritize_words(self, words: List[str], max_words: int) -> List[str]:
        """Priorise et limite la liste de mots"""
        # Tri par longueur et complexité
        def word_score(word):
            score = 0
            # Longueur optimale
            if 6 <= len(word) <= 12:
                score += 10
            # Présence de chiffres
            if any(c.isdigit() for c in word):
                score += 5
            # Présence de majuscules
            if any(c.isupper() for c in word):
                score += 3
            # Présence de symboles
            if any(c in '!@#$%^&*()_+-=' for c in word):
                score += 7
            
            return score
        
        # Tri et limitation
        scored_words = [(word, word_score(word)) for word in words]
        scored_words.sort(key=lambda x: x[1], reverse=True)
        
        return [word for word, score in scored_words[:max_words]]
    
    def export_wordlist(self, words: List[str], 
                       filename: str, 
                       format_type: str = 'txt',
                       output_dir: str = 'wordlists/custom') -> str:
        """
        Exporte la wordlist dans différents formats
        
        Args:
            words: Liste des mots
            filename: Nom du fichier (sans extension)
            format_type: Format ('txt', 'csv', 'json')
            output_dir: Répertoire de sortie
            
        Returns:
            Chemin du fichier créé
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'txt':
            filepath = output_path / f"{filename}_{timestamp}.txt"
            with open(filepath, 'w', encoding='utf-8') as f:
                for word in words:
                    f.write(f"{word}\n")
        
        elif format_type == 'csv':
            filepath = output_path / f"{filename}_{timestamp}.csv"
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['password', 'length', 'complexity'])
                for word in words:
                    complexity = self._calculate_complexity(word)
                    writer.writerow([word, len(word), complexity])
        
        elif format_type == 'json':
            filepath = output_path / f"{filename}_{timestamp}.json"
            wordlist_data = {
                'generated_on': datetime.now().isoformat(),
                'total_words': len(words),
                'words': words,
                'statistics': self._generate_statistics(words)
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(wordlist_data, f, indent=2, ensure_ascii=False)
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        logger.info(f"Wordlist exported to {filepath}")
        return str(filepath)
    
    def _calculate_complexity(self, word: str) -> str:
        """Calcule la complexité d'un mot de passe"""
        score = 0
        
        if any(c.islower() for c in word):
            score += 1
        if any(c.isupper() for c in word):
            score += 1
        if any(c.isdigit() for c in word):
            score += 1
        if any(c in '!@#$%^&*()_+-=' for c in word):
            score += 1
        
        if score <= 1:
            return 'low'
        elif score <= 2:
            return 'medium'
        else:
            return 'high'
    
    def _generate_statistics(self, words: List[str]) -> Dict[str, Any]:
        """Génère des statistiques sur la wordlist"""
        if not words:
            return {}
        
        lengths = [len(word) for word in words]
        complexities = [self._calculate_complexity(word) for word in words]
        
        return {
            'min_length': min(lengths),
            'max_length': max(lengths),
            'avg_length': sum(lengths) / len(lengths),
            'complexity_distribution': {
                'low': complexities.count('low'),
                'medium': complexities.count('medium'),
                'high': complexities.count('high')
            }
        }


def main():
    """Fonction principale pour test"""
    builder = WordlistBuilder()
    
    # Test 1: Génération basée sur un profil
    profile = TargetProfile(
        first_names=['john', 'jane'],
        last_names=['doe', 'smith'],
        company_names=['acmecorp', 'acme'],
        interests=['football', 'music'],
        birthdates=['1990', '1985']
    )
    
    wordlist1 = builder.build_from_profile(profile, max_words=500)
    print(f"Generated {len(wordlist1)} words from profile")
    
    # Export
    filepath1 = builder.export_wordlist(
        wordlist1, 
        'profile_based_wordlist',
        format_type='txt'
    )
    
    # Test 2: Génération basée sur OSINT
    domains = ['example.com']  # Domaine d'exemple
    wordlist2 = builder.build_from_osint(domains, max_words=300)
    print(f"Generated {len(wordlist2)} words from OSINT")
    
    # Test 3: Génération basée sur l'entreprise
    wordlist3 = builder.build_from_company_info(
        'Acme Corporation',
        industry='technology',
        location='San Francisco',
        max_words=400
    )
    print(f"Generated {len(wordlist3)} words for company")
    
    # Export combiné
    combined_wordlist = list(set(wordlist1 + wordlist2 + wordlist3))
    filepath_combined = builder.export_wordlist(
        combined_wordlist,
        'combined_wordlist',
        format_type='json'
    )
    
    print(f"Combined wordlist with {len(combined_wordlist)} unique words")
    print(f"Exported to: {filepath_combined}")


if __name__ == "__main__":
    main()