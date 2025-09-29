#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Complete Password Audit Demo - Password Cracking Platform
============================================================================
Démonstration complète d'un audit de sécurité des mots de passe utilisant
toute la plateforme : Hashcat, analyse de patterns, génération de wordlists
et reporting complet.

Author: Cybersecurity Portfolio
Version: 1.0.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path

# Ajout du chemin src au PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

try:
    from hashcat.hashcat_manager import HashcatManager, HashType, AttackConfig
    from analysis.password_analyzer import PasswordAnalyzer
    from wordlist_generator.wordlist_builder import WordlistBuilder, TargetProfile
except ImportError as e:
    print(f"❌ Erreur d'import: {e}")
    print("Assurez-vous que le projet est correctement configuré.")
    sys.exit(1)


class PasswordAuditDemo:
    """
    Démonstration complète d'un audit de mots de passe
    """
    
    def __init__(self, demo_name: str = "Corporate_Audit_Demo"):
        """
        Initialisation de la démonstration
        
        Args:
            demo_name: Nom de la démonstration
        """
        self.demo_name = demo_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialisation des composants
        self.hashcat_manager = None
        self.password_analyzer = None
        self.wordlist_builder = None
        
        # Chemins de travail
        self.demo_dir = project_root / 'examples' / f'demo_{self.timestamp}'
        self.hashes_dir = self.demo_dir / 'hashes'
        self.wordlists_dir = self.demo_dir / 'wordlists'
        self.results_dir = self.demo_dir / 'results'
        
        # Configuration de l'audit
        self.audit_config = {
            'company_name': 'ACME Corporation',
            'industry': 'technology',
            'location': 'San Francisco, CA',
            'employee_count': 250,
            'audit_scope': 'all_employees'
        }
        
        self._setup_demo_environment()
        
    def _setup_demo_environment(self):
        """Configure l'environnement de démonstration"""
        print(f"🔧 Configuration de l'environnement de démonstration: {self.demo_name}")
        
        # Création des répertoires
        self.demo_dir.mkdir(parents=True, exist_ok=True)
        self.hashes_dir.mkdir(exist_ok=True)
        self.wordlists_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        try:
            # Initialisation des outils
            self.hashcat_manager = HashcatManager(
                outfile_dir=str(self.results_dir / 'cracked'),
                session_dir=str(self.results_dir / 'sessions')
            )
            
            self.password_analyzer = PasswordAnalyzer()
            self.wordlist_builder = WordlistBuilder()
            
            print("✅ Environnement configuré avec succès")
            
        except Exception as e:
            print(f"❌ Erreur lors de la configuration: {e}")
            print("Note: Hashcat doit être installé et accessible dans le PATH")
    
    def generate_demo_hashes(self):
        """Génère un ensemble de hashs de démonstration"""
        print("\n🔑 === GÉNÉRATION DES HASHS DE DÉMONSTRATION ===")
        
        # Mots de passe typiques d'entreprise (faibles à forts)
        demo_passwords = [
            # Très faibles
            "password", "123456", "admin", "welcome", "login",
            "qwerty", "letmein", "password123", "admin123",
            
            # Faibles avec patterns d'entreprise
            "acme123", "acme2023", "acme2024", "ACMEcorp",
            "company1", "office123", "team2023", "work123",
            
            # Moyens
            "Password1", "Welcome123", "Acme@2023", "MyPass123",
            "Office2024!", "Team$ecure", "Work_123", "Corp@123",
            
            # Plus forts mais avec patterns
            "Acme_Secure123", "MyP@ssw0rd2024", "C0rp0r@te_123",
            "Secur3_P@ss", "Str0ng_Acme!", "M0nkey_Business",
            
            # Personnalisés avec informations OSINT
            "john.smith123", "mary.johnson2023", "david_wilson",
            "sarah@acme", "mike.brown123", "lisa_davis2024",
            
            # Basés sur la localisation
            "SanFrancisco1", "California123", "SF_Office",
            "BayArea2023", "Golden_Gate1", "CA_Team123",
            
            # Tech industry specific
            "Python123", "JavaScript!", "Docker_123", "API_Key1",
            "DevOps2024", "CloudNative", "Microservices1"
        ] * 3  # Triplé pour simuler plus d'utilisateurs
        
        # Génération des hashs MD5 et SHA256 pour la démo
        hash_files = {}
        
        try:
            import hashlib
            
            # Génération MD5
            md5_hashes = []
            for pwd in demo_passwords:
                hash_md5 = hashlib.md5(pwd.encode()).hexdigest()
                md5_hashes.append(hash_md5)
            
            md5_file = self.hashes_dir / 'demo_md5_hashes.txt'
            with open(md5_file, 'w') as f:
                for hash_val in md5_hashes:
                    f.write(f"{hash_val}\n")
            
            hash_files['md5'] = str(md5_file)
            
            # Génération SHA256
            sha256_hashes = []
            for pwd in demo_passwords:
                hash_sha256 = hashlib.sha256(pwd.encode()).hexdigest()
                sha256_hashes.append(hash_sha256)
            
            sha256_file = self.hashes_dir / 'demo_sha256_hashes.txt'
            with open(sha256_file, 'w') as f:
                for hash_val in sha256_hashes:
                    f.write(f"{hash_val}\n")
            
            hash_files['sha256'] = str(sha256_file)
            
            # Sauvegarde de la correspondance pour validation
            mapping_file = self.hashes_dir / 'password_mapping.json'
            with open(mapping_file, 'w') as f:
                json.dump({
                    'passwords': demo_passwords,
                    'md5_hashes': md5_hashes,
                    'sha256_hashes': sha256_hashes
                }, f, indent=2)
            
            print(f"✅ Généré {len(demo_passwords)} hashs de démonstration")
            print(f"   📁 MD5: {md5_file}")
            print(f"   📁 SHA256: {sha256_file}")
            print(f"   📁 Mapping: {mapping_file}")
            
            return hash_files, demo_passwords
            
        except Exception as e:
            print(f"❌ Erreur lors de la génération des hashs: {e}")
            return {}, []
    
    def generate_custom_wordlists(self):
        """Génère des wordlists personnalisées pour l'audit"""
        print("\n📝 === GÉNÉRATION DE WORDLISTS PERSONNALISÉES ===")
        
        wordlists_created = []
        
        try:
            # 1. Wordlist basée sur le profil de l'entreprise
            print("🏢 Génération de la wordlist entreprise...")
            company_wordlist = self.wordlist_builder.build_from_company_info(
                company_name=self.audit_config['company_name'],
                industry=self.audit_config['industry'],
                location=self.audit_config['location'],
                max_words=2000
            )
            
            company_file = self.wordlist_builder.export_wordlist(
                company_wordlist,
                'acme_corporate_wordlist',
                format_type='txt',
                output_dir=str(self.wordlists_dir)
            )
            wordlists_created.append(company_file)
            
            # 2. Wordlist basée sur un profil employé type
            print("👤 Génération de la wordlist profil employé...")
            employee_profile = TargetProfile(
                first_names=['john', 'jane', 'mike', 'sarah', 'david', 'mary'],
                last_names=['smith', 'johnson', 'wilson', 'brown', 'davis', 'taylor'],
                company_names=['acme', 'acmecorp', 'acme corporation'],
                job_titles=['developer', 'manager', 'analyst', 'engineer'],
                departments=['it', 'engineering', 'sales', 'marketing', 'hr'],
                interests=['tech', 'coding', 'sports', 'travel', 'music'],
                birthdates=['1990', '1985', '1992', '1988', '1995']
            )
            
            profile_wordlist = self.wordlist_builder.build_from_profile(
                profile=employee_profile,
                enable_mutations=True,
                max_words=3000
            )
            
            profile_file = self.wordlist_builder.export_wordlist(
                profile_wordlist,
                'acme_employee_profile_wordlist',
                format_type='txt',
                output_dir=str(self.wordlists_dir)
            )
            wordlists_created.append(profile_file)
            
            # 3. Wordlist basée sur OSINT (simulation)
            print("🔍 Génération de la wordlist OSINT...")
            # En réel, ceci utiliserait des domaines réels
            osint_domains = ['example.com']  # Domaine d'exemple
            osint_wordlist = self.wordlist_builder.build_from_osint(
                domains=osint_domains,
                max_words=1500
            )
            
            osint_file = self.wordlist_builder.export_wordlist(
                osint_wordlist,
                'acme_osint_wordlist',
                format_type='txt',
                output_dir=str(self.wordlists_dir)
            )
            wordlists_created.append(osint_file)
            
            # 4. Wordlist combinée optimisée
            print("🔗 Création de la wordlist combinée...")
            combined_words = list(set(company_wordlist + profile_wordlist + osint_wordlist))
            
            combined_file = self.wordlist_builder.export_wordlist(
                combined_words,
                'acme_master_wordlist',
                format_type='json',
                output_dir=str(self.wordlists_dir)
            )
            wordlists_created.append(combined_file)
            
            print(f"✅ {len(wordlists_created)} wordlists créées avec succès:")
            for i, wordlist_file in enumerate(wordlists_created, 1):
                print(f"   {i}. {Path(wordlist_file).name}")
            
            return wordlists_created
            
        except Exception as e:
            print(f"❌ Erreur lors de la génération des wordlists: {e}")
            return []
    
    def run_hashcat_attacks(self, hash_files, wordlists):
        """Lance les attaques Hashcat avec différentes stratégies"""
        print("\n⚡ === LANCEMENT DES ATTAQUES HASHCAT ===")
        
        attack_results = []
        
        # Configuration des attaques à lancer
        attack_scenarios = [
            {
                'name': 'Quick MD5 Dictionary',
                'hash_file': hash_files.get('md5'),
                'hash_type': HashType.MD5,
                'wordlist': wordlists[0] if wordlists else None,
                'description': 'Attaque rapide par dictionnaire sur MD5'
            },
            {
                'name': 'Custom Wordlist SHA256',
                'hash_file': hash_files.get('sha256'),
                'hash_type': HashType.SHA256,
                'wordlist': wordlists[-1] if wordlists else None,  # Master wordlist
                'description': 'Attaque avec wordlist personnalisée sur SHA256'
            }
        ]
        
        for i, scenario in enumerate(attack_scenarios, 1):
            if not scenario['hash_file'] or not scenario['wordlist']:
                print(f"⏭️  Scénario {i} ignoré (fichiers manquants)")
                continue
            
            print(f"\n🎯 Scénario {i}: {scenario['name']}")
            print(f"   📄 Description: {scenario['description']}")
            
            try:
                # Configuration de l'attaque
                config = AttackConfig(
                    hash_file=scenario['hash_file'],
                    hash_type=scenario['hash_type'],
                    wordlists=[scenario['wordlist']],
                    session_name=f"demo_attack_{i}_{self.timestamp}",
                    runtime_limit=300,  # 5 minutes max pour la démo
                    workload_profile=2  # Performance modérée pour la démo
                )
                
                # Configuration des callbacks pour monitoring
                def progress_callback(line):
                    if "Progress" in line:
                        print(f"   📊 {line.strip()}")
                
                def monitor_callback(data):
                    if data['runtime'] % 30 == 0:  # Toutes les 30 secondes
                        print(f"   ⏱️  Runtime: {data['runtime']}s, "
                              f"GPU: {data['gpu_utilization']:.1f}%")
                
                self.hashcat_manager.set_callback("progress", progress_callback)
                self.hashcat_manager.set_callback("monitor", monitor_callback)
                
                # Lancement de l'attaque
                print(f"   🚀 Démarrage de l'attaque...")
                start_time = time.time()
                
                result = self.hashcat_manager.dictionary_attack(config)
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Affichage des résultats
                print(f"   ✅ Attaque terminée en {duration:.1f}s")
                print(f"   📊 Résultats:")
                print(f"      - Hashs crackés: {result.cracked_hashes}/{result.total_hashes}")
                print(f"      - Taux de succès: {result.success_rate:.1%}")
                print(f"      - Vitesse: {result.hash_rate}")
                
                attack_results.append(result)
                
                # Export du résultat
                report_file = self.results_dir / f"attack_{i}_report.html"
                self.hashcat_manager.export_result(result, str(report_file), "html")
                print(f"   📄 Rapport sauvé: {report_file.name}")
                
            except Exception as e:
                print(f"   ❌ Erreur lors de l'attaque {i}: {e}")
                continue
        
        return attack_results
    
    def analyze_cracked_passwords(self, demo_passwords):
        """Analyse les mots de passe crackés"""
        print("\n📊 === ANALYSE DES MOTS DE PASSE ===")
        
        try:
            # Analyse du dataset complet
            print("🔍 Analyse statistique du dataset...")
            analysis = self.password_analyzer.analyze_dataset(demo_passwords)
            
            # Affichage des résultats principaux
            print(f"\n📈 Résultats de l'analyse:")
            print(f"   Total des mots de passe: {analysis.total_passwords}")
            print(f"   Mots de passe uniques: {analysis.unique_passwords}")
            print(f"   Taux de duplication: {analysis.duplicate_rate:.1%}")
            
            print(f"\n🔢 Distribution des longueurs:")
            for length, count in sorted(analysis.length_distribution.items())[:10]:
                percentage = (count / analysis.total_passwords) * 100
                print(f"      {length} caractères: {count} ({percentage:.1f}%)")
            
            print(f"\n💪 Distribution de la force:")
            for strength, count in analysis.strength_distribution.items():
                percentage = (count / analysis.total_passwords) * 100
                print(f"      {strength}: {count} ({percentage:.1f}%)")
            
            print(f"\n🔍 Top 10 patterns détectés:")
            for pattern, count in analysis.top_patterns[:10]:
                print(f"      {pattern}: {count} occurrences")
            
            print(f"\n⚠️  Top 10 mots de passe vulnérables:")
            for pwd, count in analysis.top_passwords[:10]:
                print(f"      '{pwd}': {count} utilisations")
            
            # Export de l'analyse
            self.password_analyzer.export_analysis(
                analysis, 
                output_dir=str(self.results_dir)
            )
            
            print(f"\n✅ Analyse complète exportée dans {self.results_dir}")
            
            return analysis
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {e}")
            return None
    
    def generate_executive_summary(self, analysis, attack_results):
        """Génère un résumé exécutif de l'audit"""
        print("\n📋 === GÉNÉRATION DU RÉSUMÉ EXÉCUTIF ===")
        
        try:
            summary = {
                'audit_info': {
                    'company': self.audit_config['company_name'],
                    'date': datetime.now().isoformat(),
                    'scope': f"{analysis.total_passwords} comptes utilisateur",
                    'methodology': 'Analyse par dictionnaire et patterns'
                },
                'key_findings': {
                    'vulnerability_score': self._calculate_vulnerability_score(analysis),
                    'duplicate_rate': analysis.duplicate_rate,
                    'weak_passwords': self._count_weak_passwords(analysis),
                    'common_patterns': len(analysis.top_patterns)
                },
                'attack_effectiveness': {
                    'total_attacks': len(attack_results),
                    'average_success_rate': sum(r.success_rate for r in attack_results) / len(attack_results) if attack_results else 0,
                    'fastest_crack_time': min((r.runtime_seconds for r in attack_results), default=0)
                },
                'recommendations': analysis.recommendations[:10],  # Top 10
                'next_steps': [
                    "Implémenter une politique de mots de passe robuste",
                    "Déployer l'authentification multifacteur (MFA)",
                    "Organiser une formation de sensibilisation",
                    "Mettre en place une vérification périodique",
                    "Considérer l'usage de gestionnaires de mots de passe"
                ]
            }
            
            # Sauvegarde du résumé
            summary_file = self.results_dir / f'executive_summary_{self.timestamp}.json'
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            # Affichage du résumé
            print(f"🎯 Résumé Exécutif - Audit {self.audit_config['company_name']}")
            print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
            print(f"🔍 Portée: {summary['audit_info']['scope']}")
            
            print(f"\n🚨 Principales Vulnérabilités:")
            print(f"   Score de vulnérabilité: {summary['key_findings']['vulnerability_score']:.1f}/10")
            print(f"   Mots de passe dupliqués: {summary['key_findings']['duplicate_rate']:.1%}")
            print(f"   Mots de passe faibles: {summary['key_findings']['weak_passwords']}")
            
            print(f"\n⚡ Efficacité des Attaques:")
            if attack_results:
                print(f"   Attaques lancées: {summary['attack_effectiveness']['total_attacks']}")
                print(f"   Taux de succès moyen: {summary['attack_effectiveness']['average_success_rate']:.1%}")
            
            print(f"\n💡 Recommandations Prioritaires:")
            for i, rec in enumerate(summary['recommendations'][:5], 1):
                print(f"   {i}. {rec}")
            
            print(f"\n✅ Résumé sauvé: {summary_file}")
            
            return summary
            
        except Exception as e:
            print(f"❌ Erreur lors de la génération du résumé: {e}")
            return None
    
    def _calculate_vulnerability_score(self, analysis):
        """Calcule un score de vulnérabilité (0-10)"""
        score = 0
        
        # Duplication
        if analysis.duplicate_rate > 0.3:
            score += 3
        elif analysis.duplicate_rate > 0.1:
            score += 1.5
        
        # Mots de passe faibles
        weak_count = (analysis.strength_distribution.get('very_weak', 0) + 
                     analysis.strength_distribution.get('weak', 0))
        weak_ratio = weak_count / analysis.total_passwords
        
        if weak_ratio > 0.5:
            score += 4
        elif weak_ratio > 0.3:
            score += 2
        elif weak_ratio > 0.1:
            score += 1
        
        # Patterns communs
        if len(analysis.top_patterns) > 20:
            score += 2
        elif len(analysis.top_patterns) > 10:
            score += 1
        
        # Longueurs courtes
        short_passwords = sum(count for length, count in analysis.length_distribution.items() if length < 8)
        short_ratio = short_passwords / analysis.total_passwords
        
        if short_ratio > 0.3:
            score += 1
        
        return min(10, score)
    
    def _count_weak_passwords(self, analysis):
        """Compte les mots de passe faibles"""
        return (analysis.strength_distribution.get('very_weak', 0) + 
                analysis.strength_distribution.get('weak', 0))
    
    def run_complete_demo(self):
        """Lance la démonstration complète"""
        print("🎭 DÉMONSTRATION COMPLÈTE - AUDIT DE SÉCURITÉ DES MOTS DE PASSE")
        print("=" * 80)
        print(f"🏢 Entreprise: {self.audit_config['company_name']}")
        print(f"📍 Localisation: {self.audit_config['location']}")
        print(f"🏭 Secteur: {self.audit_config['industry']}")
        print(f"👥 Employés: {self.audit_config['employee_count']}")
        print("=" * 80)
        print("⚠️  AVERTISSEMENT: Démonstration à des fins éducatives uniquement")
        print("=" * 80)
        
        try:
            # Étape 1: Génération des hashs de démonstration
            hash_files, demo_passwords = self.generate_demo_hashes()
            if not hash_files:
                raise Exception("Impossible de générer les hashs de démonstration")
            
            # Étape 2: Génération des wordlists personnalisées
            wordlists = self.generate_custom_wordlists()
            
            # Étape 3: Attaques Hashcat (si disponible)
            attack_results = []
            if self.hashcat_manager and wordlists:
                try:
                    attack_results = self.run_hashcat_attacks(hash_files, wordlists)
                except Exception as e:
                    print(f"⚠️  Attaques Hashcat ignorées: {e}")
            
            # Étape 4: Analyse des mots de passe
            analysis = self.analyze_cracked_passwords(demo_passwords)
            if not analysis:
                raise Exception("Impossible d'analyser les mots de passe")
            
            # Étape 5: Résumé exécutif
            summary = self.generate_executive_summary(analysis, attack_results)
            
            # Conclusion
            print("\n🎉 === DÉMONSTRATION TERMINÉE ===")
            print(f"📁 Tous les résultats sont disponibles dans: {self.demo_dir}")
            print("\n📊 Fichiers générés:")
            
            for result_file in self.results_dir.rglob('*'):
                if result_file.is_file():
                    print(f"   📄 {result_file.name}")
            
            print(f"\n✅ Audit de sécurité complété avec succès!")
            print(f"⏱️  Durée totale: ~{time.time() - self._start_time:.1f} secondes")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Erreur lors de la démonstration: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        self._start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type:
            print(f"\n💥 Erreur détectée: {exc_val}")
        
        # Nettoyage si nécessaire
        print("\n🧹 Nettoyage terminé")


def main():
    """Fonction principale"""
    print("🚀 Démarrage de la démonstration d'audit de sécurité...")
    
    # Vérification de l'environnement
    if not check_environment():
        sys.exit(1)
    
    # Lancement de la démonstration complète
    with PasswordAuditDemo("ACME_Corp_Security_Audit_2024") as demo:
        success = demo.run_complete_demo()
    
    if success:
        print("\n🎯 Démonstration réussie!")
        print("📚 Consultez la documentation pour plus d'informations.")
    else:
        print("\n💔 La démonstration a échoué.")
        sys.exit(1)


def check_environment():
    """Vérifie l'environnement avant le lancement"""
    print("🔍 Vérification de l'environnement...")
    
    # Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requis")
        return False
    
    # Répertoires requis
    required_dirs = ['src', 'examples']
    for dirname in required_dirs:
        dir_path = project_root / dirname
        if not dir_path.exists():
            print(f"❌ Répertoire manquant: {dirname}")
            return False
    
    print("✅ Environnement vérifié")
    return True


if __name__ == "__main__":
    main()