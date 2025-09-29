#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Forensic Analysis Toolkit - Main CLI Interface
============================================================================
Interface principale pour orchestrer tous les modules d'analyse forensique :
- Analyse disque (images, fichiers, malware, récupération)
- Analyse mémoire (processus, injections, artefacts)
- Analyse réseau (PCAP, flux, menaces, géolocalisation)
- Analyse mobile (iOS/Android, communications, géolocalisation)
- Analyse cryptographique (chiffrement, stéganographie, certificats)
- Analyse timeline (corrélation temporelle, reconstruction)
- Corrélation IA (machine learning, hypothèses, MITRE ATT&CK)
- Génération de rapports (HTML, PDF, JSON, conformité)

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import argparse
import asyncio
import logging
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import traceback
import signal
import time

# Configuration du chemin pour les modules
sys.path.append(str(Path(__file__).parent / "src"))

# Import des modules forensiques
try:
    from disk_analyzer.disk_analyzer import DiskAnalyzer
    from memory_analyzer.memory_analyzer import MemoryAnalyzer
    from network_analyzer.network_analyzer import NetworkAnalyzer
    from mobile_analyzer.mobile_analyzer import MobileAnalyzer
    from crypto_analyzer.crypto_analyzer import CryptoAnalyzer
    from timeline_analyzer.timeline_analyzer import TimelineAnalyzer
    from ai_correlator.ai_correlator import AICorrelator
    from reporting.reporting_engine import ReportingEngine, CaseInformation, ReportType, ReportFormat
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Erreur importation modules: {e}")
    MODULES_AVAILABLE = False

# Bibliothèques pour interface avancée
try:
    import rich
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Configuration du logging
def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Configure le système de logging"""
    level = getattr(logging, log_level.upper())
    
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )

logger = logging.getLogger(__name__)

class ForensicToolkit:
    """
    Interface principale du Forensic Analysis Toolkit
    """
    
    def __init__(self, evidence_dir: str = "./evidence", output_dir: str = "./output"):
        """
        Initialise le toolkit forensique
        
        Args:
            evidence_dir: Répertoire des preuves
            output_dir: Répertoire de sortie
        """
        self.evidence_dir = Path(evidence_dir)
        self.output_dir = Path(output_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Console Rich si disponible
        self.console = Console() if RICH_AVAILABLE else None
        
        # Initialisation des analyseurs
        self.analyzers = {}
        self.current_case = None
        self.analysis_results = {}
        
        # Statistiques d'exécution
        self.execution_stats = {
            'start_time': None,
            'end_time': None,
            'modules_executed': [],
            'errors': [],
            'warnings': []
        }
        
        # Gestion des signaux pour arrêt propre
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self._initialize_analyzers()
    
    def _signal_handler(self, signum, frame):
        """Gestionnaire de signaux pour arrêt propre"""
        if self.console:
            self.console.print("\n🛑 Arrêt du toolkit en cours...", style="bold red")
        else:
            print("\n🛑 Arrêt du toolkit en cours...")
        
        self._cleanup()
        sys.exit(0)
    
    def _initialize_analyzers(self):
        """Initialise tous les analyseurs forensiques"""
        if not MODULES_AVAILABLE:
            logger.error("Modules forensiques non disponibles")
            return
        
        try:
            # Création des répertoires spécialisés
            modules_dirs = {
                'disk': self.evidence_dir / 'disk',
                'memory': self.evidence_dir / 'memory', 
                'network': self.evidence_dir / 'network',
                'mobile': self.evidence_dir / 'mobile',
                'crypto': self.evidence_dir / 'crypto',
                'timeline': self.evidence_dir / 'timeline',
                'reports': self.output_dir / 'reports',
                'models': self.output_dir / 'models'
            }
            
            for dir_path in modules_dirs.values():
                dir_path.mkdir(parents=True, exist_ok=True)
            
            # Initialisation des analyseurs
            self.analyzers = {
                'disk': DiskAnalyzer(str(modules_dirs['disk'])),
                'memory': MemoryAnalyzer(str(modules_dirs['memory'])),
                'network': NetworkAnalyzer(str(modules_dirs['network'])),
                'mobile': MobileAnalyzer(str(modules_dirs['mobile'])),
                'crypto': CryptoAnalyzer(str(modules_dirs['crypto'])),
                'timeline': TimelineAnalyzer(str(modules_dirs['timeline'])),
                'ai': AICorrelator(str(self.evidence_dir), str(modules_dirs['models'])),
                'reporting': ReportingEngine(str(self.evidence_dir), str(modules_dirs['reports']))
            }
            
            logger.info("Tous les analyseurs initialisés avec succès")
            
        except Exception as e:
            logger.error(f"Erreur initialisation analyseurs: {e}")
            raise
    
    def print_banner(self):
        """Affiche la bannière du toolkit"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔍 FORENSIC ANALYSIS TOOLKIT v2.1.0                      ║
║                         Cybersecurity Portfolio                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  📊 Disk Analysis    │  🧠 Memory Analysis   │  🌐 Network Analysis         ║
║  📱 Mobile Analysis  │  🔒 Crypto Analysis   │  🕒 Timeline Analysis        ║
║  🤖 AI Correlator    │  📋 Report Generation │  🎯 MITRE ATT&CK Mapping    ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        if self.console:
            self.console.print(banner, style="bold cyan")
        else:
            print(banner)
    
    def create_case(self, case_id: str, case_name: str, investigator: str, 
                   organization: str, incident_type: str, description: str) -> CaseInformation:
        """
        Crée un nouveau cas d'investigation
        
        Args:
            case_id: Identifiant unique du cas
            case_name: Nom du cas
            investigator: Nom de l'enquêteur
            organization: Organisation
            incident_type: Type d'incident
            description: Description du cas
            
        Returns:
            Informations du cas créé
        """
        case_info = CaseInformation(
            case_id=case_id,
            case_name=case_name,
            investigator=investigator,
            organization=organization,
            case_date=datetime.now(timezone.utc),
            incident_type=incident_type,
            description=description
        )
        
        self.current_case = case_info
        
        # Création du répertoire du cas
        case_dir = self.evidence_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Sauvegarde des informations du cas
        case_file = case_dir / "case_info.json"
        with open(case_file, 'w', encoding='utf-8') as f:
            json.dump({
                'case_id': case_info.case_id,
                'case_name': case_info.case_name,
                'investigator': case_info.investigator,
                'organization': case_info.organization,
                'case_date': case_info.case_date.isoformat(),
                'incident_type': case_info.incident_type,
                'description': case_info.description,
                'created_with': 'Forensic Analysis Toolkit v2.1.0'
            }, indent=2, ensure_ascii=False)
        
        if self.console:
            panel = Panel(
                f"[bold green]✅ Cas créé avec succès[/bold green]\n\n"
                f"[bold]ID:[/bold] {case_id}\n"
                f"[bold]Nom:[/bold] {case_name}\n"
                f"[bold]Enquêteur:[/bold] {investigator}\n"
                f"[bold]Type:[/bold] {incident_type}",
                title="Nouveau Cas",
                border_style="green"
            )
            self.console.print(panel)
        else:
            print(f"✅ Cas créé: {case_id} - {case_name}")
        
        logger.info(f"Nouveau cas créé: {case_id}")
        return case_info
    
    def load_case(self, case_id: str) -> Optional[CaseInformation]:
        """
        Charge un cas existant
        
        Args:
            case_id: Identifiant du cas
            
        Returns:
            Informations du cas chargé
        """
        case_dir = self.evidence_dir / case_id
        case_file = case_dir / "case_info.json"
        
        if not case_file.exists():
            logger.error(f"Cas non trouvé: {case_id}")
            return None
        
        try:
            with open(case_file, 'r', encoding='utf-8') as f:
                case_data = json.load(f)
            
            case_info = CaseInformation(
                case_id=case_data['case_id'],
                case_name=case_data['case_name'],
                investigator=case_data['investigator'],
                organization=case_data['organization'],
                case_date=datetime.fromisoformat(case_data['case_date']),
                incident_type=case_data['incident_type'],
                description=case_data['description']
            )
            
            self.current_case = case_info
            logger.info(f"Cas chargé: {case_id}")
            return case_info
            
        except Exception as e:
            logger.error(f"Erreur chargement cas {case_id}: {e}")
            return None
    
    def list_cases(self) -> List[Dict[str, Any]]:
        """Liste tous les cas disponibles"""
        cases = []
        
        if not self.evidence_dir.exists():
            return cases
        
        for case_dir in self.evidence_dir.iterdir():
            if case_dir.is_dir():
                case_file = case_dir / "case_info.json"
                if case_file.exists():
                    try:
                        with open(case_file, 'r', encoding='utf-8') as f:
                            case_data = json.load(f)
                        cases.append(case_data)
                    except Exception as e:
                        logger.warning(f"Erreur lecture cas {case_dir.name}: {e}")
        
        return sorted(cases, key=lambda x: x.get('case_date', ''), reverse=True)
    
    async def run_disk_analysis(self, target_path: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse disque
        
        Args:
            target_path: Chemin vers l'image disque ou répertoire
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['disk']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🔍 Analyse disque en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.analyze_disk_image, target_path, case_id
                )
        else:
            print("🔍 Analyse disque en cours...")
            results = analyzer.analyze_disk_image(target_path, case_id)
        
        self.analysis_results['disk'] = results
        self.execution_stats['modules_executed'].append('disk')
        
        logger.info(f"Analyse disque terminée pour {target_path}")
        return results
    
    async def run_memory_analysis(self, memory_dump_path: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse mémoire
        
        Args:
            memory_dump_path: Chemin vers le dump mémoire
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['memory']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🧠 Analyse mémoire en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.analyze_memory_dump, memory_dump_path, case_id
                )
        else:
            print("🧠 Analyse mémoire en cours...")
            results = analyzer.analyze_memory_dump(memory_dump_path, case_id)
        
        self.analysis_results['memory'] = results
        self.execution_stats['modules_executed'].append('memory')
        
        logger.info(f"Analyse mémoire terminée pour {memory_dump_path}")
        return results
    
    async def run_network_analysis(self, pcap_path: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse réseau
        
        Args:
            pcap_path: Chemin vers le fichier PCAP
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['network']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🌐 Analyse réseau en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.analyze_pcap, pcap_path, case_id
                )
        else:
            print("🌐 Analyse réseau en cours...")
            results = analyzer.analyze_pcap(pcap_path, case_id)
        
        self.analysis_results['network'] = results
        self.execution_stats['modules_executed'].append('network')
        
        logger.info(f"Analyse réseau terminée pour {pcap_path}")
        return results
    
    async def run_mobile_analysis(self, backup_path: str, device_type: str = "ios", **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse mobile
        
        Args:
            backup_path: Chemin vers la sauvegarde mobile
            device_type: Type d'appareil (ios/android)
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['mobile']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status(f"📱 Analyse mobile {device_type.upper()} en cours..."):
                if device_type.lower() == "ios":
                    results = await asyncio.get_event_loop().run_in_executor(
                        None, analyzer.analyze_ios_backup, backup_path, case_id
                    )
                else:
                    results = await asyncio.get_event_loop().run_in_executor(
                        None, analyzer.analyze_android_backup, backup_path, case_id
                    )
        else:
            print(f"📱 Analyse mobile {device_type.upper()} en cours...")
            if device_type.lower() == "ios":
                results = analyzer.analyze_ios_backup(backup_path, case_id)
            else:
                results = analyzer.analyze_android_backup(backup_path, case_id)
        
        self.analysis_results['mobile'] = results
        self.execution_stats['modules_executed'].append('mobile')
        
        logger.info(f"Analyse mobile {device_type} terminée pour {backup_path}")
        return results
    
    async def run_crypto_analysis(self, target_path: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse cryptographique
        
        Args:
            target_path: Chemin vers le fichier ou répertoire à analyser
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['crypto']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🔒 Analyse cryptographique en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.analyze_file, target_path, case_id
                )
        else:
            print("🔒 Analyse cryptographique en cours...")
            results = analyzer.analyze_file(target_path, case_id)
        
        self.analysis_results['crypto'] = results
        self.execution_stats['modules_executed'].append('crypto')
        
        logger.info(f"Analyse cryptographique terminée pour {target_path}")
        return results
    
    async def run_timeline_analysis(self, **kwargs) -> Dict[str, Any]:
        """
        Exécute l'analyse timeline
        
        Args:
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['timeline']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🕒 Analyse timeline en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.create_timeline, case_id
                )
        else:
            print("🕒 Analyse timeline en cours...")
            results = analyzer.create_timeline(case_id)
        
        self.analysis_results['timeline'] = results
        self.execution_stats['modules_executed'].append('timeline')
        
        logger.info("Analyse timeline terminée")
        return results
    
    async def run_ai_correlation(self, **kwargs) -> Dict[str, Any]:
        """
        Exécute la corrélation IA
        
        Args:
            **kwargs: Options supplémentaires
            
        Returns:
            Résultats de l'analyse
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        analyzer = self.analyzers['ai']
        case_id = self.current_case.case_id
        
        if self.console:
            with self.console.status("🤖 Corrélation IA en cours..."):
                results = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.perform_correlation_analysis, case_id
                )
        else:
            print("🤖 Corrélation IA en cours...")
            results = analyzer.perform_correlation_analysis(case_id)
        
        self.analysis_results['ai'] = results
        self.execution_stats['modules_executed'].append('ai')
        
        logger.info("Corrélation IA terminée")
        return results
    
    async def generate_report(self, report_type: str = "executive", report_format: str = "html", **kwargs) -> str:
        """
        Génère un rapport
        
        Args:
            report_type: Type de rapport (executive/technical)
            report_format: Format (html/pdf/json)
            **kwargs: Options supplémentaires
            
        Returns:
            Chemin vers le rapport généré
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        reporting_engine = self.analyzers['reporting']
        
        # Mapping des types de rapports
        report_type_map = {
            'executive': ReportType.EXECUTIVE_SUMMARY,
            'technical': ReportType.TECHNICAL_DETAILED,
            'investigation': ReportType.INVESTIGATION_SUMMARY,
            'timeline': ReportType.TIMELINE_ANALYSIS,
            'evidence': ReportType.EVIDENCE_CATALOG,
            'compliance': ReportType.COMPLIANCE_REPORT,
            'incident': ReportType.INCIDENT_RESPONSE
        }
        
        # Mapping des formats
        format_map = {
            'html': ReportFormat.HTML,
            'pdf': ReportFormat.PDF,
            'json': ReportFormat.JSON,
            'csv': ReportFormat.CSV,
            'markdown': ReportFormat.MARKDOWN
        }
        
        report_type_enum = report_type_map.get(report_type.lower(), ReportType.EXECUTIVE_SUMMARY)
        format_enum = format_map.get(report_format.lower(), ReportFormat.HTML)
        
        if self.console:
            with self.console.status(f"📋 Génération rapport {report_type} ({report_format})..."):
                report_path = await asyncio.get_event_loop().run_in_executor(
                    None, reporting_engine.generate_report, 
                    self.current_case.case_id, self.current_case, report_type_enum, format_enum
                )
        else:
            print(f"📋 Génération rapport {report_type} ({report_format})...")
            report_path = reporting_engine.generate_report(
                self.current_case.case_id, self.current_case, report_type_enum, format_enum
            )
        
        logger.info(f"Rapport généré: {report_path}")
        return report_path
    
    async def run_full_analysis(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécute une analyse complète selon la configuration
        
        Args:
            config: Configuration d'analyse
            
        Returns:
            Résultats consolidés
        """
        if not self.current_case:
            raise ValueError("Aucun cas actif. Créez ou chargez un cas d'abord.")
        
        self.execution_stats['start_time'] = datetime.now(timezone.utc)
        results = {}
        
        if self.console:
            self.console.print("🚀 Début de l'analyse forensique complète", style="bold green")
        else:
            print("🚀 Début de l'analyse forensique complète")
        
        # Progression si Rich disponible
        if self.console and RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                
                total_tasks = sum(1 for k, v in config.items() if k.endswith('_path') and v)
                if config.get('run_timeline', False):
                    total_tasks += 1
                if config.get('run_ai', False):
                    total_tasks += 1
                
                task = progress.add_task("Analyse forensique", total=total_tasks)
                
                # Analyses individuelles
                if config.get('disk_path'):
                    progress.update(task, description="Analyse disque...")
                    try:
                        results['disk'] = await self.run_disk_analysis(config['disk_path'])
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Disk analysis: {e}")
                        logger.error(f"Erreur analyse disque: {e}")
                
                if config.get('memory_path'):
                    progress.update(task, description="Analyse mémoire...")
                    try:
                        results['memory'] = await self.run_memory_analysis(config['memory_path'])
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Memory analysis: {e}")
                        logger.error(f"Erreur analyse mémoire: {e}")
                
                if config.get('network_path'):
                    progress.update(task, description="Analyse réseau...")
                    try:
                        results['network'] = await self.run_network_analysis(config['network_path'])
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Network analysis: {e}")
                        logger.error(f"Erreur analyse réseau: {e}")
                
                if config.get('mobile_path'):
                    progress.update(task, description="Analyse mobile...")
                    try:
                        device_type = config.get('mobile_type', 'ios')
                        results['mobile'] = await self.run_mobile_analysis(config['mobile_path'], device_type)
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Mobile analysis: {e}")
                        logger.error(f"Erreur analyse mobile: {e}")
                
                if config.get('crypto_path'):
                    progress.update(task, description="Analyse cryptographique...")
                    try:
                        results['crypto'] = await self.run_crypto_analysis(config['crypto_path'])
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Crypto analysis: {e}")
                        logger.error(f"Erreur analyse cryptographique: {e}")
                
                if config.get('run_timeline', False):
                    progress.update(task, description="Analyse timeline...")
                    try:
                        results['timeline'] = await self.run_timeline_analysis()
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"Timeline analysis: {e}")
                        logger.error(f"Erreur analyse timeline: {e}")
                
                if config.get('run_ai', False):
                    progress.update(task, description="Corrélation IA...")
                    try:
                        results['ai'] = await self.run_ai_correlation()
                        progress.advance(task)
                    except Exception as e:
                        self.execution_stats['errors'].append(f"AI correlation: {e}")
                        logger.error(f"Erreur corrélation IA: {e}")
                
                progress.update(task, description="✅ Analyse terminée")
        
        else:
            # Version sans Rich
            if config.get('disk_path'):
                try:
                    results['disk'] = await self.run_disk_analysis(config['disk_path'])
                except Exception as e:
                    self.execution_stats['errors'].append(f"Disk analysis: {e}")
                    logger.error(f"Erreur analyse disque: {e}")
            
            if config.get('memory_path'):
                try:
                    results['memory'] = await self.run_memory_analysis(config['memory_path'])
                except Exception as e:
                    self.execution_stats['errors'].append(f"Memory analysis: {e}")
                    logger.error(f"Erreur analyse mémoire: {e}")
            
            if config.get('network_path'):
                try:
                    results['network'] = await self.run_network_analysis(config['network_path'])
                except Exception as e:
                    self.execution_stats['errors'].append(f"Network analysis: {e}")
                    logger.error(f"Erreur analyse réseau: {e}")
            
            if config.get('mobile_path'):
                try:
                    device_type = config.get('mobile_type', 'ios')
                    results['mobile'] = await self.run_mobile_analysis(config['mobile_path'], device_type)
                except Exception as e:
                    self.execution_stats['errors'].append(f"Mobile analysis: {e}")
                    logger.error(f"Erreur analyse mobile: {e}")
            
            if config.get('crypto_path'):
                try:
                    results['crypto'] = await self.run_crypto_analysis(config['crypto_path'])
                except Exception as e:
                    self.execution_stats['errors'].append(f"Crypto analysis: {e}")
                    logger.error(f"Erreur analyse cryptographique: {e}")
            
            if config.get('run_timeline', False):
                try:
                    results['timeline'] = await self.run_timeline_analysis()
                except Exception as e:
                    self.execution_stats['errors'].append(f"Timeline analysis: {e}")
                    logger.error(f"Erreur analyse timeline: {e}")
            
            if config.get('run_ai', False):
                try:
                    results['ai'] = await self.run_ai_correlation()
                except Exception as e:
                    self.execution_stats['errors'].append(f"AI correlation: {e}")
                    logger.error(f"Erreur corrélation IA: {e}")
        
        self.execution_stats['end_time'] = datetime.now(timezone.utc)
        self.analysis_results.update(results)
        
        return results
    
    def display_analysis_summary(self):
        """Affiche un résumé des analyses"""
        if not self.analysis_results:
            if self.console:
                self.console.print("Aucune analyse effectuée", style="yellow")
            else:
                print("Aucune analyse effectuée")
            return
        
        if self.console and RICH_AVAILABLE:
            # Version Rich
            table = Table(title="Résumé des Analyses Forensiques")
            table.add_column("Module", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Éléments Analysés", justify="right", style="green")
            table.add_column("Éléments Suspects", justify="right", style="red")
            
            for module, results in self.analysis_results.items():
                if isinstance(results, dict):
                    status = "✅" if results.get('status') != 'error' else "❌"
                    
                    # Extraction des métriques selon le module
                    if module == 'disk':
                        analyzed = results.get('files_analyzed', 0)
                        suspicious = results.get('malware_detected', 0) + results.get('deleted_files', 0)
                    elif module == 'memory':
                        analyzed = results.get('processes_analyzed', 0)
                        suspicious = results.get('suspicious_processes', 0)
                    elif module == 'network':
                        analyzed = results.get('total_flows', 0)
                        suspicious = results.get('suspicious_domains', 0)
                    elif module == 'mobile':
                        analyzed = results.get('total_messages', 0) + results.get('total_calls', 0)
                        suspicious = results.get('suspicious_contacts', 0)
                    elif module == 'crypto':
                        analyzed = results.get('files_analyzed', 0)
                        suspicious = results.get('crypto_artifacts', 0) + results.get('stegano_artifacts', 0)
                    elif module == 'timeline':
                        analyzed = results.get('total_events', 0)
                        suspicious = results.get('anomalies_detected', 0)
                    elif module == 'ai':
                        analyzed = results.get('artifacts_analyzed', 0)
                        suspicious = results.get('anomalies', {}).get('count', 0)
                    else:
                        analyzed = 0
                        suspicious = 0
                    
                    table.add_row(
                        module.title(),
                        status,
                        str(analyzed),
                        str(suspicious)
                    )
            
            self.console.print(table)
            
            # Statistiques d'exécution
            if self.execution_stats['start_time'] and self.execution_stats['end_time']:
                duration = self.execution_stats['end_time'] - self.execution_stats['start_time']
                
                stats_panel = Panel(
                    f"[bold]Durée totale:[/bold] {duration.total_seconds():.1f} secondes\n"
                    f"[bold]Modules exécutés:[/bold] {len(self.execution_stats['modules_executed'])}\n"
                    f"[bold]Erreurs:[/bold] {len(self.execution_stats['errors'])}\n"
                    f"[bold]Avertissements:[/bold] {len(self.execution_stats['warnings'])}",
                    title="Statistiques d'Exécution",
                    border_style="blue"
                )
                self.console.print(stats_panel)
        
        else:
            # Version basique
            print("\n" + "="*50)
            print("RÉSUMÉ DES ANALYSES FORENSIQUES")
            print("="*50)
            
            for module, results in self.analysis_results.items():
                if isinstance(results, dict):
                    status = "✅" if results.get('status') != 'error' else "❌"
                    print(f"{module.upper():15} {status}")
            
            if self.execution_stats['start_time'] and self.execution_stats['end_time']:
                duration = self.execution_stats['end_time'] - self.execution_stats['start_time']
                print(f"\nDurée totale: {duration.total_seconds():.1f}s")
                print(f"Modules exécutés: {len(self.execution_stats['modules_executed'])}")
                print(f"Erreurs: {len(self.execution_stats['errors'])}")
    
    def _cleanup(self):
        """Nettoyage avant fermeture"""
        logger.info("Nettoyage des ressources...")
        # Fermeture des connexions, sauvegarde finale, etc.
    
    def save_session(self, session_path: str = None):
        """Sauvegarde la session actuelle"""
        if not session_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_path = self.output_dir / f"session_{timestamp}.json"
        
        session_data = {
            'toolkit_version': '2.1.0',
            'session_date': datetime.now(timezone.utc).isoformat(),
            'current_case': {
                'case_id': self.current_case.case_id,
                'case_name': self.current_case.case_name,
                'investigator': self.current_case.investigator,
                'organization': self.current_case.organization
            } if self.current_case else None,
            'execution_stats': {
                'start_time': self.execution_stats['start_time'].isoformat() if self.execution_stats['start_time'] else None,
                'end_time': self.execution_stats['end_time'].isoformat() if self.execution_stats['end_time'] else None,
                'modules_executed': self.execution_stats['modules_executed'],
                'errors': self.execution_stats['errors'],
                'warnings': self.execution_stats['warnings']
            },
            'analysis_summary': {
                module: {
                    'status': results.get('status', 'unknown') if isinstance(results, dict) else 'unknown',
                    'timestamp': results.get('timestamp', '') if isinstance(results, dict) else ''
                } for module, results in self.analysis_results.items()
            }
        }
        
        with open(session_path, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Session sauvegardée: {session_path}")
        return str(session_path)


class InteractiveMode:
    """
    Mode interactif pour le toolkit
    """
    
    def __init__(self, toolkit: ForensicToolkit):
        """
        Initialise le mode interactif
        
        Args:
            toolkit: Instance du toolkit forensique
        """
        self.toolkit = toolkit
        self.console = toolkit.console
    
    async def run(self):
        """Lance le mode interactif"""
        self.toolkit.print_banner()
        
        if self.console:
            self.console.print("🎯 Mode interactif activé", style="bold green")
            self.console.print("Tapez 'help' pour voir les commandes disponibles\n")
        else:
            print("🎯 Mode interactif activé")
            print("Tapez 'help' pour voir les commandes disponibles\n")
        
        while True:
            try:
                if RICH_AVAILABLE and self.console:
                    command = Prompt.ask("[bold cyan]forensic-toolkit[/bold cyan]", default="help")
                else:
                    command = input("forensic-toolkit> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd in ['exit', 'quit', 'q']:
                    break
                elif cmd == 'help' or cmd == 'h':
                    self._show_help()
                elif cmd == 'status':
                    self._show_status()
                elif cmd == 'cases':
                    self._list_cases()
                elif cmd == 'create-case':
                    await self._create_case_interactive()
                elif cmd == 'load-case':
                    await self._load_case_interactive(args)
                elif cmd == 'analyze':
                    await self._run_analysis_interactive(args)
                elif cmd == 'report':
                    await self._generate_report_interactive(args)
                elif cmd == 'summary':
                    self.toolkit.display_analysis_summary()
                elif cmd == 'save':
                    self._save_session()
                elif cmd == 'clear':
                    if self.console:
                        self.console.clear()
                    else:
                        os.system('clear' if os.name == 'posix' else 'cls')
                else:
                    if self.console:
                        self.console.print(f"❌ Commande inconnue: {cmd}", style="red")
                    else:
                        print(f"❌ Commande inconnue: {cmd}")
                
            except KeyboardInterrupt:
                if self.console:
                    self.console.print("\n🛑 Interruption utilisateur", style="yellow")
                else:
                    print("\n🛑 Interruption utilisateur")
                break
            except Exception as e:
                if self.console:
                    self.console.print(f"❌ Erreur: {e}", style="red")
                else:
                    print(f"❌ Erreur: {e}")
                logger.error(f"Erreur mode interactif: {e}")
        
        if self.console:
            self.console.print("👋 Au revoir!", style="bold green")
        else:
            print("👋 Au revoir!")
    
    def _show_help(self):
        """Affiche l'aide des commandes"""
        help_text = """
COMMANDES DISPONIBLES:

📋 Gestion des cas:
  cases                    - Liste tous les cas
  create-case             - Crée un nouveau cas (interactif)
  load-case <case_id>     - Charge un cas existant
  status                  - Affiche le statut actuel

🔍 Analyses:
  analyze disk <path>     - Analyse d'image disque
  analyze memory <path>   - Analyse de dump mémoire
  analyze network <path>  - Analyse de capture réseau
  analyze mobile <path>   - Analyse de sauvegarde mobile
  analyze crypto <path>   - Analyse cryptographique
  analyze timeline        - Analyse de timeline
  analyze ai              - Corrélation IA
  analyze all <config>    - Analyse complète

📊 Rapports:
  report executive        - Rapport exécutif
  report technical        - Rapport technique
  report <type> <format>  - Rapport personnalisé

⚙️  Utilitaires:
  summary                 - Résumé des analyses
  save                    - Sauvegarde la session
  clear                   - Nettoie l'écran
  help, h                 - Affiche cette aide
  exit, quit, q           - Quitte le programme
        """
        
        if self.console:
            self.console.print(help_text, style="cyan")
        else:
            print(help_text)
    
    def _show_status(self):
        """Affiche le statut actuel"""
        if self.toolkit.current_case:
            if self.console and RICH_AVAILABLE:
                panel = Panel(
                    f"[bold]ID:[/bold] {self.toolkit.current_case.case_id}\n"
                    f"[bold]Nom:[/bold] {self.toolkit.current_case.case_name}\n"
                    f"[bold]Enquêteur:[/bold] {self.toolkit.current_case.investigator}\n"
                    f"[bold]Type:[/bold] {self.toolkit.current_case.incident_type}",
                    title="Cas Actuel",
                    border_style="green"
                )
                self.console.print(panel)
            else:
                print(f"📁 Cas actuel: {self.toolkit.current_case.case_id} - {self.toolkit.current_case.case_name}")
        else:
            if self.console:
                self.console.print("❌ Aucun cas chargé", style="red")
            else:
                print("❌ Aucun cas chargé")
    
    def _list_cases(self):
        """Liste tous les cas"""
        cases = self.toolkit.list_cases()
        
        if not cases:
            if self.console:
                self.console.print("Aucun cas trouvé", style="yellow")
            else:
                print("Aucun cas trouvé")
            return
        
        if self.console and RICH_AVAILABLE:
            table = Table(title="Cases Disponibles")
            table.add_column("ID", style="cyan")
            table.add_column("Nom", style="white")
            table.add_column("Enquêteur", style="green")
            table.add_column("Date", style="yellow")
            table.add_column("Type", style="magenta")
            
            for case in cases:
                table.add_row(
                    case['case_id'],
                    case['case_name'],
                    case['investigator'],
                    case['case_date'][:10],
                    case['incident_type']
                )
            
            self.console.print(table)
        else:
            print("\n📁 Cas disponibles:")
            for case in cases:
                print(f"  {case['case_id']}: {case['case_name']} ({case['investigator']})")
    
    async def _create_case_interactive(self):
        """Crée un cas de manière interactive"""
        try:
            if RICH_AVAILABLE and self.console:
                case_id = Prompt.ask("ID du cas")
                case_name = Prompt.ask("Nom du cas")
                investigator = Prompt.ask("Enquêteur")
                organization = Prompt.ask("Organisation")
                incident_type = Prompt.ask("Type d'incident")
                description = Prompt.ask("Description")
            else:
                case_id = input("ID du cas: ").strip()
                case_name = input("Nom du cas: ").strip()
                investigator = input("Enquêteur: ").strip()
                organization = input("Organisation: ").strip()
                incident_type = input("Type d'incident: ").strip()
                description = input("Description: ").strip()
            
            if case_id and case_name and investigator:
                self.toolkit.create_case(case_id, case_name, investigator, organization, incident_type, description)
            else:
                if self.console:
                    self.console.print("❌ Informations manquantes", style="red")
                else:
                    print("❌ Informations manquantes")
        
        except Exception as e:
            if self.console:
                self.console.print(f"❌ Erreur création cas: {e}", style="red")
            else:
                print(f"❌ Erreur création cas: {e}")
    
    async def _load_case_interactive(self, args: List[str]):
        """Charge un cas"""
        if not args:
            if self.console:
                self.console.print("❌ Usage: load-case <case_id>", style="red")
            else:
                print("❌ Usage: load-case <case_id>")
            return
        
        case_id = args[0]
        case_info = self.toolkit.load_case(case_id)
        
        if case_info:
            if self.console:
                self.console.print(f"✅ Cas chargé: {case_id}", style="green")
            else:
                print(f"✅ Cas chargé: {case_id}")
        else:
            if self.console:
                self.console.print(f"❌ Cas non trouvé: {case_id}", style="red")
            else:
                print(f"❌ Cas non trouvé: {case_id}")
    
    async def _run_analysis_interactive(self, args: List[str]):
        """Lance une analyse"""
        if not args:
            if self.console:
                self.console.print("❌ Usage: analyze <type> [path]", style="red")
            else:
                print("❌ Usage: analyze <type> [path]")
            return
        
        analysis_type = args[0].lower()
        
        try:
            if analysis_type == 'disk' and len(args) > 1:
                await self.toolkit.run_disk_analysis(args[1])
            elif analysis_type == 'memory' and len(args) > 1:
                await self.toolkit.run_memory_analysis(args[1])
            elif analysis_type == 'network' and len(args) > 1:
                await self.toolkit.run_network_analysis(args[1])
            elif analysis_type == 'mobile' and len(args) > 1:
                device_type = args[2] if len(args) > 2 else 'ios'
                await self.toolkit.run_mobile_analysis(args[1], device_type)
            elif analysis_type == 'crypto' and len(args) > 1:
                await self.toolkit.run_crypto_analysis(args[1])
            elif analysis_type == 'timeline':
                await self.toolkit.run_timeline_analysis()
            elif analysis_type == 'ai':
                await self.toolkit.run_ai_correlation()
            else:
                if self.console:
                    self.console.print("❌ Type d'analyse invalide ou chemin manquant", style="red")
                else:
                    print("❌ Type d'analyse invalide ou chemin manquant")
        
        except Exception as e:
            if self.console:
                self.console.print(f"❌ Erreur analyse: {e}", style="red")
            else:
                print(f"❌ Erreur analyse: {e}")
    
    async def _generate_report_interactive(self, args: List[str]):
        """Génère un rapport"""
        report_type = args[0] if args else 'executive'
        report_format = args[1] if len(args) > 1 else 'html'
        
        try:
            report_path = await self.toolkit.generate_report(report_type, report_format)
            if self.console:
                self.console.print(f"✅ Rapport généré: {report_path}", style="green")
            else:
                print(f"✅ Rapport généré: {report_path}")
        
        except Exception as e:
            if self.console:
                self.console.print(f"❌ Erreur génération rapport: {e}", style="red")
            else:
                print(f"❌ Erreur génération rapport: {e}")
    
    def _save_session(self):
        """Sauvegarde la session"""
        try:
            session_path = self.toolkit.save_session()
            if self.console:
                self.console.print(f"✅ Session sauvegardée: {session_path}", style="green")
            else:
                print(f"✅ Session sauvegardée: {session_path}")
        
        except Exception as e:
            if self.console:
                self.console.print(f"❌ Erreur sauvegarde: {e}", style="red")
            else:
                print(f"❌ Erreur sauvegarde: {e}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Crée le parseur d'arguments"""
    parser = argparse.ArgumentParser(
        description="Forensic Analysis Toolkit v2.1.0 - Suite complète d'analyse forensique",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

  # Mode interactif
  ./forensic_toolkit.py -i

  # Créer un nouveau cas
  ./forensic_toolkit.py create-case --case-id CASE2024001 --case-name "Investigation Malware" --investigator "John Doe"

  # Analyse disque
  ./forensic_toolkit.py analyze disk --target /path/to/disk.img --case-id CASE2024001

  # Analyse complète
  ./forensic_toolkit.py analyze all --config analysis_config.json

  # Génération de rapport
  ./forensic_toolkit.py report --case-id CASE2024001 --type executive --format html
        """
    )
    
    # Arguments globaux
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    parser.add_argument('--log-file', help='Fichier de log')
    parser.add_argument('--evidence-dir', default='./evidence', help='Répertoire des preuves')
    parser.add_argument('--output-dir', default='./output', help='Répertoire de sortie')
    parser.add_argument('-i', '--interactive', action='store_true', help='Mode interactif')
    
    # Sous-commandes
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Sous-commande create-case
    case_parser = subparsers.add_parser('create-case', help='Créer un nouveau cas')
    case_parser.add_argument('--case-id', required=True, help='ID du cas')
    case_parser.add_argument('--case-name', required=True, help='Nom du cas')
    case_parser.add_argument('--investigator', required=True, help='Nom de l\'enquêteur')
    case_parser.add_argument('--organization', default='', help='Organisation')
    case_parser.add_argument('--incident-type', default='Investigation', help='Type d\'incident')
    case_parser.add_argument('--description', default='', help='Description du cas')
    
    # Sous-commande analyze
    analyze_parser = subparsers.add_parser('analyze', help='Lancer une analyse')
    analyze_subparsers = analyze_parser.add_subparsers(dest='analysis_type')
    
    # Analyse disque
    disk_parser = analyze_subparsers.add_parser('disk', help='Analyse disque')
    disk_parser.add_argument('--target', required=True, help='Chemin vers l\'image disque')
    disk_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse mémoire
    memory_parser = analyze_subparsers.add_parser('memory', help='Analyse mémoire')
    memory_parser.add_argument('--target', required=True, help='Chemin vers le dump mémoire')
    memory_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse réseau
    network_parser = analyze_subparsers.add_parser('network', help='Analyse réseau')
    network_parser.add_argument('--target', required=True, help='Chemin vers le fichier PCAP')
    network_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse mobile
    mobile_parser = analyze_subparsers.add_parser('mobile', help='Analyse mobile')
    mobile_parser.add_argument('--target', required=True, help='Chemin vers la sauvegarde mobile')
    mobile_parser.add_argument('--device-type', choices=['ios', 'android'], default='ios', help='Type d\'appareil')
    mobile_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse cryptographique
    crypto_parser = analyze_subparsers.add_parser('crypto', help='Analyse cryptographique')
    crypto_parser.add_argument('--target', required=True, help='Chemin vers le fichier')
    crypto_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse timeline
    timeline_parser = analyze_subparsers.add_parser('timeline', help='Analyse timeline')
    timeline_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Corrélation IA
    ai_parser = analyze_subparsers.add_parser('ai', help='Corrélation IA')
    ai_parser.add_argument('--case-id', required=True, help='ID du cas')
    
    # Analyse complète
    all_parser = analyze_subparsers.add_parser('all', help='Analyse complète')
    all_parser.add_argument('--config', required=True, help='Fichier de configuration JSON')
    
    # Sous-commande report
    report_parser = subparsers.add_parser('report', help='Générer un rapport')
    report_parser.add_argument('--case-id', required=True, help='ID du cas')
    report_parser.add_argument('--type', choices=['executive', 'technical', 'investigation', 'timeline', 'evidence', 'compliance', 'incident'], 
                              default='executive', help='Type de rapport')
    report_parser.add_argument('--format', choices=['html', 'pdf', 'json', 'csv', 'markdown'], 
                              default='html', help='Format de sortie')
    
    # Sous-commande list-cases
    subparsers.add_parser('list-cases', help='Lister tous les cas')
    
    return parser


async def main():
    """Fonction principale"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configuration du logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level, args.log_file)
    
    if not MODULES_AVAILABLE:
        print("❌ Erreur: Les modules forensiques ne sont pas disponibles.")
        print("   Vérifiez l'installation et les chemins d'importation.")
        return 1
    
    # Initialisation du toolkit
    toolkit = ForensicToolkit(args.evidence_dir, args.output_dir)
    
    try:
        # Mode interactif
        if args.interactive:
            interactive = InteractiveMode(toolkit)
            await interactive.run()
            return 0
        
        # Traitement des commandes
        if args.command == 'create-case':
            toolkit.create_case(
                args.case_id, args.case_name, args.investigator,
                args.organization, args.incident_type, args.description
            )
        
        elif args.command == 'list-cases':
            cases = toolkit.list_cases()
            if cases:
                print("📁 Cas disponibles:")
                for case in cases:
                    print(f"  {case['case_id']}: {case['case_name']} ({case['investigator']})")
            else:
                print("Aucun cas trouvé")
        
        elif args.command == 'analyze':
            # Charger le cas
            if not toolkit.load_case(args.case_id):
                print(f"❌ Cas non trouvé: {args.case_id}")
                return 1
            
            if args.analysis_type == 'disk':
                await toolkit.run_disk_analysis(args.target)
            elif args.analysis_type == 'memory':
                await toolkit.run_memory_analysis(args.target)
            elif args.analysis_type == 'network':
                await toolkit.run_network_analysis(args.target)
            elif args.analysis_type == 'mobile':
                await toolkit.run_mobile_analysis(args.target, args.device_type)
            elif args.analysis_type == 'crypto':
                await toolkit.run_crypto_analysis(args.target)
            elif args.analysis_type == 'timeline':
                await toolkit.run_timeline_analysis()
            elif args.analysis_type == 'ai':
                await toolkit.run_ai_correlation()
            elif args.analysis_type == 'all':
                with open(args.config, 'r') as f:
                    config = json.load(f)
                await toolkit.run_full_analysis(config)
            
            toolkit.display_analysis_summary()
        
        elif args.command == 'report':
            # Charger le cas
            if not toolkit.load_case(args.case_id):
                print(f"❌ Cas non trouvé: {args.case_id}")
                return 1
            
            report_path = await toolkit.generate_report(args.type, args.format)
            print(f"✅ Rapport généré: {report_path}")
        
        elif not args.command:
            # Pas de commande, afficher l'aide
            toolkit.print_banner()
            parser.print_help()
        
        # Sauvegarde automatique de la session
        if args.command and args.command != 'list-cases':
            toolkit.save_session()
    
    except KeyboardInterrupt:
        print("\n🛑 Interruption utilisateur")
        return 1
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        if args.verbose:
            traceback.print_exc()
        logger.error(f"Erreur fatale: {e}")
        return 1
    finally:
        toolkit._cleanup()
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)