#!/usr/bin/env python3
"""
DevSecOps Security Orchestrator
Orchestrateur principal pour coordonner tous les scanners de sécurité dans un pipeline CI/CD
"""

import os
import sys
import json
import yaml
import asyncio
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import hashlib
import concurrent.futures
from contextlib import asynccontextmanager
import logging

# Importer nos scanners personnalisés
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'security-scanners'))
from sast_scanner import SASTScanner, SASTReport
from dependency_scanner import DependencyScanner, DependencyScanReport
from config_scanner import ConfigScanner, ConfigScanReport

class ScanStage(Enum):
    PRE_BUILD = "pre_build"
    BUILD = "build" 
    POST_BUILD = "post_build"
    DEPLOY = "deploy"
    RUNTIME = "runtime"

class ScanType(Enum):
    SAST = "sast"
    DEPENDENCY = "dependency"
    CONFIG = "config"
    SECRETS = "secrets"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"

class OrchestrationMode(Enum):
    FAST = "fast"           # Scanners essentiels seulement
    STANDARD = "standard"   # Scanners recommandés
    COMPREHENSIVE = "comprehensive"  # Tous les scanners

class PipelineStage(Enum):
    STARTED = "started"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ScanJob:
    """Représente un job de scan individuel"""
    job_id: str
    scan_type: ScanType
    scanner_name: str
    stage: ScanStage
    priority: int = 5  # 1 = haute priorité, 10 = basse priorité
    timeout: int = 300  # timeout en secondes
    enabled: bool = True
    parallel: bool = True
    dependencies: List[str] = field(default_factory=list)  # Dépendances sur d'autres jobs
    config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Résultat d'un scan individuel"""
    job_id: str
    scan_type: ScanType
    status: str  # success, failed, timeout, skipped
    duration_seconds: float
    start_time: datetime
    end_time: Optional[datetime] = None
    report: Optional[Any] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class OrchestrationReport:
    """Rapport complet d'orchestration"""
    pipeline_id: str
    project_name: str
    orchestration_mode: OrchestrationMode
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    stage: PipelineStage = PipelineStage.STARTED
    scan_results: List[ScanResult] = field(default_factory=list)
    overall_status: str = "running"  # success, failed, warning
    security_gate_passed: bool = False
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    quality_gates: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)  # Chemins vers les rapports générés

class SecurityOrchestrator:
    """Orchestrateur principal de sécurité DevSecOps"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Initialiser les scanners
        self.scanners = self._initialize_scanners()
        
        # Définir les jobs de scan par mode
        self.scan_jobs = self._define_scan_jobs()
        
        # État de l'orchestrateur
        self.current_report: Optional[OrchestrationReport] = None
        self.executor = None

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Charge la configuration de l'orchestrateur"""
        default_config = {
            'orchestration': {
                'default_mode': 'standard',
                'max_parallel_jobs': 4,
                'global_timeout': 1800,  # 30 minutes
                'fail_fast': False,
                'continue_on_error': True
            },
            'quality_gates': {
                'critical_threshold': 0,  # Aucune vulnérabilité critique
                'high_threshold': 5,      # Max 5 vulnérabilités high
                'risk_score_threshold': 70.0,  # Score de risque max
                'dependency_age_days': 365,  # Age max des dépendances
                'code_coverage_min': 80.0    # Couverture de code min
            },
            'reporting': {
                'formats': ['json', 'sarif', 'html'],
                'output_dir': './security-reports',
                'archive_reports': True,
                'send_notifications': False
            },
            'scanners': {
                'sast': {
                    'enabled': True,
                    'timeout': 300,
                    'tools': ['bandit', 'semgrep'],
                    'exclude_patterns': ['*/test/*', '*/tests/*']
                },
                'dependency': {
                    'enabled': True,
                    'timeout': 180,
                    'include_dev_dependencies': False,
                    'vulnerability_sources': ['osv', 'github']
                },
                'config': {
                    'enabled': True,
                    'timeout': 120,
                    'compliance_frameworks': ['CIS', 'NIST']
                }
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                self._deep_merge(default_config, user_config)
        
        return default_config

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Merge profond de dictionnaires"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _setup_logging(self) -> logging.Logger:
        """Configure le logging pour l'orchestrateur"""
        logger = logging.getLogger('security_orchestrator')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger

    def _initialize_scanners(self) -> Dict[str, Any]:
        """Initialise tous les scanners disponibles"""
        scanners = {}
        
        try:
            if self.config['scanners']['sast']['enabled']:
                scanners['sast'] = SASTScanner()
                self.logger.info("✅ SAST Scanner initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize SAST Scanner: {e}")
        
        try:
            if self.config['scanners']['dependency']['enabled']:
                scanners['dependency'] = DependencyScanner()
                self.logger.info("✅ Dependency Scanner initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Dependency Scanner: {e}")
        
        try:
            if self.config['scanners']['config']['enabled']:
                scanners['config'] = ConfigScanner()
                self.logger.info("✅ Config Scanner initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Config Scanner: {e}")
        
        return scanners

    def _define_scan_jobs(self) -> Dict[OrchestrationMode, List[ScanJob]]:
        """Définit les jobs de scan pour chaque mode d'orchestration"""
        jobs = {
            OrchestrationMode.FAST: [
                ScanJob(
                    job_id="fast_sast",
                    scan_type=ScanType.SAST,
                    scanner_name="sast",
                    stage=ScanStage.PRE_BUILD,
                    priority=1,
                    timeout=120,
                    config={'quick_scan': True}
                ),
                ScanJob(
                    job_id="fast_deps",
                    scan_type=ScanType.DEPENDENCY,
                    scanner_name="dependency",
                    stage=ScanStage.PRE_BUILD,
                    priority=2,
                    timeout=60,
                    config={'critical_only': True}
                )
            ],
            
            OrchestrationMode.STANDARD: [
                ScanJob(
                    job_id="std_sast",
                    scan_type=ScanType.SAST,
                    scanner_name="sast",
                    stage=ScanStage.PRE_BUILD,
                    priority=1,
                    timeout=300
                ),
                ScanJob(
                    job_id="std_deps",
                    scan_type=ScanType.DEPENDENCY,
                    scanner_name="dependency",
                    stage=ScanStage.PRE_BUILD,
                    priority=2,
                    timeout=180,
                    parallel=True
                ),
                ScanJob(
                    job_id="std_config",
                    scan_type=ScanType.CONFIG,
                    scanner_name="config",
                    stage=ScanStage.BUILD,
                    priority=3,
                    timeout=120,
                    parallel=True
                )
            ],
            
            OrchestrationMode.COMPREHENSIVE: [
                ScanJob(
                    job_id="comp_sast",
                    scan_type=ScanType.SAST,
                    scanner_name="sast",
                    stage=ScanStage.PRE_BUILD,
                    priority=1,
                    timeout=600
                ),
                ScanJob(
                    job_id="comp_deps",
                    scan_type=ScanType.DEPENDENCY,
                    scanner_name="dependency",
                    stage=ScanStage.PRE_BUILD,
                    priority=2,
                    timeout=300,
                    parallel=True
                ),
                ScanJob(
                    job_id="comp_config",
                    scan_type=ScanType.CONFIG,
                    scanner_name="config",
                    stage=ScanStage.BUILD,
                    priority=3,
                    timeout=180,
                    parallel=True
                ),
                ScanJob(
                    job_id="comp_secrets",
                    scan_type=ScanType.SECRETS,
                    scanner_name="secrets",
                    stage=ScanStage.PRE_BUILD,
                    priority=4,
                    timeout=120,
                    parallel=True
                )
            ]
        }
        
        return jobs

    async def orchestrate_security_scan(
        self, 
        project_path: str, 
        project_name: str = None,
        mode: OrchestrationMode = OrchestrationMode.STANDARD,
        stage: ScanStage = ScanStage.PRE_BUILD
    ) -> OrchestrationReport:
        """Orchestre un scan de sécurité complet"""
        
        self.logger.info(f"🚀 Starting security orchestration for {project_path}")
        self.logger.info(f"📋 Mode: {mode.value}, Stage: {stage.value}")
        
        if not project_name:
            project_name = os.path.basename(os.path.abspath(project_path))
        
        # Initialiser le rapport
        pipeline_id = hashlib.md5(f"{project_name}_{datetime.now()}".encode()).hexdigest()
        start_time = datetime.now()
        
        report = OrchestrationReport(
            pipeline_id=pipeline_id,
            project_name=project_name,
            orchestration_mode=mode,
            start_time=start_time,
            stage=PipelineStage.STARTED
        )
        
        self.current_report = report
        
        try:
            # Créer le répertoire de sortie
            output_dir = Path(self.config['reporting']['output_dir'])
            output_dir.mkdir(parents=True, exist_ok=True)
            
            report.stage = PipelineStage.SCANNING
            
            # Obtenir les jobs pour le mode sélectionné
            jobs = self._get_jobs_for_mode_and_stage(mode, stage)
            
            if not jobs:
                self.logger.warning(f"⚠️ No scan jobs defined for mode {mode.value} and stage {stage.value}")
                report.overall_status = "success"
                report.security_gate_passed = True
                return report
            
            self.logger.info(f"📊 Executing {len(jobs)} scan jobs")
            
            # Exécuter les jobs
            scan_results = await self._execute_scan_jobs(jobs, project_path, project_name)
            report.scan_results = scan_results
            
            report.stage = PipelineStage.ANALYZING
            
            # Analyser les résultats
            await self._analyze_results(report)
            
            report.stage = PipelineStage.REPORTING
            
            # Générer les rapports
            await self._generate_reports(report, output_dir)
            
            # Évaluer les quality gates
            await self._evaluate_quality_gates(report)
            
            report.stage = PipelineStage.COMPLETED
            report.end_time = datetime.now()
            report.duration_seconds = (report.end_time - report.start_time).total_seconds()
            
            self.logger.info(f"✅ Security orchestration completed in {report.duration_seconds:.1f}s")
            self.logger.info(f"🎯 Overall Status: {report.overall_status}")
            self.logger.info(f"🚪 Security Gate: {'✅ PASSED' if report.security_gate_passed else '❌ FAILED'}")
            
            return report
            
        except Exception as e:
            self.logger.error(f"❌ Security orchestration failed: {e}")
            report.stage = PipelineStage.FAILED
            report.overall_status = "failed"
            report.end_time = datetime.now()
            report.duration_seconds = (report.end_time - report.start_time).total_seconds()
            return report

    def _get_jobs_for_mode_and_stage(self, mode: OrchestrationMode, stage: ScanStage) -> List[ScanJob]:
        """Obtient les jobs pour un mode et un stage donnés"""
        all_jobs = self.scan_jobs.get(mode, [])
        filtered_jobs = [job for job in all_jobs if job.stage == stage and job.enabled]
        
        # Trier par priorité
        filtered_jobs.sort(key=lambda x: x.priority)
        
        return filtered_jobs

    async def _execute_scan_jobs(self, jobs: List[ScanJob], project_path: str, project_name: str) -> List[ScanResult]:
        """Exécute les jobs de scan de manière optimale"""
        results = []
        
        # Séparer les jobs parallèles et séquentiels
        parallel_jobs = [job for job in jobs if job.parallel]
        sequential_jobs = [job for job in jobs if not job.parallel]
        
        # Exécuter les jobs séquentiels d'abord
        for job in sequential_jobs:
            self.logger.info(f"🔄 Executing sequential job: {job.job_id}")
            result = await self._execute_single_job(job, project_path, project_name)
            results.append(result)
            
            # Vérifier si on doit arrêter en cas d'erreur
            if result.status == "failed" and not self.config['orchestration']['continue_on_error']:
                self.logger.error(f"❌ Stopping execution due to failed job: {job.job_id}")
                break
        
        # Exécuter les jobs parallèles
        if parallel_jobs:
            self.logger.info(f"🔄 Executing {len(parallel_jobs)} parallel jobs")
            
            # Limiter le nombre de jobs parallèles
            max_parallel = self.config['orchestration']['max_parallel_jobs']
            
            # Créer des tâches pour l'exécution parallèle
            tasks = []
            for job in parallel_jobs:
                task = self._execute_single_job(job, project_path, project_name)
                tasks.append(task)
            
            # Exécuter avec limitation de concurrence
            semaphore = asyncio.Semaphore(max_parallel)
            
            async def run_with_semaphore(job, task):
                async with semaphore:
                    return await task
            
            parallel_tasks = [
                run_with_semaphore(job, task) 
                for job, task in zip(parallel_jobs, tasks)
            ]
            
            parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            
            for i, result in enumerate(parallel_results):
                if isinstance(result, Exception):
                    # Créer un résultat d'erreur
                    failed_result = ScanResult(
                        job_id=parallel_jobs[i].job_id,
                        scan_type=parallel_jobs[i].scan_type,
                        status="failed",
                        duration_seconds=0.0,
                        start_time=datetime.now(),
                        error=str(result)
                    )
                    results.append(failed_result)
                else:
                    results.append(result)
        
        return results

    async def _execute_single_job(self, job: ScanJob, project_path: str, project_name: str) -> ScanResult:
        """Exécute un job de scan individuel"""
        start_time = datetime.now()
        
        result = ScanResult(
            job_id=job.job_id,
            scan_type=job.scan_type,
            status="running",
            duration_seconds=0.0,
            start_time=start_time
        )
        
        try:
            self.logger.info(f"▶️ Starting {job.scanner_name} scan (job: {job.job_id})")
            
            # Obtenir le scanner approprié
            scanner = self.scanners.get(job.scanner_name)
            if not scanner:
                raise Exception(f"Scanner '{job.scanner_name}' not available")
            
            # Exécuter le scan avec timeout
            scan_task = self._run_scanner(scanner, job, project_path, project_name)
            report = await asyncio.wait_for(scan_task, timeout=job.timeout)
            
            result.report = report
            result.status = "success"
            result.end_time = datetime.now()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()
            
            self.logger.info(f"✅ {job.scanner_name} scan completed in {result.duration_seconds:.1f}s")
            
        except asyncio.TimeoutError:
            result.status = "timeout"
            result.error = f"Scan timed out after {job.timeout} seconds"
            result.end_time = datetime.now()
            result.duration_seconds = job.timeout
            self.logger.error(f"⏰ {job.scanner_name} scan timed out")
            
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.end_time = datetime.now()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()
            self.logger.error(f"❌ {job.scanner_name} scan failed: {e}")
        
        return result

    async def _run_scanner(self, scanner: Any, job: ScanJob, project_path: str, project_name: str) -> Any:
        """Exécute un scanner spécifique"""
        
        if job.scan_type == ScanType.SAST:
            return scanner.scan_project(project_path, project_name)
        
        elif job.scan_type == ScanType.DEPENDENCY:
            return await scanner.scan_project(project_path, project_name)
        
        elif job.scan_type == ScanType.CONFIG:
            return scanner.scan_project(project_path, project_name)
        
        else:
            raise Exception(f"Unsupported scan type: {job.scan_type}")

    async def _analyze_results(self, report: OrchestrationReport):
        """Analyse les résultats de tous les scans"""
        self.logger.info("🔍 Analyzing scan results")
        
        total_issues = 0
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        low_issues = 0
        
        failed_scans = 0
        successful_scans = 0
        
        for result in report.scan_results:
            if result.status == "success" and result.report:
                successful_scans += 1
                
                # Extraire les statistiques selon le type de rapport
                if hasattr(result.report, 'summary'):
                    summary = result.report.summary
                    total_issues += summary.get('total', 0)
                    critical_issues += summary.get('critical', 0)
                    high_issues += summary.get('high', 0)
                    medium_issues += summary.get('medium', 0)
                    low_issues += summary.get('low', 0)
                
                elif hasattr(result.report, 'issues'):
                    # Pour les rapports de configuration
                    for issue in result.report.issues:
                        total_issues += 1
                        if hasattr(issue, 'severity'):
                            severity = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                            if severity == 'critical':
                                critical_issues += 1
                            elif severity == 'high':
                                high_issues += 1
                            elif severity == 'medium':
                                medium_issues += 1
                            elif severity == 'low':
                                low_issues += 1
            
            elif result.status == "failed":
                failed_scans += 1
        
        # Mettre à jour le rapport
        report.total_issues = total_issues
        report.critical_issues = critical_issues
        report.high_issues = high_issues
        report.medium_issues = medium_issues
        report.low_issues = low_issues
        
        # Calculer le score de risque global
        report.risk_score = self._calculate_overall_risk_score(
            critical_issues, high_issues, medium_issues, low_issues
        )
        
        # Déterminer le statut global
        if failed_scans > 0:
            report.overall_status = "failed"
        elif critical_issues > 0 or high_issues > 0:
            report.overall_status = "warning"
        else:
            report.overall_status = "success"
        
        # Générer des recommandations
        report.recommendations = self._generate_recommendations(report)
        
        self.logger.info(f"📊 Analysis completed: {total_issues} total issues found")

    def _calculate_overall_risk_score(self, critical: int, high: int, medium: int, low: int) -> float:
        """Calcule un score de risque global"""
        # Pondération par sévérité
        score = (critical * 10.0) + (high * 7.0) + (medium * 4.0) + (low * 1.0)
        
        # Normaliser sur 100
        if score == 0:
            return 0.0
        
        # Formule logarithmique pour éviter des scores trop élevés
        import math
        normalized_score = min(100.0, math.log10(score + 1) * 30)
        
        return round(normalized_score, 1)

    def _generate_recommendations(self, report: OrchestrationReport) -> List[str]:
        """Génère des recommandations basées sur les résultats"""
        recommendations = []
        
        if report.critical_issues > 0:
            recommendations.append(f"🚨 {report.critical_issues} critical vulnerabilities require immediate attention")
        
        if report.high_issues > 0:
            recommendations.append(f"⚠️ {report.high_issues} high-severity issues should be addressed within 48 hours")
        
        if report.risk_score > 80:
            recommendations.append("📈 High risk score indicates significant security concerns")
        
        # Recommandations spécifiques par scanner
        failed_scans = [r for r in report.scan_results if r.status == "failed"]
        if failed_scans:
            recommendations.append(f"🔧 {len(failed_scans)} scans failed and should be investigated")
        
        # Recommandations générales
        recommendations.extend([
            "🔄 Implement regular automated security scanning",
            "📚 Provide security training to development team",
            "🛡️ Consider implementing runtime security monitoring"
        ])
        
        return recommendations

    async def _generate_reports(self, report: OrchestrationReport, output_dir: Path):
        """Génère les rapports dans différents formats"""
        self.logger.info("📄 Generating security reports")
        
        formats = self.config['reporting']['formats']
        
        # Rapport principal JSON
        if 'json' in formats:
            json_path = output_dir / f"security_report_{report.pipeline_id}.json"
            await self._generate_json_report(report, json_path)
            report.artifacts['json'] = str(json_path)
        
        # Rapport SARIF (pour intégration outils)
        if 'sarif' in formats:
            sarif_path = output_dir / f"security_report_{report.pipeline_id}.sarif"
            await self._generate_sarif_report(report, sarif_path)
            report.artifacts['sarif'] = str(sarif_path)
        
        # Rapport HTML (pour visualisation)
        if 'html' in formats:
            html_path = output_dir / f"security_report_{report.pipeline_id}.html"
            await self._generate_html_report(report, html_path)
            report.artifacts['html'] = str(html_path)
        
        self.logger.info(f"📄 Reports generated in {output_dir}")

    async def _generate_json_report(self, report: OrchestrationReport, output_path: Path):
        """Génère le rapport JSON principal"""
        data = {
            'pipeline_id': report.pipeline_id,
            'project_name': report.project_name,
            'orchestration_mode': report.orchestration_mode.value,
            'start_time': report.start_time.isoformat(),
            'end_time': report.end_time.isoformat() if report.end_time else None,
            'duration_seconds': report.duration_seconds,
            'stage': report.stage.value,
            'overall_status': report.overall_status,
            'security_gate_passed': report.security_gate_passed,
            'summary': {
                'total_issues': report.total_issues,
                'critical_issues': report.critical_issues,
                'high_issues': report.high_issues,
                'medium_issues': report.medium_issues,
                'low_issues': report.low_issues,
                'risk_score': report.risk_score
            },
            'scan_results': [
                {
                    'job_id': result.job_id,
                    'scan_type': result.scan_type.value,
                    'status': result.status,
                    'duration_seconds': result.duration_seconds,
                    'start_time': result.start_time.isoformat(),
                    'end_time': result.end_time.isoformat() if result.end_time else None,
                    'error': result.error,
                    'warnings': result.warnings,
                    'metadata': result.metadata
                }
                for result in report.scan_results
            ],
            'recommendations': report.recommendations,
            'quality_gates': report.quality_gates,
            'artifacts': report.artifacts
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    async def _generate_sarif_report(self, report: OrchestrationReport, output_path: Path):
        """Génère un rapport au format SARIF"""
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": []
        }
        
        for result in report.scan_results:
            if result.status == "success" and result.report:
                run = {
                    "tool": {
                        "driver": {
                            "name": f"DevSecOps {result.scan_type.value.upper()} Scanner",
                            "version": "1.0.0"
                        }
                    },
                    "results": []
                }
                
                # Extraire les résultats selon le type de rapport
                if hasattr(result.report, 'findings'):  # SAST
                    for finding in result.report.findings:
                        sarif_result = {
                            "ruleId": finding.rule_id,
                            "message": {"text": finding.description},
                            "level": self._severity_to_sarif_level(finding.severity.value),
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.file_path},
                                    "region": {"startLine": finding.line_number}
                                }
                            }]
                        }
                        run["results"].append(sarif_result)
                
                elif hasattr(result.report, 'issues'):  # Config
                    for issue in result.report.issues:
                        sarif_result = {
                            "ruleId": issue.rule_id,
                            "message": {"text": issue.description},
                            "level": self._severity_to_sarif_level(issue.severity.value),
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": issue.file_path},
                                    "region": {"startLine": issue.line_number or 1}
                                }
                            }]
                        }
                        run["results"].append(sarif_result)
                
                sarif["runs"].append(run)
        
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convertit la sévérité vers le niveau SARIF"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'warning')

    async def _generate_html_report(self, report: OrchestrationReport, output_path: Path):
        """Génère un rapport HTML pour visualisation"""
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Security Report - {report.project_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; }}
        .header {{ background: #1e3a8a; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .critical {{ border-left: 4px solid #dc2626; }}
        .high {{ border-left: 4px solid #ea580c; }}
        .medium {{ border-left: 4px solid #d97706; }}
        .low {{ border-left: 4px solid #65a30d; }}
        .success {{ border-left: 4px solid #059669; }}
        .metric {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
        .scan-result {{ margin-bottom: 15px; padding: 15px; border-radius: 6px; }}
        .status-success {{ background: #f0fdf4; border: 1px solid #bbf7d0; }}
        .status-failed {{ background: #fef2f2; border: 1px solid #fecaca; }}
        .status-timeout {{ background: #fffbeb; border: 1px solid #fed7aa; }}
        .recommendations {{ background: #eff6ff; padding: 20px; border-radius: 8px; }}
        .risk-score {{ font-size: 3em; font-weight: bold; text-align: center; }}
        .risk-high {{ color: #dc2626; }}
        .risk-medium {{ color: #d97706; }}
        .risk-low {{ color: #059669; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DevSecOps Security Report</h1>
        <p><strong>Project:</strong> {report.project_name}</p>
        <p><strong>Mode:</strong> {report.orchestration_mode.value.title()}</p>
        <p><strong>Date:</strong> {report.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Status:</strong> {report.overall_status.title()}</p>
        <p><strong>Security Gate:</strong> {'✅ PASSED' if report.security_gate_passed else '❌ FAILED'}</p>
    </div>

    <div class="summary">
        <div class="card critical">
            <div class="metric">{report.critical_issues}</div>
            <div>Critical Issues</div>
        </div>
        <div class="card high">
            <div class="metric">{report.high_issues}</div>
            <div>High Issues</div>
        </div>
        <div class="card medium">
            <div class="metric">{report.medium_issues}</div>
            <div>Medium Issues</div>
        </div>
        <div class="card low">
            <div class="metric">{report.low_issues}</div>
            <div>Low Issues</div>
        </div>
        <div class="card">
            <div class="risk-score risk-{self._get_risk_level(report.risk_score)}">{report.risk_score}</div>
            <div>Risk Score</div>
        </div>
    </div>

    <h2>📊 Scan Results</h2>
    <div class="scan-results">
"""
        
        for result in report.scan_results:
            status_class = f"status-{result.status}"
            html_template += f"""
        <div class="scan-result {status_class}">
            <h3>{result.scan_type.value.upper()} Scanner</h3>
            <p><strong>Status:</strong> {result.status.title()}</p>
            <p><strong>Duration:</strong> {result.duration_seconds:.1f}s</p>
            {f'<p><strong>Error:</strong> {result.error}</p>' if result.error else ''}
        </div>
"""
        
        html_template += f"""
    </div>

    <div class="recommendations">
        <h2>💡 Recommendations</h2>
        <ul>
"""
        
        for rec in report.recommendations:
            html_template += f"<li>{rec}</li>\n"
        
        html_template += """
        </ul>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_template)

    def _get_risk_level(self, risk_score: float) -> str:
        """Retourne le niveau de risque basé sur le score"""
        if risk_score >= 70:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"

    async def _evaluate_quality_gates(self, report: OrchestrationReport):
        """Évalue les quality gates et détermine si le pipeline peut continuer"""
        self.logger.info("🚪 Evaluating security quality gates")
        
        gates = self.config['quality_gates']
        quality_gates = {}
        
        # Gate: Vulnérabilités critiques
        critical_gate = {
            'name': 'Critical Vulnerabilities',
            'threshold': gates['critical_threshold'],
            'actual': report.critical_issues,
            'passed': report.critical_issues <= gates['critical_threshold']
        }
        quality_gates['critical'] = critical_gate
        
        # Gate: Vulnérabilités high
        high_gate = {
            'name': 'High Vulnerabilities',
            'threshold': gates['high_threshold'],
            'actual': report.high_issues,
            'passed': report.high_issues <= gates['high_threshold']
        }
        quality_gates['high'] = high_gate
        
        # Gate: Score de risque
        risk_gate = {
            'name': 'Risk Score',
            'threshold': gates['risk_score_threshold'],
            'actual': report.risk_score,
            'passed': report.risk_score <= gates['risk_score_threshold']
        }
        quality_gates['risk_score'] = risk_gate
        
        report.quality_gates = quality_gates
        
        # Déterminer si tous les gates sont passés
        all_passed = all(gate['passed'] for gate in quality_gates.values())
        report.security_gate_passed = all_passed
        
        # Log des résultats
        for gate_id, gate in quality_gates.items():
            status = "✅ PASSED" if gate['passed'] else "❌ FAILED"
            self.logger.info(f"🚪 {gate['name']}: {gate['actual']} (threshold: {gate['threshold']}) - {status}")
        
        if all_passed:
            self.logger.info("🎉 All security quality gates passed!")
        else:
            self.logger.warning("⚠️ Some security quality gates failed!")

    def get_scan_summary(self) -> Dict[str, Any]:
        """Retourne un résumé rapide du dernier scan"""
        if not self.current_report:
            return {"status": "no_scan_executed"}
        
        report = self.current_report
        
        return {
            "pipeline_id": report.pipeline_id,
            "project_name": report.project_name,
            "status": report.overall_status,
            "security_gate_passed": report.security_gate_passed,
            "duration_seconds": report.duration_seconds,
            "issues": {
                "critical": report.critical_issues,
                "high": report.high_issues,
                "medium": report.medium_issues,
                "low": report.low_issues,
                "total": report.total_issues
            },
            "risk_score": report.risk_score,
            "scans_executed": len(report.scan_results),
            "successful_scans": len([r for r in report.scan_results if r.status == "success"]),
            "failed_scans": len([r for r in report.scan_results if r.status == "failed"])
        }

# Exemple d'utilisation CLI
async def main():
    """Exemple d'utilisation de l'orchestrateur"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecOps Security Orchestrator")
    parser.add_argument("project_path", help="Path to project to scan")
    parser.add_argument("--mode", choices=["fast", "standard", "comprehensive"], 
                       default="standard", help="Orchestration mode")
    parser.add_argument("--stage", choices=["pre_build", "build", "post_build", "deploy", "runtime"],
                       default="pre_build", help="Pipeline stage")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--name", help="Project name")
    
    args = parser.parse_args()
    
    # Initialiser l'orchestrateur
    orchestrator = SecurityOrchestrator(args.config)
    
    # Mapper les arguments
    mode_map = {
        'fast': OrchestrationMode.FAST,
        'standard': OrchestrationMode.STANDARD, 
        'comprehensive': OrchestrationMode.COMPREHENSIVE
    }
    
    stage_map = {
        'pre_build': ScanStage.PRE_BUILD,
        'build': ScanStage.BUILD,
        'post_build': ScanStage.POST_BUILD,
        'deploy': ScanStage.DEPLOY,
        'runtime': ScanStage.RUNTIME
    }
    
    # Exécuter le scan
    report = await orchestrator.orchestrate_security_scan(
        project_path=args.project_path,
        project_name=args.name,
        mode=mode_map[args.mode],
        stage=stage_map[args.stage]
    )
    
    # Afficher le résumé
    summary = orchestrator.get_scan_summary()
    print(f"\n📊 Scan Summary:")
    print(f"Status: {summary['status']}")
    print(f"Security Gate: {'✅ PASSED' if summary['security_gate_passed'] else '❌ FAILED'}")
    print(f"Duration: {summary['duration_seconds']:.1f}s")
    print(f"Issues: {summary['issues']['total']} total ({summary['issues']['critical']} critical)")
    print(f"Risk Score: {summary['risk_score']}/100")
    
    # Code de sortie basé sur les quality gates
    exit_code = 0 if report.security_gate_passed else 1
    return exit_code

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)