#!/usr/bin/env python3
"""
Pipeline CI/CD Adapters
Adaptateurs pour intégrer l'orchestrateur de sécurité avec différentes plateformes CI/CD
"""

import os
import json
import yaml
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
import logging
from enum import Enum

from security_orchestrator import SecurityOrchestrator, OrchestrationMode, ScanStage, OrchestrationReport

class PipelineProvider(Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"
    CIRCLECI = "circleci"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"

@dataclass
class PipelineContext:
    """Contexte d'exécution du pipeline"""
    provider: PipelineProvider
    project_name: str
    branch: str
    commit_sha: str
    build_number: str
    is_pull_request: bool = False
    pull_request_id: Optional[str] = None
    target_branch: Optional[str] = None
    triggered_by: Optional[str] = None
    workspace_path: str = "."
    artifacts_path: Optional[str] = None
    environment_variables: Dict[str, str] = field(default_factory=dict)

class PipelineAdapter(ABC):
    """Interface de base pour les adaptateurs de pipeline CI/CD"""
    
    def __init__(self, orchestrator: SecurityOrchestrator):
        self.orchestrator = orchestrator
        self.logger = logging.getLogger(f'pipeline_adapter_{self.__class__.__name__.lower()}')
    
    @abstractmethod
    def get_pipeline_context(self) -> PipelineContext:
        """Obtient le contexte du pipeline actuel"""
        pass
    
    @abstractmethod
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables d'environnement dans le pipeline"""
        pass
    
    @abstractmethod
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations dans l'interface du pipeline"""
        pass
    
    @abstractmethod
    def upload_artifacts(self, report: OrchestrationReport):
        """Upload les artifacts (rapports) du pipeline"""
        pass
    
    @abstractmethod
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut du pipeline"""
        pass
    
    def run_security_scan(self, mode: OrchestrationMode = None, stage: ScanStage = None) -> OrchestrationReport:
        """Exécute le scan de sécurité dans le contexte du pipeline"""
        context = self.get_pipeline_context()
        
        # Déterminer les paramètres par défaut
        if mode is None:
            mode = self._determine_scan_mode(context)
        
        if stage is None:
            stage = self._determine_scan_stage(context)
        
        self.logger.info(f"🚀 Running security scan for {context.project_name}")
        self.logger.info(f"📋 Provider: {context.provider.value}, Mode: {mode.value}, Stage: {stage.value}")
        
        try:
            # Exécuter le scan
            import asyncio
            report = asyncio.run(
                self.orchestrator.orchestrate_security_scan(
                    project_path=context.workspace_path,
                    project_name=context.project_name,
                    mode=mode,
                    stage=stage
                )
            )
            
            # Post-traitement spécifique au pipeline
            self._post_process_report(report, context)
            
            # Créer les annotations
            self.create_pipeline_annotations(report)
            
            # Upload des artifacts
            self.upload_artifacts(report)
            
            # Définir les variables de pipeline
            self._set_result_variables(report)
            
            # Définir le statut
            status_message = f"Security scan completed: {report.total_issues} issues found"
            self.set_pipeline_status(report.security_gate_passed, status_message)
            
            return report
            
        except Exception as e:
            self.logger.error(f"❌ Security scan failed: {e}")
            self.set_pipeline_status(False, f"Security scan failed: {e}")
            raise
    
    def _determine_scan_mode(self, context: PipelineContext) -> OrchestrationMode:
        """Détermine le mode de scan basé sur le contexte"""
        if context.is_pull_request:
            return OrchestrationMode.FAST  # Scan rapide pour les PR
        elif context.branch == 'main' or context.branch == 'master':
            return OrchestrationMode.COMPREHENSIVE  # Scan complet pour main
        else:
            return OrchestrationMode.STANDARD  # Standard pour les autres branches
    
    def _determine_scan_stage(self, context: PipelineContext) -> ScanStage:
        """Détermine le stage de scan basé sur le contexte"""
        # Par défaut, scanner avant le build
        return ScanStage.PRE_BUILD
    
    def _post_process_report(self, report: OrchestrationReport, context: PipelineContext):
        """Post-traitement du rapport spécifique au pipeline"""
        # Ajouter le contexte du pipeline au rapport
        if not hasattr(report, 'pipeline_context'):
            report.pipeline_context = {
                'provider': context.provider.value,
                'branch': context.branch,
                'commit_sha': context.commit_sha,
                'build_number': context.build_number,
                'is_pull_request': context.is_pull_request,
                'pull_request_id': context.pull_request_id
            }
    
    def _set_result_variables(self, report: OrchestrationReport):
        """Définit les variables de résultat dans le pipeline"""
        variables = {
            'SECURITY_SCAN_STATUS': report.overall_status,
            'SECURITY_GATE_PASSED': str(report.security_gate_passed).lower(),
            'SECURITY_ISSUES_TOTAL': str(report.total_issues),
            'SECURITY_ISSUES_CRITICAL': str(report.critical_issues),
            'SECURITY_ISSUES_HIGH': str(report.high_issues),
            'SECURITY_RISK_SCORE': str(report.risk_score)
        }
        
        self.set_pipeline_variables(variables)

class GitHubActionsAdapter(PipelineAdapter):
    """Adaptateur pour GitHub Actions"""
    
    def get_pipeline_context(self) -> PipelineContext:
        env = os.environ
        
        return PipelineContext(
            provider=PipelineProvider.GITHUB_ACTIONS,
            project_name=env.get('GITHUB_REPOSITORY', '').split('/')[-1] or 'unknown',
            branch=env.get('GITHUB_REF_NAME', ''),
            commit_sha=env.get('GITHUB_SHA', ''),
            build_number=env.get('GITHUB_RUN_NUMBER', ''),
            is_pull_request=env.get('GITHUB_EVENT_NAME') == 'pull_request',
            pull_request_id=env.get('GITHUB_PR_NUMBER'),
            target_branch=env.get('GITHUB_BASE_REF'),
            triggered_by=env.get('GITHUB_ACTOR', ''),
            workspace_path=env.get('GITHUB_WORKSPACE', '.'),
            artifacts_path=env.get('RUNNER_TEMP'),
            environment_variables=dict(env)
        )
    
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables d'environnement GitHub Actions"""
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                for key, value in variables.items():
                    f.write(f"{key}={value}\n")
        
        # Aussi définir comme variables d'environnement
        for key, value in variables.items():
            os.environ[key] = value
    
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations GitHub Actions"""
        
        # Annotation de résumé
        if report.security_gate_passed:
            print(f"::notice title=Security Gate Passed::✅ No blocking security issues found")
        else:
            print(f"::error title=Security Gate Failed::❌ {report.critical_issues} critical, {report.high_issues} high severity issues")
        
        # Annotations pour les vulnérabilités critiques
        for result in report.scan_results:
            if result.status == "success" and result.report:
                if hasattr(result.report, 'findings'):  # SAST
                    for finding in result.report.findings:
                        if finding.severity.value in ['critical', 'high']:
                            print(f"::error file={finding.file_path},line={finding.line_number}::{finding.severity.value.upper()}: {finding.title} - {finding.description}")
                
                elif hasattr(result.report, 'issues'):  # Config
                    for issue in result.report.issues:
                        if issue.severity.value in ['critical', 'high']:
                            print(f"::error file={issue.file_path},line={issue.line_number or 1}::{issue.severity.value.upper()}: {issue.title} - {issue.description}")
        
        # Résumé dans le job summary
        self._create_github_summary(report)
    
    def _create_github_summary(self, report: OrchestrationReport):
        """Crée un résumé GitHub Actions"""
        github_step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if not github_step_summary:
            return
        
        summary_content = f"""# 🛡️ DevSecOps Security Report

## Project: {report.project_name}
- **Status**: {report.overall_status.title()}
- **Security Gate**: {'✅ PASSED' if report.security_gate_passed else '❌ FAILED'}
- **Duration**: {report.duration_seconds:.1f}s
- **Risk Score**: {report.risk_score}/100

## 📊 Issues Summary

| Severity | Count |
|----------|-------|
| Critical | {report.critical_issues} |
| High | {report.high_issues} |
| Medium | {report.medium_issues} |
| Low | {report.low_issues} |
| **Total** | **{report.total_issues}** |

## 🔍 Scan Results

| Scanner | Status | Duration |
|---------|--------|----------|
"""
        
        for result in report.scan_results:
            status_emoji = "✅" if result.status == "success" else "❌"
            summary_content += f"| {result.scan_type.value.upper()} | {status_emoji} {result.status} | {result.duration_seconds:.1f}s |\n"
        
        if report.recommendations:
            summary_content += "\n## 💡 Recommendations\n\n"
            for rec in report.recommendations:
                summary_content += f"- {rec}\n"
        
        with open(github_step_summary, 'w') as f:
            f.write(summary_content)
    
    def upload_artifacts(self, report: OrchestrationReport):
        """Upload les artifacts GitHub Actions"""
        # Les artifacts sont générés dans le répertoire de rapports
        # GitHub Actions les collectera automatiquement si configuré
        self.logger.info(f"📄 Reports generated: {list(report.artifacts.keys())}")
    
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut GitHub Actions"""
        if not success:
            print(f"::error::{message}")
            # Le workflow échouera si on lève une exception
        else:
            print(f"::notice::{message}")

class GitLabCIAdapter(PipelineAdapter):
    """Adaptateur pour GitLab CI"""
    
    def get_pipeline_context(self) -> PipelineContext:
        env = os.environ
        
        return PipelineContext(
            provider=PipelineProvider.GITLAB_CI,
            project_name=env.get('CI_PROJECT_NAME', ''),
            branch=env.get('CI_COMMIT_REF_NAME', ''),
            commit_sha=env.get('CI_COMMIT_SHA', ''),
            build_number=env.get('CI_PIPELINE_ID', ''),
            is_pull_request=env.get('CI_MERGE_REQUEST_ID') is not None,
            pull_request_id=env.get('CI_MERGE_REQUEST_IID'),
            target_branch=env.get('CI_MERGE_REQUEST_TARGET_BRANCH_NAME'),
            triggered_by=env.get('CI_COMMIT_AUTHOR', ''),
            workspace_path=env.get('CI_PROJECT_DIR', '.'),
            environment_variables=dict(env)
        )
    
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables GitLab CI"""
        # GitLab CI utilise des variables d'environnement
        for key, value in variables.items():
            os.environ[key] = value
            # Écrire dans un fichier pour les jobs suivants
            print(f"echo '{key}={value}' >> $CI_PROJECT_DIR/.security_vars")
    
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations GitLab CI"""
        # GitLab utilise le format JUnit XML pour les rapports de test
        self._create_junit_report(report)
        
        # Messages de log
        if report.security_gate_passed:
            print(f"✅ Security Gate PASSED: No blocking issues found")
        else:
            print(f"❌ Security Gate FAILED: {report.critical_issues} critical, {report.high_issues} high severity issues")
    
    def _create_junit_report(self, report: OrchestrationReport):
        """Crée un rapport JUnit pour GitLab"""
        try:
            from xml.etree.ElementTree import Element, SubElement, tostring
            import xml.dom.minidom
            
            testsuites = Element('testsuites')
            testsuite = SubElement(testsuites, 'testsuite', {
                'name': 'Security Scan',
                'tests': str(len(report.scan_results)),
                'failures': str(len([r for r in report.scan_results if r.status == 'failed'])),
                'time': str(report.duration_seconds)
            })
            
            for result in report.scan_results:
                testcase = SubElement(testsuite, 'testcase', {
                    'classname': 'SecurityScan',
                    'name': f"{result.scan_type.value}_scanner",
                    'time': str(result.duration_seconds)
                })
                
                if result.status == 'failed':
                    failure = SubElement(testcase, 'failure', {'message': result.error or 'Scan failed'})
                    failure.text = result.error
            
            # Écrire le fichier
            rough_string = tostring(testsuites, 'utf-8')
            reparsed = xml.dom.minidom.parseString(rough_string)
            with open('security-junit-report.xml', 'w') as f:
                f.write(reparsed.toprettyxml(indent="  "))
                
        except ImportError:
            self.logger.warning("⚠️ XML library not available for JUnit report")
    
    def upload_artifacts(self, report: OrchestrationReport):
        """Upload les artifacts GitLab CI"""
        # GitLab CI collecte automatiquement les artifacts définis dans .gitlab-ci.yml
        self.logger.info(f"📄 Reports generated: {list(report.artifacts.keys())}")
    
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut GitLab CI"""
        if not success:
            print(f"ERROR: {message}")
            exit(1)  # Faire échouer le job
        else:
            print(f"SUCCESS: {message}")

class JenkinsAdapter(PipelineAdapter):
    """Adaptateur pour Jenkins"""
    
    def get_pipeline_context(self) -> PipelineContext:
        env = os.environ
        
        return PipelineContext(
            provider=PipelineProvider.JENKINS,
            project_name=env.get('JOB_NAME', '').split('/')[-1] or 'unknown',
            branch=env.get('BRANCH_NAME', env.get('GIT_BRANCH', '')),
            commit_sha=env.get('GIT_COMMIT', ''),
            build_number=env.get('BUILD_NUMBER', ''),
            is_pull_request=env.get('CHANGE_ID') is not None,
            pull_request_id=env.get('CHANGE_ID'),
            target_branch=env.get('CHANGE_TARGET'),
            triggered_by=env.get('BUILD_USER', ''),
            workspace_path=env.get('WORKSPACE', '.'),
            environment_variables=dict(env)
        )
    
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables Jenkins"""
        # Écrire dans un fichier properties pour Jenkins
        with open('security-scan.properties', 'w') as f:
            for key, value in variables.items():
                f.write(f"{key}={value}\n")
                os.environ[key] = value
    
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations Jenkins"""
        # Jenkins peut utiliser des badges et des rapports HTML
        badge_color = "brightgreen" if report.security_gate_passed else "red"
        badge_message = f"{report.total_issues} issues"
        
        # Créer un badge de statut
        with open('security-badge.json', 'w') as f:
            json.dump({
                'schemaVersion': 1,
                'label': 'security',
                'message': badge_message,
                'color': badge_color
            }, f)
        
        # Messages de console
        if report.security_gate_passed:
            print(f"[INFO] ✅ Security Gate PASSED")
        else:
            print(f"[ERROR] ❌ Security Gate FAILED: {report.total_issues} issues")
    
    def upload_artifacts(self, report: OrchestrationReport):
        """Upload les artifacts Jenkins"""
        # Jenkins collecte les artifacts automatiquement selon la configuration
        self.logger.info(f"📄 Artifacts available: {list(report.artifacts.keys())}")
        
        # Publier les rapports HTML si disponible
        if 'html' in report.artifacts:
            print(f"[INFO] HTML report available at: {report.artifacts['html']}")
    
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut Jenkins"""
        if not success:
            print(f"[ERROR] {message}")
            # Jenkins utilisera le code de sortie pour déterminer le succès/échec
        else:
            print(f"[INFO] {message}")

class AzureDevOpsAdapter(PipelineAdapter):
    """Adaptateur pour Azure DevOps"""
    
    def get_pipeline_context(self) -> PipelineContext:
        env = os.environ
        
        return PipelineContext(
            provider=PipelineProvider.AZURE_DEVOPS,
            project_name=env.get('BUILD_REPOSITORY_NAME', ''),
            branch=env.get('BUILD_SOURCEBRANCH', '').replace('refs/heads/', ''),
            commit_sha=env.get('BUILD_SOURCEVERSION', ''),
            build_number=env.get('BUILD_BUILDNUMBER', ''),
            is_pull_request=env.get('BUILD_REASON') == 'PullRequest',
            pull_request_id=env.get('SYSTEM_PULLREQUEST_PULLREQUESTID'),
            target_branch=env.get('SYSTEM_PULLREQUEST_TARGETBRANCH'),
            triggered_by=env.get('BUILD_REQUESTEDFOR', ''),
            workspace_path=env.get('BUILD_SOURCESDIRECTORY', '.'),
            environment_variables=dict(env)
        )
    
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables Azure DevOps"""
        for key, value in variables.items():
            print(f"##vso[task.setvariable variable={key};]{value}")
            os.environ[key] = value
    
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations Azure DevOps"""
        
        # Messages de log avec formatting Azure DevOps
        if report.security_gate_passed:
            print(f"##[section] ✅ Security Gate PASSED")
        else:
            print(f"##[error] ❌ Security Gate FAILED: {report.total_issues} issues found")
        
        # Créer des warnings/errors pour chaque vulnérabilité critique
        for result in report.scan_results:
            if result.status == "success" and result.report:
                if hasattr(result.report, 'findings'):  # SAST
                    for finding in result.report.findings:
                        if finding.severity.value == 'critical':
                            print(f"##vso[task.logissue type=error;sourcepath={finding.file_path};linenumber={finding.line_number}]{finding.title}: {finding.description}")
                        elif finding.severity.value == 'high':
                            print(f"##vso[task.logissue type=warning;sourcepath={finding.file_path};linenumber={finding.line_number}]{finding.title}: {finding.description}")
        
        # Publier les résultats de test
        if os.path.exists('security-junit-report.xml'):
            print(f"##vso[results.publish type=JUnit;resultFiles=security-junit-report.xml;testRunTitle=Security Scan Results;]")
    
    def upload_artifacts(self, report: OrchestrationReport):
        """Upload les artifacts Azure DevOps"""
        # Publier les artifacts
        for artifact_type, artifact_path in report.artifacts.items():
            if os.path.exists(artifact_path):
                print(f"##vso[artifact.upload containerfolder=SecurityReports;artifactname={artifact_type}_report;]{artifact_path}")
    
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut Azure DevOps"""
        if not success:
            print(f"##vso[task.complete result=Failed;]{message}")
        else:
            print(f"##[section] {message}")

class DockerAdapter(PipelineAdapter):
    """Adaptateur pour exécution dans un conteneur Docker"""
    
    def get_pipeline_context(self) -> PipelineContext:
        env = os.environ
        
        return PipelineContext(
            provider=PipelineProvider.DOCKER,
            project_name=env.get('PROJECT_NAME', 'docker-project'),
            branch=env.get('GIT_BRANCH', 'main'),
            commit_sha=env.get('GIT_COMMIT', ''),
            build_number=env.get('BUILD_NUMBER', '1'),
            workspace_path=env.get('WORKSPACE', '/workspace'),
            environment_variables=dict(env)
        )
    
    def set_pipeline_variables(self, variables: Dict[str, str]):
        """Définit des variables dans l'environnement Docker"""
        for key, value in variables.items():
            os.environ[key] = value
    
    def create_pipeline_annotations(self, report: OrchestrationReport):
        """Crée des annotations pour Docker"""
        print(f"🛡️ Security Scan Results for {report.project_name}")
        print(f"Status: {report.overall_status}")
        print(f"Gate: {'PASSED' if report.security_gate_passed else 'FAILED'}")
        print(f"Issues: {report.total_issues} total ({report.critical_issues} critical)")
    
    def upload_artifacts(self, report: OrchestrationReport):
        """Sauvegarde les artifacts dans le conteneur"""
        artifacts_dir = '/workspace/security-reports'
        os.makedirs(artifacts_dir, exist_ok=True)
        
        for artifact_type, artifact_path in report.artifacts.items():
            if os.path.exists(artifact_path):
                target_path = os.path.join(artifacts_dir, f"security_report.{artifact_type}")
                import shutil
                shutil.copy2(artifact_path, target_path)
                self.logger.info(f"📄 Artifact saved: {target_path}")
    
    def set_pipeline_status(self, success: bool, message: str):
        """Définit le statut Docker (code de sortie)"""
        print(message)
        if not success:
            exit(1)

class PipelineAdapterFactory:
    """Factory pour créer les adaptateurs de pipeline appropriés"""
    
    @staticmethod
    def create_adapter(orchestrator: SecurityOrchestrator, provider: PipelineProvider = None) -> PipelineAdapter:
        """Crée l'adaptateur approprié basé sur l'environnement"""
        
        if provider is None:
            provider = PipelineAdapterFactory._detect_provider()
        
        adapters = {
            PipelineProvider.GITHUB_ACTIONS: GitHubActionsAdapter,
            PipelineProvider.GITLAB_CI: GitLabCIAdapter,
            PipelineProvider.JENKINS: JenkinsAdapter,
            PipelineProvider.AZURE_DEVOPS: AzureDevOpsAdapter,
            PipelineProvider.DOCKER: DockerAdapter
        }
        
        adapter_class = adapters.get(provider, DockerAdapter)  # Fallback vers Docker
        return adapter_class(orchestrator)
    
    @staticmethod
    def _detect_provider() -> PipelineProvider:
        """Détecte automatiquement le provider de pipeline"""
        env = os.environ
        
        if 'GITHUB_ACTIONS' in env:
            return PipelineProvider.GITHUB_ACTIONS
        elif 'GITLAB_CI' in env:
            return PipelineProvider.GITLAB_CI
        elif 'JENKINS_URL' in env:
            return PipelineProvider.JENKINS
        elif 'BUILD_SOURCESDIRECTORY' in env:  # Azure DevOps
            return PipelineProvider.AZURE_DEVOPS
        elif 'BITBUCKET_COMMIT' in env:
            return PipelineProvider.BITBUCKET
        elif 'CIRCLECI' in env:
            return PipelineProvider.CIRCLECI
        else:
            return PipelineProvider.DOCKER  # Default fallback

# Fonction utilitaire pour une utilisation simple
def run_security_pipeline(
    mode: OrchestrationMode = None, 
    stage: ScanStage = None,
    config_path: Optional[str] = None
) -> OrchestrationReport:
    """
    Fonction utilitaire pour exécuter facilement un scan de sécurité
    dans n'importe quel environnement CI/CD
    """
    # Créer l'orchestrateur
    orchestrator = SecurityOrchestrator(config_path)
    
    # Créer l'adaptateur approprié
    adapter = PipelineAdapterFactory.create_adapter(orchestrator)
    
    # Exécuter le scan
    return adapter.run_security_scan(mode, stage)

# Script CLI principal
def main():
    """Point d'entrée principal pour l'exécution en pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecOps Pipeline Security Scanner")
    parser.add_argument("--mode", choices=["fast", "standard", "comprehensive"], 
                       help="Scan mode")
    parser.add_argument("--stage", choices=["pre_build", "build", "post_build", "deploy", "runtime"],
                       help="Pipeline stage")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--provider", choices=[p.value for p in PipelineProvider],
                       help="Force specific pipeline provider")
    
    args = parser.parse_args()
    
    try:
        # Mapper les arguments
        mode_map = {
            'fast': OrchestrationMode.FAST,
            'standard': OrchestrationMode.STANDARD,
            'comprehensive': OrchestrationMode.COMPREHENSIVE
        } if args.mode else {}
        
        stage_map = {
            'pre_build': ScanStage.PRE_BUILD,
            'build': ScanStage.BUILD,
            'post_build': ScanStage.POST_BUILD,
            'deploy': ScanStage.DEPLOY,
            'runtime': ScanStage.RUNTIME
        } if args.stage else {}
        
        provider_map = {p.value: p for p in PipelineProvider} if args.provider else {}
        
        # Créer l'orchestrateur et l'adaptateur
        orchestrator = SecurityOrchestrator(args.config)
        
        provider = provider_map.get(args.provider) if args.provider else None
        adapter = PipelineAdapterFactory.create_adapter(orchestrator, provider)
        
        # Exécuter le scan
        report = adapter.run_security_scan(
            mode=mode_map.get(args.mode),
            stage=stage_map.get(args.stage)
        )
        
        # Code de sortie basé sur les quality gates
        exit_code = 0 if report.security_gate_passed else 1
        exit(exit_code)
        
    except Exception as e:
        print(f"❌ Pipeline security scan failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()