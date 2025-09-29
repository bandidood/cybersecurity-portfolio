#!/usr/bin/env python3
"""
Configuration Security Scanner
Scanner de sécurité pour configurations d'infrastructure et CI/CD
"""

import os
import json
import yaml
import re
import subprocess
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import hashlib
import base64
import xml.etree.ElementTree as ET
from collections import defaultdict

class ConfigType(Enum):
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    ANSIBLE = "ansible"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    AWS_CLOUDFORMATION = "aws_cloudformation"
    NGINX = "nginx"
    APACHE = "apache"
    SSH = "ssh"
    NETWORK = "network"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ConfigIssue:
    """Représente un problème de configuration détecté"""
    issue_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 à 1.0
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    config_type: Optional[ConfigType] = None
    affected_resource: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    compliance_frameworks: List[str] = field(default_factory=list)
    impact: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

@dataclass
class ConfigScanReport:
    """Rapport complet d'analyse de configuration"""
    scan_id: str
    project_name: str
    scan_time: datetime
    duration_seconds: float
    total_files_scanned: int
    config_types_found: List[ConfigType] = field(default_factory=list)
    issues: List[ConfigIssue] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    compliance_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    risk_score: float = 0.0

class ConfigScanner:
    """Scanner de sécurité des configurations"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.security_rules = self._load_security_rules()
        
        # Patterns de fichiers par type de configuration
        self.file_patterns = {
            ConfigType.DOCKER: [
                r'Dockerfile.*', r'docker-compose\.ya?ml', r'\.dockerignore'
            ],
            ConfigType.KUBERNETES: [
                r'.*\.ya?ml', r'.*\.json'  # Dans des dossiers k8s/kubernetes
            ],
            ConfigType.TERRAFORM: [
                r'.*\.tf$', r'.*\.tfvars$', r'terraform\.tfstate.*'
            ],
            ConfigType.ANSIBLE: [
                r'.*\.ya?ml', r'ansible\.cfg', r'hosts', r'inventory'
            ],
            ConfigType.GITHUB_ACTIONS: [
                r'\.github/workflows/.*\.ya?ml'
            ],
            ConfigType.GITLAB_CI: [
                r'\.gitlab-ci\.ya?ml', r'\.gitlab/.*\.ya?ml'
            ],
            ConfigType.JENKINS: [
                r'Jenkinsfile.*', r'jenkins\.ya?ml', r'config\.xml'
            ],
            ConfigType.AWS_CLOUDFORMATION: [
                r'.*\.template', r'.*cloudformation.*\.ya?ml', r'.*\.cfn\.'
            ],
            ConfigType.NGINX: [
                r'nginx\.conf', r'.*\.nginx', r'sites-available/.*', r'sites-enabled/.*'
            ],
            ConfigType.APACHE: [
                r'httpd\.conf', r'apache2\.conf', r'\.htaccess', r'.*\.vhost'
            ],
            ConfigType.SSH: [
                r'sshd_config', r'ssh_config', r'authorized_keys'
            ]
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Charge la configuration du scanner"""
        default_config = {
            'timeout': 300,
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'exclude_patterns': [
                '*/node_modules/*',
                '*/vendor/*',
                '*/.git/*',
                '*/dist/*',
                '*/build/*'
            ],
            'compliance_frameworks': [
                'CIS', 'NIST', 'PCI-DSS', 'SOC2', 'GDPR'
            ],
            'severity_threshold': 'low',
            'enable_secret_detection': True,
            'enable_hardcoded_credentials': True
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config

    def _load_security_rules(self) -> Dict[str, Dict[str, Any]]:
        """Charge les règles de sécurité par type de configuration"""
        return {
            # Règles Docker
            'docker_root_user': {
                'config_types': [ConfigType.DOCKER],
                'pattern': r'USER\s+root|USER\s+0',
                'severity': Severity.HIGH,
                'title': 'Container running as root user',
                'description': 'Container is configured to run as root user',
                'remediation': 'Create and use a non-root user',
                'cwe_id': 'CWE-250',
                'compliance': ['CIS', 'NIST']
            },
            'docker_privileged_mode': {
                'config_types': [ConfigType.DOCKER],
                'pattern': r'privileged:\s*true|--privileged',
                'severity': Severity.CRITICAL,
                'title': 'Container running in privileged mode',
                'description': 'Container has unrestricted access to host',
                'remediation': 'Remove privileged flag and use specific capabilities',
                'cwe_id': 'CWE-250'
            },
            'docker_secrets_in_env': {
                'config_types': [ConfigType.DOCKER],
                'pattern': r'ENV\s+.*(?:PASSWORD|SECRET|TOKEN|KEY).*=',
                'severity': Severity.HIGH,
                'title': 'Secrets in environment variables',
                'description': 'Sensitive data exposed in environment variables',
                'remediation': 'Use Docker secrets or external secret management'
            },
            
            # Règles Kubernetes
            'k8s_privileged_pod': {
                'config_types': [ConfigType.KUBERNETES],
                'pattern': r'privileged:\s*true',
                'severity': Severity.CRITICAL,
                'title': 'Privileged pod detected',
                'description': 'Pod running with privileged access',
                'remediation': 'Remove privileged flag and use security contexts'
            },
            'k8s_hostpid_enabled': {
                'config_types': [ConfigType.KUBERNETES],
                'pattern': r'hostPID:\s*true',
                'severity': Severity.HIGH,
                'title': 'Pod using host PID namespace',
                'description': 'Pod can see all processes on the host',
                'remediation': 'Remove hostPID or set to false'
            },
            'k8s_hostnetwork_enabled': {
                'config_types': [ConfigType.KUBERNETES],
                'pattern': r'hostNetwork:\s*true',
                'severity': Severity.HIGH,
                'title': 'Pod using host network',
                'description': 'Pod has access to host network interfaces',
                'remediation': 'Remove hostNetwork or set to false'
            },
            'k8s_allow_privilege_escalation': {
                'config_types': [ConfigType.KUBERNETES],
                'pattern': r'allowPrivilegeEscalation:\s*true',
                'severity': Severity.MEDIUM,
                'title': 'Privilege escalation allowed',
                'description': 'Container can gain more privileges',
                'remediation': 'Set allowPrivilegeEscalation to false'
            },
            
            # Règles Terraform
            'tf_s3_public_read': {
                'config_types': [ConfigType.TERRAFORM],
                'pattern': r'acl\s*=\s*["\']public-read["\']',
                'severity': Severity.HIGH,
                'title': 'S3 bucket with public read access',
                'description': 'S3 bucket allows public read access',
                'remediation': 'Restrict bucket access to specific users/roles'
            },
            'tf_security_group_wide_open': {
                'config_types': [ConfigType.TERRAFORM],
                'pattern': r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
                'severity': Severity.HIGH,
                'title': 'Security group open to the world',
                'description': 'Security group allows access from anywhere',
                'remediation': 'Restrict access to specific IP ranges'
            },
            'tf_hardcoded_secrets': {
                'config_types': [ConfigType.TERRAFORM],
                'pattern': r'(?:password|secret|token|key)\s*=\s*["\'][^"\']+["\']',
                'severity': Severity.CRITICAL,
                'title': 'Hardcoded secrets in Terraform',
                'description': 'Sensitive data hardcoded in configuration',
                'remediation': 'Use variables or external secret management'
            },
            
            # Règles CI/CD
            'cicd_hardcoded_credentials': {
                'config_types': [ConfigType.GITHUB_ACTIONS, ConfigType.GITLAB_CI],
                'pattern': r'(?:password|token|key|secret):\s*["\'][^"\']+["\']',
                'severity': Severity.CRITICAL,
                'title': 'Hardcoded credentials in CI/CD',
                'description': 'Credentials exposed in pipeline configuration',
                'remediation': 'Use encrypted secrets or environment variables'
            },
            'cicd_insecure_checkout': {
                'config_types': [ConfigType.GITHUB_ACTIONS, ConfigType.GITLAB_CI],
                'pattern': r'fetch-depth:\s*0|GIT_DEPTH:\s*0',
                'severity': Severity.MEDIUM,
                'title': 'Full repository checkout',
                'description': 'Pipeline downloads entire repository history',
                'remediation': 'Use shallow checkout for better security and performance'
            },
            'cicd_sudo_usage': {
                'config_types': [ConfigType.GITHUB_ACTIONS, ConfigType.GITLAB_CI],
                'pattern': r'sudo\s+',
                'severity': Severity.MEDIUM,
                'title': 'Sudo usage in pipeline',
                'description': 'Pipeline uses sudo for privileged operations',
                'remediation': 'Use containers or least-privilege approach'
            },
            
            # Règles génériques pour secrets
            'generic_api_key': {
                'config_types': list(ConfigType),
                'pattern': r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                'severity': Severity.HIGH,
                'title': 'API key detected',
                'description': 'Hardcoded API key found',
                'remediation': 'Use environment variables or secret management'
            },
            'generic_aws_key': {
                'config_types': list(ConfigType),
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': Severity.CRITICAL,
                'title': 'AWS access key detected',
                'description': 'AWS access key exposed in configuration',
                'remediation': 'Remove key and rotate immediately'
            },
            'generic_private_key': {
                'config_types': list(ConfigType),
                'pattern': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                'severity': Severity.CRITICAL,
                'title': 'Private key detected',
                'description': 'Private key exposed in configuration',
                'remediation': 'Remove key and rotate immediately'
            },
            
            # Règles SSH
            'ssh_permit_root_login': {
                'config_types': [ConfigType.SSH],
                'pattern': r'PermitRootLogin\s+yes',
                'severity': Severity.HIGH,
                'title': 'SSH root login permitted',
                'description': 'SSH server allows direct root login',
                'remediation': 'Set PermitRootLogin to no or prohibit-password'
            },
            'ssh_password_auth': {
                'config_types': [ConfigType.SSH],
                'pattern': r'PasswordAuthentication\s+yes',
                'severity': Severity.MEDIUM,
                'title': 'SSH password authentication enabled',
                'description': 'SSH allows password-based authentication',
                'remediation': 'Use key-based authentication only'
            },
            'ssh_empty_passwords': {
                'config_types': [ConfigType.SSH],
                'pattern': r'PermitEmptyPasswords\s+yes',
                'severity': Severity.CRITICAL,
                'title': 'SSH empty passwords permitted',
                'description': 'SSH allows login with empty passwords',
                'remediation': 'Set PermitEmptyPasswords to no'
            }
        }

    def scan_project(self, project_path: str, project_name: str = None) -> ConfigScanReport:
        """Scanner complet des configurations d'un projet"""
        print(f"🔍 Starting configuration security scan of {project_path}")
        start_time = datetime.now()
        
        if not project_name:
            project_name = os.path.basename(os.path.abspath(project_path))
        
        scan_id = hashlib.md5(f"{project_name}_{start_time}".encode()).hexdigest()
        
        # Découverte des fichiers de configuration
        config_files = self._discover_config_files(project_path)
        config_types_found = list(set(cf['type'] for cf in config_files))
        
        print(f"📊 Found {len(config_files)} configuration files")
        print(f"📋 Config types: {[ct.value for ct in config_types_found]}")
        
        # Analyse des configurations
        all_issues = []
        
        for config_file in config_files:
            print(f"🔧 Scanning {os.path.relpath(config_file['path'], project_path)}")
            try:
                issues = self._scan_config_file(
                    config_file['path'], 
                    config_file['type'], 
                    project_path
                )
                all_issues.extend(issues)
            except Exception as e:
                print(f"⚠️ Error scanning {config_file['path']}: {e}")
        
        # Post-traitement et déduplication
        all_issues = self._post_process_issues(all_issues)
        
        # Génération du rapport
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = self._generate_summary(all_issues)
        compliance_status = self._assess_compliance(all_issues)
        risk_score = self._calculate_risk_score(all_issues, len(config_files))
        
        report = ConfigScanReport(
            scan_id=scan_id,
            project_name=project_name,
            scan_time=start_time,
            duration_seconds=duration,
            total_files_scanned=len(config_files),
            config_types_found=config_types_found,
            issues=all_issues,
            summary=summary,
            compliance_status=compliance_status,
            risk_score=risk_score
        )
        
        print(f"✅ Configuration scan completed in {duration:.1f}s")
        print(f"📊 Summary: {summary}")
        print(f"🎯 Risk Score: {risk_score:.1f}/100")
        
        return report

    def _discover_config_files(self, project_path: str) -> List[Dict[str, Any]]:
        """Découvre tous les fichiers de configuration dans le projet"""
        config_files = []
        
        for root, dirs, files in os.walk(project_path):
            # Exclure les dossiers configurés
            dirs[:] = [d for d in dirs if not any(
                re.match(pattern.replace('*', '.*'), os.path.join(root, d))
                for pattern in self.config['exclude_patterns']
            )]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, project_path)
                
                # Vérifier la taille du fichier
                try:
                    if os.path.getsize(file_path) > self.config['max_file_size']:
                        continue
                except OSError:
                    continue
                
                # Déterminer le type de configuration
                config_type = self._identify_config_type(file_path, relative_path)
                
                if config_type:
                    config_files.append({
                        'path': file_path,
                        'relative_path': relative_path,
                        'type': config_type,
                        'name': file
                    })
        
        return config_files

    def _identify_config_type(self, file_path: str, relative_path: str) -> Optional[ConfigType]:
        """Identifie le type de configuration d'un fichier"""
        filename = os.path.basename(file_path)
        
        for config_type, patterns in self.file_patterns.items():
            for pattern in patterns:
                if re.search(pattern, relative_path, re.IGNORECASE):
                    # Vérifications spécifiques pour certains types
                    if config_type == ConfigType.KUBERNETES:
                        # Vérifier si c'est dans un dossier k8s ou contient des ressources k8s
                        if ('k8s' in relative_path.lower() or 
                            'kubernetes' in relative_path.lower() or
                            self._contains_k8s_resources(file_path)):
                            return config_type
                    elif config_type == ConfigType.ANSIBLE:
                        # Vérifier si c'est un playbook Ansible
                        if (filename in ['hosts', 'inventory', 'ansible.cfg'] or
                            self._contains_ansible_tasks(file_path)):
                            return config_type
                    else:
                        return config_type
        
        return None

    def _contains_k8s_resources(self, file_path: str) -> bool:
        """Vérifie si le fichier contient des ressources Kubernetes"""
        k8s_kinds = [
            'Pod', 'Service', 'Deployment', 'ConfigMap', 'Secret',
            'Ingress', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob'
        ]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Chercher les ressources Kubernetes communes
                for kind in k8s_kinds:
                    if re.search(rf'kind:\s*{kind}', content, re.IGNORECASE):
                        return True
                
                # Chercher apiVersion
                if re.search(r'apiVersion:', content):
                    return True
        
        except Exception:
            pass
        
        return False

    def _contains_ansible_tasks(self, file_path: str) -> bool:
        """Vérifie si le fichier contient des tâches Ansible"""
        ansible_keywords = [
            'hosts:', 'tasks:', 'roles:', 'vars:', 'handlers:',
            'playbook', 'ansible_', 'become:', 'gather_facts:'
        ]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for keyword in ansible_keywords:
                    if keyword in content.lower():
                        return True
        
        except Exception:
            pass
        
        return False

    def _scan_config_file(self, file_path: str, config_type: ConfigType, project_root: str) -> List[ConfigIssue]:
        """Scanner un fichier de configuration spécifique"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Appliquer les règles applicables
            applicable_rules = self._get_applicable_rules(config_type)
            
            for rule_id, rule in applicable_rules.items():
                matches = list(re.finditer(rule['pattern'], content, re.MULTILINE | re.IGNORECASE))
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extraire le contexte
                    evidence = self._extract_evidence(content, match, lines, line_number)
                    
                    issue = ConfigIssue(
                        issue_id=f"{config_type.value}_{hashlib.md5(f'{file_path}{line_number}{rule_id}'.encode()).hexdigest()[:8]}",
                        rule_id=rule_id,
                        title=rule['title'],
                        description=rule['description'],
                        severity=rule['severity'],
                        confidence=rule.get('confidence', 0.8),
                        file_path=os.path.relpath(file_path, project_root),
                        line_number=line_number,
                        config_type=config_type,
                        remediation=rule.get('remediation'),
                        references=rule.get('references', []),
                        cwe_id=rule.get('cwe_id'),
                        owasp_category=rule.get('owasp_category'),
                        compliance_frameworks=rule.get('compliance', []),
                        evidence=evidence
                    )
                    
                    issues.append(issue)
            
            # Analyse spécifique par type de configuration
            if config_type == ConfigType.DOCKER:
                issues.extend(self._analyze_dockerfile(file_path, content, project_root))
            elif config_type == ConfigType.KUBERNETES:
                issues.extend(self._analyze_k8s_manifest(file_path, content, project_root))
            elif config_type == ConfigType.TERRAFORM:
                issues.extend(self._analyze_terraform(file_path, content, project_root))
        
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}")
        
        return issues

    def _get_applicable_rules(self, config_type: ConfigType) -> Dict[str, Dict[str, Any]]:
        """Retourne les règles applicables pour un type de configuration"""
        applicable_rules = {}
        
        for rule_id, rule in self.security_rules.items():
            rule_config_types = rule.get('config_types', [])
            
            # Vérifier si la règle s'applique à ce type de config
            if config_type in rule_config_types or ConfigType in rule_config_types:
                applicable_rules[rule_id] = rule
        
        return applicable_rules

    def _extract_evidence(self, content: str, match: re.Match, lines: List[str], line_number: int) -> Dict[str, Any]:
        """Extrait les preuves contextuelles d'une détection"""
        evidence = {
            'matched_text': match.group(0),
            'line_content': lines[line_number - 1] if line_number <= len(lines) else '',
            'context_lines': []
        }
        
        # Extraire quelques lignes de contexte
        context_range = 2
        start_line = max(0, line_number - context_range - 1)
        end_line = min(len(lines), line_number + context_range)
        
        for i in range(start_line, end_line):
            evidence['context_lines'].append({
                'line_number': i + 1,
                'content': lines[i],
                'is_match_line': i + 1 == line_number
            })
        
        return evidence

    def _analyze_dockerfile(self, file_path: str, content: str, project_root: str) -> List[ConfigIssue]:
        """Analyse spécifique des Dockerfiles"""
        issues = []
        lines = content.split('\n')
        
        # Vérifier l'utilisation d'images de base non sécurisées
        base_image_line = None
        for i, line in enumerate(lines):
            if line.strip().startswith('FROM '):
                base_image_line = i + 1
                image = line.split()[1].lower()
                
                # Images à éviter
                if ':latest' in image:
                    issues.append(ConfigIssue(
                        issue_id=f"docker_latest_{hashlib.md5(f'{file_path}{i}'.encode()).hexdigest()[:8]}",
                        rule_id='docker_latest_tag',
                        title='Using :latest tag',
                        description='Dockerfile uses :latest tag which can lead to inconsistent builds',
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        file_path=os.path.relpath(file_path, project_root),
                        line_number=base_image_line,
                        config_type=ConfigType.DOCKER,
                        remediation='Use specific version tags',
                        compliance_frameworks=['CIS']
                    ))
        
        # Vérifier les ports exposés dangereux
        dangerous_ports = ['22', '23', '135', '445', '1433', '3389']
        for i, line in enumerate(lines):
            if line.strip().startswith('EXPOSE '):
                ports = line.split()[1:]
                for port in ports:
                    port_num = port.split('/')[0]  # Enlever le protocole si présent
                    if port_num in dangerous_ports:
                        issues.append(ConfigIssue(
                            issue_id=f"docker_dangerous_port_{hashlib.md5(f'{file_path}{i}{port}'.encode()).hexdigest()[:8]}",
                            rule_id='docker_dangerous_port',
                            title=f'Dangerous port {port} exposed',
                            description=f'Container exposes potentially dangerous port {port}',
                            severity=Severity.HIGH,
                            confidence=0.8,
                            file_path=os.path.relpath(file_path, project_root),
                            line_number=i + 1,
                            config_type=ConfigType.DOCKER,
                            remediation='Remove unnecessary port exposures or use non-standard ports'
                        ))
        
        return issues

    def _analyze_k8s_manifest(self, file_path: str, content: str, project_root: str) -> List[ConfigIssue]:
        """Analyse spécifique des manifestes Kubernetes"""
        issues = []
        
        try:
            # Parser YAML
            documents = yaml.safe_load_all(content)
            
            for doc_index, doc in enumerate(documents):
                if not doc or not isinstance(doc, dict):
                    continue
                
                kind = doc.get('kind', '')
                metadata = doc.get('metadata', {})
                spec = doc.get('spec', {})
                
                # Analyser les pods et déploiements
                if kind in ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet']:
                    pod_spec = spec
                    if kind != 'Pod':
                        pod_spec = spec.get('template', {}).get('spec', {})
                    
                    # Vérifier les conteneurs
                    containers = pod_spec.get('containers', [])
                    for container_index, container in enumerate(containers):
                        # Image sans tag ou avec :latest
                        image = container.get('image', '')
                        if ':latest' in image or ':' not in image:
                            issues.append(ConfigIssue(
                                issue_id=f"k8s_latest_image_{hashlib.md5(f'{file_path}{doc_index}{container_index}'.encode()).hexdigest()[:8]}",
                                rule_id='k8s_latest_image',
                                title='Container using :latest or no tag',
                                description='Container image without specific version tag',
                                severity=Severity.MEDIUM,
                                confidence=0.9,
                                file_path=os.path.relpath(file_path, project_root),
                                config_type=ConfigType.KUBERNETES,
                                affected_resource=f"{kind}/{metadata.get('name', 'unknown')}",
                                remediation='Use specific image tags'
                            ))
                        
                        # Resources non définies
                        resources = container.get('resources', {})
                        if not resources.get('limits') and not resources.get('requests'):
                            issues.append(ConfigIssue(
                                issue_id=f"k8s_no_resources_{hashlib.md5(f'{file_path}{doc_index}{container_index}'.encode()).hexdigest()[:8]}",
                                rule_id='k8s_no_resource_limits',
                                title='No resource limits defined',
                                description='Container has no CPU/memory limits',
                                severity=Severity.MEDIUM,
                                confidence=0.8,
                                file_path=os.path.relpath(file_path, project_root),
                                config_type=ConfigType.KUBERNETES,
                                affected_resource=f"{kind}/{metadata.get('name', 'unknown')}",
                                remediation='Define resource requests and limits'
                            ))
                
                # Analyser les services
                elif kind == 'Service':
                    service_type = spec.get('type', 'ClusterIP')
                    if service_type == 'LoadBalancer':
                        # Vérifier si des restrictions d'IP sont en place
                        if not spec.get('loadBalancerSourceRanges'):
                            issues.append(ConfigIssue(
                                issue_id=f"k8s_lb_no_restrictions_{hashlib.md5(f'{file_path}{doc_index}'.encode()).hexdigest()[:8]}",
                                rule_id='k8s_loadbalancer_no_restrictions',
                                title='LoadBalancer without IP restrictions',
                                description='LoadBalancer service without source IP restrictions',
                                severity=Severity.HIGH,
                                confidence=0.9,
                                file_path=os.path.relpath(file_path, project_root),
                                config_type=ConfigType.KUBERNETES,
                                affected_resource=f"Service/{metadata.get('name', 'unknown')}",
                                remediation='Add loadBalancerSourceRanges to restrict access'
                            ))
        
        except Exception as e:
            print(f"⚠️ Error parsing Kubernetes manifest {file_path}: {e}")
        
        return issues

    def _analyze_terraform(self, file_path: str, content: str, project_root: str) -> List[ConfigIssue]:
        """Analyse spécifique des configurations Terraform"""
        issues = []
        lines = content.split('\n')
        
        # Analyser les ressources AWS S3
        s3_bucket_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"'
        s3_matches = re.finditer(s3_bucket_pattern, content, re.MULTILINE)
        
        for match in s3_matches:
            bucket_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1
            
            # Trouver le bloc de configuration
            bucket_block = self._extract_terraform_block(content, match.start())
            
            # Vérifier la configuration de versioning
            if 'versioning' not in bucket_block:
                issues.append(ConfigIssue(
                    issue_id=f"tf_s3_no_versioning_{hashlib.md5(f'{file_path}{bucket_name}'.encode()).hexdigest()[:8]}",
                    rule_id='tf_s3_no_versioning',
                    title='S3 bucket without versioning',
                    description=f'S3 bucket {bucket_name} does not have versioning enabled',
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    file_path=os.path.relpath(file_path, project_root),
                    line_number=start_line,
                    config_type=ConfigType.TERRAFORM,
                    affected_resource=f"aws_s3_bucket.{bucket_name}",
                    remediation='Enable versioning for the S3 bucket'
                ))
            
            # Vérifier le chiffrement
            if 'server_side_encryption_configuration' not in bucket_block:
                issues.append(ConfigIssue(
                    issue_id=f"tf_s3_no_encryption_{hashlib.md5(f'{file_path}{bucket_name}'.encode()).hexdigest()[:8]}",
                    rule_id='tf_s3_no_encryption',
                    title='S3 bucket without encryption',
                    description=f'S3 bucket {bucket_name} does not have encryption enabled',
                    severity=Severity.HIGH,
                    confidence=0.9,
                    file_path=os.path.relpath(file_path, project_root),
                    line_number=start_line,
                    config_type=ConfigType.TERRAFORM,
                    affected_resource=f"aws_s3_bucket.{bucket_name}",
                    remediation='Enable server-side encryption for the S3 bucket'
                ))
        
        return issues

    def _extract_terraform_block(self, content: str, start_pos: int) -> str:
        """Extrait un bloc Terraform complet"""
        lines = content[start_pos:].split('\n')
        block_lines = []
        brace_count = 0
        in_block = False
        
        for line in lines:
            if '{' in line:
                in_block = True
                brace_count += line.count('{')
            
            if in_block:
                block_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count <= 0:
                    break
        
        return '\n'.join(block_lines)

    def _post_process_issues(self, issues: List[ConfigIssue]) -> List[ConfigIssue]:
        """Post-traitement des problèmes détectés"""
        # Déduplication
        seen = set()
        deduplicated = []
        
        for issue in issues:
            # Clé de déduplication basée sur le fichier, la ligne et la règle
            key = (issue.file_path, issue.line_number, issue.rule_id)
            if key not in seen:
                seen.add(key)
                deduplicated.append(issue)
        
        # Tri par sévérité puis par fichier
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        
        deduplicated.sort(key=lambda i: (
            severity_order[i.severity],
            i.file_path,
            i.line_number or 0
        ))
        
        return deduplicated

    def _generate_summary(self, issues: List[ConfigIssue]) -> Dict[str, int]:
        """Génère un résumé des problèmes"""
        summary = {
            'total': len(issues),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for issue in issues:
            summary[issue.severity.value] += 1
        
        # Statistiques par type de configuration
        config_type_stats = defaultdict(int)
        for issue in issues:
            if issue.config_type:
                config_type_stats[issue.config_type.value] += 1
        
        summary['by_config_type'] = dict(config_type_stats)
        
        return summary

    def _assess_compliance(self, issues: List[ConfigIssue]) -> Dict[str, Dict[str, Any]]:
        """Évalue la conformité aux frameworks de sécurité"""
        compliance_status = {}
        
        for framework in self.config['compliance_frameworks']:
            framework_issues = [
                issue for issue in issues 
                if framework in issue.compliance_frameworks
            ]
            
            total_checks = len([
                rule for rule in self.security_rules.values() 
                if framework in rule.get('compliance', [])
            ])
            
            failed_checks = len(framework_issues)
            passed_checks = total_checks - failed_checks
            
            compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 100
            
            compliance_status[framework] = {
                'compliance_percentage': compliance_percentage,
                'total_checks': total_checks,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'critical_failures': len([i for i in framework_issues if i.severity == Severity.CRITICAL]),
                'high_failures': len([i for i in framework_issues if i.severity == Severity.HIGH])
            }
        
        return compliance_status

    def _calculate_risk_score(self, issues: List[ConfigIssue], total_files: int) -> float:
        """Calcule un score de risque global"""
        if not issues:
            return 0.0
        
        # Pondération par sévérité
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.1
        }
        
        total_weight = sum(severity_weights[issue.severity] for issue in issues)
        
        # Normaliser par rapport au nombre de fichiers
        if total_files > 0:
            risk_score = min(100.0, (total_weight / total_files) * 5)
        else:
            risk_score = 0.0
        
        return round(risk_score, 1)

    def export_report(self, report: ConfigScanReport, format: str = 'json', output_path: str = None) -> str:
        """Exporte le rapport dans le format spécifié"""
        if format == 'json':
            data = {
                'scan_id': report.scan_id,
                'project_name': report.project_name,
                'scan_time': report.scan_time.isoformat(),
                'duration_seconds': report.duration_seconds,
                'total_files_scanned': report.total_files_scanned,
                'config_types_found': [ct.value for ct in report.config_types_found],
                'summary': report.summary,
                'compliance_status': report.compliance_status,
                'risk_score': report.risk_score,
                'issues': [
                    {
                        'issue_id': issue.issue_id,
                        'rule_id': issue.rule_id,
                        'title': issue.title,
                        'description': issue.description,
                        'severity': issue.severity.value,
                        'confidence': issue.confidence,
                        'file_path': issue.file_path,
                        'line_number': issue.line_number,
                        'column_number': issue.column_number,
                        'config_type': issue.config_type.value if issue.config_type else None,
                        'affected_resource': issue.affected_resource,
                        'remediation': issue.remediation,
                        'references': issue.references,
                        'cwe_id': issue.cwe_id,
                        'owasp_category': issue.owasp_category,
                        'compliance_frameworks': issue.compliance_frameworks,
                        'impact': issue.impact,
                        'evidence': issue.evidence
                    }
                    for issue in report.issues
                ]
            }
            
            output = json.dumps(data, indent=2)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"📄 Report exported to {output_path}")
        
        return output

# Exemple d'utilisation
def main():
    """Exemple d'utilisation du scanner de configuration"""
    scanner = ConfigScanner()
    
    # Scanner un projet d'exemple
    project_path = "/path/to/your/project"
    
    if os.path.exists(project_path):
        report = scanner.scan_project(project_path, "Example Project")
        
        print(f"\n📊 Configuration Scan Results:")
        print(f"Project: {report.project_name}")
        print(f"Duration: {report.duration_seconds:.1f}s")
        print(f"Files scanned: {report.total_files_scanned}")
        print(f"Config types: {[ct.value for ct in report.config_types_found]}")
        print(f"Risk Score: {report.risk_score}/100")
        
        print(f"\n🚨 Security Issues:")
        summary = report.summary
        for severity in ['critical', 'high', 'medium', 'low']:
            count = summary.get(severity, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[severity]
                print(f"{emoji} {severity.title()}: {count}")
        
        print(f"\n📋 Compliance Status:")
        for framework, status in report.compliance_status.items():
            print(f"{framework}: {status['compliance_percentage']:.1f}% ({status['passed_checks']}/{status['total_checks']})")
        
        print(f"\n📝 Example Issues:")
        for issue in report.issues[:3]:
            print(f"   • {issue.title} ({issue.severity.value})")
            print(f"     File: {issue.file_path}:{issue.line_number}")
            print(f"     Description: {issue.description}")
        
        # Exporter le rapport
        scanner.export_report(report, 'json', 'config_scan_report.json')
    
    else:
        print("⚠️ Project path not found, running demo...")
        # Créer un rapport de démonstration
        demo_issues = [
            ConfigIssue(
                issue_id="demo_001",
                rule_id="docker_root_user",
                title="Container running as root",
                description="Docker container configured to run as root user",
                severity=Severity.HIGH,
                confidence=0.9,
                file_path="Dockerfile",
                line_number=10,
                config_type=ConfigType.DOCKER,
                remediation="Create and use a non-root user"
            ),
            ConfigIssue(
                issue_id="demo_002",
                rule_id="k8s_privileged_pod",
                title="Privileged pod detected",
                description="Pod running with privileged access",
                severity=Severity.CRITICAL,
                confidence=0.95,
                file_path="k8s/deployment.yaml",
                line_number=25,
                config_type=ConfigType.KUBERNETES,
                remediation="Remove privileged flag"
            )
        ]
        
        print(f"📊 Demo Results:")
        print(f"Issues found: {len(demo_issues)}")
        print(f"Critical: 1, High: 1")

if __name__ == "__main__":
    main()