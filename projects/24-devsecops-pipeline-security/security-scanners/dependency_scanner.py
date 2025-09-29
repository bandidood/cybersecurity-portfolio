#!/usr/bin/env python3
"""
Dependency & CVE Scanner
Scanner de vulnérabilités dans les dépendances et packages
"""

import os
import json
import subprocess
import requests
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import hashlib
import re
import semver
import asyncio
import aiohttp
import yaml

class PackageManager(Enum):
    NPM = "npm"
    PIP = "pip"
    MAVEN = "maven"
    GRADLE = "gradle"
    COMPOSER = "composer"
    GEM = "gem"
    GO_MOD = "go"
    CARGO = "cargo"
    NUGET = "nuget"

class VulnerabilitySource(Enum):
    NVD = "nvd"
    SNYK = "snyk"
    OSV = "osv"
    GITHUB = "github"
    PYUP = "pyup"
    NPMJS = "npmjs"

@dataclass
class PackageDependency:
    """Représente une dépendance de package"""
    name: str
    version: str
    package_manager: PackageManager
    is_direct: bool = True
    is_dev: bool = False
    license: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    file_path: Optional[str] = None

@dataclass
class VulnerabilityInfo:
    """Information détaillée sur une vulnérabilité"""
    cve_id: Optional[str] = None
    vulnerability_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_versions: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    source: VulnerabilitySource = VulnerabilitySource.NVD
    cwe_ids: List[str] = field(default_factory=list)

@dataclass
class DependencyVulnerability:
    """Vulnérabilité détectée dans une dépendance"""
    package: PackageDependency
    vulnerability: VulnerabilityInfo
    is_exploitable: bool = False
    is_patchable: bool = False
    upgrade_path: Optional[str] = None
    workaround: Optional[str] = None
    priority_score: float = 0.0

@dataclass
class LicenseIssue:
    """Problème de licence détecté"""
    package: PackageDependency
    license: str
    issue_type: str  # "incompatible", "missing", "copyleft", etc.
    severity: str
    description: str

@dataclass
class DependencyScanReport:
    """Rapport complet d'analyse des dépendances"""
    scan_id: str
    project_name: str
    scan_time: datetime
    duration_seconds: float
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    package_managers: List[PackageManager] = field(default_factory=list)
    vulnerabilities: List[DependencyVulnerability] = field(default_factory=list)
    license_issues: List[LicenseIssue] = field(default_factory=list)
    outdated_packages: List[PackageDependency] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)

class DependencyScanner:
    """Scanner de vulnérabilités des dépendances"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.vulnerability_cache = {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Configuration des bases de données de vulnérabilités
        self.vuln_databases = {
            VulnerabilitySource.OSV: {
                'url': 'https://api.osv.dev/v1/query',
                'enabled': True
            },
            VulnerabilitySource.GITHUB: {
                'url': 'https://api.github.com/advisories',
                'enabled': True,
                'token': os.getenv('GITHUB_TOKEN')
            },
            VulnerabilitySource.SNYK: {
                'url': 'https://snyk.io/api/v1',
                'enabled': False,  # Nécessite une clé API
                'token': os.getenv('SNYK_TOKEN')
            }
        }
        
        # Patterns de fichiers de dépendances
        self.dependency_files = {
            PackageManager.NPM: ['package.json', 'package-lock.json', 'yarn.lock'],
            PackageManager.PIP: ['requirements.txt', 'requirements-dev.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml'],
            PackageManager.MAVEN: ['pom.xml'],
            PackageManager.GRADLE: ['build.gradle', 'build.gradle.kts'],
            PackageManager.COMPOSER: ['composer.json', 'composer.lock'],
            PackageManager.GEM: ['Gemfile', 'Gemfile.lock'],
            PackageManager.GO_MOD: ['go.mod', 'go.sum'],
            PackageManager.CARGO: ['Cargo.toml', 'Cargo.lock'],
            PackageManager.NUGET: ['*.csproj', 'packages.config', 'project.json']
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Charge la configuration du scanner"""
        default_config = {
            'timeout': 300,
            'max_concurrent_requests': 10,
            'cache_ttl_hours': 24,
            'severity_threshold': 'medium',
            'include_dev_dependencies': True,
            'check_licenses': True,
            'allowed_licenses': [
                'MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 
                'ISC', 'Unlicense', 'CC0-1.0'
            ],
            'forbidden_licenses': [
                'GPL-3.0', 'AGPL-3.0', 'LGPL-3.0'
            ]
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config

    async def scan_project(self, project_path: str, project_name: str = None) -> DependencyScanReport:
        """Scanner complet des dépendances d'un projet"""
        print(f"🔍 Starting dependency scan of {project_path}")
        start_time = datetime.now()
        
        if not project_name:
            project_name = os.path.basename(os.path.abspath(project_path))
        
        scan_id = hashlib.md5(f"{project_name}_{start_time}".encode()).hexdigest()
        
        # Initialiser la session HTTP
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config['timeout'])
        )
        
        try:
            # Découverte et parsing des fichiers de dépendances
            dependencies = await self._discover_dependencies(project_path)
            package_managers = list(set(dep.package_manager for dep in dependencies))
            
            print(f"📊 Found {len(dependencies)} dependencies using {len(package_managers)} package managers")
            
            direct_deps = sum(1 for dep in dependencies if dep.is_direct)
            transitive_deps = len(dependencies) - direct_deps
            
            # Analyse des vulnérabilités
            print("🔧 Scanning for vulnerabilities...")
            vulnerabilities = await self._scan_vulnerabilities(dependencies)
            
            # Analyse des licences
            print("📄 Checking licenses...")
            license_issues = await self._check_licenses(dependencies)
            
            # Détection des packages obsolètes
            print("📅 Checking for outdated packages...")
            outdated_packages = await self._check_outdated_packages(dependencies)
            
            # Génération du rapport
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            summary = self._generate_summary(vulnerabilities, license_issues, outdated_packages)
            risk_assessment = self._assess_risk(vulnerabilities, dependencies)
            
            report = DependencyScanReport(
                scan_id=scan_id,
                project_name=project_name,
                scan_time=start_time,
                duration_seconds=duration,
                total_dependencies=len(dependencies),
                direct_dependencies=direct_deps,
                transitive_dependencies=transitive_deps,
                package_managers=package_managers,
                vulnerabilities=vulnerabilities,
                license_issues=license_issues,
                outdated_packages=outdated_packages,
                summary=summary,
                risk_assessment=risk_assessment
            )
            
            print(f"✅ Dependency scan completed in {duration:.1f}s")
            print(f"📊 Summary: {summary}")
            
            return report
            
        finally:
            if self.session:
                await self.session.close()

    async def _discover_dependencies(self, project_path: str) -> List[PackageDependency]:
        """Découvre toutes les dépendances du projet"""
        all_dependencies = []
        
        for package_manager, file_patterns in self.dependency_files.items():
            for pattern in file_patterns:
                files = self._find_files(project_path, pattern)
                
                for file_path in files:
                    print(f"📁 Parsing {os.path.relpath(file_path, project_path)}")
                    try:
                        deps = await self._parse_dependency_file(file_path, package_manager)
                        all_dependencies.extend(deps)
                    except Exception as e:
                        print(f"⚠️ Error parsing {file_path}: {e}")
        
        # Déduplication
        seen = set()
        unique_dependencies = []
        
        for dep in all_dependencies:
            key = (dep.name, dep.version, dep.package_manager)
            if key not in seen:
                seen.add(key)
                unique_dependencies.append(dep)
        
        return unique_dependencies

    def _find_files(self, project_path: str, pattern: str) -> List[str]:
        """Trouve les fichiers correspondant au pattern"""
        files = []
        
        if '*' in pattern:
            # Utiliser glob pour les patterns avec wildcards
            import glob
            full_pattern = os.path.join(project_path, '**', pattern)
            files = glob.glob(full_pattern, recursive=True)
        else:
            # Recherche directe pour les noms de fichiers exacts
            for root, _, filenames in os.walk(project_path):
                if pattern in filenames:
                    files.append(os.path.join(root, pattern))
        
        return files

    async def _parse_dependency_file(self, file_path: str, package_manager: PackageManager) -> List[PackageDependency]:
        """Parse un fichier de dépendances spécifique"""
        dependencies = []
        
        try:
            if package_manager == PackageManager.NPM:
                dependencies = await self._parse_npm_dependencies(file_path)
            elif package_manager == PackageManager.PIP:
                dependencies = await self._parse_pip_dependencies(file_path)
            elif package_manager == PackageManager.MAVEN:
                dependencies = await self._parse_maven_dependencies(file_path)
            elif package_manager == PackageManager.COMPOSER:
                dependencies = await self._parse_composer_dependencies(file_path)
            elif package_manager == PackageManager.GO_MOD:
                dependencies = await self._parse_go_dependencies(file_path)
            elif package_manager == PackageManager.CARGO:
                dependencies = await self._parse_cargo_dependencies(file_path)
        
        except Exception as e:
            print(f"⚠️ Failed to parse {file_path}: {e}")
        
        return dependencies

    async def _parse_npm_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances NPM/Yarn"""
        dependencies = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith('package.json'):
                data = json.load(f)
                
                # Dépendances de production
                for name, version in data.get('dependencies', {}).items():
                    dependencies.append(PackageDependency(
                        name=name,
                        version=self._clean_version(version),
                        package_manager=PackageManager.NPM,
                        is_direct=True,
                        is_dev=False,
                        file_path=file_path
                    ))
                
                # Dépendances de développement
                if self.config['include_dev_dependencies']:
                    for name, version in data.get('devDependencies', {}).items():
                        dependencies.append(PackageDependency(
                            name=name,
                            version=self._clean_version(version),
                            package_manager=PackageManager.NPM,
                            is_direct=True,
                            is_dev=True,
                            file_path=file_path
                        ))
        
        return dependencies

    async def _parse_pip_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances Python"""
        dependencies = []
        
        if file_path.endswith('.txt'):
            # Requirements.txt format
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parser les lignes comme "package==1.0.0" ou "package>=1.0.0"
                        match = re.match(r'^([a-zA-Z0-9_.-]+)([><=!]+)([^;]+)', line)
                        if match:
                            name, operator, version = match.groups()
                            dependencies.append(PackageDependency(
                                name=name.strip(),
                                version=version.strip(),
                                package_manager=PackageManager.PIP,
                                is_direct=True,
                                is_dev='dev' in os.path.basename(file_path),
                                file_path=file_path
                            ))
        
        elif file_path.endswith('Pipfile'):
            # Pipfile format
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
                for name, version in data.get('packages', {}).items():
                    if isinstance(version, str):
                        version_str = version
                    elif isinstance(version, dict):
                        version_str = version.get('version', '*')
                    else:
                        version_str = '*'
                    
                    dependencies.append(PackageDependency(
                        name=name,
                        version=self._clean_version(version_str),
                        package_manager=PackageManager.PIP,
                        is_direct=True,
                        is_dev=False,
                        file_path=file_path
                    ))
        
        return dependencies

    async def _parse_maven_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances Maven"""
        dependencies = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Namespace Maven
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            
            # Trouver toutes les dépendances
            deps = root.findall('.//m:dependency', ns)
            
            for dep in deps:
                group_id = dep.find('m:groupId', ns)
                artifact_id = dep.find('m:artifactId', ns)
                version = dep.find('m:version', ns)
                scope = dep.find('m:scope', ns)
                
                if group_id is not None and artifact_id is not None:
                    name = f"{group_id.text}:{artifact_id.text}"
                    version_str = version.text if version is not None else "latest"
                    scope_str = scope.text if scope is not None else "compile"
                    
                    dependencies.append(PackageDependency(
                        name=name,
                        version=version_str,
                        package_manager=PackageManager.MAVEN,
                        is_direct=True,
                        is_dev=scope_str in ['test', 'provided'],
                        file_path=file_path
                    ))
        
        except Exception as e:
            print(f"⚠️ Error parsing Maven POM: {e}")
        
        return dependencies

    async def _parse_composer_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances Composer (PHP)"""
        dependencies = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            # Dépendances de production
            for name, version in data.get('require', {}).items():
                if name != 'php':  # Exclure la version PHP
                    dependencies.append(PackageDependency(
                        name=name,
                        version=self._clean_version(version),
                        package_manager=PackageManager.COMPOSER,
                        is_direct=True,
                        is_dev=False,
                        file_path=file_path
                    ))
            
            # Dépendances de développement
            if self.config['include_dev_dependencies']:
                for name, version in data.get('require-dev', {}).items():
                    dependencies.append(PackageDependency(
                        name=name,
                        version=self._clean_version(version),
                        package_manager=PackageManager.COMPOSER,
                        is_direct=True,
                        is_dev=True,
                        file_path=file_path
                    ))
        
        return dependencies

    async def _parse_go_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances Go"""
        dependencies = []
        
        if file_path.endswith('go.mod'):
            with open(file_path, 'r', encoding='utf-8') as f:
                in_require = False
                
                for line in f:
                    line = line.strip()
                    
                    if line.startswith('require ('):
                        in_require = True
                        continue
                    elif line == ')' and in_require:
                        in_require = False
                        continue
                    elif in_require or line.startswith('require '):
                        # Nettoyer la ligne
                        line = line.replace('require ', '').strip()
                        
                        # Parser "module version"
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            
                            dependencies.append(PackageDependency(
                                name=name,
                                version=version,
                                package_manager=PackageManager.GO_MOD,
                                is_direct=True,
                                is_dev=False,
                                file_path=file_path
                            ))
        
        return dependencies

    async def _parse_cargo_dependencies(self, file_path: str) -> List[PackageDependency]:
        """Parse les dépendances Cargo (Rust)"""
        dependencies = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
            # Dépendances de production
            for name, version_info in data.get('dependencies', {}).items():
                if isinstance(version_info, str):
                    version = version_info
                elif isinstance(version_info, dict):
                    version = version_info.get('version', '*')
                else:
                    version = '*'
                
                dependencies.append(PackageDependency(
                    name=name,
                    version=self._clean_version(version),
                    package_manager=PackageManager.CARGO,
                    is_direct=True,
                    is_dev=False,
                    file_path=file_path
                ))
            
            # Dépendances de développement
            if self.config['include_dev_dependencies']:
                for name, version_info in data.get('dev-dependencies', {}).items():
                    if isinstance(version_info, str):
                        version = version_info
                    elif isinstance(version_info, dict):
                        version = version_info.get('version', '*')
                    else:
                        version = '*'
                    
                    dependencies.append(PackageDependency(
                        name=name,
                        version=self._clean_version(version),
                        package_manager=PackageManager.CARGO,
                        is_direct=True,
                        is_dev=True,
                        file_path=file_path
                    ))
        
        return dependencies

    def _clean_version(self, version: str) -> str:
        """Nettoie et normalise les versions"""
        # Supprimer les préfixes comme ^, ~, >=, etc.
        version = re.sub(r'^[~^>=<]+', '', version.strip())
        return version

    async def _scan_vulnerabilities(self, dependencies: List[PackageDependency]) -> List[DependencyVulnerability]:
        """Scanner les vulnérabilités dans les dépendances"""
        vulnerabilities = []
        
        # Grouper par package manager pour optimiser les requêtes
        by_pm = {}
        for dep in dependencies:
            if dep.package_manager not in by_pm:
                by_pm[dep.package_manager] = []
            by_pm[dep.package_manager].append(dep)
        
        # Scanner chaque groupe
        tasks = []
        for pm, deps in by_pm.items():
            tasks.append(self._scan_package_group(deps, pm))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"⚠️ Error scanning package group: {result}")
            else:
                vulnerabilities.extend(result)
        
        return vulnerabilities

    async def _scan_package_group(self, dependencies: List[PackageDependency], package_manager: PackageManager) -> List[DependencyVulnerability]:
        """Scanner un groupe de packages du même gestionnaire"""
        vulnerabilities = []
        
        # Créer des tâches pour chaque dépendance
        semaphore = asyncio.Semaphore(self.config['max_concurrent_requests'])
        tasks = []
        
        for dep in dependencies:
            task = self._scan_single_dependency(dep, semaphore)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"⚠️ Error scanning dependency: {result}")
            elif result:
                vulnerabilities.extend(result)
        
        return vulnerabilities

    async def _scan_single_dependency(self, dependency: PackageDependency, semaphore: asyncio.Semaphore) -> List[DependencyVulnerability]:
        """Scanner une dépendance unique"""
        async with semaphore:
            vulnerabilities = []
            
            # Vérifier le cache
            cache_key = f"{dependency.package_manager.value}:{dependency.name}:{dependency.version}"
            if cache_key in self.vulnerability_cache:
                cached_data = self.vulnerability_cache[cache_key]
                if datetime.now() - cached_data['timestamp'] < timedelta(hours=self.config['cache_ttl_hours']):
                    return cached_data['vulnerabilities']
            
            # Scanner avec OSV.dev (Open Source Vulnerabilities)
            osv_vulns = await self._query_osv_database(dependency)
            
            # Scanner avec GitHub Advisory Database
            github_vulns = await self._query_github_advisories(dependency)
            
            # Combiner les résultats
            all_vulns = osv_vulns + github_vulns
            
            # Créer les objets DependencyVulnerability
            for vuln_info in all_vulns:
                vuln = DependencyVulnerability(
                    package=dependency,
                    vulnerability=vuln_info,
                    is_exploitable=self._assess_exploitability(vuln_info),
                    is_patchable=self._check_patchable(dependency, vuln_info),
                    priority_score=self._calculate_priority_score(dependency, vuln_info)
                )
                vulnerabilities.append(vuln)
            
            # Mettre en cache
            self.vulnerability_cache[cache_key] = {
                'timestamp': datetime.now(),
                'vulnerabilities': vulnerabilities
            }
            
            return vulnerabilities

    async def _query_osv_database(self, dependency: PackageDependency) -> List[VulnerabilityInfo]:
        """Interroge la base de données OSV.dev"""
        vulnerabilities = []
        
        try:
            # Mapper le package manager vers l'écosystème OSV
            ecosystem_map = {
                PackageManager.NPM: 'npm',
                PackageManager.PIP: 'PyPI',
                PackageManager.MAVEN: 'Maven',
                PackageManager.GO_MOD: 'Go',
                PackageManager.CARGO: 'crates.io'
            }
            
            ecosystem = ecosystem_map.get(dependency.package_manager)
            if not ecosystem:
                return vulnerabilities
            
            query = {
                'package': {
                    'name': dependency.name,
                    'ecosystem': ecosystem
                },
                'version': dependency.version
            }
            
            async with self.session.post(
                self.vuln_databases[VulnerabilitySource.OSV]['url'],
                json=query,
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln_data in data.get('vulns', []):
                        vuln_info = VulnerabilityInfo(
                            vulnerability_id=vuln_data.get('id', ''),
                            title=vuln_data.get('summary', ''),
                            description=vuln_data.get('details', ''),
                            severity=self._extract_severity_from_osv(vuln_data),
                            published_date=self._parse_datetime(vuln_data.get('published')),
                            modified_date=self._parse_datetime(vuln_data.get('modified')),
                            references=[ref.get('url', '') for ref in vuln_data.get('references', [])],
                            source=VulnerabilitySource.OSV,
                            affected_versions=self._extract_affected_versions(vuln_data)
                        )
                        
                        # Extraire CVE si disponible
                        for alias in vuln_data.get('aliases', []):
                            if alias.startswith('CVE-'):
                                vuln_info.cve_id = alias
                                break
                        
                        vulnerabilities.append(vuln_info)
        
        except Exception as e:
            print(f"⚠️ Error querying OSV database: {e}")
        
        return vulnerabilities

    async def _query_github_advisories(self, dependency: PackageDependency) -> List[VulnerabilityInfo]:
        """Interroge GitHub Advisory Database"""
        vulnerabilities = []
        
        try:
            # GitHub Advisory Database supporte plusieurs écosystèmes
            ecosystem_map = {
                PackageManager.NPM: 'npm',
                PackageManager.PIP: 'pip',
                PackageManager.MAVEN: 'maven',
                PackageManager.COMPOSER: 'composer',
                PackageManager.GEM: 'rubygems',
                PackageManager.GO_MOD: 'go',
                PackageManager.CARGO: 'rust'
            }
            
            ecosystem = ecosystem_map.get(dependency.package_manager)
            if not ecosystem:
                return vulnerabilities
            
            url = f"{self.vuln_databases[VulnerabilitySource.GITHUB]['url']}"
            params = {
                'ecosystem': ecosystem,
                'affects': dependency.name,
                'per_page': 100
            }
            
            headers = {}
            if self.vuln_databases[VulnerabilitySource.GITHUB]['token']:
                headers['Authorization'] = f"token {self.vuln_databases[VulnerabilitySource.GITHUB]['token']}"
            
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    advisories = await response.json()
                    
                    for advisory in advisories:
                        # Vérifier si la version est affectée
                        if self._is_version_affected(dependency.version, advisory):
                            vuln_info = VulnerabilityInfo(
                                vulnerability_id=advisory.get('ghsa_id', ''),
                                cve_id=advisory.get('cve_id'),
                                title=advisory.get('summary', ''),
                                description=advisory.get('description', ''),
                                severity=advisory.get('severity', 'unknown').lower(),
                                cvss_score=self._extract_cvss_score(advisory),
                                published_date=self._parse_datetime(advisory.get('published_at')),
                                modified_date=self._parse_datetime(advisory.get('updated_at')),
                                references=[ref.get('url', '') for ref in advisory.get('references', [])],
                                source=VulnerabilitySource.GITHUB
                            )
                            
                            vulnerabilities.append(vuln_info)
                
                elif response.status == 403:
                    print("⚠️ GitHub API rate limit exceeded. Consider adding GITHUB_TOKEN.")
        
        except Exception as e:
            print(f"⚠️ Error querying GitHub advisories: {e}")
        
        return vulnerabilities

    def _extract_severity_from_osv(self, vuln_data: Dict[str, Any]) -> str:
        """Extrait la sévérité des données OSV"""
        # OSV peut avoir différents formats de sévérité
        severity = vuln_data.get('severity', [])
        
        if isinstance(severity, list) and severity:
            for sev in severity:
                if isinstance(sev, dict):
                    if sev.get('type') == 'CVSS_V3':
                        score = sev.get('score')
                        if score:
                            return self._cvss_score_to_severity(float(score))
        
        return 'unknown'

    def _cvss_score_to_severity(self, score: float) -> str:
        """Convertit un score CVSS en sévérité"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score > 0.0:
            return 'low'
        else:
            return 'info'

    def _extract_affected_versions(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extrait les versions affectées des données de vulnérabilité"""
        affected_versions = []
        
        for affected in vuln_data.get('affected', []):
            ranges = affected.get('ranges', [])
            for range_info in ranges:
                events = range_info.get('events', [])
                for event in events:
                    if 'introduced' in event:
                        affected_versions.append(f">={event['introduced']}")
                    elif 'fixed' in event:
                        affected_versions.append(f"<{event['fixed']}")
        
        return affected_versions

    def _extract_cvss_score(self, advisory: Dict[str, Any]) -> Optional[float]:
        """Extrait le score CVSS d'un advisory GitHub"""
        cvss = advisory.get('cvss', {})
        return cvss.get('score') if cvss else None

    def _is_version_affected(self, version: str, advisory: Dict[str, Any]) -> bool:
        """Vérifie si une version est affectée par une vulnérabilité"""
        # Logique simplifiée - dans la réalité, il faudrait analyser les ranges
        vulnerabilities = advisory.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            affected_ranges = vuln.get('vulnerable_version_range', '')
            if affected_ranges:
                # Ici on devrait implémenter une logique de comparaison de versions
                # Pour l'exemple, on considère que c'est affecté
                return True
        
        return False

    def _parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse une date ISO"""
        if not date_str:
            return None
        
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def _assess_exploitability(self, vuln_info: VulnerabilityInfo) -> bool:
        """Évalue si une vulnérabilité est exploitable"""
        # Critères pour déterminer l'exploitabilité
        high_risk_conditions = [
            vuln_info.severity in ['critical', 'high'],
            vuln_info.cvss_score and vuln_info.cvss_score >= 7.0,
            'remote' in vuln_info.description.lower(),
            'rce' in vuln_info.description.lower(),
            'code execution' in vuln_info.description.lower()
        ]
        
        return sum(high_risk_conditions) >= 2

    def _check_patchable(self, dependency: PackageDependency, vuln_info: VulnerabilityInfo) -> bool:
        """Vérifie si une vulnérabilité peut être corrigée"""
        return vuln_info.fixed_version is not None

    def _calculate_priority_score(self, dependency: PackageDependency, vuln_info: VulnerabilityInfo) -> float:
        """Calcule un score de priorité pour la vulnérabilité"""
        score = 0.0
        
        # Score de base selon la sévérité
        severity_scores = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0,
            'info': 0.1
        }
        score += severity_scores.get(vuln_info.severity, 1.0)
        
        # Bonus pour les dépendances directes
        if dependency.is_direct:
            score += 2.0
        
        # Bonus pour les vulnérabilités exploitables
        if self._assess_exploitability(vuln_info):
            score += 3.0
        
        # Malus pour les dépendances de développement
        if dependency.is_dev:
            score *= 0.5
        
        return score

    async def _check_licenses(self, dependencies: List[PackageDependency]) -> List[LicenseIssue]:
        """Vérifie les problèmes de licences"""
        license_issues = []
        
        if not self.config['check_licenses']:
            return license_issues
        
        for dependency in dependencies:
            # Ici, on devrait interroger les registres de packages pour obtenir les licences
            # Pour l'exemple, on simule quelques cas
            
            if dependency.name in ['gpl-licensed-package']:
                issue = LicenseIssue(
                    package=dependency,
                    license='GPL-3.0',
                    issue_type='forbidden',
                    severity='high',
                    description='GPL license is not allowed in this project'
                )
                license_issues.append(issue)
        
        return license_issues

    async def _check_outdated_packages(self, dependencies: List[PackageDependency]) -> List[PackageDependency]:
        """Détecte les packages obsolètes"""
        outdated_packages = []
        
        # Cette fonction nécessiterait d'interroger les registres pour obtenir les dernières versions
        # Pour l'exemple, on simule quelques packages obsolètes
        
        for dependency in dependencies:
            if self._is_version_outdated(dependency.version):
                outdated_packages.append(dependency)
        
        return outdated_packages

    def _is_version_outdated(self, version: str) -> bool:
        """Détermine si une version est obsolète (logique simplifiée)"""
        # Dans la réalité, il faudrait comparer avec la dernière version disponible
        return version.startswith('0.') or 'alpha' in version or 'beta' in version

    def _generate_summary(self, vulnerabilities: List[DependencyVulnerability], 
                         license_issues: List[LicenseIssue], 
                         outdated_packages: List[PackageDependency]) -> Dict[str, int]:
        """Génère un résumé des résultats"""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'exploitable_vulnerabilities': sum(1 for v in vulnerabilities if v.is_exploitable),
            'patchable_vulnerabilities': sum(1 for v in vulnerabilities if v.is_patchable),
            'license_issues': len(license_issues),
            'outdated_packages': len(outdated_packages)
        }
        
        for vuln in vulnerabilities:
            severity_key = f"{vuln.vulnerability.severity}_vulnerabilities"
            if severity_key in summary:
                summary[severity_key] += 1
        
        return summary

    def _assess_risk(self, vulnerabilities: List[DependencyVulnerability], 
                    dependencies: List[PackageDependency]) -> Dict[str, Any]:
        """Évalue le risque global du projet"""
        total_deps = len(dependencies)
        vulnerable_deps = len(set(v.package.name for v in vulnerabilities))
        
        # Calcul du score de risque
        risk_score = 0.0
        for vuln in vulnerabilities:
            risk_score += vuln.priority_score
        
        # Normalisation du score (0-100)
        if total_deps > 0:
            normalized_score = min(100, (risk_score / total_deps) * 10)
        else:
            normalized_score = 0
        
        # Classification du risque
        if normalized_score >= 80:
            risk_level = 'critical'
        elif normalized_score >= 60:
            risk_level = 'high'
        elif normalized_score >= 40:
            risk_level = 'medium'
        elif normalized_score >= 20:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'overall_risk_score': normalized_score,
            'risk_level': risk_level,
            'vulnerable_dependencies_ratio': vulnerable_deps / total_deps if total_deps > 0 else 0,
            'total_dependencies': total_deps,
            'vulnerable_dependencies': vulnerable_deps,
            'recommendations': self._generate_recommendations(vulnerabilities, normalized_score)
        }

    def _generate_recommendations(self, vulnerabilities: List[DependencyVulnerability], risk_score: float) -> List[str]:
        """Génère des recommandations de sécurité"""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("🚨 Critical risk level - Immediate action required")
        elif risk_score >= 60:
            recommendations.append("⚠️ High risk level - Address vulnerabilities within 48 hours")
        
        critical_vulns = [v for v in vulnerabilities if v.vulnerability.severity == 'critical']
        if critical_vulns:
            recommendations.append(f"🔴 {len(critical_vulns)} critical vulnerabilities found - Update immediately")
        
        exploitable_vulns = [v for v in vulnerabilities if v.is_exploitable]
        if exploitable_vulns:
            recommendations.append(f"💥 {len(exploitable_vulns)} exploitable vulnerabilities detected")
        
        patchable_vulns = [v for v in vulnerabilities if v.is_patchable]
        if patchable_vulns:
            recommendations.append(f"🔧 {len(patchable_vulns)} vulnerabilities can be fixed by updating")
        
        recommendations.extend([
            "📋 Review and update dependency management policies",
            "🔄 Implement automated dependency scanning in CI/CD",
            "📊 Monitor dependencies regularly for new vulnerabilities"
        ])
        
        return recommendations

    def export_report(self, report: DependencyScanReport, format: str = 'json', output_path: str = None) -> str:
        """Exporte le rapport dans le format spécifié"""
        if format == 'json':
            data = {
                'scan_id': report.scan_id,
                'project_name': report.project_name,
                'scan_time': report.scan_time.isoformat(),
                'duration_seconds': report.duration_seconds,
                'total_dependencies': report.total_dependencies,
                'direct_dependencies': report.direct_dependencies,
                'transitive_dependencies': report.transitive_dependencies,
                'package_managers': [pm.value for pm in report.package_managers],
                'summary': report.summary,
                'risk_assessment': report.risk_assessment,
                'vulnerabilities': [
                    {
                        'package': {
                            'name': v.package.name,
                            'version': v.package.version,
                            'package_manager': v.package.package_manager.value,
                            'is_direct': v.package.is_direct,
                            'is_dev': v.package.is_dev,
                            'file_path': v.package.file_path
                        },
                        'vulnerability': {
                            'vulnerability_id': v.vulnerability.vulnerability_id,
                            'cve_id': v.vulnerability.cve_id,
                            'title': v.vulnerability.title,
                            'description': v.vulnerability.description,
                            'severity': v.vulnerability.severity,
                            'cvss_score': v.vulnerability.cvss_score,
                            'published_date': v.vulnerability.published_date.isoformat() if v.vulnerability.published_date else None,
                            'references': v.vulnerability.references,
                            'source': v.vulnerability.source.value
                        },
                        'is_exploitable': v.is_exploitable,
                        'is_patchable': v.is_patchable,
                        'priority_score': v.priority_score,
                        'upgrade_path': v.upgrade_path,
                        'workaround': v.workaround
                    }
                    for v in report.vulnerabilities
                ],
                'license_issues': [
                    {
                        'package': {
                            'name': li.package.name,
                            'version': li.package.version,
                            'package_manager': li.package.package_manager.value
                        },
                        'license': li.license,
                        'issue_type': li.issue_type,
                        'severity': li.severity,
                        'description': li.description
                    }
                    for li in report.license_issues
                ],
                'outdated_packages': [
                    {
                        'name': op.name,
                        'current_version': op.version,
                        'package_manager': op.package_manager.value
                    }
                    for op in report.outdated_packages
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
async def main():
    """Exemple d'utilisation du scanner de dépendances"""
    scanner = DependencyScanner()
    
    # Scanner un projet d'exemple
    project_path = "/path/to/your/project"
    
    if os.path.exists(project_path):
        report = await scanner.scan_project(project_path, "Example Project")
        
        print(f"\n📊 Dependency Scan Results:")
        print(f"Project: {report.project_name}")
        print(f"Duration: {report.duration_seconds:.1f}s")
        print(f"Total dependencies: {report.total_dependencies}")
        print(f"Direct: {report.direct_dependencies}, Transitive: {report.transitive_dependencies}")
        print(f"Package managers: {[pm.value for pm in report.package_managers]}")
        
        print(f"\n🚨 Security Summary:")
        summary = report.summary
        for level in ['critical', 'high', 'medium', 'low']:
            count = summary.get(f'{level}_vulnerabilities', 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[level]
                print(f"{emoji} {level.title()}: {count}")
        
        print(f"\n📊 Risk Assessment:")
        risk = report.risk_assessment
        print(f"Overall risk: {risk['risk_level'].upper()} ({risk['overall_risk_score']:.1f}/100)")
        print(f"Vulnerable dependencies: {risk['vulnerable_dependencies']}/{risk['total_dependencies']}")
        
        print(f"\n💡 Recommendations:")
        for rec in risk['recommendations'][:5]:
            print(f"   {rec}")
        
        # Exporter le rapport
        scanner.export_report(report, 'json', 'dependency_report.json')
    
    else:
        print("⚠️ Project path not found, running demo...")
        # Créer un rapport de démonstration
        demo_deps = [
            PackageDependency("express", "4.17.1", PackageManager.NPM, True, False),
            PackageDependency("lodash", "4.17.15", PackageManager.NPM, True, False),
            PackageDependency("requests", "2.25.1", PackageManager.PIP, True, False)
        ]
        
        demo_vulns = [
            DependencyVulnerability(
                package=demo_deps[1],
                vulnerability=VulnerabilityInfo(
                    vulnerability_id="GHSA-1234-5678-9012",
                    cve_id="CVE-2021-23337",
                    title="Prototype Pollution in lodash",
                    description="Prototype pollution vulnerability",
                    severity="high",
                    cvss_score=8.2,
                    source=VulnerabilitySource.GITHUB
                ),
                is_exploitable=True,
                is_patchable=True,
                priority_score=8.5
            )
        ]
        
        print(f"📊 Demo Results:")
        print(f"Dependencies: {len(demo_deps)}")
        print(f"Vulnerabilities: {len(demo_vulns)}")
        print(f"High-severity issues: 1")

if __name__ == "__main__":
    asyncio.run(main())