#!/usr/bin/env python3
"""
Static Application Security Testing (SAST) Scanner
Analyse statique de sécurité du code source multi-langages
"""

import os
import subprocess
import json
import yaml
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import hashlib
import re
import ast

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    PHP = "php"
    RUBY = "ruby"
    SWIFT = "swift"
    KOTLIN = "kotlin"

@dataclass
class SASTFinding:
    """Représente une vulnérabilité détectée par SAST"""
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 à 1.0
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    language: Optional[Language] = None
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class SASTReport:
    """Rapport complet d'analyse SAST"""
    scan_id: str
    project_name: str
    scan_time: datetime
    duration_seconds: float
    total_files_scanned: int
    total_lines_of_code: int
    findings: List[SASTFinding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    languages_detected: List[Language] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    baseline_comparison: Optional[Dict[str, Any]] = None

class SASTScanner:
    """Scanner de sécurité statique multi-outils"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.rules = self._load_security_rules()
        self.language_patterns = {
            Language.PYTHON: [r'\.py$'],
            Language.JAVASCRIPT: [r'\.js$', r'\.jsx$'],
            Language.TYPESCRIPT: [r'\.ts$', r'\.tsx$'],
            Language.JAVA: [r'\.java$'],
            Language.CSHARP: [r'\.cs$'],
            Language.GO: [r'\.go$'],
            Language.PHP: [r'\.php$'],
            Language.RUBY: [r'\.rb$'],
            Language.SWIFT: [r'\.swift$'],
            Language.KOTLIN: [r'\.kt$']
        }
        
        # Configuration des outils SAST
        self.tools_config = {
            'bandit': {
                'languages': [Language.PYTHON],
                'command': 'bandit -r {path} -f json',
                'enabled': True
            },
            'semgrep': {
                'languages': [Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
                'command': 'semgrep --config=auto {path} --json',
                'enabled': True
            },
            'eslint': {
                'languages': [Language.JAVASCRIPT, Language.TYPESCRIPT],
                'command': 'eslint {path} --format json',
                'enabled': True
            },
            'pylint': {
                'languages': [Language.PYTHON],
                'command': 'pylint {path} --output-format=json',
                'enabled': True
            }
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Charge la configuration SAST"""
        default_config = {
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'timeout': 300,  # 5 minutes
            'parallel_jobs': 4,
            'exclude_patterns': [
                '*/node_modules/*',
                '*/vendor/*',
                '*/dist/*',
                '*/build/*',
                '*/.git/*',
                '*/test/*',
                '*/tests/*'
            ],
            'severity_mapping': {
                'error': 'high',
                'warning': 'medium',
                'info': 'low'
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config

    def _load_security_rules(self) -> Dict[str, Dict[str, Any]]:
        """Charge les règles de sécurité personnalisées"""
        return {
            # Règles Python
            'python_sql_injection': {
                'pattern': r'execute\s*\(\s*["\'].*%.*["\']',
                'severity': Severity.HIGH,
                'cwe': 'CWE-89',
                'owasp': 'A03:2021 – Injection',
                'description': 'Potential SQL injection vulnerability',
                'remediation': 'Use parameterized queries'
            },
            'python_command_injection': {
                'pattern': r'os\.system\s*\(\s*.*\+',
                'severity': Severity.HIGH,
                'cwe': 'CWE-78',
                'description': 'Potential command injection',
                'remediation': 'Use subprocess with shell=False'
            },
            'python_hardcoded_password': {
                'pattern': r'password\s*=\s*["\'][^"\']+["\']',
                'severity': Severity.MEDIUM,
                'cwe': 'CWE-798',
                'description': 'Hardcoded password detected',
                'remediation': 'Use environment variables or secure storage'
            },
            
            # Règles JavaScript
            'js_eval_usage': {
                'pattern': r'eval\s*\(',
                'severity': Severity.HIGH,
                'cwe': 'CWE-95',
                'description': 'Use of eval() function',
                'remediation': 'Avoid eval() and use safer alternatives'
            },
            'js_innerHTML': {
                'pattern': r'innerHTML\s*=',
                'severity': Severity.MEDIUM,
                'cwe': 'CWE-79',
                'description': 'Potential XSS via innerHTML',
                'remediation': 'Use textContent or sanitize input'
            }
        }

    def scan_project(self, project_path: str, project_name: str = None) -> SASTReport:
        """Analyse complète d'un projet"""
        print(f"🔍 Starting SAST scan of {project_path}")
        start_time = datetime.now()
        
        if not project_name:
            project_name = os.path.basename(os.path.abspath(project_path))
        
        scan_id = hashlib.md5(f"{project_name}_{start_time}".encode()).hexdigest()
        
        # Découverte des fichiers et langages
        files_by_language = self._discover_files(project_path)
        languages_detected = list(files_by_language.keys())
        total_files = sum(len(files) for files in files_by_language.values())
        total_loc = self._count_lines_of_code(files_by_language)
        
        print(f"📊 Found {total_files} files in {len(languages_detected)} languages")
        print(f"📏 Total lines of code: {total_loc:,}")
        
        all_findings = []
        tools_used = []
        
        # Analyse avec outils externes
        for tool, config in self.tools_config.items():
            if not config['enabled']:
                continue
                
            tool_languages = [lang for lang in config['languages'] if lang in languages_detected]
            if not tool_languages:
                continue
                
            print(f"🔧 Running {tool} scanner...")
            try:
                findings = self._run_tool(tool, project_path, files_by_language)
                all_findings.extend(findings)
                tools_used.append(tool)
                print(f"   ✅ {tool}: {len(findings)} findings")
            except Exception as e:
                print(f"   ❌ {tool}: Error - {e}")
        
        # Analyse avec règles personnalisées
        print("🔧 Running custom rules...")
        custom_findings = self._run_custom_rules(files_by_language)
        all_findings.extend(custom_findings)
        print(f"   ✅ Custom rules: {len(custom_findings)} findings")
        
        # Post-traitement des résultats
        all_findings = self._post_process_findings(all_findings)
        
        # Génération du rapport
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = self._generate_summary(all_findings)
        
        report = SASTReport(
            scan_id=scan_id,
            project_name=project_name,
            scan_time=start_time,
            duration_seconds=duration,
            total_files_scanned=total_files,
            total_lines_of_code=total_loc,
            findings=all_findings,
            summary=summary,
            languages_detected=languages_detected,
            tools_used=tools_used
        )
        
        print(f"✅ SAST scan completed in {duration:.1f}s")
        print(f"📊 Summary: {summary}")
        
        return report

    def _discover_files(self, project_path: str) -> Dict[Language, List[str]]:
        """Découvre et classe les fichiers par langage"""
        files_by_language = {}
        
        for root, dirs, files in os.walk(project_path):
            # Exclure les dossiers configurés
            dirs[:] = [d for d in dirs if not any(
                re.match(pattern.replace('*', '.*'), os.path.join(root, d))
                for pattern in self.config['exclude_patterns']
            )]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Vérifier la taille du fichier
                if os.path.getsize(file_path) > self.config['max_file_size']:
                    continue
                
                # Déterminer le langage
                for language, patterns in self.language_patterns.items():
                    if any(re.search(pattern, file, re.IGNORECASE) for pattern in patterns):
                        if language not in files_by_language:
                            files_by_language[language] = []
                        files_by_language[language].append(file_path)
                        break
        
        return files_by_language

    def _count_lines_of_code(self, files_by_language: Dict[Language, List[str]]) -> int:
        """Compte le nombre total de lignes de code"""
        total_loc = 0
        
        for language, files in files_by_language.items():
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_loc += sum(1 for line in f if line.strip())
                except Exception:
                    pass
        
        return total_loc

    def _run_tool(self, tool: str, project_path: str, files_by_language: Dict[Language, List[str]]) -> List[SASTFinding]:
        """Exécute un outil SAST externe"""
        findings = []
        
        if tool == 'bandit' and Language.PYTHON in files_by_language:
            findings.extend(self._run_bandit(project_path))
        elif tool == 'semgrep':
            findings.extend(self._run_semgrep(project_path))
        elif tool == 'eslint' and (Language.JAVASCRIPT in files_by_language or Language.TYPESCRIPT in files_by_language):
            findings.extend(self._run_eslint(project_path))
        elif tool == 'pylint' and Language.PYTHON in files_by_language:
            findings.extend(self._run_pylint(project_path))
        
        return findings

    def _run_bandit(self, project_path: str) -> List[SASTFinding]:
        """Exécute Bandit pour l'analyse Python"""
        findings = []
        
        try:
            cmd = ['bandit', '-r', project_path, '-f', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            
            if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
                data = json.loads(result.stdout)
                
                for issue in data.get('results', []):
                    finding = SASTFinding(
                        finding_id=f"bandit_{hashlib.md5(f\"{issue['filename']}{issue['line_number']}{issue['test_id']}\".encode()).hexdigest()[:8]}",
                        rule_id=issue['test_id'],
                        title=issue['test_name'],
                        description=issue['issue_text'],
                        severity=self._map_bandit_severity(issue['issue_severity']),
                        confidence=self._map_bandit_confidence(issue['issue_confidence']),
                        file_path=issue['filename'],
                        line_number=issue['line_number'],
                        code_snippet=issue['code'],
                        cwe_id=issue.get('more_info', '').split('/')[-1] if 'cwe' in issue.get('more_info', '') else None,
                        language=Language.PYTHON
                    )
                    findings.append(finding)
        
        except subprocess.TimeoutExpired:
            print(f"⚠️ Bandit scan timed out")
        except Exception as e:
            print(f"⚠️ Bandit scan failed: {e}")
        
        return findings

    def _run_semgrep(self, project_path: str) -> List[SASTFinding]:
        """Exécute Semgrep pour l'analyse multi-langages"""
        findings = []
        
        try:
            cmd = ['semgrep', '--config=auto', project_path, '--json', '--quiet']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for issue in data.get('results', []):
                    finding = SASTFinding(
                        finding_id=f"semgrep_{hashlib.md5(f\"{issue['path']}{issue['start']['line']}{issue['check_id']}\".encode()).hexdigest()[:8]}",
                        rule_id=issue['check_id'],
                        title=issue['check_id'].split('.')[-1],
                        description=issue['extra']['message'],
                        severity=self._map_semgrep_severity(issue['extra']['severity']),
                        confidence=0.8,  # Semgrep généralement fiable
                        file_path=issue['path'],
                        line_number=issue['start']['line'],
                        column_number=issue['start']['col'],
                        code_snippet=issue['extra'].get('lines', ''),
                        owasp_category=issue['extra'].get('metadata', {}).get('owasp', ''),
                        cwe_id=issue['extra'].get('metadata', {}).get('cwe', ''),
                        references=issue['extra'].get('metadata', {}).get('references', [])
                    )
                    findings.append(finding)
        
        except subprocess.TimeoutExpired:
            print(f"⚠️ Semgrep scan timed out")
        except Exception as e:
            print(f"⚠️ Semgrep scan failed: {e}")
        
        return findings

    def _run_eslint(self, project_path: str) -> List[SASTFinding]:
        """Exécute ESLint pour JavaScript/TypeScript"""
        findings = []
        
        try:
            # Configuration ESLint de base pour sécurité
            eslint_config = {
                "extends": ["eslint:recommended", "@eslint/js/recommended"],
                "rules": {
                    "no-eval": "error",
                    "no-implied-eval": "error",
                    "no-new-func": "error",
                    "no-script-url": "error"
                }
            }
            
            config_path = os.path.join(project_path, '.eslint-security.json')
            with open(config_path, 'w') as f:
                json.dump(eslint_config, f)
            
            cmd = ['eslint', project_path, '--config', config_path, '--format', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            
            if result.returncode in [0, 1]:
                data = json.loads(result.stdout)
                
                for file_result in data:
                    for message in file_result.get('messages', []):
                        severity = Severity.HIGH if message['severity'] == 2 else Severity.MEDIUM
                        
                        finding = SASTFinding(
                            finding_id=f"eslint_{hashlib.md5(f\"{file_result['filePath']}{message['line']}{message['ruleId']}\".encode()).hexdigest()[:8]}",
                            rule_id=message.get('ruleId', 'unknown'),
                            title=message.get('ruleId', 'ESLint Issue'),
                            description=message['message'],
                            severity=severity,
                            confidence=0.7,
                            file_path=file_result['filePath'],
                            line_number=message['line'],
                            column_number=message['column'],
                            language=Language.JAVASCRIPT
                        )
                        findings.append(finding)
            
            # Cleanup
            if os.path.exists(config_path):
                os.remove(config_path)
        
        except subprocess.TimeoutExpired:
            print(f"⚠️ ESLint scan timed out")
        except Exception as e:
            print(f"⚠️ ESLint scan failed: {e}")
        
        return findings

    def _run_pylint(self, project_path: str) -> List[SASTFinding]:
        """Exécute Pylint pour l'analyse Python"""
        findings = []
        
        try:
            cmd = ['pylint', project_path, '--output-format=json', '--disable=all', 
                   '--enable=eval-used,exec-used,bad-builtin']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            
            if result.returncode in [0, 1, 2]:  # Pylint exit codes
                try:
                    data = json.loads(result.stdout)
                    
                    for issue in data:
                        finding = SASTFinding(
                            finding_id=f"pylint_{hashlib.md5(f\"{issue['path']}{issue['line']}{issue['symbol']}\".encode()).hexdigest()[:8]}",
                            rule_id=issue['symbol'],
                            title=issue['symbol'],
                            description=issue['message'],
                            severity=self._map_pylint_severity(issue['type']),
                            confidence=0.6,
                            file_path=issue['path'],
                            line_number=issue['line'],
                            column_number=issue['column'],
                            language=Language.PYTHON
                        )
                        findings.append(finding)
                except json.JSONDecodeError:
                    pass  # Pylint parfois ne retourne pas du JSON valide
        
        except subprocess.TimeoutExpired:
            print(f"⚠️ Pylint scan timed out")
        except Exception as e:
            print(f"⚠️ Pylint scan failed: {e}")
        
        return findings

    def _run_custom_rules(self, files_by_language: Dict[Language, List[str]]) -> List[SASTFinding]:
        """Exécute les règles de sécurité personnalisées"""
        findings = []
        
        for language, files in files_by_language.items():
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        # Appliquer les règles appropriées selon le langage
                        applicable_rules = self._get_applicable_rules(language)
                        
                        for rule_id, rule in applicable_rules.items():
                            matches = list(re.finditer(rule['pattern'], content, re.MULTILINE | re.IGNORECASE))
                            
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                
                                finding = SASTFinding(
                                    finding_id=f"custom_{hashlib.md5(f'{file_path}{line_number}{rule_id}'.encode()).hexdigest()[:8]}",
                                    rule_id=rule_id,
                                    title=rule_id.replace('_', ' ').title(),
                                    description=rule['description'],
                                    severity=rule['severity'],
                                    confidence=0.7,
                                    file_path=file_path,
                                    line_number=line_number,
                                    code_snippet=lines[line_number - 1] if line_number <= len(lines) else '',
                                    cwe_id=rule.get('cwe'),
                                    owasp_category=rule.get('owasp'),
                                    remediation=rule.get('remediation'),
                                    language=language
                                )
                                findings.append(finding)
                
                except Exception as e:
                    print(f"⚠️ Error scanning {file_path}: {e}")
        
        return findings

    def _get_applicable_rules(self, language: Language) -> Dict[str, Dict[str, Any]]:
        """Retourne les règles applicables pour un langage"""
        applicable_rules = {}
        
        for rule_id, rule in self.rules.items():
            if language == Language.PYTHON and rule_id.startswith('python_'):
                applicable_rules[rule_id] = rule
            elif language in [Language.JAVASCRIPT, Language.TYPESCRIPT] and rule_id.startswith('js_'):
                applicable_rules[rule_id] = rule
        
        return applicable_rules

    def _post_process_findings(self, findings: List[SASTFinding]) -> List[SASTFinding]:
        """Post-traitement des résultats pour déduplication et amélioration"""
        # Déduplication basée sur fichier + ligne + règle
        seen = set()
        deduplicated = []
        
        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        # Tri par sévérité puis par fichier
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        
        deduplicated.sort(key=lambda f: (severity_order[f.severity], f.file_path, f.line_number))
        
        return deduplicated

    def _generate_summary(self, findings: List[SASTFinding]) -> Dict[str, int]:
        """Génère un résumé des résultats"""
        summary = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            summary[finding.severity.value] += 1
        
        return summary

    def _map_bandit_severity(self, severity: str) -> Severity:
        """Mappe la sévérité Bandit vers notre enum"""
        mapping = {
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)

    def _map_bandit_confidence(self, confidence: str) -> float:
        """Mappe la confiance Bandit vers un float"""
        mapping = {
            'HIGH': 0.9,
            'MEDIUM': 0.7,
            'LOW': 0.5
        }
        return mapping.get(confidence.upper(), 0.7)

    def _map_semgrep_severity(self, severity: str) -> Severity:
        """Mappe la sévérité Semgrep vers notre enum"""
        mapping = {
            'ERROR': Severity.HIGH,
            'WARNING': Severity.MEDIUM,
            'INFO': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)

    def _map_pylint_severity(self, message_type: str) -> Severity:
        """Mappe le type de message Pylint vers notre enum"""
        mapping = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'refactor': Severity.LOW,
            'convention': Severity.INFO
        }
        return mapping.get(message_type.lower(), Severity.MEDIUM)

    def export_report(self, report: SASTReport, format: str = 'json', output_path: str = None) -> str:
        """Exporte le rapport dans le format spécifié"""
        if format == 'json':
            data = {
                'scan_id': report.scan_id,
                'project_name': report.project_name,
                'scan_time': report.scan_time.isoformat(),
                'duration_seconds': report.duration_seconds,
                'total_files_scanned': report.total_files_scanned,
                'total_lines_of_code': report.total_lines_of_code,
                'summary': report.summary,
                'languages_detected': [lang.value for lang in report.languages_detected],
                'tools_used': report.tools_used,
                'findings': [
                    {
                        'finding_id': f.finding_id,
                        'rule_id': f.rule_id,
                        'title': f.title,
                        'description': f.description,
                        'severity': f.severity.value,
                        'confidence': f.confidence,
                        'file_path': f.file_path,
                        'line_number': f.line_number,
                        'column_number': f.column_number,
                        'code_snippet': f.code_snippet,
                        'cwe_id': f.cwe_id,
                        'owasp_category': f.owasp_category,
                        'remediation': f.remediation,
                        'references': f.references,
                        'language': f.language.value if f.language else None,
                        'timestamp': f.timestamp.isoformat()
                    }
                    for f in report.findings
                ]
            }
            
            output = json.dumps(data, indent=2)
        
        elif format == 'sarif':
            # Format SARIF (Static Analysis Results Interchange Format)
            output = self._generate_sarif_report(report)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"📄 Report exported to {output_path}")
        
        return output

    def _generate_sarif_report(self, report: SASTReport) -> str:
        """Génère un rapport au format SARIF"""
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DevSecOps SAST Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/devsecops/sast-scanner"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for finding in report.findings:
            result = {
                "ruleId": finding.rule_id,
                "message": {
                    "text": finding.description
                },
                "level": self._severity_to_sarif_level(finding.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.column_number or 1
                            }
                        }
                    }
                ]
            }
            
            if finding.cwe_id:
                result["properties"] = {"cwe": finding.cwe_id}
            
            sarif["runs"][0]["results"].append(result)
        
        return json.dumps(sarif, indent=2)

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convertit la sévérité vers le niveau SARIF"""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "warning")

# Exemple d'utilisation
async def main():
    """Exemple d'utilisation du scanner SAST"""
    scanner = SASTScanner()
    
    # Scanner un projet Python d'exemple
    project_path = "/path/to/your/project"
    
    if os.path.exists(project_path):
        report = scanner.scan_project(project_path, "Example Project")
        
        print(f"\n📊 SAST Scan Results:")
        print(f"Project: {report.project_name}")
        print(f"Duration: {report.duration_seconds:.1f}s")
        print(f"Files scanned: {report.total_files_scanned}")
        print(f"Lines of code: {report.total_lines_of_code:,}")
        print(f"Languages: {[lang.value for lang in report.languages_detected]}")
        print(f"Tools used: {report.tools_used}")
        
        print(f"\n🚨 Security Findings:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = report.summary.get(severity.value, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity.value, "⚪")
                print(f"{emoji} {severity.value.title()}: {count}")
        
        # Afficher quelques exemples de vulnérabilités
        print(f"\n📝 Example Findings:")
        for finding in report.findings[:5]:
            print(f"   • {finding.title} ({finding.severity.value})")
            print(f"     File: {finding.file_path}:{finding.line_number}")
            print(f"     Description: {finding.description}")
        
        # Exporter le rapport
        scanner.export_report(report, 'json', 'sast_report.json')
        scanner.export_report(report, 'sarif', 'sast_report.sarif')
    
    else:
        print("⚠️ Project path not found, running with demo data...")
        # Créer un rapport de démonstration
        demo_report = SASTReport(
            scan_id="demo_scan_123",
            project_name="Demo Project",
            scan_time=datetime.now(),
            duration_seconds=45.2,
            total_files_scanned=25,
            total_lines_of_code=2500,
            summary={'critical': 2, 'high': 5, 'medium': 12, 'low': 8, 'info': 3},
            languages_detected=[Language.PYTHON, Language.JAVASCRIPT],
            tools_used=['bandit', 'semgrep']
        )
        
        print(f"📊 Demo SAST Results: {demo_report.summary}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())