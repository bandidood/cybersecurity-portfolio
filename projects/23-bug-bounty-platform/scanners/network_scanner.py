#!/usr/bin/env python3
"""
Network Vulnerability Scanner
Automated scanner for network services and infrastructure vulnerabilities
"""

import socket
import asyncio
import aiofiles
import subprocess
import json
import re
import ipaddress
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import xml.etree.ElementTree as ET
import hashlib
import concurrent.futures
import threading
import time

@dataclass
class NetworkTarget:
    """Represents a network target for scanning"""
    target: str  # IP, CIDR, or hostname
    ports: Optional[List[int]] = None  # Specific ports, None for common ports
    port_range: Optional[Tuple[int, int]] = None  # Port range (start, end)
    timeout: int = 5
    max_threads: int = 50
    service_detection: bool = True
    version_detection: bool = True
    os_detection: bool = False
    aggressive_scan: bool = False
    exclude_hosts: List[str] = field(default_factory=list)

@dataclass
class ServiceInfo:
    """Information about a discovered service"""
    host: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    fingerprint: Optional[str] = None

@dataclass
class NetworkVulnerability:
    """Represents a network vulnerability"""
    vuln_id: str
    name: str
    severity: str
    confidence: float
    description: str
    host: str
    port: int
    service: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

class NetworkScanner:
    """Advanced network vulnerability scanner"""
    
    def __init__(self):
        self.discovered_hosts = set()
        self.discovered_services = []
        self.vulnerabilities = []
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'hosts_scanned': 0,
            'services_found': 0,
            'vulnerabilities_found': 0
        }
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ]
        
        # Service banners and version signatures
        self.service_signatures = {
            'ssh': {
                'patterns': [r'SSH-(\d+\.\d+)-(.+)', r'OpenSSH[_\s]+(\d+\.\d+)'],
                'vulns': self._check_ssh_vulns
            },
            'ftp': {
                'patterns': [r'(\w+)\s+FTP.*[Ss]erver.*(\d+\.\d+)', r'220.*FTP.*(\d+\.\d+)'],
                'vulns': self._check_ftp_vulns
            },
            'http': {
                'patterns': [r'Server:\s*(.+)', r'Apache/(\d+\.\d+\.\d+)', r'nginx/(\d+\.\d+)'],
                'vulns': self._check_http_vulns
            },
            'mysql': {
                'patterns': [r'(\d+\.\d+\.\d+)-MySQL', r'mysql_native_password'],
                'vulns': self._check_mysql_vulns
            },
            'postgresql': {
                'patterns': [r'PostgreSQL\s+(\d+\.\d+)', r'FATAL.*password'],
                'vulns': self._check_postgresql_vulns
            },
            'redis': {
                'patterns': [r'redis_version:(\d+\.\d+\.\d+)', r'\+PONG'],
                'vulns': self._check_redis_vulns
            }
        }
        
        # Known vulnerability patterns
        self.vuln_patterns = {
            'weak_ciphers': [
                'RC4', 'DES', '3DES', 'MD5', 'SHA1'
            ],
            'default_credentials': {
                'admin': ['admin', 'password', '123456'],
                'root': ['root', 'toor', 'password'],
                'guest': ['guest', ''],
                'oracle': ['oracle', 'system'],
                'postgres': ['postgres', 'password']
            },
            'outdated_versions': {
                'openssh': ['5.3', '6.6', '7.0'],
                'apache': ['2.2', '2.4.29'],
                'nginx': ['1.10', '1.14.0'],
                'mysql': ['5.5', '5.6'],
                'postgresql': ['9.3', '9.4', '9.5']
            }
        }

    async def scan_network(self, target: NetworkTarget) -> Tuple[List[ServiceInfo], List[NetworkVulnerability]]:
        """Main network scanning method"""
        print(f"🎯 Starting network scan of {target.target}")
        self.scan_stats['start_time'] = datetime.now()
        
        # Step 1: Host discovery
        hosts = await self._discover_hosts(target)
        
        # Step 2: Port scanning
        services = await self._scan_ports(hosts, target)
        
        # Step 3: Service detection and banner grabbing
        await self._detect_services(services, target)
        
        # Step 4: Vulnerability assessment
        await self._assess_vulnerabilities(services, target)
        
        self.scan_stats['end_time'] = datetime.now()
        self.scan_stats['hosts_scanned'] = len(hosts)
        self.scan_stats['services_found'] = len(self.discovered_services)
        self.scan_stats['vulnerabilities_found'] = len(self.vulnerabilities)
        
        print(f"✅ Network scan completed: {len(self.vulnerabilities)} vulnerabilities found")
        return self.discovered_services, self.vulnerabilities

    async def _discover_hosts(self, target: NetworkTarget) -> List[str]:
        """Discover active hosts in the target range"""
        hosts = []
        
        try:
            if '/' in target.target:  # CIDR notation
                network = ipaddress.ip_network(target.target, strict=False)
                print(f"🔍 Discovering hosts in {network} ({network.num_addresses} addresses)")
                
                # Limit host discovery to reasonable size
                if network.num_addresses > 1024:
                    print("⚠️ Large network detected, limiting to first 1024 hosts")
                    host_list = list(network.hosts())[:1024]
                else:
                    host_list = list(network.hosts())
                
                # Ping sweep
                tasks = []
                semaphore = asyncio.Semaphore(target.max_threads)
                
                for host in host_list:
                    if str(host) not in target.exclude_hosts:
                        task = self._ping_host(str(host), semaphore, target.timeout)
                        tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                hosts = [host for host in results if host and not isinstance(host, Exception)]
                
            else:  # Single host
                if await self._ping_host(target.target, asyncio.Semaphore(1), target.timeout):
                    hosts.append(target.target)
        
        except Exception as e:
            print(f"❌ Error in host discovery: {e}")
            # Fallback to single target
            hosts = [target.target]
        
        print(f"📊 Discovered {len(hosts)} active hosts")
        self.discovered_hosts.update(hosts)
        return hosts

    async def _ping_host(self, host: str, semaphore: asyncio.Semaphore, timeout: int) -> Optional[str]:
        """Ping a single host to check if it's alive"""
        async with semaphore:
            try:
                # Use OS-specific ping command
                import platform
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
                else:
                    cmd = ['ping', '-c', '1', '-W', str(timeout), host]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout + 2
                )
                
                if process.returncode == 0:
                    return host
                    
            except Exception:
                pass
                
        return None

    async def _scan_ports(self, hosts: List[str], target: NetworkTarget) -> List[ServiceInfo]:
        """Scan ports on discovered hosts"""
        print(f"🔍 Scanning ports on {len(hosts)} hosts")
        services = []
        
        # Determine ports to scan
        if target.ports:
            ports_to_scan = target.ports
        elif target.port_range:
            ports_to_scan = list(range(target.port_range[0], target.port_range[1] + 1))
        else:
            ports_to_scan = self.common_ports
        
        print(f"📊 Scanning {len(ports_to_scan)} ports per host")
        
        tasks = []
        semaphore = asyncio.Semaphore(target.max_threads)
        
        for host in hosts:
            for port in ports_to_scan:
                task = self._scan_port(host, port, semaphore, target.timeout)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                services.append(result)
        
        print(f"📊 Found {len(services)} open ports")
        return services

    async def _scan_port(self, host: str, port: int, semaphore: asyncio.Semaphore, timeout: int) -> Optional[ServiceInfo]:
        """Scan a single port"""
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                
                service = ServiceInfo(
                    host=host,
                    port=port,
                    protocol='tcp',
                    state='open'
                )
                return service
                
            except Exception:
                return None

    async def _detect_services(self, services: List[ServiceInfo], target: NetworkTarget):
        """Detect services and grab banners"""
        if not target.service_detection:
            self.discovered_services = services
            return
        
        print(f"🔍 Detecting services for {len(services)} open ports")
        
        tasks = []
        semaphore = asyncio.Semaphore(20)  # Limit concurrent banner grabs
        
        for service in services:
            task = self._grab_banner(service, semaphore, target.timeout)
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
        self.discovered_services = services

    async def _grab_banner(self, service: ServiceInfo, semaphore: asyncio.Semaphore, timeout: int):
        """Grab service banner"""
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(service.host, service.port),
                    timeout=timeout
                )
                
                # Try to read banner
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                    service.banner = banner.decode('utf-8', errors='ignore').strip()
                except:
                    # Try sending a probe
                    writer.write(b'GET / HTTP/1.0\r\n\r\n')
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=2)
                    service.banner = response.decode('utf-8', errors='ignore').strip()
                
                writer.close()
                await writer.wait_closed()
                
                # Identify service from banner
                self._identify_service(service)
                
            except Exception as e:
                # Fallback service detection based on port
                service.service_name = self._guess_service_by_port(service.port)

    def _identify_service(self, service: ServiceInfo):
        """Identify service from banner"""
        if not service.banner:
            service.service_name = self._guess_service_by_port(service.port)
            return
        
        banner_lower = service.banner.lower()
        
        # Check against known patterns
        for service_name, config in self.service_signatures.items():
            for pattern in config['patterns']:
                match = re.search(pattern, service.banner, re.IGNORECASE)
                if match:
                    service.service_name = service_name
                    if len(match.groups()) > 0:
                        service.version = match.group(1)
                    return
        
        # Fallback identification
        if 'http' in banner_lower or 'html' in banner_lower:
            service.service_name = 'http'
        elif 'ssh' in banner_lower:
            service.service_name = 'ssh'
        elif 'ftp' in banner_lower:
            service.service_name = 'ftp'
        elif 'smtp' in banner_lower:
            service.service_name = 'smtp'
        else:
            service.service_name = self._guess_service_by_port(service.port)

    def _guess_service_by_port(self, port: int) -> str:
        """Guess service by well-known port"""
        port_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpc', 135: 'msrpc', 139: 'netbios',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1723: 'pptp', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb'
        }
        return port_map.get(port, 'unknown')

    async def _assess_vulnerabilities(self, services: List[ServiceInfo], target: NetworkTarget):
        """Assess vulnerabilities in discovered services"""
        print(f"🔍 Assessing vulnerabilities for {len(services)} services")
        
        for service in services:
            if service.service_name:
                await self._check_service_vulnerabilities(service, target)

    async def _check_service_vulnerabilities(self, service: ServiceInfo, target: NetworkTarget):
        """Check vulnerabilities for a specific service"""
        service_name = service.service_name.lower()
        
        # Check against signature-based vulnerabilities
        if service_name in self.service_signatures:
            vuln_checker = self.service_signatures[service_name]['vulns']
            await vuln_checker(service, target)
        
        # Generic checks
        await self._check_generic_vulnerabilities(service, target)

    async def _check_ssh_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check SSH-specific vulnerabilities"""
        if not service.banner:
            return
        
        # Check for outdated OpenSSH versions
        version_match = re.search(r'OpenSSH[_\s]+(\d+\.\d+)', service.banner)
        if version_match:
            version = version_match.group(1)
            if version in self.vuln_patterns['outdated_versions'].get('openssh', []):
                vuln = NetworkVulnerability(
                    vuln_id=f"ssh_outdated_{service.host}_{service.port}",
                    name="Outdated SSH Version",
                    severity="Medium",
                    confidence=0.9,
                    description=f"Outdated OpenSSH version {version} detected",
                    host=service.host,
                    port=service.port,
                    service="ssh",
                    evidence=f"Banner: {service.banner}",
                    remediation="Update OpenSSH to the latest version",
                    references=["https://www.openssh.com/security.html"]
                )
                self.vulnerabilities.append(vuln)
        
        # Check for weak authentication methods
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(service.host, service.port),
                timeout=5
            )
            
            # Try authentication with common credentials
            for username, passwords in self.vuln_patterns['default_credentials'].items():
                if username in ['root', 'admin']:  # Focus on high-impact accounts
                    for password in passwords[:2]:  # Limit attempts
                        # This is a simulated check - in reality, you'd implement proper SSH auth
                        if self._simulate_weak_auth_check(username, password):
                            vuln = NetworkVulnerability(
                                vuln_id=f"ssh_weak_creds_{service.host}_{service.port}",
                                name="Weak SSH Credentials",
                                severity="Critical",
                                confidence=0.8,
                                description=f"Weak credentials detected: {username}/{password}",
                                host=service.host,
                                port=service.port,
                                service="ssh",
                                evidence=f"Authentication successful with {username}:{password}",
                                remediation="Change default passwords and implement key-based authentication",
                                references=["https://owasp.org/www-community/vulnerabilities/Weak_password"]
                            )
                            self.vulnerabilities.append(vuln)
                            break
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass

    async def _check_ftp_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check FTP-specific vulnerabilities"""
        if not service.banner:
            return
        
        # Check for anonymous FTP
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(service.host, service.port),
                timeout=5
            )
            
            # Try anonymous login
            writer.write(b'USER anonymous\r\n')
            await writer.drain()
            response = await reader.read(1024)
            
            writer.write(b'PASS anonymous@example.com\r\n')
            await writer.drain()
            response = await reader.read(1024)
            
            if b'230' in response:  # Successful login
                vuln = NetworkVulnerability(
                    vuln_id=f"ftp_anonymous_{service.host}_{service.port}",
                    name="Anonymous FTP Access",
                    severity="High",
                    confidence=1.0,
                    description="Anonymous FTP access is enabled",
                    host=service.host,
                    port=service.port,
                    service="ftp",
                    evidence="Anonymous login successful",
                    remediation="Disable anonymous FTP access",
                    references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]
                )
                self.vulnerabilities.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass

    async def _check_http_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check HTTP-specific vulnerabilities"""
        # Check for common HTTP vulnerabilities
        scheme = 'https' if service.port in [443, 8443] else 'http'
        url = f"{scheme}://{service.host}:{service.port}"
        
        # This would integrate with the web scanner
        # For now, just check server header
        if service.banner and 'Server:' in service.banner:
            server_match = re.search(r'Server:\s*(.+)', service.banner)
            if server_match:
                server = server_match.group(1).strip()
                
                # Check for server version disclosure
                vuln = NetworkVulnerability(
                    vuln_id=f"http_version_disclosure_{service.host}_{service.port}",
                    name="Server Version Disclosure",
                    severity="Low",
                    confidence=1.0,
                    description=f"Server version disclosed: {server}",
                    host=service.host,
                    port=service.port,
                    service="http",
                    evidence=f"Server header: {server}",
                    remediation="Configure web server to hide version information",
                    references=["https://owasp.org/www-community/Security_Headers"]
                )
                self.vulnerabilities.append(vuln)

    async def _check_mysql_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check MySQL-specific vulnerabilities"""
        # Check for default MySQL credentials
        common_creds = [('root', ''), ('root', 'root'), ('root', 'mysql')]
        
        for username, password in common_creds:
            if self._simulate_weak_auth_check(username, password):
                vuln = NetworkVulnerability(
                    vuln_id=f"mysql_weak_creds_{service.host}_{service.port}",
                    name="Weak MySQL Credentials",
                    severity="Critical",
                    confidence=0.8,
                    description=f"Weak MySQL credentials: {username}/{password}",
                    host=service.host,
                    port=service.port,
                    service="mysql",
                    evidence=f"Authentication successful with {username}:{password}",
                    remediation="Change default MySQL passwords and restrict access",
                    references=["https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html"]
                )
                self.vulnerabilities.append(vuln)
                break

    async def _check_postgresql_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check PostgreSQL-specific vulnerabilities"""
        # Similar to MySQL check
        common_creds = [('postgres', ''), ('postgres', 'postgres'), ('postgres', 'password')]
        
        for username, password in common_creds:
            if self._simulate_weak_auth_check(username, password):
                vuln = NetworkVulnerability(
                    vuln_id=f"postgresql_weak_creds_{service.host}_{service.port}",
                    name="Weak PostgreSQL Credentials",
                    severity="Critical",
                    confidence=0.8,
                    description=f"Weak PostgreSQL credentials: {username}/{password}",
                    host=service.host,
                    port=service.port,
                    service="postgresql",
                    evidence=f"Authentication successful with {username}:{password}",
                    remediation="Change default PostgreSQL passwords and configure proper authentication",
                    references=["https://www.postgresql.org/docs/current/auth-methods.html"]
                )
                self.vulnerabilities.append(vuln)
                break

    async def _check_redis_vulns(self, service: ServiceInfo, target: NetworkTarget):
        """Check Redis-specific vulnerabilities"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(service.host, service.port),
                timeout=5
            )
            
            # Try INFO command (should work if no auth required)
            writer.write(b'INFO\r\n')
            await writer.drain()
            response = await reader.read(1024)
            
            if b'redis_version' in response:
                vuln = NetworkVulnerability(
                    vuln_id=f"redis_no_auth_{service.host}_{service.port}",
                    name="Redis No Authentication",
                    severity="High",
                    confidence=1.0,
                    description="Redis instance accessible without authentication",
                    host=service.host,
                    port=service.port,
                    service="redis",
                    evidence="INFO command executed successfully",
                    remediation="Configure Redis authentication and bind to localhost only",
                    references=["https://redis.io/topics/security"]
                )
                self.vulnerabilities.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass

    async def _check_generic_vulnerabilities(self, service: ServiceInfo, target: NetworkTarget):
        """Check for generic vulnerabilities"""
        # Check for services running on non-standard ports
        expected_port = self._get_standard_port(service.service_name)
        if expected_port and service.port != expected_port:
            # This might indicate security through obscurity or misconfiguration
            vuln = NetworkVulnerability(
                vuln_id=f"non_standard_port_{service.host}_{service.port}",
                name="Service on Non-Standard Port",
                severity="Info",
                confidence=0.6,
                description=f"{service.service_name} service running on non-standard port {service.port}",
                host=service.host,
                port=service.port,
                service=service.service_name,
                evidence=f"Expected port: {expected_port}, actual port: {service.port}",
                remediation="Ensure service configuration is intentional and properly secured",
                references=["https://www.iana.org/assignments/service-names-port-numbers/"]
            )
            self.vulnerabilities.append(vuln)

    def _get_standard_port(self, service_name: str) -> Optional[int]:
        """Get standard port for a service"""
        standard_ports = {
            'ftp': 21, 'ssh': 22, 'telnet': 23, 'smtp': 25, 'dns': 53,
            'http': 80, 'pop3': 110, 'imap': 143, 'https': 443,
            'mysql': 3306, 'postgresql': 5432, 'redis': 6379
        }
        return standard_ports.get(service_name.lower())

    def _simulate_weak_auth_check(self, username: str, password: str) -> bool:
        """Simulate weak authentication check (placeholder)"""
        # In a real implementation, this would actually attempt authentication
        # For demo purposes, we'll simulate finding weak creds occasionally
        import random
        return random.random() < 0.1  # 10% chance of finding weak creds

    def generate_report(self, format: str = "json") -> str:
        """Generate network scan report"""
        report_data = {
            'scan_info': {
                'start_time': self.scan_stats['start_time'].isoformat() if self.scan_stats['start_time'] else None,
                'end_time': self.scan_stats['end_time'].isoformat() if self.scan_stats['end_time'] else None,
                'duration': str(self.scan_stats['end_time'] - self.scan_stats['start_time']) if self.scan_stats['end_time'] and self.scan_stats['start_time'] else None,
                'hosts_scanned': self.scan_stats['hosts_scanned'],
                'services_found': self.scan_stats['services_found'],
                'vulnerabilities_found': self.scan_stats['vulnerabilities_found']
            },
            'discovered_hosts': list(self.discovered_hosts),
            'services': [],
            'vulnerabilities': []
        }
        
        # Add services
        for service in self.discovered_services:
            service_data = {
                'host': service.host,
                'port': service.port,
                'protocol': service.protocol,
                'state': service.state,
                'service_name': service.service_name,
                'version': service.version,
                'banner': service.banner[:200] + "..." if service.banner and len(service.banner) > 200 else service.banner
            }
            report_data['services'].append(service_data)
        
        # Add vulnerabilities
        for vuln in self.vulnerabilities:
            vuln_data = {
                'id': vuln.vuln_id,
                'name': vuln.name,
                'severity': vuln.severity,
                'confidence': vuln.confidence,
                'description': vuln.description,
                'host': vuln.host,
                'port': vuln.port,
                'service': vuln.service,
                'cve_id': vuln.cve_id,
                'cvss_score': vuln.cvss_score,
                'exploit_available': vuln.exploit_available,
                'evidence': vuln.evidence,
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
    """Example usage of the network scanner"""
    scanner = NetworkScanner()
    
    target = NetworkTarget(
        target="127.0.0.1",
        ports=[22, 80, 443, 3306, 5432],
        timeout=3,
        service_detection=True,
        version_detection=True
    )
    
    services, vulnerabilities = await scanner.scan_network(target)
    
    print(f"\n📊 Network Scan Results:")
    print(f"Found {len(services)} services and {len(vulnerabilities)} vulnerabilities")
    
    print(f"\n🔍 Discovered Services:")
    for service in services[:10]:  # Show first 10
        print(f"  {service.host}:{service.port} - {service.service_name or 'unknown'} ({service.state})")
        if service.banner:
            print(f"    Banner: {service.banner[:100]}...")
    
    print(f"\n🚨 Vulnerabilities:")
    for vuln in vulnerabilities[:5]:  # Show first 5
        print(f"  {vuln.name} ({vuln.severity}) - {vuln.host}:{vuln.port}")
        print(f"    {vuln.description}")
    
    # Generate report
    report = scanner.generate_report()
    print(f"\n📄 Report generated ({len(report)} characters)")

if __name__ == "__main__":
    asyncio.run(main())