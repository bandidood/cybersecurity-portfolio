#!/usr/bin/env python3
"""
Unified Scan Engine
Coordinates and manages different types of vulnerability scans
"""

import asyncio
import json
import uuid
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import logging

from .web_scanner import WebScanner, ScanTarget as WebTarget, Vulnerability as WebVuln
from .network_scanner import NetworkScanner, NetworkTarget, NetworkVulnerability as NetVuln

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanType(Enum):
    WEB = "web"
    NETWORK = "network" 
    COMBINED = "combined"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScanConfiguration:
    """Configuration for a vulnerability scan"""
    scan_id: str
    scan_type: ScanType
    target: str
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Web scan specific
    web_depth: int = 2
    web_max_pages: int = 50
    include_subdomains: bool = False
    custom_headers: Optional[Dict[str, str]] = None
    
    # Network scan specific
    ports: Optional[List[int]] = None
    port_range: Optional[tuple] = None
    timeout: int = 5
    max_threads: int = 50
    service_detection: bool = True
    version_detection: bool = True
    os_detection: bool = False
    
    # General options
    aggressive_scan: bool = False
    exclude_hosts: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    # Scheduling
    scheduled_time: Optional[datetime] = None
    recurring: bool = False
    recurring_interval: Optional[timedelta] = None

@dataclass
class ScanResult:
    """Result of a vulnerability scan"""
    scan_id: str
    scan_type: ScanType
    target: str
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[timedelta] = None
    
    # Results
    web_vulnerabilities: List[WebVuln] = field(default_factory=list)
    network_vulnerabilities: List[NetVuln] = field(default_factory=list)
    total_vulnerabilities: int = 0
    
    # Statistics
    pages_crawled: int = 0
    requests_sent: int = 0
    hosts_scanned: int = 0
    services_found: int = 0
    
    # Metadata
    error_message: Optional[str] = None
    scan_config: Optional[ScanConfiguration] = None

class ScanEngine:
    """Unified vulnerability scan engine"""
    
    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_history: List[ScanResult] = []
        self.scheduled_scans: List[ScanConfiguration] = []
        self.max_concurrent_scans = 5
        self.scan_queue = asyncio.Queue()
        self.worker_tasks = []
        self.running = False
        
    async def start_engine(self):
        """Start the scan engine"""
        if self.running:
            return
            
        self.running = True
        logger.info("🚀 Starting scan engine")
        
        # Start worker tasks
        for i in range(self.max_concurrent_scans):
            task = asyncio.create_task(self._scan_worker(f"worker-{i}"))
            self.worker_tasks.append(task)
        
        # Start scheduler task
        scheduler_task = asyncio.create_task(self._scheduler())
        self.worker_tasks.append(scheduler_task)
        
    async def stop_engine(self):
        """Stop the scan engine"""
        if not self.running:
            return
            
        self.running = False
        logger.info("🛑 Stopping scan engine")
        
        # Cancel all worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        self.worker_tasks.clear()
    
    async def submit_scan(self, config: ScanConfiguration) -> str:
        """Submit a new scan for execution"""
        scan_id = config.scan_id or str(uuid.uuid4())
        config.scan_id = scan_id
        
        # Create scan result
        result = ScanResult(
            scan_id=scan_id,
            scan_type=config.scan_type,
            target=config.target,
            status=ScanStatus.PENDING,
            start_time=datetime.now(),
            scan_config=config
        )
        
        # Add to active scans
        self.active_scans[scan_id] = result
        
        # Queue for execution
        if config.scheduled_time and config.scheduled_time > datetime.now():
            # Schedule for later
            self.scheduled_scans.append(config)
            logger.info(f"📅 Scheduled scan {scan_id} for {config.scheduled_time}")
        else:
            # Execute immediately
            await self.scan_queue.put(config)
            logger.info(f"📥 Queued scan {scan_id} for immediate execution")
        
        return scan_id
    
    async def get_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Get the status of a scan"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        # Check scan history
        for result in self.scan_history:
            if result.scan_id == scan_id:
                return result
        
        return None
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id not in self.active_scans:
            return False
        
        result = self.active_scans[scan_id]
        if result.status == ScanStatus.RUNNING:
            result.status = ScanStatus.CANCELLED
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time
            logger.info(f"❌ Cancelled scan {scan_id}")
            return True
        
        return False
    
    async def list_active_scans(self) -> List[ScanResult]:
        """List all active scans"""
        return list(self.active_scans.values())
    
    async def get_scan_history(self, limit: int = 100) -> List[ScanResult]:
        """Get scan history"""
        return self.scan_history[-limit:]
    
    async def _scan_worker(self, worker_id: str):
        """Worker task that processes scans from the queue"""
        logger.info(f"👷 Worker {worker_id} started")
        
        while self.running:
            try:
                # Wait for a scan configuration
                config = await asyncio.wait_for(self.scan_queue.get(), timeout=1.0)
                
                # Execute the scan
                await self._execute_scan(config)
                
                # Mark task as done
                self.scan_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"❌ Worker {worker_id} error: {e}")
                continue
        
        logger.info(f"👷 Worker {worker_id} stopped")
    
    async def _scheduler(self):
        """Scheduler task that manages scheduled scans"""
        logger.info("📅 Scheduler started")
        
        while self.running:
            try:
                current_time = datetime.now()
                
                # Check for scheduled scans that are ready to execute
                ready_scans = []
                for config in self.scheduled_scans[:]:
                    if config.scheduled_time and config.scheduled_time <= current_time:
                        ready_scans.append(config)
                        self.scheduled_scans.remove(config)
                
                # Queue ready scans
                for config in ready_scans:
                    await self.scan_queue.put(config)
                    logger.info(f"📤 Queued scheduled scan {config.scan_id}")
                
                # Handle recurring scans
                for config in ready_scans:
                    if config.recurring and config.recurring_interval:
                        # Schedule next occurrence
                        new_config = ScanConfiguration(
                            scan_id=str(uuid.uuid4()),
                            scan_type=config.scan_type,
                            target=config.target,
                            name=config.name,
                            description=config.description,
                            scheduled_time=current_time + config.recurring_interval,
                            recurring=True,
                            recurring_interval=config.recurring_interval
                        )
                        self.scheduled_scans.append(new_config)
                        logger.info(f"🔄 Scheduled recurring scan {new_config.scan_id}")
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"❌ Scheduler error: {e}")
                await asyncio.sleep(60)
        
        logger.info("📅 Scheduler stopped")
    
    async def _execute_scan(self, config: ScanConfiguration):
        """Execute a single scan"""
        scan_id = config.scan_id
        result = self.active_scans.get(scan_id)
        
        if not result:
            logger.error(f"❌ Scan result not found for {scan_id}")
            return
        
        logger.info(f"🎯 Starting scan {scan_id} ({config.scan_type.value}) on {config.target}")
        
        try:
            # Update status
            result.status = ScanStatus.RUNNING
            result.start_time = datetime.now()
            
            # Execute based on scan type
            if config.scan_type == ScanType.WEB:
                await self._execute_web_scan(config, result)
            elif config.scan_type == ScanType.NETWORK:
                await self._execute_network_scan(config, result)
            elif config.scan_type == ScanType.COMBINED:
                await self._execute_combined_scan(config, result)
            
            # Update final status
            result.status = ScanStatus.COMPLETED
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time
            result.total_vulnerabilities = len(result.web_vulnerabilities) + len(result.network_vulnerabilities)
            
            logger.info(f"✅ Completed scan {scan_id}: {result.total_vulnerabilities} vulnerabilities found")
            
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time
            logger.error(f"❌ Scan {scan_id} failed: {e}")
        
        finally:
            # Move to history and remove from active
            self.scan_history.append(result)
            del self.active_scans[scan_id]
            
            # Limit history size
            if len(self.scan_history) > 1000:
                self.scan_history = self.scan_history[-500:]
    
    async def _execute_web_scan(self, config: ScanConfiguration, result: ScanResult):
        """Execute web vulnerability scan"""
        scanner = WebScanner()
        
        target = WebTarget(
            url=config.target,
            depth=config.web_depth,
            max_pages=config.web_max_pages,
            include_subdomains=config.include_subdomains,
            custom_headers=config.custom_headers,
            exclude_paths=config.exclude_paths
        )
        
        vulnerabilities = await scanner.scan_target(target)
        
        # Update results
        result.web_vulnerabilities = vulnerabilities
        result.pages_crawled = scanner.scan_stats.get('pages_crawled', 0)
        result.requests_sent = scanner.scan_stats.get('total_requests', 0)
    
    async def _execute_network_scan(self, config: ScanConfiguration, result: ScanResult):
        """Execute network vulnerability scan"""
        scanner = NetworkScanner()
        
        target = NetworkTarget(
            target=config.target,
            ports=config.ports,
            port_range=config.port_range,
            timeout=config.timeout,
            max_threads=config.max_threads,
            service_detection=config.service_detection,
            version_detection=config.version_detection,
            os_detection=config.os_detection,
            aggressive_scan=config.aggressive_scan,
            exclude_hosts=config.exclude_hosts
        )
        
        services, vulnerabilities = await scanner.scan_network(target)
        
        # Update results
        result.network_vulnerabilities = vulnerabilities
        result.hosts_scanned = scanner.scan_stats.get('hosts_scanned', 0)
        result.services_found = scanner.scan_stats.get('services_found', 0)
    
    async def _execute_combined_scan(self, config: ScanConfiguration, result: ScanResult):
        """Execute combined web and network scan"""
        # First run network scan to discover services
        await self._execute_network_scan(config, result)
        
        # Then run web scan on discovered HTTP services
        web_targets = []
        for vuln in result.network_vulnerabilities:
            if vuln.service in ['http', 'https']:
                scheme = 'https' if vuln.port in [443, 8443] else 'http'
                url = f"{scheme}://{vuln.host}:{vuln.port}"
                web_targets.append(url)
        
        # Add original target if it looks like a URL
        if config.target.startswith(('http://', 'https://')):
            web_targets.append(config.target)
        
        # Run web scans
        for url in web_targets[:5]:  # Limit to 5 web targets
            try:
                web_config = ScanConfiguration(
                    scan_id=f"{config.scan_id}-web-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                    scan_type=ScanType.WEB,
                    target=url,
                    web_depth=config.web_depth,
                    web_max_pages=config.web_max_pages,
                    include_subdomains=config.include_subdomains,
                    custom_headers=config.custom_headers
                )
                
                web_result = ScanResult(
                    scan_id=web_config.scan_id,
                    scan_type=ScanType.WEB,
                    target=url,
                    status=ScanStatus.RUNNING,
                    start_time=datetime.now()
                )
                
                await self._execute_web_scan(web_config, web_result)
                result.web_vulnerabilities.extend(web_result.web_vulnerabilities)
                result.pages_crawled += web_result.pages_crawled
                result.requests_sent += web_result.requests_sent
                
            except Exception as e:
                logger.error(f"❌ Web scan failed for {url}: {e}")
    
    def generate_consolidated_report(self, scan_id: str, format: str = "json") -> Optional[str]:
        """Generate consolidated report for a scan"""
        result = None
        
        # Find scan result
        if scan_id in self.active_scans:
            result = self.active_scans[scan_id]
        else:
            for r in self.scan_history:
                if r.scan_id == scan_id:
                    result = r
                    break
        
        if not result:
            return None
        
        # Build consolidated report
        report_data = {
            'scan_info': {
                'scan_id': result.scan_id,
                'scan_type': result.scan_type.value,
                'target': result.target,
                'status': result.status.value,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat() if result.end_time else None,
                'duration': str(result.duration) if result.duration else None,
                'total_vulnerabilities': result.total_vulnerabilities
            },
            'statistics': {
                'pages_crawled': result.pages_crawled,
                'requests_sent': result.requests_sent,
                'hosts_scanned': result.hosts_scanned,
                'services_found': result.services_found
            },
            'vulnerabilities': {
                'web': [],
                'network': []
            },
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Add web vulnerabilities
        for vuln in result.web_vulnerabilities:
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
            report_data['vulnerabilities']['web'].append(vuln_data)
            
            # Update summary
            severity = vuln.severity.lower()
            if severity in report_data['summary']:
                report_data['summary'][severity] += 1
        
        # Add network vulnerabilities
        for vuln in result.network_vulnerabilities:
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
            report_data['vulnerabilities']['network'].append(vuln_data)
            
            # Update summary
            severity = vuln.severity.lower()
            if severity in report_data['summary']:
                report_data['summary'][severity] += 1
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        else:
            return str(report_data)

# Example usage
async def main():
    """Example usage of the scan engine"""
    engine = ScanEngine()
    await engine.start_engine()
    
    try:
        # Submit a web scan
        web_config = ScanConfiguration(
            scan_id="web-scan-001",
            scan_type=ScanType.WEB,
            target="https://httpbin.org",
            name="Test Web Scan",
            web_depth=2,
            web_max_pages=20
        )
        
        scan_id = await engine.submit_scan(web_config)
        print(f"📤 Submitted web scan: {scan_id}")
        
        # Submit a network scan
        network_config = ScanConfiguration(
            scan_id="network-scan-001",
            scan_type=ScanType.NETWORK,
            target="127.0.0.1",
            name="Test Network Scan",
            ports=[22, 80, 443, 3306],
            service_detection=True
        )
        
        scan_id = await engine.submit_scan(network_config)
        print(f"📤 Submitted network scan: {scan_id}")
        
        # Wait for scans to complete
        await asyncio.sleep(30)
        
        # Check results
        active_scans = await engine.list_active_scans()
        print(f"\n📊 Active scans: {len(active_scans)}")
        
        history = await engine.get_scan_history()
        print(f"📊 Scan history: {len(history)}")
        
        for result in history:
            print(f"  {result.scan_id}: {result.status.value} - {result.total_vulnerabilities} vulns")
            
            # Generate report
            report = engine.generate_consolidated_report(result.scan_id)
            if report:
                print(f"    Report size: {len(report)} characters")
        
    finally:
        await engine.stop_engine()

if __name__ == "__main__":
    asyncio.run(main())