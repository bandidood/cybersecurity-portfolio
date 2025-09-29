#!/usr/bin/env python3
"""
MISP-TheHive-Cortex Integration and Synchronization
Advanced workflow orchestration for threat intelligence and incident response
Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import time
import os
import requests
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import schedule
import threading
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseObservable, CustomFieldHelper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/soc/integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class IntegrationConfig:
    """Configuration for MISP-TheHive-Cortex integration"""
    misp_url: str
    misp_key: str
    thehive_url: str
    thehive_key: str
    cortex_url: str
    cortex_key: str
    sync_interval: int = 300  # 5 minutes
    auto_create_cases: bool = True
    auto_run_analyzers: bool = True
    misp_to_thehive_tags: List[str] = None
    case_template: str = "misp-event-case"
    severity_mapping: Dict[str, int] = None
    organization: str = "soc-team"

class MISPTheHiveCortexIntegration:
    """Main integration class for orchestrating MISP-TheHive-Cortex workflows"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        
        # Initialize API clients
        self.misp = PyMISP(config.misp_url, config.misp_key, ssl=False)
        self.thehive = TheHiveApi(config.thehive_url, config.thehive_key, version='5')
        
        # Set default values
        if config.misp_to_thehive_tags is None:
            self.config.misp_to_thehive_tags = ['thehive-import', 'apt', 'malware', 'campaign']
        
        if config.severity_mapping is None:
            self.config.severity_mapping = {
                'high': 3,
                'medium': 2,
                'low': 1,
                'undefined': 2
            }
        
        # Initialize sync database
        self._initialize_sync_db()
        
        # Track processed items
        self.processed_events = set()
        self.processed_cases = set()
        
        # Background sync thread
        self.sync_running = False
        self.sync_thread = None
    
    def _initialize_sync_db(self):
        """Initialize database for tracking synchronization state"""
        db_path = '/opt/cortex/data/misp_thehive_sync.db'
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create tables
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS misp_events (
                id INTEGER PRIMARY KEY,
                event_id TEXT UNIQUE NOT NULL,
                event_uuid TEXT UNIQUE NOT NULL,
                last_modified TIMESTAMP,
                thehive_case_id TEXT,
                sync_status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS thehive_cases (
                id INTEGER PRIMARY KEY,
                case_id TEXT UNIQUE NOT NULL,
                case_number TEXT,
                misp_event_id TEXT,
                cortex_jobs TEXT,
                sync_status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                object_id TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );
            
            CREATE TABLE IF NOT EXISTS cortex_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT UNIQUE NOT NULL,
                case_id TEXT,
                analyzer_name TEXT,
                observable_type TEXT,
                observable_value TEXT,
                status TEXT,
                result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
        ''')
        
        self.conn.commit()
    
    def _log_sync_action(self, source: str, action: str, object_id: str, status: str, details: str = ""):
        """Log synchronization actions"""
        self.conn.execute(
            "INSERT INTO sync_log (source, action, object_id, status, details) VALUES (?, ?, ?, ?, ?)",
            (source, action, object_id, status, details)
        )
        self.conn.commit()
        logger.info(f"{source}: {action} {object_id} - {status}")
    
    async def start_sync(self):
        """Start the synchronization process"""
        logger.info("Starting MISP-TheHive-Cortex synchronization...")
        
        if not self.sync_running:
            self.sync_running = True
            self.sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
            self.sync_thread.start()
            
            # Schedule periodic sync
            schedule.every(self.config.sync_interval).seconds.do(self._schedule_sync)
            
            logger.info("Synchronization started successfully")
        else:
            logger.warning("Synchronization is already running")
    
    def stop_sync(self):
        """Stop the synchronization process"""
        logger.info("Stopping synchronization...")
        self.sync_running = False
        if self.sync_thread:
            self.sync_thread.join()
        logger.info("Synchronization stopped")
    
    def _sync_worker(self):
        """Background worker for synchronization"""
        while self.sync_running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Sync worker error: {e}")
                time.sleep(10)  # Wait before retrying
    
    def _schedule_sync(self):
        """Scheduled sync function"""
        asyncio.run(self.perform_sync())
    
    async def perform_sync(self):
        """Perform complete synchronization"""
        logger.info("Starting scheduled synchronization")
        
        try:
            # 1. MISP to TheHive sync
            await self._sync_misp_to_thehive()
            
            # 2. TheHive to Cortex sync
            await self._sync_thehive_to_cortex()
            
            # 3. Cortex results back to TheHive and MISP
            await self._sync_cortex_results()
            
            # 4. Cleanup old entries
            await self._cleanup_old_entries()
            
            logger.info("Scheduled synchronization completed successfully")
            
        except Exception as e:
            logger.error(f"Synchronization failed: {e}")
            self._log_sync_action("SYSTEM", "sync_error", "all", "failed", str(e))
    
    async def _sync_misp_to_thehive(self):
        """Sync MISP events to TheHive cases"""
        logger.info("Syncing MISP events to TheHive...")
        
        try:
            # Get recent MISP events
            search_filters = {
                'published': True,
                'tags': self.config.misp_to_thehive_tags,
                'date_from': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            }
            
            events = self.misp.search('events', **search_filters)
            
            for event in events:
                try:
                    event_id = str(event['Event']['id'])
                    event_uuid = event['Event']['uuid']
                    
                    # Check if already processed
                    if self._is_event_processed(event_id):
                        continue
                    
                    # Check if event should be imported
                    if not self._should_import_event(event['Event']):
                        continue
                    
                    # Create TheHive case from MISP event
                    case = await self._create_case_from_misp_event(event['Event'])
                    
                    if case:
                        # Record in sync database
                        self.conn.execute(
                            "INSERT OR REPLACE INTO misp_events (event_id, event_uuid, thehive_case_id, sync_status, last_modified) VALUES (?, ?, ?, ?, ?)",
                            (event_id, event_uuid, case['id'], 'completed', event['Event'].get('timestamp', datetime.now().isoformat()))
                        )
                        self.conn.commit()
                        
                        self._log_sync_action("MISP->TheHive", "case_created", event_id, "success", f"Case ID: {case['id']}")
                        
                        # Add observables from MISP attributes
                        await self._add_observables_from_misp_event(case['id'], event['Event'])
                    
                except Exception as e:
                    logger.error(f"Failed to sync MISP event {event_id}: {e}")
                    self._log_sync_action("MISP->TheHive", "case_creation", event_id, "failed", str(e))
        
        except Exception as e:
            logger.error(f"MISP to TheHive sync failed: {e}")
            self._log_sync_action("MISP->TheHive", "sync", "all", "failed", str(e))
    
    def _is_event_processed(self, event_id: str) -> bool:
        """Check if MISP event has already been processed"""
        cursor = self.conn.execute(
            "SELECT id FROM misp_events WHERE event_id = ? AND sync_status = 'completed'",
            (event_id,)
        )
        return cursor.fetchone() is not None
    
    def _should_import_event(self, event: Dict) -> bool:
        """Determine if MISP event should be imported to TheHive"""
        # Check threat level
        threat_level = event.get('threat_level_id', '4')
        if int(threat_level) > 3:  # Only import medium and high threats
            return False
        
        # Check tags
        event_tags = [tag['name'] for tag in event.get('Tag', [])]
        if not any(tag in event_tags for tag in self.config.misp_to_thehive_tags):
            return False
        
        # Check if event has attributes
        if not event.get('Attribute', []):
            return False
        
        return True
    
    async def _create_case_from_misp_event(self, event: Dict) -> Optional[Dict]:
        """Create TheHive case from MISP event"""
        try:
            # Determine severity from threat level
            threat_level_mapping = {
                '1': 3,  # High
                '2': 2,  # Medium
                '3': 1,  # Low
                '4': 1   # Undefined
            }
            
            severity = threat_level_mapping.get(str(event.get('threat_level_id', '4')), 2)
            
            # Extract tags
            tags = [tag['name'] for tag in event.get('Tag', [])]
            tags.extend(['misp-import', 'automated'])
            
            # Create case
            case_data = {
                'title': f"MISP Event #{event['id']}: {event.get('info', 'Imported from MISP')}",
                'description': self._generate_case_description(event),
                'severity': severity,
                'tlp': self._map_misp_tlp_to_thehive(event.get('distribution', '1')),
                'tags': tags,
                'customFields': CustomFieldHelper().build_custom_field('misp-event-id', 'string', event['id']),
                'template': self.config.case_template
            }
            
            # Create case via API
            response = requests.post(
                f"{self.config.thehive_url}/api/case",
                headers={
                    'Authorization': f"Bearer {self.config.thehive_key}",
                    'Content-Type': 'application/json'
                },
                json=case_data,
                verify=False
            )
            
            if response.status_code == 201:
                case = response.json()
                logger.info(f"Created TheHive case {case['id']} from MISP event {event['id']}")
                return case
            else:
                logger.error(f"Failed to create case: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating case from MISP event: {e}")
            return None
    
    def _generate_case_description(self, event: Dict) -> str:
        """Generate case description from MISP event"""
        description = f"""
# MISP Event Import

**Event ID:** {event['id']}
**UUID:** {event['uuid']}
**Info:** {event.get('info', 'N/A')}
**Date:** {event.get('date', 'N/A')}
**Org:** {event.get('Org', {}).get('name', 'N/A')}
**Threat Level:** {self._get_threat_level_name(event.get('threat_level_id', '4'))}
**Analysis:** {self._get_analysis_name(event.get('analysis', '0'))}

## Event Details
{event.get('info', 'No additional details provided')}

## Attributes Count
- Total: {len(event.get('Attribute', []))}
- Objects: {len(event.get('Object', []))}

This case was automatically created from a MISP event import.
"""
        return description
    
    def _get_threat_level_name(self, level_id: str) -> str:
        """Map MISP threat level ID to name"""
        mapping = {
            '1': 'High',
            '2': 'Medium', 
            '3': 'Low',
            '4': 'Undefined'
        }
        return mapping.get(str(level_id), 'Unknown')
    
    def _get_analysis_name(self, analysis_id: str) -> str:
        """Map MISP analysis ID to name"""
        mapping = {
            '0': 'Initial',
            '1': 'Ongoing',
            '2': 'Complete'
        }
        return mapping.get(str(analysis_id), 'Unknown')
    
    def _map_misp_tlp_to_thehive(self, distribution: str) -> int:
        """Map MISP distribution level to TheHive TLP"""
        mapping = {
            '0': 0,  # Your organization only -> TLP:RED
            '1': 1,  # This community only -> TLP:AMBER
            '2': 2,  # Connected communities -> TLP:AMBER
            '3': 3,  # All communities -> TLP:GREEN
            '4': 3,  # Sharing group -> TLP:GREEN
            '5': 3   # Inherit event -> TLP:GREEN
        }
        return mapping.get(str(distribution), 2)
    
    async def _add_observables_from_misp_event(self, case_id: str, event: Dict):
        """Add observables to TheHive case from MISP event attributes"""
        try:
            observables = []
            
            # Process attributes
            for attribute in event.get('Attribute', []):
                observable = self._create_observable_from_attribute(attribute, case_id)
                if observable:
                    observables.append(observable)
            
            # Process objects
            for obj in event.get('Object', []):
                for attribute in obj.get('Attribute', []):
                    observable = self._create_observable_from_attribute(attribute, case_id)
                    if observable:
                        observables.append(observable)
            
            # Batch create observables
            if observables:
                for observable in observables:
                    response = requests.post(
                        f"{self.config.thehive_url}/api/case/{case_id}/observable",
                        headers={
                            'Authorization': f"Bearer {self.config.thehive_key}",
                            'Content-Type': 'application/json'
                        },
                        json=observable,
                        verify=False
                    )
                    
                    if response.status_code == 201:
                        logger.debug(f"Added observable {observable['data']} to case {case_id}")
                    else:
                        logger.warning(f"Failed to add observable: {response.text}")
                
                logger.info(f"Added {len(observables)} observables to case {case_id}")
        
        except Exception as e:
            logger.error(f"Error adding observables to case {case_id}: {e}")
    
    def _create_observable_from_attribute(self, attribute: Dict, case_id: str) -> Optional[Dict]:
        """Create TheHive observable from MISP attribute"""
        try:
            # Map MISP attribute types to TheHive data types
            type_mapping = {
                'ip-src': 'ip',
                'ip-dst': 'ip',
                'hostname': 'fqdn',
                'domain': 'domain',
                'url': 'url',
                'md5': 'hash',
                'sha1': 'hash',
                'sha256': 'hash',
                'email-src': 'mail',
                'email-dst': 'mail',
                'filename': 'filename',
                'user-agent': 'user-agent',
                'registry-key': 'registry',
                'mutex': 'other'
            }
            
            misp_type = attribute.get('type', '')
            thehive_type = type_mapping.get(misp_type, 'other')
            
            # Skip if unsupported type
            if thehive_type == 'other' and misp_type not in ['other', 'comment']:
                return None
            
            # Create observable
            observable = {
                'dataType': thehive_type,
                'data': attribute.get('value', ''),
                'message': attribute.get('comment', f"Imported from MISP attribute {attribute.get('id', '')}"),
                'tags': [f"misp:{misp_type}", 'misp-import'],
                'tlp': self._map_misp_tlp_to_thehive(attribute.get('distribution', '1')),
                'ioc': not attribute.get('to_ids', False)  # Inverted because to_ids=True means it's an IoC
            }
            
            # Add MISP-specific tags if present
            if attribute.get('Tag'):
                for tag in attribute['Tag']:
                    observable['tags'].append(f"misp:{tag['name']}")
            
            return observable
        
        except Exception as e:
            logger.error(f"Error creating observable from attribute: {e}")
            return None
    
    async def _sync_thehive_to_cortex(self):
        """Sync TheHive cases to Cortex for analysis"""
        logger.info("Syncing TheHive cases to Cortex...")
        
        try:
            # Get recent cases that need analysis
            cases = await self._get_cases_for_analysis()
            
            for case in cases:
                try:
                    case_id = case['id']
                    
                    # Get observables for the case
                    observables = await self._get_case_observables(case_id)
                    
                    # Run analyzers on observables
                    for observable in observables:
                        await self._run_analyzers_on_observable(case_id, observable)
                    
                    # Record sync status
                    self.conn.execute(
                        "INSERT OR REPLACE INTO thehive_cases (case_id, case_number, sync_status) VALUES (?, ?, ?)",
                        (case_id, case.get('caseId', ''), 'analyzed')
                    )
                    self.conn.commit()
                    
                    self._log_sync_action("TheHive->Cortex", "analysis_started", case_id, "success")
                
                except Exception as e:
                    logger.error(f"Failed to analyze case {case_id}: {e}")
                    self._log_sync_action("TheHive->Cortex", "analysis_failed", case_id, "failed", str(e))
        
        except Exception as e:
            logger.error(f"TheHive to Cortex sync failed: {e}")
    
    async def _get_cases_for_analysis(self) -> List[Dict]:
        """Get TheHive cases that need Cortex analysis"""
        try:
            # Query for recent cases with MISP import tags
            response = requests.get(
                f"{self.config.thehive_url}/api/case",
                headers={
                    'Authorization': f"Bearer {self.config.thehive_key}",
                    'Content-Type': 'application/json'
                },
                params={
                    'range': '0-50',
                    'sort': '-createdAt',
                    'filter': json.dumps({
                        'tags': 'misp-import',
                        'status': 'Open'
                    })
                },
                verify=False
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get cases: {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"Error getting cases for analysis: {e}")
            return []
    
    async def _get_case_observables(self, case_id: str) -> List[Dict]:
        """Get observables for a specific case"""
        try:
            response = requests.get(
                f"{self.config.thehive_url}/api/case/{case_id}/observable",
                headers={
                    'Authorization': f"Bearer {self.config.thehive_key}",
                    'Content-Type': 'application/json'
                },
                verify=False
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get observables: {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"Error getting observables for case {case_id}: {e}")
            return []
    
    async def _run_analyzers_on_observable(self, case_id: str, observable: Dict):
        """Run appropriate Cortex analyzers on observable"""
        try:
            observable_type = observable.get('dataType', '')
            observable_value = observable.get('data', '')
            observable_id = observable.get('id', '')
            
            # Define analyzer mappings
            analyzer_mappings = {
                'ip': ['MaxMind_GeoIP_3_0', 'Shodan_DNSResolve_1_0', 'VirusTotal_GetReport_3_0'],
                'domain': ['URLVoid_1_0', 'VirusTotal_GetReport_3_0', 'PassiveTotal_2_0'],
                'hash': ['VirusTotal_GetReport_3_0', 'Yara_2_0', 'File_Info_8_0'],
                'url': ['URLVoid_1_0', 'VirusTotal_GetReport_3_0'],
                'mail': ['DomainTools_2_0']
            }
            
            analyzers = analyzer_mappings.get(observable_type, [])
            
            for analyzer_name in analyzers:
                try:
                    job_data = {
                        'dataType': observable_type,
                        'data': observable_value,
                        'tlp': observable.get('tlp', 2),
                        'message': f'Automated analysis from case {case_id}',
                        'parameters': {}
                    }
                    
                    # Submit job to Cortex
                    response = requests.post(
                        f"{self.config.cortex_url}/api/analyzer/{analyzer_name}/run",
                        headers={
                            'Authorization': f"Bearer {self.config.cortex_key}",
                            'Content-Type': 'application/json'
                        },
                        json=job_data,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        job = response.json()
                        job_id = job.get('id', '')
                        
                        # Record job in database
                        self.conn.execute(
                            "INSERT INTO cortex_jobs (job_id, case_id, analyzer_name, observable_type, observable_value, status) VALUES (?, ?, ?, ?, ?, ?)",
                            (job_id, case_id, analyzer_name, observable_type, observable_value, 'InProgress')
                        )
                        self.conn.commit()
                        
                        logger.info(f"Started Cortex job {job_id} for {analyzer_name} on {observable_value}")
                    else:
                        logger.warning(f"Failed to start analyzer {analyzer_name}: {response.text}")
                
                except Exception as e:
                    logger.error(f"Error running analyzer {analyzer_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error analyzing observable {observable_id}: {e}")
    
    async def _sync_cortex_results(self):
        """Sync Cortex analysis results back to TheHive and MISP"""
        logger.info("Syncing Cortex results back to TheHive and MISP...")
        
        try:
            # Get completed jobs
            cursor = self.conn.execute(
                "SELECT job_id, case_id, analyzer_name, observable_type, observable_value FROM cortex_jobs WHERE status = 'InProgress'"
            )
            
            jobs = cursor.fetchall()
            
            for job in jobs:
                job_id, case_id, analyzer_name, observable_type, observable_value = job
                
                try:
                    # Check job status
                    response = requests.get(
                        f"{self.config.cortex_url}/api/job/{job_id}",
                        headers={
                            'Authorization': f"Bearer {self.config.cortex_key}",
                            'Content-Type': 'application/json'
                        },
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        job_status = response.json()
                        
                        if job_status.get('status') == 'Success':
                            # Get job report
                            report_response = requests.get(
                                f"{self.config.cortex_url}/api/job/{job_id}/report",
                                headers={
                                    'Authorization': f"Bearer {self.config.cortex_key}",
                                    'Content-Type': 'application/json'
                                },
                                verify=False
                            )
                            
                            if report_response.status_code == 200:
                                report = report_response.json()
                                
                                # Update job status
                                self.conn.execute(
                                    "UPDATE cortex_jobs SET status = 'Success', result = ?, completed_at = ? WHERE job_id = ?",
                                    (json.dumps(report), datetime.now().isoformat(), job_id)
                                )
                                self.conn.commit()
                                
                                # Add results to TheHive case
                                await self._add_analysis_results_to_case(case_id, analyzer_name, report)
                                
                                # Extract new IoCs and add to MISP if needed
                                await self._extract_and_add_iocs_to_misp(case_id, analyzer_name, report)
                                
                                self._log_sync_action("Cortex->TheHive", "results_added", job_id, "success")
                        
                        elif job_status.get('status') == 'Failure':
                            # Update job status
                            self.conn.execute(
                                "UPDATE cortex_jobs SET status = 'Failure', completed_at = ? WHERE job_id = ?",
                                (datetime.now().isoformat(), job_id)
                            )
                            self.conn.commit()
                            
                            self._log_sync_action("Cortex->TheHive", "job_failed", job_id, "failed")
                
                except Exception as e:
                    logger.error(f"Error processing job {job_id}: {e}")
        
        except Exception as e:
            logger.error(f"Cortex results sync failed: {e}")
    
    async def _add_analysis_results_to_case(self, case_id: str, analyzer_name: str, report: Dict):
        """Add Cortex analysis results to TheHive case"""
        try:
            # Create task for analysis results
            task_data = {
                'title': f'{analyzer_name} Analysis Results',
                'group': 'analysis',
                'description': self._format_analysis_results(analyzer_name, report),
                'status': 'Completed'
            }
            
            response = requests.post(
                f"{self.config.thehive_url}/api/case/{case_id}/task",
                headers={
                    'Authorization': f"Bearer {self.config.thehive_key}",
                    'Content-Type': 'application/json'
                },
                json=task_data,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"Added {analyzer_name} results to case {case_id}")
            else:
                logger.warning(f"Failed to add results to case: {response.text}")
        
        except Exception as e:
            logger.error(f"Error adding analysis results to case: {e}")
    
    def _format_analysis_results(self, analyzer_name: str, report: Dict) -> str:
        """Format Cortex analysis results for TheHive"""
        summary = report.get('summary', {})
        taxonomies = report.get('taxonomies', [])
        
        result_text = f"""
# {analyzer_name} Analysis Results

## Summary
"""
        
        for key, value in summary.items():
            result_text += f"- **{key}**: {value}\n"
        
        if taxonomies:
            result_text += "\n## Taxonomies\n"
            for taxonomy in taxonomies:
                level = taxonomy.get('level', 'info')
                predicate = taxonomy.get('predicate', '')
                value = taxonomy.get('value', '')
                result_text += f"- **{level.upper()}**: {predicate} = {value}\n"
        
        result_text += f"\n*Analysis completed at {datetime.now().isoformat()}*"
        
        return result_text
    
    async def _extract_and_add_iocs_to_misp(self, case_id: str, analyzer_name: str, report: Dict):
        """Extract IoCs from analysis results and add to MISP"""
        try:
            # Extract IoCs based on analyzer type
            iocs = []
            
            if analyzer_name.startswith('VirusTotal'):
                iocs.extend(self._extract_iocs_from_virustotal(report))
            elif analyzer_name.startswith('PassiveTotal'):
                iocs.extend(self._extract_iocs_from_passivetotal(report))
            elif analyzer_name.startswith('URLVoid'):
                iocs.extend(self._extract_iocs_from_urlvoid(report))
            
            # Get original MISP event ID
            cursor = self.conn.execute(
                "SELECT misp_event_id FROM thehive_cases WHERE case_id = ?",
                (case_id,)
            )
            result = cursor.fetchone()
            
            if result and result[0]:
                misp_event_id = result[0]
                
                # Add IoCs to MISP event
                for ioc in iocs:
                    await self._add_attribute_to_misp_event(misp_event_id, ioc)
        
        except Exception as e:
            logger.error(f"Error extracting IoCs: {e}")
    
    def _extract_iocs_from_virustotal(self, report: Dict) -> List[Dict]:
        """Extract IoCs from VirusTotal report"""
        iocs = []
        
        try:
            full_report = report.get('full', {})
            
            # Extract related domains
            if 'resolutions' in full_report:
                for resolution in full_report['resolutions']:
                    if 'hostname' in resolution:
                        iocs.append({
                            'type': 'domain',
                            'value': resolution['hostname'],
                            'comment': f'Related domain from VirusTotal analysis',
                            'to_ids': True
                        })
            
            # Extract related IPs
            if 'detected_urls' in full_report:
                for url_data in full_report['detected_urls'][:5]:  # Limit to 5
                    if 'url' in url_data:
                        iocs.append({
                            'type': 'url',
                            'value': url_data['url'],
                            'comment': f'Malicious URL detected by VirusTotal',
                            'to_ids': True
                        })
        
        except Exception as e:
            logger.error(f"Error extracting VirusTotal IoCs: {e}")
        
        return iocs
    
    def _extract_iocs_from_passivetotal(self, report: Dict) -> List[Dict]:
        """Extract IoCs from PassiveTotal report"""
        iocs = []
        
        try:
            full_report = report.get('full', {})
            
            # Extract passive DNS results
            if 'results' in full_report:
                for result in full_report['results'][:10]:  # Limit to 10
                    if 'resolve' in result:
                        iocs.append({
                            'type': 'ip-dst',
                            'value': result['resolve'],
                            'comment': f'Passive DNS resolution from PassiveTotal',
                            'to_ids': False
                        })
        
        except Exception as e:
            logger.error(f"Error extracting PassiveTotal IoCs: {e}")
        
        return iocs
    
    def _extract_iocs_from_urlvoid(self, report: Dict) -> List[Dict]:
        """Extract IoCs from URLVoid report"""
        iocs = []
        
        try:
            full_report = report.get('full', {})
            
            # Extract IP address if domain is malicious
            if full_report.get('data', {}).get('detections', 0) > 0:
                ip_address = full_report.get('data', {}).get('ip', {}).get('addr')
                if ip_address:
                    iocs.append({
                        'type': 'ip-dst',
                        'value': ip_address,
                        'comment': f'IP hosting malicious domain (URLVoid)',
                        'to_ids': True
                    })
        
        except Exception as e:
            logger.error(f"Error extracting URLVoid IoCs: {e}")
        
        return iocs
    
    async def _add_attribute_to_misp_event(self, event_id: str, ioc: Dict):
        """Add attribute to MISP event"""
        try:
            # Create MISP attribute
            attribute = MISPAttribute()
            attribute.type = ioc['type']
            attribute.value = ioc['value']
            attribute.comment = ioc.get('comment', '')
            attribute.to_ids = ioc.get('to_ids', False)
            
            # Add to MISP event
            result = self.misp.add_attribute(event_id, attribute)
            
            if 'Attribute' in result:
                logger.info(f"Added attribute {ioc['value']} to MISP event {event_id}")
            else:
                logger.warning(f"Failed to add attribute to MISP: {result}")
        
        except Exception as e:
            logger.error(f"Error adding attribute to MISP event {event_id}: {e}")
    
    async def _cleanup_old_entries(self):
        """Clean up old sync database entries"""
        try:
            # Remove entries older than 30 days
            cutoff_date = (datetime.now() - timedelta(days=30)).isoformat()
            
            self.conn.execute("DELETE FROM sync_log WHERE timestamp < ?", (cutoff_date,))
            self.conn.execute("DELETE FROM cortex_jobs WHERE created_at < ? AND status IN ('Success', 'Failure')", (cutoff_date,))
            
            self.conn.commit()
            logger.info("Cleaned up old sync database entries")
        
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    async def manual_sync_event(self, event_id: str) -> bool:
        """Manually sync a specific MISP event"""
        try:
            # Get MISP event
            event = self.misp.get_event(event_id)
            
            if event and 'Event' in event:
                # Create case
                case = await self._create_case_from_misp_event(event['Event'])
                
                if case:
                    # Add observables
                    await self._add_observables_from_misp_event(case['id'], event['Event'])
                    
                    # Record sync
                    self.conn.execute(
                        "INSERT OR REPLACE INTO misp_events (event_id, event_uuid, thehive_case_id, sync_status) VALUES (?, ?, ?, ?)",
                        (event_id, event['Event']['uuid'], case['id'], 'completed')
                    )
                    self.conn.commit()
                    
                    self._log_sync_action("MANUAL", "event_sync", event_id, "success", f"Case: {case['id']}")
                    return True
            
            return False
        
        except Exception as e:
            logger.error(f"Manual sync failed for event {event_id}: {e}")
            return False
    
    def get_sync_statistics(self) -> Dict[str, Any]:
        """Get synchronization statistics"""
        try:
            stats = {}
            
            # MISP events synced
            cursor = self.conn.execute("SELECT COUNT(*) FROM misp_events WHERE sync_status = 'completed'")
            stats['misp_events_synced'] = cursor.fetchone()[0]
            
            # TheHive cases
            cursor = self.conn.execute("SELECT COUNT(*) FROM thehive_cases")
            stats['thehive_cases'] = cursor.fetchone()[0]
            
            # Cortex jobs
            cursor = self.conn.execute("SELECT status, COUNT(*) FROM cortex_jobs GROUP BY status")
            cortex_jobs = dict(cursor.fetchall())
            stats['cortex_jobs'] = cortex_jobs
            
            # Recent sync actions
            cursor = self.conn.execute("SELECT COUNT(*) FROM sync_log WHERE timestamp > datetime('now', '-1 day')")
            stats['recent_sync_actions'] = cursor.fetchone()[0]
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting sync statistics: {e}")
            return {}

# Configuration and main execution
async def main():
    """Main execution function"""
    
    # Load configuration
    config = IntegrationConfig(
        misp_url="http://misp:80",
        misp_key="misp-api-key-here",
        thehive_url="http://thehive:9000",
        thehive_key="thehive-api-key-here", 
        cortex_url="http://cortex:9001",
        cortex_key="cortex-api-key-here",
        sync_interval=300,
        auto_create_cases=True,
        auto_run_analyzers=True
    )
    
    # Initialize integration
    integration = MISPTheHiveCortexIntegration(config)
    
    try:
        # Start synchronization
        await integration.start_sync()
        
        # Run initial sync
        await integration.perform_sync()
        
        # Get statistics
        stats = integration.get_sync_statistics()
        print(f"Sync Statistics: {json.dumps(stats, indent=2)}")
        
        # Keep running
        logger.info("Integration is running... Press Ctrl+C to stop")
        while True:
            await asyncio.sleep(60)
            
    except KeyboardInterrupt:
        logger.info("Stopping integration...")
        integration.stop_sync()
    except Exception as e:
        logger.error(f"Integration error: {e}")
        integration.stop_sync()

if __name__ == "__main__":
    asyncio.run(main())