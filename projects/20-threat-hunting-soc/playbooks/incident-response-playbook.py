#!/usr/bin/env python3
"""
SOC SOAR Incident Response Playbook
Advanced automated incident response with TheHive and Cortex integration
Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import requests
import yaml
import smtplib
from email.mime.text import MimeText, MimeMultipart
from email.mime.base import MimeBase
from email import encoders
import subprocess
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/soc/incident-response.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class IncidentStatus(Enum):
    OPEN = "Open"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"

class ResponseAction(Enum):
    INVESTIGATE = "investigate"
    CONTAIN = "contain"
    ERADICATE = "eradicate"
    RECOVER = "recover"
    LESSONS_LEARNED = "lessons_learned"

@dataclass
class IncidentContext:
    """Context data for incident response"""
    incident_id: str
    case_id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: int = 2
    tlp: int = 2
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    source: str = ""
    artifacts: List[Dict] = None
    iocs: List[Dict] = None
    affected_systems: List[str] = None
    timeline: List[Dict] = None
    evidence: List[Dict] = None
    mitigation_actions: List[Dict] = None
    lessons_learned: str = ""
    created_at: str = ""
    updated_at: str = ""
    
    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = []
        if self.iocs is None:
            self.iocs = []
        if self.affected_systems is None:
            self.affected_systems = []
        if self.timeline is None:
            self.timeline = []
        if self.evidence is None:
            self.evidence = []
        if self.mitigation_actions is None:
            self.mitigation_actions = []
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        self.updated_at = datetime.utcnow().isoformat()

class TheHiveClient:
    """Client for TheHive API interactions"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    async def create_case(self, context: IncidentContext) -> Dict:
        """Create a new case in TheHive"""
        case_data = {
            'title': context.title,
            'description': context.description,
            'severity': context.severity,
            'tlp': context.tlp,
            'tags': ['automated', 'soar', f'severity-{context.severity}'],
            'customFields': {
                'business-impact': self._assess_business_impact(context.severity),
                'affected-systems': context.affected_systems
            },
            'tasks': self._generate_tasks(context)
        }
        
        try:
            response = requests.post(
                f'{self.url}/api/case',
                headers=self.headers,
                json=case_data,
                timeout=30
            )
            response.raise_for_status()
            case = response.json()
            logger.info(f"Created TheHive case: {case['id']}")
            return case
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create TheHive case: {e}")
            raise
    
    async def update_case(self, case_id: str, updates: Dict) -> Dict:
        """Update existing case"""
        try:
            response = requests.patch(
                f'{self.url}/api/case/{case_id}',
                headers=self.headers,
                json=updates,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update case {case_id}: {e}")
            raise
    
    async def add_artifacts(self, case_id: str, artifacts: List[Dict]) -> List[Dict]:
        """Add artifacts to case"""
        added_artifacts = []
        for artifact in artifacts:
            try:
                response = requests.post(
                    f'{self.url}/api/case/{case_id}/artifact',
                    headers=self.headers,
                    json={
                        'dataType': artifact.get('type', 'other'),
                        'data': artifact.get('value', ''),
                        'message': artifact.get('description', ''),
                        'tags': artifact.get('tags', []),
                        'tlp': artifact.get('tlp', 2),
                        'ioc': artifact.get('ioc', False)
                    },
                    timeout=30
                )
                response.raise_for_status()
                added_artifacts.append(response.json())
                logger.info(f"Added artifact {artifact.get('value')} to case {case_id}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to add artifact {artifact.get('value')}: {e}")
        
        return added_artifacts
    
    def _assess_business_impact(self, severity: int) -> str:
        """Assess business impact based on severity"""
        impact_mapping = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        return impact_mapping.get(severity, "medium")
    
    def _generate_tasks(self, context: IncidentContext) -> List[Dict]:
        """Generate standard incident response tasks"""
        base_tasks = [
            {
                'title': 'Initial Assessment',
                'group': 'analysis',
                'description': 'Perform initial threat assessment and containment evaluation',
                'status': 'Waiting'
            },
            {
                'title': 'Containment',
                'group': 'response',
                'description': 'Implement containment measures to prevent spread',
                'status': 'Waiting'
            },
            {
                'title': 'Evidence Collection',
                'group': 'forensics',
                'description': 'Collect and preserve digital evidence',
                'status': 'Waiting'
            },
            {
                'title': 'Analysis',
                'group': 'analysis',
                'description': 'Detailed analysis of the incident',
                'status': 'Waiting'
            },
            {
                'title': 'Eradication',
                'group': 'response',
                'description': 'Remove threat from environment',
                'status': 'Waiting'
            },
            {
                'title': 'Recovery',
                'group': 'response',
                'description': 'Restore systems and services',
                'status': 'Waiting'
            },
            {
                'title': 'Lessons Learned',
                'group': 'documentation',
                'description': 'Document lessons learned and update procedures',
                'status': 'Waiting'
            }
        ]
        
        # Add custom tasks based on incident type
        if any('malware' in tag for tag in context.artifacts):
            base_tasks.extend([
                {
                    'title': 'Malware Analysis',
                    'group': 'analysis',
                    'description': 'Perform static and dynamic malware analysis',
                    'status': 'Waiting'
                },
                {
                    'title': 'IoC Extraction',
                    'group': 'intelligence',
                    'description': 'Extract indicators of compromise from malware',
                    'status': 'Waiting'
                }
            ])
        
        return base_tasks

class CortexClient:
    """Client for Cortex analyzer and responder interactions"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    async def run_analyzer(self, analyzer_name: str, data_type: str, data: str, tlp: int = 2) -> Dict:
        """Run a specific analyzer on data"""
        job_data = {
            'dataType': data_type,
            'data': data,
            'tlp': tlp,
            'message': f'Automated analysis via SOAR playbook'
        }
        
        try:
            response = requests.post(
                f'{self.url}/api/analyzer/{analyzer_name}/run',
                headers=self.headers,
                json=job_data,
                timeout=30
            )
            response.raise_for_status()
            job = response.json()
            
            # Wait for job completion
            job_id = job['id']
            result = await self._wait_for_job_completion(job_id)
            logger.info(f"Analyzer {analyzer_name} completed for {data}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to run analyzer {analyzer_name}: {e}")
            raise
    
    async def run_responder(self, responder_name: str, object_type: str, object_id: str) -> Dict:
        """Run a specific responder"""
        job_data = {
            'responderId': responder_name,
            'objectType': object_type,
            'objectId': object_id
        }
        
        try:
            response = requests.post(
                f'{self.url}/api/responder/{responder_name}/run',
                headers=self.headers,
                json=job_data,
                timeout=30
            )
            response.raise_for_status()
            job = response.json()
            
            # Wait for job completion
            job_id = job['id']
            result = await self._wait_for_job_completion(job_id)
            logger.info(f"Responder {responder_name} completed for {object_id}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to run responder {responder_name}: {e}")
            raise
    
    async def _wait_for_job_completion(self, job_id: str, timeout: int = 300) -> Dict:
        """Wait for Cortex job to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(
                    f'{self.url}/api/job/{job_id}',
                    headers=self.headers,
                    timeout=10
                )
                response.raise_for_status()
                job = response.json()
                
                if job['status'] == 'Success':
                    # Get full report
                    report_response = requests.get(
                        f'{self.url}/api/job/{job_id}/report',
                        headers=self.headers,
                        timeout=10
                    )
                    report_response.raise_for_status()
                    return report_response.json()
                elif job['status'] == 'Failure':
                    raise Exception(f"Job {job_id} failed: {job.get('errorMessage', 'Unknown error')}")
                
                await asyncio.sleep(5)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error checking job status: {e}")
                await asyncio.sleep(10)
        
        raise TimeoutError(f"Job {job_id} timed out after {timeout} seconds")

class NotificationManager:
    """Handle various notification methods"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    async def send_alert(self, incident: IncidentContext, message: str, urgency: str = "normal"):
        """Send alert through configured channels"""
        tasks = []
        
        if self.config.get('email', {}).get('enabled', False):
            tasks.append(self._send_email(incident, message, urgency))
        
        if self.config.get('slack', {}).get('enabled', False):
            tasks.append(self._send_slack(incident, message, urgency))
        
        if self.config.get('teams', {}).get('enabled', False):
            tasks.append(self._send_teams(incident, message, urgency))
        
        if self.config.get('pagerduty', {}).get('enabled', False) and urgency == "critical":
            tasks.append(self._send_pagerduty(incident, message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_email(self, incident: IncidentContext, message: str, urgency: str):
        """Send email notification"""
        config = self.config['email']
        
        try:
            msg = MimeMultipart()
            msg['From'] = config['from']
            msg['To'] = ', '.join(config['recipients'])
            msg['Subject'] = f"[SOC ALERT - {urgency.upper()}] {incident.title}"
            
            body = f"""
            Incident Response Alert
            =======================
            
            Incident ID: {incident.incident_id}
            Title: {incident.title}
            Severity: {incident.severity}/4
            Status: {incident.status.value}
            
            Description:
            {incident.description}
            
            Alert Message:
            {message}
            
            Affected Systems: {', '.join(incident.affected_systems) if incident.affected_systems else 'None'}
            
            Dashboard: {config.get('dashboard_url', 'N/A')}
            
            This is an automated message from the SOC SOAR platform.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(config['smtp_host'], config['smtp_port'])
            if config.get('use_tls', False):
                server.starttls()
            if config.get('username') and config.get('password'):
                server.login(config['username'], config['password'])
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent for incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    async def _send_slack(self, incident: IncidentContext, message: str, urgency: str):
        """Send Slack notification"""
        config = self.config['slack']
        
        try:
            webhook_url = config['webhook_url']
            
            color_mapping = {
                'normal': '#36a64f',
                'warning': '#ffaa00',
                'critical': '#ff0000'
            }
            
            payload = {
                'channel': config.get('channel', '#soc-alerts'),
                'username': 'SOC-SOAR',
                'icon_emoji': ':warning:',
                'attachments': [
                    {
                        'color': color_mapping.get(urgency, '#36a64f'),
                        'title': f"SOC Alert - {incident.title}",
                        'fields': [
                            {
                                'title': 'Incident ID',
                                'value': incident.incident_id,
                                'short': True
                            },
                            {
                                'title': 'Severity',
                                'value': f"{incident.severity}/4",
                                'short': True
                            },
                            {
                                'title': 'Status',
                                'value': incident.status.value,
                                'short': True
                            },
                            {
                                'title': 'Urgency',
                                'value': urgency.upper(),
                                'short': True
                            },
                            {
                                'title': 'Message',
                                'value': message,
                                'short': False
                            }
                        ],
                        'footer': 'SOC SOAR Platform',
                        'ts': int(time.time())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack alert sent for incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    async def _send_teams(self, incident: IncidentContext, message: str, urgency: str):
        """Send Microsoft Teams notification"""
        config = self.config['teams']
        
        try:
            webhook_url = config['webhook_url']
            
            color_mapping = {
                'normal': '00ff00',
                'warning': 'ffaa00',
                'critical': 'ff0000'
            }
            
            payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': f'SOC Alert - {incident.title}',
                'themeColor': color_mapping.get(urgency, '00ff00'),
                'sections': [
                    {
                        'activityTitle': f'🚨 SOC Alert - {urgency.upper()}',
                        'activitySubtitle': incident.title,
                        'facts': [
                            {'name': 'Incident ID', 'value': incident.incident_id},
                            {'name': 'Severity', 'value': f'{incident.severity}/4'},
                            {'name': 'Status', 'value': incident.status.value},
                            {'name': 'Description', 'value': incident.description[:200] + '...' if len(incident.description) > 200 else incident.description}
                        ],
                        'text': message
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Teams alert sent for incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")

class ResponseOrchestrator:
    """Main orchestrator for incident response"""
    
    def __init__(self, config_file: str):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.thehive = TheHiveClient(
            self.config['thehive']['url'],
            self.config['thehive']['api_key']
        )
        
        self.cortex = CortexClient(
            self.config['cortex']['url'],
            self.config['cortex']['api_key']
        )
        
        self.notifications = NotificationManager(self.config['notifications'])
        
        self.playbooks = {
            'malware_incident': self._malware_incident_playbook,
            'network_intrusion': self._network_intrusion_playbook,
            'data_exfiltration': self._data_exfiltration_playbook,
            'phishing_attack': self._phishing_attack_playbook,
            'insider_threat': self._insider_threat_playbook,
            'ddos_attack': self._ddos_attack_playbook,
            'generic_security_incident': self._generic_security_incident_playbook
        }
    
    async def execute_incident_response(self, incident_data: Dict) -> IncidentContext:
        """Execute automated incident response"""
        # Create incident context
        context = IncidentContext(
            incident_id=incident_data.get('id', f"INC-{int(time.time())}"),
            title=incident_data.get('title', 'Security Incident'),
            description=incident_data.get('description', ''),
            severity=incident_data.get('severity', 2),
            source=incident_data.get('source', 'automated'),
            artifacts=incident_data.get('artifacts', []),
            affected_systems=incident_data.get('affected_systems', [])
        )
        
        logger.info(f"Starting incident response for {context.incident_id}")
        
        try:
            # Phase 1: Initial Response
            await self._initial_response(context)
            
            # Phase 2: Determine playbook type
            playbook_type = self._determine_playbook_type(context)
            logger.info(f"Selected playbook: {playbook_type}")
            
            # Phase 3: Execute specific playbook
            if playbook_type in self.playbooks:
                context = await self.playbooks[playbook_type](context)
            else:
                context = await self._generic_security_incident_playbook(context)
            
            # Phase 4: Final documentation and closure
            await self._finalize_incident(context)
            
            logger.info(f"Incident response completed for {context.incident_id}")
            return context
            
        except Exception as e:
            logger.error(f"Incident response failed for {context.incident_id}: {e}")
            await self.notifications.send_alert(
                context,
                f"Automated incident response failed: {str(e)}",
                "critical"
            )
            raise
    
    async def _initial_response(self, context: IncidentContext):
        """Phase 1: Initial response and assessment"""
        # Create TheHive case
        case = await self.thehive.create_case(context)
        context.case_id = case['id']
        
        # Add artifacts to case
        if context.artifacts:
            await self.thehive.add_artifacts(context.case_id, context.artifacts)
        
        # Send initial alert
        await self.notifications.send_alert(
            context,
            f"New security incident detected and case {context.case_id} created",
            "warning" if context.severity >= 3 else "normal"
        )
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'initial_response',
            'description': f'Case {context.case_id} created in TheHive',
            'automated': True
        })
    
    def _determine_playbook_type(self, context: IncidentContext) -> str:
        """Determine which playbook to execute based on incident characteristics"""
        title_lower = context.title.lower()
        description_lower = context.description.lower()
        
        # Check for malware indicators
        malware_keywords = ['malware', 'trojan', 'virus', 'ransomware', 'backdoor', 'keylogger']
        if any(keyword in title_lower or keyword in description_lower for keyword in malware_keywords):
            return 'malware_incident'
        
        # Check for network intrusion indicators
        intrusion_keywords = ['intrusion', 'unauthorized access', 'lateral movement', 'privilege escalation']
        if any(keyword in title_lower or keyword in description_lower for keyword in intrusion_keywords):
            return 'network_intrusion'
        
        # Check for data exfiltration indicators
        exfiltration_keywords = ['data exfiltration', 'data theft', 'unauthorized download', 'sensitive data']
        if any(keyword in title_lower or keyword in description_lower for keyword in exfiltration_keywords):
            return 'data_exfiltration'
        
        # Check for phishing indicators
        phishing_keywords = ['phishing', 'spear phishing', 'social engineering', 'malicious email']
        if any(keyword in title_lower or keyword in description_lower for keyword in phishing_keywords):
            return 'phishing_attack'
        
        # Check for DDoS indicators
        ddos_keywords = ['ddos', 'dos attack', 'volumetric attack', 'application layer attack']
        if any(keyword in title_lower or keyword in description_lower for keyword in ddos_keywords):
            return 'ddos_attack'
        
        # Check for insider threat indicators
        insider_keywords = ['insider threat', 'insider attack', 'rogue employee', 'privilege abuse']
        if any(keyword in title_lower or keyword in description_lower for keyword in insider_keywords):
            return 'insider_threat'
        
        return 'generic_security_incident'
    
    async def _malware_incident_playbook(self, context: IncidentContext) -> IncidentContext:
        """Playbook for malware incidents"""
        logger.info(f"Executing malware incident playbook for {context.incident_id}")
        
        # Containment phase
        await self._contain_malware(context)
        
        # Analysis phase
        await self._analyze_malware(context)
        
        # Eradication phase
        await self._eradicate_malware(context)
        
        # Recovery phase
        await self._recover_from_malware(context)
        
        return context
    
    async def _contain_malware(self, context: IncidentContext):
        """Contain malware spread"""
        logger.info(f"Starting malware containment for {context.incident_id}")
        
        containment_actions = []
        
        # Isolate affected systems
        for system in context.affected_systems:
            try:
                # Use Cortex responder to isolate system
                isolation_result = await self.cortex.run_responder(
                    'SystemIsolator_1_0',
                    'system',
                    system
                )
                
                containment_actions.append({
                    'action': 'system_isolation',
                    'target': system,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'success',
                    'details': f'System {system} isolated successfully'
                })
                
                logger.info(f"Isolated system: {system}")
                
            except Exception as e:
                logger.error(f"Failed to isolate system {system}: {e}")
                containment_actions.append({
                    'action': 'system_isolation',
                    'target': system,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'failed',
                    'details': f'Failed to isolate {system}: {str(e)}'
                })
        
        # Block malicious IPs and domains from artifacts
        for artifact in context.artifacts:
            if artifact.get('type') in ['ip', 'domain']:
                try:
                    block_result = await self.cortex.run_responder(
                        'IPBlocker_1_0',
                        'artifact',
                        artifact['value']
                    )
                    
                    containment_actions.append({
                        'action': 'network_blocking',
                        'target': artifact['value'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'result': 'success',
                        'details': f"Blocked {artifact['type']}: {artifact['value']}"
                    })
                    
                    logger.info(f"Blocked {artifact['type']}: {artifact['value']}")
                    
                except Exception as e:
                    logger.error(f"Failed to block {artifact['value']}: {e}")
        
        context.mitigation_actions.extend(containment_actions)
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'containment',
            'description': f'Contained malware - isolated {len(context.affected_systems)} systems',
            'automated': True
        })
        
        # Send containment notification
        await self.notifications.send_alert(
            context,
            f"Malware containment completed. {len(containment_actions)} actions taken.",
            "warning"
        )
    
    async def _analyze_malware(self, context: IncidentContext):
        """Analyze malware samples and artifacts"""
        logger.info(f"Starting malware analysis for {context.incident_id}")
        
        analysis_results = []
        
        # Analyze file hashes
        file_artifacts = [a for a in context.artifacts if a.get('type') in ['hash', 'file']]
        for artifact in file_artifacts:
            try:
                # Run VirusTotal analysis
                vt_result = await self.cortex.run_analyzer(
                    'VirusTotal_GetReport_3_0',
                    artifact['type'],
                    artifact['value']
                )
                
                analysis_results.append({
                    'analyzer': 'VirusTotal',
                    'artifact': artifact['value'],
                    'result': vt_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Run YARA analysis if file hash
                if artifact.get('type') == 'hash':
                    yara_result = await self.cortex.run_analyzer(
                        'Yara_2_0',
                        'hash',
                        artifact['value']
                    )
                    
                    analysis_results.append({
                        'analyzer': 'YARA',
                        'artifact': artifact['value'],
                        'result': yara_result,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
            except Exception as e:
                logger.error(f"Analysis failed for {artifact['value']}: {e}")
        
        # Extract IoCs from analysis results
        extracted_iocs = self._extract_iocs_from_analysis(analysis_results)
        context.iocs.extend(extracted_iocs)
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'analysis',
            'description': f'Analyzed {len(file_artifacts)} artifacts, extracted {len(extracted_iocs)} IoCs',
            'automated': True
        })
        
        logger.info(f"Malware analysis completed for {context.incident_id}")
    
    async def _eradicate_malware(self, context: IncidentContext):
        """Eradicate malware from environment"""
        logger.info(f"Starting malware eradication for {context.incident_id}")
        
        eradication_actions = []
        
        # Remove malware from infected systems
        for system in context.affected_systems:
            try:
                # Use Cortex responder for malware removal
                removal_result = await self.cortex.run_responder(
                    'MalwareRemover_1_0',
                    'system',
                    system
                )
                
                eradication_actions.append({
                    'action': 'malware_removal',
                    'target': system,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'success',
                    'details': f'Malware removed from {system}'
                })
                
            except Exception as e:
                logger.error(f"Failed to remove malware from {system}: {e}")
                eradication_actions.append({
                    'action': 'malware_removal',
                    'target': system,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'failed',
                    'details': f'Failed to remove malware from {system}: {str(e)}'
                })
        
        # Update security tools with new IoCs
        await self._update_security_tools_with_iocs(context.iocs)
        
        context.mitigation_actions.extend(eradication_actions)
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'eradication',
            'description': f'Eradicated malware from {len(context.affected_systems)} systems',
            'automated': True
        })
    
    async def _recover_from_malware(self, context: IncidentContext):
        """Recover systems and services after malware eradication"""
        logger.info(f"Starting recovery for {context.incident_id}")
        
        recovery_actions = []
        
        # Restore systems from backup if needed
        for system in context.affected_systems:
            try:
                # Check system integrity
                integrity_result = await self.cortex.run_analyzer(
                    'SystemIntegrityChecker_1_0',
                    'system',
                    system
                )
                
                if integrity_result.get('status') == 'compromised':
                    # Restore from backup
                    restore_result = await self.cortex.run_responder(
                        'SystemRestore_1_0',
                        'system',
                        system
                    )
                    
                    recovery_actions.append({
                        'action': 'system_restore',
                        'target': system,
                        'timestamp': datetime.utcnow().isoformat(),
                        'result': 'success',
                        'details': f'Restored {system} from backup'
                    })
                else:
                    # System clean, remove isolation
                    deisolation_result = await self.cortex.run_responder(
                        'SystemDeIsolator_1_0',
                        'system',
                        system
                    )
                    
                    recovery_actions.append({
                        'action': 'system_deisolation',
                        'target': system,
                        'timestamp': datetime.utcnow().isoformat(),
                        'result': 'success',
                        'details': f'Removed isolation from {system}'
                    })
                
            except Exception as e:
                logger.error(f"Recovery failed for {system}: {e}")
                recovery_actions.append({
                    'action': 'recovery',
                    'target': system,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'failed',
                    'details': f'Recovery failed for {system}: {str(e)}'
                })
        
        context.mitigation_actions.extend(recovery_actions)
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'recovery',
            'description': f'Recovered {len(context.affected_systems)} systems',
            'automated': True
        })
        
        # Send recovery notification
        await self.notifications.send_alert(
            context,
            f"System recovery completed. {len(recovery_actions)} recovery actions taken.",
            "normal"
        )
    
    async def _network_intrusion_playbook(self, context: IncidentContext) -> IncidentContext:
        """Playbook for network intrusion incidents"""
        logger.info(f"Executing network intrusion playbook for {context.incident_id}")
        
        # Containment: Block suspicious IPs and isolate compromised accounts
        await self._contain_network_intrusion(context)
        
        # Analysis: Investigate attack vectors and lateral movement
        await self._analyze_network_intrusion(context)
        
        # Eradication: Remove attacker presence
        await self._eradicate_network_intrusion(context)
        
        # Recovery: Restore secure access
        await self._recover_from_network_intrusion(context)
        
        return context
    
    async def _generic_security_incident_playbook(self, context: IncidentContext) -> IncidentContext:
        """Generic playbook for security incidents"""
        logger.info(f"Executing generic security incident playbook for {context.incident_id}")
        
        # Standard incident response phases
        await self._generic_containment(context)
        await self._generic_analysis(context)
        await self._generic_eradication(context)
        await self._generic_recovery(context)
        
        return context
    
    async def _generic_containment(self, context: IncidentContext):
        """Generic containment actions"""
        # Block known bad IPs and domains
        for artifact in context.artifacts:
            if artifact.get('type') in ['ip', 'domain'] and artifact.get('ioc', False):
                try:
                    await self.cortex.run_responder('IPBlocker_1_0', 'artifact', artifact['value'])
                    logger.info(f"Blocked {artifact['type']}: {artifact['value']}")
                except Exception as e:
                    logger.error(f"Failed to block {artifact['value']}: {e}")
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'containment',
            'description': 'Generic containment actions completed',
            'automated': True
        })
    
    async def _generic_analysis(self, context: IncidentContext):
        """Generic analysis actions"""
        # Analyze artifacts with available analyzers
        for artifact in context.artifacts:
            try:
                if artifact.get('type') == 'ip':
                    result = await self.cortex.run_analyzer('MaxMind_GeoIP_3_0', 'ip', artifact['value'])
                elif artifact.get('type') == 'domain':
                    result = await self.cortex.run_analyzer('URLVoid_1_0', 'domain', artifact['value'])
                elif artifact.get('type') == 'hash':
                    result = await self.cortex.run_analyzer('VirusTotal_GetReport_3_0', 'hash', artifact['value'])
                    
                logger.info(f"Analyzed {artifact['type']}: {artifact['value']}")
            except Exception as e:
                logger.error(f"Analysis failed for {artifact['value']}: {e}")
        
        # Update timeline
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'analysis',
            'description': f'Analyzed {len(context.artifacts)} artifacts',
            'automated': True
        })
    
    async def _generic_eradication(self, context: IncidentContext):
        """Generic eradication actions"""
        # Standard eradication steps
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'eradication',
            'description': 'Generic eradication actions completed',
            'automated': True
        })
    
    async def _generic_recovery(self, context: IncidentContext):
        """Generic recovery actions"""
        # Standard recovery steps
        context.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'recovery',
            'description': 'Generic recovery actions completed',
            'automated': True
        })
    
    def _extract_iocs_from_analysis(self, analysis_results: List[Dict]) -> List[Dict]:
        """Extract IoCs from Cortex analysis results"""
        iocs = []
        
        for result in analysis_results:
            try:
                if result['analyzer'] == 'VirusTotal':
                    report = result['result']
                    if report.get('positives', 0) > 0:
                        iocs.append({
                            'type': 'hash',
                            'value': result['artifact'],
                            'source': 'VirusTotal',
                            'confidence': min(report.get('positives', 0) / report.get('total', 1) * 100, 100),
                            'tags': ['malware', 'automated']
                        })
                
                elif result['analyzer'] == 'YARA':
                    report = result['result']
                    if report.get('matches'):
                        for match in report['matches']:
                            iocs.append({
                                'type': 'yara_rule',
                                'value': match.get('rule', ''),
                                'source': 'YARA',
                                'confidence': 85,
                                'tags': ['yara', 'automated']
                            })
                            
            except Exception as e:
                logger.error(f"Failed to extract IoCs from analysis result: {e}")
        
        return iocs
    
    async def _update_security_tools_with_iocs(self, iocs: List[Dict]):
        """Update security tools with new IoCs"""
        try:
            # Update MISP with new IoCs
            for ioc in iocs:
                await self.cortex.run_responder(
                    'MISP_2_1',
                    'ioc',
                    json.dumps(ioc)
                )
            
            logger.info(f"Updated security tools with {len(iocs)} IoCs")
            
        except Exception as e:
            logger.error(f"Failed to update security tools with IoCs: {e}")
    
    async def _finalize_incident(self, context: IncidentContext):
        """Final incident documentation and closure"""
        # Generate lessons learned
        context.lessons_learned = self._generate_lessons_learned(context)
        
        # Update case with final status
        if context.case_id:
            await self.thehive.update_case(context.case_id, {
                'status': 'Resolved',
                'summary': f'Automated incident response completed. {len(context.mitigation_actions)} actions taken.',
                'customFields': {
                    'lessons-learned': context.lessons_learned
                }
            })
        
        # Generate incident report
        report = self._generate_incident_report(context)
        
        # Send final notification
        await self.notifications.send_alert(
            context,
            f"Incident response completed successfully. See case {context.case_id} for details.",
            "normal"
        )
        
        # Save incident data
        with open(f'/var/log/soc/incidents/{context.incident_id}.json', 'w') as f:
            json.dump(asdict(context), f, indent=2, default=str)
        
        logger.info(f"Incident {context.incident_id} finalized and documented")
    
    def _generate_lessons_learned(self, context: IncidentContext) -> str:
        """Generate lessons learned from incident"""
        lessons = []
        
        # Analyze response effectiveness
        successful_actions = [a for a in context.mitigation_actions if a.get('result') == 'success']
        failed_actions = [a for a in context.mitigation_actions if a.get('result') == 'failed']
        
        lessons.append(f"Response Effectiveness: {len(successful_actions)} successful actions, {len(failed_actions)} failed actions")
        
        if failed_actions:
            lessons.append("Failed Actions Analysis:")
            for action in failed_actions[:3]:  # Limit to first 3
                lessons.append(f"- {action.get('action', 'Unknown')}: {action.get('details', 'No details')}")
        
        # Time to containment analysis
        containment_events = [t for t in context.timeline if t.get('action') == 'containment']
        if containment_events:
            containment_time = datetime.fromisoformat(containment_events[0]['timestamp']) - datetime.fromisoformat(context.created_at)
            lessons.append(f"Time to Containment: {containment_time.total_seconds() / 60:.1f} minutes")
        
        # Recommendations
        lessons.append("\nRecommendations:")
        if context.severity >= 3:
            lessons.append("- Consider implementing additional monitoring for high-severity incidents")
        if len(context.affected_systems) > 5:
            lessons.append("- Review network segmentation to limit incident scope")
        if failed_actions:
            lessons.append("- Review and test automated response procedures")
        
        return "\n".join(lessons)
    
    def _generate_incident_report(self, context: IncidentContext) -> str:
        """Generate comprehensive incident report"""
        report = f"""
        INCIDENT RESPONSE REPORT
        ========================
        
        Incident ID: {context.incident_id}
        Case ID: {context.case_id}
        Title: {context.title}
        Severity: {context.severity}/4
        
        TIMELINE
        --------
        """
        
        for event in context.timeline:
            report += f"{event['timestamp']}: {event['description']}\n"
        
        report += f"""
        
        AFFECTED SYSTEMS
        ----------------
        {', '.join(context.affected_systems) if context.affected_systems else 'None'}
        
        MITIGATION ACTIONS
        ------------------
        """
        
        for action in context.mitigation_actions:
            report += f"- {action.get('action', 'Unknown')}: {action.get('details', 'No details')} [{action.get('result', 'Unknown')}]\n"
        
        report += f"""
        
        INDICATORS OF COMPROMISE
        ------------------------
        """
        
        for ioc in context.iocs:
            report += f"- {ioc.get('type', 'Unknown')}: {ioc.get('value', '')} (Confidence: {ioc.get('confidence', 0)}%)\n"
        
        report += f"""
        
        LESSONS LEARNED
        ---------------
        {context.lessons_learned}
        
        REPORT GENERATED: {datetime.utcnow().isoformat()}
        """
        
        return report

# Additional playbook methods would be implemented similarly...
async def main():
    """Main execution function for testing"""
    # Example incident data
    incident_data = {
        'id': 'INC-2024-001',
        'title': 'Malware Detection on Workstation',
        'description': 'Suspicious malware activity detected on user workstation WS-001',
        'severity': 3,
        'source': 'EDR',
        'artifacts': [
            {
                'type': 'hash',
                'value': 'a1b2c3d4e5f6789012345678901234567890abcd',
                'description': 'Malicious file hash',
                'ioc': True,
                'tags': ['malware']
            },
            {
                'type': 'ip',
                'value': '192.168.1.100',
                'description': 'Suspicious communication',
                'ioc': True,
                'tags': ['c2']
            }
        ],
        'affected_systems': ['WS-001', 'WS-002']
    }
    
    # Initialize orchestrator
    orchestrator = ResponseOrchestrator('config/soar-config.yaml')
    
    # Execute incident response
    result = await orchestrator.execute_incident_response(incident_data)
    
    print(f"Incident response completed: {result.incident_id}")
    print(f"Case ID: {result.case_id}")
    print(f"Actions taken: {len(result.mitigation_actions)}")

if __name__ == "__main__":
    asyncio.run(main())