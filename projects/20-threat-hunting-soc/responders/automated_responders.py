#!/usr/bin/env python3
"""
Automated Cortex Responders for SOC SOAR Platform
Advanced automated response capabilities for incident containment
Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import time
import os
import re
import subprocess
import socket
import requests
import yaml
import smtplib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from email.mime.text import MimeText, MimeMultipart
from email.mime.base import MimeBase
from email import encoders
import paramiko
import winrm
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import ssl
import certifi

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/soc/responders.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ResponderResult:
    """Standard responder result format"""
    success: bool
    full: Dict[str, Any]
    operations: List[Dict[str, Any]]
    message: str

class BaseResponder(ABC):
    """Base class for automated responders"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.version = "1.0"
        self.author = "SOC Team"
        
    @abstractmethod
    async def run(self, data: str) -> ResponderResult:
        """Execute the responder"""
        pass
    
    def _log_operation(self, action: str, target: str, result: str, details: str = "") -> Dict[str, Any]:
        """Log responder operation"""
        operation = {
            "timestamp": datetime.utcnow().isoformat(),
            "responder": self.name,
            "action": action,
            "target": target,
            "result": result,
            "details": details
        }
        logger.info(f"{self.name}: {action} on {target} - {result}")
        return operation

class IPBlockerResponder(BaseResponder):
    """Advanced IP blocking responder with multiple firewall support"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.firewall_type = config.get('firewall_type', 'iptables')
        self.ssh_config = config.get('ssh_config', {})
        self.api_config = config.get('api_config', {})
        self.whitelist = set(config.get('whitelist', [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'
        ]))
        self.block_duration = config.get('default_duration', '24h')
        
        # Initialize blocked IPs database
        self._initialize_blocked_ips_db()
    
    def _initialize_blocked_ips_db(self):
        """Initialize database for tracking blocked IPs"""
        db_path = self.config.get('blocked_ips_db', '/opt/cortex/data/blocked_ips.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                reason TEXT,
                firewall_rule_id TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        self.conn.commit()
    
    async def run(self, data: str) -> ResponderResult:
        """Block IP address using configured firewall"""
        logger.info(f"Running IP blocker for: {data}")
        
        operations = []
        
        try:
            # Parse IP address
            ip_address = data.strip()
            
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
            except ValueError:
                raise Exception(f"Invalid IP address: {ip_address}")
            
            # Check if IP is whitelisted
            if self._is_whitelisted(ip_address):
                operation = self._log_operation("whitelist_check", ip_address, "blocked", "IP is whitelisted")
                operations.append(operation)
                
                return ResponderResult(
                    success=False,
                    full={"ip": ip_address, "reason": "whitelisted"},
                    operations=operations,
                    message=f"IP {ip_address} is whitelisted and cannot be blocked"
                )
            
            # Check if already blocked
            if self._is_already_blocked(ip_address):
                operation = self._log_operation("duplicate_check", ip_address, "skipped", "IP already blocked")
                operations.append(operation)
                
                return ResponderResult(
                    success=True,
                    full={"ip": ip_address, "status": "already_blocked"},
                    operations=operations,
                    message=f"IP {ip_address} is already blocked"
                )
            
            # Block IP based on firewall type
            if self.firewall_type == 'iptables':
                result = await self._block_with_iptables(ip_address)
            elif self.firewall_type == 'pfsense':
                result = await self._block_with_pfsense(ip_address)
            elif self.firewall_type == 'fortigate':
                result = await self._block_with_fortigate(ip_address)
            elif self.firewall_type == 'cisco_asa':
                result = await self._block_with_cisco_asa(ip_address)
            elif self.firewall_type == 'windows':
                result = await self._block_with_windows_firewall(ip_address)
            else:
                raise Exception(f"Unsupported firewall type: {self.firewall_type}")
            
            if result['success']:
                # Record blocked IP in database
                self._record_blocked_ip(ip_address, result.get('rule_id', ''), "Automated SOAR response")
                
                operation = self._log_operation("ip_block", ip_address, "success", f"Blocked via {self.firewall_type}")
                operations.append(operation)
                
                # Schedule automatic unblock if duration is set
                if self.block_duration and self.block_duration != 'permanent':
                    await self._schedule_unblock(ip_address, self.block_duration)
                
                return ResponderResult(
                    success=True,
                    full={"ip": ip_address, "firewall": self.firewall_type, "rule_id": result.get('rule_id', '')},
                    operations=operations,
                    message=f"Successfully blocked IP {ip_address}"
                )
            else:
                operation = self._log_operation("ip_block", ip_address, "failed", result.get('error', ''))
                operations.append(operation)
                
                return ResponderResult(
                    success=False,
                    full={"ip": ip_address, "error": result.get('error', '')},
                    operations=operations,
                    message=f"Failed to block IP {ip_address}: {result.get('error', '')}"
                )
                
        except Exception as e:
            logger.error(f"IP blocking failed: {e}")
            operation = self._log_operation("ip_block", data, "error", str(e))
            operations.append(operation)
            
            return ResponderResult(
                success=False,
                full={"error": str(e)},
                operations=operations,
                message=f"IP blocking failed: {str(e)}"
            )
    
    def _is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is in whitelist"""
        ip_obj = ipaddress.ip_address(ip_address)
        
        for whitelist_entry in self.whitelist:
            try:
                if ip_obj in ipaddress.ip_network(whitelist_entry, strict=False):
                    return True
            except ValueError:
                continue
        
        return False
    
    def _is_already_blocked(self, ip_address: str) -> bool:
        """Check if IP is already blocked"""
        cursor = self.conn.execute(
            "SELECT id FROM blocked_ips WHERE ip_address = ? AND status = 'active' AND (expires_at IS NULL OR expires_at > datetime('now'))",
            (ip_address,)
        )
        return cursor.fetchone() is not None
    
    async def _block_with_iptables(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using iptables"""
        try:
            if self.ssh_config:
                # Remote iptables execution via SSH
                result = await self._execute_remote_command(
                    f"iptables -I INPUT -s {ip_address} -j DROP",
                    self.ssh_config
                )
            else:
                # Local iptables execution
                result = subprocess.run(
                    ['iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            if result.returncode == 0:
                return {"success": True, "rule_id": f"iptables-{ip_address}"}
            else:
                return {"success": False, "error": result.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _block_with_pfsense(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using pfSense API"""
        try:
            api_url = self.api_config.get('pfsense_url')
            api_key = self.api_config.get('pfsense_key')
            
            if not api_url or not api_key:
                raise Exception("pfSense API configuration missing")
            
            # Create firewall rule via pfSense API
            payload = {
                "interface": "wan",
                "protocol": "any",
                "src": ip_address,
                "dst": "any",
                "descr": f"SOAR Auto-block {datetime.utcnow().isoformat()}",
                "type": "block"
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"{api_url}/api/v1/firewall/rule",
                json=payload,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                rule_data = response.json()
                return {"success": True, "rule_id": rule_data.get('id', '')}
            else:
                return {"success": False, "error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _block_with_fortigate(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using FortiGate API"""
        try:
            api_url = self.api_config.get('fortigate_url')
            api_key = self.api_config.get('fortigate_key')
            
            if not api_url or not api_key:
                raise Exception("FortiGate API configuration missing")
            
            # Add IP to address object
            address_payload = {
                "name": f"SOAR_Block_{ip_address.replace('.', '_')}",
                "subnet": f"{ip_address}/32",
                "type": "ipmask",
                "comment": f"SOAR Auto-block {datetime.utcnow().isoformat()}"
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Create address object
            response = requests.post(
                f"{api_url}/api/v2/cmdb/firewall/address",
                json=address_payload,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                # Create blocking policy
                policy_payload = {
                    "name": f"SOAR_Block_Policy_{ip_address.replace('.', '_')}",
                    "srcintf": [{"name": "any"}],
                    "dstintf": [{"name": "any"}],
                    "srcaddr": [{"name": address_payload["name"]}],
                    "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}],
                    "action": "deny",
                    "comments": f"SOAR Auto-block policy {datetime.utcnow().isoformat()}"
                }
                
                policy_response = requests.post(
                    f"{api_url}/api/v2/cmdb/firewall/policy",
                    json=policy_payload,
                    headers=headers,
                    timeout=30,
                    verify=False
                )
                
                if policy_response.status_code == 200:
                    return {"success": True, "rule_id": policy_payload["name"]}
                else:
                    return {"success": False, "error": f"Policy creation failed: {policy_response.status_code}"}
            else:
                return {"success": False, "error": f"Address creation failed: {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _block_with_cisco_asa(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using Cisco ASA"""
        try:
            ssh_config = self.ssh_config.get('cisco_asa', {})
            
            commands = [
                "enable",
                self.ssh_config.get('enable_password', ''),
                "configure terminal",
                f"access-list SOAR_BLOCK deny ip host {ip_address} any",
                "access-group SOAR_BLOCK in interface outside",
                "write memory",
                "exit"
            ]
            
            result = await self._execute_cisco_commands(commands, ssh_config)
            
            if result['success']:
                return {"success": True, "rule_id": f"SOAR_BLOCK-{ip_address}"}
            else:
                return {"success": False, "error": result.get('error', '')}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _block_with_windows_firewall(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using Windows Firewall via WinRM"""
        try:
            winrm_config = self.ssh_config.get('winrm', {})
            
            if not winrm_config:
                raise Exception("WinRM configuration missing")
            
            # PowerShell command to block IP
            ps_command = f"""
            New-NetFirewallRule -DisplayName "SOAR Auto-block {ip_address}" -Direction Inbound -Protocol Any -Action Block -RemoteAddress {ip_address}
            """
            
            session = winrm.Session(
                winrm_config['host'],
                auth=(winrm_config['username'], winrm_config['password']),
                transport='ntlm'
            )
            
            result = session.run_ps(ps_command)
            
            if result.status_code == 0:
                return {"success": True, "rule_id": f"Windows-FW-{ip_address}"}
            else:
                return {"success": False, "error": result.std_err.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _record_blocked_ip(self, ip_address: str, rule_id: str, reason: str):
        """Record blocked IP in database"""
        expires_at = None
        if self.block_duration and self.block_duration != 'permanent':
            duration_seconds = self._parse_duration(self.block_duration)
            expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
        
        self.conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip_address, expires_at, reason, firewall_rule_id) VALUES (?, ?, ?, ?)",
            (ip_address, expires_at, reason, rule_id)
        )
        self.conn.commit()
    
    async def _execute_remote_command(self, command: str, ssh_config: Dict) -> subprocess.CompletedProcess:
        """Execute command on remote host via SSH"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=ssh_config['host'],
                username=ssh_config['username'],
                password=ssh_config.get('password'),
                key_filename=ssh_config.get('key_file'),
                timeout=30
            )
            
            stdin, stdout, stderr = ssh.exec_command(command)
            
            return_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode()
            stderr_data = stderr.read().decode()
            
            return type('Result', (), {
                'returncode': return_code,
                'stdout': stdout_data,
                'stderr': stderr_data
            })()
            
        finally:
            ssh.close()
    
    def _parse_duration(self, duration: str) -> int:
        """Parse duration string to seconds"""
        duration = duration.lower()
        
        if duration.endswith('s'):
            return int(duration[:-1])
        elif duration.endswith('m'):
            return int(duration[:-1]) * 60
        elif duration.endswith('h'):
            return int(duration[:-1]) * 3600
        elif duration.endswith('d'):
            return int(duration[:-1]) * 86400
        else:
            return int(duration)
    
    async def _schedule_unblock(self, ip_address: str, duration: str):
        """Schedule automatic unblock"""
        # This would typically be handled by a background task or cron job
        logger.info(f"Scheduled unblock for {ip_address} in {duration}")

class HostQuarantineResponder(BaseResponder):
    """Advanced host quarantine responder with multiple isolation methods"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.isolation_method = config.get('isolation_method', 'network')
        self.ad_config = config.get('active_directory', {})
        self.edr_config = config.get('edr_config', {})
        self.network_config = config.get('network_config', {})
        
        # Initialize quarantined hosts database
        self._initialize_quarantine_db()
    
    def _initialize_quarantine_db(self):
        """Initialize database for tracking quarantined hosts"""
        db_path = self.config.get('quarantine_db', '/opt/cortex/data/quarantined_hosts.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                method TEXT NOT NULL,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                reason TEXT,
                status TEXT DEFAULT 'active',
                restore_data TEXT
            )
        ''')
        self.conn.commit()
    
    async def run(self, data: str) -> ResponderResult:
        """Quarantine host using configured method"""
        logger.info(f"Running host quarantine for: {data}")
        
        operations = []
        
        try:
            # Parse host identifier (hostname or IP)
            host_identifier = data.strip()
            
            # Determine if it's IP or hostname
            try:
                ipaddress.ip_address(host_identifier)
                is_ip = True
                hostname = await self._resolve_hostname(host_identifier)
            except ValueError:
                is_ip = False
                hostname = host_identifier
                ip_address = await self._resolve_ip(hostname)
            
            # Check if already quarantined
            if self._is_already_quarantined(hostname or host_identifier):
                operation = self._log_operation("duplicate_check", hostname or host_identifier, "skipped", "Host already quarantined")
                operations.append(operation)
                
                return ResponderResult(
                    success=True,
                    full={"host": hostname or host_identifier, "status": "already_quarantined"},
                    operations=operations,
                    message=f"Host {hostname or host_identifier} is already quarantined"
                )
            
            # Perform quarantine based on method
            if self.isolation_method == 'network':
                result = await self._quarantine_network(hostname or host_identifier, ip_address if not is_ip else host_identifier)
            elif self.isolation_method == 'active_directory':
                result = await self._quarantine_ad(hostname)
            elif self.isolation_method == 'edr':
                result = await self._quarantine_edr(hostname or host_identifier)
            elif self.isolation_method == 'combined':
                result = await self._quarantine_combined(hostname or host_identifier, ip_address if not is_ip else host_identifier)
            else:
                raise Exception(f"Unsupported isolation method: {self.isolation_method}")
            
            if result['success']:
                # Record quarantined host
                self._record_quarantined_host(
                    hostname or host_identifier,
                    ip_address if not is_ip else host_identifier,
                    self.isolation_method,
                    "Automated SOAR response",
                    result.get('restore_data', {})
                )
                
                operation = self._log_operation("host_quarantine", hostname or host_identifier, "success", f"Quarantined via {self.isolation_method}")
                operations.append(operation)
                
                return ResponderResult(
                    success=True,
                    full={
                        "host": hostname or host_identifier,
                        "ip": ip_address if not is_ip else host_identifier,
                        "method": self.isolation_method
                    },
                    operations=operations,
                    message=f"Successfully quarantined host {hostname or host_identifier}"
                )
            else:
                operation = self._log_operation("host_quarantine", hostname or host_identifier, "failed", result.get('error', ''))
                operations.append(operation)
                
                return ResponderResult(
                    success=False,
                    full={"host": hostname or host_identifier, "error": result.get('error', '')},
                    operations=operations,
                    message=f"Failed to quarantine host {hostname or host_identifier}: {result.get('error', '')}"
                )
                
        except Exception as e:
            logger.error(f"Host quarantine failed: {e}")
            operation = self._log_operation("host_quarantine", data, "error", str(e))
            operations.append(operation)
            
            return ResponderResult(
                success=False,
                full={"error": str(e)},
                operations=operations,
                message=f"Host quarantine failed: {str(e)}"
            )
    
    async def _quarantine_network(self, hostname: str, ip_address: str) -> Dict[str, Any]:
        """Quarantine host via network isolation"""
        try:
            # Create firewall rule to block all traffic except management
            management_ips = self.network_config.get('management_ips', ['10.0.0.0/24'])
            
            # Block all traffic except to management network
            block_rules = []
            for mgmt_ip in management_ips:
                rule_id = f"quarantine-{hostname}-{int(time.time())}"
                
                # This would integrate with network equipment APIs
                # For demonstration, we'll simulate the API calls
                rule_result = await self._create_network_isolation_rule(ip_address, mgmt_ip, rule_id)
                if rule_result['success']:
                    block_rules.append(rule_id)
            
            if block_rules:
                return {
                    "success": True,
                    "restore_data": {"rules": block_rules, "method": "network"}
                }
            else:
                return {"success": False, "error": "Failed to create isolation rules"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _quarantine_ad(self, hostname: str) -> Dict[str, Any]:
        """Quarantine host via Active Directory"""
        try:
            server = Server(
                self.ad_config['server'],
                port=self.ad_config.get('port', 389),
                get_info=ALL,
                use_ssl=self.ad_config.get('use_ssl', False)
            )
            
            conn = Connection(
                server,
                user=self.ad_config['username'],
                password=self.ad_config['password'],
                auto_bind=True
            )
            
            # Search for computer object
            search_base = self.ad_config.get('search_base', 'dc=domain,dc=com')
            search_filter = f"(&(objectClass=computer)(cn={hostname}))"
            
            conn.search(search_base, search_filter, attributes=['distinguishedName', 'userAccountControl'])
            
            if not conn.entries:
                return {"success": False, "error": f"Computer {hostname} not found in AD"}
            
            computer_dn = str(conn.entries[0].distinguishedName)
            current_uac = int(conn.entries[0].userAccountControl)
            
            # Disable computer account
            new_uac = current_uac | 0x2  # Add ACCOUNTDISABLE flag
            
            result = conn.modify(computer_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
            
            if result:
                # Move to quarantine OU if configured
                quarantine_ou = self.ad_config.get('quarantine_ou')
                if quarantine_ou:
                    conn.modify_dn(computer_dn, f"cn={hostname}", new_superior=quarantine_ou)
                
                return {
                    "success": True,
                    "restore_data": {
                        "method": "ad",
                        "original_dn": computer_dn,
                        "original_uac": current_uac,
                        "quarantine_ou": quarantine_ou
                    }
                }
            else:
                return {"success": False, "error": "Failed to modify AD object"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _quarantine_edr(self, host_identifier: str) -> Dict[str, Any]:
        """Quarantine host via EDR solution"""
        try:
            edr_type = self.edr_config.get('type', 'crowdstrike')
            
            if edr_type == 'crowdstrike':
                return await self._quarantine_crowdstrike(host_identifier)
            elif edr_type == 'sentinelone':
                return await self._quarantine_sentinelone(host_identifier)
            elif edr_type == 'defender':
                return await self._quarantine_defender(host_identifier)
            else:
                return {"success": False, "error": f"Unsupported EDR type: {edr_type}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _quarantine_crowdstrike(self, host_identifier: str) -> Dict[str, Any]:
        """Quarantine host using CrowdStrike Falcon API"""
        try:
            api_url = self.edr_config.get('api_url', 'https://api.crowdstrike.com')
            client_id = self.edr_config.get('client_id')
            client_secret = self.edr_config.get('client_secret')
            
            # Get OAuth token
            auth_response = requests.post(
                f"{api_url}/oauth2/token",
                data={
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'client_credentials'
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if auth_response.status_code != 200:
                return {"success": False, "error": "Failed to authenticate with CrowdStrike"}
            
            token = auth_response.json()['access_token']
            headers = {'Authorization': f'Bearer {token}'}
            
            # Find device ID
            device_response = requests.get(
                f"{api_url}/devices/queries/devices/v1",
                params={'filter': f"hostname:'{host_identifier}'"},
                headers=headers,
                timeout=30
            )
            
            if device_response.status_code != 200:
                return {"success": False, "error": "Failed to find device"}
            
            device_ids = device_response.json().get('resources', [])
            if not device_ids:
                return {"success": False, "error": "Device not found"}
            
            # Quarantine device
            quarantine_response = requests.post(
                f"{api_url}/devices/entities/devices-actions/v2",
                json={
                    'ids': device_ids,
                    'action_name': 'contain',
                    'parameters': [{'name': 'comment', 'value': 'SOAR automated quarantine'}]
                },
                headers=headers,
                timeout=30
            )
            
            if quarantine_response.status_code == 202:
                return {
                    "success": True,
                    "restore_data": {
                        "method": "crowdstrike",
                        "device_ids": device_ids,
                        "action_id": quarantine_response.json().get('resources', [{}])[0].get('id')
                    }
                }
            else:
                return {"success": False, "error": "Failed to quarantine device"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _quarantine_combined(self, hostname: str, ip_address: str) -> Dict[str, Any]:
        """Quarantine using multiple methods for maximum isolation"""
        results = {}
        
        # Network isolation
        network_result = await self._quarantine_network(hostname, ip_address)
        results['network'] = network_result
        
        # AD quarantine if configured
        if self.ad_config:
            ad_result = await self._quarantine_ad(hostname)
            results['ad'] = ad_result
        
        # EDR quarantine if configured
        if self.edr_config:
            edr_result = await self._quarantine_edr(hostname)
            results['edr'] = edr_result
        
        # Check if at least one method succeeded
        success_count = sum(1 for result in results.values() if result.get('success', False))
        
        if success_count > 0:
            return {
                "success": True,
                "restore_data": {
                    "method": "combined",
                    "results": results
                }
            }
        else:
            return {
                "success": False,
                "error": "All quarantine methods failed",
                "details": results
            }
    
    def _is_already_quarantined(self, hostname: str) -> bool:
        """Check if host is already quarantined"""
        cursor = self.conn.execute(
            "SELECT id FROM quarantined_hosts WHERE hostname = ? AND status = 'active'",
            (hostname,)
        )
        return cursor.fetchone() is not None
    
    def _record_quarantined_host(self, hostname: str, ip_address: str, method: str, reason: str, restore_data: Dict):
        """Record quarantined host in database"""
        self.conn.execute(
            "INSERT INTO quarantined_hosts (hostname, ip_address, method, reason, restore_data) VALUES (?, ?, ?, ?, ?)",
            (hostname, ip_address, method, reason, json.dumps(restore_data))
        )
        self.conn.commit()
    
    async def _resolve_hostname(self, ip_address: str) -> Optional[str]:
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except:
            return None
    
    async def _resolve_ip(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(hostname)
        except:
            return None
    
    async def _create_network_isolation_rule(self, ip_address: str, allowed_network: str, rule_id: str) -> Dict[str, Any]:
        """Create network isolation rule (mock implementation)"""
        # This would integrate with actual network equipment
        return {"success": True, "rule_id": rule_id}

class NotificationResponder(BaseResponder):
    """Advanced notification responder with multiple channels"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.channels = config.get('channels', {})
        self.templates = config.get('templates', {})
        
    async def run(self, data: str) -> ResponderResult:
        """Send notifications through configured channels"""
        logger.info(f"Running notification responder with data: {data[:100]}...")
        
        operations = []
        
        try:
            # Parse notification data (JSON expected)
            try:
                notification_data = json.loads(data)
            except json.JSONDecodeError:
                # If not JSON, treat as simple message
                notification_data = {
                    "message": data,
                    "urgency": "normal",
                    "title": "SOC Alert"
                }
            
            # Send notifications to all configured channels
            results = {}
            
            if self.channels.get('email', {}).get('enabled', False):
                email_result = await self._send_email_notification(notification_data)
                results['email'] = email_result
                operations.append(self._log_operation("email_notification", "email", "success" if email_result['success'] else "failed"))
            
            if self.channels.get('slack', {}).get('enabled', False):
                slack_result = await self._send_slack_notification(notification_data)
                results['slack'] = slack_result
                operations.append(self._log_operation("slack_notification", "slack", "success" if slack_result['success'] else "failed"))
            
            if self.channels.get('teams', {}).get('enabled', False):
                teams_result = await self._send_teams_notification(notification_data)
                results['teams'] = teams_result
                operations.append(self._log_operation("teams_notification", "teams", "success" if teams_result['success'] else "failed"))
            
            if self.channels.get('sms', {}).get('enabled', False):
                sms_result = await self._send_sms_notification(notification_data)
                results['sms'] = sms_result
                operations.append(self._log_operation("sms_notification", "sms", "success" if sms_result['success'] else "failed"))
            
            if self.channels.get('webhook', {}).get('enabled', False):
                webhook_result = await self._send_webhook_notification(notification_data)
                results['webhook'] = webhook_result
                operations.append(self._log_operation("webhook_notification", "webhook", "success" if webhook_result['success'] else "failed"))
            
            # Check overall success
            successful_channels = [channel for channel, result in results.items() if result.get('success', False)]
            
            return ResponderResult(
                success=len(successful_channels) > 0,
                full={
                    "notification_data": notification_data,
                    "results": results,
                    "successful_channels": successful_channels
                },
                operations=operations,
                message=f"Notifications sent to {len(successful_channels)} channels: {', '.join(successful_channels)}"
            )
            
        except Exception as e:
            logger.error(f"Notification sending failed: {e}")
            operation = self._log_operation("notification", "all_channels", "error", str(e))
            operations.append(operation)
            
            return ResponderResult(
                success=False,
                full={"error": str(e)},
                operations=operations,
                message=f"Notification sending failed: {str(e)}"
            )
    
    async def _send_email_notification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send email notification"""
        try:
            email_config = self.channels['email']
            
            # Create email
            msg = MimeMultipart()
            msg['From'] = email_config['from']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = f"[SOC ALERT] {data.get('title', 'Security Alert')}"
            
            # Generate email body from template
            template_name = data.get('template', 'default')
            template_path = self.templates.get(template_name, {}).get('email')
            
            if template_path and os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    template = f.read()
                
                # Simple template substitution
                body = template.format(**data)
            else:
                # Default email body
                body = f"""
SOC Security Alert

Title: {data.get('title', 'Security Alert')}
Urgency: {data.get('urgency', 'normal').upper()}
Time: {datetime.utcnow().isoformat()}

Message:
{data.get('message', 'No message provided')}

Incident Details:
{json.dumps(data.get('incident', {}), indent=2)}

This is an automated message from the SOC SOAR platform.
"""
            
            msg.attach(MimeText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
            if email_config.get('use_tls', False):
                server.starttls()
            if email_config.get('username') and email_config.get('password'):
                server.login(email_config['username'], email_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_slack_notification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send Slack notification"""
        try:
            slack_config = self.channels['slack']
            
            urgency = data.get('urgency', 'normal')
            color_mapping = {
                'low': '#36a64f',
                'normal': '#36a64f',
                'high': '#ffaa00',
                'critical': '#ff0000'
            }
            
            payload = {
                'channel': slack_config.get('channel', '#soc-alerts'),
                'username': 'SOC-SOAR',
                'icon_emoji': ':warning:',
                'attachments': [
                    {
                        'color': color_mapping.get(urgency, '#36a64f'),
                        'title': f"🚨 {data.get('title', 'SOC Alert')}",
                        'fields': [
                            {
                                'title': 'Urgency',
                                'value': urgency.upper(),
                                'short': True
                            },
                            {
                                'title': 'Time',
                                'value': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'short': True
                            }
                        ],
                        'text': data.get('message', 'No message provided'),
                        'footer': 'SOC SOAR Platform',
                        'ts': int(time.time())
                    }
                ]
            }
            
            # Add incident details if available
            if data.get('incident'):
                incident = data['incident']
                payload['attachments'][0]['fields'].extend([
                    {
                        'title': 'Incident ID',
                        'value': incident.get('id', 'N/A'),
                        'short': True
                    },
                    {
                        'title': 'Affected Systems',
                        'value': ', '.join(incident.get('affected_systems', [])) or 'None',
                        'short': False
                    }
                ])
            
            response = requests.post(
                slack_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return {"success": True}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_teams_notification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send Microsoft Teams notification"""
        try:
            teams_config = self.channels['teams']
            
            urgency = data.get('urgency', 'normal')
            color_mapping = {
                'low': '00ff00',
                'normal': '36a64f',
                'high': 'ffaa00',
                'critical': 'ff0000'
            }
            
            payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': data.get('title', 'SOC Alert'),
                'themeColor': color_mapping.get(urgency, '36a64f'),
                'sections': [
                    {
                        'activityTitle': f"🚨 {data.get('title', 'SOC Alert')}",
                        'activitySubtitle': f"Urgency: {urgency.upper()}",
                        'facts': [
                            {'name': 'Time', 'value': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')},
                            {'name': 'Source', 'value': 'SOC SOAR Platform'}
                        ],
                        'text': data.get('message', 'No message provided')
                    }
                ]
            }
            
            # Add incident details if available
            if data.get('incident'):
                incident = data['incident']
                payload['sections'][0]['facts'].extend([
                    {'name': 'Incident ID', 'value': incident.get('id', 'N/A')},
                    {'name': 'Affected Systems', 'value': ', '.join(incident.get('affected_systems', [])) or 'None'}
                ])
            
            response = requests.post(
                teams_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return {"success": True}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_sms_notification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send SMS notification"""
        try:
            sms_config = self.channels['sms']
            
            # Format SMS message
            message = f"SOC ALERT: {data.get('title', 'Security Alert')} - {data.get('message', 'No details')[:100]}"
            
            # Use Twilio API (example)
            if sms_config.get('provider') == 'twilio':
                from twilio.rest import Client
                
                client = Client(sms_config['account_sid'], sms_config['auth_token'])
                
                for recipient in sms_config['recipients']:
                    message = client.messages.create(
                        body=message,
                        from_=sms_config['from_number'],
                        to=recipient
                    )
                
                return {"success": True}
            else:
                return {"success": False, "error": "Unsupported SMS provider"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_webhook_notification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook notification"""
        try:
            webhook_config = self.channels['webhook']
            
            payload = {
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'soc-soar',
                'event_type': 'security_alert',
                'data': data
            }
            
            headers = {'Content-Type': 'application/json'}
            
            # Add authentication if configured
            if webhook_config.get('auth_header'):
                headers['Authorization'] = webhook_config['auth_header']
            
            response = requests.post(
                webhook_config['url'],
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if 200 <= response.status_code < 300:
                return {"success": True}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}

# Factory function to create responders
def create_responder(responder_name: str, config: Dict[str, Any]) -> BaseResponder:
    """Factory function to create responder instances"""
    responders = {
        'IPBlocker': IPBlockerResponder,
        'HostQuarantine': HostQuarantineResponder,
        'Notification': NotificationResponder
    }
    
    if responder_name not in responders:
        raise ValueError(f"Unknown responder: {responder_name}")
    
    return responders[responder_name](config)

# Main execution function for testing
async def main():
    """Test the responders"""
    
    # Test IP Blocker
    ip_blocker_config = {
        'firewall_type': 'iptables',
        'ssh_config': {
            'host': 'firewall.soc.local',
            'username': 'admin',
            'password': 'admin123'
        },
        'whitelist': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        'default_duration': '24h'
    }
    
    ip_blocker = create_responder('IPBlocker', ip_blocker_config)
    result = await ip_blocker.run('192.168.1.100')
    print(f"IP Blocker Result: {result.message}")
    
    # Test Host Quarantine
    quarantine_config = {
        'isolation_method': 'network',
        'network_config': {
            'management_ips': ['10.0.0.0/24']
        }
    }
    
    quarantine_responder = create_responder('HostQuarantine', quarantine_config)
    result = await quarantine_responder.run('DESKTOP-001')
    print(f"Host Quarantine Result: {result.message}")
    
    # Test Notifications
    notification_config = {
        'channels': {
            'slack': {
                'enabled': True,
                'webhook_url': 'https://hooks.slack.com/services/TEST',
                'channel': '#soc-alerts'
            }
        }
    }
    
    notification_responder = create_responder('Notification', notification_config)
    
    notification_data = {
        "title": "Test Security Alert",
        "message": "This is a test alert from the SOC SOAR platform",
        "urgency": "high",
        "incident": {
            "id": "INC-2024-001",
            "affected_systems": ["SERVER-001", "DESKTOP-002"]
        }
    }
    
    result = await notification_responder.run(json.dumps(notification_data))
    print(f"Notification Result: {result.message}")

if __name__ == "__main__":
    asyncio.run(main())