#!/usr/bin/env python3
"""
Network Behavior Analytics Engine
Advanced network traffic analysis for anomaly detection and lateral movement identification.

Author: SOC Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Any, Tuple, Set
import networkx as nx
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

class NetworkTopologyMapper:
    """Map and analyze network topology for behavioral analysis."""
    
    def __init__(self):
        """Initialize network topology mapper."""
        self.network_graph = nx.DiGraph()
        self.subnet_mappings = {}
        self.device_profiles = {}
        self.communication_baselines = {}
        
    def build_network_topology(self, network_flows: List[Dict]) -> Dict[str, Any]:
        """Build network topology from flow data."""
        try:
            # Clear previous topology
            self.network_graph.clear()
            
            # Process network flows
            for flow in network_flows:
                src_ip = flow.get('source_ip')
                dst_ip = flow.get('destination_ip')
                src_port = flow.get('source_port', 0)
                dst_port = flow.get('destination_port', 0)
                protocol = flow.get('protocol', 'unknown')
                bytes_transferred = flow.get('bytes', 0)
                timestamp = flow.get('timestamp', datetime.utcnow())
                
                if src_ip and dst_ip:
                    # Add nodes
                    self.network_graph.add_node(src_ip, type='host')
                    self.network_graph.add_node(dst_ip, type='host')
                    
                    # Add or update edge
                    if self.network_graph.has_edge(src_ip, dst_ip):
                        # Update existing edge
                        edge_data = self.network_graph[src_ip][dst_ip]
                        edge_data['flow_count'] += 1
                        edge_data['total_bytes'] += bytes_transferred
                        edge_data['protocols'].add(protocol)
                        edge_data['dst_ports'].add(dst_port)
                        edge_data['last_seen'] = max(edge_data['last_seen'], timestamp)
                    else:
                        # Create new edge
                        self.network_graph.add_edge(src_ip, dst_ip, 
                                                  flow_count=1,
                                                  total_bytes=bytes_transferred,
                                                  protocols={protocol},
                                                  dst_ports={dst_port},
                                                  first_seen=timestamp,
                                                  last_seen=timestamp)
            
            # Analyze topology
            topology_analysis = self._analyze_topology()
            
            return {
                'nodes_count': self.network_graph.number_of_nodes(),
                'edges_count': self.network_graph.number_of_edges(),
                'topology_metrics': topology_analysis,
                'subnet_analysis': self._analyze_subnets(),
                'communication_patterns': self._identify_communication_patterns()
            }
            
        except Exception as e:
            logger.error(f"Network topology building failed: {e}")
            return {'error': str(e)}
    
    def _analyze_topology(self) -> Dict[str, Any]:
        """Analyze network topology metrics."""
        try:
            analysis = {}
            
            if self.network_graph.number_of_nodes() > 0:
                # Centrality measures
                betweenness = nx.betweenness_centrality(self.network_graph)
                closeness = nx.closeness_centrality(self.network_graph)
                degree_centrality = nx.degree_centrality(self.network_graph)
                
                analysis['most_central_nodes'] = {
                    'betweenness': sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:10],
                    'closeness': sorted(closeness.items(), key=lambda x: x[1], reverse=True)[:10],
                    'degree': sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:10]
                }
                
                # Network density
                analysis['network_density'] = nx.density(self.network_graph)
                
                # Connected components
                analysis['connected_components'] = nx.number_connected_components(self.network_graph.to_undirected())
                
                # Clustering coefficient
                analysis['clustering_coefficient'] = nx.average_clustering(self.network_graph.to_undirected())
            
            return analysis
            
        except Exception as e:
            logger.error(f"Topology analysis failed: {e}")
            return {'error': str(e)}
    
    def _analyze_subnets(self) -> Dict[str, Any]:
        """Analyze subnet-level communication patterns."""
        subnet_stats = defaultdict(lambda: {
            'internal_communication': 0,
            'external_communication': 0,
            'unique_external_ips': set(),
            'protocols': set(),
            'total_bytes': 0
        })
        
        try:
            # Define common private subnets
            private_subnets = [
                ip_network('10.0.0.0/8'),
                ip_network('172.16.0.0/12'),
                ip_network('192.168.0.0/16')
            ]
            
            for src_ip, dst_ip, edge_data in self.network_graph.edges(data=True):
                try:
                    src_addr = ip_address(src_ip)
                    dst_addr = ip_address(dst_ip)
                    
                    # Determine source subnet
                    src_subnet = None
                    for subnet in private_subnets:
                        if src_addr in subnet:
                            src_subnet = str(subnet)
                            break
                    
                    if src_subnet:
                        stats = subnet_stats[src_subnet]
                        
                        # Check if destination is internal or external
                        is_internal = any(dst_addr in subnet for subnet in private_subnets)
                        
                        if is_internal:
                            stats['internal_communication'] += edge_data['flow_count']
                        else:
                            stats['external_communication'] += edge_data['flow_count']
                            stats['unique_external_ips'].add(dst_ip)
                        
                        stats['protocols'].update(edge_data['protocols'])
                        stats['total_bytes'] += edge_data['total_bytes']
                
                except Exception:
                    continue
            
            # Convert sets to lists for JSON serialization
            result = {}
            for subnet, stats in subnet_stats.items():
                result[subnet] = {
                    'internal_communication': stats['internal_communication'],
                    'external_communication': stats['external_communication'],
                    'unique_external_ips': len(stats['unique_external_ips']),
                    'protocols': list(stats['protocols']),
                    'total_bytes': stats['total_bytes'],
                    'external_ratio': stats['external_communication'] / max(
                        stats['internal_communication'] + stats['external_communication'], 1
                    )
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Subnet analysis failed: {e}")
            return {'error': str(e)}
    
    def _identify_communication_patterns(self) -> Dict[str, Any]:
        """Identify common communication patterns."""
        patterns = {
            'beaconing_candidates': [],
            'high_volume_transfers': [],
            'unusual_protocols': [],
            'port_scanning_indicators': []
        }
        
        try:
            for src_ip, dst_ip, edge_data in self.network_graph.edges(data=True):
                flow_count = edge_data['flow_count']
                total_bytes = edge_data['total_bytes']
                protocols = edge_data['protocols']
                dst_ports = edge_data['dst_ports']
                
                # Beaconing detection (high frequency, low volume)
                if flow_count > 50 and total_bytes / flow_count < 1000:
                    patterns['beaconing_candidates'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'flow_count': flow_count,
                        'avg_bytes_per_flow': total_bytes / flow_count,
                        'protocols': list(protocols)
                    })
                
                # High volume transfers
                if total_bytes > 100 * 1024 * 1024:  # 100MB threshold
                    patterns['high_volume_transfers'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'total_bytes': total_bytes,
                        'flow_count': flow_count,
                        'protocols': list(protocols)
                    })
                
                # Unusual protocols
                unusual_protocols = protocols - {'tcp', 'udp', 'icmp', 'http', 'https', 'dns'}
                if unusual_protocols:
                    patterns['unusual_protocols'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'unusual_protocols': list(unusual_protocols),
                        'all_protocols': list(protocols)
                    })
                
                # Port scanning (many destination ports)
                if len(dst_ports) > 20:
                    patterns['port_scanning_indicators'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'port_count': len(dst_ports),
                        'ports_sampled': sorted(list(dst_ports))[:10]
                    })
            
            return patterns
            
        except Exception as e:
            logger.error(f"Communication pattern identification failed: {e}")
            return {'error': str(e)}

class LateralMovementDetector:
    """Detect lateral movement patterns in network traffic."""
    
    def __init__(self):
        """Initialize lateral movement detector."""
        self.authentication_events = []
        self.process_events = []
        self.network_events = []
        self.movement_chains = []
        
    async def detect_lateral_movement(self, security_events: List[Dict]) -> Dict[str, Any]:
        """Detect lateral movement indicators in security events."""
        try:
            # Categorize events
            self._categorize_events(security_events)
            
            # Detect movement patterns
            movement_indicators = {
                'authentication_anomalies': self._detect_auth_anomalies(),
                'privilege_escalation': self._detect_privilege_escalation(),
                'remote_execution': self._detect_remote_execution(),
                'credential_reuse': self._detect_credential_reuse(),
                'movement_chains': self._build_movement_chains(),
                'timeline_analysis': self._analyze_movement_timeline()
            }
            
            # Calculate risk score
            risk_assessment = self._assess_movement_risk(movement_indicators)
            
            return {
                'movement_indicators': movement_indicators,
                'risk_assessment': risk_assessment,
                'affected_hosts': self._get_affected_hosts(),
                'attack_path_reconstruction': self._reconstruct_attack_paths(),
                'recommendations': self._generate_movement_recommendations(risk_assessment)
            }
            
        except Exception as e:
            logger.error(f"Lateral movement detection failed: {e}")
            return {'error': str(e)}
    
    def _categorize_events(self, events: List[Dict]):
        """Categorize events by type for analysis."""
        self.authentication_events = []
        self.process_events = []
        self.network_events = []
        
        for event in events:
            event_type = event.get('event_type', '').lower()
            
            if 'login' in event_type or 'logon' in event_type or 'auth' in event_type:
                self.authentication_events.append(event)
            elif 'process' in event_type or 'execution' in event_type:
                self.process_events.append(event)
            elif 'network' in event_type or 'connection' in event_type:
                self.network_events.append(event)
    
    def _detect_auth_anomalies(self) -> List[Dict]:
        """Detect authentication anomalies indicating lateral movement."""
        anomalies = []
        
        try:
            # Group authentication events by user and source
            user_auth_patterns = defaultdict(lambda: defaultdict(list))
            
            for event in self.authentication_events:
                user = event.get('user', 'unknown')
                source_ip = event.get('source_ip', 'unknown')
                timestamp = event.get('timestamp', datetime.utcnow())
                success = event.get('success', False)
                
                user_auth_patterns[user][source_ip].append({
                    'timestamp': timestamp,
                    'success': success,
                    'event': event
                })
            
            # Analyze patterns for each user
            for user, source_patterns in user_auth_patterns.items():
                # Multiple source IPs for same user (potential lateral movement)
                if len(source_patterns) > 1:
                    source_ips = list(source_patterns.keys())
                    for source_ip in source_ips:
                        events = source_patterns[source_ip]
                        successful_auths = [e for e in events if e['success']]
                        
                        if successful_auths:
                            anomalies.append({
                                'type': 'multiple_source_authentication',
                                'user': user,
                                'source_ip': source_ip,
                                'auth_count': len(successful_auths),
                                'total_sources': len(source_ips),
                                'first_auth': min(e['timestamp'] for e in successful_auths).isoformat(),
                                'last_auth': max(e['timestamp'] for e in successful_auths).isoformat()
                            })
                
                # Rapid authentication across multiple hosts
                all_events = []
                for events in source_patterns.values():
                    all_events.extend([e for e in events if e['success']])
                
                if len(all_events) >= 2:
                    all_events.sort(key=lambda x: x['timestamp'])
                    time_deltas = []
                    
                    for i in range(1, len(all_events)):
                        delta = (all_events[i]['timestamp'] - all_events[i-1]['timestamp']).total_seconds()
                        time_deltas.append(delta)
                    
                    # Rapid succession (within 5 minutes)
                    rapid_auths = [d for d in time_deltas if d < 300]
                    if len(rapid_auths) >= 2:
                        anomalies.append({
                            'type': 'rapid_authentication_sequence',
                            'user': user,
                            'rapid_auth_count': len(rapid_auths),
                            'min_interval_seconds': min(rapid_auths),
                            'avg_interval_seconds': sum(rapid_auths) / len(rapid_auths)
                        })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Authentication anomaly detection failed: {e}")
            return []
    
    def _detect_privilege_escalation(self) -> List[Dict]:
        """Detect privilege escalation events."""
        escalations = []
        
        try:
            # Look for process events indicating privilege escalation
            escalation_indicators = [
                'runas', 'psexec', 'wmic', 'powershell', 'cmd',
                'net user', 'net group', 'whoami', 'elevation'
            ]
            
            for event in self.process_events:
                command_line = event.get('command_line', '').lower()
                process_name = event.get('process_name', '').lower()
                user = event.get('user', 'unknown')
                host = event.get('host', 'unknown')
                
                # Check for escalation indicators
                for indicator in escalation_indicators:
                    if indicator in command_line or indicator in process_name:
                        escalations.append({
                            'type': 'privilege_escalation_attempt',
                            'host': host,
                            'user': user,
                            'process_name': process_name,
                            'command_line': command_line[:200],  # Truncate for safety
                            'indicator': indicator,
                            'timestamp': event.get('timestamp', datetime.utcnow()).isoformat()
                        })
                        break
            
            return escalations
            
        except Exception as e:
            logger.error(f"Privilege escalation detection failed: {e}")
            return []
    
    def _detect_remote_execution(self) -> List[Dict]:
        """Detect remote execution indicators."""
        remote_exec = []
        
        try:
            remote_execution_tools = [
                'psexec', 'wmic', 'winrm', 'powershell', 'schtasks',
                'at.exe', 'sc.exe', 'reg.exe', 'mshta', 'rundll32'
            ]
            
            for event in self.process_events:
                process_name = event.get('process_name', '').lower()
                command_line = event.get('command_line', '').lower()
                parent_process = event.get('parent_process_name', '').lower()
                user = event.get('user', 'unknown')
                host = event.get('host', 'unknown')
                
                # Check for remote execution tools
                for tool in remote_execution_tools:
                    if tool in process_name or tool in command_line:
                        # Additional indicators for remote execution
                        remote_indicators = ['\\\\', 'remote', '/s ', '-s ', 'computer', 'target']
                        has_remote_indicator = any(indicator in command_line for indicator in remote_indicators)
                        
                        if has_remote_indicator or tool in ['psexec', 'wmic', 'winrm']:
                            remote_exec.append({
                                'type': 'remote_execution',
                                'host': host,
                                'user': user,
                                'tool': tool,
                                'process_name': process_name,
                                'command_line': command_line[:200],
                                'parent_process': parent_process,
                                'timestamp': event.get('timestamp', datetime.utcnow()).isoformat()
                            })
                            break
            
            return remote_exec
            
        except Exception as e:
            logger.error(f"Remote execution detection failed: {e}")
            return []
    
    def _detect_credential_reuse(self) -> List[Dict]:
        """Detect credential reuse patterns."""
        credential_reuse = []
        
        try:
            # Group successful authentications by user
            user_sessions = defaultdict(list)
            
            for event in self.authentication_events:
                if event.get('success', False):
                    user = event.get('user', 'unknown')
                    source_ip = event.get('source_ip', 'unknown')
                    target_host = event.get('target_host', 'unknown')
                    timestamp = event.get('timestamp', datetime.utcnow())
                    
                    user_sessions[user].append({
                        'source_ip': source_ip,
                        'target_host': target_host,
                        'timestamp': timestamp
                    })
            
            # Analyze credential reuse patterns
            for user, sessions in user_sessions.items():
                if len(sessions) < 2:
                    continue
                
                # Sort by timestamp
                sessions.sort(key=lambda x: x['timestamp'])
                
                # Look for rapid credential reuse across different hosts
                for i in range(1, len(sessions)):
                    current = sessions[i]
                    previous = sessions[i-1]
                    
                    # Different hosts within short time frame
                    if (current['target_host'] != previous['target_host'] and 
                        (current['timestamp'] - previous['timestamp']).total_seconds() < 600):  # 10 minutes
                        
                        credential_reuse.append({
                            'type': 'rapid_credential_reuse',
                            'user': user,
                            'previous_host': previous['target_host'],
                            'current_host': current['target_host'],
                            'time_delta_seconds': (current['timestamp'] - previous['timestamp']).total_seconds(),
                            'previous_timestamp': previous['timestamp'].isoformat(),
                            'current_timestamp': current['timestamp'].isoformat()
                        })
            
            return credential_reuse
            
        except Exception as e:
            logger.error(f"Credential reuse detection failed: {e}")
            return []
    
    def _build_movement_chains(self) -> List[Dict]:
        """Build lateral movement chains from events."""
        chains = []
        
        try:
            # Create movement graph
            movement_graph = nx.DiGraph()
            
            # Add nodes and edges based on authentication and execution events
            for event in self.authentication_events + self.process_events:
                if event.get('success', True):  # Include successful or unknown status events
                    source = event.get('source_ip', 'unknown')
                    target = event.get('target_host', event.get('host', 'unknown'))
                    user = event.get('user', 'unknown')
                    timestamp = event.get('timestamp', datetime.utcnow())
                    
                    # Add edge with attributes
                    if movement_graph.has_edge(source, target):
                        edge_data = movement_graph[source][target]
                        edge_data['event_count'] += 1
                        edge_data['users'].add(user)
                        edge_data['last_seen'] = max(edge_data['last_seen'], timestamp)
                    else:
                        movement_graph.add_edge(source, target,
                                              event_count=1,
                                              users={user},
                                              first_seen=timestamp,
                                              last_seen=timestamp)
            
            # Find movement chains (paths longer than 2 hops)
            for source in movement_graph.nodes():
                for target in movement_graph.nodes():
                    if source != target:
                        try:
                            # Find all paths between source and target
                            paths = list(nx.all_simple_paths(movement_graph, source, target, cutoff=5))
                            
                            for path in paths:
                                if len(path) >= 3:  # At least 3 nodes (2 hops)
                                    chain_info = {
                                        'type': 'lateral_movement_chain',
                                        'path': path,
                                        'length': len(path),
                                        'hop_count': len(path) - 1,
                                        'users_involved': set(),
                                        'start_time': None,
                                        'end_time': None,
                                        'total_events': 0
                                    }
                                    
                                    # Collect information about the chain
                                    for i in range(len(path) - 1):
                                        edge_data = movement_graph[path[i]][path[i+1]]
                                        chain_info['users_involved'].update(edge_data['users'])
                                        chain_info['total_events'] += edge_data['event_count']
                                        
                                        if chain_info['start_time'] is None:
                                            chain_info['start_time'] = edge_data['first_seen']
                                        else:
                                            chain_info['start_time'] = min(chain_info['start_time'], edge_data['first_seen'])
                                        
                                        if chain_info['end_time'] is None:
                                            chain_info['end_time'] = edge_data['last_seen']
                                        else:
                                            chain_info['end_time'] = max(chain_info['end_time'], edge_data['last_seen'])
                                    
                                    # Convert sets to lists for JSON serialization
                                    chain_info['users_involved'] = list(chain_info['users_involved'])
                                    chain_info['start_time'] = chain_info['start_time'].isoformat()
                                    chain_info['end_time'] = chain_info['end_time'].isoformat()
                                    chain_info['duration_seconds'] = (
                                        datetime.fromisoformat(chain_info['end_time'].replace('Z', '+00:00')) -
                                        datetime.fromisoformat(chain_info['start_time'].replace('Z', '+00:00'))
                                    ).total_seconds()
                                    
                                    chains.append(chain_info)
                                    
                        except nx.NetworkXNoPath:
                            continue
            
            # Sort chains by risk score (length * events * recency)
            current_time = datetime.utcnow()
            for chain in chains:
                end_time = datetime.fromisoformat(chain['end_time'].replace('Z', '+00:00'))
                recency_factor = max(0.1, 1 - (current_time - end_time).total_seconds() / (24 * 3600))  # 24 hour decay
                chain['risk_score'] = chain['length'] * chain['total_events'] * recency_factor
            
            chains.sort(key=lambda x: x['risk_score'], reverse=True)
            
            return chains[:10]  # Return top 10 chains
            
        except Exception as e:
            logger.error(f"Movement chain building failed: {e}")
            return []
    
    def _analyze_movement_timeline(self) -> Dict[str, Any]:
        """Analyze timeline of movement events."""
        try:
            all_events = self.authentication_events + self.process_events + self.network_events
            all_events.sort(key=lambda x: x.get('timestamp', datetime.utcnow()))
            
            if not all_events:
                return {}
            
            timeline = {
                'total_events': len(all_events),
                'time_span_hours': 0,
                'event_rate_per_hour': 0,
                'peak_activity_periods': [],
                'event_distribution': {
                    'authentication': len(self.authentication_events),
                    'process': len(self.process_events),
                    'network': len(self.network_events)
                }
            }
            
            # Calculate time span
            first_event = all_events[0].get('timestamp', datetime.utcnow())
            last_event = all_events[-1].get('timestamp', datetime.utcnow())
            time_span = (last_event - first_event).total_seconds() / 3600  # hours
            
            timeline['time_span_hours'] = time_span
            if time_span > 0:
                timeline['event_rate_per_hour'] = len(all_events) / time_span
            
            # Find peak activity periods (1-hour windows with high activity)
            hourly_counts = defaultdict(int)
            for event in all_events:
                timestamp = event.get('timestamp', datetime.utcnow())
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] += 1
            
            # Find top 5 peak periods
            sorted_periods = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            timeline['peak_activity_periods'] = [
                {
                    'timestamp': period[0].isoformat(),
                    'event_count': period[1]
                }
                for period in sorted_periods
            ]
            
            return timeline
            
        except Exception as e:
            logger.error(f"Timeline analysis failed: {e}")
            return {'error': str(e)}
    
    def _assess_movement_risk(self, indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall lateral movement risk."""
        try:
            risk_factors = {
                'auth_anomalies': len(indicators.get('authentication_anomalies', [])),
                'privilege_escalations': len(indicators.get('privilege_escalation', [])),
                'remote_executions': len(indicators.get('remote_execution', [])),
                'credential_reuses': len(indicators.get('credential_reuse', [])),
                'movement_chains': len(indicators.get('movement_chains', []))
            }
            
            # Weight factors
            weights = {
                'auth_anomalies': 0.15,
                'privilege_escalations': 0.25,
                'remote_executions': 0.3,
                'credential_reuses': 0.2,
                'movement_chains': 0.1
            }
            
            # Calculate weighted risk score
            risk_score = 0
            for factor, count in risk_factors.items():
                risk_score += min(count * weights[factor], weights[factor] * 10)  # Cap individual contributions
            
            # Normalize to 0-1 scale
            risk_score = min(risk_score, 1.0)
            
            # Determine risk level
            if risk_score >= 0.8:
                risk_level = 'critical'
            elif risk_score >= 0.6:
                risk_level = 'high'
            elif risk_score >= 0.4:
                risk_level = 'medium'
            elif risk_score >= 0.2:
                risk_level = 'low'
            else:
                risk_level = 'minimal'
            
            return {
                'risk_score': risk_score,
                'risk_level': risk_level,
                'contributing_factors': risk_factors,
                'weights_applied': weights,
                'assessment_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            return {'risk_score': 0.5, 'risk_level': 'unknown', 'error': str(e)}
    
    def _get_affected_hosts(self) -> List[str]:
        """Get list of hosts affected by lateral movement."""
        hosts = set()
        
        for event in self.authentication_events + self.process_events + self.network_events:
            host = event.get('host')
            target_host = event.get('target_host')
            
            if host:
                hosts.add(host)
            if target_host:
                hosts.add(target_host)
        
        return list(hosts)
    
    def _reconstruct_attack_paths(self) -> List[Dict]:
        """Reconstruct potential attack paths."""
        paths = []
        
        try:
            # Simple path reconstruction based on temporal correlation
            user_activities = defaultdict(list)
            
            for event in self.authentication_events + self.process_events:
                user = event.get('user', 'unknown')
                host = event.get('host', event.get('target_host', 'unknown'))
                timestamp = event.get('timestamp', datetime.utcnow())
                event_type = event.get('event_type', 'unknown')
                
                user_activities[user].append({
                    'host': host,
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'event': event
                })
            
            # Construct paths for each user
            for user, activities in user_activities.items():
                if len(activities) < 2:
                    continue
                
                # Sort by timestamp
                activities.sort(key=lambda x: x['timestamp'])
                
                # Group activities by host transitions
                path = []
                current_host = None
                
                for activity in activities:
                    if activity['host'] != current_host:
                        if current_host is not None:
                            path.append({
                                'from_host': current_host,
                                'to_host': activity['host'],
                                'timestamp': activity['timestamp'].isoformat(),
                                'event_type': activity['event_type']
                            })
                        current_host = activity['host']
                
                if len(path) > 0:
                    paths.append({
                        'user': user,
                        'path': path,
                        'host_count': len(set(p['to_host'] for p in path) | {path[0]['from_host']} if path else set()),
                        'start_time': activities[0]['timestamp'].isoformat(),
                        'end_time': activities[-1]['timestamp'].isoformat(),
                        'duration_seconds': (activities[-1]['timestamp'] - activities[0]['timestamp']).total_seconds()
                    })
            
            return sorted(paths, key=lambda x: x['host_count'], reverse=True)[:10]
            
        except Exception as e:
            logger.error(f"Attack path reconstruction failed: {e}")
            return []
    
    def _generate_movement_recommendations(self, risk_assessment: Dict) -> List[str]:
        """Generate recommendations based on movement analysis."""
        recommendations = []
        
        try:
            risk_level = risk_assessment.get('risk_level', 'minimal')
            factors = risk_assessment.get('contributing_factors', {})
            
            if risk_level in ['critical', 'high']:
                recommendations.extend([
                    "URGENT: Activate incident response procedures for lateral movement",
                    "Isolate affected systems to prevent further spread",
                    "Review and disable compromised user accounts",
                    "Implement additional network segmentation"
                ])
            
            if factors.get('auth_anomalies', 0) > 0:
                recommendations.append("Review authentication logs for credential compromise")
            
            if factors.get('privilege_escalations', 0) > 0:
                recommendations.append("Audit administrative privileges and access controls")
            
            if factors.get('remote_executions', 0) > 0:
                recommendations.extend([
                    "Disable unnecessary remote execution tools (PSExec, WMIC)",
                    "Implement application whitelisting"
                ])
            
            if factors.get('credential_reuses', 0) > 0:
                recommendations.extend([
                    "Force password resets for affected accounts",
                    "Implement credential rotation policies"
                ])
            
            if factors.get('movement_chains', 0) > 0:
                recommendations.extend([
                    "Implement network micro-segmentation",
                    "Deploy endpoint detection and response (EDR) solutions"
                ])
            
            # General recommendations
            recommendations.extend([
                "Enable PowerShell logging and monitoring",
                "Implement just-in-time (JIT) administrative access",
                "Deploy network behavior analytics",
                "Conduct security awareness training"
            ])
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            recommendations.append("Manual security review recommended due to analysis error")
        
        return recommendations

class NetworkBehaviorAnalyzer:
    """Main network behavior analytics engine."""
    
    def __init__(self, elasticsearch_client=None):
        """Initialize network behavior analyzer."""
        self.es_client = elasticsearch_client
        self.topology_mapper = NetworkTopologyMapper()
        self.movement_detector = LateralMovementDetector()
        
        # Analysis cache
        self.analysis_cache = {}
        
    async def analyze_network_behavior(self, analysis_window_hours: int = 24) -> Dict[str, Any]:
        """Perform comprehensive network behavior analysis."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=analysis_window_hours)
            
            logger.info(f"Starting network behavior analysis for {analysis_window_hours} hour window")
            
            # Collect network data
            network_flows = await self._collect_network_flows(start_time, end_time)
            security_events = await self._collect_security_events(start_time, end_time)
            
            # Perform topology analysis
            topology_analysis = self.topology_mapper.build_network_topology(network_flows)
            
            # Perform lateral movement detection
            movement_analysis = await self.movement_detector.detect_lateral_movement(security_events)
            
            # Detect network anomalies
            network_anomalies = await self._detect_network_anomalies(network_flows)
            
            # Generate comprehensive report
            analysis_result = {
                'analysis_period': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'duration_hours': analysis_window_hours
                },
                'data_summary': {
                    'network_flows_analyzed': len(network_flows),
                    'security_events_analyzed': len(security_events)
                },
                'topology_analysis': topology_analysis,
                'lateral_movement_analysis': movement_analysis,
                'network_anomalies': network_anomalies,
                'overall_risk_assessment': self._calculate_overall_risk(
                    topology_analysis, movement_analysis, network_anomalies
                ),
                'actionable_recommendations': self._generate_comprehensive_recommendations(
                    topology_analysis, movement_analysis, network_anomalies
                )
            }
            
            # Cache results
            cache_key = f"network_analysis_{int(end_time.timestamp())}"
            self.analysis_cache[cache_key] = analysis_result
            
            logger.info("Network behavior analysis completed successfully")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Network behavior analysis failed: {e}")
            return {'error': str(e)}
    
    async def _collect_network_flows(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Collect network flow data from Elasticsearch."""
        if not self.es_client:
            # Return mock data for testing
            return self._generate_mock_network_flows(100)
        
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }}},
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "destination.ip"}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 10000
            }
            
            response = self.es_client.search(index="netflow-*,firewall-*", body=query)
            
            flows = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                flows.append({
                    'source_ip': source.get('source', {}).get('ip'),
                    'destination_ip': source.get('destination', {}).get('ip'),
                    'source_port': source.get('source', {}).get('port', 0),
                    'destination_port': source.get('destination', {}).get('port', 0),
                    'protocol': source.get('network', {}).get('protocol', 'unknown'),
                    'bytes': source.get('network', {}).get('bytes', 0),
                    'timestamp': datetime.fromisoformat(source.get('@timestamp', '').replace('Z', '+00:00'))
                })
            
            return flows
            
        except Exception as e:
            logger.error(f"Network flow collection failed: {e}")
            return self._generate_mock_network_flows(100)
    
    async def _collect_security_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Collect security events from Elasticsearch."""
        if not self.es_client:
            # Return mock data for testing
            return self._generate_mock_security_events(50)
        
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }}},
                            {"terms": {"event.category": ["authentication", "process", "network"]}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 5000
            }
            
            response = self.es_client.search(index="winlogbeat-*,syslog-*", body=query)
            
            events = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                events.append({
                    'event_type': source.get('event', {}).get('category'),
                    'user': source.get('user', {}).get('name'),
                    'host': source.get('host', {}).get('hostname'),
                    'source_ip': source.get('source', {}).get('ip'),
                    'target_host': source.get('destination', {}).get('host'),
                    'process_name': source.get('process', {}).get('name'),
                    'command_line': source.get('process', {}).get('command_line'),
                    'success': source.get('event', {}).get('outcome') == 'success',
                    'timestamp': datetime.fromisoformat(source.get('@timestamp', '').replace('Z', '+00:00'))
                })
            
            return events
            
        except Exception as e:
            logger.error(f"Security event collection failed: {e}")
            return self._generate_mock_security_events(50)
    
    async def _detect_network_anomalies(self, network_flows: List[Dict]) -> Dict[str, Any]:
        """Detect network traffic anomalies using machine learning."""
        try:
            if len(network_flows) < 10:
                return {'error': 'Insufficient data for anomaly detection'}
            
            # Prepare feature matrix
            features = []
            flow_info = []
            
            # Group flows by source-destination pairs
            flow_pairs = defaultdict(lambda: {
                'bytes_total': 0,
                'packet_count': 0,
                'duration_seconds': 0,
                'port_diversity': set(),
                'protocol_diversity': set(),
                'first_seen': None,
                'last_seen': None
            })
            
            for flow in network_flows:
                key = (flow['source_ip'], flow['destination_ip'])
                pair_data = flow_pairs[key]
                
                pair_data['bytes_total'] += flow['bytes']
                pair_data['packet_count'] += 1
                pair_data['port_diversity'].add(flow['destination_port'])
                pair_data['protocol_diversity'].add(flow['protocol'])
                
                if pair_data['first_seen'] is None:
                    pair_data['first_seen'] = flow['timestamp']
                else:
                    pair_data['first_seen'] = min(pair_data['first_seen'], flow['timestamp'])
                
                if pair_data['last_seen'] is None:
                    pair_data['last_seen'] = flow['timestamp']
                else:
                    pair_data['last_seen'] = max(pair_data['last_seen'], flow['timestamp'])
            
            # Extract features for each flow pair
            for (src_ip, dst_ip), data in flow_pairs.items():
                duration = (data['last_seen'] - data['first_seen']).total_seconds()
                
                feature_vector = [
                    data['bytes_total'],
                    data['packet_count'],
                    len(data['port_diversity']),
                    len(data['protocol_diversity']),
                    duration,
                    data['bytes_total'] / max(data['packet_count'], 1),  # avg bytes per packet
                    data['packet_count'] / max(duration, 1)  # packet rate
                ]
                
                features.append(feature_vector)
                flow_info.append({
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'metrics': {
                        'bytes_total': data['bytes_total'],
                        'packet_count': data['packet_count'],
                        'port_diversity': len(data['port_diversity']),
                        'protocol_diversity': len(data['protocol_diversity']),
                        'duration_seconds': duration
                    }
                })
            
            if len(features) < 5:
                return {'error': 'Insufficient flow pairs for analysis'}
            
            # Apply anomaly detection
            features_array = np.array(features)
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features_array)
            
            # Isolation Forest
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_predictions = iso_forest.fit_predict(features_scaled)
            
            # DBSCAN clustering
            dbscan = DBSCAN(eps=0.5, min_samples=3)
            cluster_labels = dbscan.fit_predict(features_scaled)
            
            # Identify anomalies
            anomalies = []
            for i, (prediction, cluster) in enumerate(zip(anomaly_predictions, cluster_labels)):
                if prediction == -1 or cluster == -1:  # Anomaly or noise
                    anomaly_info = flow_info[i].copy()
                    anomaly_info['anomaly_score'] = float(iso_forest.decision_function([features_scaled[i]])[0])
                    anomaly_info['cluster_label'] = int(cluster)
                    anomaly_info['anomaly_type'] = 'isolation_forest' if prediction == -1 else 'clustering_noise'
                    anomalies.append(anomaly_info)
            
            return {
                'total_flow_pairs_analyzed': len(features),
                'anomalies_detected': len(anomalies),
                'anomaly_percentage': len(anomalies) / len(features) * 100,
                'anomalous_flows': sorted(anomalies, key=lambda x: x['anomaly_score'])[:20],  # Top 20
                'clustering_results': {
                    'num_clusters': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0),
                    'noise_points': sum(1 for label in cluster_labels if label == -1)
                }
            }
            
        except Exception as e:
            logger.error(f"Network anomaly detection failed: {e}")
            return {'error': str(e)}
    
    def _calculate_overall_risk(self, topology: Dict, movement: Dict, anomalies: Dict) -> Dict[str, Any]:
        """Calculate overall network behavior risk score."""
        try:
            risk_components = {
                'topology_risk': 0.0,
                'movement_risk': 0.0,
                'anomaly_risk': 0.0
            }
            
            # Topology risk factors
            if 'communication_patterns' in topology:
                patterns = topology['communication_patterns']
                risk_components['topology_risk'] = min(
                    (len(patterns.get('beaconing_candidates', [])) * 0.3 +
                     len(patterns.get('unusual_protocols', [])) * 0.2 +
                     len(patterns.get('port_scanning_indicators', [])) * 0.4 +
                     len(patterns.get('high_volume_transfers', [])) * 0.1) / 10, 1.0
                )
            
            # Movement risk
            if 'risk_assessment' in movement:
                risk_components['movement_risk'] = movement['risk_assessment'].get('risk_score', 0.0)
            
            # Anomaly risk
            if 'anomaly_percentage' in anomalies:
                risk_components['anomaly_risk'] = min(anomalies['anomaly_percentage'] / 20.0, 1.0)  # 20% = max risk
            
            # Calculate weighted overall risk
            weights = {'topology_risk': 0.3, 'movement_risk': 0.5, 'anomaly_risk': 0.2}
            overall_risk = sum(risk_components[component] * weights[component] 
                             for component in risk_components)
            
            # Determine risk level
            if overall_risk >= 0.8:
                risk_level = 'critical'
            elif overall_risk >= 0.6:
                risk_level = 'high'
            elif overall_risk >= 0.4:
                risk_level = 'medium'
            elif overall_risk >= 0.2:
                risk_level = 'low'
            else:
                risk_level = 'minimal'
            
            return {
                'overall_risk_score': overall_risk,
                'risk_level': risk_level,
                'risk_components': risk_components,
                'weights_applied': weights,
                'assessment_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Overall risk calculation failed: {e}")
            return {'overall_risk_score': 0.5, 'risk_level': 'unknown', 'error': str(e)}
    
    def _generate_comprehensive_recommendations(self, topology: Dict, movement: Dict, 
                                              anomalies: Dict) -> List[str]:
        """Generate comprehensive recommendations from all analyses."""
        recommendations = []
        
        try:
            # Topology-based recommendations
            if 'communication_patterns' in topology:
                patterns = topology['communication_patterns']
                
                if patterns.get('beaconing_candidates'):
                    recommendations.append("Investigate potential C2 beaconing communications")
                
                if patterns.get('port_scanning_indicators'):
                    recommendations.append("Block source IPs showing port scanning behavior")
                
                if patterns.get('unusual_protocols'):
                    recommendations.append("Review and restrict unusual network protocols")
            
            # Movement-based recommendations
            if 'recommendations' in movement:
                recommendations.extend(movement['recommendations'][:5])  # Top 5
            
            # Anomaly-based recommendations
            if anomalies.get('anomaly_percentage', 0) > 10:
                recommendations.extend([
                    "High network anomaly rate detected - implement enhanced monitoring",
                    "Review network baseline and update detection thresholds"
                ])
            
            # General network security recommendations
            recommendations.extend([
                "Implement network segmentation and zero-trust architecture",
                "Deploy network behavior analytics (NBA) solutions",
                "Enable comprehensive network logging and monitoring",
                "Implement automated threat response capabilities"
            ])
            
        except Exception as e:
            logger.error(f"Comprehensive recommendation generation failed: {e}")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_mock_network_flows(self, count: int) -> List[Dict]:
        """Generate mock network flows for testing."""
        flows = []
        base_time = datetime.utcnow() - timedelta(hours=1)
        
        for i in range(count):
            flow = {
                'source_ip': f"192.168.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
                'destination_ip': f"10.0.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
                'source_port': np.random.randint(1024, 65535),
                'destination_port': np.random.choice([80, 443, 22, 3389, 445, 53, 123]),
                'protocol': np.random.choice(['tcp', 'udp', 'icmp']),
                'bytes': np.random.randint(64, 10000),
                'timestamp': base_time + timedelta(seconds=i * 36)
            }
            flows.append(flow)
        
        return flows
    
    def _generate_mock_security_events(self, count: int) -> List[Dict]:
        """Generate mock security events for testing."""
        events = []
        base_time = datetime.utcnow() - timedelta(hours=1)
        users = ['john.doe', 'jane.smith', 'admin', 'service_account']
        hosts = ['WORKSTATION-01', 'SERVER-01', 'DC-01', 'WEB-01']
        
        for i in range(count):
            event = {
                'event_type': np.random.choice(['authentication', 'process', 'network']),
                'user': np.random.choice(users),
                'host': np.random.choice(hosts),
                'source_ip': f"192.168.1.{np.random.randint(10, 200)}",
                'target_host': np.random.choice(hosts),
                'process_name': np.random.choice(['cmd.exe', 'powershell.exe', 'explorer.exe', 'svchost.exe']),
                'command_line': 'mock command line',
                'success': np.random.choice([True, True, True, False]),  # 75% success rate
                'timestamp': base_time + timedelta(seconds=i * 72)
            }
            events.append(event)
        
        return events

async def main():
    """Main function for testing network behavior analyzer."""
    # Initialize analyzer
    analyzer = NetworkBehaviorAnalyzer()
    
    # Run analysis
    print("Starting network behavior analysis...")
    results = await analyzer.analyze_network_behavior(analysis_window_hours=24)
    
    # Print summary
    print(f"\nAnalysis completed!")
    print(f"Overall risk level: {results.get('overall_risk_assessment', {}).get('risk_level', 'unknown')}")
    print(f"Risk score: {results.get('overall_risk_assessment', {}).get('overall_risk_score', 0):.2f}")
    
    print(f"\nData analyzed:")
    print(f"- Network flows: {results.get('data_summary', {}).get('network_flows_analyzed', 0)}")
    print(f"- Security events: {results.get('data_summary', {}).get('security_events_analyzed', 0)}")
    
    print(f"\nKey findings:")
    movement_analysis = results.get('lateral_movement_analysis', {})
    if 'movement_indicators' in movement_analysis:
        indicators = movement_analysis['movement_indicators']
        print(f"- Authentication anomalies: {len(indicators.get('authentication_anomalies', []))}")
        print(f"- Privilege escalations: {len(indicators.get('privilege_escalation', []))}")
        print(f"- Movement chains: {len(indicators.get('movement_chains', []))}")
    
    network_anomalies = results.get('network_anomalies', {})
    print(f"- Network anomalies detected: {network_anomalies.get('anomalies_detected', 0)}")
    
    print(f"\nTop recommendations:")
    recommendations = results.get('actionable_recommendations', [])
    for i, rec in enumerate(recommendations[:5], 1):
        print(f"{i}. {rec}")

if __name__ == "__main__":
    asyncio.run(main())