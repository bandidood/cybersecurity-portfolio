#!/usr/bin/env python3
"""
Firewall Configuration Framework - Data Models
Defines data structures for firewall rules, policies, and network objects
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Action(Enum):
    """Firewall rule action types"""
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    DROP = "drop"
    LOG = "log"
    LOG_AND_ALLOW = "log_and_allow"
    LOG_AND_DENY = "log_and_deny"


class Protocol(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"
    ESP = "esp"
    AH = "ah"
    GRE = "gre"


class Direction(Enum):
    """Traffic direction"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class Severity(Enum):
    """Rule severity for security policy"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NetworkObject:
    """Represents a network object (host, network, group)"""
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    description: Optional[str] = None
    object_type: str = "host"  # host, network, group, range
    members: List[str] = field(default_factory=list)  # For groups

    def to_cidr(self) -> str:
        """Convert to CIDR notation"""
        if self.object_type == "host":
            return f"{self.ip_address}/32"
        elif self.object_type == "network":
            # Convert netmask to CIDR prefix
            if self.netmask:
                prefix = sum([bin(int(x)).count('1') for x in self.netmask.split('.')])
                return f"{self.ip_address}/{prefix}"
        return self.ip_address or "any"

    def __repr__(self) -> str:
        if self.object_type == "group":
            return f"Group({self.name}, members={len(self.members)})"
        return f"{self.name}({self.to_cidr()})"


@dataclass
class Service:
    """Network service definition"""
    name: str
    protocol: Protocol
    port: Optional[str] = None  # Can be single port or range "80-443"
    description: Optional[str] = None

    def port_range(self) -> tuple:
        """Get port range as tuple (start, end)"""
        if not self.port:
            return (1, 65535)
        if '-' in self.port:
            start, end = self.port.split('-')
            return (int(start), int(end))
        return (int(self.port), int(self.port))

    def __repr__(self) -> str:
        return f"{self.name}({self.protocol.value}/{self.port or 'any'})"


@dataclass
class FirewallRule:
    """Complete firewall rule definition"""
    rule_id: int
    name: str
    action: Action
    source: NetworkObject
    destination: NetworkObject
    service: Service
    direction: Direction = Direction.INBOUND
    enabled: bool = True
    logging: bool = False
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary"""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'action': self.action.value,
            'source': str(self.source),
            'destination': str(self.destination),
            'service': str(self.service),
            'direction': self.direction.value,
            'enabled': self.enabled,
            'logging': self.logging,
            'description': self.description,
            'tags': self.tags,
            'metadata': self.metadata
        }

    def __repr__(self) -> str:
        status = "✓" if self.enabled else "✗"
        return (f"[{self.rule_id}] {status} {self.action.value.upper()}: "
                f"{self.source} → {self.destination} ({self.service})")


@dataclass
class Zone:
    """Network security zone"""
    name: str
    interface: str
    networks: List[NetworkObject] = field(default_factory=list)
    security_level: int = 0  # 0-100, higher is more trusted
    description: Optional[str] = None

    def __repr__(self) -> str:
        return f"Zone({self.name}, security_level={self.security_level})"


@dataclass
class Policy:
    """Firewall policy containing multiple rules"""
    name: str
    rules: List[FirewallRule] = field(default_factory=list)
    zones: List[Zone] = field(default_factory=list)
    default_action: Action = Action.DENY
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a rule to the policy"""
        self.rules.append(rule)

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID"""
        original_length = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < original_length

    def get_rule(self, rule_id: int) -> Optional[FirewallRule]:
        """Get a rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_enabled_rules(self) -> List[FirewallRule]:
        """Get only enabled rules"""
        return [r for r in self.rules if r.enabled]

    def count_by_action(self) -> Dict[str, int]:
        """Count rules by action type"""
        counts = {}
        for rule in self.rules:
            action = rule.action.value
            counts[action] = counts.get(action, 0) + 1
        return counts

    def __repr__(self) -> str:
        return f"Policy({self.name}, {len(self.rules)} rules, default={self.default_action.value})"


@dataclass
class RuleConflict:
    """Represents a conflict between firewall rules"""
    rule1: FirewallRule
    rule2: FirewallRule
    conflict_type: str  # shadowed, redundant, contradictory
    severity: Severity
    description: str
    recommendation: str

    def __repr__(self) -> str:
        return (f"CONFLICT[{self.conflict_type.upper()}]: "
                f"Rule {self.rule1.rule_id} ↔ Rule {self.rule2.rule_id} "
                f"({self.severity.value})")


@dataclass
class AuditResult:
    """Firewall configuration audit result"""
    policy_name: str
    timestamp: datetime
    total_rules: int
    enabled_rules: int
    conflicts: List[RuleConflict] = field(default_factory=list)
    unused_rules: List[int] = field(default_factory=list)
    high_risk_rules: List[int] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_score: float = 0.0  # 0-100

    def get_critical_issues(self) -> List[RuleConflict]:
        """Get critical and high severity conflicts"""
        return [c for c in self.conflicts
                if c.severity in [Severity.CRITICAL, Severity.HIGH]]

    def __repr__(self) -> str:
        return (f"AuditResult({self.policy_name}, "
                f"score={self.compliance_score:.1f}%, "
                f"conflicts={len(self.conflicts)}, "
                f"critical={len(self.get_critical_issues())})")


# Common network objects and services
COMMON_NETWORKS = {
    'any': NetworkObject('any', '0.0.0.0', '0.0.0.0', 'Any network'),
    'localhost': NetworkObject('localhost', '127.0.0.1', '255.255.255.255', 'Localhost'),
    'private_class_a': NetworkObject('private_class_a', '10.0.0.0', '255.0.0.0', 'Class A private'),
    'private_class_b': NetworkObject('private_class_b', '172.16.0.0', '255.240.0.0', 'Class B private'),
    'private_class_c': NetworkObject('private_class_c', '192.168.0.0', '255.255.0.0', 'Class C private'),
}

COMMON_SERVICES = {
    'http': Service('HTTP', Protocol.TCP, '80', 'Hypertext Transfer Protocol'),
    'https': Service('HTTPS', Protocol.TCP, '443', 'HTTP Secure'),
    'ssh': Service('SSH', Protocol.TCP, '22', 'Secure Shell'),
    'rdp': Service('RDP', Protocol.TCP, '3389', 'Remote Desktop Protocol'),
    'dns': Service('DNS', Protocol.UDP, '53', 'Domain Name System'),
    'smtp': Service('SMTP', Protocol.TCP, '25', 'Simple Mail Transfer Protocol'),
    'smtps': Service('SMTPS', Protocol.TCP, '465', 'SMTP Secure'),
    'ftp': Service('FTP', Protocol.TCP, '21', 'File Transfer Protocol'),
    'sftp': Service('SFTP', Protocol.TCP, '22', 'SSH File Transfer Protocol'),
    'mysql': Service('MySQL', Protocol.TCP, '3306', 'MySQL Database'),
    'postgres': Service('PostgreSQL', Protocol.TCP, '5432', 'PostgreSQL Database'),
    'mssql': Service('MSSQL', Protocol.TCP, '1433', 'Microsoft SQL Server'),
    'icmp': Service('ICMP', Protocol.ICMP, None, 'Internet Control Message Protocol'),
    'any': Service('ANY', Protocol.ANY, None, 'Any protocol/port'),
}
