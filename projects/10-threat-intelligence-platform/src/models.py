#!/usr/bin/env python3
"""
Threat Intelligence Platform - Data Models
Core data models for IOCs, threat feeds, and intelligence objects
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import hashlib


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    SSL_CERT = "ssl_cert"


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(Enum):
    """Confidence levels for intelligence"""
    CONFIRMED = "confirmed"  # 90-100%
    HIGH = "high"           # 70-89%
    MEDIUM = "medium"       # 50-69%
    LOW = "low"             # 30-49%
    UNCONFIRMED = "unconfirmed"  # <30%


class FeedStatus(Enum):
    """Status of threat feeds"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    description: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Threat actor attribution
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)

    # Metadata
    false_positive: bool = False
    whitelisted: bool = False
    expired: bool = False
    expiry_date: Optional[datetime] = None

    def __post_init__(self):
        """Generate unique ID for IOC"""
        self.ioc_id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate unique identifier for IOC"""
        hash_input = f"{self.ioc_type.value}:{self.value}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]

    def is_valid(self) -> bool:
        """Check if IOC is still valid"""
        if self.whitelisted or self.false_positive or self.expired:
            return False
        if self.expiry_date and datetime.now() > self.expiry_date:
            self.expired = True
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert IOC to dictionary"""
        return {
            'ioc_id': self.ioc_id,
            'ioc_type': self.ioc_type.value,
            'value': self.value,
            'threat_level': self.threat_level.value,
            'confidence': self.confidence.value,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags,
            'sources': self.sources,
            'description': self.description,
            'context': self.context,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'threat_actors': self.threat_actors,
            'campaigns': self.campaigns,
            'valid': self.is_valid()
        }


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration"""
    feed_id: str
    name: str
    feed_type: str  # misp, otx, virustotal, custom, etc.
    url: str
    status: FeedStatus = FeedStatus.ACTIVE
    api_key: Optional[str] = None
    update_interval: int = 3600  # seconds
    last_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    total_iocs: int = 0
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    # Quality metrics
    reliability_score: float = 0.5  # 0-1
    false_positive_rate: float = 0.0
    avg_confidence: float = 0.5

    # Statistics
    iocs_collected: int = 0
    errors_count: int = 0
    last_error: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def needs_update(self) -> bool:
        """Check if feed needs updating"""
        if not self.enabled or self.status != FeedStatus.ACTIVE:
            return False
        if not self.next_update:
            return True
        return datetime.now() >= self.next_update

    def to_dict(self) -> Dict[str, Any]:
        """Convert feed to dictionary"""
        return {
            'feed_id': self.feed_id,
            'name': self.name,
            'feed_type': self.feed_type,
            'url': self.url,
            'status': self.status.value,
            'enabled': self.enabled,
            'update_interval': self.update_interval,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'total_iocs': self.total_iocs,
            'reliability_score': self.reliability_score,
            'false_positive_rate': self.false_positive_rate,
            'tags': self.tags
        }


@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    motivation: Optional[str] = None  # financial, espionage, hacktivism, etc.
    sophistication: str = "unknown"  # beginner, intermediate, advanced, expert

    # Attribution
    country: Optional[str] = None
    groups: List[str] = field(default_factory=list)

    # TTP mapping
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)

    # Associated data
    campaigns: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)

    first_seen: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)

    description: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert threat actor to dictionary"""
        return {
            'actor_id': self.actor_id,
            'name': self.name,
            'aliases': self.aliases,
            'motivation': self.motivation,
            'sophistication': self.sophistication,
            'country': self.country,
            'tactics': self.tactics,
            'techniques': self.techniques,
            'tools': self.tools,
            'campaigns': self.campaigns,
            'first_seen': self.first_seen.isoformat(),
            'last_activity': self.last_activity.isoformat()
        }


@dataclass
class Campaign:
    """Threat campaign"""
    campaign_id: str
    name: str
    description: Optional[str] = None

    # Attribution
    threat_actors: List[str] = field(default_factory=list)

    # Timeline
    start_date: datetime = field(default_factory=datetime.now)
    end_date: Optional[datetime] = None
    active: bool = True

    # Targets
    target_sectors: List[str] = field(default_factory=list)
    target_countries: List[str] = field(default_factory=list)

    # TTPs
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)

    # IOCs
    iocs: List[str] = field(default_factory=list)

    # Metadata
    confidence: Confidence = Confidence.MEDIUM
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert campaign to dictionary"""
        return {
            'campaign_id': self.campaign_id,
            'name': self.name,
            'description': self.description,
            'threat_actors': self.threat_actors,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'active': self.active,
            'target_sectors': self.target_sectors,
            'target_countries': self.target_countries,
            'confidence': self.confidence.value,
            'tags': self.tags
        }


@dataclass
class ThreatReport:
    """Threat intelligence report"""
    report_id: str
    title: str
    summary: str
    report_type: str  # tactical, operational, strategic

    # Content
    content: str
    iocs: List[IOC] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)

    # Classification
    severity: ThreatLevel = ThreatLevel.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    tlp: str = "WHITE"  # Traffic Light Protocol: RED, AMBER, GREEN, WHITE

    # Metadata
    created_date: datetime = field(default_factory=datetime.now)
    published_date: Optional[datetime] = None
    author: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary"""
        return {
            'report_id': self.report_id,
            'title': self.title,
            'summary': self.summary,
            'report_type': self.report_type,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'tlp': self.tlp,
            'created_date': self.created_date.isoformat(),
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'tags': self.tags,
            'ioc_count': len(self.iocs)
        }


# Common threat actor groups
KNOWN_THREAT_ACTORS = {
    'apt28': ThreatActor('apt28', 'APT28', ['Fancy Bear', 'Sofacy'], 'espionage', 'expert', 'RU'),
    'apt29': ThreatActor('apt29', 'APT29', ['Cozy Bear'], 'espionage', 'expert', 'RU'),
    'lazarus': ThreatActor('lazarus', 'Lazarus Group', ['Hidden Cobra'], 'financial', 'expert', 'KP'),
    'apt41': ThreatActor('apt41', 'APT41', ['Winnti'], 'espionage', 'expert', 'CN'),
}

# Common MITRE ATT&CK tactics
MITRE_TACTICS = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
]
