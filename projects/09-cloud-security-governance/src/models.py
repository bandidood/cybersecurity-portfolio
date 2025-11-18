"""
Cloud Security Governance - Data Models
Defines core data structures for compliance checks and findings
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
import json


class CloudProvider(Enum):
    """Cloud provider enumeration"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    MULTI_CLOUD = "multi_cloud"


class ComplianceFramework(Enum):
    """Compliance framework enumeration"""
    CIS = "cis"
    NIST = "nist"
    ISO27001 = "iso27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CUSTOM = "custom"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    """Status of a compliance finding"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class ResourceType(Enum):
    """Cloud resource types"""
    # AWS
    EC2_INSTANCE = "ec2_instance"
    S3_BUCKET = "s3_bucket"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    SECURITY_GROUP = "security_group"

    # Azure
    VIRTUAL_MACHINE = "virtual_machine"
    STORAGE_ACCOUNT = "storage_account"
    SQL_DATABASE = "sql_database"
    KEY_VAULT = "key_vault"

    # GCP
    COMPUTE_INSTANCE = "compute_instance"
    STORAGE_BUCKET = "storage_bucket"
    CLOUD_SQL = "cloud_sql"

    # Generic
    NETWORK = "network"
    DATABASE = "database"
    IDENTITY = "identity"
    UNKNOWN = "unknown"


@dataclass
class CloudResource:
    """Cloud resource representation"""
    resource_id: str
    resource_type: ResourceType
    resource_name: str
    provider: CloudProvider
    region: str
    account_id: str
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'resource_id': self.resource_id,
            'resource_type': self.resource_type.value,
            'resource_name': self.resource_name,
            'provider': self.provider.value,
            'region': self.region,
            'account_id': self.account_id,
            'tags': self.tags,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


@dataclass
class ComplianceFinding:
    """Security or compliance finding"""
    finding_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    resource: CloudResource
    framework: ComplianceFramework
    control_id: str
    recommendation: str
    remediation: str
    discovered_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    risk_score: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'resource': self.resource.to_dict(),
            'framework': self.framework.value,
            'control_id': self.control_id,
            'recommendation': self.recommendation,
            'remediation': self.remediation,
            'discovered_at': self.discovered_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'risk_score': self.risk_score,
            'evidence': self.evidence,
            'references': self.references
        }


@dataclass
class PolicyRule:
    """Security policy rule"""
    rule_id: str
    name: str
    description: str
    framework: ComplianceFramework
    control_id: str
    severity: Severity
    resource_types: List[ResourceType]
    check_function: str
    remediation_steps: List[str]
    references: List[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'framework': self.framework.value,
            'control_id': self.control_id,
            'severity': self.severity.value,
            'resource_types': [rt.value for rt in self.resource_types],
            'check_function': self.check_function,
            'remediation_steps': self.remediation_steps,
            'references': self.references,
            'enabled': self.enabled
        }


@dataclass
class ComplianceReport:
    """Compliance assessment report"""
    report_id: str
    provider: CloudProvider
    framework: ComplianceFramework
    account_id: str
    scan_time: datetime = field(default_factory=datetime.now)
    findings: List[ComplianceFinding] = field(default_factory=list)
    total_resources: int = 0
    compliant_resources: int = 0
    non_compliant_resources: int = 0
    compliance_score: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)

    def calculate_metrics(self):
        """Calculate compliance metrics"""
        if not self.findings:
            self.compliance_score = 100.0
            return

        # Count by severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }

        for finding in self.findings:
            if finding.status == FindingStatus.OPEN:
                severity_counts[finding.severity] += 1

        # Calculate weighted score (100 = perfect)
        total_weight = (
            severity_counts[Severity.CRITICAL] * 10 +
            severity_counts[Severity.HIGH] * 5 +
            severity_counts[Severity.MEDIUM] * 2 +
            severity_counts[Severity.LOW] * 1
        )

        max_score = 100
        self.compliance_score = max(0, max_score - total_weight)

        # Update summary
        self.summary = {
            'total_findings': len(self.findings),
            'open_findings': sum(1 for f in self.findings if f.status == FindingStatus.OPEN),
            'by_severity': {s.value: severity_counts[s] for s in Severity},
            'by_status': {},
            'top_risks': []
        }

        # Count by status
        for status in FindingStatus:
            count = sum(1 for f in self.findings if f.status == status)
            self.summary['by_status'][status.value] = count

        # Top risks
        critical_findings = [
            f for f in self.findings
            if f.severity in [Severity.CRITICAL, Severity.HIGH] and f.status == FindingStatus.OPEN
        ]
        critical_findings.sort(key=lambda x: x.risk_score, reverse=True)
        self.summary['top_risks'] = [
            {
                'title': f.title,
                'severity': f.severity.value,
                'resource': f.resource.resource_name,
                'control': f.control_id
            }
            for f in critical_findings[:5]
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'provider': self.provider.value,
            'framework': self.framework.value,
            'account_id': self.account_id,
            'scan_time': self.scan_time.isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'total_resources': self.total_resources,
            'compliant_resources': self.compliant_resources,
            'non_compliant_resources': self.non_compliant_resources,
            'compliance_score': self.compliance_score,
            'summary': self.summary
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, output_path: str):
        """Save report to file"""
        with open(output_path, 'w') as f:
            f.write(self.to_json())


@dataclass
class RemediationPlan:
    """Remediation action plan"""
    plan_id: str
    finding: ComplianceFinding
    priority: int
    estimated_effort: str  # e.g., "15 minutes", "2 hours"
    automation_available: bool
    steps: List[str]
    terraform_code: Optional[str] = None
    cli_commands: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'plan_id': self.plan_id,
            'finding': self.finding.to_dict(),
            'priority': self.priority,
            'estimated_effort': self.estimated_effort,
            'automation_available': self.automation_available,
            'steps': self.steps,
            'terraform_code': self.terraform_code,
            'cli_commands': self.cli_commands,
            'assigned_to': self.assigned_to,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'status': self.status
        }
