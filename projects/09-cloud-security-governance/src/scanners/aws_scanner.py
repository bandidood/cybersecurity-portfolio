"""
AWS Security Scanner
Scans AWS resources for compliance violations
"""

import hashlib
from datetime import datetime
from typing import List, Dict, Optional
import uuid

from ..models import (
    CloudResource, ComplianceFinding, CloudProvider,
    ResourceType, Severity, FindingStatus, ComplianceFramework
)


class AWSSecurityScanner:
    """
    AWS security and compliance scanner
    Simulates AWS API calls for demonstration purposes
    """

    def __init__(self, account_id: str = "123456789012", region: str = "us-east-1"):
        """
        Initialize AWS scanner

        Args:
            account_id: AWS account ID
            region: AWS region
        """
        self.account_id = account_id
        self.region = region
        self.provider = CloudProvider.AWS

    def scan_s3_buckets(self) -> List[ComplianceFinding]:
        """Scan S3 buckets for security misconfigurations"""
        findings = []

        # Simulate S3 bucket discovery
        sample_buckets = [
            {
                'name': 'company-data-backup',
                'encryption': False,
                'public_access': False,
                'versioning': True,
                'logging': True
            },
            {
                'name': 'public-website-assets',
                'encryption': False,
                'public_access': True,
                'versioning': False,
                'logging': False
            },
            {
                'name': 'sensitive-documents',
                'encryption': True,
                'public_access': False,
                'versioning': True,
                'logging': True
            }
        ]

        for bucket in sample_buckets:
            resource = CloudResource(
                resource_id=f"arn:aws:s3:::{bucket['name']}",
                resource_type=ResourceType.S3_BUCKET,
                resource_name=bucket['name'],
                provider=self.provider,
                region="us-east-1",  # S3 is global
                account_id=self.account_id,
                tags={'Environment': 'Production'},
                metadata=bucket
            )

            # Check encryption
            if not bucket['encryption']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="S3 Bucket Encryption Not Enabled",
                    description=f"S3 bucket '{bucket['name']}' does not have default encryption enabled",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-2.1.1",
                    recommendation="Enable default encryption for S3 bucket",
                    remediation="aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration '{...}'",
                    risk_score=75.0,
                    evidence={'encryption_enabled': False},
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
                    ]
                )
                findings.append(finding)

            # Check public access
            if bucket['public_access']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="S3 Bucket Publicly Accessible",
                    description=f"S3 bucket '{bucket['name']}' allows public access",
                    severity=Severity.CRITICAL,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-2.1.5",
                    recommendation="Block all public access to S3 bucket unless specifically required",
                    remediation="aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    risk_score=95.0,
                    evidence={'public_access_enabled': True},
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                    ]
                )
                findings.append(finding)

            # Check versioning
            if not bucket['versioning']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="S3 Bucket Versioning Not Enabled",
                    description=f"S3 bucket '{bucket['name']}' does not have versioning enabled",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-2.1.3",
                    recommendation="Enable versioning to protect against accidental deletion",
                    remediation="aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled",
                    risk_score=50.0,
                    evidence={'versioning_enabled': False}
                )
                findings.append(finding)

            # Check logging
            if not bucket['logging']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="S3 Bucket Access Logging Not Enabled",
                    description=f"S3 bucket '{bucket['name']}' does not have access logging enabled",
                    severity=Severity.LOW,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-3.8",
                    recommendation="Enable S3 bucket access logging for audit trail",
                    remediation="aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status '{...}'",
                    risk_score=30.0,
                    evidence={'logging_enabled': False}
                )
                findings.append(finding)

        return findings

    def scan_ec2_instances(self) -> List[ComplianceFinding]:
        """Scan EC2 instances for security issues"""
        findings = []

        # Simulate EC2 instance discovery
        sample_instances = [
            {
                'instance_id': 'i-0123456789abcdef0',
                'name': 'web-server-01',
                'public_ip': '54.123.45.67',
                'monitoring': True,
                'ebs_encrypted': True,
                'imdsv2': True
            },
            {
                'instance_id': 'i-abcdef0123456789a',
                'name': 'app-server-01',
                'public_ip': None,
                'monitoring': False,
                'ebs_encrypted': False,
                'imdsv2': False
            }
        ]

        for instance in sample_instances:
            resource = CloudResource(
                resource_id=instance['instance_id'],
                resource_type=ResourceType.EC2_INSTANCE,
                resource_name=instance['name'],
                provider=self.provider,
                region=self.region,
                account_id=self.account_id,
                tags={'Environment': 'Production'},
                metadata=instance
            )

            # Check CloudWatch detailed monitoring
            if not instance['monitoring']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="EC2 Detailed Monitoring Not Enabled",
                    description=f"EC2 instance '{instance['name']}' does not have detailed monitoring enabled",
                    severity=Severity.LOW,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-4.15",
                    recommendation="Enable detailed monitoring for better visibility",
                    remediation=f"aws ec2 monitor-instances --instance-ids {instance['instance_id']}",
                    risk_score=25.0,
                    evidence={'detailed_monitoring': False}
                )
                findings.append(finding)

            # Check EBS encryption
            if not instance['ebs_encrypted']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="EBS Volume Not Encrypted",
                    description=f"EC2 instance '{instance['name']}' has unencrypted EBS volumes",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-2.2.1",
                    recommendation="Enable EBS encryption for data at rest",
                    remediation="Create encrypted snapshot and launch new instance from encrypted volume",
                    risk_score=70.0,
                    evidence={'ebs_encrypted': False}
                )
                findings.append(finding)

            # Check IMDSv2
            if not instance['imdsv2']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="IMDSv2 Not Enforced",
                    description=f"EC2 instance '{instance['name']}' does not require IMDSv2",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-5.6",
                    recommendation="Require IMDSv2 to prevent SSRF attacks",
                    remediation=f"aws ec2 modify-instance-metadata-options --instance-id {instance['instance_id']} --http-tokens required",
                    risk_score=55.0,
                    evidence={'imdsv2_required': False}
                )
                findings.append(finding)

        return findings

    def scan_security_groups(self) -> List[ComplianceFinding]:
        """Scan security groups for overly permissive rules"""
        findings = []

        # Simulate security group discovery
        sample_sgs = [
            {
                'group_id': 'sg-0123456789abcdef0',
                'name': 'web-server-sg',
                'rules': [
                    {'protocol': 'tcp', 'port': 80, 'source': '0.0.0.0/0'},
                    {'protocol': 'tcp', 'port': 443, 'source': '0.0.0.0/0'},
                    {'protocol': 'tcp', 'port': 22, 'source': '0.0.0.0/0'}  # Risky!
                ]
            },
            {
                'group_id': 'sg-abcdef0123456789a',
                'name': 'database-sg',
                'rules': [
                    {'protocol': 'tcp', 'port': 3306, 'source': '10.0.0.0/8'}
                ]
            }
        ]

        for sg in sample_sgs:
            resource = CloudResource(
                resource_id=sg['group_id'],
                resource_type=ResourceType.SECURITY_GROUP,
                resource_name=sg['name'],
                provider=self.provider,
                region=self.region,
                account_id=self.account_id,
                metadata=sg
            )

            # Check for unrestricted SSH access
            ssh_rules = [r for r in sg['rules'] if r['port'] == 22 and r['source'] == '0.0.0.0/0']
            if ssh_rules:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="Security Group Allows Unrestricted SSH Access",
                    description=f"Security group '{sg['name']}' allows SSH access from anywhere (0.0.0.0/0)",
                    severity=Severity.CRITICAL,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-5.2",
                    recommendation="Restrict SSH access to specific IP ranges or use bastion host",
                    remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg['group_id']} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                    risk_score=90.0,
                    evidence={'unrestricted_ssh': True, 'rules': ssh_rules}
                )
                findings.append(finding)

            # Check for unrestricted database access
            db_ports = [3306, 5432, 1433, 27017]
            for rule in sg['rules']:
                if rule['port'] in db_ports and rule['source'] == '0.0.0.0/0':
                    finding = ComplianceFinding(
                        finding_id=str(uuid.uuid4())[:8],
                        title="Security Group Allows Unrestricted Database Access",
                        description=f"Security group '{sg['name']}' allows database access from anywhere",
                        severity=Severity.CRITICAL,
                        status=FindingStatus.OPEN,
                        resource=resource,
                        framework=ComplianceFramework.CIS,
                        control_id="CIS-5.3",
                        recommendation="Restrict database access to application security groups only",
                        remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg['group_id']} --protocol tcp --port {rule['port']} --cidr 0.0.0.0/0",
                        risk_score=95.0,
                        evidence={'unrestricted_database': True, 'port': rule['port']}
                    )
                    findings.append(finding)

        return findings

    def scan_iam(self) -> List[ComplianceFinding]:
        """Scan IAM for security issues"""
        findings = []

        # Simulate IAM user discovery
        sample_users = [
            {
                'username': 'admin',
                'mfa_enabled': False,
                'access_keys': [{'age_days': 180, 'last_used': 90}],
                'password_age': 400
            },
            {
                'username': 'developer',
                'mfa_enabled': True,
                'access_keys': [{'age_days': 45, 'last_used': 2}],
                'password_age': 60
            }
        ]

        for user in sample_users:
            resource = CloudResource(
                resource_id=f"arn:aws:iam::{self.account_id}:user/{user['username']}",
                resource_type=ResourceType.IAM_USER,
                resource_name=user['username'],
                provider=self.provider,
                region="global",
                account_id=self.account_id,
                metadata=user
            )

            # Check MFA
            if not user['mfa_enabled']:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="MFA Not Enabled for IAM User",
                    description=f"IAM user '{user['username']}' does not have MFA enabled",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-1.2",
                    recommendation="Enable MFA for all IAM users, especially privileged users",
                    remediation=f"aws iam enable-mfa-device --user-name {user['username']} --serial-number arn:aws:iam::...:mfa/... --authentication-code-1 ... --authentication-code-2 ...",
                    risk_score=80.0,
                    evidence={'mfa_enabled': False}
                )
                findings.append(finding)

            # Check access key age
            for key in user['access_keys']:
                if key['age_days'] > 90:
                    finding = ComplianceFinding(
                        finding_id=str(uuid.uuid4())[:8],
                        title="IAM Access Key Older Than 90 Days",
                        description=f"IAM user '{user['username']}' has access key older than 90 days",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                        resource=resource,
                        framework=ComplianceFramework.CIS,
                        control_id="CIS-1.14",
                        recommendation="Rotate access keys regularly (at least every 90 days)",
                        remediation=f"aws iam create-access-key --user-name {user['username']} && aws iam delete-access-key --user-name {user['username']} --access-key-id OLD_KEY",
                        risk_score=60.0,
                        evidence={'key_age_days': key['age_days']}
                    )
                    findings.append(finding)

            # Check password age
            if user['password_age'] > 90:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    title="IAM User Password Older Than 90 Days",
                    description=f"IAM user '{user['username']}' password is older than 90 days",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.OPEN,
                    resource=resource,
                    framework=ComplianceFramework.CIS,
                    control_id="CIS-1.11",
                    recommendation="Enforce password rotation policy",
                    remediation="Update account password policy to require password rotation every 90 days",
                    risk_score=50.0,
                    evidence={'password_age_days': user['password_age']}
                )
                findings.append(finding)

        return findings

    def run_full_scan(self) -> List[ComplianceFinding]:
        """Run comprehensive security scan across all resource types"""
        all_findings = []

        # Run all scans
        all_findings.extend(self.scan_s3_buckets())
        all_findings.extend(self.scan_ec2_instances())
        all_findings.extend(self.scan_security_groups())
        all_findings.extend(self.scan_iam())

        return all_findings
