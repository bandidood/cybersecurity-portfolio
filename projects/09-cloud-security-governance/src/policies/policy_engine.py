"""
Policy Engine
Evaluates cloud resources against security policies
"""

from typing import List, Dict, Callable
from ..models import PolicyRule, CloudResource, ComplianceFinding, Severity, ComplianceFramework, ResourceType


class PolicyEngine:
    """
    Policy evaluation engine
    Applies security policies to cloud resources
    """

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self.load_default_rules()

    def load_default_rules(self):
        """Load default security policy rules"""
        # CIS AWS Foundation Benchmark rules
        self.add_rule(PolicyRule(
            rule_id="CIS-AWS-2.1.1",
            name="S3 Bucket Encryption",
            description="Ensure S3 buckets have encryption enabled",
            framework=ComplianceFramework.CIS,
            control_id="2.1.1",
            severity=Severity.HIGH,
            resource_types=[ResourceType.S3_BUCKET],
            check_function="check_s3_encryption",
            remediation_steps=[
                "1. Navigate to S3 console",
                "2. Select the bucket",
                "3. Go to Properties tab",
                "4. Enable Default encryption",
                "5. Choose encryption type (SSE-S3 or SSE-KMS)"
            ],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
            ]
        ))

        self.add_rule(PolicyRule(
            rule_id="CIS-AWS-5.2",
            name="No Unrestricted SSH Access",
            description="Ensure security groups do not allow unrestricted SSH access",
            framework=ComplianceFramework.CIS,
            control_id="5.2",
            severity=Severity.CRITICAL,
            resource_types=[ResourceType.SECURITY_GROUP],
            check_function="check_ssh_access",
            remediation_steps=[
                "1. Navigate to EC2 console",
                "2. Select Security Groups",
                "3. Remove inbound rule for port 22 from 0.0.0.0/0",
                "4. Add restrictive rule with specific IP ranges"
            ]
        ))

        self.add_rule(PolicyRule(
            rule_id="CIS-AWS-1.2",
            name="MFA for IAM Users",
            description="Ensure MFA is enabled for all IAM users",
            framework=ComplianceFramework.CIS,
            control_id="1.2",
            severity=Severity.HIGH,
            resource_types=[ResourceType.IAM_USER],
            check_function="check_mfa_enabled",
            remediation_steps=[
                "1. Navigate to IAM console",
                "2. Select Users",
                "3. Click on username",
                "4. Security credentials tab",
                "5. Assign MFA device"
            ]
        ))

        # NIST controls
        self.add_rule(PolicyRule(
            rule_id="NIST-AC-6",
            name="Least Privilege",
            description="Ensure principle of least privilege is applied",
            framework=ComplianceFramework.NIST,
            control_id="AC-6",
            severity=Severity.HIGH,
            resource_types=[ResourceType.IAM_USER, ResourceType.IAM_ROLE],
            check_function="check_least_privilege",
            remediation_steps=[
                "1. Review IAM policies",
                "2. Remove unnecessary permissions",
                "3. Use AWS managed policies when possible",
                "4. Implement role-based access control"
            ]
        ))

    def add_rule(self, rule: PolicyRule):
        """Add a policy rule"""
        self.rules.append(rule)

    def get_rules_for_framework(self, framework: ComplianceFramework) -> List[PolicyRule]:
        """Get all rules for a specific compliance framework"""
        return [r for r in self.rules if r.framework == framework and r.enabled]

    def get_rules_for_resource_type(self, resource_type: ResourceType) -> List[PolicyRule]:
        """Get all rules applicable to a resource type"""
        return [r for r in self.rules if resource_type in r.resource_types and r.enabled]

    def evaluate_resource(self, resource: CloudResource) -> List[Dict]:
        """
        Evaluate a resource against all applicable rules

        Returns:
            List of policy violations
        """
        applicable_rules = self.get_rules_for_resource_type(resource.resource_type)
        violations = []

        for rule in applicable_rules:
            # Check function would be called here
            # For now, we mark as evaluated
            violations.append({
                'rule': rule,
                'resource': resource,
                'evaluated': True
            })

        return violations

    def generate_remediation_plan(self, finding: ComplianceFinding) -> Dict:
        """Generate remediation plan for a finding"""
        # Find matching rule
        matching_rules = [
            r for r in self.rules
            if r.control_id == finding.control_id
        ]

        if not matching_rules:
            return {
                'steps': finding.remediation.split('\n'),
                'automation': 'Manual remediation required'
            }

        rule = matching_rules[0]

        return {
            'steps': rule.remediation_steps,
            'automation': self._generate_automation_script(finding, rule),
            'priority': self._calculate_priority(finding),
            'estimated_effort': self._estimate_effort(finding)
        }

    def _generate_automation_script(self, finding: ComplianceFinding, rule: PolicyRule) -> str:
        """Generate automation script for remediation"""
        # Simplified - in real scenario, this would generate actual scripts
        resource = finding.resource

        if resource.resource_type == ResourceType.S3_BUCKET:
            return f"""
# Enable S3 bucket encryption
aws s3api put-bucket-encryption \\
    --bucket {resource.resource_name} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "AES256"
            }}
        }}]
    }}'
"""
        elif resource.resource_type == ResourceType.SECURITY_GROUP:
            return f"""
# Remove unrestricted SSH access
aws ec2 revoke-security-group-ingress \\
    --group-id {resource.resource_id} \\
    --protocol tcp \\
    --port 22 \\
    --cidr 0.0.0.0/0
"""
        elif resource.resource_type == ResourceType.IAM_USER:
            return f"""
# Enable MFA for IAM user
# Note: This requires manual steps to register MFA device
aws iam enable-mfa-device \\
    --user-name {resource.resource_name} \\
    --serial-number <MFA_DEVICE_ARN> \\
    --authentication-code-1 <CODE1> \\
    --authentication-code-2 <CODE2>
"""

        return "# Manual remediation required"

    def _calculate_priority(self, finding: ComplianceFinding) -> int:
        """Calculate remediation priority (1-5, 1 being highest)"""
        severity_priority = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5
        }
        return severity_priority.get(finding.severity, 3)

    def _estimate_effort(self, finding: ComplianceFinding) -> str:
        """Estimate effort for remediation"""
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            return "15-30 minutes"
        elif finding.severity == Severity.MEDIUM:
            return "30-60 minutes"
        else:
            return "1-2 hours"

    def export_policies(self, output_path: str, format: str = "json"):
        """Export policies to file"""
        import json

        policies_dict = {
            'total_rules': len(self.rules),
            'by_framework': {},
            'by_severity': {},
            'rules': [r.to_dict() for r in self.rules]
        }

        # Count by framework
        for framework in ComplianceFramework:
            count = sum(1 for r in self.rules if r.framework == framework)
            if count > 0:
                policies_dict['by_framework'][framework.value] = count

        # Count by severity
        for severity in Severity:
            count = sum(1 for r in self.rules if r.severity == severity)
            if count > 0:
                policies_dict['by_severity'][severity.value] = count

        with open(output_path, 'w') as f:
            json.dump(policies_dict, f, indent=2)
