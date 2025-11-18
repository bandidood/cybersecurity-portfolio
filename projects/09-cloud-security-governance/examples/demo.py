#!/usr/bin/env python3
"""
Cloud Security Governance - Demonstration Script
Shows complete workflow of cloud security compliance scanning
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanners.aws_scanner import AWSSecurityScanner
from src.policies.policy_engine import PolicyEngine
from src.models import ComplianceReport, CloudProvider, ComplianceFramework


def print_header(title: str):
    """Print formatted section header"""
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80 + "\n")


def demo_aws_scanner():
    """Demonstrate AWS security scanner"""
    print_header("1. AWS Security Scanner")

    print("The AWS scanner checks for common security misconfigurations:")
    print("  • S3 bucket encryption and public access")
    print("  • EC2 instance security (monitoring, EBS encryption, IMDSv2)")
    print("  • Security group rules (SSH, database access)")
    print("  • IAM user security (MFA, key rotation, password age)")

    print("\nRunning AWS scan...")

    scanner = AWSSecurityScanner(account_id="123456789012", region="us-east-1")
    findings = scanner.run_full_scan()

    print(f"\n✓ Scan complete: {len(findings)} findings discovered")

    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print("\nFindings by severity:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity.upper():12} : {count}")

    return findings


def demo_policy_engine():
    """Demonstrate policy engine"""
    print_header("2. Policy Engine")

    print("The policy engine contains security rules from multiple frameworks:")
    print("  • CIS AWS Foundation Benchmark")
    print("  • NIST Cybersecurity Framework")
    print("  • ISO 27001")
    print("  • SOC 2")

    engine = PolicyEngine()

    print(f"\nTotal rules loaded: {len(engine.rules)}")

    # Count by framework
    framework_counts = {}
    for rule in engine.rules:
        fw = rule.framework.value
        framework_counts[fw] = framework_counts.get(fw, 0) + 1

    print("\nRules by framework:")
    for fw, count in framework_counts.items():
        print(f"  {fw.upper():12} : {count}")

    # Show sample rules
    print("\nSample rules:")
    for rule in engine.rules[:3]:
        print(f"\n  {rule.rule_id}: {rule.name}")
        print(f"    Framework: {rule.framework.value.upper()}")
        print(f"    Severity: {rule.severity.value}")
        print(f"    Description: {rule.description}")


def demo_compliance_report(findings):
    """Demonstrate compliance report generation"""
    print_header("3. Compliance Report Generation")

    print("Creating compliance report...")

    report = ComplianceReport(
        report_id="demo_report_001",
        provider=CloudProvider.AWS,
        framework=ComplianceFramework.CIS,
        account_id="123456789012",
        findings=findings,
        total_resources=15
    )

    # Calculate metrics
    report.compliant_resources = report.total_resources - len(findings)
    report.non_compliant_resources = len(findings)
    report.calculate_metrics()

    print(f"\n✓ Report generated successfully")
    print(f"\nCompliance Metrics:")
    print(f"  Compliance Score: {report.compliance_score:.1f}%")
    print(f"  Total Resources: {report.total_resources}")
    print(f"  Compliant: {report.compliant_resources}")
    print(f"  Non-Compliant: {report.non_compliant_resources}")

    print(f"\nTop Risks:")
    for risk in report.summary.get('top_risks', [])[:3]:
        print(f"  • {risk['title']}")
        print(f"    Severity: {risk['severity'].upper()}")
        print(f"    Resource: {risk['resource']}")
        print(f"    Control: {risk['control']}")


def demo_remediation():
    """Demonstrate remediation guidance"""
    print_header("4. Remediation Guidance")

    print("The platform provides actionable remediation steps:")
    print("  • Step-by-step manual remediation instructions")
    print("  • Automated remediation scripts (AWS CLI, Terraform)")
    print("  • Priority and effort estimates")
    print("  • Links to official documentation")

    print("\nExample remediation for 'S3 Bucket Encryption Not Enabled':")
    print("""
  Manual Steps:
    1. Navigate to S3 console
    2. Select the bucket
    3. Go to Properties tab
    4. Enable Default encryption
    5. Choose encryption type (SSE-S3 or SSE-KMS)

  Automated (AWS CLI):
    aws s3api put-bucket-encryption \\
        --bucket company-data-backup \\
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }'

  Priority: P2 - Urgent
  Estimated Effort: 15-30 minutes
    """)


def demo_cli_usage():
    """Demonstrate CLI usage"""
    print_header("5. CLI Tool Usage")

    print("The CLI provides complete governance control:\n")

    commands = [
        ("scan --provider aws --framework cis", "Run compliance scan"),
        ("  --output report.json", "Save scan results"),
        ("", ""),
        ("report scan_results.json", "Generate formatted report"),
        ("  --format html", "HTML format report"),
        ("", ""),
        ("rules --framework cis", "List CIS policy rules"),
        ("  --severity critical", "Filter by severity"),
        ("", ""),
        ("remediate scan_results.json", "Generate remediation plan"),
        ("  --severity critical", "Critical findings only"),
        ("", ""),
        ("export --type policies", "Export all policies"),
        ("  --output policies.json", "To JSON file"),
    ]

    for cmd, desc in commands:
        if cmd:
            print(f"  {cmd:<45} # {desc}")
        else:
            print()

    print("\nExample workflow:")
    print("""
    # 1. Run scan
    $ python src/cli.py scan --provider aws --framework cis --output scan.json

    # 2. Generate report
    $ python src/cli.py report scan.json --format text --output report.txt

    # 3. Create remediation plan
    $ python src/cli.py remediate scan.json --severity critical --output remediate.json

    # 4. List all rules
    $ python src/cli.py rules --framework cis
    """)


def demo_integration():
    """Demonstrate integration scenarios"""
    print_header("6. Integration Scenarios")

    print("Common integration patterns:\n")

    scenarios = [
        ("CI/CD Pipeline", [
            "Run compliance scan before deployment",
            "Block deployment if critical findings exist",
            "Generate compliance report for each release",
            "Track compliance score over time"
        ]),
        ("Security Operations", [
            "Schedule daily compliance scans",
            "Alert on new critical findings",
            "Integrate with SIEM for correlation",
            "Export findings to ticketing system"
        ]),
        ("Governance & Audit", [
            "Generate quarterly compliance reports",
            "Track remediation progress",
            "Demonstrate compliance to auditors",
            "Maintain audit trail of changes"
        ]),
        ("DevSecOps", [
            "Policy-as-code in version control",
            "Automated remediation via Infrastructure-as-Code",
            "Shift-left security into development",
            "Continuous compliance monitoring"
        ])
    ]

    for scenario, steps in scenarios:
        print(f"{scenario}:")
        for step in steps:
            print(f"  • {step}")
        print()


def main():
    """Run complete demonstration"""
    print("\n" + "="*80)
    print(" CLOUD SECURITY GOVERNANCE - COMPREHENSIVE DEMONSTRATION")
    print("="*80)

    # Run demonstrations
    findings = demo_aws_scanner()
    demo_policy_engine()
    demo_compliance_report(findings)
    demo_remediation()
    demo_cli_usage()
    demo_integration()

    # Final summary
    print_header("Demonstration Complete")
    print("This demonstration showcased:")
    print("  ✓ AWS security scanner with multiple checks")
    print("  ✓ Policy engine with compliance frameworks")
    print("  ✓ Compliance report generation and scoring")
    print("  ✓ Remediation guidance and automation")
    print("  ✓ CLI tool for security operations")
    print("  ✓ Integration scenarios and best practices")

    print("\nTo get started:")
    print("  1. Install dependencies: pip install -r requirements.txt")
    print("  2. Run a scan: python src/cli.py scan --provider aws --framework cis")
    print("  3. Review findings and compliance score")
    print("  4. Generate remediation plan")
    print("  5. Integrate into your workflow")

    print("\nFor production deployment:")
    print("  • Configure real cloud provider credentials")
    print("  • Customize policy rules for your requirements")
    print("  • Set up automated scanning schedules")
    print("  • Integrate with CI/CD and SIEM")
    print("  • Track compliance metrics over time")

    print("\n" + "="*80)


if __name__ == "__main__":
    main()
