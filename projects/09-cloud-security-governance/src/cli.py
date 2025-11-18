#!/usr/bin/env python3
"""
Cloud Security Governance - Command Line Interface
Main CLI for cloud security compliance scanning
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import ComplianceReport, CloudProvider, ComplianceFramework, FindingStatus, Severity
from src.scanners.aws_scanner import AWSSecurityScanner
from src.policies.policy_engine import PolicyEngine


class CloudGovernanceCLI:
    """Command-line interface for cloud security governance"""

    def __init__(self):
        self.policy_engine = PolicyEngine()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="Cloud Security Governance CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan cloud environment')
        scan_parser.add_argument('--provider', choices=['aws', 'azure', 'gcp'],
                                 required=True, help='Cloud provider')
        scan_parser.add_argument('--framework', choices=['cis', 'nist', 'iso27001', 'soc2'],
                                 default='cis', help='Compliance framework')
        scan_parser.add_argument('--account-id', help='Cloud account ID')
        scan_parser.add_argument('--region', default='us-east-1', help='Cloud region')
        scan_parser.add_argument('--output', '-o', help='Output report path')
        scan_parser.add_argument('--format', choices=['json', 'text', 'html'],
                                 default='text', help='Report format')

        # Report command
        report_parser = subparsers.add_parser('report', help='Generate report from scan')
        report_parser.add_argument('scan_file', help='Scan results file (JSON)')
        report_parser.add_argument('--format', choices=['text', 'html', 'pdf'],
                                   default='text', help='Report format')
        report_parser.add_argument('--output', '-o', help='Output report path')

        # List rules command
        rules_parser = subparsers.add_parser('rules', help='List policy rules')
        rules_parser.add_argument('--framework', choices=['cis', 'nist', 'iso27001'],
                                  help='Filter by framework')
        rules_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                                  help='Filter by severity')

        # Remediate command
        remediate_parser = subparsers.add_parser('remediate', help='Generate remediation plan')
        remediate_parser.add_argument('scan_file', help='Scan results file (JSON)')
        remediate_parser.add_argument('--finding-id', help='Specific finding ID to remediate')
        remediate_parser.add_argument('--severity', choices=['critical', 'high'],
                                      help='Remediate findings by severity')
        remediate_parser.add_argument('--output', '-o', help='Output remediation plan path')

        # Export command
        export_parser = subparsers.add_parser('export', help='Export policies or findings')
        export_parser.add_argument('--type', choices=['policies', 'findings'],
                                   required=True, help='What to export')
        export_parser.add_argument('--output', '-o', required=True, help='Output file path')

        return parser

    def run(self, args=None):
        """Run CLI with arguments"""
        args = self.parser.parse_args(args)

        if not args.command:
            self.parser.print_help()
            return

        # Execute command
        command_method = getattr(self, f'cmd_{args.command}', None)
        if command_method:
            command_method(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)

    def cmd_scan(self, args):
        """Scan cloud environment"""
        print(f"Scanning {args.provider.upper()} environment...")
        print(f"Framework: {args.framework.upper()}")
        print("-" * 80)

        # Initialize scanner based on provider
        if args.provider == 'aws':
            account_id = args.account_id or "123456789012"
            scanner = AWSSecurityScanner(account_id=account_id, region=args.region)
            provider = CloudProvider.AWS
        elif args.provider == 'azure':
            print("Azure scanner not yet implemented (demo mode)")
            return
        elif args.provider == 'gcp':
            print("GCP scanner not yet implemented (demo mode)")
            return

        # Run scan
        try:
            findings = scanner.run_full_scan()

            print(f"\nScan complete: {len(findings)} findings discovered\n")

            # Create report
            framework = ComplianceFramework(args.framework)
            report = ComplianceReport(
                report_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                provider=provider,
                framework=framework,
                account_id=account_id,
                findings=findings,
                total_resources=self._count_unique_resources(findings)
            )

            # Calculate metrics
            report.compliant_resources = report.total_resources - len(findings)
            report.non_compliant_resources = len(findings)
            report.calculate_metrics()

            # Print summary
            self._print_scan_summary(report)

            # Save report if output specified
            if args.output:
                report.save(args.output)
                print(f"\n✓ Report saved to: {args.output}")
            else:
                # Print detailed findings
                self._print_findings(findings)

        except Exception as e:
            print(f"Error during scan: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    def cmd_report(self, args):
        """Generate report from scan results"""
        import json

        print(f"Loading scan results from: {args.scan_file}")

        try:
            with open(args.scan_file, 'r') as f:
                report_data = json.load(f)

            # Recreate report object (simplified)
            print("\nGenerating report...")
            print(f"Provider: {report_data.get('provider', 'unknown').upper()}")
            print(f"Framework: {report_data.get('framework', 'unknown').upper()}")
            print(f"Compliance Score: {report_data.get('compliance_score', 0):.1f}%")
            print(f"Total Findings: {len(report_data.get('findings', []))}")

            if args.output:
                # Save formatted report
                with open(args.output, 'w') as f:
                    f.write(self._format_report_text(report_data))
                print(f"\n✓ Report saved to: {args.output}")

        except FileNotFoundError:
            print(f"Error: Scan file not found: {args.scan_file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error generating report: {e}")
            sys.exit(1)

    def cmd_rules(self, args):
        """List policy rules"""
        rules = self.policy_engine.rules

        # Apply filters
        if args.framework:
            framework = ComplianceFramework(args.framework)
            rules = [r for r in rules if r.framework == framework]

        if args.severity:
            severity = Severity(args.severity)
            rules = [r for r in rules if r.severity == severity]

        print(f"\nPolicy Rules ({len(rules)} found):\n")
        print(f"{'Rule ID':<20} {'Name':<40} {'Framework':<10} {'Severity'}")
        print("-" * 100)

        for rule in rules:
            print(f"{rule.rule_id:<20} {rule.name:<40} {rule.framework.value:<10} {rule.severity.value}")

    def cmd_remediate(self, args):
        """Generate remediation plan"""
        import json

        print(f"Loading scan results from: {args.scan_file}")

        try:
            with open(args.scan_file, 'r') as f:
                report_data = json.load(f)

            findings = report_data.get('findings', [])

            # Filter findings
            if args.finding_id:
                findings = [f for f in findings if f['finding_id'] == args.finding_id]
            elif args.severity:
                findings = [f for f in findings if f['severity'] == args.severity]

            if not findings:
                print("No findings match the specified criteria.")
                return

            print(f"\nGenerating remediation plan for {len(findings)} findings...\n")

            remediation_plan = []
            for finding_data in findings:
                plan = {
                    'finding_id': finding_data['finding_id'],
                    'title': finding_data['title'],
                    'severity': finding_data['severity'],
                    'remediation': finding_data['remediation'],
                    'priority': self._get_priority(finding_data['severity'])
                }
                remediation_plan.append(plan)

            # Print remediation plan
            for i, plan in enumerate(remediation_plan, 1):
                print(f"{i}. {plan['title']}")
                print(f"   Priority: {plan['priority']}")
                print(f"   Severity: {plan['severity'].upper()}")
                print(f"   Remediation: {plan['remediation']}")
                print()

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(remediation_plan, f, indent=2)
                print(f"✓ Remediation plan saved to: {args.output}")

        except FileNotFoundError:
            print(f"Error: Scan file not found: {args.scan_file}")
            sys.exit(1)

    def cmd_export(self, args):
        """Export policies or findings"""
        if args.type == 'policies':
            self.policy_engine.export_policies(args.output)
            print(f"✓ Policies exported to: {args.output}")
        elif args.type == 'findings':
            print("Findings export requires a scan file (use 'scan' command first)")

    def _count_unique_resources(self, findings) -> int:
        """Count unique resources from findings"""
        unique_resources = set()
        for finding in findings:
            unique_resources.add(finding.resource.resource_id)
        return len(unique_resources)

    def _print_scan_summary(self, report: ComplianceReport):
        """Print scan summary"""
        print("\nScan Summary:")
        print("=" * 80)
        print(f"Compliance Score: {report.compliance_score:.1f}%")
        print(f"Total Resources Scanned: {report.total_resources}")
        print(f"Compliant Resources: {report.compliant_resources}")
        print(f"Non-Compliant Resources: {report.non_compliant_resources}")
        print()

        print("Findings by Severity:")
        for severity, count in report.summary['by_severity'].items():
            if count > 0:
                print(f"  {severity.upper():12} : {count}")
        print()

        print("Findings by Status:")
        for status, count in report.summary['by_status'].items():
            if count > 0:
                print(f"  {status:12} : {count}")

    def _print_findings(self, findings):
        """Print detailed findings"""
        print("\n" + "=" * 80)
        print("Detailed Findings:")
        print("=" * 80 + "\n")

        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Print in order of severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                print(f"\n{severity.upper()} Severity Findings ({len(by_severity[severity])}):")
                print("-" * 80)

                for finding in by_severity[severity][:5]:  # Limit to 5 per severity
                    print(f"\n{finding.title}")
                    print(f"  Resource: {finding.resource.resource_name} ({finding.resource.resource_type.value})")
                    print(f"  Control: {finding.control_id}")
                    print(f"  Description: {finding.description}")
                    print(f"  Recommendation: {finding.recommendation}")

                if len(by_severity[severity]) > 5:
                    print(f"\n  ... and {len(by_severity[severity]) - 5} more {severity} findings")

    def _format_report_text(self, report_data: dict) -> str:
        """Format report as text"""
        lines = []
        lines.append("="*80)
        lines.append(" CLOUD SECURITY COMPLIANCE REPORT")
        lines.append("="*80)
        lines.append("")
        lines.append(f"Provider: {report_data.get('provider', 'unknown').upper()}")
        lines.append(f"Framework: {report_data.get('framework', 'unknown').upper()}")
        lines.append(f"Account ID: {report_data.get('account_id', 'unknown')}")
        lines.append(f"Scan Time: {report_data.get('scan_time', 'unknown')}")
        lines.append(f"Compliance Score: {report_data.get('compliance_score', 0):.1f}%")
        lines.append("")

        summary = report_data.get('summary', {})
        lines.append("Summary:")
        lines.append(f"  Total Findings: {summary.get('total_findings', 0)}")
        lines.append(f"  Open Findings: {summary.get('open_findings', 0)}")
        lines.append("")

        return "\n".join(lines)

    def _get_priority(self, severity: str) -> str:
        """Get priority from severity"""
        priority_map = {
            'critical': 'P1 - Immediate',
            'high': 'P2 - Urgent',
            'medium': 'P3 - Medium',
            'low': 'P4 - Low'
        }
        return priority_map.get(severity, 'P3 - Medium')


def main():
    """Main entry point"""
    cli = CloudGovernanceCLI()
    cli.run()


if __name__ == '__main__':
    main()
