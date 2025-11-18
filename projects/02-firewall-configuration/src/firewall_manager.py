#!/usr/bin/env python3
"""
Firewall Configuration Manager - Main CLI Tool
Comprehensive firewall management tool for enterprise environments
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from models import (
    Policy, FirewallRule, NetworkObject, Service, Zone,
    Action, Protocol, Direction, COMMON_NETWORKS, COMMON_SERVICES
)
from rule_generator import get_generator
from rule_analyzer import RuleAnalyzer
from report_generator import ReportGenerator


class FirewallManager:
    """Main firewall management class"""

    def __init__(self):
        self.policy: Optional[Policy] = None

    def create_policy(self, name: str, description: str = "") -> Policy:
        """Create a new firewall policy"""
        self.policy = Policy(
            name=name,
            description=description,
            default_action=Action.DENY
        )
        return self.policy

    def load_policy(self, filename: str) -> Policy:
        """Load policy from JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)

        # Reconstruct policy from JSON
        self.policy = self._policy_from_dict(data)
        return self.policy

    def save_policy(self, filename: str) -> None:
        """Save policy to JSON file"""
        if not self.policy:
            raise ValueError("No policy loaded")

        data = self._policy_to_dict(self.policy)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a rule to the current policy"""
        if not self.policy:
            raise ValueError("No policy loaded. Create or load a policy first.")
        self.policy.add_rule(rule)

    def generate_config(self, platform: str, output_file: Optional[str] = None) -> str:
        """Generate firewall configuration for specified platform"""
        if not self.policy:
            raise ValueError("No policy loaded")

        generator = get_generator(platform, self.policy)
        config = generator.generate_all()

        if output_file:
            with open(output_file, 'w') as f:
                f.write(config)
            print(f"Configuration written to {output_file}")

        return config

    def analyze_policy(self) -> None:
        """Analyze current policy for issues"""
        if not self.policy:
            raise ValueError("No policy loaded")

        analyzer = RuleAnalyzer(self.policy)
        result = analyzer.analyze()

        # Print summary
        print(f"\n{'='*70}")
        print(f"  FIREWALL POLICY AUDIT REPORT")
        print(f"{'='*70}\n")
        print(f"Policy: {result.policy_name}")
        print(f"Date: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{'='*70}")
        print(f"  SUMMARY")
        print(f"{'='*70}\n")
        print(f"Total Rules:          {result.total_rules}")
        print(f"Enabled Rules:        {result.enabled_rules}")
        print(f"Conflicts Found:      {len(result.conflicts)}")
        print(f"  - Critical:         {len([c for c in result.conflicts if c.severity.value == 'critical'])}")
        print(f"  - High:             {len([c for c in result.conflicts if c.severity.value == 'high'])}")
        print(f"  - Medium:           {len([c for c in result.conflicts if c.severity.value == 'medium'])}")
        print(f"High-Risk Rules:      {len(result.high_risk_rules)}")
        print(f"Compliance Score:     {result.compliance_score:.1f}%")

        # Print conflicts
        if result.conflicts:
            print(f"\n{'='*70}")
            print(f"  CONFLICTS DETECTED")
            print(f"{'='*70}\n")
            for conflict in result.conflicts:
                print(f"[{conflict.severity.value.upper()}] {conflict.conflict_type.upper()}")
                print(f"  Rule {conflict.rule1.rule_id} ↔ Rule {conflict.rule2.rule_id}")
                print(f"  {conflict.description}")
                print(f"  → {conflict.recommendation}\n")

        # Print recommendations
        if result.recommendations:
            print(f"{'='*70}")
            print(f"  RECOMMENDATIONS")
            print(f"{'='*70}\n")
            for i, rec in enumerate(result.recommendations, 1):
                print(f"{i}. {rec}")

        print(f"\n{'='*70}\n")

    def generate_report(self, format: str = 'html', output_file: Optional[str] = None) -> None:
        """Generate detailed analysis report"""
        if not self.policy:
            raise ValueError("No policy loaded")

        analyzer = RuleAnalyzer(self.policy)
        result = analyzer.analyze()

        report_gen = ReportGenerator(self.policy, result)

        if format == 'html':
            report = report_gen.generate_html()
            default_file = f"{self.policy.name}_report.html"
        elif format == 'json':
            report = report_gen.generate_json()
            default_file = f"{self.policy.name}_report.json"
        else:
            raise ValueError(f"Unsupported format: {format}")

        output_path = output_file or default_file
        with open(output_path, 'w') as f:
            f.write(report)

        print(f"Report generated: {output_path}")

    def _policy_to_dict(self, policy: Policy) -> dict:
        """Convert policy to dictionary"""
        return {
            'name': policy.name,
            'description': policy.description,
            'version': policy.version,
            'default_action': policy.default_action.value,
            'rules': [rule.to_dict() for rule in policy.rules]
        }

    def _policy_from_dict(self, data: dict) -> Policy:
        """Reconstruct policy from dictionary"""
        # This is a simplified version - would need full deserialization in production
        policy = Policy(
            name=data['name'],
            description=data.get('description', ''),
            version=data.get('version', '1.0')
        )
        # Add rules deserialization logic here
        return policy


def create_sample_policy() -> Policy:
    """Create a sample policy for demonstration"""
    policy = Policy(
        name="Enterprise_Firewall_Policy",
        description="Sample enterprise firewall configuration",
        default_action=Action.DENY
    )

    # Add some sample rules
    rules = [
        # Allow web traffic from LAN to Internet
        FirewallRule(
            rule_id=1,
            name="Allow_Web_Traffic",
            action=Action.ALLOW,
            source=NetworkObject("LAN_Users", "10.2.0.0", "255.255.255.0"),
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['https'],
            logging=True,
            description="Allow HTTPS from user network to Internet"
        ),
        # Allow SSH from management network
        FirewallRule(
            rule_id=2,
            name="Allow_SSH_Management",
            action=Action.ALLOW,
            source=NetworkObject("Management", "10.1.0.0", "255.255.255.0"),
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['ssh'],
            logging=True,
            description="Allow SSH from management network"
        ),
        # Block all other traffic
        FirewallRule(
            rule_id=3,
            name="Default_Deny",
            action=Action.DENY,
            source=COMMON_NETWORKS['any'],
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['any'],
            logging=True,
            description="Default deny rule"
        ),
    ]

    for rule in rules:
        policy.add_rule(rule)

    return policy


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Enterprise Firewall Configuration Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Create policy
    create_parser = subparsers.add_parser('create', help='Create new policy')
    create_parser.add_argument('name', help='Policy name')
    create_parser.add_argument('--desc', help='Policy description', default='')

    # Generate config
    gen_parser = subparsers.add_parser('generate', help='Generate firewall config')
    gen_parser.add_argument('platform', choices=['iptables', 'pfsense', 'fortigate', 'cisco-asa'],
                           help='Target platform')
    gen_parser.add_argument('--policy', required=True, help='Policy file (JSON)')
    gen_parser.add_argument('--output', '-o', help='Output file')

    # Analyze policy
    analyze_parser = subparsers.add_parser('analyze', help='Analyze policy for issues')
    analyze_parser.add_argument('policy', help='Policy file (JSON)')

    # Generate report
    report_parser = subparsers.add_parser('report', help='Generate analysis report')
    report_parser.add_argument('policy', help='Policy file (JSON)')
    report_parser.add_argument('--format', choices=['html', 'json'], default='html')
    report_parser.add_argument('--output', '-o', help='Output file')

    # Create sample
    sample_parser = subparsers.add_parser('sample', help='Create sample policy')
    sample_parser.add_argument('--output', '-o', default='sample_policy.json',
                              help='Output file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = FirewallManager()

    try:
        if args.command == 'create':
            policy = manager.create_policy(args.name, args.desc)
            print(f"Created policy: {policy.name}")

        elif args.command == 'generate':
            manager.load_policy(args.policy)
            config = manager.generate_config(args.platform, args.output)
            if not args.output:
                print(config)

        elif args.command == 'analyze':
            manager.load_policy(args.policy)
            manager.analyze_policy()

        elif args.command == 'report':
            manager.load_policy(args.policy)
            manager.generate_report(args.format, args.output)

        elif args.command == 'sample':
            policy = create_sample_policy()
            manager.policy = policy
            manager.save_policy(args.output)
            print(f"Sample policy created: {args.output}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
