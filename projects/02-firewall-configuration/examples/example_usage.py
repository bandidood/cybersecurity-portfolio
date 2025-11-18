#!/usr/bin/env python3
"""
Example Usage of Firewall Configuration Framework
Demonstrates how to use the framework to create, analyze, and generate firewall configs
"""

import sys
sys.path.insert(0, '../src')

from models import (
    Policy, FirewallRule, NetworkObject, Service, Zone,
    Action, Protocol, Direction, COMMON_NETWORKS, COMMON_SERVICES
)
from rule_generator import get_generator
from rule_analyzer import RuleAnalyzer
from report_generator import ReportGenerator


def create_enterprise_policy() -> Policy:
    """Create a comprehensive enterprise firewall policy"""
    policy = Policy(
        name="Enterprise_Security_Policy_2025",
        description="Multi-zone enterprise firewall configuration with defense-in-depth",
        default_action=Action.DENY,
        version="2.0"
    )

    # Define network zones
    policy.zones = [
        Zone("DMZ", "eth0", security_level=30),
        Zone("LAN_Users", "eth1", security_level=50),
        Zone("LAN_Servers", "eth2", security_level=70),
        Zone("Management", "eth3", security_level=90),
    ]

    # Define custom network objects
    dmz_web = NetworkObject("DMZ_Web", "172.16.10.10", "255.255.255.255", "Public web server")
    lan_users = NetworkObject("LAN_Users", "10.2.0.0", "255.255.255.0", "User workstations")
    lan_servers = NetworkObject("LAN_Servers", "10.3.0.0", "255.255.255.0", "Internal servers")
    management = NetworkObject("Management", "10.1.0.0", "255.255.255.0", "Management network")
    database_server = NetworkObject("DB_Server", "10.3.0.50", "255.255.255.255", "Database server")

    # Define custom services
    web_custom = Service("Custom_Web", Protocol.TCP, "8080", "Custom web application")
    db_service = Service("MySQL", Protocol.TCP, "3306", "MySQL database")

    # Create firewall rules
    rules = [
        # 1. Allow HTTPS from Internet to DMZ web server
        FirewallRule(
            rule_id=1,
            name="Allow_Internet_to_DMZ_Web",
            action=Action.ALLOW,
            source=COMMON_NETWORKS['any'],
            destination=dmz_web,
            service=COMMON_SERVICES['https'],
            direction=Direction.INBOUND,
            logging=True,
            description="Public web server access",
            tags=["dmz", "public", "web"]
        ),

        # 2. Allow users to access internal web applications
        FirewallRule(
            rule_id=2,
            name="Users_to_Internal_Apps",
            action=Action.ALLOW,
            source=lan_users,
            destination=lan_servers,
            service=web_custom,
            logging=True,
            description="User access to internal applications",
            tags=["internal", "web"]
        ),

        # 3. Allow application servers to database
        FirewallRule(
            rule_id=3,
            name="AppServer_to_Database",
            action=Action.ALLOW,
            source=lan_servers,
            destination=database_server,
            service=db_service,
            logging=True,
            description="Application database access",
            tags=["database", "backend"]
        ),

        # 4. Allow management SSH access
        FirewallRule(
            rule_id=4,
            name="Management_SSH",
            action=Action.ALLOW,
            source=management,
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['ssh'],
            logging=True,
            description="Management SSH access to all systems",
            tags=["management", "ssh"]
        ),

        # 5. Allow users HTTP/HTTPS to Internet
        FirewallRule(
            rule_id=5,
            name="Users_Web_Browsing",
            action=Action.ALLOW,
            source=lan_users,
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['https'],
            direction=Direction.OUTBOUND,
            logging=False,
            description="User web browsing",
            tags=["internet", "users"]
        ),

        # 6. DENY direct database access from user network (security)
        FirewallRule(
            rule_id=6,
            name="Block_Users_to_Database",
            action=Action.DENY,
            source=lan_users,
            destination=database_server,
            service=db_service,
            logging=True,
            description="Prevent direct user access to database",
            tags=["security", "database"]
        ),

        # 7. Allow DNS from all internal networks
        FirewallRule(
            rule_id=7,
            name="Allow_DNS",
            action=Action.ALLOW,
            source=COMMON_NETWORKS['private_class_a'],
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['dns'],
            logging=False,
            description="DNS resolution",
            tags=["dns", "essential"]
        ),

        # 8. Default deny with logging
        FirewallRule(
            rule_id=8,
            name="Default_Deny_All",
            action=Action.DENY,
            source=COMMON_NETWORKS['any'],
            destination=COMMON_NETWORKS['any'],
            service=COMMON_SERVICES['any'],
            logging=True,
            description="Default deny rule - catches all unmatched traffic",
            tags=["default", "security"]
        ),
    ]

    for rule in rules:
        policy.add_rule(rule)

    return policy


def main():
    """Main example execution"""
    print("="*70)
    print(" ENTERPRISE FIREWALL CONFIGURATION FRAMEWORK - Example")
    print("="*70)
    print()

    # 1. Create policy
    print("[1] Creating enterprise firewall policy...")
    policy = create_enterprise_policy()
    print(f"    ✓ Policy created: {policy.name}")
    print(f"    ✓ Total rules: {len(policy.rules)}")
    print(f"    ✓ Zones defined: {len(policy.zones)}")
    print()

    # 2. Generate configurations for different platforms
    print("[2] Generating firewall configurations...")

    platforms = ['iptables', 'pfsense', 'fortigate', 'cisco-asa']
    for platform in platforms:
        generator = get_generator(platform, policy)
        output_file = f"../configs/{platform}_config.conf"
        generator.save_to_file(output_file)
        print(f"    ✓ {platform.upper()} config saved to: {output_file}")
    print()

    # 3. Analyze policy
    print("[3] Analyzing firewall policy for issues...")
    analyzer = RuleAnalyzer(policy)
    audit_result = analyzer.analyze()

    print(f"    ✓ Compliance Score: {audit_result.compliance_score:.1f}%")
    print(f"    ✓ Conflicts Found: {len(audit_result.conflicts)}")
    print(f"    ✓ High-Risk Rules: {len(audit_result.high_risk_rules)}")
    print()

    # 4. Generate reports
    print("[4] Generating audit reports...")
    report_gen = ReportGenerator(policy, audit_result)

    # HTML report
    html_report = report_gen.generate_html()
    with open("../reports/audit_report.html", 'w') as f:
        f.write(html_report)
    print("    ✓ HTML report: ../reports/audit_report.html")

    # JSON report
    json_report = report_gen.generate_json()
    with open("../reports/audit_report.json", 'w') as f:
        f.write(json_report)
    print("    ✓ JSON report: ../reports/audit_report.json")
    print()

    # 5. Display summary
    print("[5] Policy Summary:")
    print(f"    • Total Rules: {audit_result.total_rules}")
    print(f"    • Enabled: {audit_result.enabled_rules}")
    print(f"    • Disabled: {audit_result.total_rules - audit_result.enabled_rules}")
    print()

    if audit_result.conflicts:
        print("    ⚠ Conflicts:")
        for conflict in audit_result.conflicts[:3]:  # Show first 3
            print(f"      - {conflict.conflict_type.upper()}: "
                  f"Rule {conflict.rule1.rule_id} ↔ Rule {conflict.rule2.rule_id}")

    print()
    print("="*70)
    print(" Example completed successfully!")
    print(" Check the 'configs/' and 'reports/' directories for outputs.")
    print("="*70)


if __name__ == '__main__':
    main()
