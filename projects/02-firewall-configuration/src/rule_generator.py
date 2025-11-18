#!/usr/bin/env python3
"""
Firewall Rule Generator - Multi-platform Support
Generates firewall rules for different platforms: iptables, pfSense, FortiGate, Cisco ASA
"""

from typing import List, Dict
from models import FirewallRule, Policy, Action, Protocol, NetworkObject, Service
from abc import ABC, abstractmethod


class FirewallGenerator(ABC):
    """Abstract base class for firewall rule generators"""

    def __init__(self, policy: Policy):
        self.policy = policy

    @abstractmethod
    def generate_rule(self, rule: FirewallRule) -> str:
        """Generate a single firewall rule"""
        pass

    @abstractmethod
    def generate_header(self) -> str:
        """Generate configuration header"""
        pass

    @abstractmethod
    def generate_footer(self) -> str:
        """Generate configuration footer"""
        pass

    def generate_all(self) -> str:
        """Generate complete firewall configuration"""
        output = [self.generate_header()]

        for rule in self.policy.get_enabled_rules():
            output.append(self.generate_rule(rule))

        output.append(self.generate_footer())
        return '\n'.join(output)

    def save_to_file(self, filename: str) -> None:
        """Save generated configuration to file"""
        with open(filename, 'w') as f:
            f.write(self.generate_all())


class IptablesGenerator(FirewallGenerator):
    """Generate iptables rules (Linux netfilter)"""

    def generate_header(self) -> str:
        return f"""#!/bin/bash
# iptables Firewall Configuration
# Generated from policy: {self.policy.name}
# Version: {self.policy.version}
# Date: {self.policy.created_at.strftime('%Y-%m-%d %H:%M:%S')}

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT {self.policy.default_action.value.upper()}
iptables -P FORWARD {self.policy.default_action.value.upper()}
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rules
"""

    def generate_footer(self) -> str:
        return f"""
# Log dropped packets (optional)
# iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "
# iptables -A FORWARD -j LOG --log-prefix "iptables-dropped: "

# Save rules
iptables-save > /etc/iptables/rules.v4

echo "Firewall rules applied successfully"
"""

    def generate_rule(self, rule: FirewallRule) -> str:
        """Generate iptables rule"""
        parts = []

        # Comment
        parts.append(f"# Rule {rule.rule_id}: {rule.name}")
        if rule.description:
            parts.append(f"# {rule.description}")

        # Build iptables command
        cmd = ["iptables -A"]

        # Chain (INPUT/FORWARD based on direction)
        if rule.direction.value == "inbound":
            cmd.append("INPUT")
        else:
            cmd.append("FORWARD")

        # Protocol
        if rule.service.protocol != Protocol.ANY:
            cmd.append(f"-p {rule.service.protocol.value}")

        # Source
        if rule.source.ip_address and rule.source.ip_address != "0.0.0.0":
            cmd.append(f"-s {rule.source.to_cidr()}")

        # Destination
        if rule.destination.ip_address and rule.destination.ip_address != "0.0.0.0":
            cmd.append(f"-d {rule.destination.to_cidr()}")

        # Port
        if rule.service.port:
            if rule.service.protocol in [Protocol.TCP, Protocol.UDP]:
                cmd.append(f"--dport {rule.service.port}")

        # Logging
        if rule.logging:
            log_cmd = ' '.join(cmd)
            parts.append(f"{log_cmd} -j LOG --log-prefix \"[RULE-{rule.rule_id}] \"")

        # Action
        action_map = {
            Action.ALLOW: "ACCEPT",
            Action.DENY: "DROP",
            Action.REJECT: "REJECT",
            Action.DROP: "DROP",
        }
        cmd.append(f"-j {action_map.get(rule.action, 'DROP')}")

        parts.append(' '.join(cmd))
        parts.append("")  # Empty line

        return '\n'.join(parts)


class PfSenseGenerator(FirewallGenerator):
    """Generate pfSense rules (FreeBSD pf)"""

    def generate_header(self) -> str:
        return f"""# pfSense Firewall Configuration
# Policy: {self.policy.name}
# Version: {self.policy.version}
# Date: {self.policy.created_at.strftime('%Y-%m-%d %H:%M:%S')}
#
# To apply: pfctl -f /etc/pf.conf

# Macros
ext_if = "wan"
int_if = "lan"

# Tables
table <rfc1918> {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }}

# Options
set block-policy drop
set loginterface {self.policy.default_action.value}
set skip on lo0

# Normalization
scrub in all

# Default policies
block log all

# Rules
"""

    def generate_footer(self) -> str:
        return """
# End of firewall rules
"""

    def generate_rule(self, rule: FirewallRule) -> str:
        """Generate pfSense rule"""
        parts = []

        # Comment
        parts.append(f"# Rule {rule.rule_id}: {rule.name}")

        # Build pf rule
        cmd = []

        # Action
        if rule.action in [Action.ALLOW, Action.LOG_AND_ALLOW]:
            cmd.append("pass")
        else:
            cmd.append("block")

        # Direction
        if rule.direction.value == "inbound":
            cmd.append("in")
        elif rule.direction.value == "outbound":
            cmd.append("out")

        # Logging
        if rule.logging:
            cmd.append("log")

        # Quick (first match wins)
        cmd.append("quick")

        # Interface
        cmd.append("on $ext_if")

        # Protocol
        if rule.service.protocol != Protocol.ANY:
            cmd.append(f"proto {rule.service.protocol.value}")

        # Source
        if rule.source.ip_address and rule.source.ip_address != "0.0.0.0":
            cmd.append(f"from {rule.source.to_cidr()}")
        else:
            cmd.append("from any")

        # Destination
        if rule.destination.ip_address and rule.destination.ip_address != "0.0.0.0":
            cmd.append(f"to {rule.destination.to_cidr()}")
        else:
            cmd.append("to any")

        # Port
        if rule.service.port:
            cmd.append(f"port {rule.service.port}")

        parts.append(' '.join(cmd))
        parts.append("")

        return '\n'.join(parts)


class FortiGateGenerator(FirewallGenerator):
    """Generate FortiGate rules (Fortinet CLI)"""

    def generate_header(self) -> str:
        return f"""# FortiGate Firewall Configuration
# Policy: {self.policy.name}
# Version: {self.policy.version}
# Date: {self.policy.created_at.strftime('%Y-%m-%d %H:%M:%S')}

config firewall policy
"""

    def generate_footer(self) -> str:
        return """end
"""

    def generate_rule(self, rule: FirewallRule) -> str:
        """Generate FortiGate rule"""
        parts = []

        # Edit policy
        parts.append(f"    edit {rule.rule_id}")
        parts.append(f"        set name \"{rule.name}\"")

        # Source/destination interfaces
        parts.append(f"        set srcintf \"port1\"")
        parts.append(f"        set dstintf \"port2\"")

        # Source address
        src_addr = rule.source.name if rule.source.name else "all"
        parts.append(f"        set srcaddr \"{src_addr}\"")

        # Destination address
        dst_addr = rule.destination.name if rule.destination.name else "all"
        parts.append(f"        set dstaddr \"{dst_addr}\"")

        # Service
        service = rule.service.name if rule.service.name else "ALL"
        parts.append(f"        set service \"{service}\"")

        # Schedule
        parts.append(f"        set schedule \"always\"")

        # Action
        action = "accept" if rule.action == Action.ALLOW else "deny"
        parts.append(f"        set action {action}")

        # Logging
        log_level = "all" if rule.logging else "security"
        parts.append(f"        set logtraffic {log_level}")

        # Status
        status = "enable" if rule.enabled else "disable"
        parts.append(f"        set status {status}")

        # Comments
        if rule.description:
            parts.append(f"        set comments \"{rule.description}\"")

        parts.append("    next")
        parts.append("")

        return '\n'.join(parts)


class CiscoASAGenerator(FirewallGenerator):
    """Generate Cisco ASA rules"""

    def generate_header(self) -> str:
        return f"""! Cisco ASA Firewall Configuration
! Policy: {self.policy.name}
! Version: {self.policy.version}
! Date: {self.policy.created_at.strftime('%Y-%m-%d %H:%M:%S')}

! Clear existing ACLs (optional)
! clear configure access-list

! Configure interfaces
"""

    def generate_footer(self) -> str:
        return """
! Apply ACL to interfaces
access-group OUTSIDE_IN in interface outside
access-group INSIDE_IN in interface inside

! Save configuration
write memory
"""

    def generate_rule(self, rule: FirewallRule) -> str:
        """Generate Cisco ASA ACL rule"""
        parts = []

        # Comment
        parts.append(f"! Rule {rule.rule_id}: {rule.name}")

        # ACL name
        acl_name = "OUTSIDE_IN" if rule.direction.value == "inbound" else "INSIDE_IN"

        # Build ACE
        cmd = [f"access-list {acl_name} extended"]

        # Action
        if rule.action == Action.ALLOW:
            cmd.append("permit")
        else:
            cmd.append("deny")

        # Protocol
        proto = rule.service.protocol.value if rule.service.protocol != Protocol.ANY else "ip"
        cmd.append(proto)

        # Source
        if rule.source.ip_address and rule.source.ip_address != "0.0.0.0":
            cmd.append(f"{rule.source.ip_address} {rule.source.netmask or '255.255.255.255'}")
        else:
            cmd.append("any")

        # Destination
        if rule.destination.ip_address and rule.destination.ip_address != "0.0.0.0":
            cmd.append(f"{rule.destination.ip_address} {rule.destination.netmask or '255.255.255.255'}")
        else:
            cmd.append("any")

        # Port
        if rule.service.port and proto in ['tcp', 'udp']:
            cmd.append(f"eq {rule.service.port}")

        # Logging
        if rule.logging:
            cmd.append("log")

        parts.append(' '.join(cmd))
        parts.append("")

        return '\n'.join(parts)


# Factory function to get the appropriate generator
def get_generator(platform: str, policy: Policy) -> FirewallGenerator:
    """Factory function to get the appropriate generator"""
    generators = {
        'iptables': IptablesGenerator,
        'pfsense': PfSenseGenerator,
        'fortigate': FortiGateGenerator,
        'cisco-asa': CiscoASAGenerator,
    }

    generator_class = generators.get(platform.lower())
    if not generator_class:
        raise ValueError(f"Unsupported platform: {platform}. "
                        f"Supported platforms: {', '.join(generators.keys())}")

    return generator_class(policy)
