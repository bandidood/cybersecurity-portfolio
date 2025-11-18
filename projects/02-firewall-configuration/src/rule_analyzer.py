#!/usr/bin/env python3
"""
Firewall Rule Analyzer
Analyzes firewall rules for conflicts, redundancies, optimization opportunities
"""

from typing import List, Set, Tuple
from models import (
    FirewallRule, Policy, RuleConflict, AuditResult,
    Action, Severity, NetworkObject
)
from datetime import datetime
import ipaddress


class RuleAnalyzer:
    """Analyzes firewall rules for issues and optimization opportunities"""

    def __init__(self, policy: Policy):
        self.policy = policy

    def analyze(self) -> AuditResult:
        """Perform complete analysis of firewall policy"""
        result = AuditResult(
            policy_name=self.policy.name,
            timestamp=datetime.now(),
            total_rules=len(self.policy.rules),
            enabled_rules=len(self.policy.get_enabled_rules())
        )

        # Detect conflicts
        result.conflicts = self.detect_conflicts()

        # Find unused/redundant rules
        result.unused_rules = self.find_unused_rules()

        # Identify high-risk rules
        result.high_risk_rules = self.find_high_risk_rules()

        # Generate recommendations
        result.recommendations = self.generate_recommendations(result)

        # Calculate compliance score
        result.compliance_score = self.calculate_compliance_score(result)

        return result

    def detect_conflicts(self) -> List[RuleConflict]:
        """Detect conflicts between firewall rules"""
        conflicts = []
        rules = self.policy.get_enabled_rules()

        for i, rule1 in enumerate(rules):
            for j, rule2 in enumerate(rules[i+1:], start=i+1):
                # Check for shadowing (rule1 makes rule2 unreachable)
                if self._is_shadowed(rule1, rule2):
                    conflicts.append(RuleConflict(
                        rule1=rule1,
                        rule2=rule2,
                        conflict_type="shadowed",
                        severity=Severity.HIGH,
                        description=f"Rule {rule1.rule_id} shadows rule {rule2.rule_id}",
                        recommendation=f"Move rule {rule2.rule_id} before rule {rule1.rule_id} or remove it"
                    ))

                # Check for redundancy
                if self._is_redundant(rule1, rule2):
                    conflicts.append(RuleConflict(
                        rule1=rule1,
                        rule2=rule2,
                        conflict_type="redundant",
                        severity=Severity.MEDIUM,
                        description=f"Rule {rule2.rule_id} is redundant with rule {rule1.rule_id}",
                        recommendation=f"Consider removing rule {rule2.rule_id}"
                    ))

                # Check for contradictions
                if self._is_contradictory(rule1, rule2):
                    conflicts.append(RuleConflict(
                        rule1=rule1,
                        rule2=rule2,
                        conflict_type="contradictory",
                        severity=Severity.CRITICAL,
                        description=f"Rules {rule1.rule_id} and {rule2.rule_id} have contradictory actions",
                        recommendation="Review and consolidate these rules"
                    ))

        return conflicts

    def _is_shadowed(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if rule2 is shadowed by rule1"""
        # Rule2 is shadowed if:
        # 1. Rule1 comes first
        # 2. Rule1's match criteria are broader or equal to rule2's
        # 3. They have different actions

        if rule1.action == rule2.action:
            return False

        # Check if rule1's source contains rule2's source
        if not self._network_contains(rule1.source, rule2.source):
            return False

        # Check if rule1's destination contains rule2's destination
        if not self._network_contains(rule1.destination, rule2.destination):
            return False

        # Check if rule1's service contains rule2's service
        if not self._service_contains(rule1.service, rule2.service):
            return False

        return True

    def _is_redundant(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if rule2 is redundant with rule1"""
        # Rules are redundant if they match the same traffic and have the same action
        if rule1.action != rule2.action:
            return False

        # Check if rules match the exact same traffic
        return (
            self._networks_equal(rule1.source, rule2.source) and
            self._networks_equal(rule1.destination, rule2.destination) and
            self._services_equal(rule1.service, rule2.service)
        )

    def _is_contradictory(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if rules have contradictory actions for the same traffic"""
        if rule1.action == rule2.action:
            return False

        # Check if rules match exactly the same traffic but with different actions
        return (
            self._networks_equal(rule1.source, rule2.source) and
            self._networks_equal(rule1.destination, rule2.destination) and
            self._services_equal(rule1.service, rule2.service)
        )

    def _network_contains(self, net1: NetworkObject, net2: NetworkObject) -> bool:
        """Check if net1 contains net2"""
        try:
            network1 = ipaddress.ip_network(net1.to_cidr(), strict=False)
            network2 = ipaddress.ip_network(net2.to_cidr(), strict=False)
            return network2.subnet_of(network1)
        except:
            # If any network is "any" or can't be parsed
            if net1.ip_address == "0.0.0.0" or net1.name == "any":
                return True
            return False

    def _networks_equal(self, net1: NetworkObject, net2: NetworkObject) -> bool:
        """Check if two networks are equal"""
        try:
            network1 = ipaddress.ip_network(net1.to_cidr(), strict=False)
            network2 = ipaddress.ip_network(net2.to_cidr(), strict=False)
            return network1 == network2
        except:
            return net1.name == net2.name

    def _service_contains(self, svc1, svc2) -> bool:
        """Check if service1 contains service2"""
        # Protocol must match or svc1 must be ANY
        if svc1.protocol.value == "any":
            return True
        if svc1.protocol != svc2.protocol:
            return False

        # Check port ranges
        if not svc1.port or svc1.port == "any":
            return True

        range1 = svc1.port_range()
        range2 = svc2.port_range()

        return range1[0] <= range2[0] and range1[1] >= range2[1]

    def _services_equal(self, svc1, svc2) -> bool:
        """Check if two services are equal"""
        return (
            svc1.protocol == svc2.protocol and
            svc1.port == svc2.port
        )

    def find_unused_rules(self) -> List[int]:
        """Find rules that might be unused (heuristic-based)"""
        unused = []

        for rule in self.policy.rules:
            # Rules allowing from/to localhost might be unused
            if (rule.source.ip_address == "127.0.0.1" or
                rule.destination.ip_address == "127.0.0.1"):
                if rule.action == Action.DENY:
                    unused.append(rule.rule_id)

        return unused

    def find_high_risk_rules(self) -> List[int]:
        """Identify high-risk firewall rules"""
        high_risk = []

        for rule in self.policy.get_enabled_rules():
            risk_score = 0

            # Rule allows traffic from anywhere
            if rule.source.ip_address == "0.0.0.0" or rule.source.name == "any":
                risk_score += 30

            # Rule allows to sensitive ports without restriction
            sensitive_ports = ['22', '3389', '23', '21', '1433', '3306', '5432']
            if rule.service.port in sensitive_ports:
                risk_score += 25

            # Rule allows all protocols
            if rule.service.protocol.value == "any":
                risk_score += 15

            # Rule has no logging enabled
            if not rule.logging:
                risk_score += 10

            # Rule allows without description
            if not rule.description:
                risk_score += 5

            # High risk if score >= 50
            if risk_score >= 50:
                high_risk.append(rule.rule_id)
                rule.metadata['risk_score'] = risk_score

        return high_risk

    def generate_recommendations(self, result: AuditResult) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Based on conflicts
        if len(result.conflicts) > 0:
            recommendations.append(
                f"Found {len(result.conflicts)} rule conflicts. "
                f"Review and resolve {len(result.get_critical_issues())} critical issues immediately."
            )

        # Based on default action
        if self.policy.default_action != Action.DENY:
            recommendations.append(
                "Consider changing default policy to DENY for better security posture."
            )

        # Based on logging
        no_logging = sum(1 for r in self.policy.get_enabled_rules() if not r.logging)
        if no_logging > len(self.policy.rules) * 0.5:
            recommendations.append(
                f"{no_logging} rules have logging disabled. "
                "Enable logging for better visibility and forensics."
            )

        # Based on high-risk rules
        if len(result.high_risk_rules) > 0:
            recommendations.append(
                f"Identified {len(result.high_risk_rules)} high-risk rules. "
                "Review and restrict these rules to reduce attack surface."
            )

        # Based on rule count
        if len(self.policy.rules) > 100:
            recommendations.append(
                "Policy contains over 100 rules. Consider consolidating or using rule groups."
            )

        # Based on disabled rules
        disabled_count = len([r for r in self.policy.rules if not r.enabled])
        if disabled_count > 10:
            recommendations.append(
                f"Found {disabled_count} disabled rules. Clean up unused rules regularly."
            )

        return recommendations

    def calculate_compliance_score(self, result: AuditResult) -> float:
        """Calculate overall compliance score (0-100)"""
        score = 100.0

        # Deduct for conflicts
        score -= len(result.get_critical_issues()) * 10
        score -= len([c for c in result.conflicts if c.severity == Severity.HIGH]) * 5
        score -= len([c for c in result.conflicts if c.severity == Severity.MEDIUM]) * 2

        # Deduct for high-risk rules
        score -= len(result.high_risk_rules) * 3

        # Deduct for poor logging
        no_logging = sum(1 for r in self.policy.get_enabled_rules() if not r.logging)
        logging_ratio = no_logging / max(len(self.policy.rules), 1)
        score -= logging_ratio * 15

        # Deduct for wrong default policy
        if self.policy.default_action != Action.DENY:
            score -= 10

        # Deduct for lack of documentation
        no_desc = sum(1 for r in self.policy.rules if not r.description)
        desc_ratio = no_desc / max(len(self.policy.rules), 1)
        score -= desc_ratio * 10

        return max(0.0, min(100.0, score))

    def optimize_rules(self) -> Policy:
        """Optimize firewall rules by removing redundancies and reordering"""
        optimized_policy = Policy(
            name=f"{self.policy.name}_optimized",
            default_action=self.policy.default_action,
            description=f"Optimized version of {self.policy.name}"
        )

        # Remove redundant rules
        seen_rules = set()
        for rule in self.policy.get_enabled_rules():
            rule_signature = self._get_rule_signature(rule)
            if rule_signature not in seen_rules:
                optimized_policy.add_rule(rule)
                seen_rules.add(rule_signature)

        # Reorder rules: most specific first, then broader rules
        optimized_policy.rules.sort(key=self._rule_specificity, reverse=True)

        # Renumber rules
        for i, rule in enumerate(optimized_policy.rules, start=1):
            rule.rule_id = i

        return optimized_policy

    def _get_rule_signature(self, rule: FirewallRule) -> str:
        """Get unique signature for a rule"""
        return f"{rule.source.to_cidr()}|{rule.destination.to_cidr()}|{rule.service}|{rule.action.value}"

    def _rule_specificity(self, rule: FirewallRule) -> int:
        """Calculate rule specificity score (higher = more specific)"""
        score = 0

        # More specific source network
        try:
            net = ipaddress.ip_network(rule.source.to_cidr(), strict=False)
            score += net.prefixlen
        except:
            pass

        # More specific destination network
        try:
            net = ipaddress.ip_network(rule.destination.to_cidr(), strict=False)
            score += net.prefixlen
        except:
            pass

        # Specific port vs port range
        if rule.service.port and '-' not in rule.service.port:
            score += 20

        # Specific protocol vs ANY
        if rule.service.protocol.value != "any":
            score += 10

        return score
