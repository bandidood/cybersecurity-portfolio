#!/usr/bin/env python3
"""
Firewall Report Generator
Generates detailed HTML and JSON reports for firewall policy analysis
"""

import json
from datetime import datetime
from typing import Dict, Any
from models import Policy, AuditResult


class ReportGenerator:
    """Generate audit reports in various formats"""

    def __init__(self, policy: Policy, audit_result: AuditResult):
        self.policy = policy
        self.result = audit_result

    def generate_html(self) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firewall Audit Report - {self.policy.name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .content {{
            padding: 40px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        .conflict-item {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
        }}
        .conflict-item.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .conflict-item.high {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        .conflict-item h4 {{
            font-size: 1.1em;
            margin-bottom: 10px;
            color: #721c24;
        }}
        .conflict-item.high h4 {{
            color: #856404;
        }}
        .rule-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .rule-table th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        .rule-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        .rule-table tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.allow {{
            background: #d4edda;
            color: #155724;
        }}
        .badge.deny {{
            background: #f8d7da;
            color: #721c24;
        }}
        .badge.high-risk {{
            background: #ff6b6b;
            color: white;
        }}
        .score {{
            font-size: 4em;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }}
        .score.good {{
            color: #28a745;
        }}
        .score.medium {{
            color: #ffc107;
        }}
        .score.poor {{
            color: #dc3545;
        }}
        .recommendation {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 Firewall Audit Report</h1>
            <p>{self.policy.name}</p>
            <p style="font-size: 0.9em; opacity: 0.8;">
                Generated on {self.result.timestamp.strftime('%Y-%m-%d at %H:%M:%S')}
            </p>
        </div>

        <div class="content">
            <!-- Summary Stats -->
            <div class="summary">
                <div class="stat-card">
                    <h3>Total Rules</h3>
                    <div class="value">{self.result.total_rules}</div>
                </div>
                <div class="stat-card">
                    <h3>Enabled Rules</h3>
                    <div class="value">{self.result.enabled_rules}</div>
                </div>
                <div class="stat-card">
                    <h3>Conflicts</h3>
                    <div class="value">{len(self.result.conflicts)}</div>
                </div>
                <div class="stat-card">
                    <h3>High Risk</h3>
                    <div class="value">{len(self.result.high_risk_rules)}</div>
                </div>
            </div>

            <!-- Compliance Score -->
            <div class="section">
                <h2>Overall Compliance Score</h2>
                {self._generate_score_html()}
            </div>

            <!-- Conflicts -->
            {self._generate_conflicts_html()}

            <!-- High-Risk Rules -->
            {self._generate_high_risk_html()}

            <!-- All Rules -->
            {self._generate_rules_table_html()}

            <!-- Recommendations -->
            {self._generate_recommendations_html()}
        </div>

        <div class="footer">
            <p>Generated by Enterprise Firewall Configuration Manager</p>
            <p>Policy Version: {self.policy.version} | Default Action: {self.policy.default_action.value.upper()}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_score_html(self) -> str:
        """Generate compliance score HTML"""
        score = self.result.compliance_score

        if score >= 80:
            score_class = "good"
            status = "Excellent"
        elif score >= 60:
            score_class = "medium"
            status = "Needs Improvement"
        else:
            score_class = "poor"
            status = "Critical Issues"

        return f"""
        <div class="score {score_class}">
            {score:.1f}%
        </div>
        <p style="text-align: center; font-size: 1.5em; margin-top: -10px;">
            {status}
        </p>
        """

    def _generate_conflicts_html(self) -> str:
        """Generate conflicts section HTML"""
        if not self.result.conflicts:
            return ""

        conflicts_html = ['<div class="section"><h2>Conflicts Detected</h2>']

        for conflict in self.result.conflicts:
            severity_class = conflict.severity.value
            conflicts_html.append(f"""
            <div class="conflict-item {severity_class}">
                <h4>[{conflict.severity.value.upper()}] {conflict.conflict_type.upper()}</h4>
                <p><strong>Rules:</strong> {conflict.rule1.rule_id} ↔ {conflict.rule2.rule_id}</p>
                <p><strong>Issue:</strong> {conflict.description}</p>
                <p><strong>Recommendation:</strong> {conflict.recommendation}</p>
            </div>
            """)

        conflicts_html.append('</div>')
        return '\n'.join(conflicts_html)

    def _generate_high_risk_html(self) -> str:
        """Generate high-risk rules section HTML"""
        if not self.result.high_risk_rules:
            return ""

        html = ['<div class="section"><h2>High-Risk Rules</h2>']
        html.append('<p>These rules have been identified as potentially risky:</p>')
        html.append('<ul>')

        for rule_id in self.result.high_risk_rules:
            rule = self.policy.get_rule(rule_id)
            if rule:
                risk_score = rule.metadata.get('risk_score', 0)
                html.append(f'<li><strong>Rule {rule_id}:</strong> {rule.name} (Risk Score: {risk_score})</li>')

        html.append('</ul>')
        html.append('</div>')
        return '\n'.join(html)

    def _generate_rules_table_html(self) -> str:
        """Generate rules table HTML"""
        html = ['<div class="section"><h2>Firewall Rules</h2>']
        html.append('<table class="rule-table">')
        html.append('<tr><th>ID</th><th>Name</th><th>Action</th><th>Source</th><th>Destination</th><th>Service</th><th>Status</th></tr>')

        for rule in self.policy.rules:
            status = "✓ Enabled" if rule.enabled else "✗ Disabled"
            action_class = "allow" if rule.action.value == "allow" else "deny"
            high_risk_badge = ""
            if rule.rule_id in self.result.high_risk_rules:
                high_risk_badge = ' <span class="badge high-risk">HIGH RISK</span>'

            html.append(f"""
            <tr>
                <td>{rule.rule_id}</td>
                <td>{rule.name}{high_risk_badge}</td>
                <td><span class="badge {action_class}">{rule.action.value.upper()}</span></td>
                <td>{rule.source.name}</td>
                <td>{rule.destination.name}</td>
                <td>{rule.service.name}</td>
                <td>{status}</td>
            </tr>
            """)

        html.append('</table>')
        html.append('</div>')
        return '\n'.join(html)

    def _generate_recommendations_html(self) -> str:
        """Generate recommendations section HTML"""
        if not self.result.recommendations:
            return ""

        html = ['<div class="section"><h2>Recommendations</h2>']

        for i, rec in enumerate(self.result.recommendations, 1):
            html.append(f'<div class="recommendation">{i}. {rec}</div>')

        html.append('</div>')
        return '\n'.join(html)

    def generate_json(self) -> str:
        """Generate JSON report"""
        report_data = {
            'policy_name': self.policy.name,
            'policy_version': self.policy.version,
            'audit_timestamp': self.result.timestamp.isoformat(),
            'summary': {
                'total_rules': self.result.total_rules,
                'enabled_rules': self.result.enabled_rules,
                'disabled_rules': self.result.total_rules - self.result.enabled_rules,
                'conflicts': len(self.result.conflicts),
                'high_risk_rules': len(self.result.high_risk_rules),
                'compliance_score': self.result.compliance_score
            },
            'conflicts': [
                {
                    'rule1_id': c.rule1.rule_id,
                    'rule2_id': c.rule2.rule_id,
                    'type': c.conflict_type,
                    'severity': c.severity.value,
                    'description': c.description,
                    'recommendation': c.recommendation
                }
                for c in self.result.conflicts
            ],
            'high_risk_rules': [
                {
                    'rule_id': rule_id,
                    'name': self.policy.get_rule(rule_id).name if self.policy.get_rule(rule_id) else 'Unknown',
                    'risk_score': self.policy.get_rule(rule_id).metadata.get('risk_score', 0)
                        if self.policy.get_rule(rule_id) else 0
                }
                for rule_id in self.result.high_risk_rules
            ],
            'recommendations': self.result.recommendations,
            'rules': [
                {
                    'id': rule.rule_id,
                    'name': rule.name,
                    'action': rule.action.value,
                    'source': str(rule.source),
                    'destination': str(rule.destination),
                    'service': str(rule.service),
                    'enabled': rule.enabled,
                    'logging': rule.logging
                }
                for rule in self.policy.rules
            ]
        }

        return json.dumps(report_data, indent=2)
