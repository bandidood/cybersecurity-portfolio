"""
Report Generator for Bug Bounty Platform
Generates vulnerability reports in multiple formats
"""

from datetime import datetime
from typing import List, Dict, Optional
import json
from pathlib import Path


class VulnerabilityReport:
    """Generate comprehensive vulnerability reports"""

    def __init__(self, vulnerability_data: Dict):
        self.data = vulnerability_data
        self.timestamp = datetime.now()

    def generate_markdown(self) -> str:
        """Generate Markdown formatted report"""
        lines = []

        # Header
        lines.append("# Vulnerability Report")
        lines.append(f"\n**Report ID:** {self.data.get('id', 'N/A')}")
        lines.append(f"**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Severity:** {self.data.get('severity', 'Unknown').upper()}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append(f"\n{self.data.get('summary', 'No summary provided.')}")
        lines.append("")

        # Vulnerability Details
        lines.append("## Vulnerability Details")
        lines.append(f"\n**Title:** {self.data.get('title', 'Untitled')}")
        lines.append(f"**Type:** {self.data.get('type', 'Unknown')}")
        lines.append(f"**CVSS Score:** {self.data.get('cvss_score', 'N/A')}")
        lines.append(f"**CWE ID:** {self.data.get('cwe_id', 'N/A')}")
        lines.append("")

        # Description
        lines.append("## Description")
        lines.append(f"\n{self.data.get('description', 'No description provided.')}")
        lines.append("")

        # Impact
        lines.append("## Impact")
        lines.append(f"\n{self.data.get('impact', 'No impact assessment provided.')}")
        lines.append("")

        # Proof of Concept
        if 'poc' in self.data:
            lines.append("## Proof of Concept")
            lines.append("\n```")
            lines.append(self.data['poc'])
            lines.append("```")
            lines.append("")

        # Steps to Reproduce
        if 'steps_to_reproduce' in self.data:
            lines.append("## Steps to Reproduce")
            for i, step in enumerate(self.data['steps_to_reproduce'], 1):
                lines.append(f"\n{i}. {step}")
            lines.append("")

        # Remediation
        lines.append("## Recommended Remediation")
        lines.append(f"\n{self.data.get('remediation', 'No remediation guidance provided.')}")
        lines.append("")

        # Affected Components
        if 'affected_components' in self.data:
            lines.append("## Affected Components")
            for component in self.data['affected_components']:
                lines.append(f"\n- {component}")
            lines.append("")

        # References
        if 'references' in self.data:
            lines.append("## References")
            for ref in self.data['references']:
                lines.append(f"\n- {ref}")
            lines.append("")

        # Reporter Information
        lines.append("## Reporter Information")
        reporter = self.data.get('reporter', {})
        lines.append(f"\n**Name:** {reporter.get('name', 'Anonymous')}")
        lines.append(f"**Submitted:** {reporter.get('submitted_date', 'Unknown')}")
        lines.append("")

        return "\n".join(lines)

    def generate_json(self, indent: int = 2) -> str:
        """Generate JSON formatted report"""
        report_data = {
            'report_id': self.data.get('id'),
            'generated_at': self.timestamp.isoformat(),
            'vulnerability': self.data,
            'metadata': {
                'format_version': '1.0',
                'generator': 'Bug Bounty Platform Report Generator'
            }
        }
        return json.dumps(report_data, indent=indent)

    def generate_html(self) -> str:
        """Generate HTML formatted report"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {self.data.get('id', 'N/A')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        .severity {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 4px;
            font-weight: bold;
            color: white;
        }}
        .severity-critical {{ background: #e74c3c; }}
        .severity-high {{ background: #e67e22; }}
        .severity-medium {{ background: #f39c12; }}
        .severity-low {{ background: #27ae60; }}
        .info-box {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .metadata {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        ul {{
            line-height: 1.8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Vulnerability Report</h1>

        <div class="metadata">
            <p><strong>Report ID:</strong> {self.data.get('id', 'N/A')}</p>
            <p><strong>Generated:</strong> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Severity:</strong>
                <span class="severity severity-{self.data.get('severity', 'low').lower()}">
                    {self.data.get('severity', 'Unknown').upper()}
                </span>
            </p>
        </div>

        <div class="info-box">
            <h2>📋 Executive Summary</h2>
            <p>{self.data.get('summary', 'No summary provided.')}</p>
        </div>

        <h2>🔍 Vulnerability Details</h2>
        <ul>
            <li><strong>Title:</strong> {self.data.get('title', 'Untitled')}</li>
            <li><strong>Type:</strong> {self.data.get('type', 'Unknown')}</li>
            <li><strong>CVSS Score:</strong> {self.data.get('cvss_score', 'N/A')}</li>
            <li><strong>CWE ID:</strong> {self.data.get('cwe_id', 'N/A')}</li>
        </ul>

        <h2>📝 Description</h2>
        <p>{self.data.get('description', 'No description provided.')}</p>

        <h2>⚠️ Impact</h2>
        <p>{self.data.get('impact', 'No impact assessment provided.')}</p>

        {"<h2>🧪 Proof of Concept</h2><div class='code-block'><pre>" + self.data.get('poc', '') + "</pre></div>" if 'poc' in self.data else ""}

        <h2>✅ Recommended Remediation</h2>
        <p>{self.data.get('remediation', 'No remediation guidance provided.')}</p>

        <h2>👤 Reporter Information</h2>
        <ul>
            <li><strong>Name:</strong> {self.data.get('reporter', {}).get('name', 'Anonymous')}</li>
            <li><strong>Submitted:</strong> {self.data.get('reporter', {}).get('submitted_date', 'Unknown')}</li>
        </ul>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; font-size: 0.9em;">
            <p>Generated by Bug Bounty Platform Report Generator</p>
        </footer>
    </div>
</body>
</html>
"""
        return html

    def save(self, output_path: str, format: str = 'markdown'):
        """Save report to file"""
        path = Path(output_path)

        if format == 'markdown':
            content = self.generate_markdown()
            path = path.with_suffix('.md')
        elif format == 'json':
            content = self.generate_json()
            path = path.with_suffix('.json')
        elif format == 'html':
            content = self.generate_html()
            path = path.with_suffix('.html')
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

        return str(path)


class ProgramReport:
    """Generate bug bounty program summary reports"""

    def __init__(self, program_data: Dict):
        self.data = program_data
        self.timestamp = datetime.now()

    def generate_summary(self) -> str:
        """Generate program summary report"""
        lines = []

        lines.append("# Bug Bounty Program Report")
        lines.append(f"\n**Program:** {self.data.get('name', 'Unnamed Program')}")
        lines.append(f"**Report Period:** {self.data.get('period', 'N/A')}")
        lines.append(f"**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Statistics
        stats = self.data.get('statistics', {})
        lines.append("## Program Statistics")
        lines.append(f"\n- Total Submissions: {stats.get('total_submissions', 0)}")
        lines.append(f"- Valid Vulnerabilities: {stats.get('valid_vulnerabilities', 0)}")
        lines.append(f"- Duplicate Reports: {stats.get('duplicates', 0)}")
        lines.append(f"- False Positives: {stats.get('false_positives', 0)}")
        lines.append(f"- Total Paid: ${stats.get('total_paid', 0):,.2f}")
        lines.append("")

        # Severity Breakdown
        severity = stats.get('by_severity', {})
        lines.append("## Vulnerabilities by Severity")
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            count = severity.get(sev.lower(), 0)
            lines.append(f"\n- **{sev}:** {count}")
        lines.append("")

        # Top Researchers
        if 'top_researchers' in self.data:
            lines.append("## Top Researchers")
            for i, researcher in enumerate(self.data['top_researchers'][:5], 1):
                lines.append(f"\n{i}. {researcher['name']} - {researcher['submissions']} submissions, ${researcher['earned']:,.2f} earned")
            lines.append("")

        # Recent Critical Findings
        if 'critical_findings' in self.data:
            lines.append("## Recent Critical Findings")
            for finding in self.data['critical_findings'][:5]:
                lines.append(f"\n- **{finding['title']}** (CVSS: {finding.get('cvss_score', 'N/A')})")
                lines.append(f"  - Reporter: {finding.get('reporter', 'Anonymous')}")
                lines.append(f"  - Status: {finding.get('status', 'Unknown')}")
            lines.append("")

        return "\n".join(lines)

    def save(self, output_path: str):
        """Save program report"""
        content = self.generate_summary()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return output_path
