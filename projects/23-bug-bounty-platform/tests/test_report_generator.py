"""
Unit tests for Report Generator
"""

import unittest
import json
from datetime import datetime
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reports.report_generator import VulnerabilityReport, ProgramReport


class TestVulnerabilityReport(unittest.TestCase):
    """Test VulnerabilityReport class"""

    def setUp(self):
        """Set up test data"""
        self.vulnerability_data = {
            'id': 'VUL-2024-001',
            'title': 'SQL Injection in User Search',
            'severity': 'critical',
            'type': 'SQL Injection',
            'cvss_score': '9.8',
            'cwe_id': 'CWE-89',
            'summary': 'Critical SQL injection vulnerability found in user search endpoint',
            'description': 'The application does not properly sanitize user input in search queries',
            'impact': 'Attackers can extract sensitive data from the database',
            'poc': 'GET /api/search?q=test\' OR 1=1--',
            'steps_to_reproduce': [
                'Navigate to /search',
                'Enter payload: test\' OR 1=1--',
                'Observe database error messages',
                'Extract data using UNION queries'
            ],
            'remediation': 'Use parameterized queries and input validation',
            'affected_components': ['User Search API', 'Search Controller'],
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cwe.mitre.org/data/definitions/89.html'
            ],
            'reporter': {
                'name': 'Security Researcher',
                'submitted_date': '2024-01-15'
            }
        }
        self.report = VulnerabilityReport(self.vulnerability_data)

    def test_initialization(self):
        """Test report initialization"""
        self.assertEqual(self.report.data, self.vulnerability_data)
        self.assertIsInstance(self.report.timestamp, datetime)

    def test_generate_markdown(self):
        """Test Markdown report generation"""
        markdown = self.report.generate_markdown()

        # Check required sections
        self.assertIn('# Vulnerability Report', markdown)
        self.assertIn('## Executive Summary', markdown)
        self.assertIn('## Vulnerability Details', markdown)
        self.assertIn('## Description', markdown)
        self.assertIn('## Impact', markdown)
        self.assertIn('## Proof of Concept', markdown)
        self.assertIn('## Steps to Reproduce', markdown)
        self.assertIn('## Recommended Remediation', markdown)
        self.assertIn('## Reporter Information', markdown)

        # Check data inclusion
        self.assertIn('VUL-2024-001', markdown)
        self.assertIn('SQL Injection in User Search', markdown)
        self.assertIn('CRITICAL', markdown)
        self.assertIn('9.8', markdown)
        self.assertIn('CWE-89', markdown)

    def test_generate_json(self):
        """Test JSON report generation"""
        json_str = self.report.generate_json()
        report_data = json.loads(json_str)

        # Check structure
        self.assertIn('report_id', report_data)
        self.assertIn('generated_at', report_data)
        self.assertIn('vulnerability', report_data)
        self.assertIn('metadata', report_data)

        # Check data
        self.assertEqual(report_data['report_id'], 'VUL-2024-001')
        self.assertEqual(report_data['vulnerability']['title'], 'SQL Injection in User Search')
        self.assertEqual(report_data['metadata']['format_version'], '1.0')

    def test_generate_html(self):
        """Test HTML report generation"""
        html = self.report.generate_html()

        # Check HTML structure
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('<html lang="en">', html)
        self.assertIn('</html>', html)

        # Check content
        self.assertIn('VUL-2024-001', html)
        self.assertIn('SQL Injection in User Search', html)
        self.assertIn('severity-critical', html)

        # Check CSS styling
        self.assertIn('<style>', html)
        self.assertIn('font-family:', html)

    def test_save_markdown(self):
        """Test saving report as Markdown"""
        output_path = '/tmp/test_report'
        saved_path = self.report.save(output_path, format='markdown')

        # Check file was created
        self.assertTrue(Path(saved_path).exists())
        self.assertTrue(saved_path.endswith('.md'))

        # Check content
        with open(saved_path, 'r') as f:
            content = f.read()
            self.assertIn('# Vulnerability Report', content)

        # Cleanup
        Path(saved_path).unlink()

    def test_save_json(self):
        """Test saving report as JSON"""
        output_path = '/tmp/test_report'
        saved_path = self.report.save(output_path, format='json')

        # Check file was created
        self.assertTrue(Path(saved_path).exists())
        self.assertTrue(saved_path.endswith('.json'))

        # Check valid JSON
        with open(saved_path, 'r') as f:
            data = json.load(f)
            self.assertIn('report_id', data)

        # Cleanup
        Path(saved_path).unlink()

    def test_save_html(self):
        """Test saving report as HTML"""
        output_path = '/tmp/test_report'
        saved_path = self.report.save(output_path, format='html')

        # Check file was created
        self.assertTrue(Path(saved_path).exists())
        self.assertTrue(saved_path.endswith('.html'))

        # Check content
        with open(saved_path, 'r') as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)

        # Cleanup
        Path(saved_path).unlink()

    def test_save_invalid_format(self):
        """Test saving with invalid format"""
        with self.assertRaises(ValueError):
            self.report.save('/tmp/test_report', format='invalid')


class TestProgramReport(unittest.TestCase):
    """Test ProgramReport class"""

    def setUp(self):
        """Set up test data"""
        self.program_data = {
            'name': 'Acme Corp Bug Bounty',
            'period': 'Q1 2024',
            'statistics': {
                'total_submissions': 150,
                'valid_vulnerabilities': 85,
                'duplicates': 40,
                'false_positives': 25,
                'total_paid': 125000.00,
                'by_severity': {
                    'critical': 5,
                    'high': 20,
                    'medium': 35,
                    'low': 25
                }
            },
            'top_researchers': [
                {'name': 'Alice Security', 'submissions': 15, 'earned': 25000},
                {'name': 'Bob Hacker', 'submissions': 12, 'earned': 18000},
                {'name': 'Carol Tester', 'submissions': 10, 'earned': 15000}
            ],
            'critical_findings': [
                {
                    'title': 'Remote Code Execution',
                    'cvss_score': '10.0',
                    'reporter': 'Alice Security',
                    'status': 'Fixed'
                },
                {
                    'title': 'Authentication Bypass',
                    'cvss_score': '9.8',
                    'reporter': 'Bob Hacker',
                    'status': 'In Progress'
                }
            ]
        }
        self.report = ProgramReport(self.program_data)

    def test_initialization(self):
        """Test report initialization"""
        self.assertEqual(self.report.data, self.program_data)
        self.assertIsInstance(self.report.timestamp, datetime)

    def test_generate_summary(self):
        """Test program summary generation"""
        summary = self.report.generate_summary()

        # Check required sections
        self.assertIn('# Bug Bounty Program Report', summary)
        self.assertIn('## Program Statistics', summary)
        self.assertIn('## Vulnerabilities by Severity', summary)
        self.assertIn('## Top Researchers', summary)
        self.assertIn('## Recent Critical Findings', summary)

        # Check data
        self.assertIn('Acme Corp Bug Bounty', summary)
        self.assertIn('Q1 2024', summary)
        self.assertIn('Total Submissions: 150', summary)
        self.assertIn('Total Paid: $125,000.00', summary)
        self.assertIn('Alice Security', summary)

    def test_save_summary(self):
        """Test saving program summary"""
        output_path = '/tmp/test_program_report.md'
        saved_path = self.report.save(output_path)

        # Check file was created
        self.assertTrue(Path(saved_path).exists())

        # Check content
        with open(saved_path, 'r') as f:
            content = f.read()
            self.assertIn('# Bug Bounty Program Report', content)

        # Cleanup
        Path(saved_path).unlink()


if __name__ == '__main__':
    unittest.main()
