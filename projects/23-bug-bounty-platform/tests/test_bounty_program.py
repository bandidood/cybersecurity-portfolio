"""
Unit tests for Bug Bounty Program Management System
"""

import unittest
from decimal import Decimal
import sys
import os
import importlib.util
from pathlib import Path

# Import using importlib to avoid conflicts with Python's built-in platform module
parent_dir = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location(
    'bounty_program',
    parent_dir / 'platform' / 'bounty_program.py'
)
bounty_program = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty_program)

# Extract classes
ProgramManager = bounty_program.ProgramManager
BugBountyProgram = bounty_program.BugBountyProgram
ScopeItem = bounty_program.ScopeItem
ProgramStatus = bounty_program.ProgramStatus
ScopeType = bounty_program.ScopeType
VulnSeverity = bounty_program.VulnSeverity


class TestProgramManager(unittest.TestCase):
    """Test ProgramManager class"""

    def setUp(self):
        """Set up test manager"""
        self.manager = ProgramManager()

    def test_create_program(self):
        """Test program creation"""
        program = self.manager.create_program(
            name="Test Program",
            organization_id="org_123",
            description="Test bug bounty program",
            total_budget=Decimal('50000.00')
        )

        self.assertIsInstance(program, BugBountyProgram)
        self.assertEqual(program.name, "Test Program")
        self.assertEqual(program.organization_id, "org_123")
        self.assertEqual(program.status, ProgramStatus.DRAFT)
        self.assertEqual(program.total_budget, Decimal('50000.00'))
        self.assertEqual(len(program.reward_tiers), 5)  # Default tiers

    def test_get_program(self):
        """Test retrieving a program"""
        program = self.manager.create_program(
            name="Test Program",
            organization_id="org_123",
            description="Test"
        )

        retrieved = self.manager.get_program(program.program_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.program_id, program.program_id)

    def test_add_scope_item(self):
        """Test adding scope items"""
        program = self.manager.create_program(
            name="Test Program",
            organization_id="org_123",
            description="Test"
        )

        scope_item = ScopeItem(
            scope_id="",
            scope_type=ScopeType.WEB_APPLICATION,
            target="https://app.example.com",
            description="Main web application",
            max_severity=VulnSeverity.CRITICAL
        )

        result = self.manager.add_scope_item(program.program_id, scope_item)
        self.assertTrue(result)

        updated = self.manager.get_program(program.program_id)
        self.assertEqual(len(updated.scope_items), 1)

    def test_activate_program(self):
        """Test activating a program"""
        program = self.manager.create_program(
            name="Test Program",
            organization_id="org_123",
            description="Test",
            total_budget=Decimal('50000.00')
        )

        # Add scope item (required for activation)
        scope_item = ScopeItem(
            scope_id="",
            scope_type=ScopeType.WEB_APPLICATION,
            target="https://app.example.com",
            description="Test"
        )
        self.manager.add_scope_item(program.program_id, scope_item)

        # Activate
        result = self.manager.activate_program(program.program_id)
        self.assertTrue(result)

        updated = self.manager.get_program(program.program_id)
        self.assertEqual(updated.status, ProgramStatus.ACTIVE)

    def test_get_program_metrics(self):
        """Test getting program metrics"""
        program = self.manager.create_program(
            name="Test Program",
            organization_id="org_123",
            description="Test",
            total_budget=Decimal('50000.00')
        )

        metrics = self.manager.get_program_metrics(program.program_id)

        self.assertIn('program_id', metrics)
        self.assertIn('status', metrics)
        self.assertIn('total_submissions', metrics)


if __name__ == '__main__':
    unittest.main()
