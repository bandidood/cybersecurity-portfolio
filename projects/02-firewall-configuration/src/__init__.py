"""
Enterprise Firewall Configuration Framework
A comprehensive toolkit for managing firewall policies across multiple platforms
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .models import (
    FirewallRule,
    Policy,
    NetworkObject,
    Service,
    Zone,
    Action,
    Protocol,
    Direction,
    Severity,
    COMMON_NETWORKS,
    COMMON_SERVICES
)

from .rule_generator import get_generator, FirewallGenerator
from .rule_analyzer import RuleAnalyzer
from .report_generator import ReportGenerator
from .firewall_manager import FirewallManager

__all__ = [
    'FirewallRule',
    'Policy',
    'NetworkObject',
    'Service',
    'Zone',
    'Action',
    'Protocol',
    'Direction',
    'Severity',
    'COMMON_NETWORKS',
    'COMMON_SERVICES',
    'get_generator',
    'FirewallGenerator',
    'RuleAnalyzer',
    'ReportGenerator',
    'FirewallManager',
]
