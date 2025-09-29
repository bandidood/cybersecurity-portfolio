#!/usr/bin/env python3
"""
Bug Bounty Program Management System
Manages bug bounty programs, rewards, and researcher interactions
"""

import uuid
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib
from decimal import Decimal

class ProgramStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ENDED = "ended"

class ScopeType(Enum):
    WEB_APPLICATION = "web_application"
    MOBILE_APPLICATION = "mobile_application"
    API = "api"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"

class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScopeItem:
    """Represents an item in scope for bug bounty program"""
    scope_id: str
    scope_type: ScopeType
    target: str  # URL, IP range, app name, etc.
    description: str
    in_scope: bool = True
    max_severity: Optional[VulnSeverity] = None
    special_instructions: Optional[str] = None
    excluded_vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class RewardTier:
    """Defines reward amounts for different severity levels"""
    severity: VulnSeverity
    min_reward: Decimal
    max_reward: Decimal
    currency: str = "USD"
    bonus_conditions: List[str] = field(default_factory=list)

@dataclass
class BugBountyProgram:
    """Represents a bug bounty program"""
    program_id: str
    name: str
    organization_id: str
    description: str
    status: ProgramStatus = ProgramStatus.DRAFT
    
    # Scope definition
    scope_items: List[ScopeItem] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    
    # Reward structure
    reward_tiers: List[RewardTier] = field(default_factory=list)
    total_budget: Optional[Decimal] = None
    budget_remaining: Optional[Decimal] = None
    
    # Program timeline
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    created_date: datetime = field(default_factory=datetime.now)
    updated_date: datetime = field(default_factory=datetime.now)
    
    # Program settings
    private_program: bool = False  # True for invite-only
    invited_researchers: Set[str] = field(default_factory=set)
    auto_validate_scans: bool = False
    require_proof_of_concept: bool = True
    allow_automated_scanning: bool = True
    safe_harbor_enabled: bool = True
    
    # Rules and requirements
    disclosure_policy: str = "Coordinated disclosure required"
    submission_requirements: List[str] = field(default_factory=list)
    prohibited_activities: List[str] = field(default_factory=list)
    
    # Statistics
    total_submissions: int = 0
    valid_submissions: int = 0
    total_rewards_paid: Decimal = Decimal('0.00')
    average_response_time: Optional[float] = None  # in hours
    
    # Contact information
    contact_email: str = ""
    security_team: List[str] = field(default_factory=list)

class ProgramManager:
    """Manages bug bounty programs"""
    
    def __init__(self):
        self.programs: Dict[str, BugBountyProgram] = {}
        self.organization_programs: Dict[str, List[str]] = {}
        
        # Default reward tiers
        self.default_reward_tiers = [
            RewardTier(VulnSeverity.CRITICAL, Decimal('5000.00'), Decimal('20000.00')),
            RewardTier(VulnSeverity.HIGH, Decimal('1000.00'), Decimal('5000.00')),
            RewardTier(VulnSeverity.MEDIUM, Decimal('250.00'), Decimal('1000.00')),
            RewardTier(VulnSeverity.LOW, Decimal('50.00'), Decimal('250.00')),
            RewardTier(VulnSeverity.INFO, Decimal('0.00'), Decimal('50.00'))
        ]
        
        # Default scope templates
        self.scope_templates = {
            "web_app_basic": [
                ScopeItem(
                    scope_id=str(uuid.uuid4()),
                    scope_type=ScopeType.WEB_APPLICATION,
                    target="*.example.com",
                    description="Main web application and subdomains",
                    max_severity=VulnSeverity.CRITICAL
                ),
                ScopeItem(
                    scope_id=str(uuid.uuid4()),
                    scope_type=ScopeType.API,
                    target="api.example.com",
                    description="REST API endpoints",
                    max_severity=VulnSeverity.HIGH
                )
            ]
        }

    def create_program(
        self,
        name: str,
        organization_id: str,
        description: str,
        **kwargs
    ) -> BugBountyProgram:
        """Create a new bug bounty program"""
        program_id = str(uuid.uuid4())
        
        program = BugBountyProgram(
            program_id=program_id,
            name=name,
            organization_id=organization_id,
            description=description,
            reward_tiers=self.default_reward_tiers.copy(),
            **kwargs
        )
        
        # Add default submission requirements
        program.submission_requirements = [
            "Detailed description of the vulnerability",
            "Step-by-step reproduction instructions",
            "Proof of concept (if applicable)",
            "Impact assessment",
            "Suggested remediation"
        ]
        
        # Add default prohibited activities
        program.prohibited_activities = [
            "Social engineering attacks",
            "Physical attacks on facilities",
            "Denial of service attacks",
            "Data destruction or modification",
            "Privacy violations",
            "Spam or phishing"
        ]
        
        self.programs[program_id] = program
        
        # Track by organization
        if organization_id not in self.organization_programs:
            self.organization_programs[organization_id] = []
        self.organization_programs[organization_id].append(program_id)
        
        return program

    def get_program(self, program_id: str) -> Optional[BugBountyProgram]:
        """Get a program by ID"""
        return self.programs.get(program_id)

    def list_programs(
        self,
        organization_id: Optional[str] = None,
        status: Optional[ProgramStatus] = None,
        public_only: bool = False
    ) -> List[BugBountyProgram]:
        """List programs with optional filters"""
        programs = list(self.programs.values())
        
        if organization_id:
            program_ids = self.organization_programs.get(organization_id, [])
            programs = [p for p in programs if p.program_id in program_ids]
        
        if status:
            programs = [p for p in programs if p.status == status]
        
        if public_only:
            programs = [p for p in programs if not p.private_program]
        
        return programs

    def update_program(self, program_id: str, updates: Dict[str, Any]) -> bool:
        """Update program properties"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        for key, value in updates.items():
            if hasattr(program, key):
                setattr(program, key, value)
        
        program.updated_date = datetime.now()
        return True

    def add_scope_item(self, program_id: str, scope_item: ScopeItem) -> bool:
        """Add an item to program scope"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        scope_item.scope_id = str(uuid.uuid4())
        program.scope_items.append(scope_item)
        program.updated_date = datetime.now()
        return True

    def remove_scope_item(self, program_id: str, scope_id: str) -> bool:
        """Remove an item from program scope"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        program.scope_items = [
            item for item in program.scope_items 
            if item.scope_id != scope_id
        ]
        program.updated_date = datetime.now()
        return True

    def update_reward_tier(self, program_id: str, severity: VulnSeverity, min_reward: Decimal, max_reward: Decimal) -> bool:
        """Update reward tier for a severity level"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        for tier in program.reward_tiers:
            if tier.severity == severity:
                tier.min_reward = min_reward
                tier.max_reward = max_reward
                break
        else:
            # Add new tier if doesn't exist
            program.reward_tiers.append(
                RewardTier(severity, min_reward, max_reward)
            )
        
        program.updated_date = datetime.now()
        return True

    def activate_program(self, program_id: str) -> bool:
        """Activate a program"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        # Validation checks
        if not program.scope_items:
            raise ValueError("Program must have at least one scope item")
        
        if not program.reward_tiers:
            raise ValueError("Program must have reward tiers defined")
        
        if program.total_budget and program.total_budget <= 0:
            raise ValueError("Program budget must be positive")
        
        program.status = ProgramStatus.ACTIVE
        program.start_date = datetime.now()
        program.budget_remaining = program.total_budget
        program.updated_date = datetime.now()
        
        return True

    def pause_program(self, program_id: str) -> bool:
        """Pause an active program"""
        program = self.programs.get(program_id)
        if not program or program.status != ProgramStatus.ACTIVE:
            return False
        
        program.status = ProgramStatus.PAUSED
        program.updated_date = datetime.now()
        return True

    def end_program(self, program_id: str) -> bool:
        """End a program"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        program.status = ProgramStatus.ENDED
        program.end_date = datetime.now()
        program.updated_date = datetime.now()
        return True

    def invite_researcher(self, program_id: str, researcher_id: str) -> bool:
        """Invite a researcher to a private program"""
        program = self.programs.get(program_id)
        if not program or not program.private_program:
            return False
        
        program.invited_researchers.add(researcher_id)
        program.updated_date = datetime.now()
        return True

    def remove_researcher_invitation(self, program_id: str, researcher_id: str) -> bool:
        """Remove researcher invitation"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        program.invited_researchers.discard(researcher_id)
        program.updated_date = datetime.now()
        return True

    def can_researcher_access(self, program_id: str, researcher_id: str) -> bool:
        """Check if researcher can access program"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        # Public programs are accessible to all
        if not program.private_program:
            return True
        
        # Private programs require invitation
        return researcher_id in program.invited_researchers

    def get_reward_amount(self, program_id: str, severity: VulnSeverity, base_amount: Optional[Decimal] = None) -> Decimal:
        """Get reward amount for a vulnerability"""
        program = self.programs.get(program_id)
        if not program:
            return Decimal('0.00')
        
        for tier in program.reward_tiers:
            if tier.severity == severity:
                if base_amount and tier.min_reward <= base_amount <= tier.max_reward:
                    return base_amount
                return (tier.min_reward + tier.max_reward) / 2
        
        return Decimal('0.00')

    def update_program_stats(self, program_id: str, stats_update: Dict[str, Any]) -> bool:
        """Update program statistics"""
        program = self.programs.get(program_id)
        if not program:
            return False
        
        if 'total_submissions' in stats_update:
            program.total_submissions = stats_update['total_submissions']
        
        if 'valid_submissions' in stats_update:
            program.valid_submissions = stats_update['valid_submissions']
        
        if 'reward_paid' in stats_update:
            program.total_rewards_paid += Decimal(str(stats_update['reward_paid']))
            if program.budget_remaining:
                program.budget_remaining -= Decimal(str(stats_update['reward_paid']))
        
        if 'response_time' in stats_update:
            if program.average_response_time:
                # Simple moving average
                program.average_response_time = (program.average_response_time + stats_update['response_time']) / 2
            else:
                program.average_response_time = stats_update['response_time']
        
        program.updated_date = datetime.now()
        return True

    def get_program_metrics(self, program_id: str) -> Dict[str, Any]:
        """Get program performance metrics"""
        program = self.programs.get(program_id)
        if not program:
            return {}
        
        metrics = {
            'program_id': program_id,
            'status': program.status.value,
            'total_submissions': program.total_submissions,
            'valid_submissions': program.valid_submissions,
            'validity_rate': program.valid_submissions / max(program.total_submissions, 1),
            'total_rewards_paid': float(program.total_rewards_paid),
            'average_reward': float(program.total_rewards_paid) / max(program.valid_submissions, 1),
            'budget_utilization': float(program.total_rewards_paid) / float(program.total_budget) if program.total_budget else 0,
            'average_response_time': program.average_response_time,
            'program_age_days': (datetime.now() - program.created_date).days,
            'scope_items_count': len(program.scope_items),
            'invited_researchers': len(program.invited_researchers)
        }
        
        return metrics

    def search_programs(self, query: str, filters: Dict[str, Any] = None) -> List[BugBountyProgram]:
        """Search programs by name, description, or tags"""
        programs = list(self.programs.values())
        
        # Text search
        if query:
            query_lower = query.lower()
            programs = [
                p for p in programs
                if query_lower in p.name.lower() or query_lower in p.description.lower()
            ]
        
        # Apply filters
        if filters:
            if 'min_reward' in filters:
                min_reward = Decimal(str(filters['min_reward']))
                programs = [
                    p for p in programs
                    if any(tier.max_reward >= min_reward for tier in p.reward_tiers)
                ]
            
            if 'scope_type' in filters:
                scope_type = ScopeType(filters['scope_type'])
                programs = [
                    p for p in programs
                    if any(item.scope_type == scope_type for item in p.scope_items)
                ]
        
        return programs

    def export_program_data(self, program_id: str) -> Optional[Dict[str, Any]]:
        """Export program data for backup or migration"""
        program = self.programs.get(program_id)
        if not program:
            return None
        
        return {
            'program_id': program.program_id,
            'name': program.name,
            'organization_id': program.organization_id,
            'description': program.description,
            'status': program.status.value,
            'scope_items': [
                {
                    'scope_id': item.scope_id,
                    'scope_type': item.scope_type.value,
                    'target': item.target,
                    'description': item.description,
                    'in_scope': item.in_scope,
                    'max_severity': item.max_severity.value if item.max_severity else None,
                    'special_instructions': item.special_instructions,
                    'excluded_vulnerabilities': item.excluded_vulnerabilities
                }
                for item in program.scope_items
            ],
            'reward_tiers': [
                {
                    'severity': tier.severity.value,
                    'min_reward': float(tier.min_reward),
                    'max_reward': float(tier.max_reward),
                    'currency': tier.currency,
                    'bonus_conditions': tier.bonus_conditions
                }
                for tier in program.reward_tiers
            ],
            'total_budget': float(program.total_budget) if program.total_budget else None,
            'budget_remaining': float(program.budget_remaining) if program.budget_remaining else None,
            'start_date': program.start_date.isoformat() if program.start_date else None,
            'end_date': program.end_date.isoformat() if program.end_date else None,
            'created_date': program.created_date.isoformat(),
            'updated_date': program.updated_date.isoformat(),
            'private_program': program.private_program,
            'invited_researchers': list(program.invited_researchers),
            'settings': {
                'auto_validate_scans': program.auto_validate_scans,
                'require_proof_of_concept': program.require_proof_of_concept,
                'allow_automated_scanning': program.allow_automated_scanning,
                'safe_harbor_enabled': program.safe_harbor_enabled
            },
            'policies': {
                'disclosure_policy': program.disclosure_policy,
                'submission_requirements': program.submission_requirements,
                'prohibited_activities': program.prohibited_activities
            },
            'statistics': {
                'total_submissions': program.total_submissions,
                'valid_submissions': program.valid_submissions,
                'total_rewards_paid': float(program.total_rewards_paid),
                'average_response_time': program.average_response_time
            },
            'contact': {
                'contact_email': program.contact_email,
                'security_team': program.security_team
            }
        }

# Example usage
def example_usage():
    """Example of how to use the ProgramManager"""
    manager = ProgramManager()
    
    # Create a new program
    program = manager.create_program(
        name="Acme Corp Web Security Program",
        organization_id="org_123",
        description="Bug bounty program for Acme Corp's web applications",
        total_budget=Decimal('50000.00'),
        contact_email="security@acme.com"
    )
    
    print(f"Created program: {program.program_id}")
    
    # Add scope items
    scope_item = ScopeItem(
        scope_id="",  # Will be generated
        scope_type=ScopeType.WEB_APPLICATION,
        target="https://app.acme.com",
        description="Main web application",
        max_severity=VulnSeverity.CRITICAL
    )
    
    manager.add_scope_item(program.program_id, scope_item)
    
    # Update reward tiers
    manager.update_reward_tier(
        program.program_id,
        VulnSeverity.CRITICAL,
        Decimal('10000.00'),
        Decimal('25000.00')
    )
    
    # Activate the program
    manager.activate_program(program.program_id)
    
    # Get program metrics
    metrics = manager.get_program_metrics(program.program_id)
    print(f"Program metrics: {json.dumps(metrics, indent=2)}")
    
    # Search programs
    results = manager.search_programs("web", {"min_reward": 5000})
    print(f"Search results: {len(results)} programs found")

if __name__ == "__main__":
    example_usage()