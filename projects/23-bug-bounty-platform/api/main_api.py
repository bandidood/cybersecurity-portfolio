#!/usr/bin/env python3
"""
Bug Bounty Platform REST API
Main API endpoints for the bug bounty platform
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta
from decimal import Decimal
import json
import asyncio

# Import our platform modules
import sys
sys.path.append('..')
from platform.bounty_program import (
    ProgramManager, BugBountyProgram, ScopeItem, RewardTier,
    ProgramStatus, ScopeType, VulnSeverity as ProgramSeverity
)
from platform.vulnerability_reports import (
    ReportManager, VulnerabilityReport, VulnerabilityType, 
    Severity, ReportStatus, ValidationResult
)
from scanners.scan_engine import (
    ScanEngine, ScanConfiguration, ScanType, ScanStatus
)

# Initialize FastAPI app
app = FastAPI(
    title="Bug Bounty Platform API",
    description="REST API for managing bug bounty programs and vulnerability reports",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
program_manager = ProgramManager()
report_manager = ReportManager()
scan_engine = ScanEngine()

# Security
security = HTTPBearer()

# Global state
authenticated_users = {}  # Simple in-memory auth for demo

# Pydantic models for requests/responses
class CreateProgramRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    organization_id: str
    description: str = Field(..., min_length=1, max_length=2000)
    total_budget: Optional[float] = None
    private_program: bool = False
    contact_email: str

class ScopeItemRequest(BaseModel):
    scope_type: str
    target: str
    description: str
    in_scope: bool = True
    max_severity: Optional[str] = None
    special_instructions: Optional[str] = None
    excluded_vulnerabilities: List[str] = []

class RewardTierRequest(BaseModel):
    severity: str
    min_reward: float
    max_reward: float
    currency: str = "USD"

class SubmitReportRequest(BaseModel):
    program_id: str
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=10, max_length=10000)
    vulnerability_type: str
    severity: str
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    proof_of_concept: Optional[str] = None
    impact_description: str = ""
    remediation_suggestion: Optional[str] = None

class ValidateReportRequest(BaseModel):
    result: str
    notes: str
    step_name: str = "manual_validation"

class ScanRequest(BaseModel):
    scan_type: str
    target: str
    name: Optional[str] = None
    description: Optional[str] = None
    # Web scan options
    web_depth: int = 2
    web_max_pages: int = 50
    include_subdomains: bool = False
    # Network scan options
    ports: Optional[List[int]] = None
    timeout: int = 5
    service_detection: bool = True

class UserResponse(BaseModel):
    user_id: str
    username: str
    role: str
    permissions: List[str]

# Authentication helper
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user"""
    token = credentials.credentials
    user = authenticated_users.get(token)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application"""
    await scan_engine.start_engine()
    
    # Create demo users
    authenticated_users["admin-token"] = {
        "user_id": "admin_1",
        "username": "admin",
        "role": "admin",
        "organization_id": "org_demo",
        "permissions": ["all"]
    }
    
    authenticated_users["researcher-token"] = {
        "user_id": "researcher_1", 
        "username": "researcher",
        "role": "researcher",
        "permissions": ["submit_reports", "view_programs"]
    }
    
    authenticated_users["triager-token"] = {
        "user_id": "triager_1",
        "username": "triager", 
        "role": "triager",
        "organization_id": "org_demo",
        "permissions": ["validate_reports", "manage_reports"]
    }

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await scan_engine.stop_engine()

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Authentication endpoints
@app.post("/auth/login")
async def login(username: str, password: str):
    """Login endpoint (demo implementation)"""
    # Demo login - in production, verify against database
    demo_users = {
        "admin": "admin-token",
        "researcher": "researcher-token", 
        "triager": "triager-token"
    }
    
    token = demo_users.get(username)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    user = authenticated_users[token]
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user)
    }

# Program management endpoints
@app.post("/programs", response_model=Dict[str, Any])
async def create_program(
    request: CreateProgramRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new bug bounty program"""
    if "admin" not in current_user["role"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create programs"
        )
    
    try:
        program = program_manager.create_program(
            name=request.name,
            organization_id=current_user.get("organization_id", request.organization_id),
            description=request.description,
            total_budget=Decimal(str(request.total_budget)) if request.total_budget else None,
            private_program=request.private_program,
            contact_email=request.contact_email
        )
        
        return {
            "program_id": program.program_id,
            "name": program.name,
            "status": program.status.value,
            "created_date": program.created_date.isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create program: {str(e)}"
        )

@app.get("/programs", response_model=List[Dict[str, Any]])
async def list_programs(
    status_filter: Optional[str] = None,
    public_only: bool = False,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List bug bounty programs"""
    try:
        status_enum = ProgramStatus(status_filter) if status_filter else None
        
        # Filter by organization for non-admin users
        org_id = None
        if current_user["role"] != "admin":
            org_id = current_user.get("organization_id")
        
        programs = program_manager.list_programs(
            organization_id=org_id,
            status=status_enum,
            public_only=public_only and current_user["role"] == "researcher"
        )
        
        result = []
        for program in programs:
            # Check access permissions
            if (program.private_program and 
                current_user["role"] == "researcher" and 
                not program_manager.can_researcher_access(program.program_id, current_user["user_id"])):
                continue
            
            result.append({
                "program_id": program.program_id,
                "name": program.name,
                "description": program.description,
                "status": program.status.value,
                "private_program": program.private_program,
                "total_budget": float(program.total_budget) if program.total_budget else None,
                "budget_remaining": float(program.budget_remaining) if program.budget_remaining else None,
                "total_submissions": program.total_submissions,
                "valid_submissions": program.valid_submissions,
                "created_date": program.created_date.isoformat(),
                "scope_items_count": len(program.scope_items),
                "reward_tiers_count": len(program.reward_tiers)
            })
        
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to list programs: {str(e)}"
        )

@app.get("/programs/{program_id}", response_model=Dict[str, Any])
async def get_program(
    program_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get program details"""
    program = program_manager.get_program(program_id)
    if not program:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Program not found"
        )
    
    # Check access permissions
    if (program.private_program and 
        current_user["role"] == "researcher" and 
        not program_manager.can_researcher_access(program_id, current_user["user_id"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to private program"
        )
    
    return {
        "program_id": program.program_id,
        "name": program.name,
        "description": program.description,
        "status": program.status.value,
        "private_program": program.private_program,
        "total_budget": float(program.total_budget) if program.total_budget else None,
        "budget_remaining": float(program.budget_remaining) if program.budget_remaining else None,
        "start_date": program.start_date.isoformat() if program.start_date else None,
        "end_date": program.end_date.isoformat() if program.end_date else None,
        "scope_items": [
            {
                "scope_id": item.scope_id,
                "scope_type": item.scope_type.value,
                "target": item.target,
                "description": item.description,
                "in_scope": item.in_scope,
                "max_severity": item.max_severity.value if item.max_severity else None,
                "special_instructions": item.special_instructions,
                "excluded_vulnerabilities": item.excluded_vulnerabilities
            }
            for item in program.scope_items
        ],
        "reward_tiers": [
            {
                "severity": tier.severity.value,
                "min_reward": float(tier.min_reward),
                "max_reward": float(tier.max_reward),
                "currency": tier.currency,
                "bonus_conditions": tier.bonus_conditions
            }
            for tier in program.reward_tiers
        ],
        "submission_requirements": program.submission_requirements,
        "prohibited_activities": program.prohibited_activities,
        "contact_email": program.contact_email,
        "statistics": {
            "total_submissions": program.total_submissions,
            "valid_submissions": program.valid_submissions,
            "total_rewards_paid": float(program.total_rewards_paid),
            "average_response_time": program.average_response_time
        }
    }

@app.post("/programs/{program_id}/activate")
async def activate_program(
    program_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Activate a program"""
    if "admin" not in current_user["role"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can activate programs"
        )
    
    try:
        success = program_manager.activate_program(program_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Program not found"
            )
        
        return {"message": "Program activated successfully"}
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.post("/programs/{program_id}/scope")
async def add_scope_item(
    program_id: str,
    request: ScopeItemRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Add scope item to program"""
    if "admin" not in current_user["role"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can modify program scope"
        )
    
    try:
        scope_item = ScopeItem(
            scope_id="",  # Will be generated
            scope_type=ScopeType(request.scope_type),
            target=request.target,
            description=request.description,
            in_scope=request.in_scope,
            max_severity=ProgramSeverity(request.max_severity) if request.max_severity else None,
            special_instructions=request.special_instructions,
            excluded_vulnerabilities=request.excluded_vulnerabilities
        )
        
        success = program_manager.add_scope_item(program_id, scope_item)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Program not found"
            )
        
        return {
            "message": "Scope item added successfully",
            "scope_id": scope_item.scope_id
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scope type or severity: {str(e)}"
        )

# Report management endpoints
@app.post("/reports", response_model=Dict[str, Any])
async def submit_report(
    request: SubmitReportRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Submit a vulnerability report"""
    if current_user["role"] not in ["researcher", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only researchers can submit reports"
        )
    
    try:
        # Validate program exists and is accessible
        program = program_manager.get_program(request.program_id)
        if not program:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Program not found"
            )
        
        if program.status != ProgramStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Program is not active"
            )
        
        # Check access for private programs
        if (program.private_program and 
            current_user["role"] == "researcher" and 
            not program_manager.can_researcher_access(request.program_id, current_user["user_id"])):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to private program"
            )
        
        report = report_manager.submit_report(
            program_id=request.program_id,
            researcher_id=current_user["user_id"],
            title=request.title,
            description=request.description,
            vulnerability_type=VulnerabilityType(request.vulnerability_type),
            severity=Severity(request.severity),
            affected_url=request.affected_url,
            affected_parameter=request.affected_parameter,
            proof_of_concept=request.proof_of_concept,
            impact_description=request.impact_description,
            remediation_suggestion=request.remediation_suggestion
        )
        
        return {
            "report_id": report.report_id,
            "status": report.status.value,
            "submitted_date": report.submitted_date.isoformat(),
            "priority_score": report.priority_score
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid vulnerability type or severity: {str(e)}"
        )

@app.get("/reports", response_model=List[Dict[str, Any]])
async def list_reports(
    program_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List vulnerability reports"""
    try:
        # Determine filtering based on user role
        researcher_id = None
        if current_user["role"] == "researcher":
            researcher_id = current_user["user_id"]
        
        # Filter by organization for triagers
        if current_user["role"] == "triager" and program_id:
            program = program_manager.get_program(program_id)
            if program and program.organization_id != current_user.get("organization_id"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this program's reports"
                )
        
        status_enum = ReportStatus(status_filter) if status_filter else None
        severity_enum = Severity(severity_filter) if severity_filter else None
        
        reports = report_manager.list_reports(
            program_id=program_id,
            researcher_id=researcher_id,
            status=status_enum,
            severity=severity_enum,
            limit=limit
        )
        
        result = []
        for report in reports:
            result.append({
                "report_id": report.report_id,
                "program_id": report.program_id,
                "title": report.title,
                "vulnerability_type": report.vulnerability_type.value,
                "severity": report.severity.value,
                "status": report.status.value,
                "validation_result": report.validation_result.value,
                "submitted_date": report.submitted_date.isoformat(),
                "last_updated": report.last_updated.isoformat(),
                "priority_score": report.priority_score,
                "reward_amount": float(report.reward_amount) if report.reward_amount else None,
                "reward_paid": report.reward_paid,
                "assigned_triager": report.assigned_triager,
                "comments_count": len(report.comments),
                "attachments_count": len(report.attachments)
            })
        
        return result
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status or severity: {str(e)}"
        )

@app.get("/reports/{report_id}", response_model=Dict[str, Any])
async def get_report(
    report_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get report details"""
    report = report_manager.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access permissions
    if (current_user["role"] == "researcher" and 
        report.researcher_id != current_user["user_id"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this report"
        )
    
    # Filter internal comments for researchers
    comments = []
    for comment in report.comments:
        if current_user["role"] == "researcher" and comment.is_internal:
            continue
        comments.append({
            "comment_id": comment.comment_id,
            "author_type": comment.author_type,
            "content": comment.content,
            "timestamp": comment.timestamp.isoformat(),
            "attachments": comment.attachments
        })
    
    return {
        "report_id": report.report_id,
        "program_id": report.program_id,
        "title": report.title,
        "description": report.description,
        "vulnerability_type": report.vulnerability_type.value,
        "severity": report.severity.value,
        "affected_url": report.affected_url,
        "affected_parameter": report.affected_parameter,
        "proof_of_concept": report.proof_of_concept,
        "impact_description": report.impact_description,
        "remediation_suggestion": report.remediation_suggestion,
        "status": report.status.value,
        "validation_result": report.validation_result.value,
        "submitted_date": report.submitted_date.isoformat(),
        "last_updated": report.last_updated.isoformat(),
        "triaged_date": report.triaged_date.isoformat() if report.triaged_date else None,
        "resolved_date": report.resolved_date.isoformat() if report.resolved_date else None,
        "priority_score": report.priority_score,
        "reward_amount": float(report.reward_amount) if report.reward_amount else None,
        "reward_currency": report.reward_currency,
        "reward_paid": report.reward_paid,
        "reward_date": report.reward_date.isoformat() if report.reward_date else None,
        "assigned_triager": report.assigned_triager,
        "cve_id": report.cve_id,
        "cvss_score": report.cvss_score,
        "duplicate_of": report.duplicate_of,
        "related_reports": list(report.related_reports),
        "comments": comments,
        "attachments": [
            {
                "file_id": att.file_id,
                "filename": att.filename,
                "file_size": att.file_size,
                "content_type": att.content_type,
                "upload_date": att.upload_date.isoformat(),
                "description": att.description,
                "is_proof_of_concept": att.is_proof_of_concept
            }
            for att in report.attachments
        ],
        "validation_steps": [
            {
                "step_id": step.step_id,
                "step_name": step.step_name,
                "result": step.result.value,
                "notes": step.notes,
                "timestamp": step.timestamp.isoformat(),
                "time_spent": step.time_spent
            }
            for step in report.validation_steps
        ]
    }

@app.post("/reports/{report_id}/validate")
async def validate_report(
    report_id: str,
    request: ValidateReportRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Validate a report"""
    if current_user["role"] not in ["triager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only triagers can validate reports"
        )
    
    try:
        result_enum = ValidationResult(request.result)
        
        success = report_manager.validate_report(
            report_id=report_id,
            validator_id=current_user["user_id"],
            result=result_enum,
            notes=request.notes,
            step_name=request.step_name
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )
        
        return {"message": "Report validated successfully"}
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid validation result: {str(e)}"
        )

@app.post("/reports/{report_id}/comments")
async def add_comment(
    report_id: str,
    content: str,
    is_internal: bool = False,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Add comment to report"""
    # Only allow internal comments for triagers/admins
    if is_internal and current_user["role"] == "researcher":
        is_internal = False
    
    comment_id = report_manager.add_comment(
        report_id=report_id,
        author_id=current_user["user_id"],
        author_type=current_user["role"],
        content=content,
        is_internal=is_internal
    )
    
    if not comment_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    return {
        "comment_id": comment_id,
        "message": "Comment added successfully"
    }

# Scan management endpoints
@app.post("/scans", response_model=Dict[str, Any])
async def submit_scan(
    request: ScanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Submit a new scan"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and triagers can submit scans"
        )
    
    try:
        scan_type_enum = ScanType(request.scan_type)
        
        config = ScanConfiguration(
            scan_id="",  # Will be generated
            scan_type=scan_type_enum,
            target=request.target,
            name=request.name,
            description=request.description,
            web_depth=request.web_depth,
            web_max_pages=request.web_max_pages,
            include_subdomains=request.include_subdomains,
            ports=request.ports,
            timeout=request.timeout,
            service_detection=request.service_detection
        )
        
        scan_id = await scan_engine.submit_scan(config)
        
        return {
            "scan_id": scan_id,
            "message": "Scan submitted successfully"
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan type: {str(e)}"
        )

@app.get("/scans", response_model=List[Dict[str, Any]])
async def list_scans(
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List scans"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and triagers can view scans"
        )
    
    try:
        # Get active and recent scans
        active_scans = await scan_engine.list_active_scans()
        history = await scan_engine.get_scan_history(limit)
        
        all_scans = active_scans + history
        
        result = []
        for scan in all_scans[-limit:]:
            result.append({
                "scan_id": scan.scan_id,
                "scan_type": scan.scan_type.value,
                "target": scan.target,
                "status": scan.status.value,
                "start_time": scan.start_time.isoformat(),
                "end_time": scan.end_time.isoformat() if scan.end_time else None,
                "duration": str(scan.duration) if scan.duration else None,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "pages_crawled": scan.pages_crawled,
                "hosts_scanned": scan.hosts_scanned,
                "services_found": scan.services_found,
                "error_message": scan.error_message
            })
        
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list scans: {str(e)}"
        )

@app.get("/scans/{scan_id}", response_model=Dict[str, Any])
async def get_scan_status(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get scan status and results"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and triagers can view scan results"
        )
    
    scan_result = await scan_engine.get_scan_status(scan_id)
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return {
        "scan_id": scan_result.scan_id,
        "scan_type": scan_result.scan_type.value,
        "target": scan_result.target,
        "status": scan_result.status.value,
        "start_time": scan_result.start_time.isoformat(),
        "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
        "duration": str(scan_result.duration) if scan_result.duration else None,
        "total_vulnerabilities": scan_result.total_vulnerabilities,
        "web_vulnerabilities": len(scan_result.web_vulnerabilities),
        "network_vulnerabilities": len(scan_result.network_vulnerabilities),
        "pages_crawled": scan_result.pages_crawled,
        "requests_sent": scan_result.requests_sent,
        "hosts_scanned": scan_result.hosts_scanned,
        "services_found": scan_result.services_found,
        "error_message": scan_result.error_message
    }

@app.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = "json",
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get detailed scan report"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and triagers can view scan reports"
        )
    
    report = scan_engine.generate_consolidated_report(scan_id, format)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan report not found"
        )
    
    if format == "json":
        return JSONResponse(content=json.loads(report))
    else:
        return {"report": report}

# Statistics endpoints
@app.get("/stats/programs/{program_id}")
async def get_program_stats(
    program_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get program statistics"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    program_stats = report_manager.get_program_stats(program_id)
    program_metrics = program_manager.get_program_metrics(program_id)
    
    return {
        "program_stats": program_stats,
        "program_metrics": program_metrics
    }

@app.get("/stats/researchers/{researcher_id}")
async def get_researcher_stats(
    researcher_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get researcher statistics"""
    # Users can only view their own stats unless admin
    if (current_user["role"] != "admin" and 
        current_user["user_id"] != researcher_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    stats = report_manager.get_researcher_stats(researcher_id)
    return {"researcher_stats": stats}

# Search endpoints
@app.get("/search/programs")
async def search_programs(
    q: str,
    min_reward: Optional[float] = None,
    scope_type: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Search programs"""
    filters = {}
    if min_reward:
        filters["min_reward"] = min_reward
    if scope_type:
        filters["scope_type"] = scope_type
    
    programs = program_manager.search_programs(q, filters)
    
    result = []
    for program in programs:
        # Check access for private programs
        if (program.private_program and 
            current_user["role"] == "researcher" and 
            not program_manager.can_researcher_access(program.program_id, current_user["user_id"])):
            continue
        
        result.append({
            "program_id": program.program_id,
            "name": program.name,
            "description": program.description[:200] + "..." if len(program.description) > 200 else program.description,
            "status": program.status.value,
            "total_submissions": program.total_submissions
        })
    
    return {"results": result}

@app.get("/search/reports")
async def search_reports(
    q: str,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Search reports"""
    if current_user["role"] not in ["admin", "triager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and triagers can search all reports"
        )
    
    filters = {}
    if severity:
        filters["severity"] = severity
    if status_filter:
        filters["status"] = status_filter
    if vulnerability_type:
        filters["vulnerability_type"] = vulnerability_type
    
    reports = report_manager.search_reports(q, filters, limit)
    
    result = []
    for report in reports:
        result.append({
            "report_id": report.report_id,
            "title": report.title,
            "vulnerability_type": report.vulnerability_type.value,
            "severity": report.severity.value,
            "status": report.status.value,
            "submitted_date": report.submitted_date.isoformat(),
            "priority_score": report.priority_score
        })
    
    return {"results": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)