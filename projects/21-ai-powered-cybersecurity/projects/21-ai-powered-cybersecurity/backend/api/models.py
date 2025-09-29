#!/usr/bin/env python3
"""
API Data Models - Pydantic schemas for request/response validation
Author: AI Cybersecurity Team
Version: 1.0.0
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field, validator
from enum import Enum

# Enums
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

class ThreatLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class LogClassification(str, Enum):
    NORMAL = "normal"
    SECURITY_EVENT = "security_event"
    SECURITY_ALERT = "security_alert"

class PriorityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    MUTEX = "mutex"
    BITCOIN_ADDRESS = "bitcoin_address"

class MalwareFamily(str, Enum):
    BANKING_TROJAN = "banking_trojan"
    RANSOMWARE = "ransomware"
    BACKDOOR = "backdoor"
    APT_MALWARE = "apt_malware"
    COMMODITY_MALWARE = "commodity_malware"
    UNKNOWN = "unknown"

class RecommendationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

# Base response model
class APIResponse(BaseModel):
    success: bool = Field(True, description="Request success status")
    message: Optional[str] = Field(None, description="Response message")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Response timestamp")

class PaginatedResponse(BaseModel):
    total: int = Field(..., description="Total number of items")
    page: int = Field(1, description="Current page number")
    per_page: int = Field(10, description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")

# Log Analysis Models
class LogEntryRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="Log entry text to analyze")
    source: Optional[str] = Field(None, description="Log source identifier")

class BatchLogRequest(BaseModel):
    log_entries: List[str] = Field(..., min_items=1, max_items=100, description="List of log entries to analyze")
    source: Optional[str] = Field(None, description="Log source identifier")

class IOCContext(BaseModel):
    geolocation: Optional[str] = None
    asn: Optional[str] = None
    reputation: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    dns_records: Optional[List[str]] = None
    file_type: Optional[str] = None
    size: Optional[str] = None
    signature_status: Optional[str] = None

class IOC(BaseModel):
    value: str = Field(..., description="IOC value")
    type: IOCType = Field(..., description="IOC type")
    first_seen: str = Field(default_factory=lambda: datetime.now().isoformat(), description="First seen timestamp")
    confidence: float = Field(..., ge=0.0, le=1.0, description="IOC confidence score")
    tags: List[str] = Field(default_factory=list, description="IOC tags")
    context: Optional[IOCContext] = Field(None, description="Additional IOC context")

class EntityMatch(BaseModel):
    text: str = Field(..., description="Matched entity text")
    start: int = Field(..., ge=0, description="Start position in text")
    end: int = Field(..., ge=0, description="End position in text")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Entity confidence score")

class SeverityAssessment(BaseModel):
    severity: SeverityLevel = Field(..., description="Assessed severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Severity confidence score")
    scores: Dict[SeverityLevel, float] = Field(..., description="Individual severity scores")

class ThreatAnalysis(BaseModel):
    threat_level: ThreatLevel = Field(..., description="Overall threat level")
    total_score: float = Field(..., ge=0.0, description="Total threat score")
    indicators: Dict[str, float] = Field(..., description="Threat indicator scores")

class MLPredictions(BaseModel):
    log_type: Dict[str, Union[LogClassification, float]] = Field(..., description="Log type prediction")
    priority: Dict[str, Union[PriorityLevel, float]] = Field(..., description="Priority prediction")

class LogAnalysisResult(BaseModel):
    entry_id: str = Field(..., description="Log entry identifier")
    original_text: str = Field(..., description="Original log text")
    processed_text: str = Field(..., description="Processed log text")
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Analysis timestamp")
    iocs: Dict[IOCType, List[str]] = Field(default_factory=dict, description="Extracted IOCs")
    entities: Dict[str, List[EntityMatch]] = Field(default_factory=dict, description="Extracted entities")
    severity: SeverityAssessment = Field(..., description="Severity assessment")
    threat_analysis: ThreatAnalysis = Field(..., description="Threat analysis results")
    ml_predictions: Optional[MLPredictions] = Field(None, description="ML model predictions")

class LogAnalysisResponse(APIResponse):
    data: LogAnalysisResult = Field(..., description="Analysis result")

class BatchLogAnalysisResponse(APIResponse):
    data: List[LogAnalysisResult] = Field(..., description="Batch analysis results")

# Threat Intelligence Models
class ThreatReportRequest(BaseModel):
    content: str = Field(..., min_length=10, max_length=50000, description="Threat report content")
    title: Optional[str] = Field(None, description="Report title")
    source: Optional[str] = Field(None, description="Report source")

class TTP(BaseModel):
    tactic: str = Field(..., description="MITRE ATT&CK tactic")
    technique: str = Field(..., description="MITRE ATT&CK technique")
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    description: str = Field(..., description="Technique description")
    indicators: List[str] = Field(default_factory=list, description="Technique indicators")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Technique confidence")

class ThreatAttribution(BaseModel):
    attributed_actor: Optional[str] = Field(None, description="Attributed threat actor")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Attribution confidence")
    all_scores: Dict[str, float] = Field(default_factory=dict, description="All actor scores")
    attribution_method: str = Field(..., description="Attribution method used")

class MalwareClassification(BaseModel):
    malware_family: MalwareFamily = Field(..., description="Classified malware family")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Classification confidence")
    all_scores: Dict[MalwareFamily, float] = Field(default_factory=dict, description="All family scores")

class ThreatMLPredictions(BaseModel):
    report_type: Dict[str, Union[str, float]] = Field(..., description="Report type prediction")
    intelligence_confidence: Dict[str, Union[str, float]] = Field(..., description="Intelligence confidence prediction")
    campaign_cluster: int = Field(..., description="Campaign cluster ID")

class ThreatIntelAnalysis(BaseModel):
    report_id: str = Field(..., description="Report identifier")
    original_text: str = Field(..., description="Original report text")
    processed_text: str = Field(..., description="Processed report text")
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Analysis timestamp")
    iocs: Dict[IOCType, List[str]] = Field(default_factory=dict, description="Extracted IOCs")
    enriched_iocs: Dict[IOCType, Dict[str, IOC]] = Field(default_factory=dict, description="Enriched IOCs")
    ttps: List[TTP] = Field(default_factory=list, description="Extracted TTPs")
    attribution: ThreatAttribution = Field(..., description="Threat attribution")
    malware_classification: MalwareClassification = Field(..., description="Malware classification")
    ml_predictions: Optional[ThreatMLPredictions] = Field(None, description="ML predictions")

class ThreatIntelResponse(APIResponse):
    data: ThreatIntelAnalysis = Field(..., description="Threat intelligence analysis")

# Incident Analysis Models
class IncidentCorrelation(BaseModel):
    shared_iocs: List[str] = Field(default_factory=list, description="Shared IOCs between sources")
    threat_actor_mentions: List[Dict[str, Union[str, float]]] = Field(default_factory=list, description="Threat actor mentions")
    technique_overlap: List[str] = Field(default_factory=list, description="Overlapping techniques")
    severity_correlation: Dict[str, Any] = Field(default_factory=dict, description="Severity correlation data")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Overall correlation confidence")

class SecurityRecommendation(BaseModel):
    priority: RecommendationPriority = Field(..., description="Recommendation priority")
    category: str = Field(..., description="Recommendation category")
    action: str = Field(..., description="Recommended action")
    details: str = Field(..., description="Recommendation details")

class SecurityIncident(BaseModel):
    incident_id: str = Field(..., description="Incident identifier")
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Analysis timestamp")
    log_analysis: List[LogAnalysisResult] = Field(default_factory=list, description="Log analysis results")
    threat_intelligence: List[ThreatIntelAnalysis] = Field(default_factory=list, description="Threat intel results")
    correlation: IncidentCorrelation = Field(..., description="Correlation analysis")
    recommendations: List[SecurityRecommendation] = Field(default_factory=list, description="Security recommendations")

class IncidentRequest(BaseModel):
    log_entries: List[str] = Field(..., min_items=1, description="Log entries for analysis")
    threat_reports: List[str] = Field(default_factory=list, description="Threat reports for analysis")

class IncidentResponse(APIResponse):
    data: SecurityIncident = Field(..., description="Incident analysis results")

# Health and Status Models
class ModelStatus(BaseModel):
    name: str = Field(..., description="Model name")
    status: str = Field(..., description="Model status")
    last_loaded: Optional[str] = Field(None, description="Last loaded timestamp")
    memory_usage_mb: Optional[float] = Field(None, description="Memory usage in MB")
    accuracy: Optional[float] = Field(None, description="Model accuracy")

class HealthStatus(BaseModel):
    status: str = Field(..., description="Overall health status")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Health check timestamp")
    uptime: str = Field(..., description="Service uptime")
    models: List[ModelStatus] = Field(default_factory=list, description="ML model statuses")
    system: Dict[str, Any] = Field(default_factory=dict, description="System information")

class HealthResponse(APIResponse):
    data: HealthStatus = Field(..., description="Health status data")

# File Upload Models
class FileUploadResponse(APIResponse):
    filename: str = Field(..., description="Uploaded filename")
    size: int = Field(..., description="File size in bytes")
    content_type: str = Field(..., description="File content type")
    processing_id: str = Field(..., description="Processing job ID")

# Error Models
class ErrorResponse(BaseModel):
    success: bool = Field(False, description="Request success status")
    error: str = Field(..., description="Error message")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")
    path: Optional[str] = Field(None, description="Request path")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")