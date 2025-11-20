#!/usr/bin/env python3
"""
API Data Models
Pydantic models for request/response validation
Author: AI Cybersecurity Team
Version: 1.0.0
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field, validator


# ========================================
# Health Check Models
# ========================================

class HealthResponse(BaseModel):
    """Basic health check response"""
    status: str = Field(..., description="Health status: healthy, degraded, or unhealthy")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    message: str = Field(..., description="Health status message")


class SystemHealth(BaseModel):
    """Detailed system health metrics"""
    status: str
    cpu_usage: float = Field(..., ge=0, le=100)
    memory_usage: float = Field(..., ge=0, le=100)
    disk_usage: float = Field(..., ge=0, le=100)
    uptime_seconds: int = Field(..., ge=0)
    models_loaded: int = Field(..., ge=0)
    api_endpoints_active: int = Field(..., ge=0)
    health_score: float = Field(..., ge=0, le=1)
    last_updated: str


# ========================================
# Log Analysis Models
# ========================================

class LogEntry(BaseModel):
    """Single log entry for analysis"""
    timestamp: Optional[str] = Field(None, description="Log timestamp")
    source: Optional[str] = Field(None, description="Log source (system, application, etc.)")
    message: str = Field(..., description="Log message content")
    severity: Optional[str] = Field(None, description="Log severity level")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class LogAnalysisRequest(BaseModel):
    """Request for log analysis"""
    logs: List[LogEntry] = Field(..., min_items=1, description="List of log entries to analyze")
    analysis_type: str = Field(
        "comprehensive",
        description="Type of analysis: comprehensive, anomaly, security, performance"
    )
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)


class LogAnalysisResponse(BaseModel):
    """Response from log analysis"""
    success: bool
    analysis_id: str = Field(..., description="Unique analysis identifier")
    timestamp: str
    summary: Dict[str, Any] = Field(..., description="Analysis summary")
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    security_events: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    total_logs_analyzed: int


class LogClassificationRequest(BaseModel):
    """Request for log classification"""
    log_message: str = Field(..., min_length=1)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


class LogClassificationResponse(BaseModel):
    """Response from log classification"""
    category: str = Field(..., description="Classified category")
    confidence: float = Field(..., ge=0, le=1)
    severity: str = Field(..., description="Severity level: critical, high, medium, low, info")
    is_security_relevant: bool
    extracted_entities: Dict[str, List[str]] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)


# ========================================
# Threat Intelligence Models
# ========================================

class ThreatIndicator(BaseModel):
    """Threat indicator (IOC)"""
    type: str = Field(..., description="Indicator type: ip, domain, hash, url, email")
    value: str = Field(..., description="Indicator value")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0, le=1)
    tags: List[str] = Field(default_factory=list)


class ThreatReport(BaseModel):
    """Threat intelligence report"""
    title: str
    content: str = Field(..., min_length=10)
    source: Optional[str] = None
    date: Optional[str] = None
    indicators: List[ThreatIndicator] = Field(default_factory=list)


class ThreatIntelRequest(BaseModel):
    """Request for threat intelligence analysis"""
    report: ThreatReport
    analysis_depth: str = Field("standard", description="Analysis depth: quick, standard, deep")
    extract_iocs: bool = Field(True, description="Extract indicators of compromise")


class ThreatIntelResponse(BaseModel):
    """Response from threat intelligence analysis"""
    success: bool
    analysis_id: str
    timestamp: str
    threat_level: str = Field(..., description="Overall threat level: critical, high, medium, low")
    threat_actors: List[str] = Field(default_factory=list)
    attack_vectors: List[str] = Field(default_factory=list)
    affected_industries: List[str] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    summary: str
    recommendations: List[str] = Field(default_factory=list)
    related_threats: List[str] = Field(default_factory=list)


class IOCEnrichmentRequest(BaseModel):
    """Request for IOC enrichment"""
    indicators: List[ThreatIndicator] = Field(..., min_items=1)
    enrich_with: List[str] = Field(
        default_factory=lambda: ["reputation", "geolocation", "whois", "malware_families"],
        description="Enrichment sources to use"
    )


class IOCEnrichmentResponse(BaseModel):
    """Response from IOC enrichment"""
    success: bool
    enriched_indicators: List[Dict[str, Any]]
    timestamp: str


# ========================================
# Incident Analysis Models
# ========================================

class IncidentSeverity(str, Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    """Incident status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    """Security incident"""
    title: str = Field(..., min_length=3)
    description: str = Field(..., min_length=10)
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    occurred_at: Optional[str] = None
    detected_at: Optional[str] = None
    affected_systems: List[str] = Field(default_factory=list)
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentAnalysisRequest(BaseModel):
    """Request for incident analysis"""
    incident: Incident
    include_timeline: bool = Field(True)
    suggest_response: bool = Field(True)
    correlate_threats: bool = Field(True)


class TimelineEvent(BaseModel):
    """Single event in incident timeline"""
    timestamp: str
    event_type: str
    description: str
    severity: str
    source: Optional[str] = None


class ResponseAction(BaseModel):
    """Recommended response action"""
    priority: int = Field(..., ge=1, le=5)
    action: str
    description: str
    estimated_time: Optional[str] = None
    required_tools: List[str] = Field(default_factory=list)


class IncidentAnalysisResponse(BaseModel):
    """Response from incident analysis"""
    success: bool
    analysis_id: str
    timestamp: str
    incident_summary: str
    threat_assessment: Dict[str, Any]
    timeline: List[TimelineEvent] = Field(default_factory=list)
    root_cause: Optional[str] = None
    impact_analysis: Dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)
    recommended_actions: List[ResponseAction] = Field(default_factory=list)
    related_incidents: List[str] = Field(default_factory=list)
    containment_status: str
    estimated_damage: Optional[Dict[str, Any]] = None


# ========================================
# ML Prediction Models
# ========================================

class NetworkTrafficData(BaseModel):
    """Network traffic data for anomaly detection"""
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int = Field(..., ge=0, le=65535)
    destination_port: int = Field(..., ge=0, le=65535)
    protocol: str
    bytes_sent: int = Field(..., ge=0)
    bytes_received: int = Field(..., ge=0)
    packets_sent: int = Field(..., ge=0)
    packets_received: int = Field(..., ge=0)
    duration: float = Field(..., ge=0)
    flags: Optional[List[str]] = Field(default_factory=list)


class AnomalyDetectionRequest(BaseModel):
    """Request for anomaly detection"""
    traffic_data: List[NetworkTrafficData] = Field(..., min_items=1)
    sensitivity: float = Field(0.5, ge=0, le=1, description="Detection sensitivity")
    model_type: str = Field("isolation_forest", description="Model to use")


class AnomalyDetectionResponse(BaseModel):
    """Response from anomaly detection"""
    success: bool
    timestamp: str
    total_samples: int
    anomalies_detected: int
    anomaly_score: float = Field(..., ge=0, le=1)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    risk_level: str
    recommendations: List[str] = Field(default_factory=list)


class MalwareFeatures(BaseModel):
    """Features for malware classification"""
    file_hash: str
    file_size: int = Field(..., ge=0)
    file_type: str
    pe_characteristics: Optional[Dict[str, Any]] = None
    strings_analysis: Optional[Dict[str, Any]] = None
    entropy: Optional[float] = Field(None, ge=0, le=8)
    imports: Optional[List[str]] = Field(default_factory=list)
    sections: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class MalwareClassificationRequest(BaseModel):
    """Request for malware classification"""
    features: MalwareFeatures
    deep_analysis: bool = Field(False)


class MalwareClassificationResponse(BaseModel):
    """Response from malware classification"""
    success: bool
    timestamp: str
    is_malicious: bool
    confidence: float = Field(..., ge=0, le=1)
    malware_family: Optional[str] = None
    malware_type: Optional[str] = None
    threat_level: str
    capabilities: List[str] = Field(default_factory=list)
    yara_matches: List[str] = Field(default_factory=list)
    behavioral_indicators: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class UserBehaviorData(BaseModel):
    """User behavior data for risk scoring"""
    user_id: str
    timestamp: str
    activity_type: str
    resource_accessed: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = None
    login_time: Optional[str] = None
    failed_login_attempts: int = Field(0, ge=0)
    data_volume_transferred: Optional[int] = Field(None, ge=0)
    unusual_access_times: bool = False
    geographic_anomaly: bool = False


class UserRiskScoringRequest(BaseModel):
    """Request for user risk scoring"""
    behavior_data: List[UserBehaviorData] = Field(..., min_items=1)
    baseline_period_days: int = Field(30, ge=1, le=365)


class UserRiskScoringResponse(BaseModel):
    """Response from user risk scoring"""
    success: bool
    timestamp: str
    user_id: str
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: str = Field(..., description="Risk level: critical, high, medium, low")
    anomalies_detected: List[Dict[str, Any]] = Field(default_factory=list)
    behavior_changes: List[str] = Field(default_factory=list)
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    comparison_to_baseline: Dict[str, Any] = Field(default_factory=dict)


class AttackPredictionRequest(BaseModel):
    """Request for attack prediction"""
    historical_data: List[Dict[str, Any]] = Field(..., min_items=10)
    prediction_horizon: str = Field("24h", description="Prediction timeframe: 1h, 6h, 24h, 7d")
    threat_types: Optional[List[str]] = Field(None)


class AttackPredictionResponse(BaseModel):
    """Response from attack prediction"""
    success: bool
    timestamp: str
    prediction_timeframe: str
    attack_likelihood: float = Field(..., ge=0, le=1)
    predicted_attack_types: List[Dict[str, Any]] = Field(default_factory=list)
    high_risk_assets: List[str] = Field(default_factory=list)
    threat_trends: Dict[str, Any] = Field(default_factory=dict)
    preventive_measures: List[str] = Field(default_factory=list)
    confidence_interval: Dict[str, float] = Field(default_factory=dict)


# ========================================
# Generic Response Models
# ========================================

class ErrorResponse(BaseModel):
    """Error response"""
    success: bool = False
    error: str
    error_code: Optional[str] = None
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseModel):
    """Generic success response"""
    success: bool = True
    message: str
    timestamp: str
    data: Optional[Dict[str, Any]] = None


# ========================================
# Batch Processing Models
# ========================================

class BatchAnalysisRequest(BaseModel):
    """Request for batch analysis"""
    analysis_type: str = Field(
        ...,
        description="Type of analysis: logs, threats, incidents, anomalies"
    )
    items: List[Dict[str, Any]] = Field(..., min_items=1)
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)


class BatchAnalysisResponse(BaseModel):
    """Response from batch analysis"""
    success: bool
    batch_id: str
    timestamp: str
    total_items: int
    processed_items: int
    failed_items: int
    results: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
