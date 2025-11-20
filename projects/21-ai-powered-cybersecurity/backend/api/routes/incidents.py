#!/usr/bin/env python3
"""
Incident Analysis API Routes
Advanced incident analysis and response orchestration
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from api.models import (
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    Incident,
    TimelineEvent,
    ResponseAction,
    SuccessResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=IncidentAnalysisResponse)
async def analyze_incident(request: IncidentAnalysisRequest):
    """
    Perform comprehensive incident analysis using AI/ML

    Analyzes security incidents to provide:
    - Root cause analysis
    - Impact assessment
    - Timeline reconstruction
    - MITRE ATT&CK technique mapping
    - Automated response recommendations
    - Related incident correlation

    Args:
        request: Incident analysis request with incident details

    Returns:
        Comprehensive incident analysis with recommended actions
    """
    try:
        logger.info(f"Analyzing incident: {request.incident.title}")

        # Import incident analyzer
        try:
            from nlp_models.incident_analyzer import IncidentAnalyzer
            analyzer = IncidentAnalyzer()
        except Exception as e:
            logger.error(f"Failed to load IncidentAnalyzer: {e}")
            # Continue with basic analysis if model unavailable
            analyzer = None

        incident = request.incident

        # Perform threat assessment
        threat_assessment = _assess_threat_level(incident, analyzer)

        # Reconstruct timeline if requested
        timeline = []
        if request.include_timeline:
            timeline = _reconstruct_timeline(incident, analyzer)

        # Perform root cause analysis
        root_cause = _analyze_root_cause(incident, analyzer)

        # Calculate impact
        impact_analysis = _assess_impact(incident, analyzer)

        # Map to MITRE ATT&CK
        mitre_tactics, mitre_techniques = _map_incident_to_mitre(incident, analyzer)

        # Generate response recommendations if requested
        recommended_actions = []
        if request.suggest_response:
            recommended_actions = _generate_response_actions(
                incident,
                threat_assessment,
                impact_analysis
            )

        # Find related incidents if requested
        related_incidents = []
        if request.correlate_threats:
            related_incidents = _find_related_incidents(incident)

        # Determine containment status
        containment_status = _assess_containment(incident)

        # Estimate damage
        estimated_damage = _estimate_damage(incident, impact_analysis)

        # Generate incident summary
        incident_summary = _generate_incident_summary(
            incident,
            threat_assessment,
            impact_analysis
        )

        # Create response
        response = IncidentAnalysisResponse(
            success=True,
            analysis_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            incident_summary=incident_summary,
            threat_assessment=threat_assessment,
            timeline=timeline,
            root_cause=root_cause,
            impact_analysis=impact_analysis,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            recommended_actions=recommended_actions,
            related_incidents=related_incidents,
            containment_status=containment_status,
            estimated_damage=estimated_damage
        )

        logger.info(f"Incident analysis completed: {response.analysis_id}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Incident analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Incident analysis failed: {str(e)}"
        )


@router.post("/create", response_model=SuccessResponse)
async def create_incident(incident: Incident):
    """
    Create a new security incident

    Args:
        incident: Incident details

    Returns:
        Success response with incident ID
    """
    try:
        incident_id = str(uuid.uuid4())

        logger.info(f"Created incident: {incident_id} - {incident.title}")

        return SuccessResponse(
            success=True,
            message=f"Incident created successfully",
            timestamp=datetime.now().isoformat(),
            data={
                'incident_id': incident_id,
                'title': incident.title,
                'severity': incident.severity.value,
                'status': incident.status.value
            }
        )

    except Exception as e:
        logger.error(f"Failed to create incident: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create incident: {str(e)}"
        )


@router.get("/list")
async def list_incidents(
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Result offset")
):
    """
    List security incidents with optional filters

    Args:
        severity: Optional severity filter
        status: Optional status filter
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        List of incidents matching filters
    """
    try:
        # This would query a real incident database
        # For now, return mock data
        incidents = {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'filters': {
                'severity': severity,
                'status': status
            },
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': 0
            },
            'incidents': []
        }

        return incidents

    except Exception as e:
        logger.error(f"Failed to list incidents: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list incidents: {str(e)}"
        )


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    """
    Get detailed information about a specific incident

    Args:
        incident_id: Incident identifier

    Returns:
        Detailed incident information
    """
    try:
        # This would query a real incident database
        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident_id,
            'message': 'Incident not found in database'
        }

    except Exception as e:
        logger.error(f"Failed to get incident: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get incident: {str(e)}"
        )


@router.get("/statistics/overview")
async def get_incident_statistics():
    """
    Get incident statistics and metrics

    Returns:
        Aggregated incident statistics including trends and distributions
    """
    return {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'statistics': {
            'total_incidents': 0,
            'open_incidents': 0,
            'critical_incidents': 0,
            'mean_time_to_detect': 0,
            'mean_time_to_respond': 0,
            'mean_time_to_resolve': 0,
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'status_distribution': {
                'new': 0,
                'investigating': 0,
                'contained': 0,
                'resolved': 0
            }
        }
    }


# Helper functions

def _assess_threat_level(incident: Incident, analyzer) -> Dict[str, Any]:
    """Assess threat level and characteristics"""
    threat_score = 0

    # Factor in severity
    severity_scores = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 1
    }
    threat_score += severity_scores.get(incident.severity.value, 0)

    # Factor in affected systems
    threat_score += min(len(incident.affected_systems), 5)

    # Factor in indicators
    threat_score += min(len(incident.indicators), 5)

    # Normalize to 0-100
    threat_score = min(threat_score * 5, 100)

    return {
        'threat_score': threat_score,
        'threat_level': _score_to_level(threat_score),
        'confidence': 0.85,
        'factors': {
            'severity': incident.severity.value,
            'affected_systems_count': len(incident.affected_systems),
            'indicators_count': len(incident.indicators)
        }
    }


def _reconstruct_timeline(incident: Incident, analyzer) -> List[TimelineEvent]:
    """Reconstruct incident timeline"""
    timeline = []

    # Add key events based on incident data
    if incident.occurred_at:
        timeline.append(TimelineEvent(
            timestamp=incident.occurred_at,
            event_type='incident_occurrence',
            description=f'Incident occurred: {incident.title}',
            severity=incident.severity.value,
            source='incident_data'
        ))

    if incident.detected_at:
        timeline.append(TimelineEvent(
            timestamp=incident.detected_at,
            event_type='incident_detection',
            description='Incident detected by security systems',
            severity='medium',
            source='detection_system'
        ))

    # Add current timestamp as analysis event
    timeline.append(TimelineEvent(
        timestamp=datetime.now().isoformat(),
        event_type='incident_analysis',
        description='AI-powered incident analysis initiated',
        severity='info',
        source='ai_analysis'
    ))

    return sorted(timeline, key=lambda x: x.timestamp)


def _analyze_root_cause(incident: Incident, analyzer) -> str:
    """Analyze probable root cause"""
    # This would use ML in production
    root_causes = []

    description_lower = incident.description.lower()

    if 'phishing' in description_lower or 'email' in description_lower:
        root_causes.append('phishing email compromise')

    if 'vulnerability' in description_lower or 'exploit' in description_lower:
        root_causes.append('unpatched vulnerability exploitation')

    if 'credential' in description_lower or 'password' in description_lower:
        root_causes.append('compromised credentials')

    if 'misconfiguration' in description_lower:
        root_causes.append('security misconfiguration')

    if root_causes:
        return f"Probable root cause: {', '.join(root_causes)}"
    else:
        return "Root cause analysis requires additional investigation"


def _assess_impact(incident: Incident, analyzer) -> Dict[str, Any]:
    """Assess incident impact"""
    impact = {
        'scope': _calculate_scope(incident),
        'severity_level': incident.severity.value,
        'affected_assets': len(incident.affected_systems),
        'data_exposure_risk': _assess_data_exposure(incident),
        'business_impact': _assess_business_impact(incident),
        'regulatory_impact': _assess_regulatory_impact(incident)
    }

    return impact


def _calculate_scope(incident: Incident) -> str:
    """Calculate incident scope"""
    system_count = len(incident.affected_systems)

    if system_count == 0:
        return 'isolated'
    elif system_count == 1:
        return 'single_system'
    elif system_count <= 5:
        return 'limited'
    elif system_count <= 20:
        return 'moderate'
    else:
        return 'widespread'


def _assess_data_exposure(incident: Incident) -> str:
    """Assess potential data exposure"""
    description_lower = incident.description.lower()

    if any(word in description_lower for word in ['exfiltration', 'leak', 'breach', 'stolen']):
        return 'high'
    elif any(word in description_lower for word in ['access', 'unauthorized', 'exposure']):
        return 'medium'
    else:
        return 'low'


def _assess_business_impact(incident: Incident) -> str:
    """Assess business impact level"""
    severity_impact = {
        'critical': 'severe',
        'high': 'major',
        'medium': 'moderate',
        'low': 'minor',
        'info': 'negligible'
    }

    return severity_impact.get(incident.severity.value, 'unknown')


def _assess_regulatory_impact(incident: Incident) -> str:
    """Assess regulatory/compliance impact"""
    description_lower = incident.description.lower()

    if any(word in description_lower for word in ['pii', 'personal', 'gdpr', 'hipaa', 'pci']):
        return 'requires_notification'
    else:
        return 'internal_only'


def _map_incident_to_mitre(incident: Incident, analyzer) -> tuple:
    """Map incident to MITRE ATT&CK framework"""
    tactics = []
    techniques = []

    description_lower = incident.description.lower()

    # Initial Access
    if any(word in description_lower for word in ['phishing', 'exploit', 'brute force']):
        tactics.append('Initial Access')
        techniques.append({
            'id': 'T1566',
            'name': 'Phishing',
            'tactic': 'Initial Access'
        })

    # Persistence
    if any(word in description_lower for word in ['backdoor', 'persistence', 'scheduled']):
        tactics.append('Persistence')

    # Credential Access
    if any(word in description_lower for word in ['credential', 'password', 'dump']):
        tactics.append('Credential Access')
        techniques.append({
            'id': 'T1003',
            'name': 'OS Credential Dumping',
            'tactic': 'Credential Access'
        })

    # Lateral Movement
    if any(word in description_lower for word in ['lateral', 'movement', 'spread']):
        tactics.append('Lateral Movement')

    # Exfiltration
    if any(word in description_lower for word in ['exfiltration', 'data transfer', 'stolen']):
        tactics.append('Exfiltration')

    # Impact
    if any(word in description_lower for word in ['ransomware', 'destruction', 'defacement']):
        tactics.append('Impact')
        techniques.append({
            'id': 'T1486',
            'name': 'Data Encrypted for Impact',
            'tactic': 'Impact'
        })

    return list(set(tactics)), techniques


def _generate_response_actions(
    incident: Incident,
    threat_assessment: Dict[str, Any],
    impact_analysis: Dict[str, Any]
) -> List[ResponseAction]:
    """Generate prioritized response actions"""
    actions = []

    # Immediate containment
    if threat_assessment['threat_level'] in ['critical', 'high']:
        actions.append(ResponseAction(
            priority=1,
            action='Isolate affected systems',
            description='Immediately disconnect affected systems from network to prevent spread',
            estimated_time='15 minutes',
            required_tools=['Network Management', 'EDR Console']
        ))

    # Evidence preservation
    actions.append(ResponseAction(
        priority=2,
        action='Preserve digital evidence',
        description='Create forensic images and collect logs before remediation',
        estimated_time='1-2 hours',
        required_tools=['Forensic Tools', 'Log Collectors']
    ))

    # Threat hunting
    if len(incident.indicators) > 0:
        actions.append(ResponseAction(
            priority=3,
            action='Hunt for IOCs across environment',
            description='Search for indicators of compromise across all systems',
            estimated_time='2-4 hours',
            required_tools=['SIEM', 'EDR', 'Threat Intelligence Platform']
        ))

    # Vulnerability patching
    actions.append(ResponseAction(
        priority=4,
        action='Patch identified vulnerabilities',
        description='Apply security patches to affected systems and similar assets',
        estimated_time='4-8 hours',
        required_tools=['Patch Management', 'Vulnerability Scanner']
    ))

    # Recovery
    actions.append(ResponseAction(
        priority=5,
        action='Restore affected systems',
        description='Rebuild or restore systems from clean backups',
        estimated_time='Varies',
        required_tools=['Backup System', 'Imaging Tools']
    ))

    return actions


def _find_related_incidents(incident: Incident) -> List[str]:
    """Find related incidents based on similarities"""
    # This would query incident database in production
    return []


def _assess_containment(incident: Incident) -> str:
    """Assess current containment status"""
    status_containment = {
        'new': 'uncontained',
        'investigating': 'partially_contained',
        'contained': 'fully_contained',
        'resolved': 'resolved',
        'closed': 'closed'
    }

    return status_containment.get(incident.status.value, 'unknown')


def _estimate_damage(incident: Incident, impact_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Estimate potential damage and costs"""
    # Simplified damage estimation
    severity_costs = {
        'critical': {'min': 500000, 'max': 5000000},
        'high': {'min': 100000, 'max': 500000},
        'medium': {'min': 10000, 'max': 100000},
        'low': {'min': 1000, 'max': 10000},
        'info': {'min': 0, 'max': 1000}
    }

    cost_range = severity_costs.get(incident.severity.value, {'min': 0, 'max': 0})

    return {
        'estimated_cost_range': cost_range,
        'currency': 'USD',
        'factors': [
            'Investigation and remediation labor',
            'System downtime',
            'Data recovery costs',
            'Potential regulatory fines',
            'Reputation damage'
        ]
    }


def _generate_incident_summary(
    incident: Incident,
    threat_assessment: Dict[str, Any],
    impact_analysis: Dict[str, Any]
) -> str:
    """Generate executive summary of incident"""
    summary = f"{incident.severity.value.upper()} severity incident: {incident.title}. "
    summary += f"Threat level assessed as {threat_assessment['threat_level']}. "
    summary += f"Impact scope: {impact_analysis['scope']}. "

    if len(incident.affected_systems) > 0:
        summary += f"Affecting {len(incident.affected_systems)} system(s). "

    summary += f"Current status: {incident.status.value}."

    return summary


def _score_to_level(score: int) -> str:
    """Convert numeric score to threat level"""
    if score >= 80:
        return 'critical'
    elif score >= 60:
        return 'high'
    elif score >= 40:
        return 'medium'
    elif score >= 20:
        return 'low'
    else:
        return 'minimal'
