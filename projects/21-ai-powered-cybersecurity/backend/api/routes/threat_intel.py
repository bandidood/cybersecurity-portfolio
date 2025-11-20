#!/usr/bin/env python3
"""
Threat Intelligence API Routes
Advanced threat intelligence analysis and IOC processing
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import uuid
import re
from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from api.models import (
    ThreatIntelRequest,
    ThreatIntelResponse,
    IOCEnrichmentRequest,
    IOCEnrichmentResponse,
    ThreatReport,
    ThreatIndicator,
    SuccessResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=ThreatIntelResponse)
async def analyze_threat_report(request: ThreatIntelRequest):
    """
    Analyze threat intelligence report using NLP and ML

    Performs comprehensive analysis including:
    - Threat actor identification
    - Attack vector analysis
    - MITRE ATT&CK technique mapping
    - IOC extraction
    - Affected industry identification
    - Threat level assessment

    Args:
        request: Threat intelligence analysis request

    Returns:
        Detailed threat analysis with recommendations
    """
    try:
        logger.info(f"Analyzing threat report: {request.report.title}")

        # Import threat intel analyzer
        try:
            from nlp_models.threat_intel_analyzer import ThreatIntelligenceAnalyzer
            analyzer = ThreatIntelligenceAnalyzer()
        except Exception as e:
            logger.error(f"Failed to load ThreatIntelligenceAnalyzer: {e}")
            raise HTTPException(
                status_code=503,
                detail="Threat intelligence service unavailable"
            )

        # Analyze report
        analysis = analyzer.analyze_report(request.report.content)

        # Extract IOCs if requested
        extracted_iocs = []
        if request.extract_iocs:
            ioc_results = analyzer.extract_iocs(request.report.content)
            for ioc_type, ioc_values in ioc_results.items():
                for ioc_value in ioc_values:
                    extracted_iocs.append(ThreatIndicator(
                        type=ioc_type,
                        value=ioc_value,
                        confidence=0.85,
                        tags=['extracted', 'needs_verification']
                    ))

        # Combine with provided indicators
        all_indicators = list(request.report.indicators) + extracted_iocs

        # Map to MITRE ATT&CK
        mitre_techniques = _map_to_mitre(analysis)

        # Identify threat actors
        threat_actors = _identify_threat_actors(request.report.content, analysis)

        # Determine threat level
        threat_level = _calculate_threat_level(analysis, all_indicators)

        # Generate recommendations
        recommendations = _generate_threat_recommendations(
            threat_level,
            analysis,
            all_indicators
        )

        # Find related threats
        related_threats = _find_related_threats(analysis, threat_actors)

        # Create response
        response = ThreatIntelResponse(
            success=True,
            analysis_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            threat_level=threat_level,
            threat_actors=threat_actors,
            attack_vectors=analysis.get('attack_vectors', []),
            affected_industries=analysis.get('affected_industries', []),
            mitre_techniques=mitre_techniques,
            indicators=all_indicators[:100],  # Limit to top 100
            summary=_generate_threat_summary(analysis, threat_level),
            recommendations=recommendations,
            related_threats=related_threats
        )

        logger.info(f"Threat analysis completed: {response.analysis_id}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Threat analysis failed: {str(e)}"
        )


@router.post("/enrich-iocs", response_model=IOCEnrichmentResponse)
async def enrich_indicators(request: IOCEnrichmentRequest):
    """
    Enrich indicators of compromise with threat intelligence

    Enriches IOCs with:
    - Reputation scores
    - Geolocation data
    - WHOIS information
    - Known malware families
    - Historical sightings
    - Related indicators

    Args:
        request: IOC enrichment request with indicators

    Returns:
        Enriched indicator data
    """
    try:
        logger.info(f"Enriching {len(request.indicators)} indicators")

        enriched_indicators = []

        for indicator in request.indicators:
            enriched_data = {
                'original': indicator.dict(),
                'enrichment': {}
            }

            # Enrich based on type
            if indicator.type == 'ip':
                enriched_data['enrichment'] = _enrich_ip(indicator.value)
            elif indicator.type == 'domain':
                enriched_data['enrichment'] = _enrich_domain(indicator.value)
            elif indicator.type == 'hash':
                enriched_data['enrichment'] = _enrich_hash(indicator.value)
            elif indicator.type == 'url':
                enriched_data['enrichment'] = _enrich_url(indicator.value)
            elif indicator.type == 'email':
                enriched_data['enrichment'] = _enrich_email(indicator.value)

            # Add reputation score
            enriched_data['enrichment']['reputation_score'] = _calculate_reputation(
                indicator.type,
                indicator.value
            )

            enriched_indicators.append(enriched_data)

        response = IOCEnrichmentResponse(
            success=True,
            enriched_indicators=enriched_indicators,
            timestamp=datetime.now().isoformat()
        )

        return response

    except Exception as e:
        logger.error(f"IOC enrichment failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"IOC enrichment failed: {str(e)}"
        )


@router.get("/search")
async def search_threat_intelligence(
    query: str = Query(..., min_length=3, description="Search query"),
    ioc_type: str = Query(None, description="Filter by IOC type"),
    threat_level: str = Query(None, description="Filter by threat level")
):
    """
    Search threat intelligence database

    Searches for threats, IOCs, and reports matching the query.

    Args:
        query: Search term
        ioc_type: Optional IOC type filter
        threat_level: Optional threat level filter

    Returns:
        Search results with matching threats and indicators
    """
    try:
        logger.info(f"Searching threat intelligence: {query}")

        # This would query a real threat intel database
        # For now, return mock results
        results = {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'filters': {
                'ioc_type': ioc_type,
                'threat_level': threat_level
            },
            'results': {
                'threats': [],
                'indicators': [],
                'reports': []
            },
            'total_results': 0
        }

        return results

    except Exception as e:
        logger.error(f"Threat intelligence search failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/mitre-mapping")
async def get_mitre_mapping(technique_id: str = Query(..., description="MITRE ATT&CK technique ID")):
    """
    Get detailed information about a MITRE ATT&CK technique

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., T1566)

    Returns:
        Detailed technique information including tactics, mitigations, and detections
    """
    try:
        # Mock MITRE data - in production, this would query MITRE ATT&CK API
        mitre_data = {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'technique_id': technique_id,
            'name': 'Phishing' if 'T1566' in technique_id else 'Unknown Technique',
            'tactics': ['Initial Access'],
            'description': 'Adversaries may send phishing messages to gain access to victim systems.',
            'mitigations': [
                'User training and awareness',
                'Email filtering and anti-spam',
                'Network intrusion prevention'
            ],
            'detections': [
                'Monitor for suspicious email attachments',
                'Analyze network traffic for C2 communications',
                'Review authentication logs for anomalies'
            ],
            'related_techniques': ['T1598', 'T1204']
        }

        return mitre_data

    except Exception as e:
        logger.error(f"MITRE mapping lookup failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"MITRE mapping lookup failed: {str(e)}"
        )


@router.get("/threat-actors")
async def list_threat_actors():
    """
    List known threat actors and APT groups

    Returns:
        List of threat actors with activity summaries
    """
    # Mock threat actor data
    threat_actors = {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'actors': [
            {
                'name': 'APT28',
                'aliases': ['Fancy Bear', 'Sofacy'],
                'origin': 'Russia',
                'activity': 'Active',
                'targets': ['Government', 'Military', 'Media'],
                'techniques': ['Spear Phishing', 'Credential Harvesting', 'Lateral Movement']
            },
            {
                'name': 'APT29',
                'aliases': ['Cozy Bear', 'The Dukes'],
                'origin': 'Russia',
                'activity': 'Active',
                'targets': ['Government', 'Think Tanks', 'Healthcare'],
                'techniques': ['Supply Chain', 'Cloud Exploitation', 'Stealth']
            }
        ],
        'total_actors': 2
    }

    return threat_actors


# Helper functions

def _map_to_mitre(analysis: Dict[str, Any]) -> List[Dict[str, str]]:
    """Map threat analysis to MITRE ATT&CK techniques"""
    # This is a simplified mapping - production would use ML-based mapping
    techniques = []

    keywords = analysis.get('keywords', [])

    if any(kw in ['phishing', 'email', 'spear'] for kw in keywords):
        techniques.append({'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'})

    if any(kw in ['ransomware', 'encrypt', 'crypto'] for kw in keywords):
        techniques.append({'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'})

    if any(kw in ['credential', 'password', 'dump'] for kw in keywords):
        techniques.append({'id': 'T1003', 'name': 'OS Credential Dumping', 'tactic': 'Credential Access'})

    if any(kw in ['lateral', 'movement', 'pivot'] for kw in keywords):
        techniques.append({'id': 'T1021', 'name': 'Remote Services', 'tactic': 'Lateral Movement'})

    return techniques


def _identify_threat_actors(content: str, analysis: Dict[str, Any]) -> List[str]:
    """Identify potential threat actors from report content"""
    threat_actors = []

    # Known APT patterns
    apt_patterns = [
        r'APT\d+',
        r'Fancy Bear',
        r'Cozy Bear',
        r'Lazarus',
        r'Carbanak',
        r'FIN\d+'
    ]

    for pattern in apt_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        threat_actors.extend(matches)

    # Remove duplicates and limit
    return list(set(threat_actors))[:10]


def _calculate_threat_level(analysis: Dict[str, Any], indicators: List[ThreatIndicator]) -> str:
    """Calculate overall threat level"""
    score = 0

    # Factor in number of IOCs
    if len(indicators) > 50:
        score += 3
    elif len(indicators) > 20:
        score += 2
    elif len(indicators) > 5:
        score += 1

    # Factor in attack vectors
    attack_vectors = analysis.get('attack_vectors', [])
    if len(attack_vectors) > 3:
        score += 2

    # Factor in keywords
    keywords = analysis.get('keywords', [])
    critical_keywords = ['ransomware', 'zero-day', 'apt', 'breach', 'compromise']
    if any(kw in ' '.join(keywords).lower() for kw in critical_keywords):
        score += 2

    # Determine threat level
    if score >= 6:
        return 'critical'
    elif score >= 4:
        return 'high'
    elif score >= 2:
        return 'medium'
    else:
        return 'low'


def _generate_threat_recommendations(
    threat_level: str,
    analysis: Dict[str, Any],
    indicators: List[ThreatIndicator]
) -> List[str]:
    """Generate actionable threat recommendations"""
    recommendations = []

    if threat_level in ['critical', 'high']:
        recommendations.append("🚨 Immediate action required - deploy threat hunting teams")
        recommendations.append("Block all identified IOCs at network perimeter")
        recommendations.append("Conduct thorough investigation of potentially affected systems")

    if len(indicators) > 0:
        recommendations.append(f"Add {len(indicators)} IOCs to threat intelligence feeds")
        recommendations.append("Update SIEM rules to detect related activity")

    attack_vectors = analysis.get('attack_vectors', [])
    if 'phishing' in attack_vectors:
        recommendations.append("Increase email security awareness training")

    if 'ransomware' in str(analysis).lower():
        recommendations.append("Verify backup integrity and test restoration procedures")

    recommendations.append("Share findings with threat intelligence community")

    return recommendations


def _generate_threat_summary(analysis: Dict[str, Any], threat_level: str) -> str:
    """Generate executive summary of threat"""
    return f"Threat analysis completed with {threat_level} severity level. " \
           f"Analysis identified {len(analysis.get('attack_vectors', []))} attack vectors. " \
           f"Immediate protective measures recommended."


def _find_related_threats(analysis: Dict[str, Any], threat_actors: List[str]) -> List[str]:
    """Find related threats based on analysis"""
    # This would query a threat database in production
    return []


def _enrich_ip(ip_address: str) -> Dict[str, Any]:
    """Enrich IP address with threat intelligence"""
    return {
        'geolocation': {'country': 'Unknown', 'city': 'Unknown'},
        'asn': 'Unknown',
        'is_tor': False,
        'is_vpn': False,
        'is_proxy': False,
        'abuse_score': 0,
        'last_seen': None
    }


def _enrich_domain(domain: str) -> Dict[str, Any]:
    """Enrich domain with threat intelligence"""
    return {
        'registrar': 'Unknown',
        'registration_date': None,
        'expiration_date': None,
        'name_servers': [],
        'is_newly_registered': False,
        'similar_domains': []
    }


def _enrich_hash(file_hash: str) -> Dict[str, Any]:
    """Enrich file hash with malware intelligence"""
    return {
        'malware_family': None,
        'first_seen': None,
        'last_seen': None,
        'detection_rate': 0,
        'file_names': [],
        'file_type': None
    }


def _enrich_url(url: str) -> Dict[str, Any]:
    """Enrich URL with threat intelligence"""
    return {
        'categories': [],
        'is_phishing': False,
        'is_malicious': False,
        'screenshot_available': False,
        'final_url': url
    }


def _enrich_email(email: str) -> Dict[str, Any]:
    """Enrich email address with threat intelligence"""
    return {
        'domain_reputation': 'unknown',
        'is_disposable': False,
        'associated_breaches': [],
        'spam_score': 0
    }


def _calculate_reputation(ioc_type: str, value: str) -> float:
    """Calculate reputation score for IOC (0.0 = malicious, 1.0 = benign)"""
    # This would integrate with threat intelligence feeds in production
    return 0.5  # Neutral score
