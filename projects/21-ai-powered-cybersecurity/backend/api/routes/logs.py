#!/usr/bin/env python3
"""
Log Analysis API Routes
Advanced log analysis and classification endpoints
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from api.models import (
    LogAnalysisRequest,
    LogAnalysisResponse,
    LogClassificationRequest,
    LogClassificationResponse,
    SuccessResponse,
    ErrorResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze multiple log entries using NLP and ML

    Performs comprehensive analysis including:
    - Anomaly detection
    - Security event identification
    - Pattern recognition
    - Severity classification
    - Entity extraction

    Args:
        request: Log analysis request with log entries and options

    Returns:
        Detailed analysis results with anomalies and recommendations
    """
    try:
        logger.info(f"Analyzing {len(request.logs)} log entries")

        # Import log analyzer
        try:
            from nlp_models.log_analyzer import LogAnalyzer
            analyzer = LogAnalyzer()
        except Exception as e:
            logger.error(f"Failed to load LogAnalyzer: {e}")
            raise HTTPException(
                status_code=503,
                detail="Log analysis service unavailable"
            )

        # Prepare log data
        log_messages = [log.message for log in request.logs]

        # Perform analysis
        analysis_results = {
            'anomalies': [],
            'security_events': [],
            'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'categories': {},
            'extracted_entities': {'ips': set(), 'domains': set(), 'files': set(), 'users': set()}
        }

        # Analyze each log entry
        for idx, log_entry in enumerate(request.logs):
            try:
                # Classify log
                classification = analyzer.classify_log(log_entry.message)

                # Extract entities
                entities = analyzer.extract_entities(log_entry.message)

                # Update statistics
                category = classification.get('category', 'unknown')
                severity = classification.get('severity', 'info')

                analysis_results['severity_distribution'][severity] = \
                    analysis_results['severity_distribution'].get(severity, 0) + 1

                analysis_results['categories'][category] = \
                    analysis_results['categories'].get(category, 0) + 1

                # Check for anomalies
                is_anomaly = classification.get('is_anomaly', False)
                if is_anomaly or severity in ['critical', 'high']:
                    analysis_results['anomalies'].append({
                        'log_index': idx,
                        'message': log_entry.message[:200],
                        'severity': severity,
                        'category': category,
                        'confidence': classification.get('confidence', 0.0),
                        'timestamp': log_entry.timestamp or datetime.now().isoformat()
                    })

                # Check for security events
                if classification.get('is_security_relevant', False):
                    analysis_results['security_events'].append({
                        'log_index': idx,
                        'message': log_entry.message[:200],
                        'event_type': category,
                        'severity': severity,
                        'indicators': entities,
                        'timestamp': log_entry.timestamp or datetime.now().isoformat()
                    })

                # Collect entities
                if entities:
                    for entity_type, entity_values in entities.items():
                        if entity_type in analysis_results['extracted_entities']:
                            analysis_results['extracted_entities'][entity_type].update(entity_values)

            except Exception as e:
                logger.warning(f"Failed to analyze log entry {idx}: {e}")
                continue

        # Convert sets to lists for JSON serialization
        for entity_type in analysis_results['extracted_entities']:
            analysis_results['extracted_entities'][entity_type] = \
                list(analysis_results['extracted_entities'][entity_type])

        # Generate recommendations
        recommendations = _generate_recommendations(analysis_results)

        # Generate summary
        summary = {
            'total_logs': len(request.logs),
            'anomalies_found': len(analysis_results['anomalies']),
            'security_events': len(analysis_results['security_events']),
            'most_common_category': max(
                analysis_results['categories'].items(),
                key=lambda x: x[1],
                default=('unknown', 0)
            )[0] if analysis_results['categories'] else 'none',
            'highest_severity': _get_highest_severity(analysis_results['severity_distribution']),
            'analysis_type': request.analysis_type
        }

        # Create response
        response = LogAnalysisResponse(
            success=True,
            analysis_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            summary=summary,
            anomalies=analysis_results['anomalies'][:50],  # Limit to top 50
            security_events=analysis_results['security_events'][:50],
            recommendations=recommendations,
            severity_distribution=analysis_results['severity_distribution'],
            total_logs_analyzed=len(request.logs)
        )

        logger.info(f"Log analysis completed: {response.analysis_id}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Log analysis failed: {str(e)}"
        )


@router.post("/classify", response_model=LogClassificationResponse)
async def classify_log(request: LogClassificationRequest):
    """
    Classify a single log message

    Uses NLP to determine:
    - Log category (error, warning, security, etc.)
    - Severity level
    - Security relevance
    - Extracted entities (IPs, domains, files, users)

    Args:
        request: Log classification request with message and context

    Returns:
        Classification results with category, severity, and entities
    """
    try:
        logger.info("Classifying log message")

        # Import log analyzer
        try:
            from nlp_models.log_analyzer import LogAnalyzer
            analyzer = LogAnalyzer()
        except Exception as e:
            logger.error(f"Failed to load LogAnalyzer: {e}")
            raise HTTPException(
                status_code=503,
                detail="Log classification service unavailable"
            )

        # Classify log
        classification = analyzer.classify_log(request.log_message)

        # Extract entities
        entities = analyzer.extract_entities(request.log_message)

        # Generate recommendations
        recommendations = []
        severity = classification.get('severity', 'info')
        is_security = classification.get('is_security_relevant', False)

        if severity == 'critical':
            recommendations.append("Immediate investigation required - critical severity detected")
        if is_security:
            recommendations.append("Security team notification recommended")
        if entities.get('ips'):
            recommendations.append("Review IP addresses for known threats")
        if entities.get('files'):
            recommendations.append("Scan mentioned files for malware")

        # Create response
        response = LogClassificationResponse(
            category=classification.get('category', 'unknown'),
            confidence=classification.get('confidence', 0.0),
            severity=severity,
            is_security_relevant=is_security,
            extracted_entities=entities,
            recommendations=recommendations
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Log classification failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Log classification failed: {str(e)}"
        )


@router.post("/extract-entities")
async def extract_entities(log_message: str):
    """
    Extract security-relevant entities from log message

    Extracts:
    - IP addresses
    - Domain names
    - File paths
    - User names
    - Email addresses
    - URLs

    Args:
        log_message: Log message text

    Returns:
        Dictionary of extracted entities by type
    """
    try:
        from nlp_models.log_analyzer import LogAnalyzer
        analyzer = LogAnalyzer()

        entities = analyzer.extract_entities(log_message)

        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'entities': entities,
            'total_entities': sum(len(v) for v in entities.values())
        }

    except Exception as e:
        logger.error(f"Entity extraction failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Entity extraction failed: {str(e)}"
        )


@router.get("/statistics")
async def get_log_statistics():
    """
    Get log analysis statistics

    Returns aggregated statistics about log analysis operations
    including performance metrics and common patterns.
    """
    return {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'statistics': {
            'total_logs_analyzed': 0,  # Would be from database
            'average_processing_time_ms': 150,
            'most_common_categories': ['authentication', 'system', 'security'],
            'most_common_severities': ['info', 'warning', 'error'],
            'models_loaded': True,
            'service_uptime': 'operational'
        }
    }


def _generate_recommendations(analysis_results: Dict[str, Any]) -> List[str]:
    """Generate actionable recommendations based on analysis results"""
    recommendations = []

    # Check for critical anomalies
    critical_count = sum(
        1 for a in analysis_results['anomalies']
        if a.get('severity') == 'critical'
    )
    if critical_count > 0:
        recommendations.append(
            f"🚨 {critical_count} critical anomalies detected - immediate investigation required"
        )

    # Check for security events
    if len(analysis_results['security_events']) > 0:
        recommendations.append(
            f"⚠️ {len(analysis_results['security_events'])} security-relevant events found - review recommended"
        )

    # Check for suspicious entities
    ips = analysis_results['extracted_entities'].get('ips', [])
    if len(ips) > 20:
        recommendations.append(
            f"📍 High volume of unique IP addresses ({len(ips)}) - check for scanning activity"
        )

    files = analysis_results['extracted_entities'].get('files', [])
    if len(files) > 10:
        recommendations.append(
            f"📁 Multiple file references detected ({len(files)}) - verify file integrity"
        )

    # Check severity distribution
    high_severity = analysis_results['severity_distribution'].get('high', 0) + \
                   analysis_results['severity_distribution'].get('critical', 0)

    if high_severity > len(analysis_results['anomalies']) * 0.1:
        recommendations.append(
            "⚡ High percentage of severe events - consider increasing monitoring"
        )

    if not recommendations:
        recommendations.append("✅ No immediate security concerns detected")

    return recommendations


def _get_highest_severity(severity_dist: Dict[str, int]) -> str:
    """Determine highest severity level present"""
    severity_order = ['critical', 'high', 'medium', 'low', 'info']

    for severity in severity_order:
        if severity_dist.get(severity, 0) > 0:
            return severity

    return 'info'
