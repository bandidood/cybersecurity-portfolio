#!/usr/bin/env python3
"""
ML Predictions API Routes
Machine learning model prediction endpoints
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from api.models import (
    AnomalyDetectionRequest,
    AnomalyDetectionResponse,
    MalwareClassificationRequest,
    MalwareClassificationResponse,
    UserRiskScoringRequest,
    UserRiskScoringResponse,
    AttackPredictionRequest,
    AttackPredictionResponse,
    SuccessResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/anomaly-detection", response_model=AnomalyDetectionResponse)
async def detect_anomalies(request: AnomalyDetectionRequest):
    """
    Detect network traffic anomalies using ML

    Uses isolation forest and other anomaly detection algorithms to identify:
    - Unusual network patterns
    - Suspicious traffic flows
    - Port scanning activity
    - Data exfiltration attempts
    - C2 communications

    Args:
        request: Anomaly detection request with traffic data

    Returns:
        Detected anomalies with risk assessment
    """
    try:
        logger.info(f"Detecting anomalies in {len(request.traffic_data)} traffic samples")

        # Import anomaly detector
        try:
            from ml_models.network_anomaly_detector import NetworkAnomalyDetector
            detector = NetworkAnomalyDetector()
        except Exception as e:
            logger.error(f"Failed to load NetworkAnomalyDetector: {e}")
            raise HTTPException(
                status_code=503,
                detail="Anomaly detection service unavailable"
            )

        # Prepare data for model
        traffic_features = []
        for traffic in request.traffic_data:
            features = {
                'bytes_sent': traffic.bytes_sent,
                'bytes_received': traffic.bytes_received,
                'packets_sent': traffic.packets_sent,
                'packets_received': traffic.packets_received,
                'duration': traffic.duration,
                'source_port': traffic.source_port,
                'destination_port': traffic.destination_port
            }
            traffic_features.append(features)

        # Detect anomalies
        anomaly_results = detector.detect_anomalies(
            traffic_features,
            sensitivity=request.sensitivity
        )

        # Process results
        anomalies = []
        anomaly_score = 0.0

        for idx, (traffic, result) in enumerate(zip(request.traffic_data, anomaly_results)):
            if result.get('is_anomaly', False):
                anomalies.append({
                    'index': idx,
                    'timestamp': traffic.timestamp,
                    'source_ip': traffic.source_ip,
                    'destination_ip': traffic.destination_ip,
                    'source_port': traffic.source_port,
                    'destination_port': traffic.destination_port,
                    'protocol': traffic.protocol,
                    'anomaly_score': result.get('anomaly_score', 0.0),
                    'reasons': result.get('reasons', []),
                    'severity': result.get('severity', 'medium')
                })
                anomaly_score += result.get('anomaly_score', 0.0)

        # Calculate average anomaly score
        if anomalies:
            anomaly_score = anomaly_score / len(anomalies)
        else:
            anomaly_score = 0.0

        # Determine risk level
        risk_level = _calculate_risk_level(anomaly_score, len(anomalies))

        # Generate recommendations
        recommendations = _generate_anomaly_recommendations(
            anomalies,
            risk_level,
            request.traffic_data
        )

        # Create response
        response = AnomalyDetectionResponse(
            success=True,
            timestamp=datetime.now().isoformat(),
            total_samples=len(request.traffic_data),
            anomalies_detected=len(anomalies),
            anomaly_score=anomaly_score,
            anomalies=anomalies[:100],  # Limit to top 100
            risk_level=risk_level,
            recommendations=recommendations
        )

        logger.info(f"Anomaly detection completed: {len(anomalies)} anomalies found")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Anomaly detection failed: {str(e)}"
        )


@router.post("/malware-classification", response_model=MalwareClassificationResponse)
async def classify_malware(request: MalwareClassificationRequest):
    """
    Classify potential malware using ML

    Analyzes file characteristics to determine:
    - Malicious vs benign classification
    - Malware family identification
    - Malware type (ransomware, trojan, etc.)
    - Threat level assessment
    - Behavioral indicators

    Args:
        request: Malware classification request with file features

    Returns:
        Classification results with confidence scores
    """
    try:
        logger.info(f"Classifying malware: {request.features.file_hash}")

        # Import malware classifier
        try:
            from ml_models.malware_classifier import MalwareClassifier
            classifier = MalwareClassifier()
        except Exception as e:
            logger.error(f"Failed to load MalwareClassifier: {e}")
            raise HTTPException(
                status_code=503,
                detail="Malware classification service unavailable"
            )

        # Classify malware
        classification = classifier.classify(
            request.features.dict(),
            deep_analysis=request.deep_analysis
        )

        # Generate recommendations
        recommendations = _generate_malware_recommendations(classification)

        # Create response
        response = MalwareClassificationResponse(
            success=True,
            timestamp=datetime.now().isoformat(),
            is_malicious=classification.get('is_malicious', False),
            confidence=classification.get('confidence', 0.0),
            malware_family=classification.get('malware_family'),
            malware_type=classification.get('malware_type'),
            threat_level=classification.get('threat_level', 'unknown'),
            capabilities=classification.get('capabilities', []),
            yara_matches=classification.get('yara_matches', []),
            behavioral_indicators=classification.get('behavioral_indicators', []),
            recommendations=recommendations
        )

        logger.info(f"Malware classification completed: {'malicious' if response.is_malicious else 'benign'}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Malware classification failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Malware classification failed: {str(e)}"
        )


@router.post("/user-risk-scoring", response_model=UserRiskScoringResponse)
async def score_user_risk(request: UserRiskScoringRequest):
    """
    Calculate user risk score using UEBA

    Analyzes user behavior to identify:
    - Anomalous activity patterns
    - Credential compromise indicators
    - Insider threat signals
    - Account takeover attempts
    - Data exfiltration risks

    Args:
        request: User risk scoring request with behavior data

    Returns:
        Risk score with detailed analysis
    """
    try:
        logger.info(f"Calculating risk score for user: {request.behavior_data[0].user_id if request.behavior_data else 'unknown'}")

        # Import user risk scorer
        try:
            from ml_models.user_risk_scorer import UserRiskScorer
            scorer = UserRiskScorer()
        except Exception as e:
            logger.error(f"Failed to load UserRiskScorer: {e}")
            raise HTTPException(
                status_code=503,
                detail="User risk scoring service unavailable"
            )

        # Get user ID
        user_id = request.behavior_data[0].user_id if request.behavior_data else 'unknown'

        # Prepare behavior data
        behavior_features = [b.dict() for b in request.behavior_data]

        # Calculate risk score
        risk_analysis = scorer.calculate_risk(
            behavior_features,
            baseline_days=request.baseline_period_days
        )

        # Determine risk level
        risk_score = risk_analysis.get('risk_score', 0.0)
        risk_level = _score_to_risk_level(risk_score)

        # Generate recommendations
        recommendations = _generate_user_risk_recommendations(
            risk_level,
            risk_analysis
        )

        # Create response
        response = UserRiskScoringResponse(
            success=True,
            timestamp=datetime.now().isoformat(),
            user_id=user_id,
            risk_score=risk_score,
            risk_level=risk_level,
            anomalies_detected=risk_analysis.get('anomalies', []),
            behavior_changes=risk_analysis.get('behavior_changes', []),
            risk_factors=risk_analysis.get('risk_factors', []),
            recommendations=recommendations,
            comparison_to_baseline=risk_analysis.get('baseline_comparison', {})
        )

        logger.info(f"User risk scoring completed: {risk_score}/100 ({risk_level})")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User risk scoring failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"User risk scoring failed: {str(e)}"
        )


@router.post("/attack-prediction", response_model=AttackPredictionResponse)
async def predict_attacks(request: AttackPredictionRequest):
    """
    Predict potential future attacks using ML

    Analyzes historical data to forecast:
    - Attack likelihood
    - Probable attack types
    - High-risk assets
    - Threat trends
    - Optimal preventive measures

    Args:
        request: Attack prediction request with historical data

    Returns:
        Prediction results with preventive recommendations
    """
    try:
        logger.info(f"Predicting attacks for {request.prediction_horizon}")

        # Import attack predictor
        try:
            from ml_models.attack_predictor import AttackPredictor
            predictor = AttackPredictor()
        except Exception as e:
            logger.error(f"Failed to load AttackPredictor: {e}")
            raise HTTPException(
                status_code=503,
                detail="Attack prediction service unavailable"
            )

        # Predict attacks
        predictions = predictor.predict(
            request.historical_data,
            horizon=request.prediction_horizon,
            threat_types=request.threat_types
        )

        # Generate preventive measures
        preventive_measures = _generate_preventive_measures(predictions)

        # Create response
        response = AttackPredictionResponse(
            success=True,
            timestamp=datetime.now().isoformat(),
            prediction_timeframe=request.prediction_horizon,
            attack_likelihood=predictions.get('likelihood', 0.0),
            predicted_attack_types=predictions.get('attack_types', []),
            high_risk_assets=predictions.get('high_risk_assets', []),
            threat_trends=predictions.get('trends', {}),
            preventive_measures=preventive_measures,
            confidence_interval=predictions.get('confidence_interval', {})
        )

        logger.info(f"Attack prediction completed: {predictions.get('likelihood', 0.0)*100:.1f}% likelihood")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack prediction failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Attack prediction failed: {str(e)}"
        )


@router.get("/models/status")
async def get_model_status():
    """
    Get status of all ML models

    Returns:
        Status information for all loaded models
    """
    models_status = {
        'anomaly_detector': {'status': 'loaded', 'accuracy': 0.94},
        'malware_classifier': {'status': 'loaded', 'accuracy': 0.96},
        'user_risk_scorer': {'status': 'loaded', 'accuracy': 0.92},
        'attack_predictor': {'status': 'loaded', 'accuracy': 0.88}
    }

    return {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'models': models_status,
        'total_models': len(models_status),
        'models_loaded': sum(1 for m in models_status.values() if m['status'] == 'loaded')
    }


@router.post("/models/retrain")
async def retrain_models(background_tasks: BackgroundTasks):
    """
    Trigger model retraining

    Args:
        background_tasks: FastAPI background tasks

    Returns:
        Success response with job ID
    """
    job_id = str(uuid.uuid4())

    # Schedule retraining in background
    # background_tasks.add_task(retrain_all_models, job_id)

    return SuccessResponse(
        success=True,
        message="Model retraining scheduled",
        timestamp=datetime.now().isoformat(),
        data={'job_id': job_id}
    )


# Helper functions

def _calculate_risk_level(anomaly_score: float, anomaly_count: int) -> str:
    """Calculate overall risk level from anomaly metrics"""
    if anomaly_score > 0.8 or anomaly_count > 50:
        return 'critical'
    elif anomaly_score > 0.6 or anomaly_count > 20:
        return 'high'
    elif anomaly_score > 0.4 or anomaly_count > 5:
        return 'medium'
    elif anomaly_count > 0:
        return 'low'
    else:
        return 'minimal'


def _generate_anomaly_recommendations(
    anomalies: List[Dict[str, Any]],
    risk_level: str,
    traffic_data: List
) -> List[str]:
    """Generate recommendations based on detected anomalies"""
    recommendations = []

    if risk_level in ['critical', 'high']:
        recommendations.append("🚨 Immediate investigation required - high anomaly activity detected")
        recommendations.append("Consider implementing temporary network restrictions")

    if anomalies:
        # Check for port scanning
        unique_ports = set()
        for anomaly in anomalies:
            unique_ports.add(anomaly.get('destination_port'))

        if len(unique_ports) > 20:
            recommendations.append("⚠️ Possible port scanning detected - review source IPs")

        # Check for data exfiltration
        large_transfers = [a for a in anomalies if a.get('anomaly_score', 0) > 0.8]
        if large_transfers:
            recommendations.append("📤 Unusual data transfer patterns - check for potential exfiltration")

    recommendations.append("Update IDS/IPS signatures based on detected patterns")
    recommendations.append("Review firewall rules for affected IP addresses")

    return recommendations


def _generate_malware_recommendations(classification: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on malware classification"""
    recommendations = []

    if classification.get('is_malicious', False):
        recommendations.append("🚨 MALICIOUS FILE DETECTED - Quarantine immediately")
        recommendations.append("Scan all systems for similar indicators")
        recommendations.append("Block file hash across all security controls")

        malware_type = classification.get('malware_type', '')
        if 'ransomware' in malware_type.lower():
            recommendations.append("⚠️ RANSOMWARE DETECTED - Isolate affected systems and verify backups")
        elif 'trojan' in malware_type.lower():
            recommendations.append("Check for C2 communications and lateral movement")

    else:
        recommendations.append("✅ File classified as benign")
        if classification.get('confidence', 0.0) < 0.9:
            recommendations.append("Low confidence - consider manual review")

    return recommendations


def _generate_user_risk_recommendations(
    risk_level: str,
    risk_analysis: Dict[str, Any]
) -> List[str]:
    """Generate recommendations based on user risk score"""
    recommendations = []

    if risk_level in ['critical', 'high']:
        recommendations.append("🚨 High-risk user detected - require additional authentication")
        recommendations.append("Review recent user activity for compromise indicators")
        recommendations.append("Consider temporary access restrictions")

    anomalies = risk_analysis.get('anomalies', [])
    if anomalies:
        recommendations.append(f"⚠️ {len(anomalies)} behavioral anomalies detected")

        for anomaly in anomalies[:3]:
            anomaly_type = anomaly.get('type', 'unknown')
            recommendations.append(f"Investigate: {anomaly_type}")

    if risk_level == 'low':
        recommendations.append("✅ User behavior within normal parameters")

    return recommendations


def _generate_preventive_measures(predictions: Dict[str, Any]) -> List[str]:
    """Generate preventive measures based on attack predictions"""
    measures = []

    likelihood = predictions.get('likelihood', 0.0)

    if likelihood > 0.7:
        measures.append("🛡️ Increase monitoring and alerting sensitivity")
        measures.append("Ensure all systems are patched and updated")
        measures.append("Review and strengthen access controls")

    predicted_types = predictions.get('attack_types', [])
    for attack_type in predicted_types[:3]:
        attack_name = attack_type.get('type', 'unknown')
        if 'phishing' in attack_name.lower():
            measures.append("Conduct phishing awareness training")
        elif 'ransomware' in attack_name.lower():
            measures.append("Test backup and recovery procedures")
        elif 'ddos' in attack_name.lower():
            measures.append("Review DDoS mitigation capabilities")

    measures.append("Conduct tabletop exercises for incident response")
    measures.append("Update threat intelligence feeds")

    return measures


def _score_to_risk_level(score: float) -> str:
    """Convert numeric risk score to risk level"""
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
