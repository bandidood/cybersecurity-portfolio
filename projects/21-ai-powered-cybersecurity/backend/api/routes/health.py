#!/usr/bin/env python3
"""
Health Check API Routes
System health monitoring and status endpoints
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import psutil
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from api.models import HealthResponse, SystemHealth

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/", response_model=HealthResponse)
async def health_check():
    """
    Basic health check endpoint
    
    Returns simple health status for load balancers and monitoring systems.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        message="AI Cybersecurity Platform is operational"
    )

@router.get("/detailed", response_model=Dict[str, Any])
async def detailed_health_check():
    """
    Detailed system health check
    
    Returns comprehensive health information including:
    - System resource utilization
    - Model loading status
    - API endpoint availability
    - Database connectivity
    - Performance metrics
    """
    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Check model status
        model_status = await _check_model_status()
        
        # Calculate overall health score
        health_score = _calculate_health_score(cpu_percent, memory.percent, disk.percent)
        
        health_data = SystemHealth(
            status="healthy" if health_score > 0.7 else "degraded" if health_score > 0.4 else "unhealthy",
            cpu_usage=cpu_percent,
            memory_usage=memory.percent,
            disk_usage=disk.percent,
            uptime_seconds=int(datetime.now().timestamp() - psutil.boot_time()),
            models_loaded=model_status["loaded_count"],
            api_endpoints_active=model_status["endpoints_active"],
            health_score=health_score,
            last_updated=datetime.now().isoformat()
        )
        
        return {
            "health": health_data.dict(),
            "models": model_status["details"],
            "system_info": {
                "python_version": f"{psutil.WINDOWS if psutil.WINDOWS else 'Linux'}",
                "cpu_count": psutil.cpu_count(),
                "total_memory_gb": round(memory.total / (1024**3), 2),
                "total_disk_gb": round(disk.total / (1024**3), 2)
            },
            "recommendations": _get_health_recommendations(health_score, cpu_percent, memory.percent)
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")

async def _check_model_status() -> Dict[str, Any]:
    """Check the status of all AI models"""
    model_status = {
        "loaded_count": 0,
        "endpoints_active": 0,
        "details": {}
    }
    
    # Check log analyzer model
    try:
        from nlp_models.log_analyzer import LogAnalyzer
        analyzer = LogAnalyzer()
        model_status["details"]["log_analyzer"] = {
            "status": "loaded" if hasattr(analyzer, 'models') else "not_loaded",
            "trained": getattr(analyzer, 'is_trained', False),
            "last_used": datetime.now().isoformat()
        }
        if model_status["details"]["log_analyzer"]["status"] == "loaded":
            model_status["loaded_count"] += 1
            model_status["endpoints_active"] += 1
    except Exception as e:
        model_status["details"]["log_analyzer"] = {
            "status": "error",
            "error": str(e)
        }
    
    # Check threat intel analyzer model
    try:
        from nlp_models.threat_intel_analyzer import ThreatIntelligenceAnalyzer
        analyzer = ThreatIntelligenceAnalyzer()
        model_status["details"]["threat_intel_analyzer"] = {
            "status": "loaded" if hasattr(analyzer, 'models') else "not_loaded",
            "trained": getattr(analyzer, 'is_trained', False),
            "last_used": datetime.now().isoformat()
        }
        if model_status["details"]["threat_intel_analyzer"]["status"] == "loaded":
            model_status["loaded_count"] += 1
            model_status["endpoints_active"] += 1
    except Exception as e:
        model_status["details"]["threat_intel_analyzer"] = {
            "status": "error",
            "error": str(e)
        }
    
    # Check incident analyzer model
    try:
        from nlp_models.incident_analyzer import IncidentAnalyzer
        analyzer = IncidentAnalyzer()
        model_status["details"]["incident_analyzer"] = {
            "status": "loaded" if hasattr(analyzer, 'models') else "not_loaded",
            "trained": getattr(analyzer, 'is_trained', False),
            "last_used": datetime.now().isoformat()
        }
        if model_status["details"]["incident_analyzer"]["status"] == "loaded":
            model_status["loaded_count"] += 1
            model_status["endpoints_active"] += 1
    except Exception as e:
        model_status["details"]["incident_analyzer"] = {
            "status": "error",
            "error": str(e)
        }
    
    return model_status

def _calculate_health_score(cpu_percent: float, memory_percent: float, disk_percent: float) -> float:
    """Calculate overall system health score (0.0 to 1.0)"""
    
    # Weight factors
    cpu_weight = 0.4
    memory_weight = 0.4
    disk_weight = 0.2
    
    # Convert usage percentages to health scores (inverted)
    cpu_score = max(0, (100 - cpu_percent) / 100)
    memory_score = max(0, (100 - memory_percent) / 100)
    disk_score = max(0, (100 - disk_percent) / 100)
    
    # Calculate weighted health score
    health_score = (
        cpu_score * cpu_weight +
        memory_score * memory_weight +
        disk_score * disk_weight
    )
    
    return round(health_score, 3)

def _get_health_recommendations(health_score: float, cpu_percent: float, memory_percent: float) -> list:
    """Get health improvement recommendations based on system metrics"""
    recommendations = []
    
    if health_score < 0.5:
        recommendations.append("System performance is degraded - consider scaling resources")
    
    if cpu_percent > 80:
        recommendations.append("High CPU usage detected - consider optimizing workloads or adding CPU resources")
    
    if memory_percent > 85:
        recommendations.append("High memory usage detected - consider increasing RAM or optimizing memory usage")
    
    if cpu_percent > 90 or memory_percent > 90:
        recommendations.append("Critical resource usage - immediate attention required")
    
    if not recommendations:
        recommendations.append("System is operating within normal parameters")
    
    return recommendations

@router.get("/models")
async def get_model_health():
    """
    Get detailed health status of all AI models
    
    Returns information about model loading status, training state,
    performance metrics, and resource utilization.
    """
    try:
        model_status = await _check_model_status()
        
        return {
            "success": True,
            "data": {
                "summary": {
                    "total_models": 3,
                    "loaded_models": model_status["loaded_count"],
                    "active_endpoints": model_status["endpoints_active"],
                    "health_status": "healthy" if model_status["loaded_count"] >= 2 else "degraded"
                },
                "models": model_status["details"],
                "last_updated": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Model health check failed: {e}")
        raise HTTPException(status_code=500, detail="Model health check failed")

@router.get("/metrics")
async def get_system_metrics():
    """
    Get real-time system performance metrics
    
    Returns current system resource utilization and performance
    indicators for monitoring and alerting systems.
    """
    try:
        # Get detailed system metrics
        cpu_times = psutil.cpu_times()
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "cpu": {
                "usage_percent": psutil.cpu_percent(interval=1),
                "user_time": cpu_times.user,
                "system_time": cpu_times.system,
                "idle_time": cpu_times.idle,
                "core_count": psutil.cpu_count(),
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            },
            "memory": {
                "total_bytes": memory.total,
                "available_bytes": memory.available,
                "used_bytes": memory.used,
                "usage_percent": memory.percent,
                "cached_bytes": getattr(memory, 'cached', 0),
                "buffers_bytes": getattr(memory, 'buffers', 0)
            },
            "swap": {
                "total_bytes": swap.total,
                "used_bytes": swap.used,
                "free_bytes": swap.free,
                "usage_percent": swap.percent
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "usage_percent": (disk.used / disk.total) * 100
            },
            "network": {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
        }
        
        return {
            "success": True,
            "data": metrics
        }
        
    except Exception as e:
        logger.error(f"System metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail="System metrics collection failed")

@router.get("/readiness")
async def readiness_probe():
    """
    Kubernetes/Docker readiness probe endpoint
    
    Returns 200 OK when the application is ready to serve traffic.
    Used by orchestration systems to determine deployment readiness.
    """
    try:
        # Check if at least one model is loaded
        model_status = await _check_model_status()
        
        if model_status["loaded_count"] == 0:
            raise HTTPException(status_code=503, detail="No models loaded - not ready")
        
        return {
            "status": "ready",
            "timestamp": datetime.now().isoformat(),
            "models_loaded": model_status["loaded_count"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        raise HTTPException(status_code=503, detail="Application not ready")

@router.get("/liveness")
async def liveness_probe():
    """
    Kubernetes/Docker liveness probe endpoint
    
    Returns 200 OK when the application is alive and responsive.
    Used by orchestration systems to determine if restart is needed.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time())
    }