#!/usr/bin/env python3
"""
Threat Intelligence Platform - FastAPI REST API
Provides HTTP endpoints for threat intelligence queries
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime
import logging

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IOC, ThreatFeed, IOCType, ThreatLevel, Confidence
from processors.correlation_engine import CorrelationEngine
from collectors import OTXCollector, AbuseIPDBCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Threat Intelligence Platform API",
    description="Enterprise threat intelligence aggregation and correlation platform",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize correlation engine (global instance)
correlation_engine = CorrelationEngine()


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting Threat Intelligence Platform API...")
    logger.info("Correlation engine initialized")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Threat Intelligence Platform API",
        "version": "1.0.0",
        "status": "online",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    stats = correlation_engine.get_statistics()
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "statistics": stats
    }


@app.get("/api/iocs", response_model=List[dict])
async def get_iocs(
    ioc_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    limit: int = Query(100, le=1000)
):
    """Get IOCs with optional filtering"""
    try:
        # Convert string parameters to enums
        ioc_type_enum = None
        if ioc_type:
            try:
                ioc_type_enum = IOCType(ioc_type)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid IOC type: {ioc_type}")

        threat_level_enum = None
        if threat_level:
            try:
                threat_level_enum = ThreatLevel(threat_level)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid threat level: {threat_level}")

        # Get IOCs from correlation engine
        all_iocs = list(correlation_engine.ioc_database.values())[:limit]

        # Apply filters
        if ioc_type_enum:
            all_iocs = [ioc for ioc in all_iocs if ioc.ioc_type == ioc_type_enum]

        if threat_level_enum:
            all_iocs = [ioc for ioc in all_iocs if ioc.threat_level == threat_level_enum]

        return [ioc.to_dict() for ioc in all_iocs]

    except Exception as e:
        logger.error(f"Error fetching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/iocs/search")
async def search_iocs(
    q: str = Query(..., min_length=1),
    limit: int = Query(100, le=1000)
):
    """Search IOCs by value, tags, or description"""
    try:
        results = correlation_engine.search(q, limit=limit)
        return {
            "query": q,
            "total": len(results),
            "iocs": [ioc.to_dict() for ioc in results]
        }
    except Exception as e:
        logger.error(f"Error searching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/iocs/{ioc_id}")
async def get_ioc(ioc_id: str):
    """Get details of a specific IOC"""
    ioc = correlation_engine.ioc_database.get(ioc_id)

    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")

    # Get related IOCs
    related = correlation_engine.find_related_iocs(ioc, max_results=10)

    return {
        "ioc": ioc.to_dict(),
        "threat_score": correlation_engine.calculate_threat_score(ioc),
        "related_iocs": [r.to_dict() for r in related]
    }


@app.get("/api/iocs/{ioc_id}/related")
async def get_related_iocs(
    ioc_id: str,
    limit: int = Query(50, le=200)
):
    """Get IOCs related to the specified IOC"""
    ioc = correlation_engine.ioc_database.get(ioc_id)

    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")

    related = correlation_engine.find_related_iocs(ioc, max_results=limit)

    return {
        "ioc_id": ioc_id,
        "ioc_value": ioc.value,
        "related_count": len(related),
        "related_iocs": [r.to_dict() for r in related]
    }


@app.get("/api/campaigns")
async def get_campaigns(
    min_iocs: int = Query(3, ge=1)
):
    """Identify potential threat campaigns"""
    try:
        campaigns = correlation_engine.identify_campaigns(min_iocs=min_iocs)

        # Convert to serializable format
        result = []
        for campaign in campaigns:
            campaign_dict = {
                'name': campaign['name'],
                'ioc_count': campaign['ioc_count'],
                'first_seen': campaign['first_seen'].isoformat(),
                'last_seen': campaign['last_seen'].isoformat(),
                'threat_level': campaign['threat_level'].value,
                'iocs': [ioc.to_dict() for ioc in campaign['iocs'][:10]]  # Limit to 10 for performance
            }
            result.append(campaign_dict)

        return {
            "total_campaigns": len(result),
            "campaigns": result
        }

    except Exception as e:
        logger.error(f"Error identifying campaigns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/statistics")
async def get_statistics():
    """Get platform statistics"""
    stats = correlation_engine.get_statistics()
    return stats


@app.post("/api/iocs")
async def add_ioc(ioc_data: dict):
    """Add a new IOC to the platform"""
    try:
        # Create IOC from data
        ioc = IOC(
            ioc_type=IOCType(ioc_data['ioc_type']),
            value=ioc_data['value'],
            threat_level=ThreatLevel(ioc_data.get('threat_level', 'medium')),
            confidence=Confidence(ioc_data.get('confidence', 'medium')),
            tags=ioc_data.get('tags', []),
            description=ioc_data.get('description')
        )

        correlation_engine.add_ioc(ioc)

        return {
            "status": "success",
            "ioc_id": ioc.ioc_id,
            "ioc": ioc.to_dict()
        }

    except Exception as e:
        logger.error(f"Error adding IOC: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/iocs/expired")
async def clear_expired_iocs():
    """Remove expired IOCs from the database"""
    try:
        count = correlation_engine.clear_expired()
        return {
            "status": "success",
            "removed_count": count
        }
    except Exception as e:
        logger.error(f"Error clearing expired IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
