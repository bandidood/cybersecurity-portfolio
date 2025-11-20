#!/usr/bin/env python3
"""
AI-Powered Cybersecurity Platform - Main Application
FastAPI backend server with ML/NLP capabilities
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import API routes
from api.routes import health, logs, threat_intel, incidents, ml_predictions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('logs/app.log') if Path('logs').exists() else logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="AI-Powered Cybersecurity Platform",
    description="""
    Advanced cybersecurity platform leveraging AI, ML, and NLP for:
    - Intelligent threat detection and analysis
    - Automated log analysis and correlation
    - Real-time anomaly detection
    - Predictive security analytics
    - Incident response automation

    ## Features
    * **Log Analysis**: NLP-powered log classification and entity extraction
    * **Threat Intelligence**: Automated IOC extraction and threat report analysis
    * **Incident Analysis**: AI-assisted incident investigation and response
    * **ML Predictions**: Anomaly detection, malware classification, risk scoring
    * **Real-time Processing**: Stream processing for live security events

    ## Authentication
    Currently in development mode. Production deployment requires authentication.

    ## Rate Limiting
    API rate limits apply per IP address:
    - Standard endpoints: 100 requests/minute
    - ML prediction endpoints: 20 requests/minute
    - Heavy analysis endpoints: 10 requests/minute
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "Security Team",
        "email": "security@example.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:80",
        "http://frontend:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Process-Time"]
)

# Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Middleware for request tracking and timing
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add request ID and processing time headers"""
    import time
    import uuid

    request_id = str(uuid.uuid4())
    start_time = time.time()

    # Add request ID to request state
    request.state.request_id = request_id

    # Process request
    response = await call_next(request)

    # Calculate processing time
    process_time = time.time() - start_time

    # Add headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"

    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} | "
        f"Status: {response.status_code} | "
        f"Time: {process_time:.4f}s | "
        f"ID: {request_id}"
    )

    return response


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path)
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "Request validation failed",
            "details": exc.errors(),
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "message": str(exc) if app.debug else "An unexpected error occurred",
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path)
        }
    )


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Execute on application startup"""
    logger.info("=" * 80)
    logger.info("🚀 AI-Powered Cybersecurity Platform Starting")
    logger.info("=" * 80)
    logger.info(f"Version: {app.version}")
    logger.info(f"Documentation: http://localhost:8000/docs")
    logger.info(f"Health Check: http://localhost:8000/health")
    logger.info("=" * 80)

    # Initialize ML models (in background to avoid blocking startup)
    logger.info("🤖 Loading AI/ML models...")
    try:
        # Models will be lazy-loaded on first request
        logger.info("✅ Model loading scheduled (lazy initialization)")
    except Exception as e:
        logger.warning(f"⚠️ Model loading warning: {e}")

    logger.info("✅ Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Execute on application shutdown"""
    logger.info("=" * 80)
    logger.info("🛑 AI-Powered Cybersecurity Platform Shutting Down")
    logger.info("=" * 80)
    logger.info("Cleaning up resources...")
    # Add cleanup logic here
    logger.info("✅ Shutdown complete")


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint with API information
    """
    return {
        "message": "AI-Powered Cybersecurity Platform API",
        "version": app.version,
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "documentation": "/docs",
        "health_check": "/health",
        "endpoints": {
            "health": "/health",
            "logs": "/api/logs",
            "threat_intel": "/api/threat-intel",
            "incidents": "/api/incidents",
            "ml_predictions": "/api/ml"
        }
    }


# Include routers
app.include_router(
    health.router,
    prefix="/health",
    tags=["Health"],
    responses={
        200: {"description": "Service is healthy"},
        503: {"description": "Service unavailable"}
    }
)

app.include_router(
    logs.router,
    prefix="/api/logs",
    tags=["Log Analysis"],
    responses={
        200: {"description": "Successful response"},
        422: {"description": "Validation error"},
        500: {"description": "Internal server error"}
    }
)

app.include_router(
    threat_intel.router,
    prefix="/api/threat-intel",
    tags=["Threat Intelligence"],
    responses={
        200: {"description": "Successful response"},
        422: {"description": "Validation error"},
        500: {"description": "Internal server error"}
    }
)

app.include_router(
    incidents.router,
    prefix="/api/incidents",
    tags=["Incident Analysis"],
    responses={
        200: {"description": "Successful response"},
        422: {"description": "Validation error"},
        500: {"description": "Internal server error"}
    }
)

app.include_router(
    ml_predictions.router,
    prefix="/api/ml",
    tags=["ML Predictions"],
    responses={
        200: {"description": "Successful response"},
        422: {"description": "Validation error"},
        503: {"description": "Model unavailable"},
        500: {"description": "Internal server error"}
    }
)


# Development server
if __name__ == "__main__":
    import os

    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("RELOAD", "true").lower() == "true"
    workers = int(os.getenv("WORKERS", 1))
    log_level = os.getenv("LOG_LEVEL", "info").lower()

    logger.info(f"Starting server on {host}:{port}")
    logger.info(f"Reload: {reload} | Workers: {workers} | Log Level: {log_level}")

    # Run server
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,  # Workers not compatible with reload
        log_level=log_level,
        access_log=True,
        use_colors=True
    )
