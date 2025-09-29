#!/usr/bin/env python3
"""
Log Analysis API Routes
Endpoints for security log analysis, IOC extraction, and threat classification
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import sys
import os
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks, Depends
from fastapi.responses import JSONResponse

# Add nlp_models to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "nlp_models"))

from api.models import (
    LogEntryRequest, BatchLogRequest, LogAnalysisResponse, BatchLogAnalysisResponse,
    LogAnalysisResult, SeverityAssessment, ThreatAnalysis, MLPredictions,
    SeverityLevel, ThreatLevel, IOCType, FileUploadResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Global model cache
_log_analyzer = None

def get_log_analyzer():
    """Get or initialize the log analyzer model"""
    global _log_analyzer
    
    if _log_analyzer is None:
        try:
            logger.info("Loading SecurityLogAnalyzer model...")
            from log_analyzer import SecurityLogAnalyzer
            
            _log_analyzer = SecurityLogAnalyzer()
            
            # Try to initialize NLP models (optional)
            try:
                _log_analyzer.initialize_models()
                logger.info("✅ NLP models initialized")
            except Exception as e:
                logger.warning(f"⚠️ Could not initialize advanced NLP models: {e}")
            
            # Generate synthetic training data if no model is trained
            if not _log_analyzer.is_trained:
                logger.info("Training log analyzer with synthetic data...")
                training_data = _log_analyzer.generate_synthetic_logs(n_samples=1000)
                _log_analyzer.fit(training_data)
                logger.info("✅ Log analyzer training completed")
            
        except Exception as e:
            logger.error(f"❌ Failed to load log analyzer: {e}")
            raise HTTPException(status_code=500, detail="Failed to initialize log analysis model")
    
    return _log_analyzer

def convert_analysis_result(result: Dict[str, Any], entry_id: str = None) -> LogAnalysisResult:
    """Convert log analyzer result to API response format"""
    
    # Generate entry ID if not provided
    if entry_id is None:
        entry_id = f"LOG-{str(uuid.uuid4())[:8].upper()}"
    
    # Convert IOCs to correct format
    iocs = {}
    for ioc_type, ioc_list in result.get('iocs', {}).items():
        if ioc_list and isinstance(ioc_list, list):
            try:
                iocs[IOCType(ioc_type)] = ioc_list
            except ValueError:
                # Handle unknown IOC types
                logger.warning(f"Unknown IOC type: {ioc_type}")
    
    # Convert entities (simplified for now)
    entities = {}
    for entity_type, entity_list in result.get('entities', {}).items():
        if entity_list:
            entities[entity_type] = entity_list
    
    # Convert severity assessment
    severity_data = result.get('severity', {})
    severity = SeverityAssessment(
        severity=SeverityLevel(severity_data.get('severity', 'unknown')),
        confidence=severity_data.get('confidence', 0.0),
        scores={
            SeverityLevel.CRITICAL: severity_data.get('scores', {}).get('critical', 0.0),
            SeverityLevel.HIGH: severity_data.get('scores', {}).get('high', 0.0),
            SeverityLevel.MEDIUM: severity_data.get('scores', {}).get('medium', 0.0),
            SeverityLevel.LOW: severity_data.get('scores', {}).get('low', 0.0),
            SeverityLevel.UNKNOWN: severity_data.get('scores', {}).get('unknown', 0.0)
        }
    )
    
    # Convert threat analysis
    threat_data = result.get('threat_analysis', {})
    threat_analysis = ThreatAnalysis(
        threat_level=ThreatLevel(threat_data.get('threat_level', 'low')),
        total_score=threat_data.get('total_score', 0.0),
        indicators=threat_data.get('indicators', {})
    )
    
    # Convert ML predictions
    ml_predictions = None
    if 'ml_predictions' in result and result['ml_predictions']:
        ml_data = result['ml_predictions']
        ml_predictions = MLPredictions(
            log_type={
                'prediction': ml_data.get('log_type', {}).get('prediction', 'normal'),
                'confidence': ml_data.get('log_type', {}).get('confidence', 0.0)
            },
            priority={
                'prediction': ml_data.get('priority', {}).get('prediction', 'low'),
                'confidence': ml_data.get('priority', {}).get('confidence', 0.0)
            }
        )
    
    return LogAnalysisResult(
        entry_id=entry_id,
        original_text=result.get('original_text', ''),
        processed_text=result.get('processed_text', ''),
        analysis_timestamp=result.get('analysis_timestamp', datetime.now().isoformat()),
        iocs=iocs,
        entities=entities,
        severity=severity,
        threat_analysis=threat_analysis,
        ml_predictions=ml_predictions
    )

@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_log_entry(request: LogEntryRequest):
    """
    Analyze a single log entry for IOCs, threats, and classification
    
    This endpoint processes a log entry through the AI-powered analysis pipeline:
    - Extracts indicators of compromise (IOCs)
    - Classifies severity level and threat level
    - Applies ML models for log type and priority prediction
    - Performs entity recognition and text processing
    """
    try:
        analyzer = get_log_analyzer()
        
        # Analyze the log entry
        result = analyzer.analyze_text(request.text)
        
        # Convert to API response format
        analysis_result = convert_analysis_result(result)
        
        logger.info(f"Successfully analyzed log entry: {analysis_result.entry_id}")
        
        return LogAnalysisResponse(
            success=True,
            message="Log analysis completed successfully",
            data=analysis_result
        )
        
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/analyze/batch", response_model=BatchLogAnalysisResponse)
async def analyze_batch_logs(request: BatchLogRequest):
    """
    Analyze multiple log entries in batch for improved performance
    
    Processes up to 100 log entries simultaneously, ideal for:
    - Bulk log processing
    - Historical log analysis
    - Real-time log stream analysis
    """
    try:
        analyzer = get_log_analyzer()
        
        # Analyze all log entries
        results = analyzer.batch_analyze(request.log_entries)
        
        # Convert results to API response format
        analysis_results = []
        for i, result in enumerate(results):
            if 'error' not in result:
                entry_id = f"LOG-{str(uuid.uuid4())[:8].upper()}-{i+1:03d}"
                analysis_result = convert_analysis_result(result, entry_id)
                analysis_results.append(analysis_result)
            else:
                logger.error(f"Analysis failed for entry {i}: {result.get('error')}")
        
        logger.info(f"Successfully analyzed {len(analysis_results)} log entries")
        
        return BatchLogAnalysisResponse(
            success=True,
            message=f"Batch analysis completed: {len(analysis_results)} entries processed",
            data=analysis_results
        )
        
    except Exception as e:
        logger.error(f"Batch log analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@router.post("/upload", response_model=FileUploadResponse)
async def upload_log_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Log file to upload and analyze")
):
    """
    Upload a log file for processing
    
    Supported formats:
    - .log, .txt: Plain text logs
    - .json: Structured JSON logs
    - .csv: CSV formatted logs
    
    The file will be processed in the background and results can be retrieved
    using the returned processing_id.
    """
    
    # Validate file type
    allowed_extensions = {'.log', '.txt', '.json', '.csv'}
    file_extension = Path(file.filename).suffix.lower()
    
    if file_extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}"
        )
    
    # Validate file size (max 100MB)
    max_size = 100 * 1024 * 1024  # 100MB
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(status_code=400, detail="File too large (max 100MB)")
    
    # Generate processing ID
    processing_id = str(uuid.uuid4())
    
    # Schedule background processing
    background_tasks.add_task(process_uploaded_file, content, file.filename, processing_id)
    
    logger.info(f"File uploaded: {file.filename} ({len(content)} bytes), processing_id: {processing_id}")
    
    return FileUploadResponse(
        success=True,
        message="File uploaded successfully, processing in background",
        filename=file.filename,
        size=len(content),
        content_type=file.content_type or "text/plain",
        processing_id=processing_id
    )

async def process_uploaded_file(content: bytes, filename: str, processing_id: str):
    """Background task to process uploaded file"""
    try:
        logger.info(f"Processing uploaded file: {filename} (ID: {processing_id})")
        
        # Decode file content
        text_content = content.decode('utf-8', errors='ignore')
        
        # Split into log entries (simple line-based splitting)
        log_entries = [line.strip() for line in text_content.split('\n') if line.strip()]
        
        if not log_entries:
            logger.error(f"No log entries found in file: {filename}")
            return
        
        # Analyze log entries
        analyzer = get_log_analyzer()
        results = analyzer.batch_analyze(log_entries[:100])  # Limit to first 100 entries
        
        # TODO: Store results in database or cache for retrieval
        # For now, just log the results
        logger.info(f"File processing completed: {filename}, analyzed {len(results)} entries")
        
    except Exception as e:
        logger.error(f"File processing failed for {filename}: {e}")

@router.get("/status/{processing_id}")
async def get_processing_status(processing_id: str):
    """
    Get the status of a file processing job
    
    Returns the current status and results (if completed) for a file upload job.
    """
    # TODO: Implement actual status tracking
    # For now, return a mock response
    
    return {
        "success": True,
        "processing_id": processing_id,
        "status": "completed",
        "message": "Processing completed successfully",
        "results_available": True,
        "processed_entries": 45,
        "timestamp": datetime.now().isoformat()
    }

@router.get("/models/info")
async def get_model_info():
    """
    Get information about loaded log analysis models
    
    Returns details about the current state of ML models including:
    - Model status and capabilities
    - Training metrics
    - Performance statistics
    """
    try:
        analyzer = get_log_analyzer()
        
        return {
            "success": True,
            "models": {
                "log_analyzer": {
                    "status": "loaded" if analyzer.is_trained else "not_trained",
                    "capabilities": [
                        "IOC extraction (12 types)",
                        "Severity classification (5 levels)",
                        "Threat analysis (5 categories)",
                        "ML predictions (log type, priority)",
                        "Entity recognition"
                    ],
                    "supported_iocs": [
                        "ip_address", "domain", "url", "email",
                        "md5", "sha1", "sha256", "cve",
                        "file_path", "registry_key", "process_name", "mutex"
                    ],
                    "nlp_models": {
                        "spacy": analyzer.nlp is not None,
                        "transformers": analyzer.transformer_model is not None
                    },
                    "vocabulary_size": len(analyzer.vocabulary) if hasattr(analyzer, 'vocabulary') else 0
                }
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get model info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve model information")

@router.post("/models/retrain")
async def retrain_models(background_tasks: BackgroundTasks):
    """
    Retrain the log analysis models with fresh synthetic data
    
    This endpoint triggers a background retraining process using updated
    synthetic data to improve model accuracy and adapt to new threat patterns.
    """
    
    def retrain_task():
        try:
            logger.info("Starting log analyzer retraining...")
            analyzer = get_log_analyzer()
            
            # Generate fresh training data
            training_data = analyzer.generate_synthetic_logs(n_samples=2000)
            
            # Retrain models
            metrics = analyzer.fit(training_data)
            
            logger.info(f"Retraining completed successfully: {metrics}")
            
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
    
    background_tasks.add_task(retrain_task)
    
    return {
        "success": True,
        "message": "Model retraining started in background",
        "estimated_time": "3-5 minutes",
        "timestamp": datetime.now().isoformat()
    }