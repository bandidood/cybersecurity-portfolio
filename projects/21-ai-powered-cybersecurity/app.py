#!/usr/bin/env python3
"""
AI-Powered Cybersecurity Platform - Main Application Entry Point
Starts the FastAPI backend server with AI/ML capabilities
"""

import uvicorn
from pathlib import Path
import sys
import os

# Add backend to Python path
backend_dir = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_dir))

def main():
    """Main entry point for the application"""
    print("="*70)
    print(" AI-POWERED CYBERSECURITY PLATFORM")
    print("="*70)
    print("\nStarting AI/ML security analysis platform...")
    print("\nFeatures:")
    print("  • Machine Learning threat detection")
    print("  • NLP-powered log analysis")
    print("  • Real-time anomaly detection")
    print("  • Threat intelligence analysis")
    print("\nServer will be available at: http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    print("\n" + "="*70 + "\n")

    # Configuration
    config = {
        "app": "backend.api.main:app",
        "host": os.getenv("HOST", "0.0.0.0"),
        "port": int(os.getenv("PORT", 8000)),
        "reload": os.getenv("ENV", "development") == "development",
        "log_level": os.getenv("LOG_LEVEL", "info"),
    }

    # Start server
    uvicorn.run(**config)

if __name__ == "__main__":
    main()
