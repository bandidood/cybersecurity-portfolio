#!/usr/bin/env python3
"""
AI Model Setup Script
Initializes and validates AI/ML models for the cybersecurity platform
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def print_header(title):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f" {title}")
    print("="*70)

def check_dependencies():
    """Check if required dependencies are installed"""
    print_header("Checking Dependencies")

    required_packages = [
        'numpy',
        'pandas',
        'scikit-learn',
        'tensorflow',
        'transformers',
        'fastapi',
        'uvicorn'
    ]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✓ {package} installed")
        except ImportError:
            print(f"  ✗ {package} NOT installed")
            missing_packages.append(package)

    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("   Please run: pip install -r requirements.txt")
        return False

    print("\n✓ All dependencies are installed!")
    return True

def setup_ml_models():
    """Initialize ML models"""
    print_header("Setting Up ML Models")

    models_dir = Path(__file__).parent.parent / "ml_models"

    models = [
        ("malware_classifier.py", "Malware Classification"),
        ("network_anomaly_detector.py", "Network Anomaly Detection"),
        ("attack_predictor.py", "Attack Prediction"),
        ("user_risk_scorer.py", "User Risk Scoring")
    ]

    for model_file, model_name in models:
        model_path = models_dir / model_file
        if model_path.exists():
            print(f"  ✓ {model_name} - Found")
        else:
            print(f"  ✗ {model_name} - Missing")

    print("\n✓ ML models setup complete!")

def setup_nlp_models():
    """Initialize NLP models"""
    print_header("Setting Up NLP Models")

    nlp_dir = Path(__file__).parent.parent / "nlp_models"

    models = [
        ("log_analyzer.py", "Log Analysis"),
        ("threat_intel_analyzer.py", "Threat Intelligence Analysis")
    ]

    for model_file, model_name in models:
        model_path = nlp_dir / model_file
        if model_path.exists():
            print(f"  ✓ {model_name} - Found")
        else:
            print(f"  ✗ {model_name} - Missing")

    print("\n✓ NLP models setup complete!")

def create_directories():
    """Create required directories"""
    print_header("Creating Directories")

    directories = [
        "models/saved",
        "data/training",
        "data/validation",
        "logs",
        "cache"
    ]

    base_dir = Path(__file__).parent.parent

    for directory in directories:
        dir_path = base_dir / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Created: {directory}")

    print("\n✓ Directories created!")

def verify_backend():
    """Verify backend API setup"""
    print_header("Verifying Backend API")

    backend_dir = Path(__file__).parent.parent / "backend"

    if backend_dir.exists():
        print(f"  ✓ Backend directory found")
    else:
        print(f"  ✗ Backend directory not found")
        return False

    api_routes = backend_dir / "api" / "routes"
    if api_routes.exists():
        print(f"  ✓ API routes configured")
    else:
        print(f"  ✗ API routes not found")

    print("\n✓ Backend verification complete!")
    return True

def verify_frontend():
    """Verify frontend setup"""
    print_header("Verifying Frontend")

    frontend_dir = Path(__file__).parent.parent / "frontend"

    if frontend_dir.exists():
        print(f"  ✓ Frontend directory found")

        package_json = frontend_dir / "package.json"
        if package_json.exists():
            print(f"  ✓ package.json found")
        else:
            print(f"  ✗ package.json not found")

        src_dir = frontend_dir / "src"
        if src_dir.exists():
            print(f"  ✓ Source files found")
        else:
            print(f"  ✗ Source files not found")
    else:
        print(f"  ✗ Frontend directory not found")

    print("\n✓ Frontend verification complete!")

def main():
    """Main setup function"""
    print("\n" + "="*70)
    print(" AI-POWERED CYBERSECURITY PLATFORM - MODEL SETUP")
    print("="*70)

    # Check dependencies
    if not check_dependencies():
        print("\n❌ Setup failed: Missing dependencies")
        sys.exit(1)

    # Create directories
    create_directories()

    # Setup models
    setup_ml_models()
    setup_nlp_models()

    # Verify components
    verify_backend()
    verify_frontend()

    # Final message
    print_header("Setup Complete!")
    print("\n✅ AI/ML models are ready to use!")
    print("\nNext steps:")
    print("  1. Start the backend: python app.py")
    print("  2. Start the frontend: cd frontend && npm run dev")
    print("  3. Access the platform: http://localhost:8000")
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()
