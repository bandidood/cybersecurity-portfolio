#!/usr/bin/env python3
"""
Script de lancement pour le dashboard DevSecOps
Usage: python run_dashboard.py [--config config.yaml] [--port 8080] [--debug]
"""

import os
import sys
import yaml
import argparse
from pathlib import Path
import logging

# Ajouter le chemin du dashboard au PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dashboard'))

def setup_logging(debug=False):
    """Configure le logging"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('dashboard.log')
        ]
    )

def load_config(config_path=None):
    """Charge la configuration du dashboard"""
    
    # Configuration par défaut
    default_config = {
        'secret_key': 'devsecops-dashboard-secret-key-change-in-production',
        'database_path': './monitoring/metrics.db',
        'monitoring': {
            'database_path': './monitoring/metrics.db',
            'collection_interval': 30,  # secondes
            'prometheus': {
                'enabled': False,
                'port': 9090,
                'metrics_path': '/metrics'
            },
            'influxdb': {
                'enabled': False,
                'url': 'http://localhost:8086',
                'token': '',
                'org': 'devsecops',
                'bucket': 'security-metrics'
            }
        },
        'orchestrator_config': './config/orchestrator-config.yaml',
        'alerts': {
            'enabled': True,
            'notification_channels': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'localhost',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_email': 'devsecops@company.com',
                    'recipients': []
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': '',
                    'channel': '#security-alerts'
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'headers': {}
                }
            }
        },
        'security': {
            'require_auth': False,  # Désactivé par défaut pour la démo
            'session_timeout': 3600,  # 1 heure
            'allowed_hosts': ['*'],  # Restreindre en production
            'cors_origins': ['*']    # Restreindre en production
        },
        'features': {
            'real_time_updates': True,
            'scan_history_days': 30,
            'max_concurrent_scans': 5,
            'auto_cleanup_reports': True,
            'cleanup_after_days': 7
        }
    }
    
    config = default_config.copy()
    
    # Charger la configuration personnalisée si fournie
    if config_path:
        config_file = Path(config_path)
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f)
                    
                def merge_config(base, override):
                    """Merge récursif des configurations"""
                    for key, value in override.items():
                        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                            merge_config(base[key], value)
                        else:
                            base[key] = value
                
                merge_config(config, user_config)
                print(f"Configuration loaded from: {config_path}")
                
            except yaml.YAMLError as e:
                print(f"Error loading config file {config_path}: {e}")
                print("Using default configuration")
        else:
            print(f"Config file {config_path} not found, using default configuration")
    
    return config

def create_required_directories(config):
    """Crée les répertoires nécessaires"""
    dirs_to_create = [
        './monitoring',
        './security-reports',
        './dashboard/templates',
        './dashboard/static',
        './logs',
        Path(config['database_path']).parent
    ]
    
    for dir_path in dirs_to_create:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"Directory created/verified: {dir_path}")

def check_dependencies():
    """Vérifie que les dépendances sont installées"""
    required_packages = [
        'flask',
        'flask_cors', 
        'flask_socketio',
        'plotly',
        'psutil',
        'yaml'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nInstall missing packages with:")
        print("  pip install -r dashboard/requirements.txt")
        return False
    
    return True

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description="DevSecOps Security Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_dashboard.py                          # Start with default config
  python run_dashboard.py --config config.yaml    # Start with custom config
  python run_dashboard.py --port 9090 --debug     # Start on port 9090 in debug mode
  python run_dashboard.py --host 127.0.0.1        # Bind to localhost only
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file (YAML)',
        default=None
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port to bind to (default: 8080)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    parser.add_argument(
        '--no-auto-reload',
        action='store_true',
        help='Disable auto-reload in debug mode'
    )
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check dependencies and exit'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    if args.check_deps:
        print("All dependencies are installed!")
        sys.exit(0)
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    if args.host != '0.0.0.0':
        config.setdefault('server', {})['host'] = args.host
    if args.port != 8080:
        config.setdefault('server', {})['port'] = args.port
    if args.debug:
        config.setdefault('server', {})['debug'] = True
    
    # Create required directories
    create_required_directories(config)
    
    try:
        # Import et démarrage du dashboard
        from web_dashboard import WebDashboard
        
        logger.info("Starting DevSecOps Security Dashboard")
        logger.info(f"Host: {args.host}")
        logger.info(f"Port: {args.port}")
        logger.info(f"Debug mode: {args.debug}")
        
        # Créer et démarrer le dashboard
        dashboard = WebDashboard(config)
        
        print("\n" + "="*60)
        print("🛡️  DevSecOps Security Dashboard")
        print("="*60)
        print(f"🌐 Web Interface: http://{args.host}:{args.port}")
        print(f"📊 Dashboard: http://{args.host}:{args.port}/")
        print(f"🔍 API Status: http://{args.host}:{args.port}/api/system/health")
        print("="*60)
        print("\nPress Ctrl+C to stop the server")
        print()
        
        # Démarrer le serveur
        dashboard.start(
            host=args.host, 
            port=args.port, 
            debug=args.debug
        )
        
    except KeyboardInterrupt:
        print("\n\nShutting down DevSecOps Dashboard...")
        logger.info("Dashboard stopped by user")
        
    except ImportError as e:
        logger.error(f"Failed to import dashboard modules: {e}")
        print("Error: Failed to import required modules.")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r dashboard/requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Error starting dashboard: {e}")
        print(f"Error starting dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()