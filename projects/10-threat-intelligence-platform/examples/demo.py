#!/usr/bin/env python3
"""
Threat Intelligence Platform - Demonstration Script
Shows complete workflow: collection, correlation, analysis
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from models import IOC, ThreatFeed, IOCType, ThreatLevel, Confidence
from collectors import OTXCollector, AbuseIPDBCollector
from processors.correlation_engine import CorrelationEngine
import json


def print_header(title: str):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f" {title}")
    print("="*70 + "\n")


def demo_manual_ioc_creation():
    """Demonstrate creating IOCs manually"""
    print_header("1. Manual IOC Creation")

    # Create sample IOCs
    iocs = [
        IOC(
            ioc_type=IOCType.IP,
            value="192.0.2.100",
            threat_level=ThreatLevel.HIGH,
            confidence=Confidence.HIGH,
            tags=["malware", "c2", "apt28"],
            description="Known C2 server for APT28 campaign",
            mitre_tactics=["command-and-control"],
            mitre_techniques=["T1071"]
        ),
        IOC(
            ioc_type=IOCType.DOMAIN,
            value="malicious-domain.example.com",
            threat_level=ThreatLevel.CRITICAL,
            confidence=Confidence.HIGH,
            tags=["phishing", "apt28"],
            description="Phishing domain targeting financial institutions",
            mitre_tactics=["initial-access"],
            mitre_techniques=["T1566"]
        ),
        IOC(
            ioc_type=IOCType.FILE_HASH,
            value="d41d8cd98f00b204e9800998ecf8427e",
            threat_level=ThreatLevel.MEDIUM,
            confidence=Confidence.MEDIUM,
            tags=["ransomware", "wannacry"],
            description="WannaCry ransomware sample hash",
            mitre_tactics=["impact"],
            mitre_techniques=["T1486"]
        ),
        IOC(
            ioc_type=IOCType.URL,
            value="http://evil.example.com/payload.exe",
            threat_level=ThreatLevel.HIGH,
            confidence=Confidence.HIGH,
            tags=["malware", "dropper"],
            description="Malware distribution URL",
            mitre_tactics=["execution"],
            mitre_techniques=["T1204"]
        )
    ]

    print(f"Created {len(iocs)} sample IOCs:")
    for ioc in iocs:
        print(f"  • {ioc.ioc_type.value:12} | {ioc.value:40} | {ioc.threat_level.value}")

    return iocs


def demo_correlation_engine(iocs):
    """Demonstrate correlation engine capabilities"""
    print_header("2. Correlation Engine Analysis")

    # Initialize correlation engine
    engine = CorrelationEngine()

    # Add IOCs to engine
    print(f"Adding {len(iocs)} IOCs to correlation engine...")
    for ioc in iocs:
        engine.add_ioc(ioc)

    # Add some related IOCs for correlation demo
    related_iocs = [
        IOC(
            ioc_type=IOCType.IP,
            value="192.0.2.101",
            threat_level=ThreatLevel.HIGH,
            confidence=Confidence.MEDIUM,
            tags=["malware", "c2", "apt28"],  # Same campaign
            description="Secondary C2 server",
            mitre_tactics=["command-and-control"],
            mitre_techniques=["T1071"]
        ),
        IOC(
            ioc_type=IOCType.IP,
            value="192.0.2.102",
            threat_level=ThreatLevel.MEDIUM,
            confidence=Confidence.LOW,
            tags=["scanning", "apt28"],  # Same actor
            description="Reconnaissance scanning IP"
        )
    ]

    for ioc in related_iocs:
        engine.add_ioc(ioc)

    # Get statistics
    stats = engine.get_statistics()
    print(f"\nEngine Statistics:")
    print(f"  • Total IOCs: {stats['total_iocs']}")
    print(f"  • By Type: {json.dumps(stats['by_type'], indent=4)}")
    print(f"  • By Threat Level: {json.dumps(stats['by_threat_level'], indent=4)}")

    # Find related IOCs
    print(f"\n\nFinding IOCs related to: {iocs[0].value}")
    related = engine.find_related_iocs(iocs[0], max_results=5)
    print(f"Found {len(related)} related IOCs:")
    for r in related:
        score = engine.calculate_threat_score(r)
        print(f"  • {r.value:40} | Score: {score:.1f} | Tags: {', '.join(r.tags[:3])}")

    # Search functionality
    print(f"\n\nSearching for 'apt28' across all IOCs...")
    search_results = engine.search("apt28", limit=10)
    print(f"Found {len(search_results)} matches:")
    for result in search_results:
        print(f"  • {result.ioc_type.value:12} | {result.value}")

    # Campaign identification
    print(f"\n\nIdentifying potential threat campaigns...")
    campaigns = engine.identify_campaigns(min_iocs=2)
    print(f"Identified {len(campaigns)} campaigns:")
    for campaign in campaigns:
        print(f"\n  Campaign: {campaign['name']}")
        print(f"    - IOC Count: {campaign['ioc_count']}")
        print(f"    - Threat Level: {campaign['threat_level'].value}")
        print(f"    - First Seen: {campaign['first_seen'].strftime('%Y-%m-%d %H:%M')}")
        print(f"    - Last Seen: {campaign['last_seen'].strftime('%Y-%m-%d %H:%M')}")
        print(f"    - Sample IOCs: {[ioc.value for ioc in campaign['iocs'][:3]]}")

    return engine


def demo_threat_scoring(engine):
    """Demonstrate threat scoring system"""
    print_header("3. Threat Score Calculation")

    print("Calculating threat scores for all IOCs:\n")
    print(f"{'IOC Value':<40} {'Type':<12} {'Score':<8} {'Level'}")
    print("-" * 70)

    for ioc_id, ioc in list(engine.ioc_database.items())[:10]:
        score = engine.calculate_threat_score(ioc)
        print(f"{ioc.value:<40} {ioc.ioc_type.value:<12} {score:<8.1f} {ioc.threat_level.value}")


def demo_collectors():
    """Demonstrate threat feed collectors (simulation)"""
    print_header("4. Threat Feed Collectors (Simulation)")

    # Note: Real collectors require API keys
    print("OTX Collector:")
    print("  • Status: Configured (requires API key)")
    print("  • Feed: AlienVault Open Threat Exchange")
    print("  • Capability: Fetches recent threat pulses and indicators")

    print("\nAbuseIPDB Collector:")
    print("  • Status: Configured (requires API key)")
    print("  • Feed: AbuseIPDB IP Reputation")
    print("  • Capability: Fetches blacklisted IPs with abuse scores")

    print("\nTo use collectors in production:")
    print("  1. Set environment variables:")
    print("     export OTX_API_KEY='your_key_here'")
    print("     export ABUSEIPDB_API_KEY='your_key_here'")
    print("  2. Initialize collector:")
    print("     collector = OTXCollector(api_key=os.getenv('OTX_API_KEY'))")
    print("  3. Collect IOCs:")
    print("     iocs = collector.collect()")


def demo_api_usage():
    """Demonstrate API usage examples"""
    print_header("5. REST API Usage Examples")

    print("Start the API server:")
    print("  $ cd src/api")
    print("  $ uvicorn main:app --reload")
    print()

    print("API Endpoints:\n")

    endpoints = [
        ("GET", "/", "API status and information"),
        ("GET", "/health", "Health check with statistics"),
        ("GET", "/api/iocs", "List all IOCs (with filters)"),
        ("GET", "/api/iocs/search?q=malware", "Search IOCs by keyword"),
        ("GET", "/api/iocs/{ioc_id}", "Get specific IOC details"),
        ("GET", "/api/iocs/{ioc_id}/related", "Get related IOCs"),
        ("GET", "/api/campaigns", "Identify threat campaigns"),
        ("GET", "/api/statistics", "Platform statistics"),
        ("POST", "/api/iocs", "Add new IOC"),
        ("DELETE", "/api/iocs/expired", "Remove expired IOCs"),
    ]

    for method, endpoint, description in endpoints:
        print(f"  {method:<8} {endpoint:<35} - {description}")

    print("\n\nExample cURL commands:")
    print()
    print("# Get all IOCs")
    print("curl http://localhost:8000/api/iocs")
    print()
    print("# Search for specific IOCs")
    print("curl 'http://localhost:8000/api/iocs/search?q=apt28&limit=10'")
    print()
    print("# Add new IOC")
    print("curl -X POST http://localhost:8000/api/iocs \\")
    print("  -H 'Content-Type: application/json' \\")
    print("  -d '{")
    print('    "ioc_type": "ip",')
    print('    "value": "198.51.100.10",')
    print('    "threat_level": "high",')
    print('    "confidence": "medium",')
    print('    "tags": ["malware", "botnet"],')
    print('    "description": "Botnet C2 server"')
    print("  }'")
    print()
    print("# Get threat campaigns")
    print("curl 'http://localhost:8000/api/campaigns?min_iocs=3'")


def demo_integration_workflow():
    """Demonstrate complete integration workflow"""
    print_header("6. Complete Integration Workflow")

    print("Typical workflow for integrating the platform:\n")

    steps = [
        ("1. Setup", [
            "Install dependencies: pip install -r requirements.txt",
            "Configure API keys in environment variables",
            "Start the REST API server"
        ]),
        ("2. Data Collection", [
            "Initialize threat feed collectors",
            "Schedule periodic collection (e.g., hourly cron job)",
            "Store collected IOCs in correlation engine"
        ]),
        ("3. Analysis", [
            "Run correlation analysis on new IOCs",
            "Identify related indicators and campaigns",
            "Calculate threat scores for prioritization"
        ]),
        ("4. Integration", [
            "Query API from SIEM for IOC lookups",
            "Export IOCs to firewall blocklists",
            "Feed indicators to IDS/IPS systems"
        ]),
        ("5. Monitoring", [
            "Track statistics via /api/statistics",
            "Monitor campaign identification",
            "Review high-confidence, high-threat IOCs daily"
        ])
    ]

    for step_name, actions in steps:
        print(f"{step_name}:")
        for action in actions:
            print(f"  • {action}")
        print()


def main():
    """Run complete demonstration"""
    print("\n" + "="*70)
    print(" THREAT INTELLIGENCE PLATFORM - COMPREHENSIVE DEMONSTRATION")
    print("="*70)

    # Run demonstrations
    iocs = demo_manual_ioc_creation()
    engine = demo_correlation_engine(iocs)
    demo_threat_scoring(engine)
    demo_collectors()
    demo_api_usage()
    demo_integration_workflow()

    # Final summary
    print_header("Demonstration Complete")
    print("This demonstration showcased:")
    print("  ✓ Manual IOC creation and management")
    print("  ✓ Correlation engine with relationship detection")
    print("  ✓ Threat scoring and campaign identification")
    print("  ✓ Threat feed collector architecture")
    print("  ✓ REST API endpoints and usage")
    print("  ✓ Complete integration workflow")
    print()
    print("For production deployment:")
    print("  1. Configure API keys for threat feed collectors")
    print("  2. Deploy REST API with proper authentication")
    print("  3. Integrate with existing security infrastructure (SIEM, firewall, IDS)")
    print("  4. Set up automated collection and analysis schedules")
    print()
    print("="*70)


if __name__ == "__main__":
    main()
