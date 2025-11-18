# Threat Intelligence Platform - Usage Guide

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Tool](#cli-tool)
- [REST API](#rest-api)
- [Python API](#python-api)
- [Threat Feed Collectors](#threat-feed-collectors)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)

## Quick Start

### Installation

```bash
# Navigate to project directory
cd projects/10-threat-intelligence-platform

# Install dependencies
pip install -r requirements.txt

# Set up API keys (optional, for threat feed collectors)
export OTX_API_KEY="your_otx_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

### Run Demo

```bash
# Run comprehensive demonstration
python examples/demo.py
```

### Start REST API Server

```bash
# Start API server
cd src/api
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# API available at: http://localhost:8000
# Interactive docs: http://localhost:8000/docs
```

## CLI Tool

The platform includes a comprehensive command-line interface for testing and interaction.

### Basic Commands

#### Add IOC

```bash
# Add IP address
python src/cli.py add ip 192.0.2.100 \
  --threat-level high \
  --confidence high \
  --tags malware c2 apt28 \
  --description "Known C2 server"

# Add domain
python src/cli.py add domain malicious.example.com \
  --threat-level critical \
  --tags phishing

# Add file hash
python src/cli.py add hash d41d8cd98f00b204e9800998ecf8427e \
  --threat-level medium \
  --tags ransomware wannacry
```

#### Search IOCs

```bash
# Search by keyword
python src/cli.py search apt28

# Search with limit
python src/cli.py search malware --limit 20
```

#### List IOCs

```bash
# List all IOCs
python src/cli.py list

# Filter by type
python src/cli.py list --type ip

# Filter by threat level
python src/cli.py list --threat-level high --limit 100
```

#### Find Related IOCs

```bash
# Find IOCs related to specific IOC ID
python src/cli.py related <ioc_id> --limit 10
```

#### Calculate Threat Score

```bash
# Get threat score for specific IOC
python src/cli.py score <ioc_id>
```

#### Identify Campaigns

```bash
# Identify threat campaigns
python src/cli.py campaigns --min-iocs 3
```

#### Platform Statistics

```bash
# Show statistics
python src/cli.py stats
```

#### Collect from Threat Feeds

```bash
# Collect from OTX
python src/cli.py collect otx --api-key your_api_key

# Collect from AbuseIPDB
python src/cli.py collect abuseipdb --api-key your_api_key

# Or use environment variables
export OTX_API_KEY="your_key"
python src/cli.py collect otx
```

#### Export IOCs

```bash
# Export to JSON
python src/cli.py export iocs.json --format json

# Export to CSV
python src/cli.py export iocs.csv --format csv
```

## REST API

The platform provides a FastAPI-based REST API for integration.

### Starting the Server

```bash
# Development mode (with auto-reload)
cd src/api
uvicorn main:app --reload

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### API Endpoints

#### Health & Status

```bash
# API status
curl http://localhost:8000/

# Health check with statistics
curl http://localhost:8000/health
```

#### IOC Management

```bash
# Get all IOCs
curl http://localhost:8000/api/iocs

# Get IOCs with filters
curl "http://localhost:8000/api/iocs?ioc_type=ip&threat_level=high&limit=50"

# Search IOCs
curl "http://localhost:8000/api/iocs/search?q=apt28&limit=10"

# Get specific IOC
curl http://localhost:8000/api/iocs/<ioc_id>

# Get related IOCs
curl "http://localhost:8000/api/iocs/<ioc_id>/related?limit=20"

# Add new IOC
curl -X POST http://localhost:8000/api/iocs \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_type": "ip",
    "value": "198.51.100.10",
    "threat_level": "high",
    "confidence": "medium",
    "tags": ["malware", "botnet"],
    "description": "Botnet C2 server"
  }'

# Delete expired IOCs
curl -X DELETE http://localhost:8000/api/iocs/expired
```

#### Campaign Analysis

```bash
# Identify threat campaigns
curl "http://localhost:8000/api/campaigns?min_iocs=3"
```

#### Statistics

```bash
# Get platform statistics
curl http://localhost:8000/api/statistics
```

### API Response Examples

#### GET /api/iocs/{ioc_id}

```json
{
  "ioc": {
    "ioc_id": "550e8400-e29b-41d4-a716-446655440000",
    "ioc_type": "ip",
    "value": "192.0.2.100",
    "threat_level": "high",
    "confidence": "high",
    "first_seen": "2025-01-15T10:30:00",
    "last_seen": "2025-01-15T14:20:00",
    "tags": ["malware", "c2", "apt28"],
    "description": "Known C2 server",
    "sources": ["OTX", "AbuseIPDB"]
  },
  "threat_score": 85.5,
  "related_iocs": [...]
}
```

#### GET /api/campaigns

```json
{
  "total_campaigns": 3,
  "campaigns": [
    {
      "name": "Campaign_apt28",
      "ioc_count": 15,
      "first_seen": "2025-01-10T08:00:00",
      "last_seen": "2025-01-15T16:30:00",
      "threat_level": "high",
      "iocs": [...]
    }
  ]
}
```

## Python API

Use the platform as a Python library in your applications.

### Basic Usage

```python
from models import IOC, IOCType, ThreatLevel, Confidence
from processors.correlation_engine import CorrelationEngine

# Initialize correlation engine
engine = CorrelationEngine()

# Create IOC
ioc = IOC(
    ioc_type=IOCType.IP,
    value="192.0.2.100",
    threat_level=ThreatLevel.HIGH,
    confidence=Confidence.HIGH,
    tags=["malware", "c2"],
    description="Suspicious IP address"
)

# Add to engine
engine.add_ioc(ioc)

# Search
results = engine.search("malware", limit=10)

# Find related IOCs
related = engine.find_related_iocs(ioc, max_results=20)

# Calculate threat score
score = engine.calculate_threat_score(ioc)

# Get statistics
stats = engine.get_statistics()

# Identify campaigns
campaigns = engine.identify_campaigns(min_iocs=3)
```

### Working with Collectors

```python
import os
from collectors import OTXCollector, AbuseIPDBCollector

# Initialize collector
otx = OTXCollector(api_key=os.getenv('OTX_API_KEY'))

# Collect IOCs
iocs = otx.collect()

# Add to correlation engine
for ioc in iocs:
    engine.add_ioc(ioc)

# Check feed statistics
print(f"Feed: {otx.feed.name}")
print(f"Status: {otx.feed.status.value}")
print(f"Last Updated: {otx.feed.last_updated}")
print(f"IOC Count: {otx.feed.ioc_count}")
```

### Advanced Correlation

```python
# Find IOCs with common tags
def find_by_tags(engine, tags):
    results = []
    for ioc in engine.ioc_database.values():
        if any(tag in ioc.tags for tag in tags):
            results.append(ioc)
    return results

# Get high-threat IOCs
high_threat = [
    ioc for ioc in engine.ioc_database.values()
    if ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
]

# Get recent IOCs (last 24 hours)
from datetime import datetime, timedelta
cutoff = datetime.now() - timedelta(hours=24)
recent = [
    ioc for ioc in engine.ioc_database.values()
    if ioc.last_seen > cutoff
]
```

## Threat Feed Collectors

### Supported Feeds

1. **AlienVault OTX** (Open Threat Exchange)
   - Free API key required
   - Sign up at: https://otx.alienvault.com/
   - Provides: IPs, domains, URLs, hashes, threat pulses

2. **AbuseIPDB**
   - Free API key required (with limits)
   - Sign up at: https://www.abuseipdb.com/
   - Provides: IP reputation, abuse confidence scores

### Configuration

```bash
# Set API keys as environment variables
export OTX_API_KEY="your_otx_api_key_here"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key_here"
```

### Automated Collection

Create a collection script for scheduled execution:

```python
#!/usr/bin/env python3
"""Automated threat intelligence collection"""

import os
from collectors import OTXCollector, AbuseIPDBCollector
from processors.correlation_engine import CorrelationEngine

def collect_all():
    engine = CorrelationEngine()

    # OTX collection
    try:
        otx = OTXCollector(api_key=os.getenv('OTX_API_KEY'))
        otx_iocs = otx.collect()
        for ioc in otx_iocs:
            engine.add_ioc(ioc)
        print(f"Collected {len(otx_iocs)} IOCs from OTX")
    except Exception as e:
        print(f"OTX collection failed: {e}")

    # AbuseIPDB collection
    try:
        abuseipdb = AbuseIPDBCollector(api_key=os.getenv('ABUSEIPDB_API_KEY'))
        abuse_iocs = abuseipdb.collect()
        for ioc in abuse_iocs:
            engine.add_ioc(ioc)
        print(f"Collected {len(abuse_iocs)} IOCs from AbuseIPDB")
    except Exception as e:
        print(f"AbuseIPDB collection failed: {e}")

    # Identify campaigns
    campaigns = engine.identify_campaigns(min_iocs=3)
    print(f"Identified {len(campaigns)} campaigns")

    return engine

if __name__ == '__main__':
    collect_all()
```

Schedule with cron:
```bash
# Run every hour
0 * * * * /usr/bin/python3 /path/to/collect_script.py
```

## Integration Examples

### SIEM Integration

```python
# Query IOCs from SIEM events
def check_ip_reputation(ip_address, engine):
    # Search for IP in IOC database
    results = engine.search(ip_address, limit=1)

    if results:
        ioc = results[0]
        score = engine.calculate_threat_score(ioc)
        return {
            'malicious': True,
            'threat_level': ioc.threat_level.value,
            'threat_score': score,
            'tags': ioc.tags,
            'sources': ioc.sources
        }

    return {'malicious': False}

# Example usage
reputation = check_ip_reputation("192.0.2.100", engine)
if reputation['malicious'] and reputation['threat_score'] > 70:
    # Trigger alert
    send_alert(f"High-threat IP detected: {reputation}")
```

### Firewall Blocklist Export

```python
# Export high-threat IPs for firewall blocking
def export_blocklist(engine, output_file):
    high_threat = [
        ioc for ioc in engine.ioc_database.values()
        if ioc.ioc_type == IOCType.IP and
           ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    ]

    with open(output_file, 'w') as f:
        for ioc in high_threat:
            f.write(f"{ioc.value}\n")

    print(f"Exported {len(high_threat)} IPs to {output_file}")

# Use with firewall
export_blocklist(engine, '/etc/firewall/blocklist.txt')
```

### IDS/IPS Integration

```python
# Generate Snort rules from IOCs
def generate_snort_rules(engine):
    rules = []

    for ioc in engine.ioc_database.values():
        if ioc.ioc_type == IOCType.IP and ioc.threat_level == ThreatLevel.CRITICAL:
            rule = f'alert ip {ioc.value} any -> any any (msg:"Threat Intel: {ioc.description}"; sid:1000001;)'
            rules.append(rule)

        elif ioc.ioc_type == IOCType.DOMAIN:
            rule = f'alert dns any any -> any any (msg:"Threat Intel: {ioc.description}"; dns_query; content:"{ioc.value}"; sid:1000002;)'
            rules.append(rule)

    return rules
```

## Best Practices

### IOC Management

1. **Regular Collection**: Schedule automated collection from threat feeds hourly or daily
2. **Deduplication**: The correlation engine automatically deduplicates IOCs
3. **Expiration**: Remove expired IOCs regularly using the API endpoint
4. **Tagging**: Use consistent tags for easy filtering and correlation
5. **Confidence Levels**: Always set appropriate confidence levels for manual IOCs

### Performance Optimization

1. **Limit Results**: Use limit parameters in searches to avoid large result sets
2. **Filters**: Apply filters (type, threat level) to reduce processing
3. **Caching**: Consider caching frequently accessed IOCs
4. **Background Jobs**: Run collection and analysis as background tasks

### Security

1. **API Keys**: Store API keys in environment variables, never in code
2. **Authentication**: Implement authentication for the REST API in production
3. **HTTPS**: Always use HTTPS in production deployments
4. **Rate Limiting**: Implement rate limiting for API endpoints
5. **Input Validation**: The platform validates IOC values, but always sanitize user input

### Monitoring

1. **Statistics**: Regularly check platform statistics via `/api/statistics`
2. **Campaign Tracking**: Monitor identified campaigns for emerging threats
3. **Feed Health**: Check threat feed status and last update times
4. **Alert Thresholds**: Set up alerts for high-threat IOCs or new campaigns

### Integration

1. **Start Small**: Begin with one integration (e.g., SIEM lookup)
2. **Test Thoroughly**: Validate IOC data before blocking/alerting
3. **False Positive Management**: Implement whitelisting for known false positives
4. **Documentation**: Document all integrations and data flows
5. **Version Control**: Track changes to integration scripts

## Troubleshooting

### Common Issues

**Issue**: Collector returns no IOCs
**Solution**: Check API key validity and rate limits

**Issue**: Low correlation results
**Solution**: Ensure IOCs have tags and consistent naming

**Issue**: API server won't start
**Solution**: Check port 8000 availability, install dependencies

**Issue**: High memory usage
**Solution**: Implement IOC expiration, limit database size

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Support

For additional help:
- Review `examples/demo.py` for comprehensive examples
- Check `PROJECT_STATUS.md` for project overview
- Examine source code comments for implementation details
