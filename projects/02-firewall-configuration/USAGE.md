# Firewall Configuration Framework - Usage Guide

## Quick Start

### Installation

```bash
# Clone the repository
cd projects/02-firewall-configuration

# Install dependencies
pip install -r requirements.txt

# Make CLI tool executable
chmod +x src/firewall_manager.py
```

### Basic Usage

#### 1. Create a Sample Policy

```bash
python src/firewall_manager.py sample --output my_policy.json
```

#### 2. Generate Firewall Configuration

Generate configuration for different platforms:

```bash
# For iptables (Linux)
python src/firewall_manager.py generate iptables --policy my_policy.json --output firewall.sh

# For pfSense (FreeBSD pf)
python src/firewall_manager.py generate pfsense --policy my_policy.json --output pf.conf

# For FortiGate
python src/firewall_manager.py generate fortigate --policy my_policy.json --output fortigate.conf

# For Cisco ASA
python src/firewall_manager.py generate cisco-asa --policy my_policy.json --output asa.conf
```

#### 3. Analyze Policy for Issues

```bash
python src/firewall_manager.py analyze my_policy.json
```

Output example:
```
======================================================================
  FIREWALL POLICY AUDIT REPORT
======================================================================

Policy: Enterprise_Security_Policy
Date: 2025-01-15 14:30:22

======================================================================
  SUMMARY
======================================================================

Total Rules:          25
Enabled Rules:        23
Conflicts Found:      3
  - Critical:         1
  - High:             2
  - Medium:           0
High-Risk Rules:      4
Compliance Score:     78.5%
```

#### 4. Generate Detailed Report

```bash
# HTML report (recommended for sharing)
python src/firewall_manager.py report my_policy.json --format html --output report.html

# JSON report (for automation/parsing)
python src/firewall_manager.py report my_policy.json --format json --output report.json
```

## Advanced Usage

### Using Python API

```python
from src.firewall_manager import FirewallManager
from src.models import *

# Create manager
manager = FirewallManager()

# Create policy
policy = manager.create_policy(
    name="My_Firewall_Policy",
    description="Custom firewall configuration"
)

# Add custom rules
rule = FirewallRule(
    rule_id=1,
    name="Allow_Web_Traffic",
    action=Action.ALLOW,
    source=NetworkObject("LAN", "192.168.1.0", "255.255.255.0"),
    destination=COMMON_NETWORKS['any'],
    service=COMMON_SERVICES['https'],
    logging=True
)

manager.add_rule(rule)

# Generate configuration
config = manager.generate_config('iptables', 'firewall.sh')

# Analyze
manager.analyze_policy()
```

### Custom Network Objects

```python
# Define custom network objects
web_dmz = NetworkObject(
    name="Web_DMZ",
    ip_address="172.16.10.0",
    netmask="255.255.255.0",
    description="DMZ for web servers",
    object_type="network"
)

# Create network groups
servers_group = NetworkObject(
    name="All_Servers",
    object_type="group",
    members=["web_dmz", "app_dmz", "db_dmz"]
)
```

### Custom Services

```python
# Define custom service
custom_app = Service(
    name="Custom_App",
    protocol=Protocol.TCP,
    port="8080",
    description="Custom application port"
)

# Port range
web_range = Service(
    name="Web_Ports",
    protocol=Protocol.TCP,
    port="80-443",
    description="Web traffic port range"
)
```

## Rule Analysis Features

### Conflict Detection

The analyzer detects three types of conflicts:

1. **Shadowed Rules**: Rules that will never be matched because an earlier rule is broader
2. **Redundant Rules**: Duplicate rules with the same match criteria
3. **Contradictory Rules**: Same match criteria but different actions

### Risk Assessment

High-risk rules are identified based on:
- Source is "any" (unrestricted)
- Sensitive ports without restriction (SSH, RDP, database ports)
- Missing logging
- No description/documentation

### Compliance Scoring

Compliance score (0-100%) considers:
- Number and severity of conflicts
- High-risk rules present
- Logging coverage
- Default policy setting
- Documentation completeness

## Platform-Specific Outputs

### iptables (Linux)

```bash
# Generated script is ready to execute
chmod +x firewall.sh
sudo ./firewall.sh
```

Features:
- Automatic chain flushing
- Stateful connection tracking
- Default policy configuration
- Automatic rules save

### pfSense (FreeBSD pf)

```bash
# Load configuration
sudo pfctl -f pf.conf

# Test configuration without applying
sudo pfctl -nf pf.conf
```

Features:
- Normalization (scrub) rules
- Quick matching (first-match-wins)
- Table support for IP lists
- Logging integration

### FortiGate

Features:
- Policy-based configuration
- Interface bindings
- Service objects
- Logging controls
- Status management

### Cisco ASA

Features:
- Extended ACLs
- Interface application
- Network/host objects
- Logging integration

## Best Practices

### Rule Organization

1. **Most specific rules first**: Place narrow rules before broad ones
2. **Group related rules**: Use tags to organize rules by function
3. **Document everything**: Always include descriptions
4. **Enable logging**: At least for DENY rules and sensitive allows
5. **Regular audits**: Analyze policy weekly for large environments

### Security Recommendations

1. **Default Deny**: Always use DENY as default action
2. **Principle of Least Privilege**: Only allow necessary traffic
3. **Separate DMZ**: Isolate public-facing services
4. **Management Network**: Dedicated network for administration
5. **Rate Limiting**: Consider implementing for public services

### Performance Optimization

1. **Rule Order**: Put most-hit rules at the top
2. **Consolidation**: Combine similar rules when possible
3. **Groups**: Use network/service groups for readability
4. **Disable Unused**: Remove or disable obsolete rules

## Troubleshooting

### Common Issues

**Issue**: Generated configuration not working
**Solution**: Check platform syntax with `--dry-run` first

**Issue**: Conflicts not detected
**Solution**: Ensure rules are enabled and have correct network objects

**Issue**: Low compliance score
**Solution**: Review recommendations section in audit report

### Debug Mode

Enable verbose output:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Examples

See `examples/example_usage.py` for a comprehensive demonstration of all features.

## Support

For issues, questions, or contributions:
- Review documentation in `README.md`
- Check example scripts in `examples/`
- Examine test cases in `tests/`
