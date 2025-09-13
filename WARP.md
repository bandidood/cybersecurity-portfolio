# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository Overview

This is a professional cybersecurity portfolio containing 50+ hands-on mini-projects demonstrating expertise across all cybersecurity domains. The repository is structured as an educational and professional showcase covering network security, penetration testing, security architecture, incident response, and compliance.

## Common Development Commands

### Repository Setup
```powershell
# Clone and initialize repository
git clone https://github.com/[USERNAME]/cybersecurity-portfolio.git
cd cybersecurity-portfolio

# View portfolio summary
.\show-portfolio-summary.ps1

# Or on Linux/macOS
./show-portfolio-summary.sh
```

### Project Management
```bash
# Deploy home lab infrastructure (Project 01)
cd projects/01-home-lab-setup/scripts/setup/
./deploy-lab.sh

# Run health check monitoring
cd projects/01-home-lab-setup/scripts/monitoring/
python3 health-check.py

# Generate network traffic for analysis (Project 03)
cd projects/projet_03_analyse_trafic_wireshark/scripts/
./generate_test_traffic.sh
python3 advanced_analyzer.py capture.pcap
```

### Git Operations
```bash
# Standard git workflow for portfolio updates
git init                                    # Initialize repository
git add .                                   # Stage all files
git commit -m "feat: project description"  # Commit with descriptive message
git push origin main                        # Push to remote repository

# Set up repository
bash setup-git-repo.sh
```

## High-Level Architecture

### Directory Structure
- **`projects/`** - 50 mini-projects organized by security domain:
  - `01-home-lab-setup/` - Virtualized security lab infrastructure
  - `02-firewall-configuration/` - Enterprise firewall deployment
  - `projet_03_analyse_trafic_wireshark/` - Network traffic analysis tools
  - Additional projects covering pentest, web security, cloud security, etc.

- **`docs/`** - Professional documentation and certifications
- **`tools/`** - Custom security tools and utilities developed
- **`research/`** - Security research publications and findings  
- **`templates/`** - Reusable configurations and boilerplates

### Key Technologies
- **Infrastructure**: VMware/VirtualBox, pfSense, Active Directory, ELK Stack
- **Languages**: Python (security automation), Bash (deployment scripts), PowerShell (Windows administration)
- **Security Tools**: Kali Linux, Wireshark, Nmap, Burp Suite, Metasploit
- **Cloud Platforms**: AWS, Azure, GCP (security configurations)
- **Monitoring**: ELK Stack, Splunk, custom Python monitoring tools

### Project Architecture Pattern
Each project follows a consistent structure:
```
project-xx-name/
├── README.md          # Detailed project documentation  
├── CHANGELOG.md       # Version history and updates
├── scripts/           # Automation and deployment scripts
├── configs/           # Configuration files and templates
├── docs/              # Technical documentation
├── evidence/          # Screenshots, logs, reports (anonymized)
└── tests/             # Validation and security tests
```

## Security Considerations

### Data Protection
- All logs, captures, and evidence are sanitized and anonymized
- `.gitignore` prevents committing sensitive files (credentials, PII, real network captures)
- Test data only - no production or client information
- VM isolation ensures contained testing environment

### Operational Security
- Network segments isolated from production environments
- Default credentials must be changed before deployment
- Regular security updates and patching required
- Monitoring and logging enabled for all activities

### Compliance Standards
Projects align with industry frameworks:
- **NIST Cybersecurity Framework** - Risk management and security controls
- **ISO 27001** - Information security management
- **OWASP Top 10** - Web application security standards  
- **CIS Controls** - Critical security controls implementation

## Key Scripts and Tools

### Infrastructure Management
- `projects/01-home-lab-setup/scripts/setup/deploy-lab.sh` - Automated lab deployment
- `projects/01-home-lab-setup/scripts/monitoring/health-check.py` - System health monitoring
- `setup-git-repo.sh` - Repository initialization and GitHub setup

### Analysis and Security Tools  
- `projects/projet_03_analyse_trafic_wireshark/scripts/advanced_analyzer.py` - Network traffic analysis with threat detection
- `projects/projet_03_analyse_trafic_wireshark/scripts/setup_wireshark.sh` - Wireshark environment configuration
- Various monitoring, alerting, and analysis scripts across projects

### Configuration Management
- `projects/01-home-lab-setup/configs/pfsense/firewall-rules.conf` - pfSense firewall rules
- VM templates and network configurations in respective project directories
- ELK Stack configurations for SIEM deployment

## Project-Specific Guidelines

### Documentation Standards
- Every project includes comprehensive README.md with objectives, methodology, and results
- CHANGELOG.md tracks all modifications and improvements
- Evidence directories contain screenshots and sanitized logs
- Architecture diagrams and network topologies documented

### Naming Conventions
- Projects: `XX-descriptive-name/` (numbered for organization)
- VMs: `Service-Role` format (e.g., `pfSense-Firewall`, `Kali-Attacker`)
- Scripts: Descriptive names with action verbs (`deploy-lab.sh`, `health-check.py`)
- Network segments: Purpose-based (`LAN-Internal`, `DMZ`, `RedTeam`, `BlueTeam`)

### Testing and Validation
- Each project includes validation tests and acceptance criteria
- Security testing performed in isolated environments only
- Performance benchmarks and success metrics defined
- Regular health checks and monitoring implemented

### Version Control Best Practices
- Atomic commits with clear, descriptive messages
- Feature branches for major project additions  
- No sensitive data in commit history
- Regular documentation updates with code changes

## Development Environment Setup

### Prerequisites
- **Hypervisor**: VMware Workstation Pro, VirtualBox, or Hyper-V
- **System Requirements**: 16GB+ RAM, 500GB+ available storage, CPU with virtualization support
- **Network**: Isolated lab network for security testing
- **Python**: 3.8+ with security libraries (pyshark, scapy, requests)

### Common Dependencies
```bash
# Python security tools
pip3 install pyshark scapy requests psutil

# System monitoring tools  
sudo apt-get install htop iftop tcpdump wireshark-qt

# Virtualization tools (varies by platform)
# VMware Workstation, VirtualBox, or cloud instances
```

### Environment Variables
- Credentials managed through environment variables or secure vaults
- No hardcoded passwords or API keys in source code
- Test environment configurations separate from any production systems

This cybersecurity portfolio demonstrates practical security expertise through hands-on projects while maintaining strict operational security and professional documentation standards.