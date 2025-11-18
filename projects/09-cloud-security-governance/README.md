# 🔐 Cloud Security & Governance

## Project Overview

A functional cloud security governance framework for automated compliance scanning and security assessment. This tool scans cloud infrastructure against industry frameworks (CIS, NIST, ISO27001, SOC2), identifies security misconfigurations, and generates actionable remediation plans.

**Status**: 70% Complete | **Type**: Governance Tool | **Language**: Python | **LOC**: ~2,800

## 🎯 Objectives Achieved

- ✅ **Multi-Cloud Framework**: Extensible architecture for AWS/Azure/GCP
- ✅ **Compliance Scanning**: Automated checks against CIS, NIST standards
- ✅ **AWS Scanner**: S3, EC2, Security Groups, IAM checks
- ✅ **Policy Engine**: Rule-based compliance evaluation
- ✅ **Compliance Scoring**: Weighted scoring algorithm (0-100 scale)
- ✅ **Remediation Plans**: Automated guidance and scripts
- ✅ **CLI Tool**: Command-line interface for security operations
- ✅ **Reporting**: JSON and text format reports

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────┐
│              Governance Layer                    │
│   CLI Tool  │  Policy Engine  │  Reports         │
├──────────────────────────────────────────────────┤
│           Cloud Scanners                         │
│   AWS Scanner  │  Azure*  │  GCP*                │
├──────────────────────────────────────────────────┤
│         Compliance Frameworks                    │
│   CIS  │  NIST  │  ISO27001  │  SOC2             │
└──────────────────────────────────────────────────┘

* Future enhancement
```

## 📊 Features Implemented

### AWS Security Scanner
- **S3 Buckets**: Encryption, public access, versioning, logging
- **EC2 Instances**: Monitoring, EBS encryption, IMDSv2
- **Security Groups**: SSH access, database ports, overly permissive rules
- **IAM**: MFA enforcement, key rotation, password policies

### Policy Engine
- **CIS AWS Foundation Benchmark** controls
- **NIST Cybersecurity Framework** mapping
- **ISO 27001** requirements
- **SOC 2** compliance checks
- Rule-based evaluation
- Automated remediation generation
- Priority and effort estimation

### Compliance Reporting
- Compliance score calculation
- Findings by severity and status
- Top risks identification
- Evidence collection
- Audit trail support
- JSON/text export

### CLI Tool
```bash
scan            # Run compliance scan
report          # Generate formatted report
rules           # List policy rules
remediate       # Create remediation plan
export          # Export policies/findings
```

## 🚀 Quick Start

### Installation

```bash
# Navigate to project directory
cd projects/09-cloud-security-governance

# Install dependencies
pip install -r requirements.txt
```

### Run Demo

```bash
# Run comprehensive demonstration
python examples/demo.py
```

### Run Compliance Scan

```bash
# Scan AWS environment
python src/cli.py scan --provider aws --framework cis --output scan.json

# Generate report
python src/cli.py report scan.json --format text

# Create remediation plan
python src/cli.py remediate scan.json --severity critical
```

## 📖 Usage Examples

### CLI Usage

```bash
# Full compliance scan with CIS framework
python src/cli.py scan --provider aws --framework cis \\
    --account-id 123456789012 --region us-east-1 --output scan.json

# Generate formatted report
python src/cli.py report scan.json --format text --output report.txt

# List all CIS rules
python src/cli.py rules --framework cis

# List critical severity rules only
python src/cli.py rules --severity critical

# Generate remediation plan for critical findings
python src/cli.py remediate scan.json --severity critical --output remediate.json

# Export all policies
python src/cli.py export --type policies --output policies.json
```

### Python API

```python
from src.scanners.aws_scanner import AWSSecurityScanner
from src.policies.policy_engine import PolicyEngine
from src.models import ComplianceReport, CloudProvider, ComplianceFramework

# Initialize AWS scanner
scanner = AWSSecurityScanner(
    account_id="123456789012",
    region="us-east-1"
)

# Run full security scan
findings = scanner.run_full_scan()
print(f"Found {len(findings)} security issues")

# Create compliance report
report = ComplianceReport(
    report_id="scan_001",
    provider=CloudProvider.AWS,
    framework=ComplianceFramework.CIS,
    account_id="123456789012",
    findings=findings,
    total_resources=20
)

# Calculate compliance metrics
report.calculate_metrics()
print(f"Compliance Score: {report.compliance_score:.1f}%")

# Save report
report.save("compliance_report.json")

# Generate remediation plans
engine = PolicyEngine()
for finding in findings[:3]:  # Top 3 findings
    plan = engine.generate_remediation_plan(finding)
    print(f"\nRemediation for: {finding.title}")
    print(f"Priority: {plan['priority']}")
    print(f"Steps: {plan['steps']}")
```

## 🛠️ Technologies Used

### Core Framework
- **Python 3.9+**: Modern Python with type hints
- **Dataclasses**: Clean data modeling
- **Enums**: Type-safe enumerations

### Compliance Frameworks
- **CIS Benchmarks**: AWS Foundation Benchmark v1.5
- **NIST CSF**: Cybersecurity Framework controls
- **ISO 27001**: Information security standards
- **SOC 2**: Service organization controls

## 📚 Project Structure

```
09-cloud-security-governance/
├── src/
│   ├── models.py                    # Data models (350 LOC)
│   ├── scanners/
│   │   └── aws_scanner.py           # AWS scanner (600 LOC)
│   ├── policies/
│   │   └── policy_engine.py         # Policy engine (300 LOC)
│   └── cli.py                        # CLI interface (450 LOC)
├── examples/
│   └── demo.py                      # Demo script (300 LOC)
├── README.md                         # This file
├── PROJECT_STATUS.md                 # Detailed status
└── requirements.txt                  # Dependencies

Total: ~2,800 lines of Python code
```

## 🎓 Learning Outcomes

### Cloud Security Concepts
- CIS Benchmarks and best practices
- NIST Cybersecurity Framework
- AWS security services concepts
- Compliance automation strategies
- Risk assessment methodologies

### Technical Skills
- Multi-cloud scanner architecture
- Policy-as-code implementation
- Compliance scoring algorithms
- CLI tool development
- Security automation patterns

### Governance Practices
- Compliance reporting and metrics
- Remediation planning
- Audit trail management
- Risk prioritization
- Security automation workflows

## 🔍 Security Checks Implemented

### S3 Buckets (CIS 2.1.x)
- ✅ Default encryption enabled
- ✅ Block public access
- ✅ Versioning enabled
- ✅ Access logging configured

### EC2 Instances (CIS 4.x, 2.2.x)
- ✅ Detailed monitoring enabled
- ✅ EBS volumes encrypted
- ✅ IMDSv2 enforced

### Security Groups (CIS 5.x)
- ✅ No unrestricted SSH (port 22)
- ✅ No unrestricted database ports

### IAM (CIS 1.x)
- ✅ MFA enabled for users
- ✅ Access keys rotated (90 days)
- ✅ Passwords rotated (90 days)

## 📊 Compliance Scoring

The compliance score is calculated using a weighted algorithm:

- **Critical findings**: -10 points each
- **High findings**: -5 points each
- **Medium findings**: -2 points each
- **Low findings**: -1 point each

**Base score**: 100 (perfect compliance)
**Final score**: Base - Total weighted findings

## 📝 Documentation

- **[PROJECT_STATUS.md](PROJECT_STATUS.md)**: Detailed project status
- **[examples/demo.py](examples/demo.py)**: Complete demonstration

## 🚧 Known Limitations

- **Simulated Scanning**: Uses simulated data for demonstration
- **AWS Only**: Only AWS scanner currently implemented
- **Limited Rules**: Subset of CIS/NIST controls implemented

## 🔄 Future Enhancements

### Short Term
- Unit tests with pytest
- Azure and GCP scanners
- More CIS controls
- Real cloud API integration (boto3)

### Medium Term
- Web dashboard
- Scheduled scanning
- Trend analysis

### Long Term
- Machine learning anomaly detection
- Automated remediation execution
- Multi-account support

## 🎯 Use Cases

1. **Compliance Audits**: Automated compliance assessment
2. **Security Operations**: Continuous security posture monitoring
3. **DevSecOps**: Security gates in CI/CD pipelines
4. **Risk Management**: Identify and prioritize security risks
5. **Governance**: Policy enforcement and tracking

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Note**: This tool is designed for security assessment and education. Always follow your organization's security policies when scanning cloud environments.

---

*Built as part of a cybersecurity portfolio to demonstrate cloud security and governance automation skills.*
