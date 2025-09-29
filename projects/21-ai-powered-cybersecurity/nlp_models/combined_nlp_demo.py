#!/usr/bin/env python3
"""
Combined NLP Demonstration Script
Showcasing integrated Security Log Analysis and Threat Intelligence processing
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import sys
import os
from datetime import datetime
import logging
import warnings

# Add the nlp_models directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from log_analyzer import SecurityLogAnalyzer
from threat_intel_analyzer import ThreatIntelligenceAnalyzer

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CybersecurityNLPPlatform:
    """
    Combined Cybersecurity NLP Platform
    Integrates log analysis and threat intelligence for comprehensive security monitoring
    """
    
    def __init__(self):
        """Initialize both analyzers"""
        logger.info("Initializing Cybersecurity NLP Platform...")
        
        # Initialize components
        self.log_analyzer = SecurityLogAnalyzer()
        self.threat_intel_analyzer = ThreatIntelligenceAnalyzer()
        
        # Track initialization status
        self.log_models_trained = False
        self.threat_models_trained = False
        
    def initialize_nlp_models(self):
        """Initialize NLP models for both analyzers"""
        logger.info("Initializing advanced NLP models...")
        
        try:
            # Initialize log analyzer NLP components
            self.log_analyzer.initialize_models()
            logger.info("✓ Log analyzer NLP models initialized")
        except Exception as e:
            logger.warning(f"⚠ Log analyzer NLP models initialization failed: {e}")
        
        # No additional NLP initialization needed for threat intel analyzer
        logger.info("✓ Threat intelligence analyzer ready")
    
    def train_models(self, log_samples=2000, threat_samples=1000):
        """Train both analysis models"""
        logger.info(f"Training models with {log_samples} log samples and {threat_samples} threat intel samples...")
        
        # Train log analyzer
        logger.info("Training Security Log Analyzer...")
        log_data = self.log_analyzer.generate_synthetic_logs(n_samples=log_samples)
        log_metrics = self.log_analyzer.fit(log_data)
        self.log_models_trained = True
        
        # Train threat intelligence analyzer
        logger.info("Training Threat Intelligence Analyzer...")
        threat_data = self.threat_intel_analyzer.generate_synthetic_reports(n_reports=threat_samples)
        threat_metrics = self.threat_intel_analyzer.fit(threat_data)
        self.threat_models_trained = True
        
        return {
            'log_analysis': log_metrics,
            'threat_intelligence': threat_metrics
        }
    
    def analyze_security_incident(self, log_entries, threat_reports):
        """
        Comprehensive security incident analysis
        Combines log analysis with threat intelligence
        """
        results = {
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'analysis_timestamp': datetime.now().isoformat(),
            'log_analysis': [],
            'threat_intelligence': [],
            'correlation': {},
            'recommendations': []
        }
        
        # Analyze logs
        logger.info(f"Analyzing {len(log_entries)} log entries...")
        for i, log_entry in enumerate(log_entries):
            try:
                log_result = self.log_analyzer.analyze_text(log_entry)
                log_result['entry_id'] = f"LOG-{i+1}"
                results['log_analysis'].append(log_result)
            except Exception as e:
                logger.error(f"Failed to analyze log entry {i+1}: {e}")
        
        # Analyze threat reports
        logger.info(f"Analyzing {len(threat_reports)} threat intelligence reports...")
        for i, report in enumerate(threat_reports):
            try:
                threat_result = self.threat_intel_analyzer.analyze_report(report)
                threat_result['report_id'] = f"THREAT-{i+1}"
                results['threat_intelligence'].append(threat_result)
            except Exception as e:
                logger.error(f"Failed to analyze threat report {i+1}: {e}")
        
        # Perform correlation analysis
        results['correlation'] = self._correlate_findings(
            results['log_analysis'], 
            results['threat_intelligence']
        )
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _correlate_findings(self, log_results, threat_results):
        """Correlate findings between log analysis and threat intelligence"""
        correlation = {
            'shared_iocs': [],
            'threat_actor_mentions': [],
            'technique_overlap': [],
            'severity_correlation': {},
            'confidence_score': 0.0
        }
        
        # Extract all IOCs from logs and threat reports
        log_iocs = set()
        threat_iocs = set()
        
        for log_result in log_results:
            for ioc_type, iocs in log_result.get('iocs', {}).items():
                log_iocs.update(iocs)
        
        for threat_result in threat_results:
            for ioc_type, iocs in threat_result.get('iocs', {}).items():
                threat_iocs.update(iocs)
        
        # Find shared IOCs
        shared_iocs = log_iocs.intersection(threat_iocs)
        correlation['shared_iocs'] = list(shared_iocs)
        
        # Check for threat actor mentions in logs
        for threat_result in threat_results:
            if threat_result.get('attribution', {}).get('attributed_actor'):
                actor = threat_result['attribution']['attributed_actor']
                for log_result in log_results:
                    if actor.lower() in log_result.get('original_text', '').lower():
                        correlation['threat_actor_mentions'].append({
                            'actor': actor,
                            'log_entry': log_result.get('entry_id'),
                            'confidence': threat_result['attribution']['confidence']
                        })
        
        # Calculate correlation confidence score
        correlation_factors = [
            len(shared_iocs) * 0.4,  # Shared IOCs weight
            len(correlation['threat_actor_mentions']) * 0.3,  # Actor mentions weight
            min(len(log_results) * len(threat_results) * 0.1, 0.3)  # Volume factor
        ]
        
        correlation['confidence_score'] = min(sum(correlation_factors), 1.0)
        
        return correlation
    
    def _generate_recommendations(self, analysis_results):
        """Generate actionable security recommendations"""
        recommendations = []
        
        # High severity log entries
        high_severity_logs = [
            log for log in analysis_results['log_analysis']
            if log.get('severity', {}).get('severity') in ['critical', 'high']
        ]
        
        if high_severity_logs:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Incident Response',
                'action': f"Investigate {len(high_severity_logs)} high-severity log entries immediately",
                'details': "Critical security events detected requiring immediate attention"
            })
        
        # Threat actor attribution
        attributed_threats = [
            threat for threat in analysis_results['threat_intelligence']
            if threat.get('attribution', {}).get('attributed_actor')
        ]
        
        if attributed_threats:
            actors = [t['attribution']['attributed_actor'] for t in attributed_threats]
            unique_actors = list(set(actors))
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Threat Hunting',
                'action': f"Initiate threat hunting for {', '.join(unique_actors)} TTPs",
                'details': "Known threat actors detected in intelligence reports"
            })
        
        # Shared IOCs
        if analysis_results['correlation']['shared_iocs']:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'IOC Management',
                'action': f"Block/monitor {len(analysis_results['correlation']['shared_iocs'])} correlated IOCs",
                'details': "IOCs appear in both logs and threat intelligence"
            })
        
        # MITRE ATT&CK techniques
        all_techniques = []
        for threat in analysis_results['threat_intelligence']:
            techniques = [ttp['technique_id'] for ttp in threat.get('ttps', [])]
            all_techniques.extend(techniques)
        
        if all_techniques:
            unique_techniques = list(set(all_techniques))
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Defense Enhancement',
                'action': f"Review defenses against {len(unique_techniques)} MITRE ATT&CK techniques",
                'details': f"Techniques identified: {', '.join(unique_techniques[:5])}"
            })
        
        return recommendations
    
    def generate_incident_report(self, analysis_results):
        """Generate a formatted incident report"""
        report = []
        report.append("="*80)
        report.append("CYBERSECURITY INCIDENT ANALYSIS REPORT")
        report.append("="*80)
        report.append(f"Incident ID: {analysis_results['incident_id']}")
        report.append(f"Analysis Time: {analysis_results['analysis_timestamp']}")
        report.append(f"Log Entries Analyzed: {len(analysis_results['log_analysis'])}")
        report.append(f"Threat Reports Analyzed: {len(analysis_results['threat_intelligence'])}")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        
        high_severity_count = len([
            log for log in analysis_results['log_analysis']
            if log.get('severity', {}).get('severity') in ['critical', 'high']
        ])
        
        attributed_actors = len([
            threat for threat in analysis_results['threat_intelligence']
            if threat.get('attribution', {}).get('attributed_actor')
        ])
        
        report.append(f"• High-severity events: {high_severity_count}")
        report.append(f"• Attributed threat actors: {attributed_actors}")
        report.append(f"• Shared IOCs: {len(analysis_results['correlation']['shared_iocs'])}")
        report.append(f"• Correlation confidence: {analysis_results['correlation']['confidence_score']:.2f}")
        report.append("")
        
        # Detailed Findings
        report.append("DETAILED FINDINGS")
        report.append("-" * 40)
        
        # Log Analysis Summary
        if analysis_results['log_analysis']:
            report.append("Log Analysis Highlights:")
            for i, log in enumerate(analysis_results['log_analysis'][:3], 1):  # Top 3
                severity = log.get('severity', {}).get('severity', 'unknown')
                threat_level = log.get('threat_analysis', {}).get('threat_level', 'unknown')
                report.append(f"  {i}. Severity: {severity.upper()}, Threat: {threat_level.upper()}")
                
                # IOCs found
                iocs = log.get('iocs', {})
                total_iocs = sum(len(ioc_list) for ioc_list in iocs.values())
                if total_iocs > 0:
                    report.append(f"     IOCs found: {total_iocs}")
        
        report.append("")
        
        # Threat Intelligence Summary
        if analysis_results['threat_intelligence']:
            report.append("Threat Intelligence Highlights:")
            for i, threat in enumerate(analysis_results['threat_intelligence'][:3], 1):  # Top 3
                attribution = threat.get('attribution', {})
                if attribution.get('attributed_actor'):
                    actor = attribution['attributed_actor']
                    confidence = attribution['confidence']
                    report.append(f"  {i}. Attributed to: {actor} (confidence: {confidence:.2f})")
                
                # MITRE ATT&CK techniques
                ttps = threat.get('ttps', [])
                if ttps:
                    techniques = [ttp['technique_id'] for ttp in ttps[:3]]
                    report.append(f"     MITRE techniques: {', '.join(techniques)}")
        
        report.append("")
        
        # Recommendations
        report.append("RECOMMENDATIONS")
        report.append("-" * 40)
        for i, rec in enumerate(analysis_results['recommendations'], 1):
            report.append(f"{i}. [{rec['priority']}] {rec['category']}: {rec['action']}")
        
        report.append("")
        report.append("="*80)
        
        return "\n".join(report)

def main():
    """Main demonstration function"""
    print("🔒 AI-Powered Cybersecurity NLP Platform Demo")
    print("=" * 60)
    
    # Initialize platform
    platform = CybersecurityNLPPlatform()
    
    # Initialize NLP models (optional)
    try:
        platform.initialize_nlp_models()
    except Exception as e:
        logger.warning(f"Advanced NLP models not available: {e}")
    
    # Train models
    print("\n📊 Training Analysis Models...")
    training_metrics = platform.train_models(log_samples=1500, threat_samples=800)
    
    print(f"✓ Log Analysis Model - Accuracy: {training_metrics['log_analysis'].get('log_type_accuracy', 0):.3f}")
    print(f"✓ Threat Intel Model - Accuracy: {training_metrics['threat_intelligence'].get('report_type_accuracy', 0):.3f}")
    
    # Sample incident data
    sample_logs = [
        "CRITICAL: Ransomware detected on host SERVER-01 with hash a1b2c3d4e5f6789012345",
        "Failed login attempts from IP 203.0.113.42 for user administrator",
        "Suspicious PowerShell execution: encoded command detected",
        "Network connection to known C2 domain evil-domain.com blocked",
        "User admin successfully logged in from IP 192.168.1.100"
    ]
    
    sample_threat_reports = [
        "APT29 group observed using PowerShell-based techniques. C2 communications to evil-domain.com detected. CVE-2021-34527 exploited for privilege escalation.",
        "New ransomware variant spreading via phishing emails. Hash a1b2c3d4e5f6789012345 confirmed malicious. Targets healthcare sector.",
        "Credential stuffing attacks from 203.0.113.42 infrastructure. Part of larger botnet campaign targeting financial institutions."
    ]
    
    # Analyze incident
    print("\n🔍 Analyzing Security Incident...")
    incident_analysis = platform.analyze_security_incident(sample_logs, sample_threat_reports)
    
    # Generate and display report
    print("\n📋 Generating Incident Report...\n")
    report = platform.generate_incident_report(incident_analysis)
    print(report)
    
    # Save models (optional)
    try:
        print("\n💾 Saving trained models...")
        platform.log_analyzer.save_model("projects/21-ai-powered-cybersecurity/nlp_models/log_analyzer_model")
        platform.threat_intel_analyzer.save_model("projects/21-ai-powered-cybersecurity/nlp_models/threat_intel_model")
        print("✓ Models saved successfully")
    except Exception as e:
        logger.error(f"Failed to save models: {e}")
    
    print("\n🎉 Cybersecurity NLP Platform demonstration completed!")
    print("\nKey Features Demonstrated:")
    print("• Security log analysis and classification")
    print("• IOC extraction and validation")
    print("• Threat intelligence processing")
    print("• MITRE ATT&CK technique mapping")
    print("• Threat actor attribution")
    print("• Cross-correlation analysis")
    print("• Actionable security recommendations")

if __name__ == "__main__":
    main()