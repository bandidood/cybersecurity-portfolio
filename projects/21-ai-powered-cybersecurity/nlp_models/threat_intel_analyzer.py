#!/usr/bin/env python3
"""
Threat Intelligence Analysis NLP Model
Advanced NLP for threat intelligence reports, IOC enrichment, and TTP extraction
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import numpy as np
import pandas as pd
import re
import json
from typing import Dict, List, Tuple, Any, Optional, Union
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.chunk import ne_chunk
from nltk.tag import pos_tag
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict, Counter
import logging
import joblib
import warnings
from datetime import datetime, timedelta
import hashlib
from dataclasses import dataclass

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatActor:
    """Threat actor profile"""
    name: str
    aliases: List[str]
    country: str
    motivation: str
    techniques: List[str]
    indicators: List[str]
    confidence: float

@dataclass
class TTP:
    """Tactics, Techniques, and Procedures"""
    tactic: str
    technique: str
    technique_id: str
    description: str
    indicators: List[str]
    confidence: float

class ThreatIntelligenceAnalyzer:
    """
    Advanced Threat Intelligence Analysis using NLP:
    - CTI reports processing and analysis
    - MITRE ATT&CK mapping and TTP extraction
    - IOC enrichment and contextualization
    - Threat actor attribution
    - Campaign and malware family identification
    - Intelligence confidence scoring
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the Threat Intelligence Analyzer"""
        self.config = config or self._default_config()
        
        # NLP components
        self.vectorizer = TfidfVectorizer(
            max_features=self.config['max_features'],
            ngram_range=(1, 4),
            stop_words='english',
            min_df=2,
            max_df=0.95
        )
        
        # Classification models
        self.malware_classifier = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            max_depth=15
        )
        self.campaign_classifier = GradientBoostingClassifier(
            n_estimators=100,
            random_state=42
        )
        self.confidence_classifier = LogisticRegression(
            max_iter=1000,
            random_state=42
        )
        
        # MITRE ATT&CK framework mapping
        self.mitre_techniques = self._load_mitre_framework()
        self.threat_actors_db = self._load_threat_actors()
        
        # IOC patterns and enrichment
        self.ioc_patterns = self._initialize_ioc_patterns()
        self.ioc_enrichment_db = defaultdict(dict)
        
        # Text processing utilities
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Clustering for campaign detection
        self.campaign_cluster = KMeans(n_clusters=10, random_state=42)
        
        # Model state
        self.is_trained = False
        self.vocabulary = set()
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'max_features': 15000,
            'min_confidence': 0.3,
            'similarity_threshold': 0.7,
            'max_text_length': 10000,
            'ttp_extraction_threshold': 0.6,
            'batch_size': 64
        }
    
    def _load_mitre_framework(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK framework mapping"""
        # Simplified MITRE ATT&CK techniques
        return {
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command and script interpreters',
                'keywords': ['powershell', 'cmd', 'bash', 'python', 'script', 'command line']
            },
            'T1055': {
                'name': 'Process Injection',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may inject code into processes',
                'keywords': ['process injection', 'dll injection', 'hollow', 'reflective']
            },
            'T1053': {
                'name': 'Scheduled Task/Job',
                'tactic': 'Persistence',
                'description': 'Adversaries may abuse task scheduling functionality',
                'keywords': ['scheduled task', 'cron', 'job', 'scheduler', 'at command']
            },
            'T1566': {
                'name': 'Phishing',
                'tactic': 'Initial Access',
                'description': 'Adversaries may send victims emails containing malicious attachments',
                'keywords': ['phishing', 'spear phishing', 'email', 'attachment', 'malicious link']
            },
            'T1003': {
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to dump credentials',
                'keywords': ['credential dump', 'mimikatz', 'lsass', 'sam', 'password hash']
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using application layer protocols',
                'keywords': ['http', 'https', 'dns', 'smtp', 'ftp', 'c2', 'command control']
            },
            'T1040': {
                'name': 'Network Sniffing',
                'tactic': 'Credential Access',
                'description': 'Adversaries may sniff network traffic',
                'keywords': ['network sniffing', 'packet capture', 'wireshark', 'tcpdump']
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'description': 'Adversaries may transfer tools or files',
                'keywords': ['file transfer', 'download', 'upload', 'certutil', 'bitsadmin']
            }
        }
    
    def _load_threat_actors(self) -> Dict[str, ThreatActor]:
        """Load threat actor profiles"""
        return {
            'APT29': ThreatActor(
                name='APT29',
                aliases=['Cozy Bear', 'The Dukes', 'Office Monkeys'],
                country='Russia',
                motivation='Espionage',
                techniques=['T1059', 'T1071', 'T1566'],
                indicators=['wellmess', 'zeroclear', 'powerduke'],
                confidence=0.9
            ),
            'APT28': ThreatActor(
                name='APT28',
                aliases=['Fancy Bear', 'Pawn Storm', 'Sednit'],
                country='Russia',
                motivation='Espionage',
                techniques=['T1566', 'T1053', 'T1105'],
                indicators=['x-agent', 'seduploader', 'gamefish'],
                confidence=0.9
            ),
            'Lazarus': ThreatActor(
                name='Lazarus',
                aliases=['HIDDEN COBRA', 'Guardians of Peace'],
                country='North Korea',
                motivation='Financial/Espionage',
                techniques=['T1055', 'T1003', 'T1071'],
                indicators=['fallchill', 'jokra', 'hoplight'],
                confidence=0.85
            )
        }
    
    def _initialize_ioc_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize IOC extraction patterns"""
        return {
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,}'),
            'mutex': re.compile(r'(?:mutex|named\s+object)[\s:]+([a-zA-Z0-9_\-\{\}]+)', re.IGNORECASE),
            'registry_key': re.compile(r'HKEY_[A-Z_]+\\[^\s\n]+'),
            'file_path': re.compile(r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*|/(?:[^/\s]+/)*[^/\s]*')
        }
    
    def preprocess_report(self, text: str) -> str:
        """Preprocess threat intelligence report"""
        if not text:
            return ""
        
        # Truncate if too long
        if len(text) > self.config['max_text_length']:
            text = text[:self.config['max_text_length']]
        
        # Clean text
        text = re.sub(r'[^\x00-\x7F]+', ' ', text)  # Remove non-ASCII
        text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
        text = text.strip()
        
        return text
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract and validate IOCs from text"""
        iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(text)
            if matches:
                unique_matches = list(set(matches))
                valid_matches = self._validate_iocs(ioc_type, unique_matches)
                if valid_matches:
                    iocs[ioc_type] = valid_matches
        
        return iocs
    
    def _validate_iocs(self, ioc_type: str, matches: List[str]) -> List[str]:
        """Validate extracted IOCs"""
        valid_matches = []
        
        for match in matches:
            if ioc_type == 'ip_address':
                # Validate IP address range
                try:
                    octets = [int(x) for x in match.split('.')]
                    if all(0 <= octet <= 255 for octet in octets):
                        # Filter out private IPs for threat intel
                        if not (octets[0] in [10, 127] or 
                               (octets[0] == 172 and 16 <= octets[1] <= 31) or
                               (octets[0] == 192 and octets[1] == 168)):
                            valid_matches.append(match)
                except:
                    continue
            elif ioc_type == 'domain':
                # Basic domain validation
                if len(match) > 3 and '.' in match and not match.startswith('.'):
                    valid_matches.append(match)
            else:
                valid_matches.append(match)
        
        return valid_matches
    
    def extract_ttps(self, text: str) -> List[TTP]:
        """Extract Tactics, Techniques, and Procedures using MITRE ATT&CK"""
        ttps = []
        text_lower = text.lower()
        
        for technique_id, technique_data in self.mitre_techniques.items():
            confidence = 0.0
            matched_keywords = []
            
            for keyword in technique_data['keywords']:
                if keyword in text_lower:
                    confidence += 1.0 / len(technique_data['keywords'])
                    matched_keywords.append(keyword)
            
            if confidence >= self.config['ttp_extraction_threshold']:
                ttp = TTP(
                    tactic=technique_data['tactic'],
                    technique=technique_data['name'],
                    technique_id=technique_id,
                    description=technique_data['description'],
                    indicators=matched_keywords,
                    confidence=min(confidence, 1.0)
                )
                ttps.append(ttp)
        
        return ttps
    
    def attribute_threat_actor(self, text: str, iocs: Dict, ttps: List[TTP]) -> Dict[str, Any]:
        """Attempt to attribute activities to known threat actors"""
        attribution_scores = defaultdict(float)
        text_lower = text.lower()
        
        for actor_name, actor in self.threat_actors_db.items():
            score = 0.0
            
            # Check aliases and name mentions
            all_names = [actor.name.lower()] + [alias.lower() for alias in actor.aliases]
            for name in all_names:
                if name in text_lower:
                    score += 0.3
            
            # Check TTP overlap
            actor_techniques = set(actor.techniques)
            extracted_techniques = set(ttp.technique_id for ttp in ttps)
            ttp_overlap = len(actor_techniques.intersection(extracted_techniques))
            if actor_techniques:
                score += (ttp_overlap / len(actor_techniques)) * 0.4
            
            # Check indicator overlap
            for indicator in actor.indicators:
                if indicator.lower() in text_lower:
                    score += 0.3
            
            attribution_scores[actor_name] = min(score, 1.0)
        
        # Find best match
        if attribution_scores:
            best_actor = max(attribution_scores, key=attribution_scores.get)
            best_score = attribution_scores[best_actor]
            
            if best_score >= self.config['min_confidence']:
                return {
                    'attributed_actor': best_actor,
                    'confidence': best_score,
                    'all_scores': dict(attribution_scores),
                    'attribution_method': 'rule_based'
                }
        
        return {
            'attributed_actor': None,
            'confidence': 0.0,
            'all_scores': dict(attribution_scores),
            'attribution_method': 'insufficient_evidence'
        }
    
    def classify_malware_family(self, text: str, iocs: Dict) -> Dict[str, Any]:
        """Classify malware family from indicators"""
        # Simplified malware family classification
        malware_indicators = {
            'banking_trojan': [
                'banking', 'financial', 'credential', 'keylogger', 'formgrabber',
                'zeus', 'emotet', 'trickbot', 'qakbot'
            ],
            'ransomware': [
                'ransomware', 'encrypt', 'ransom', 'payment', 'bitcoin',
                'wannacry', 'petya', 'ryuk', 'maze', 'sodinokibi'
            ],
            'backdoor': [
                'backdoor', 'remote access', 'rat', 'command control', 'c2',
                'cobalt strike', 'meterpreter', 'poison ivy'
            ],
            'apt_malware': [
                'apt', 'advanced persistent', 'nation state', 'espionage',
                'lateral movement', 'privilege escalation'
            ],
            'commodity_malware': [
                'commodity', 'crimeware', 'botnet', 'spam', 'mining',
                'adware', 'potentially unwanted'
            ]
        }
        
        text_lower = text.lower()
        family_scores = {}
        
        for family, keywords in malware_indicators.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            family_scores[family] = score / len(keywords)
        
        if family_scores:
            best_family = max(family_scores, key=family_scores.get)
            confidence = family_scores[best_family]
            
            return {
                'malware_family': best_family if confidence > 0.1 else 'unknown',
                'confidence': confidence,
                'all_scores': family_scores
            }
        
        return {
            'malware_family': 'unknown',
            'confidence': 0.0,
            'all_scores': {}
        }
    
    def enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, Dict]:
        """Enrich IOCs with additional context"""
        enriched_iocs = {}
        
        for ioc_type, ioc_list in iocs.items():
            enriched_iocs[ioc_type] = {}
            
            for ioc in ioc_list:
                enrichment = {
                    'value': ioc,
                    'type': ioc_type,
                    'first_seen': datetime.now().isoformat(),
                    'confidence': 0.8,
                    'tags': [],
                    'context': {}
                }
                
                # Add type-specific enrichment
                if ioc_type == 'ip_address':
                    enrichment['context'] = {
                        'geolocation': 'Unknown',
                        'asn': 'Unknown',
                        'reputation': 'Unknown'
                    }
                    enrichment['tags'].extend(['network', 'infrastructure'])
                
                elif ioc_type == 'domain':
                    enrichment['context'] = {
                        'registrar': 'Unknown',
                        'creation_date': 'Unknown',
                        'dns_records': []
                    }
                    enrichment['tags'].extend(['network', 'domain'])
                
                elif ioc_type in ['md5', 'sha1', 'sha256']:
                    enrichment['context'] = {
                        'file_type': 'Unknown',
                        'size': 'Unknown',
                        'signature_status': 'Unknown'
                    }
                    enrichment['tags'].extend(['file', 'hash'])
                
                enriched_iocs[ioc_type][ioc] = enrichment
        
        return enriched_iocs
    
    def generate_synthetic_reports(self, n_reports: int = 500) -> pd.DataFrame:
        """Generate synthetic threat intelligence reports"""
        np.random.seed(42)
        
        report_templates = [
            # APT Reports
            "Advanced Persistent Threat group {actor} has been observed using {technique} technique to compromise {target} organizations. The campaign leveraged {malware} malware with C2 communications to {domain}. IOCs include IP {ip} and file hash {hash}.",
            
            # Malware Analysis
            "New {family} malware variant discovered with enhanced {capability} functionality. The sample {hash} communicates with {domain} and drops additional payloads to {path}. Persistence achieved through {persistence}.",
            
            # Phishing Campaign
            "Phishing campaign targeting {sector} sector detected. Malicious emails from {email} contain links to {url}. Upon execution, {malware} is downloaded from {ip} establishing C2 with {domain}.",
            
            # Vulnerability Exploitation
            "{cve} vulnerability actively exploited in the wild. Attackers use {technique} to achieve {objective}. Indicators include network traffic to {ip} and suspicious processes {process}.",
            
            # Incident Response
            "Security incident at {organization} involved {actor} group using {ttp} tactics. Lateral movement achieved through {method}. Exfiltration to {ip} via {protocol} protocol observed."
        ]
        
        # Sample data pools
        actors = list(self.threat_actors_db.keys()) + ['APT40', 'FIN7', 'Carbanak', 'TA505']
        techniques = ['spear phishing', 'watering hole', 'supply chain', 'credential stuffing']
        targets = ['financial', 'healthcare', 'government', 'defense', 'energy']
        malwares = ['Cobalt Strike', 'Emotet', 'TrickBot', 'Ryuk', 'Maze', 'SolarWinds']
        capabilities = ['keylogging', 'screen capture', 'file stealing', 'cryptocurrency mining']
        families = ['banking trojan', 'ransomware', 'backdoor', 'info stealer', 'botnet']
        sectors = ['banking', 'healthcare', 'retail', 'manufacturing', 'education']
        
        reports = []
        for i in range(n_reports):
            template = np.random.choice(report_templates)
            
            # Generate synthetic IOCs
            ip = f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            domain = f"{np.random.choice(['malicious', 'evil', 'bad', 'suspicious'])}{np.random.randint(1, 999)}.{np.random.choice(['com', 'net', 'org'])}"
            email = f"{np.random.choice(['admin', 'support', 'noreply'])}@{domain}"
            hash_val = hashlib.sha256(f"malware{i}".encode()).hexdigest()
            
            report_text = template.format(
                actor=np.random.choice(actors),
                technique=np.random.choice(techniques),
                target=np.random.choice(targets),
                malware=np.random.choice(malwares),
                domain=domain,
                ip=ip,
                hash=hash_val,
                family=np.random.choice(families),
                capability=np.random.choice(capabilities),
                path=f"C:\\Users\\{np.random.choice(['Public', 'Admin', 'User'])}\\{np.random.choice(['temp', 'downloads', 'documents'])}\\"
            )
            
            # Determine report type and confidence
            if 'APT' in report_text or any(actor in report_text for actor in self.threat_actors_db.keys()):
                report_type = 'apt_report'
                confidence = np.random.uniform(0.7, 0.95)
            elif 'malware' in report_text.lower():
                report_type = 'malware_analysis'
                confidence = np.random.uniform(0.6, 0.9)
            elif 'phishing' in report_text.lower():
                report_type = 'phishing_campaign'
                confidence = np.random.uniform(0.5, 0.8)
            else:
                report_type = 'threat_intelligence'
                confidence = np.random.uniform(0.4, 0.85)
            
            reports.append({
                'report_text': report_text,
                'report_type': report_type,
                'confidence': confidence,
                'timestamp': datetime.now() - timedelta(days=np.random.randint(1, 365))
            })
        
        df = pd.DataFrame(reports)
        logger.info(f"Generated {len(df)} synthetic threat intelligence reports")
        
        return df
    
    def fit(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train the threat intelligence models"""
        logger.info("Training threat intelligence analysis models...")
        
        if 'report_text' not in df.columns:
            raise ValueError("DataFrame must contain 'report_text' column")
        
        # Preprocess reports
        df['processed_text'] = df['report_text'].apply(self.preprocess_report)
        df = df[df['processed_text'].str.len() > 10]  # Filter short texts
        
        # Extract features
        X = self.vectorizer.fit_transform(df['processed_text'])
        
        training_metrics = {}
        
        # Train report type classifier
        if 'report_type' in df.columns:
            y_type = df['report_type']
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_type, test_size=0.3, random_state=42, stratify=y_type
            )
            
            self.malware_classifier.fit(X_train, y_train)
            type_pred = self.malware_classifier.predict(X_test)
            type_accuracy = (type_pred == y_test).mean()
            training_metrics['report_type_accuracy'] = type_accuracy
        
        # Train confidence classifier
        if 'confidence' in df.columns:
            # Convert confidence to categorical
            confidence_labels = pd.cut(df['confidence'], 
                                     bins=[0, 0.3, 0.6, 0.8, 1.0], 
                                     labels=['low', 'medium', 'high', 'very_high'])
            
            y_conf = confidence_labels.dropna()
            X_conf = X[~confidence_labels.isna()]
            
            if len(y_conf) > 0:
                X_train, X_test, y_train, y_test = train_test_split(
                    X_conf, y_conf, test_size=0.3, random_state=42, stratify=y_conf
                )
                
                self.confidence_classifier.fit(X_train, y_train)
                conf_pred = self.confidence_classifier.predict(X_test)
                conf_accuracy = (conf_pred == y_test).mean()
                training_metrics['confidence_accuracy'] = conf_accuracy
        
        # Train campaign clustering
        self.campaign_cluster.fit(X)
        
        training_metrics.update({
            'vocabulary_size': len(self.vectorizer.get_feature_names_out()),
            'training_samples': len(df),
            'feature_count': X.shape[1],
            'mitre_techniques_loaded': len(self.mitre_techniques),
            'threat_actors_loaded': len(self.threat_actors_db)
        })
        
        self.is_trained = True
        logger.info("Training completed successfully")
        
        return training_metrics
    
    def analyze_report(self, report_text: str) -> Dict[str, Any]:
        """Comprehensive threat intelligence report analysis"""
        results = {
            'original_text': report_text,
            'processed_text': self.preprocess_report(report_text),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Extract IOCs
        iocs = self.extract_iocs(report_text)
        results['iocs'] = iocs
        
        # Enrich IOCs
        results['enriched_iocs'] = self.enrich_iocs(iocs)
        
        # Extract TTPs
        ttps = self.extract_ttps(report_text)
        results['ttps'] = [
            {
                'tactic': ttp.tactic,
                'technique': ttp.technique,
                'technique_id': ttp.technique_id,
                'description': ttp.description,
                'indicators': ttp.indicators,
                'confidence': ttp.confidence
            }
            for ttp in ttps
        ]
        
        # Threat actor attribution
        attribution = self.attribute_threat_actor(report_text, iocs, ttps)
        results['attribution'] = attribution
        
        # Malware family classification
        malware_classification = self.classify_malware_family(report_text, iocs)
        results['malware_classification'] = malware_classification
        
        # ML predictions (if trained)
        if self.is_trained and results['processed_text']:
            text_vector = self.vectorizer.transform([results['processed_text']])
            
            # Report type prediction
            report_type_pred = self.malware_classifier.predict(text_vector)[0]
            report_type_proba = max(self.malware_classifier.predict_proba(text_vector)[0])
            
            # Confidence prediction
            confidence_pred = self.confidence_classifier.predict(text_vector)[0]
            confidence_proba = max(self.confidence_classifier.predict_proba(text_vector)[0])
            
            # Campaign clustering
            cluster_id = self.campaign_cluster.predict(text_vector)[0]
            
            results['ml_predictions'] = {
                'report_type': {
                    'prediction': report_type_pred,
                    'confidence': float(report_type_proba)
                },
                'intelligence_confidence': {
                    'prediction': confidence_pred,
                    'confidence': float(confidence_proba)
                },
                'campaign_cluster': int(cluster_id)
            }
        
        return results
    
    def save_model(self, model_path: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        model_data = {
            'vectorizer': self.vectorizer,
            'malware_classifier': self.malware_classifier,
            'campaign_classifier': self.campaign_classifier,
            'confidence_classifier': self.confidence_classifier,
            'campaign_cluster': self.campaign_cluster,
            'config': self.config,
            'mitre_techniques': self.mitre_techniques,
            'threat_actors_db': {k: {
                'name': v.name, 'aliases': v.aliases, 'country': v.country,
                'motivation': v.motivation, 'techniques': v.techniques,
                'indicators': v.indicators, 'confidence': v.confidence
            } for k, v in self.threat_actors_db.items()},
            'ioc_patterns': {k: v.pattern for k, v in self.ioc_patterns.items()}
        }
        
        joblib.dump(model_data, f"{model_path}.pkl")
        logger.info(f"Model saved to {model_path}.pkl")
    
    def load_model(self, model_path: str):
        """Load trained model"""
        model_data = joblib.load(f"{model_path}.pkl")
        
        self.vectorizer = model_data['vectorizer']
        self.malware_classifier = model_data['malware_classifier']
        self.campaign_classifier = model_data['campaign_classifier']
        self.confidence_classifier = model_data['confidence_classifier']
        self.campaign_cluster = model_data['campaign_cluster']
        self.config.update(model_data['config'])
        self.mitre_techniques = model_data['mitre_techniques']
        
        # Restore threat actors
        actors_data = model_data['threat_actors_db']
        self.threat_actors_db = {
            k: ThreatActor(**v) for k, v in actors_data.items()
        }
        
        # Restore compiled patterns
        pattern_strings = model_data['ioc_patterns']
        self.ioc_patterns = {k: re.compile(v) for k, v in pattern_strings.items()}
        
        self.is_trained = True
        logger.info(f"Model loaded from {model_path}.pkl")

def main():
    """Demonstration of Threat Intelligence Analysis"""
    logger.info("Starting Threat Intelligence Analysis demonstration...")
    
    # Initialize analyzer
    analyzer = ThreatIntelligenceAnalyzer()
    
    # Download NLTK data
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('wordnet', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    nltk.download('maxent_ne_chunker', quiet=True)
    nltk.download('words', quiet=True)
    
    # Generate synthetic training data
    training_data = analyzer.generate_synthetic_reports(n_reports=1000)
    
    # Train models
    logger.info("Training models...")
    training_metrics = analyzer.fit(training_data)
    
    # Test analysis on sample reports
    test_reports = [
        "APT29 group has been observed using PowerShell-based techniques to compromise government networks. The malware communicates with evil-c2.com and uses CVE-2021-34527 for privilege escalation.",
        
        "New Emotet variant detected with enhanced evasion capabilities. The sample 8f14e45fceea167a5a36dedd4bea2543 downloads additional payloads from 198.51.100.10 and establishes persistence through scheduled tasks.",
        
        "Phishing campaign targeting healthcare organizations uses COVID-themed lures. Malicious attachments download TrickBot from suspicious-domain.net establishing C2 communications.",
        
        "LAZARUS group suspected in recent cryptocurrency exchange hack. Custom backdoor with hash a1b2c3d4e5f6 identified, communicating with 203.0.113.42 infrastructure.",
        
        "Ransomware incident involving Ryuk variant. Lateral movement achieved through PsExec and credential dumping with Mimikatz. File encryption began after exfiltration to 192.0.2.15."
    ]
    
    print("\n" + "="*80)
    print("THREAT INTELLIGENCE ANALYSIS RESULTS")
    print("="*80)
    
    print("\nTraining Metrics:")
    for metric, value in training_metrics.items():
        if isinstance(value, float):
            print(f"  {metric}: {value:.4f}")
        else:
            print(f"  {metric}: {value}")
    
    print(f"\nAnalyzing {len(test_reports)} threat intelligence reports...")
    
    for i, report in enumerate(test_reports, 1):
        result = analyzer.analyze_report(report)
        
        print(f"\n{'='*60}")
        print(f"REPORT {i}")
        print(f"{'='*60}")
        print(f"Text: {report[:100]}...")
        
        # Attribution
        if result['attribution']['attributed_actor']:
            print(f"Attribution: {result['attribution']['attributed_actor']} "
                  f"(confidence: {result['attribution']['confidence']:.2f})")
        
        # Malware family
        if result['malware_classification']['malware_family'] != 'unknown':
            print(f"Malware Family: {result['malware_classification']['malware_family']} "
                  f"(confidence: {result['malware_classification']['confidence']:.2f})")
        
        # TTPs
        if result['ttps']:
            print("MITRE ATT&CK Techniques:")
            for ttp in result['ttps'][:3]:  # Show top 3
                print(f"  {ttp['technique_id']}: {ttp['technique']} "
                      f"({ttp['tactic']}) - confidence: {ttp['confidence']:.2f}")
        
        # IOCs
        if result['iocs']:
            print("IOCs Extracted:")
            for ioc_type, iocs in result['iocs'].items():
                if iocs:
                    print(f"  {ioc_type}: {', '.join(iocs[:3])}{'...' if len(iocs) > 3 else ''}")
        
        # ML Predictions
        if result.get('ml_predictions'):
            ml_pred = result['ml_predictions']
            print(f"ML Report Type: {ml_pred['report_type']['prediction']} "
                  f"({ml_pred['report_type']['confidence']:.2f})")
            print(f"Intelligence Confidence: {ml_pred['intelligence_confidence']['prediction']}")
            print(f"Campaign Cluster: {ml_pred['campaign_cluster']}")
    
    # Save model
    model_path = "projects/21-ai-powered-cybersecurity/nlp_models/threat_intel_model"
    analyzer.save_model(model_path)
    
    logger.info("Threat Intelligence Analysis demonstration completed!")

if __name__ == "__main__":
    main()