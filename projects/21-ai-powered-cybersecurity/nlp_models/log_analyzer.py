#!/usr/bin/env python3
"""
Security Log Analysis NLP Model
Advanced NLP for security log analysis, IOC extraction, and threat intelligence processing
Author: AI Cybersecurity Team
Version: 1.0.0
"""

import numpy as np
import pandas as pd
import re
import json
from typing import Dict, List, Tuple, Any, Optional, Union
import spacy
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoTokenizer, AutoModel, pipeline
import torch
from collections import defaultdict, Counter
import logging
import joblib
import warnings
from datetime import datetime
import hashlib

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityLogAnalyzer:
    """
    Advanced Security Log Analysis using NLP:
    - IOC extraction from unstructured text
    - Log classification and anomaly detection
    - Threat intelligence processing
    - Security alert prioritization
    - Entity recognition for security artifacts
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the Security Log Analyzer"""
        self.config = config or self._default_config()
        
        # NLP models and components
        self.nlp = None
        self.tokenizer = None
        self.transformer_model = None
        self.vectorizer = TfidfVectorizer(
            max_features=self.config['max_features'],
            ngram_range=(1, 3),
            stop_words='english'
        )
        
        # Classification models
        self.log_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        self.threat_classifier = LogisticRegression(
            max_iter=1000,
            random_state=42
        )
        self.priority_classifier = MultinomialNB()
        
        # IOC extraction patterns
        self.ioc_patterns = self._initialize_ioc_patterns()
        self.security_keywords = self._load_security_keywords()
        
        # Lemmatizer and utilities
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Model state
        self.is_trained = False
        self.vocabulary = set()
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'max_features': 10000,
            'spacy_model': 'en_core_web_sm',
            'transformer_model': 'sentence-transformers/all-MiniLM-L6-v2',
            'min_text_length': 10,
            'max_text_length': 5000,
            'confidence_threshold': 0.7,
            'batch_size': 32
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
            'file_path': re.compile(r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*|/(?:[^/\s]+/)*[^/\s]*'),
            'registry_key': re.compile(r'HKEY_[A-Z_]+\\.*'),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'process_name': re.compile(r'\b\w+\.exe\b', re.IGNORECASE)
        }
    
    def _load_security_keywords(self) -> Dict[str, List[str]]:
        """Load security-related keywords for classification"""
        return {
            'malware': [
                'virus', 'trojan', 'worm', 'rootkit', 'backdoor', 'spyware',
                'adware', 'ransomware', 'keylogger', 'botnet', 'malware',
                'infected', 'malicious', 'suspicious'
            ],
            'attack': [
                'attack', 'exploit', 'breach', 'intrusion', 'penetration',
                'injection', 'overflow', 'phishing', 'spoofing', 'hijacking',
                'ddos', 'dos', 'mitm', 'brute force', 'credential stuffing'
            ],
            'vulnerability': [
                'vulnerability', 'exploit', 'cve', 'patch', 'update',
                'security flaw', 'weakness', 'exposure', 'misconfiguration'
            ],
            'network': [
                'firewall', 'proxy', 'vpn', 'dns', 'tcp', 'udp', 'http',
                'https', 'ssl', 'tls', 'port', 'protocol', 'traffic'
            ],
            'authentication': [
                'login', 'password', 'authentication', 'authorization',
                'session', 'token', 'certificate', 'credential', 'mfa'
            ]
        }
    
    def initialize_models(self):
        """Initialize NLP models and tokenizers"""
        try:
            # Load spaCy model
            logger.info("Loading spaCy model...")
            self.nlp = spacy.load(self.config['spacy_model'])
            
            # Download NLTK data
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('wordnet', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            
            # Load transformer model
            logger.info("Loading transformer model...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.config['transformer_model'])
            self.transformer_model = AutoModel.from_pretrained(self.config['transformer_model'])
            
            logger.info("NLP models initialized successfully")
            
        except Exception as e:
            logger.warning(f"Failed to load some NLP models: {e}")
    
    def preprocess_text(self, text: str) -> str:
        """Preprocess text for analysis"""
        if not text or len(text) < self.config['min_text_length']:
            return ""
        
        # Truncate if too long
        if len(text) > self.config['max_text_length']:
            text = text[:self.config['max_text_length']]
        
        # Basic cleaning
        text = re.sub(r'[^\x00-\x7F]+', ' ', text)  # Remove non-ASCII
        text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
        text = text.strip().lower()
        
        return text
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from text"""
        iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Remove duplicates and filter valid matches
                unique_matches = list(set(matches))
                valid_matches = []
                
                for match in unique_matches:
                    if ioc_type == 'ip_address':
                        # Validate IP address
                        octets = match.split('.')
                        if all(0 <= int(octet) <= 255 for octet in octets):
                            valid_matches.append(match)
                    elif ioc_type == 'domain':
                        # Basic domain validation
                        if len(match) > 3 and '.' in match:
                            valid_matches.append(match)
                    else:
                        valid_matches.append(match)
                
                iocs[ioc_type] = valid_matches
        
        return iocs
    
    def extract_entities(self, text: str) -> Dict[str, List[Dict]]:
        """Extract named entities using spaCy"""
        if not self.nlp:
            return {}
        
        doc = self.nlp(text)
        entities = defaultdict(list)
        
        for ent in doc.ents:
            entities[ent.label_].append({
                'text': ent.text,
                'start': ent.start_char,
                'end': ent.end_char,
                'confidence': float(ent._.confidence) if hasattr(ent._, 'confidence') else 1.0
            })
        
        return dict(entities)
    
    def classify_log_severity(self, text: str) -> Dict[str, Any]:
        """Classify log entry severity"""
        text_lower = text.lower()
        
        # Keyword-based severity scoring
        severity_keywords = {
            'critical': ['critical', 'fatal', 'emergency', 'severe', 'failure'],
            'high': ['error', 'exception', 'alert', 'warning', 'denied', 'blocked'],
            'medium': ['notice', 'info', 'timeout', 'retry', 'slow'],
            'low': ['debug', 'trace', 'verbose', 'success', 'ok']
        }
        
        scores = {}
        for severity, keywords in severity_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            scores[severity] = score
        
        # Determine primary severity
        max_score = max(scores.values()) if scores.values() else 0
        if max_score == 0:
            primary_severity = 'unknown'
        else:
            primary_severity = max(scores, key=scores.get)
        
        return {
            'severity': primary_severity,
            'confidence': min(max_score / 3, 1.0),
            'scores': scores
        }
    
    def analyze_threat_indicators(self, text: str) -> Dict[str, Any]:
        """Analyze text for threat indicators"""
        indicators = {
            'malware_score': 0,
            'attack_score': 0,
            'vulnerability_score': 0,
            'network_score': 0,
            'auth_score': 0
        }
        
        text_lower = text.lower()
        
        for category, keywords in self.security_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            indicators[f'{category}_score'] = score
        
        # Calculate overall threat score
        total_score = sum(indicators.values())
        threat_level = 'low'
        
        if total_score >= 5:
            threat_level = 'high'
        elif total_score >= 2:
            threat_level = 'medium'
        
        return {
            'threat_level': threat_level,
            'total_score': total_score,
            'indicators': indicators
        }
    
    def generate_synthetic_logs(self, n_samples: int = 1000) -> pd.DataFrame:
        """Generate synthetic security logs for training"""
        np.random.seed(42)
        
        log_templates = [
            # Normal logs
            "User {user} successfully logged in from IP {ip}",
            "File {file} was accessed by user {user}",
            "Network connection established to {ip}:{port}",
            "Process {process} started successfully",
            "Email sent from {email} to {email}",
            
            # Security events
            "Failed login attempt for user {user} from IP {ip}",
            "Suspicious file {file} detected with hash {hash}",
            "Malware {malware} blocked by antivirus",
            "Port scan detected from IP {ip}",
            "Phishing email from {email} quarantined",
            
            # Critical events
            "CRITICAL: Ransomware {malware} detected on host {host}",
            "ALERT: Brute force attack from IP {ip}",
            "ERROR: System file {file} corrupted",
            "WARNING: Unusual network traffic to {domain}",
            "BREACH: Unauthorized access to {file}"
        ]
        
        # Generate sample data
        samples = []
        for _ in range(n_samples):
            template = np.random.choice(log_templates)
            
            # Fill template with synthetic data
            log_entry = template.format(
                user=f"user{np.random.randint(1, 100)}",
                ip=f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                file=f"/path/to/{np.random.choice(['document', 'system', 'config'])}.{np.random.choice(['txt', 'exe', 'dll', 'log'])}",
                port=np.random.randint(1, 65535),
                process=f"{np.random.choice(['chrome', 'firefox', 'notepad', 'calc'])}.exe",
                email=f"user{np.random.randint(1, 50)}@{np.random.choice(['gmail.com', 'yahoo.com', 'company.com'])}",
                hash=hashlib.md5(f"file{np.random.randint(1, 1000)}".encode()).hexdigest(),
                malware=np.random.choice(['Trojan.Generic', 'Win32.Virus', 'Adware.Popup']),
                host=f"HOST-{np.random.randint(1, 100)}",
                domain=f"{np.random.choice(['suspicious', 'malicious', 'unknown'])}.{np.random.choice(['com', 'net', 'org'])}"
            )
            
            # Classify log type
            if any(word in template.lower() for word in ['critical', 'alert', 'error', 'breach']):
                log_type = 'security_alert'
                priority = 'high'
            elif any(word in template.lower() for word in ['warning', 'suspicious', 'failed']):
                log_type = 'security_event'
                priority = 'medium'
            else:
                log_type = 'normal'
                priority = 'low'
            
            samples.append({
                'log_text': log_entry,
                'log_type': log_type,
                'priority': priority,
                'timestamp': datetime.now()
            })
        
        df = pd.DataFrame(samples)
        logger.info(f"Generated {len(df)} synthetic log entries")
        
        return df
    
    def fit(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train the NLP models"""
        logger.info("Training security log analysis models...")
        
        if 'log_text' not in df.columns:
            raise ValueError("DataFrame must contain 'log_text' column")
        
        # Preprocess texts
        df['processed_text'] = df['log_text'].apply(self.preprocess_text)
        df = df[df['processed_text'].str.len() > 0]  # Remove empty texts
        
        # Extract features using TF-IDF
        X = self.vectorizer.fit_transform(df['processed_text'])
        
        # Build vocabulary
        self.vocabulary = set(self.vectorizer.get_feature_names_out())
        
        training_metrics = {}
        
        # Train log type classifier
        if 'log_type' in df.columns:
            y_type = df['log_type']
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_type, test_size=0.3, random_state=42, stratify=y_type
            )
            
            self.log_classifier.fit(X_train, y_train)
            type_pred = self.log_classifier.predict(X_test)
            type_accuracy = (type_pred == y_test).mean()
            training_metrics['log_type_accuracy'] = type_accuracy
        
        # Train priority classifier
        if 'priority' in df.columns:
            y_priority = df['priority']
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_priority, test_size=0.3, random_state=42, stratify=y_priority
            )
            
            self.priority_classifier.fit(X_train, y_train)
            priority_pred = self.priority_classifier.predict(X_test)
            priority_accuracy = (priority_pred == y_test).mean()
            training_metrics['priority_accuracy'] = priority_accuracy
        
        # Calculate additional metrics
        training_metrics.update({
            'vocabulary_size': len(self.vocabulary),
            'training_samples': len(df),
            'feature_count': X.shape[1]
        })
        
        self.is_trained = True
        logger.info("Training completed successfully")
        
        return training_metrics
    
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Comprehensive text analysis"""
        if not self.is_trained:
            logger.warning("Model not trained, using rule-based analysis only")
        
        results = {
            'original_text': text,
            'processed_text': self.preprocess_text(text),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Extract IOCs
        results['iocs'] = self.extract_iocs(text)
        
        # Extract entities
        results['entities'] = self.extract_entities(text)
        
        # Classify severity
        results['severity'] = self.classify_log_severity(text)
        
        # Analyze threats
        results['threat_analysis'] = self.analyze_threat_indicators(text)
        
        # ML-based classification (if trained)
        if self.is_trained:
            processed_text = results['processed_text']
            if processed_text:
                text_vector = self.vectorizer.transform([processed_text])
                
                # Log type prediction
                log_type_pred = self.log_classifier.predict(text_vector)[0]
                log_type_proba = max(self.log_classifier.predict_proba(text_vector)[0])
                
                # Priority prediction
                priority_pred = self.priority_classifier.predict(text_vector)[0]
                priority_proba = max(self.priority_classifier.predict_proba(text_vector)[0])
                
                results['ml_predictions'] = {
                    'log_type': {
                        'prediction': log_type_pred,
                        'confidence': float(log_type_proba)
                    },
                    'priority': {
                        'prediction': priority_pred,
                        'confidence': float(priority_proba)
                    }
                }
        
        return results
    
    def batch_analyze(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple texts in batch"""
        results = []
        
        for i, text in enumerate(texts):
            try:
                result = self.analyze_text(text)
                result['batch_index'] = i
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze text {i}: {e}")
                results.append({
                    'batch_index': i,
                    'error': str(e),
                    'original_text': text
                })
        
        return results
    
    def save_model(self, model_path: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        model_data = {
            'vectorizer': self.vectorizer,
            'log_classifier': self.log_classifier,
            'priority_classifier': self.priority_classifier,
            'vocabulary': self.vocabulary,
            'config': self.config,
            'ioc_patterns': {k: v.pattern for k, v in self.ioc_patterns.items()},
            'security_keywords': self.security_keywords
        }
        
        joblib.dump(model_data, f"{model_path}.pkl")
        logger.info(f"Model saved to {model_path}.pkl")
    
    def load_model(self, model_path: str):
        """Load trained model"""
        model_data = joblib.load(f"{model_path}.pkl")
        
        self.vectorizer = model_data['vectorizer']
        self.log_classifier = model_data['log_classifier']
        self.priority_classifier = model_data['priority_classifier']
        self.vocabulary = model_data['vocabulary']
        self.config.update(model_data['config'])
        
        # Restore compiled patterns
        pattern_strings = model_data['ioc_patterns']
        self.ioc_patterns = {k: re.compile(v) for k, v in pattern_strings.items()}
        
        self.security_keywords = model_data['security_keywords']
        self.is_trained = True
        
        logger.info(f"Model loaded from {model_path}.pkl")

def main():
    """Demonstration of Security Log Analysis"""
    logger.info("Starting Security Log Analysis demonstration...")
    
    # Initialize analyzer
    analyzer = SecurityLogAnalyzer()
    
    # Initialize NLP models (optional, can work without them)
    try:
        analyzer.initialize_models()
    except Exception as e:
        logger.warning(f"Could not initialize all NLP models: {e}")
    
    # Generate synthetic training data
    training_data = analyzer.generate_synthetic_logs(n_samples=2000)
    
    # Train models
    logger.info("Training models...")
    training_metrics = analyzer.fit(training_data)
    
    # Test analysis on sample logs
    test_logs = [
        "CRITICAL: Ransomware detected on host SERVER-01 with hash a1b2c3d4e5f6",
        "User admin failed login from IP 192.168.1.100",
        "Normal file access: document.pdf opened by user john",
        "Port scan detected from 10.0.0.50 targeting ports 22,80,443",
        "Phishing email from attacker@malicious.com blocked"
    ]
    
    print("\n" + "="*70)
    print("SECURITY LOG ANALYSIS RESULTS")
    print("="*70)
    
    print("\nTraining Metrics:")
    for metric, value in training_metrics.items():
        if isinstance(value, float):
            print(f"  {metric}: {value:.4f}")
        else:
            print(f"  {metric}: {value}")
    
    print("\nSample Log Analysis:")
    for i, log in enumerate(test_logs, 1):
        result = analyzer.analyze_text(log)
        
        print(f"\n--- Log {i} ---")
        print(f"Text: {log}")
        print(f"Severity: {result['severity']['severity']} (confidence: {result['severity']['confidence']:.2f})")
        print(f"Threat Level: {result['threat_analysis']['threat_level']}")
        
        if result.get('ml_predictions'):
            ml_pred = result['ml_predictions']
            print(f"ML Type: {ml_pred['log_type']['prediction']} ({ml_pred['log_type']['confidence']:.2f})")
            print(f"ML Priority: {ml_pred['priority']['prediction']} ({ml_pred['priority']['confidence']:.2f})")
        
        if result['iocs']:
            print("IOCs found:")
            for ioc_type, iocs in result['iocs'].items():
                if iocs:
                    print(f"  {ioc_type}: {iocs}")
    
    # Save model
    model_path = "projects/21-ai-powered-cybersecurity/nlp_models/log_analyzer_model"
    analyzer.save_model(model_path)
    
    logger.info("Security Log Analysis demonstration completed!")

if __name__ == "__main__":
    main()