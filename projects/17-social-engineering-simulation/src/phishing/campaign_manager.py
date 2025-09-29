#!/usr/bin/env python3
"""
Campaign Manager - Gestionnaire de Campagnes de Phishing
=======================================================

Gestionnaire complet pour la création, le déploiement et le suivi de campagnes
d'ingénierie sociale et de phishing avec intégration GoPhish et métriques avancées.

Author: Cybersecurity Portfolio
Version: 1.0.0
License: MIT (Educational Use Only)
"""

import json
import uuid
import datetime
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import pandas as pd
from jinja2 import Template, Environment, FileSystemLoader

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CampaignStatus(Enum):
    """États possibles d'une campagne"""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class CampaignType(Enum):
    """Types de campagnes supportées"""
    PHISHING = "phishing"
    SMISHING = "smishing"
    VISHING = "vishing"
    PRETEXTING = "pretexting"
    AWARENESS = "awareness"
    COMBINED = "combined"

class TemplateCategory(Enum):
    """Catégories de templates"""
    URGENT_SECURITY = "urgent_security"
    IT_SUPPORT = "it_support"
    HR_COMMUNICATION = "hr_communication"
    CEO_FRAUD = "ceo_fraud"
    INVOICE_SCAM = "invoice_scam"
    SOCIAL_MEDIA = "social_media"
    CUSTOM = "custom"

@dataclass
class Target:
    """Représentation d'une cible"""
    email: str
    first_name: str = ""
    last_name: str = ""
    department: str = ""
    position: str = ""
    phone: str = ""
    company: str = ""
    custom_fields: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_fields is None:
            self.custom_fields = {}

@dataclass
class EmailTemplate:
    """Template d'email de phishing"""
    id: str
    name: str
    category: TemplateCategory
    subject: str
    html_content: str
    text_content: str
    sender_name: str
    sender_email: str
    variables: List[str] = None
    attachments: List[str] = None
    landing_page_url: str = ""
    
    def __post_init__(self):
        if self.variables is None:
            self.variables = []
        if self.attachments is None:
            self.attachments = []

@dataclass
class CampaignMetrics:
    """Métriques d'une campagne"""
    sent_count: int = 0
    delivered_count: int = 0
    opened_count: int = 0
    clicked_count: int = 0
    submitted_count: int = 0
    reported_count: int = 0
    bounced_count: int = 0
    
    @property
    def open_rate(self) -> float:
        """Taux d'ouverture"""
        return (self.opened_count / self.delivered_count * 100) if self.delivered_count > 0 else 0
    
    @property
    def click_rate(self) -> float:
        """Taux de clic"""
        return (self.clicked_count / self.delivered_count * 100) if self.delivered_count > 0 else 0
    
    @property
    def submission_rate(self) -> float:
        """Taux de soumission"""
        return (self.submitted_count / self.delivered_count * 100) if self.delivered_count > 0 else 0
    
    @property
    def report_rate(self) -> float:
        """Taux de signalement"""
        return (self.reported_count / self.delivered_count * 100) if self.delivered_count > 0 else 0

@dataclass
class Campaign:
    """Représentation d'une campagne complète"""
    id: str
    name: str
    description: str
    type: CampaignType
    status: CampaignStatus
    template: EmailTemplate
    targets: List[Target]
    created_at: datetime.datetime
    scheduled_at: Optional[datetime.datetime] = None
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    metrics: CampaignMetrics = None
    settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metrics is None:
            self.metrics = CampaignMetrics()
        if self.settings is None:
            self.settings = {
                'send_delay': 0,  # Délai entre emails (secondes)
                'track_opens': True,
                'track_clicks': True,
                'capture_credentials': True,
                'capture_data': True,
                'redirect_url': '',
                'smtp_host': 'localhost',
                'smtp_port': 587,
                'smtp_username': '',
                'smtp_password': '',
                'smtp_tls': True
            }

class TemplateEngine:
    """Moteur de génération de templates personnalisés"""
    
    def __init__(self, templates_dir: str = "templates/email-templates"):
        self.templates_dir = templates_dir
        self.env = Environment(loader=FileSystemLoader(templates_dir))
        self.templates_cache = {}
    
    def load_template(self, template_id: str) -> Optional[EmailTemplate]:
        """Charge un template depuis le fichier système"""
        try:
            template_file = f"{template_id}.json"
            template_path = f"{self.templates_dir}/{template_file}"
            
            with open(template_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            template = EmailTemplate(**data)
            self.templates_cache[template_id] = template
            logger.info(f"Template loaded: {template_id}")
            return template
            
        except Exception as e:
            logger.error(f"Failed to load template {template_id}: {e}")
            return None
    
    def create_template(self, template_data: Dict[str, Any]) -> EmailTemplate:
        """Crée un nouveau template"""
        template_id = str(uuid.uuid4())
        
        template = EmailTemplate(
            id=template_id,
            name=template_data.get('name', 'Untitled Template'),
            category=TemplateCategory(template_data.get('category', 'custom')),
            subject=template_data.get('subject', ''),
            html_content=template_data.get('html_content', ''),
            text_content=template_data.get('text_content', ''),
            sender_name=template_data.get('sender_name', ''),
            sender_email=template_data.get('sender_email', ''),
            variables=template_data.get('variables', []),
            attachments=template_data.get('attachments', []),
            landing_page_url=template_data.get('landing_page_url', '')
        )
        
        self.save_template(template)
        logger.info(f"Created new template: {template.name}")
        return template
    
    def save_template(self, template: EmailTemplate) -> bool:
        """Sauvegarde un template"""
        try:
            template_file = f"{template.id}.json"
            template_path = f"{self.templates_dir}/{template_file}"
            
            with open(template_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(template), f, indent=2, default=str)
            
            logger.info(f"Template saved: {template.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            return False
    
    def render_template(self, template: EmailTemplate, target: Target) -> Dict[str, str]:
        """Rendu d'un template avec les données de la cible"""
        try:
            # Variables disponibles pour le template
            context = {
                'first_name': target.first_name,
                'last_name': target.last_name,
                'full_name': f"{target.first_name} {target.last_name}".strip(),
                'email': target.email,
                'department': target.department,
                'position': target.position,
                'company': target.company,
                'phone': target.phone,
                **target.custom_fields
            }
            
            # Rendu du sujet
            subject_template = Template(template.subject)
            rendered_subject = subject_template.render(**context)
            
            # Rendu du contenu HTML
            html_template = Template(template.html_content)
            rendered_html = html_template.render(**context)
            
            # Rendu du contenu texte
            text_template = Template(template.text_content)
            rendered_text = text_template.render(**context)
            
            return {
                'subject': rendered_subject,
                'html_content': rendered_html,
                'text_content': rendered_text
            }
            
        except Exception as e:
            logger.error(f"Failed to render template for {target.email}: {e}")
            return {
                'subject': template.subject,
                'html_content': template.html_content,
                'text_content': template.text_content
            }

class DatabaseManager:
    """Gestionnaire de base de données pour les campagnes"""
    
    def __init__(self, db_path: str = "campaigns.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialise la base de données"""
        with sqlite3.connect(self.db_path) as conn:
            # Table des campagnes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    template_data TEXT,
                    settings TEXT,
                    created_at TIMESTAMP,
                    scheduled_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP
                )
            """)
            
            # Table des cibles
            conn.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    email TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    department TEXT,
                    position TEXT,
                    phone TEXT,
                    company TEXT,
                    custom_fields TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)
            
            # Table des événements
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    target_email TEXT,
                    event_type TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)
            
            conn.commit()
            logger.info("Database initialized")
    
    def save_campaign(self, campaign: Campaign) -> bool:
        """Sauvegarde une campagne"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Sauvegarde de la campagne
                conn.execute("""
                    INSERT OR REPLACE INTO campaigns 
                    (id, name, description, type, status, template_data, settings, 
                     created_at, scheduled_at, started_at, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign.id,
                    campaign.name,
                    campaign.description,
                    campaign.type.value,
                    campaign.status.value,
                    json.dumps(asdict(campaign.template)),
                    json.dumps(campaign.settings),
                    campaign.created_at,
                    campaign.scheduled_at,
                    campaign.started_at,
                    campaign.completed_at
                ))
                
                # Suppression des anciennes cibles
                conn.execute("DELETE FROM targets WHERE campaign_id = ?", (campaign.id,))
                
                # Sauvegarde des nouvelles cibles
                for target in campaign.targets:
                    conn.execute("""
                        INSERT INTO targets 
                        (campaign_id, email, first_name, last_name, department, 
                         position, phone, company, custom_fields)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        campaign.id,
                        target.email,
                        target.first_name,
                        target.last_name,
                        target.department,
                        target.position,
                        target.phone,
                        target.company,
                        json.dumps(target.custom_fields)
                    ))
                
                conn.commit()
                logger.info(f"Campaign saved: {campaign.id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to save campaign: {e}")
            return False
    
    def load_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Charge une campagne"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Chargement de la campagne
                cursor = conn.execute("""
                    SELECT * FROM campaigns WHERE id = ?
                """, (campaign_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Chargement des cibles
                targets_cursor = conn.execute("""
                    SELECT * FROM targets WHERE campaign_id = ?
                """, (campaign_id,))
                
                targets = []
                for target_row in targets_cursor.fetchall():
                    target = Target(
                        email=target_row[2],
                        first_name=target_row[3] or "",
                        last_name=target_row[4] or "",
                        department=target_row[5] or "",
                        position=target_row[6] or "",
                        phone=target_row[7] or "",
                        company=target_row[8] or "",
                        custom_fields=json.loads(target_row[9] or "{}")
                    )
                    targets.append(target)
                
                # Reconstruction de la campagne
                template_data = json.loads(row[5])
                template = EmailTemplate(**template_data)
                
                campaign = Campaign(
                    id=row[0],
                    name=row[1],
                    description=row[2] or "",
                    type=CampaignType(row[3]),
                    status=CampaignStatus(row[4]),
                    template=template,
                    targets=targets,
                    created_at=datetime.datetime.fromisoformat(row[7]),
                    scheduled_at=datetime.datetime.fromisoformat(row[8]) if row[8] else None,
                    started_at=datetime.datetime.fromisoformat(row[9]) if row[9] else None,
                    completed_at=datetime.datetime.fromisoformat(row[10]) if row[10] else None,
                    settings=json.loads(row[6])
                )
                
                logger.info(f"Campaign loaded: {campaign_id}")
                return campaign
                
        except Exception as e:
            logger.error(f"Failed to load campaign {campaign_id}: {e}")
            return None
    
    def log_event(self, campaign_id: str, target_email: str, event_type: str, data: Dict[str, Any] = None):
        """Enregistre un événement"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO events (campaign_id, target_email, event_type, data)
                    VALUES (?, ?, ?, ?)
                """, (
                    campaign_id,
                    target_email,
                    event_type,
                    json.dumps(data or {})
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to log event: {e}")

class EmailSender:
    """Gestionnaire d'envoi d'emails"""
    
    def __init__(self, smtp_config: Dict[str, Any]):
        self.smtp_config = smtp_config
    
    def send_email(self, target: Target, rendered_content: Dict[str, str], template: EmailTemplate) -> bool:
        """Envoie un email à une cible"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{template.sender_name} <{template.sender_email}>"
            msg['To'] = target.email
            msg['Subject'] = rendered_content['subject']
            
            # Ajout du contenu texte
            text_part = MIMEText(rendered_content['text_content'], 'plain', 'utf-8')
            msg.attach(text_part)
            
            # Ajout du contenu HTML
            html_part = MIMEText(rendered_content['html_content'], 'html', 'utf-8')
            msg.attach(html_part)
            
            # Connexion SMTP et envoi
            with smtplib.SMTP(self.smtp_config['smtp_host'], self.smtp_config['smtp_port']) as server:
                if self.smtp_config.get('smtp_tls', True):
                    server.starttls()
                
                if self.smtp_config.get('smtp_username'):
                    server.login(self.smtp_config['smtp_username'], self.smtp_config['smtp_password'])
                
                server.send_message(msg)
            
            logger.info(f"Email sent to {target.email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {target.email}: {e}")
            return False

class CampaignManager:
    """Gestionnaire principal de campagnes"""
    
    def __init__(self, db_path: str = "campaigns.db", templates_dir: str = "templates/email-templates"):
        self.db = DatabaseManager(db_path)
        self.template_engine = TemplateEngine(templates_dir)
        self.campaigns = {}
    
    def create_campaign(self, 
                       name: str,
                       description: str,
                       campaign_type: Union[str, CampaignType],
                       template_data: Dict[str, Any],
                       targets: List[Dict[str, Any]],
                       settings: Dict[str, Any] = None) -> Campaign:
        """Crée une nouvelle campagne"""
        
        campaign_id = str(uuid.uuid4())
        
        # Conversion du type de campagne
        if isinstance(campaign_type, str):
            campaign_type = CampaignType(campaign_type)
        
        # Création du template
        template = self.template_engine.create_template(template_data)
        
        # Création des cibles
        campaign_targets = []
        for target_data in targets:
            target = Target(**target_data)
            campaign_targets.append(target)
        
        # Création de la campagne
        campaign = Campaign(
            id=campaign_id,
            name=name,
            description=description,
            type=campaign_type,
            status=CampaignStatus.DRAFT,
            template=template,
            targets=campaign_targets,
            created_at=datetime.datetime.now(),
            settings=settings or {}
        )
        
        # Sauvegarde
        if self.db.save_campaign(campaign):
            self.campaigns[campaign_id] = campaign
            logger.info(f"Campaign created: {name} ({campaign_id})")
            return campaign
        else:
            raise Exception("Failed to save campaign to database")
    
    def launch_campaign(self, campaign_id: str) -> bool:
        """Lance une campagne"""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            logger.error(f"Campaign not found: {campaign_id}")
            return False
        
        if campaign.status != CampaignStatus.DRAFT:
            logger.error(f"Campaign cannot be launched in current status: {campaign.status}")
            return False
        
        try:
            # Mise à jour du statut
            campaign.status = CampaignStatus.RUNNING
            campaign.started_at = datetime.datetime.now()
            
            # Configuration SMTP
            email_sender = EmailSender(campaign.settings)
            
            # Envoi des emails
            sent_count = 0
            for target in campaign.targets:
                try:
                    # Rendu du template
                    rendered_content = self.template_engine.render_template(campaign.template, target)
                    
                    # Envoi de l'email
                    if email_sender.send_email(target, rendered_content, campaign.template):
                        sent_count += 1
                        self.db.log_event(campaign_id, target.email, "email_sent")
                        campaign.metrics.sent_count += 1
                    else:
                        self.db.log_event(campaign_id, target.email, "email_failed")
                        campaign.metrics.bounced_count += 1
                    
                    # Délai entre envois
                    if campaign.settings.get('send_delay', 0) > 0:
                        import time
                        time.sleep(campaign.settings['send_delay'])
                        
                except Exception as e:
                    logger.error(f"Failed to send to {target.email}: {e}")
                    self.db.log_event(campaign_id, target.email, "email_error", {"error": str(e)})
            
            # Mise à jour des métriques
            campaign.metrics.delivered_count = sent_count
            
            # Sauvegarde
            self.db.save_campaign(campaign)
            
            logger.info(f"Campaign launched: {campaign.name} ({sent_count}/{len(campaign.targets)} emails sent)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch campaign: {e}")
            campaign.status = CampaignStatus.DRAFT
            return False
    
    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Récupère une campagne"""
        if campaign_id in self.campaigns:
            return self.campaigns[campaign_id]
        
        campaign = self.db.load_campaign(campaign_id)
        if campaign:
            self.campaigns[campaign_id] = campaign
        
        return campaign
    
    def list_campaigns(self) -> List[Campaign]:
        """Liste toutes les campagnes"""
        campaigns = []
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.execute("SELECT id FROM campaigns ORDER BY created_at DESC")
                for row in cursor.fetchall():
                    campaign = self.get_campaign(row[0])
                    if campaign:
                        campaigns.append(campaign)
        except Exception as e:
            logger.error(f"Failed to list campaigns: {e}")
        
        return campaigns
    
    def get_campaign_metrics(self, campaign_id: str) -> Optional[CampaignMetrics]:
        """Récupère les métriques d'une campagne"""
        campaign = self.get_campaign(campaign_id)
        if campaign:
            return campaign.metrics
        return None
    
    def update_metrics_from_events(self, campaign_id: str):
        """Met à jour les métriques à partir des événements enregistrés"""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.execute("""
                    SELECT event_type, COUNT(*) FROM events 
                    WHERE campaign_id = ? 
                    GROUP BY event_type
                """, (campaign_id,))
                
                campaign = self.get_campaign(campaign_id)
                if not campaign:
                    return
                
                metrics = campaign.metrics
                
                for row in cursor.fetchall():
                    event_type, count = row
                    
                    if event_type == "email_opened":
                        metrics.opened_count = count
                    elif event_type == "link_clicked":
                        metrics.clicked_count = count
                    elif event_type == "data_submitted":
                        metrics.submitted_count = count
                    elif event_type == "email_reported":
                        metrics.reported_count = count
                
                # Sauvegarde des métriques mises à jour
                self.db.save_campaign(campaign)
                
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")

def main():
    """Exemple d'utilisation du gestionnaire de campagnes"""
    
    # Initialisation du gestionnaire
    manager = CampaignManager()
    
    # Données de template
    template_data = {
        'name': 'Urgent Security Update',
        'category': 'urgent_security',
        'subject': 'URGENT: Security Update Required for {{ first_name }}',
        'html_content': '''
        <html>
        <body>
            <h2>Urgent Security Update Required</h2>
            <p>Dear {{ first_name }},</p>
            <p>We have detected unusual activity on your account. Please click the link below to verify your account:</p>
            <p><a href="http://secure-portal.com/verify">Verify Account</a></p>
            <p>IT Security Team</p>
        </body>
        </html>
        ''',
        'text_content': '''
        URGENT: Security Update Required
        
        Dear {{ first_name }},
        
        We have detected unusual activity on your account. 
        Please visit: http://secure-portal.com/verify
        
        IT Security Team
        ''',
        'sender_name': 'IT Security',
        'sender_email': 'security@company.com'
    }
    
    # Cibles de test
    targets = [
        {
            'email': 'john.doe@company.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'department': 'Finance',
            'position': 'Analyst'
        },
        {
            'email': 'jane.smith@company.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'department': 'HR',
            'position': 'Manager'
        }
    ]
    
    # Paramètres SMTP
    settings = {
        'smtp_host': 'localhost',
        'smtp_port': 1025,  # MailHog pour tests
        'send_delay': 1
    }
    
    # Création de la campagne
    campaign = manager.create_campaign(
        name="Q4 Security Awareness Test",
        description="Campaign to test employee awareness of phishing attempts",
        campaign_type="phishing",
        template_data=template_data,
        targets=targets,
        settings=settings
    )
    
    print(f"Campaign created: {campaign.name}")
    print(f"Campaign ID: {campaign.id}")
    print(f"Number of targets: {len(campaign.targets)}")
    
    # Simulation de lancement (commenté pour éviter l'envoi réel)
    # success = manager.launch_campaign(campaign.id)
    # print(f"Campaign launched: {success}")

if __name__ == "__main__":
    main()