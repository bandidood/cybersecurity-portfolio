#!/usr/bin/env python3
"""
Social Reconnaissance - Collecte d'Informations OSINT
====================================================

Module avancé de reconnaissance sociale pour la collecte automatisée
d'informations publiques sur les cibles d'ingénierie sociale.

Author: Cybersecurity Portfolio
Version: 1.0.0
License: MIT (Educational Use Only)
"""

import re
import json
import time
import requests
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
import dns.resolver
import whois
from bs4 import BeautifulSoup
import linkedin_api
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import tweepy
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class PersonProfile:
    """Profil d'une personne"""
    name: str
    email: str = ""
    phone: str = ""
    position: str = ""
    department: str = ""
    company: str = ""
    linkedin_url: str = ""
    twitter_handle: str = ""
    facebook_url: str = ""
    location: str = ""
    bio: str = ""
    interests: List[str] = None
    connections: List[str] = None
    recent_activity: List[Dict[str, Any]] = None
    profile_image: str = ""
    confidence_score: float = 0.0
    
    def __post_init__(self):
        if self.interests is None:
            self.interests = []
        if self.connections is None:
            self.connections = []
        if self.recent_activity is None:
            self.recent_activity = []

@dataclass
class CompanyProfile:
    """Profil d'une entreprise"""
    name: str
    domain: str
    industry: str = ""
    size: str = ""
    location: str = ""
    description: str = ""
    website: str = ""
    linkedin_url: str = ""
    twitter_handle: str = ""
    phone: str = ""
    email_patterns: List[str] = None
    employees: List[PersonProfile] = None
    technologies: List[str] = None
    recent_news: List[Dict[str, Any]] = None
    social_media_presence: Dict[str, str] = None
    
    def __post_init__(self):
        if self.email_patterns is None:
            self.email_patterns = []
        if self.employees is None:
            self.employees = []
        if self.technologies is None:
            self.technologies = []
        if self.recent_news is None:
            self.recent_news = []
        if self.social_media_presence is None:
            self.social_media_presence = {}

class EmailHarvester:
    """Collecteur d'adresses email"""
    
    def __init__(self):
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def harvest_from_website(self, domain: str) -> Set[str]:
        """Collecte des emails depuis un site web"""
        emails = set()
        
        try:
            # Liste des pages communes à scanner
            pages = ['', '/contact', '/about', '/team', '/staff', '/people', '/directory']
            
            for page in pages:
                url = f"http://{domain}{page}"
                try:
                    response = self.session.get(url, timeout=10)
                    if response.status_code == 200:
                        found_emails = self.email_pattern.findall(response.text)
                        for email in found_emails:
                            if domain in email.lower():
                                emails.add(email.lower())
                        
                        # Recherche dans les liens mailto
                        soup = BeautifulSoup(response.text, 'html.parser')
                        mailto_links = soup.find_all('a', href=re.compile(r'^mailto:'))
                        for link in mailto_links:
                            email = link['href'].replace('mailto:', '')
                            if '@' in email:
                                emails.add(email.lower())
                
                except Exception as e:
                    logger.debug(f"Error accessing {url}: {e}")
                
                time.sleep(1)  # Délai respectueux
        
        except Exception as e:
            logger.error(f"Error harvesting emails from {domain}: {e}")
        
        logger.info(f"Found {len(emails)} emails for domain {domain}")
        return emails
    
    def harvest_from_search_engines(self, domain: str) -> Set[str]:
        """Collecte des emails via moteurs de recherche"""
        emails = set()
        
        try:
            # Requête Google Search (via API ou scraping respectueux)
            search_query = f"site:{domain} email OR mail OR contact"
            
            # Note: En production, utiliser l'API Google Custom Search
            # Pour les tests, simulation de résultats
            
            logger.info(f"Search engine harvest for {domain} would be performed here")
            
        except Exception as e:
            logger.error(f"Error with search engine harvest: {e}")
        
        return emails
    
    def verify_email_patterns(self, domain: str, names: List[str]) -> List[str]:
        """Vérifie les patterns d'emails communs"""
        common_patterns = [
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{first}@{domain}",
            "{last}@{domain}",
            "{first_initial}{last}@{domain}",
            "{first}{last_initial}@{domain}"
        ]
        
        potential_emails = []
        
        for name in names:
            parts = name.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                first_initial = first[0] if first else ""
                last_initial = last[0] if last else ""
                
                for pattern in common_patterns:
                    email = pattern.format(
                        first=first,
                        last=last,
                        first_initial=first_initial,
                        last_initial=last_initial,
                        domain=domain
                    )
                    potential_emails.append(email)
        
        return potential_emails

class SocialMediaCollector:
    """Collecteur d'informations sur les réseaux sociaux"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.linkedin_api = None
        self.twitter_api = None
        
        # Configuration des APIs (si disponibles)
        if 'linkedin' in self.config:
            try:
                self.linkedin_api = linkedin_api.Linkedin(
                    self.config['linkedin']['username'],
                    self.config['linkedin']['password']
                )
            except Exception as e:
                logger.warning(f"LinkedIn API not available: {e}")
        
        if 'twitter' in self.config:
            try:
                auth = tweepy.OAuthHandler(
                    self.config['twitter']['consumer_key'],
                    self.config['twitter']['consumer_secret']
                )
                auth.set_access_token(
                    self.config['twitter']['access_token'],
                    self.config['twitter']['access_token_secret']
                )
                self.twitter_api = tweepy.API(auth)
            except Exception as e:
                logger.warning(f"Twitter API not available: {e}")
    
    def search_linkedin_employees(self, company_name: str) -> List[PersonProfile]:
        """Recherche des employés sur LinkedIn"""
        employees = []
        
        if not self.linkedin_api:
            logger.warning("LinkedIn API not configured")
            return employees
        
        try:
            # Recherche de profils associés à l'entreprise
            search_results = self.linkedin_api.search_people(
                keywords=f"{company_name}",
                network_depths=['F', 'S', 'O'],
                regions=['fr:0'],  # Peut être configuré
                industries=None,
                current_company=[company_name]
            )
            
            for person in search_results:
                profile = PersonProfile(
                    name=f"{person.get('firstName', '')} {person.get('lastName', '')}".strip(),
                    position=person.get('headline', ''),
                    company=company_name,
                    linkedin_url=f"https://www.linkedin.com/in/{person.get('publicIdentifier', '')}",
                    location=person.get('location', {}).get('name', ''),
                    profile_image=person.get('profilePicture', {}).get('displayImageReference', ''),
                    confidence_score=0.8
                )
                employees.append(profile)
                
                # Limite respectueuse
                if len(employees) >= 50:
                    break
                
                time.sleep(2)  # Délai respectueux
        
        except Exception as e:
            logger.error(f"Error searching LinkedIn employees: {e}")
        
        logger.info(f"Found {len(employees)} LinkedIn profiles for {company_name}")
        return employees
    
    def analyze_twitter_account(self, handle: str) -> Dict[str, Any]:
        """Analyse un compte Twitter"""
        info = {}
        
        if not self.twitter_api:
            logger.warning("Twitter API not configured")
            return info
        
        try:
            user = self.twitter_api.get_user(screen_name=handle)
            
            info = {
                'name': user.name,
                'bio': user.description,
                'location': user.location,
                'followers_count': user.followers_count,
                'friends_count': user.friends_count,
                'tweets_count': user.statuses_count,
                'created_at': user.created_at.isoformat(),
                'verified': user.verified,
                'profile_image': user.profile_image_url_https
            }
            
            # Récupération des tweets récents
            tweets = self.twitter_api.user_timeline(screen_name=handle, count=20)
            recent_tweets = []
            
            for tweet in tweets:
                recent_tweets.append({
                    'text': tweet.text,
                    'created_at': tweet.created_at.isoformat(),
                    'retweet_count': tweet.retweet_count,
                    'favorite_count': tweet.favorite_count
                })
            
            info['recent_tweets'] = recent_tweets
            
        except Exception as e:
            logger.error(f"Error analyzing Twitter account {handle}: {e}")
        
        return info

class WebScraper:
    """Scraper web pour informations publiques"""
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.driver = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def init_selenium(self):
        """Initialise Selenium WebDriver"""
        if not self.driver:
            chrome_options = Options()
            if self.headless:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            
            try:
                self.driver = webdriver.Chrome(options=chrome_options)
            except Exception as e:
                logger.error(f"Failed to initialize Chrome driver: {e}")
                self.driver = None
    
    def scrape_company_website(self, domain: str) -> Dict[str, Any]:
        """Scrape le site web d'une entreprise"""
        info = {
            'description': '',
            'technologies': [],
            'contact_info': {},
            'social_links': {},
            'employee_names': []
        }
        
        try:
            url = f"http://{domain}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Description (meta description ou about)
                meta_desc = soup.find('meta', attrs={'name': 'description'})
                if meta_desc:
                    info['description'] = meta_desc.get('content', '')
                
                # Technologies détectées
                info['technologies'] = self.detect_technologies(response.text, response.headers)
                
                # Liens sociaux
                social_patterns = {
                    'linkedin': r'linkedin\.com/company/([^/\s"\']+)',
                    'twitter': r'twitter\.com/([^/\s"\']+)',
                    'facebook': r'facebook\.com/([^/\s"\']+)'
                }
                
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        info['social_links'][platform] = matches[0]
                
                # Noms d'employés (pages équipe/à propos)
                team_links = soup.find_all('a', href=re.compile(r'(team|about|staff|people)', re.I))
                for link in team_links[:3]:  # Limite à 3 pages
                    try:
                        team_url = urljoin(url, link['href'])
                        team_response = self.session.get(team_url, timeout=10)
                        if team_response.status_code == 200:
                            names = self.extract_names_from_page(team_response.text)
                            info['employee_names'].extend(names)
                        time.sleep(1)
                    except Exception:
                        continue
        
        except Exception as e:
            logger.error(f"Error scraping {domain}: {e}")
        
        return info
    
    def detect_technologies(self, html_content: str, headers: Dict[str, str]) -> List[str]:
        """Détecte les technologies utilisées"""
        technologies = []
        
        # Détection via headers
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Détection via contenu HTML
        html_lower = html_content.lower()
        
        tech_patterns = {
            'WordPress': ['wp-content', 'wordpress'],
            'Drupal': ['drupal', 'sites/all'],
            'Joomla': ['joomla', 'administrator'],
            'React': ['react', '__react'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue.js', '__vue'],
            'jQuery': ['jquery', 'jquery.min.js'],
            'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
            'Google Analytics': ['google-analytics', 'gtag'],
            'Google Tag Manager': ['googletagmanager'],
            'CloudFlare': ['cloudflare'],
            'AWS': ['amazonaws']
        }
        
        for tech, patterns in tech_patterns.items():
            if any(pattern in html_lower for pattern in patterns):
                technologies.append(tech)
        
        return list(set(technologies))
    
    def extract_names_from_page(self, html_content: str) -> List[str]:
        """Extrait les noms de personnes d'une page"""
        names = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Patterns de noms (prénom nom avec majuscules)
        name_pattern = re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b')
        
        # Recherche dans le texte
        text_content = soup.get_text()
        potential_names = name_pattern.findall(text_content)
        
        # Filtrage des faux positifs
        common_words = {'About Us', 'Contact Us', 'Terms Of', 'Privacy Policy'}
        
        for name in potential_names:
            if name not in common_words and len(name.split()) == 2:
                names.append(name)
        
        return list(set(names))
    
    def cleanup(self):
        """Nettoyage des ressources"""
        if self.driver:
            self.driver.quit()

class DNSRecon:
    """Reconnaissance DNS"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
    
    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Collecte des informations DNS"""
        dns_info = {
            'mx_records': [],
            'a_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'subdomain_enum': []
        }
        
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answers]
                dns_info[f"{record_type.lower()}_records"] = records
            except Exception:
                pass
        
        # Énumération de sous-domaines communs
        common_subdomains = [
            'www', 'mail', 'email', 'webmail', 'ftp', 'cpanel', 'whm', 'ssh', 'ssl',
            'ns1', 'ns2', 'ns3', 'mx', 'mx1', 'mx2', 'pop', 'pop3', 'imap', 'smtp',
            'secure', 'vpn', 'admin', 'administrator', 'api', 'blog', 'forum',
            'help', 'support', 'dev', 'test', 'staging', 'demo'
        ]
        
        found_subdomains = []
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    found_subdomains.append(full_domain)
            except Exception:
                pass
        
        dns_info['subdomain_enum'] = found_subdomains
        return dns_info

class SocialRecon:
    """Classe principale de reconnaissance sociale"""
    
    def __init__(self, config_file: str = None):
        self.config = {}
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load config file: {e}")
        
        self.email_harvester = EmailHarvester()
        self.social_collector = SocialMediaCollector(self.config)
        self.web_scraper = WebScraper()
        self.dns_recon = DNSRecon()
    
    def profile_company(self, domain: str) -> CompanyProfile:
        """Profile complet d'une entreprise"""
        logger.info(f"Starting company profiling for {domain}")
        
        # Informations WHOIS
        whois_info = {}
        try:
            whois_data = whois.whois(domain)
            whois_info = {
                'registrar': whois_data.registrar,
                'creation_date': str(whois_data.creation_date) if whois_data.creation_date else None,
                'expiration_date': str(whois_data.expiration_date) if whois_data.expiration_date else None,
                'name_servers': whois_data.name_servers
            }
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
        
        # Informations DNS
        dns_info = self.dns_recon.get_dns_info(domain)
        
        # Scraping du site web
        web_info = self.web_scraper.scrape_company_website(domain)
        
        # Collecte d'emails
        emails = self.email_harvester.harvest_from_website(domain)
        
        # Patterns d'emails probables
        email_patterns = []
        if web_info['employee_names']:
            patterns = self.email_harvester.verify_email_patterns(domain, web_info['employee_names'])
            email_patterns.extend(patterns)
        
        # Recherche d'employés sur LinkedIn
        company_name = domain.split('.')[0].title()  # Approximation
        linkedin_employees = self.social_collector.search_linkedin_employees(company_name)
        
        # Création du profil d'entreprise
        company_profile = CompanyProfile(
            name=company_name,
            domain=domain,
            website=f"http://{domain}",
            description=web_info['description'],
            technologies=web_info['technologies'],
            employees=linkedin_employees,
            email_patterns=list(set(email_patterns)),
            social_media_presence=web_info['social_links']
        )
        
        logger.info(f"Company profiling completed for {domain}")
        logger.info(f"Found {len(linkedin_employees)} employees, {len(emails)} emails, {len(web_info['technologies'])} technologies")
        
        return company_profile
    
    def profile_person(self, name: str, company: str = "", additional_info: Dict[str, str] = None) -> PersonProfile:
        """Profile complet d'une personne"""
        logger.info(f"Starting person profiling for {name}")
        
        profile = PersonProfile(name=name, company=company)
        
        if additional_info:
            for key, value in additional_info.items():
                if hasattr(profile, key):
                    setattr(profile, key, value)
        
        # Recherche sur les réseaux sociaux
        search_terms = [name]
        if company:
            search_terms.append(f"{name} {company}")
        
        # Note: Ici, on ajouterait des recherches sur différentes plateformes
        # LinkedIn, Twitter, Facebook, etc.
        
        logger.info(f"Person profiling completed for {name}")
        return profile
    
    def find_employees(self, domain: str) -> List[PersonProfile]:
        """Trouve les employés d'une entreprise"""
        company_profile = self.profile_company(domain)
        return company_profile.employees
    
    def analyze_social_media(self, employees: List[PersonProfile]) -> Dict[str, Any]:
        """Analyse les réseaux sociaux des employés"""
        analysis = {
            'total_employees': len(employees),
            'linkedin_profiles': 0,
            'twitter_profiles': 0,
            'common_interests': {},
            'locations': {},
            'departments': {}
        }
        
        for employee in employees:
            if employee.linkedin_url:
                analysis['linkedin_profiles'] += 1
            if employee.twitter_handle:
                analysis['twitter_profiles'] += 1
            
            # Agrégation des données
            if employee.location:
                analysis['locations'][employee.location] = analysis['locations'].get(employee.location, 0) + 1
            
            if employee.department:
                analysis['departments'][employee.department] = analysis['departments'].get(employee.department, 0) + 1
            
            for interest in employee.interests:
                analysis['common_interests'][interest] = analysis['common_interests'].get(interest, 0) + 1
        
        return analysis
    
    def export_results(self, data: Any, filename: str, format: str = 'json') -> bool:
        """Exporte les résultats"""
        try:
            if format.lower() == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(asdict(data) if hasattr(data, '__dict__') else data, f, indent=2, default=str)
            
            logger.info(f"Results exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False
    
    def cleanup(self):
        """Nettoyage des ressources"""
        self.web_scraper.cleanup()

def main():
    """Exemple d'utilisation"""
    
    # Configuration (optionnelle)
    config = {
        'linkedin': {
            # Credentials LinkedIn (si disponibles)
        },
        'twitter': {
            # Credentials Twitter (si disponibles)
        }
    }
    
    # Initialisation
    recon = SocialRecon()
    
    try:
        # Profiling d'entreprise
        domain = "example.com"
        company_profile = recon.profile_company(domain)
        
        print(f"Company: {company_profile.name}")
        print(f"Technologies: {', '.join(company_profile.technologies)}")
        print(f"Employees found: {len(company_profile.employees)}")
        print(f"Email patterns: {len(company_profile.email_patterns)}")
        
        # Analyse des réseaux sociaux
        if company_profile.employees:
            social_analysis = recon.analyze_social_media(company_profile.employees)
            print(f"Social Media Analysis: {social_analysis}")
        
        # Export des résultats
        recon.export_results(company_profile, f"{domain}_profile.json")
        
    finally:
        recon.cleanup()

if __name__ == "__main__":
    main()