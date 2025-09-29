#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Mobile Forensics Analyzer - Forensic Analysis Toolkit
============================================================================
Analyseur mobile forensique pour dispositifs Android et iOS :
- Extraction d'artefacts système et utilisateur
- Analyse des bases de données SQLite (SMS, appels, contacts)
- Récupération d'applications et données supprimées
- Timeline des activités mobile
- Analyse de géolocalisation et métadonnées
- Décryptage et analyse des backups

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import hashlib
import logging
import sqlite3
import json
import plist
import struct
import zipfile
import gzip
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
import re
import base64

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Types de dispositifs mobiles supportés"""
    ANDROID = "Android"
    IOS = "iOS"
    UNKNOWN = "Unknown"


class ExtractionMethod(Enum):
    """Méthodes d'extraction forensique"""
    PHYSICAL = "Physical"
    LOGICAL = "Logical"
    FILE_SYSTEM = "File System"
    BACKUP = "Backup"
    JTAG = "JTAG"
    CHIP_OFF = "Chip-Off"


class ArtifactType(Enum):
    """Types d'artefacts mobile"""
    SMS = "SMS"
    CALL_LOG = "Call Log"
    CONTACTS = "Contacts"
    EMAIL = "Email"
    CHAT_MESSAGE = "Chat Message"
    BROWSER_HISTORY = "Browser History"
    LOCATION_DATA = "Location Data"
    PHOTO = "Photo"
    VIDEO = "Video"
    APPLICATION_DATA = "Application Data"
    SYSTEM_LOG = "System Log"
    NETWORK_CONNECTION = "Network Connection"
    FILE_SYSTEM = "File System"
    DELETED_FILE = "Deleted File"


@dataclass
class DeviceInfo:
    """Informations sur le dispositif mobile"""
    device_type: DeviceType
    model: str
    os_version: str
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    phone_number: Optional[str] = None
    carrier: Optional[str] = None
    last_backup_date: Optional[datetime] = None
    root_jailbreak_status: bool = False
    encryption_status: bool = False
    total_storage: Optional[int] = None
    used_storage: Optional[int] = None


@dataclass
class SMSMessage:
    """Message SMS extrait"""
    message_id: int
    thread_id: int
    address: str
    body: str
    timestamp: datetime
    message_type: str  # "sent" ou "received"
    read_status: bool = False
    service_center: Optional[str] = None
    deleted: bool = False


@dataclass
class CallRecord:
    """Enregistrement d'appel"""
    call_id: int
    phone_number: str
    contact_name: Optional[str]
    call_type: str  # "incoming", "outgoing", "missed"
    timestamp: datetime
    duration: int  # en secondes
    deleted: bool = False


@dataclass
class Contact:
    """Contact extrait"""
    contact_id: int
    display_name: str
    phone_numbers: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    organization: Optional[str] = None
    photo_uri: Optional[str] = None
    notes: Optional[str] = None
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None


@dataclass
class LocationPoint:
    """Point de géolocalisation"""
    timestamp: datetime
    latitude: float
    longitude: float
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    provider: Optional[str] = None  # GPS, Network, Passive
    source_app: Optional[str] = None


@dataclass
class BrowserRecord:
    """Enregistrement de navigation"""
    url: str
    title: str
    timestamp: datetime
    visit_count: int = 1
    browser: str = "Unknown"
    deleted: bool = False


@dataclass
class AppData:
    """Données d'application"""
    package_name: str
    app_name: str
    version: str
    install_time: Optional[datetime] = None
    last_used: Optional[datetime] = None
    data_size: int = 0
    permissions: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    suspicious: bool = False


@dataclass
class MediaFile:
    """Fichier multimédia"""
    file_path: str
    file_type: str  # "photo", "video", "audio"
    file_size: int
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    gps_coordinates: Optional[Tuple[float, float]] = None
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    deleted: bool = False
    hash_md5: Optional[str] = None


class AndroidAnalyzer:
    """Analyseur spécialisé pour Android"""
    
    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.device_info = None
        self.artifacts = []
    
    def analyze_device_info(self) -> DeviceInfo:
        """Extrait les informations du dispositif Android"""
        try:
            device_info = DeviceInfo(
                device_type=DeviceType.ANDROID,
                model="Unknown",
                os_version="Unknown"
            )
            
            # Recherche du fichier build.prop
            build_prop_path = self._find_file("build.prop")
            if build_prop_path:
                build_props = self._parse_build_prop(build_prop_path)
                device_info.model = build_props.get("ro.product.model", "Unknown")
                device_info.os_version = build_props.get("ro.build.version.release", "Unknown")
                device_info.serial_number = build_props.get("ro.serialno")
            
            # Recherche des informations téléphonie
            telephony_db = self._find_file("telephony.db")
            if telephony_db:
                device_info.carrier = self._extract_carrier_info(telephony_db)
            
            self.device_info = device_info
            return device_info
            
        except Exception as e:
            logger.error(f"Erreur analyse info dispositif: {e}")
            return DeviceInfo(device_type=DeviceType.ANDROID, model="Unknown", os_version="Unknown")
    
    def extract_sms_messages(self) -> List[SMSMessage]:
        """Extrait les messages SMS"""
        messages = []
        
        try:
            # Base de données SMS Android standard
            sms_db_paths = [
                "data/data/com.android.providers.telephony/databases/mmssms.db",
                "data/data/com.android.providers.telephony/databases/telephony.db"
            ]
            
            for db_path in sms_db_paths:
                full_path = self._find_file(db_path)
                if full_path:
                    messages.extend(self._extract_sms_from_db(full_path))
            
            logger.info(f"SMS extraits: {len(messages)}")
            return messages
            
        except Exception as e:
            logger.error(f"Erreur extraction SMS: {e}")
            return []
    
    def _extract_sms_from_db(self, db_path: str) -> List[SMSMessage]:
        """Extrait les SMS d'une base de données SQLite"""
        messages = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Requête standard pour SMS Android
            query = """
                SELECT _id, thread_id, address, body, date, type, read, service_center
                FROM sms 
                ORDER BY date DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                message = SMSMessage(
                    message_id=row[0],
                    thread_id=row[1],
                    address=row[2] or "Unknown",
                    body=row[3] or "",
                    timestamp=datetime.fromtimestamp(row[4] / 1000, tz=timezone.utc) if row[4] else datetime.now(timezone.utc),
                    message_type="sent" if row[5] == 2 else "received",
                    read_status=bool(row[6]) if row[6] is not None else False,
                    service_center=row[7]
                )
                messages.append(message)
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Erreur extraction SMS DB {db_path}: {e}")
        
        return messages
    
    def extract_call_logs(self) -> List[CallRecord]:
        """Extrait les journaux d'appels"""
        calls = []
        
        try:
            # Base de données des appels Android
            contacts_db = self._find_file("data/data/com.android.providers.contacts/databases/contacts2.db")
            
            if contacts_db:
                calls = self._extract_calls_from_db(contacts_db)
            
            logger.info(f"Appels extraits: {len(calls)}")
            return calls
            
        except Exception as e:
            logger.error(f"Erreur extraction appels: {e}")
            return []
    
    def _extract_calls_from_db(self, db_path: str) -> List[CallRecord]:
        """Extrait les appels d'une base de données"""
        calls = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            query = """
                SELECT _id, number, date, duration, type, name
                FROM calls 
                ORDER BY date DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                call_type_map = {1: "incoming", 2: "outgoing", 3: "missed"}
                
                call = CallRecord(
                    call_id=row[0],
                    phone_number=row[1] or "Unknown",
                    contact_name=row[5],
                    call_type=call_type_map.get(row[4], "unknown"),
                    timestamp=datetime.fromtimestamp(row[2] / 1000, tz=timezone.utc) if row[2] else datetime.now(timezone.utc),
                    duration=row[3] or 0
                )
                calls.append(call)
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Erreur extraction appels DB: {e}")
        
        return calls
    
    def extract_location_data(self) -> List[LocationPoint]:
        """Extrait les données de géolocalisation"""
        locations = []
        
        try:
            # Sources de géolocalisation Android
            location_sources = [
                "data/data/com.google.android.gms/databases/location_history.db",
                "data/data/com.google.android.location/databases/locations.db",
                "data/data/com.android.providers.settings/databases/settings.db"
            ]
            
            for source in location_sources:
                db_path = self._find_file(source)
                if db_path:
                    locations.extend(self._extract_locations_from_db(db_path))
            
            # Extraction des données EXIF des photos
            locations.extend(self._extract_locations_from_media())
            
            logger.info(f"Points de géolocalisation: {len(locations)}")
            return locations
            
        except Exception as e:
            logger.error(f"Erreur extraction géolocalisation: {e}")
            return []
    
    def _extract_locations_from_db(self, db_path: str) -> List[LocationPoint]:
        """Extrait les locations d'une base de données"""
        locations = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Plusieurs formats de tables possibles
            location_queries = [
                "SELECT timestamp, latitude, longitude, accuracy, provider FROM locations",
                "SELECT time, lat, lng, accuracy, source FROM location_data",
                "SELECT date, latitude, longitude, accuracy FROM gps_data"
            ]
            
            for query in location_queries:
                try:
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        if len(row) >= 3 and row[1] and row[2]:
                            location = LocationPoint(
                                timestamp=datetime.fromtimestamp(row[0] / 1000, tz=timezone.utc) if row[0] else datetime.now(timezone.utc),
                                latitude=float(row[1]),
                                longitude=float(row[2]),
                                accuracy=float(row[3]) if len(row) > 3 and row[3] else None,
                                provider=row[4] if len(row) > 4 else None
                            )
                            locations.append(location)
                    break  # Si une requête fonctionne, on s'arrête
                    
                except sqlite3.OperationalError:
                    continue
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Erreur extraction locations DB: {e}")
        
        return locations
    
    def _extract_locations_from_media(self) -> List[LocationPoint]:
        """Extrait la géolocalisation des fichiers média"""
        locations = []
        
        try:
            # Recherche des fichiers image avec EXIF
            media_dirs = [
                "storage/emulated/0/DCIM/Camera",
                "storage/emulated/0/Pictures",
                "data/data/com.android.providers.media/databases/external.db"
            ]
            
            for media_dir in media_dirs:
                full_path = self.image_path / media_dir
                if full_path.exists():
                    if full_path.is_dir():
                        for img_file in full_path.rglob("*.jpg"):
                            location = self._extract_gps_from_exif(img_file)
                            if location:
                                locations.append(location)
                    else:
                        # Base de données média
                        locations.extend(self._extract_locations_from_media_db(full_path))
        
        except Exception as e:
            logger.debug(f"Erreur extraction géolocalisation média: {e}")
        
        return locations
    
    def extract_browser_history(self) -> List[BrowserRecord]:
        """Extrait l'historique de navigation"""
        history = []
        
        try:
            # Navigateurs Android communs
            browser_paths = {
                "Chrome": "data/data/com.android.chrome/app_chrome/Default/History",
                "Firefox": "data/data/org.mozilla.firefox/databases/browser.db",
                "Opera": "data/data/com.opera.browser/databases/history",
                "Samsung Internet": "data/data/com.sec.android.app.sbrowser/databases/browser.db"
            }
            
            for browser_name, db_path in browser_paths.items():
                full_path = self._find_file(db_path)
                if full_path:
                    browser_history = self._extract_browser_history_from_db(full_path, browser_name)
                    history.extend(browser_history)
            
            logger.info(f"Historique navigation: {len(history)} entrées")
            return history
            
        except Exception as e:
            logger.error(f"Erreur extraction historique: {e}")
            return []
    
    def _extract_browser_history_from_db(self, db_path: str, browser_name: str) -> List[BrowserRecord]:
        """Extrait l'historique d'un navigateur"""
        history = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Requêtes pour différents navigateurs
            history_queries = {
                "Chrome": "SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC",
                "Firefox": "SELECT url, title, date, visits FROM moz_places ORDER BY date DESC",
                "default": "SELECT url, title, date, visit_count FROM history ORDER BY date DESC"
            }
            
            query = history_queries.get(browser_name, history_queries["default"])
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                # Conversion timestamp Chrome (microseconds depuis 1601)
                if browser_name == "Chrome" and row[2]:
                    timestamp = datetime.fromtimestamp((row[2] - 11644473600000000) / 1000000, tz=timezone.utc)
                else:
                    timestamp = datetime.fromtimestamp(row[2] / 1000, tz=timezone.utc) if row[2] else datetime.now(timezone.utc)
                
                record = BrowserRecord(
                    url=row[0] or "",
                    title=row[1] or "",
                    timestamp=timestamp,
                    visit_count=row[3] if len(row) > 3 and row[3] else 1,
                    browser=browser_name
                )
                history.append(record)
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Erreur extraction historique {browser_name}: {e}")
        
        return history
    
    def extract_installed_apps(self) -> List[AppData]:
        """Extrait la liste des applications installées"""
        apps = []
        
        try:
            # Base de données des packages Android
            packages_xml = self._find_file("data/system/packages.xml")
            if packages_xml:
                apps = self._parse_packages_xml(packages_xml)
            
            # Analyse des répertoires d'applications
            data_dir = self.image_path / "data/data"
            if data_dir.exists():
                for app_dir in data_dir.iterdir():
                    if app_dir.is_dir():
                        app_data = self._analyze_app_directory(app_dir)
                        if app_data:
                            apps.append(app_data)
            
            logger.info(f"Applications analysées: {len(apps)}")
            return apps
            
        except Exception as e:
            logger.error(f"Erreur extraction applications: {e}")
            return []
    
    def _parse_packages_xml(self, xml_path: str) -> List[AppData]:
        """Parse le fichier packages.xml d'Android"""
        apps = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for package in root.findall('package'):
                name = package.get('name', '')
                code_path = package.get('codePath', '')
                
                if name:
                    app = AppData(
                        package_name=name,
                        app_name=self._get_app_name(name),
                        version=package.get('versionName', ''),
                        install_time=self._parse_android_time(package.get('it', '0'))
                    )
                    
                    # Extraction des permissions
                    for perm in package.findall('.//uses-permission'):
                        perm_name = perm.get('name', '')
                        if perm_name:
                            app.permissions.append(perm_name)
                    
                    apps.append(app)
            
        except Exception as e:
            logger.debug(f"Erreur parse packages.xml: {e}")
        
        return apps
    
    def _find_file(self, relative_path: str) -> Optional[str]:
        """Trouve un fichier dans l'image"""
        full_path = self.image_path / relative_path
        if full_path.exists():
            return str(full_path)
        
        # Recherche récursive si le chemin exact n'existe pas
        filename = Path(relative_path).name
        for found_file in self.image_path.rglob(filename):
            return str(found_file)
        
        return None
    
    def _parse_build_prop(self, build_prop_path: str) -> Dict[str, str]:
        """Parse le fichier build.prop Android"""
        props = {}
        
        try:
            with open(build_prop_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        props[key.strip()] = value.strip()
        
        except Exception as e:
            logger.debug(f"Erreur parse build.prop: {e}")
        
        return props
    
    def _get_app_name(self, package_name: str) -> str:
        """Convertit un nom de package en nom d'app lisible"""
        app_names = {
            'com.android.chrome': 'Chrome',
            'com.whatsapp': 'WhatsApp',
            'com.facebook.katana': 'Facebook',
            'com.instagram.android': 'Instagram',
            'com.twitter.android': 'Twitter',
            'com.google.android.gm': 'Gmail',
            'com.android.vending': 'Play Store',
            'com.android.settings': 'Settings'
        }
        
        return app_names.get(package_name, package_name.split('.')[-1].title())
    
    def _parse_android_time(self, time_str: str) -> Optional[datetime]:
        """Parse un timestamp Android"""
        try:
            timestamp = int(time_str) / 1000  # Android utilise millisecondes
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, TypeError):
            return None
    
    def _extract_gps_from_exif(self, image_path: Path) -> Optional[LocationPoint]:
        """Extrait les coordonnées GPS des métadonnées EXIF"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            with Image.open(image_path) as img:
                exif_data = img._getexif()
                
                if exif_data:
                    gps_data = {}
                    for tag, value in exif_data.items():
                        tag_name = TAGS.get(tag, tag)
                        if tag_name == 'GPSInfo':
                            for gps_tag in value:
                                gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                                gps_data[gps_tag_name] = value[gps_tag]
                    
                    if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                        lat = self._convert_gps_coordinate(gps_data['GPSLatitude'], gps_data.get('GPSLatitudeRef', 'N'))
                        lon = self._convert_gps_coordinate(gps_data['GPSLongitude'], gps_data.get('GPSLongitudeRef', 'E'))
                        
                        return LocationPoint(
                            timestamp=datetime.fromtimestamp(image_path.stat().st_mtime, tz=timezone.utc),
                            latitude=lat,
                            longitude=lon,
                            source_app="Camera"
                        )
        
        except Exception as e:
            logger.debug(f"Erreur extraction GPS EXIF {image_path}: {e}")
        
        return None
    
    def _convert_gps_coordinate(self, coord_data, ref):
        """Convertit les coordonnées GPS EXIF en degrés décimaux"""
        try:
            degrees = float(coord_data[0])
            minutes = float(coord_data[1])
            seconds = float(coord_data[2])
            
            decimal = degrees + minutes/60 + seconds/3600
            
            if ref in ['S', 'W']:
                decimal = -decimal
            
            return decimal
            
        except (IndexError, ValueError, TypeError):
            return 0.0


class IOSAnalyzer:
    """Analyseur spécialisé pour iOS"""
    
    def __init__(self, backup_path: str):
        self.backup_path = Path(backup_path)
        self.device_info = None
        self.manifest = None
        self._load_manifest()
    
    def _load_manifest(self):
        """Charge le manifest du backup iOS"""
        try:
            manifest_path = self.backup_path / "Manifest.plist"
            if manifest_path.exists():
                with open(manifest_path, 'rb') as f:
                    self.manifest = plist.load(f)
            else:
                # Backup plus récent avec Manifest.db
                manifest_db = self.backup_path / "Manifest.db"
                if manifest_db.exists():
                    self._load_manifest_db(manifest_db)
        except Exception as e:
            logger.error(f"Erreur chargement manifest: {e}")
    
    def _load_manifest_db(self, manifest_db_path: Path):
        """Charge le manifest depuis la DB SQLite (iOS 10+)"""
        try:
            conn = sqlite3.connect(manifest_db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT fileID, domain, relativePath FROM Files")
            rows = cursor.fetchall()
            
            self.manifest = {}
            for file_id, domain, relative_path in rows:
                self.manifest[file_id] = {
                    'domain': domain,
                    'path': relative_path
                }
            
            conn.close()
        except Exception as e:
            logger.error(f"Erreur chargement manifest DB: {e}")
    
    def analyze_device_info(self) -> DeviceInfo:
        """Extrait les informations du dispositif iOS"""
        try:
            info_plist = self.backup_path / "Info.plist"
            device_info = DeviceInfo(
                device_type=DeviceType.IOS,
                model="Unknown",
                os_version="Unknown"
            )
            
            if info_plist.exists():
                with open(info_plist, 'rb') as f:
                    info_data = plist.load(f)
                
                device_info.model = info_data.get('Product Name', 'Unknown')
                device_info.os_version = info_data.get('Product Version', 'Unknown')
                device_info.serial_number = info_data.get('Serial Number')
                device_info.phone_number = info_data.get('Phone Number')
                device_info.last_backup_date = info_data.get('Last Backup Date')
            
            self.device_info = device_info
            return device_info
            
        except Exception as e:
            logger.error(f"Erreur analyse info dispositif iOS: {e}")
            return DeviceInfo(device_type=DeviceType.IOS, model="Unknown", os_version="Unknown")
    
    def extract_sms_messages(self) -> List[SMSMessage]:
        """Extrait les messages SMS iOS"""
        messages = []
        
        try:
            # Base de données SMS iOS
            sms_db = self._find_backup_file("HomeDomain", "Library/SMS/sms.db")
            if sms_db:
                messages = self._extract_ios_sms_from_db(sms_db)
            
            logger.info(f"SMS iOS extraits: {len(messages)}")
            return messages
            
        except Exception as e:
            logger.error(f"Erreur extraction SMS iOS: {e}")
            return []
    
    def _extract_ios_sms_from_db(self, db_path: str) -> List[SMSMessage]:
        """Extrait les SMS de la DB iOS"""
        messages = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Structure iOS SMS database
            query = """
                SELECT 
                    m.ROWID, m.guid, m.text, m.handle_id, m.service, 
                    m.date, m.date_read, m.is_from_me, h.id as phone_number
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                ORDER BY m.date DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                # iOS utilise un epoch différent (1er janvier 2001)
                ios_epoch_offset = 978307200  # Secondes entre 1970 and 2001
                timestamp = datetime.fromtimestamp(row[5] + ios_epoch_offset, tz=timezone.utc) if row[5] else datetime.now(timezone.utc)
                
                message = SMSMessage(
                    message_id=row[0],
                    thread_id=row[3] or 0,
                    address=row[8] or "Unknown",
                    body=row[2] or "",
                    timestamp=timestamp,
                    message_type="sent" if row[7] else "received",
                    read_status=bool(row[6]),
                    service_center=row[4]
                )
                messages.append(message)
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Erreur extraction SMS iOS: {e}")
        
        return messages
    
    def extract_call_logs(self) -> List[CallRecord]:
        """Extrait les journaux d'appels iOS"""
        calls = []
        
        try:
            call_db = self._find_backup_file("WirelessDomain", "Library/CallHistoryDB/CallHistory.storedata")
            if call_db:
                calls = self._extract_ios_calls_from_db(call_db)
            
            logger.info(f"Appels iOS extraits: {len(calls)}")
            return calls
            
        except Exception as e:
            logger.error(f"Erreur extraction appels iOS: {e}")
            return []
    
    def extract_location_data(self) -> List[LocationPoint]:
        """Extrait les données de géolocalisation iOS"""
        locations = []
        
        try:
            # Plusieurs sources de géolocalisation iOS
            location_sources = [
                ("RootDomain", "Library/Caches/locationd/consolidated.db"),
                ("HomeDomain", "Library/Caches/com.apple.routined/Cache.sqlite"),
                ("RootDomain", "Library/LocationHistory/location.db")
            ]
            
            for domain, path in location_sources:
                db_path = self._find_backup_file(domain, path)
                if db_path:
                    locations.extend(self._extract_ios_locations_from_db(db_path))
            
            logger.info(f"Points géolocalisation iOS: {len(locations)}")
            return locations
            
        except Exception as e:
            logger.error(f"Erreur extraction géolocalisation iOS: {e}")
            return []
    
    def _find_backup_file(self, domain: str, relative_path: str) -> Optional[str]:
        """Trouve un fichier dans le backup iOS"""
        if not self.manifest:
            return None
        
        # Recherche dans le manifest
        for file_id, file_info in self.manifest.items():
            if (file_info.get('domain') == domain and 
                file_info.get('path') == relative_path):
                
                backup_file_path = self.backup_path / file_id
                if backup_file_path.exists():
                    return str(backup_file_path)
        
        return None


class MobileAnalyzer:
    """
    Analyseur mobile forensique principal
    """
    
    def __init__(self, evidence_dir: str = "./evidence", temp_dir: str = "./temp"):
        """
        Initialise l'analyseur mobile
        
        Args:
            evidence_dir: Répertoire pour stocker les preuves
            temp_dir: Répertoire temporaire pour les analyses
        """
        self.evidence_dir = Path(evidence_dir)
        self.temp_dir = Path(temp_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.case_id = None
        self.device_analyzer = None
        self.device_info = None
        
        # Base de données SQLite pour stocker les résultats
        self.db_path = self.evidence_dir / "mobile_analysis.db"
        self._init_database()
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des analyses mobiles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mobile_analysis (
                case_id TEXT PRIMARY KEY,
                device_path TEXT NOT NULL,
                device_type TEXT,
                device_model TEXT,
                os_version TEXT,
                extraction_method TEXT,
                analysis_start TIMESTAMP,
                analysis_end TIMESTAMP,
                investigator TEXT
            )
        ''')
        
        # Table des messages SMS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                message_id INTEGER,
                thread_id INTEGER,
                address TEXT,
                body TEXT,
                timestamp TIMESTAMP,
                message_type TEXT,
                read_status BOOLEAN,
                service_center TEXT,
                deleted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table des appels
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS call_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                call_id INTEGER,
                phone_number TEXT,
                contact_name TEXT,
                call_type TEXT,
                timestamp TIMESTAMP,
                duration INTEGER,
                deleted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table des contacts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                contact_id INTEGER,
                display_name TEXT,
                phone_numbers TEXT,
                email_addresses TEXT,
                organization TEXT,
                notes TEXT,
                created_time TIMESTAMP,
                modified_time TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table des points de géolocalisation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS location_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                latitude REAL,
                longitude REAL,
                accuracy REAL,
                altitude REAL,
                speed REAL,
                provider TEXT,
                source_app TEXT,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table de l'historique de navigation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS browser_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                url TEXT,
                title TEXT,
                timestamp TIMESTAMP,
                visit_count INTEGER,
                browser TEXT,
                deleted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table des applications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS installed_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                package_name TEXT,
                app_name TEXT,
                version TEXT,
                install_time TIMESTAMP,
                last_used TIMESTAMP,
                data_size INTEGER,
                permissions TEXT,
                suspicious BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        # Table des fichiers média
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS media_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                file_path TEXT,
                file_type TEXT,
                file_size INTEGER,
                created_time TIMESTAMP,
                modified_time TIMESTAMP,
                gps_latitude REAL,
                gps_longitude REAL,
                camera_make TEXT,
                camera_model TEXT,
                deleted BOOLEAN DEFAULT FALSE,
                hash_md5 TEXT,
                FOREIGN KEY (case_id) REFERENCES mobile_analysis (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def open_device(self, device_path: str, case_id: str, device_type: DeviceType = None, 
                   extraction_method: ExtractionMethod = ExtractionMethod.LOGICAL) -> bool:
        """
        Ouvre un dispositif mobile pour analyse
        
        Args:
            device_path: Chemin vers l'image/backup du dispositif
            case_id: Identifiant du cas
            device_type: Type de dispositif (auto-détecté si None)
            extraction_method: Méthode d'extraction utilisée
            
        Returns:
            True si succès, False sinon
        """
        try:
            device_path_obj = Path(device_path)
            
            if not device_path_obj.exists():
                logger.error(f"Le chemin dispositif {device_path_obj} n'existe pas")
                return False
            
            self.case_id = case_id
            
            # Auto-détection du type de dispositif
            if device_type is None:
                device_type = self._detect_device_type(device_path_obj)
            
            # Initialisation de l'analyseur spécialisé
            if device_type == DeviceType.ANDROID:
                self.device_analyzer = AndroidAnalyzer(device_path)
            elif device_type == DeviceType.IOS:
                self.device_analyzer = IOSAnalyzer(device_path)
            else:
                logger.error(f"Type de dispositif non supporté: {device_type}")
                return False
            
            # Analyse des informations du dispositif
            self.device_info = self.device_analyzer.analyze_device_info()
            
            # Sauvegarde des informations d'analyse
            self._save_analysis_info(
                case_id=case_id,
                device_path=str(device_path_obj),
                device_type=device_type.value,
                device_model=self.device_info.model,
                os_version=self.device_info.os_version,
                extraction_method=extraction_method.value
            )
            
            logger.info(f"Dispositif mobile ouvert avec succès")
            logger.info(f"Type: {device_type.value}")
            logger.info(f"Modèle: {self.device_info.model}")
            logger.info(f"OS: {self.device_info.os_version}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ouverture du dispositif: {e}")
            return False
    
    def _detect_device_type(self, device_path: Path) -> DeviceType:
        """Détecte automatiquement le type de dispositif"""
        try:
            # Recherche de fichiers caractéristiques Android
            android_indicators = [
                "build.prop",
                "data/system/packages.xml",
                "system/build.prop"
            ]
            
            # Recherche de fichiers caractéristiques iOS
            ios_indicators = [
                "Info.plist",
                "Manifest.plist",
                "Manifest.db"
            ]
            
            # Test Android
            for indicator in android_indicators:
                if (device_path / indicator).exists():
                    return DeviceType.ANDROID
                
                # Recherche récursive
                if list(device_path.rglob(indicator)):
                    return DeviceType.ANDROID
            
            # Test iOS
            for indicator in ios_indicators:
                if (device_path / indicator).exists():
                    return DeviceType.IOS
                
                # Recherche récursive
                if list(device_path.rglob(indicator)):
                    return DeviceType.IOS
            
            return DeviceType.UNKNOWN
            
        except Exception as e:
            logger.error(f"Erreur détection type dispositif: {e}")
            return DeviceType.UNKNOWN
    
    def extract_all_artifacts(self) -> Dict[str, int]:
        """
        Extrait tous les artefacts du dispositif
        
        Returns:
            Dictionnaire avec le nombre d'artefacts extraits par type
        """
        if not self.device_analyzer:
            logger.error("Aucun dispositif ouvert")
            return {}
        
        results = {}
        
        try:
            # Extraction des messages SMS
            logger.info("Extraction des messages SMS...")
            sms_messages = self.device_analyzer.extract_sms_messages()
            self._save_sms_to_db(sms_messages)
            results['sms_messages'] = len(sms_messages)
            
            # Extraction des journaux d'appels
            logger.info("Extraction des journaux d'appels...")
            call_records = self.device_analyzer.extract_call_logs()
            self._save_calls_to_db(call_records)
            results['call_records'] = len(call_records)
            
            # Extraction des données de géolocalisation
            logger.info("Extraction des données de géolocalisation...")
            location_points = self.device_analyzer.extract_location_data()
            self._save_locations_to_db(location_points)
            results['location_points'] = len(location_points)
            
            # Extraction de l'historique de navigation
            logger.info("Extraction de l'historique de navigation...")
            browser_history = self.device_analyzer.extract_browser_history()
            self._save_browser_history_to_db(browser_history)
            results['browser_history'] = len(browser_history)
            
            # Extraction des applications installées
            logger.info("Extraction des applications installées...")
            installed_apps = self.device_analyzer.extract_installed_apps()
            self._save_apps_to_db(installed_apps)
            results['installed_apps'] = len(installed_apps)
            
            logger.info("Extraction complète terminée")
            for artifact_type, count in results.items():
                logger.info(f"  {artifact_type}: {count}")
            
            return results
            
        except Exception as e:
            logger.error(f"Erreur extraction artefacts: {e}")
            return results
    
    def generate_timeline(self) -> List[Dict[str, Any]]:
        """
        Génère une timeline complète des activités mobile
        
        Returns:
            Liste des événements triés par timestamp
        """
        timeline_events = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Requête pour tous les événements temporels
            queries = [
                ("SMS", """
                    SELECT timestamp, 'SMS' as event_type, 
                           'Message ' || message_type || ' - ' || address as description,
                           body as details
                    FROM sms_messages WHERE case_id = ?
                """),
                ("Call", """
                    SELECT timestamp, 'Call' as event_type,
                           call_type || ' call - ' || phone_number as description,
                           CAST(duration AS TEXT) || ' seconds' as details
                    FROM call_records WHERE case_id = ?
                """),
                ("Location", """
                    SELECT timestamp, 'Location' as event_type,
                           'GPS: ' || CAST(latitude AS TEXT) || ',' || CAST(longitude AS TEXT) as description,
                           provider || ' - ' || COALESCE(source_app, 'Unknown') as details
                    FROM location_points WHERE case_id = ?
                """),
                ("Browser", """
                    SELECT timestamp, 'Web Navigation' as event_type,
                           title as description, url as details
                    FROM browser_history WHERE case_id = ?
                """)
            ]
            
            for source, query in queries:
                cursor.execute(query, (self.case_id,))
                rows = cursor.fetchall()
                
                for row in rows:
                    timeline_events.append({
                        'timestamp': row[0],
                        'event_type': row[1],
                        'description': row[2],
                        'details': row[3],
                        'source': source
                    })
            
            conn.close()
            
            # Tri par timestamp
            timeline_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')
            
            logger.info(f"Timeline générée: {len(timeline_events)} événements")
            return timeline_events
            
        except Exception as e:
            logger.error(f"Erreur génération timeline: {e}")
            return []
    
    def _save_analysis_info(self, case_id: str, device_path: str, device_type: str,
                          device_model: str, os_version: str, extraction_method: str):
        """Sauvegarde les informations d'analyse en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO mobile_analysis 
            (case_id, device_path, device_type, device_model, os_version, extraction_method, analysis_start)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (case_id, device_path, device_type, device_model, os_version, extraction_method, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def _save_sms_to_db(self, messages: List[SMSMessage]):
        """Sauvegarde les SMS en base"""
        if not messages:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for message in messages:
            cursor.execute('''
                INSERT INTO sms_messages 
                (case_id, message_id, thread_id, address, body, timestamp, message_type, 
                 read_status, service_center, deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, message.message_id, message.thread_id, message.address,
                message.body, message.timestamp, message.message_type,
                message.read_status, message.service_center, message.deleted
            ))
        
        conn.commit()
        conn.close()
    
    def _save_calls_to_db(self, calls: List[CallRecord]):
        """Sauvegarde les appels en base"""
        if not calls:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for call in calls:
            cursor.execute('''
                INSERT INTO call_records 
                (case_id, call_id, phone_number, contact_name, call_type, timestamp, duration, deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, call.call_id, call.phone_number, call.contact_name,
                call.call_type, call.timestamp, call.duration, call.deleted
            ))
        
        conn.commit()
        conn.close()
    
    def _save_locations_to_db(self, locations: List[LocationPoint]):
        """Sauvegarde les points de géolocalisation en base"""
        if not locations:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for location in locations:
            cursor.execute('''
                INSERT INTO location_points 
                (case_id, timestamp, latitude, longitude, accuracy, altitude, speed, provider, source_app)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, location.timestamp, location.latitude, location.longitude,
                location.accuracy, location.altitude, location.speed, location.provider, location.source_app
            ))
        
        conn.commit()
        conn.close()
    
    def _save_browser_history_to_db(self, history: List[BrowserRecord]):
        """Sauvegarde l'historique de navigation en base"""
        if not history:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for record in history:
            cursor.execute('''
                INSERT INTO browser_history 
                (case_id, url, title, timestamp, visit_count, browser, deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, record.url, record.title, record.timestamp,
                record.visit_count, record.browser, record.deleted
            ))
        
        conn.commit()
        conn.close()
    
    def _save_apps_to_db(self, apps: List[AppData]):
        """Sauvegarde les applications en base"""
        if not apps:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for app in apps:
            cursor.execute('''
                INSERT INTO installed_apps 
                (case_id, package_name, app_name, version, install_time, last_used, 
                 data_size, permissions, suspicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, app.package_name, app.app_name, app.version,
                app.install_time, app.last_used, app.data_size,
                json.dumps(app.permissions), app.suspicious
            ))
        
        conn.commit()
        conn.close()
    
    def export_results(self, output_file: str, format_type: str = 'json') -> bool:
        """
        Export des résultats d'analyse mobile
        
        Args:
            output_file: Fichier de sortie
            format_type: Format (json, csv, xml)
            
        Returns:
            True si succès
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            if format_type.lower() == 'json':
                # Export JSON complet
                data = {
                    'device_info': self.device_info.__dict__ if self.device_info else {},
                    'analysis_info': self._get_analysis_info_from_db(conn),
                    'sms_messages': self._get_sms_from_db(conn),
                    'call_records': self._get_calls_from_db(conn),
                    'location_points': self._get_locations_from_db(conn),
                    'browser_history': self._get_browser_history_from_db(conn),
                    'installed_apps': self._get_apps_from_db(conn)
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                # Export CSV de la timeline
                import csv
                timeline = self.generate_timeline()
                
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    if timeline:
                        writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
                        writer.writeheader()
                        writer.writerows(timeline)
            
            conn.close()
            logger.info(f"Résultats exportés vers {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export: {e}")
            return False
    
    def _get_analysis_info_from_db(self, conn) -> Dict:
        """Récupère les informations d'analyse depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM mobile_analysis WHERE case_id = ?', (self.case_id,))
        row = cursor.fetchone()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return {}
    
    def _get_sms_from_db(self, conn) -> List[Dict]:
        """Récupère les SMS depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sms_messages WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_calls_from_db(self, conn) -> List[Dict]:
        """Récupère les appels depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM call_records WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_locations_from_db(self, conn) -> List[Dict]:
        """Récupère les locations depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM location_points WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_browser_history_from_db(self, conn) -> List[Dict]:
        """Récupère l'historique navigation depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM browser_history WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_apps_from_db(self, conn) -> List[Dict]:
        """Récupère les applications depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM installed_apps WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def close(self):
        """Ferme l'analyseur et nettoie les ressources"""
        self.device_analyzer = None
        self.device_info = None
        self.case_id = None
        logger.info("Analyseur mobile fermé")


def main():
    """Fonction de démonstration"""
    print("📱 Forensic Analysis Toolkit - Mobile Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = MobileAnalyzer(evidence_dir="./evidence", temp_dir="./temp")
    
    # Simulation avec un backup de test (remplacer par un vrai backup)
    test_backup = "./test_mobile/android_backup"
    case_id = f"MOBILE_CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Cas d'analyse: {case_id}")
    
    # Si le backup de test existe
    if Path(test_backup).exists():
        print(f"📱 Ouverture du backup mobile: {test_backup}")
        
        if analyzer.open_device(test_backup, case_id):
            # Extraction de tous les artefacts
            print("🔍 Extraction des artefacts mobiles...")
            results = analyzer.extract_all_artifacts()
            
            print("📊 Résultats de l'extraction:")
            for artifact_type, count in results.items():
                print(f"  📄 {artifact_type.replace('_', ' ').title()}: {count}")
            
            # Génération de la timeline
            print("🕒 Génération de la timeline...")
            timeline = analyzer.generate_timeline()
            print(f"📅 Timeline générée: {len(timeline)} événements")
            
            # Export des résultats
            output_file = f"./mobile_analysis_{case_id}.json"
            if analyzer.export_results(output_file, 'json'):
                print(f"📄 Résultats exportés: {output_file}")
            
        analyzer.close()
    else:
        print("⚠️  Aucun backup mobile de test trouvé")
        print(f"   Créez un répertoire {test_backup} ou modifiez le chemin")
        print("   Exemple: Backup iTunes, image Android ADB")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()