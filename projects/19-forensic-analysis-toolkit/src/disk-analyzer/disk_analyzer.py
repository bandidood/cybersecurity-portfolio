#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Disk Analyzer - Forensic Analysis Toolkit
============================================================================
Analyseur de disques forensique utilisant The Sleuth Kit (TSK) pour :
- Acquisition d'images de disques (DD, E01, AFF)
- Analyse de systèmes de fichiers (NTFS, EXT4, FAT32, HFS+, APFS)
- Récupération de fichiers supprimés avec carving
- Extraction de métadonnées et timeline forensique
- Détection d'anti-forensics et signatures de malware

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import hashlib
import logging
import subprocess
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import pytsk3
import pyewf
import mmap
import magic
import yara
from PIL import Image
from PIL.ExifTags import TAGS
import struct

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FileSystemType(Enum):
    """Types de systèmes de fichiers supportés"""
    NTFS = "NTFS"
    EXT2 = "EXT2"
    EXT3 = "EXT3" 
    EXT4 = "EXT4"
    FAT12 = "FAT12"
    FAT16 = "FAT16"
    FAT32 = "FAT32"
    HFS_PLUS = "HFS+"
    APFS = "APFS"
    XFS = "XFS"
    BTRFS = "BTRFS"
    UNKNOWN = "UNKNOWN"


class ImageFormat(Enum):
    """Formats d'images forensiques supportés"""
    RAW = "raw"
    DD = "dd"
    E01 = "e01"
    EWF = "ewf"
    AFF = "aff"
    VMDK = "vmdk"
    VDI = "vdi"


@dataclass
class FileSystemInfo:
    """Informations sur un système de fichiers"""
    fs_type: FileSystemType
    block_size: int
    block_count: int
    inode_count: Optional[int] = None
    free_blocks: Optional[int] = None
    free_inodes: Optional[int] = None
    volume_label: Optional[str] = None
    created_time: Optional[datetime] = None
    mounted_time: Optional[datetime] = None
    journal_size: Optional[int] = None


@dataclass
class ForensicFile:
    """Représentation d'un fichier forensique"""
    inode: int
    name: str
    path: str
    size: int
    allocated: bool
    deleted: bool
    file_type: str
    mime_type: Optional[str] = None
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    accessed_time: Optional[datetime] = None
    changed_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    carved: bool = False
    signature_match: Optional[str] = None


@dataclass
class TimelineEvent:
    """Événement dans la timeline forensique"""
    timestamp: datetime
    event_type: str  # MACB (Modified, Accessed, Created, Birth)
    source: str
    description: str
    inode: Optional[int] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CarvedFile:
    """Fichier récupéré par carving"""
    offset: int
    size: int
    file_type: str
    signature: str
    confidence: float
    recovered_path: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


class SignatureDatabase:
    """Base de données des signatures de fichiers pour carving"""
    
    def __init__(self):
        """Initialise la base de signatures"""
        self.signatures = {
            # Images
            'JPEG': [(b'\xFF\xD8\xFF', 0, b'\xFF\xD9', -2)],
            'PNG': [(b'\x89PNG\r\n\x1a\n', 0, b'IEND\xaeB`\x82', -8)],
            'GIF': [(b'GIF87a', 0, b'\x00\x3B', -2), (b'GIF89a', 0, b'\x00\x3B', -2)],
            'BMP': [(b'BM', 0, None, None)],
            'TIFF': [(b'II*\x00', 0, None, None), (b'MM\x00*', 0, None, None)],
            
            # Documents
            'PDF': [(b'%PDF-', 0, b'%%EOF', -5)],
            'DOC': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, None, None)],
            'DOCX': [(b'PK\x03\x04', 0, None, None)],  # ZIP-based
            'RTF': [(b'{\\rtf1', 0, b'}', -1)],
            
            # Archives
            'ZIP': [(b'PK\x03\x04', 0, None, None), (b'PK\x05\x06', 0, None, None)],
            'RAR': [(b'Rar!\x1a\x07\x00', 0, None, None)],
            'GZIP': [(b'\x1f\x8b\x08', 0, None, None)],
            '7ZIP': [(b'7z\xbc\xaf\x27\x1c', 0, None, None)],
            
            # Exécutables
            'PE': [(b'MZ', 0, None, None)],  # Windows PE
            'ELF': [(b'\x7fELF', 0, None, None)],  # Linux ELF
            'MACHO': [(b'\xfe\xed\xfa\xce', 0, None, None)],  # macOS Mach-O
            
            # Multimédia
            'AVI': [(b'RIFF', 0, None, None)],
            'MP4': [(b'ftypmp4', 4, None, None)],
            'MP3': [(b'ID3', 0, None, None), (b'\xff\xfb', 0, None, None)],
            'WAV': [(b'RIFF', 0, b'WAVE', 8)],
            
            # Bases de données
            'SQLITE': [(b'SQLite format 3\x00', 0, None, None)],
            'MDB': [(b'\x00\x01\x00\x00Standard Jet DB', 0, None, None)],
            
            # Cryptographie
            'PGP_PRIVATE': [(b'-----BEGIN PGP PRIVATE KEY BLOCK-----', 0, None, None)],
            'PGP_PUBLIC': [(b'-----BEGIN PGP PUBLIC KEY BLOCK-----', 0, None, None)],
            'SSH_PRIVATE': [(b'-----BEGIN OPENSSH PRIVATE KEY-----', 0, None, None)],
            'X509_CERT': [(b'-----BEGIN CERTIFICATE-----', 0, None, None)],
        }
    
    def detect_signature(self, data: bytes, offset: int = 0) -> Optional[Tuple[str, float]]:
        """
        Détecte le type de fichier basé sur la signature
        
        Args:
            data: Données à analyser
            offset: Offset dans les données
            
        Returns:
            Tuple (type_fichier, confidence) ou None
        """
        for file_type, signatures in self.signatures.items():
            for header, header_offset, footer, footer_offset in signatures:
                if offset + len(header) <= len(data):
                    if data[offset:offset + len(header)] == header:
                        confidence = 0.8
                        
                        # Vérification du footer si présent
                        if footer:
                            footer_pos = footer_offset if footer_offset is not None else len(data) + footer_offset
                            if footer_pos >= 0 and footer_pos + len(footer) <= len(data):
                                if data[footer_pos:footer_pos + len(footer)] == footer:
                                    confidence = 0.95
                                else:
                                    confidence = 0.6
                        
                        return (file_type, confidence)
        
        return None


class DiskAnalyzer:
    """
    Analyseur de disques forensique principal
    """
    
    def __init__(self, evidence_dir: str = "./evidence", temp_dir: str = "./temp"):
        """
        Initialise l'analyseur de disques
        
        Args:
            evidence_dir: Répertoire pour stocker les preuves
            temp_dir: Répertoire temporaire pour les analyses
        """
        self.evidence_dir = Path(evidence_dir)
        self.temp_dir = Path(temp_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.signature_db = SignatureDatabase()
        self.image_handle = None
        self.filesystem = None
        self.case_id = None
        self.timeline_events: List[TimelineEvent] = []
        self.carved_files: List[CarvedFile] = []
        
        # Base de données SQLite pour stocker les résultats
        self.db_path = self.evidence_dir / "forensic_analysis.db"
        self._init_database()
        
        # Initialisation YARA pour détection malware
        self.yara_rules = self._load_yara_rules()
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des cas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                image_path TEXT NOT NULL,
                image_format TEXT,
                image_size INTEGER,
                image_md5 TEXT,
                image_sha256 TEXT,
                analysis_start TIMESTAMP,
                analysis_end TIMESTAMP,
                filesystem_info TEXT,
                notes TEXT,
                investigator TEXT
            )
        ''')
        
        # Table des fichiers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                inode INTEGER,
                name TEXT,
                path TEXT,
                size INTEGER,
                allocated BOOLEAN,
                deleted BOOLEAN,
                file_type TEXT,
                mime_type TEXT,
                md5_hash TEXT,
                sha256_hash TEXT,
                created_time TIMESTAMP,
                modified_time TIMESTAMP,
                accessed_time TIMESTAMP,
                changed_time TIMESTAMP,
                metadata TEXT,
                carved BOOLEAN DEFAULT FALSE,
                signature_match TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')
        
        # Table des événements timeline
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TIMESTAMP,
                event_type TEXT,
                source TEXT,
                description TEXT,
                inode INTEGER,
                file_path TEXT,
                file_size INTEGER,
                metadata TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')
        
        # Table des fichiers récupérés par carving
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS carved_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                offset INTEGER,
                size INTEGER,
                file_type TEXT,
                signature TEXT,
                confidence REAL,
                recovered_path TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Charge les règles YARA pour détection de malware"""
        try:
            # Règles YARA basiques pour démonstration
            yara_source = '''
            rule Suspicious_PE_Characteristics
            {
                meta:
                    description = "Détecte des caractéristiques suspectes dans les PE"
                    author = "Forensic Analysis Toolkit"
                    
                strings:
                    $mz = { 4D 5A }
                    $pe = "PE"
                    $debug_string = "This program cannot be run in DOS mode" wide ascii
                    
                condition:
                    $mz at 0 and $pe and not $debug_string
            }
            
            rule Potential_Keylogger
            {
                meta:
                    description = "Détecte des patterns de keylogger"
                    
                strings:
                    $s1 = "GetAsyncKeyState" ascii
                    $s2 = "SetWindowsHookEx" ascii
                    $s3 = "keybd_event" ascii
                    $s4 = "GetForegroundWindow" ascii
                    
                condition:
                    2 of them
            }
            
            rule Cryptocurrency_Wallet
            {
                meta:
                    description = "Détecte des fichiers de portefeuille crypto"
                    
                strings:
                    $btc1 = "wallet.dat" ascii
                    $btc2 = "bitcoin" ascii nocase
                    $eth1 = "keystore" ascii
                    $eth2 = "ethereum" ascii nocase
                    
                condition:
                    any of them
            }
            '''
            
            return yara.compile(source=yara_source)
            
        except Exception as e:
            logger.warning(f"Impossible de charger les règles YARA: {e}")
            return None
    
    def open_image(self, image_path: str, case_id: str, image_format: ImageFormat = None) -> bool:
        """
        Ouvre une image forensique pour analyse
        
        Args:
            image_path: Chemin vers l'image
            case_id: Identifiant du cas
            image_format: Format de l'image (détecté automatiquement si None)
            
        Returns:
            True si succès, False sinon
        """
        try:
            self.case_id = case_id
            image_path = Path(image_path)
            
            if not image_path.exists():
                logger.error(f"L'image {image_path} n'existe pas")
                return False
            
            # Détection automatique du format si non spécifié
            if image_format is None:
                image_format = self._detect_image_format(image_path)
            
            # Ouverture selon le format
            if image_format == ImageFormat.E01 or image_format == ImageFormat.EWF:
                # Image Expert Witness Format
                ewf_handle = pyewf.handle()
                ewf_handle.open([str(image_path)])
                self.image_handle = ewf_handle
                
            else:
                # Image RAW/DD
                self.image_handle = open(image_path, 'rb')
            
            # Calcul des hashs de l'image
            image_size = image_path.stat().st_size
            md5_hash, sha256_hash = self._calculate_image_hashes(image_path)
            
            # Sauvegarde des informations du cas
            self._save_case_info(
                case_id=case_id,
                image_path=str(image_path),
                image_format=image_format.value,
                image_size=image_size,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash
            )
            
            logger.info(f"Image {image_path} ouverte avec succès")
            logger.info(f"Format: {image_format.value}, Taille: {image_size:,} bytes")
            logger.info(f"MD5: {md5_hash}")
            logger.info(f"SHA256: {sha256_hash}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ouverture de l'image: {e}")
            return False
    
    def _detect_image_format(self, image_path: Path) -> ImageFormat:
        """Détecte automatiquement le format de l'image"""
        try:
            with open(image_path, 'rb') as f:
                header = f.read(16)
                
            # Vérification des signatures
            if header.startswith(b'EVF'):
                return ImageFormat.E01
            elif header.startswith(b'FVF'):
                return ImageFormat.EWF
            elif image_path.suffix.lower() in ['.e01', '.ex01']:
                return ImageFormat.E01
            elif image_path.suffix.lower() in ['.dd', '.img', '.raw']:
                return ImageFormat.DD
            else:
                return ImageFormat.RAW
                
        except Exception:
            return ImageFormat.RAW
    
    def _calculate_image_hashes(self, image_path: Path) -> Tuple[str, str]:
        """Calcule les hashs MD5 et SHA-256 de l'image"""
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        
        try:
            with open(image_path, 'rb') as f:
                # Lecture par blocs pour les gros fichiers
                while chunk := f.read(8192):
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)
            
            return md5_hasher.hexdigest(), sha256_hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Erreur calcul hashs: {e}")
            return "", ""
    
    def analyze_filesystem(self) -> Optional[FileSystemInfo]:
        """
        Analyse le système de fichiers de l'image
        
        Returns:
            Informations sur le système de fichiers
        """
        if not self.image_handle:
            logger.error("Aucune image ouverte")
            return None
        
        try:
            # Création de l'objet TSK image
            if hasattr(self.image_handle, 'get_size'):
                # Image EWF
                img_info = pytsk3.EWF_Img_Info(self.image_handle)
            else:
                # Image RAW
                img_info = pytsk3.Img_Info(str(self.image_handle.name))
            
            # Analyse de la table des partitions
            try:
                volume_info = pytsk3.Volume_Info(img_info)
                logger.info(f"Table des partitions détectée: {volume_info.info.vstype}")
                
                # Analyse de chaque partition
                for partition in volume_info:
                    if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        logger.info(f"Partition {partition.addr}: offset={partition.start}, taille={partition.len} secteurs")
                        
                        # Analyse du système de fichiers de cette partition
                        fs_info = self._analyze_partition_filesystem(img_info, partition.start)
                        if fs_info:
                            self.filesystem = pytsk3.FS_Info(img_info, offset=(partition.start * img_info.block_size))
                            return fs_info
                        
            except Exception as e:
                logger.info("Pas de table de partitions, analyse directe du système de fichiers")
                # Tentative d'analyse directe sans partition
                self.filesystem = pytsk3.FS_Info(img_info)
                return self._get_filesystem_info(self.filesystem)
            
        except Exception as e:
            logger.error(f"Erreur analyse système de fichiers: {e}")
            return None
    
    def _analyze_partition_filesystem(self, img_info, partition_start: int) -> Optional[FileSystemInfo]:
        """Analyse le système de fichiers d'une partition spécifique"""
        try:
            offset = partition_start * img_info.block_size
            filesystem = pytsk3.FS_Info(img_info, offset=offset)
            return self._get_filesystem_info(filesystem)
            
        except Exception as e:
            logger.debug(f"Impossible d'analyser la partition à l'offset {partition_start}: {e}")
            return None
    
    def _get_filesystem_info(self, filesystem) -> FileSystemInfo:
        """Extrait les informations détaillées du système de fichiers"""
        fs_type_map = {
            pytsk3.TSK_FS_TYPE_NTFS: FileSystemType.NTFS,
            pytsk3.TSK_FS_TYPE_EXT2: FileSystemType.EXT2,
            pytsk3.TSK_FS_TYPE_EXT3: FileSystemType.EXT3,
            pytsk3.TSK_FS_TYPE_EXT4: FileSystemType.EXT4,
            pytsk3.TSK_FS_TYPE_FAT12: FileSystemType.FAT12,
            pytsk3.TSK_FS_TYPE_FAT16: FileSystemType.FAT16,
            pytsk3.TSK_FS_TYPE_FAT32: FileSystemType.FAT32,
            pytsk3.TSK_FS_TYPE_HFS: FileSystemType.HFS_PLUS,
        }
        
        fs_type = fs_type_map.get(filesystem.info.ftype, FileSystemType.UNKNOWN)
        
        info = FileSystemInfo(
            fs_type=fs_type,
            block_size=filesystem.info.block_size,
            block_count=filesystem.info.block_count,
            inode_count=getattr(filesystem.info, 'inum_count', None),
            free_blocks=getattr(filesystem.info, 'block_free', None),
            free_inodes=getattr(filesystem.info, 'inum_free', None)
        )
        
        logger.info(f"Système de fichiers: {fs_type.value}")
        logger.info(f"Taille de bloc: {info.block_size} bytes")
        logger.info(f"Nombre de blocs: {info.block_count:,}")
        
        if info.inode_count:
            logger.info(f"Nombre d'inodes: {info.inode_count:,}")
        
        return info
    
    def list_files(self, path: str = "/", recursive: bool = True, include_deleted: bool = True) -> List[ForensicFile]:
        """
        Liste les fichiers dans le système de fichiers
        
        Args:
            path: Chemin à analyser
            recursive: Analyse récursive des sous-répertoires
            include_deleted: Inclure les fichiers supprimés
            
        Returns:
            Liste des fichiers forensiques
        """
        if not self.filesystem:
            logger.error("Système de fichiers non analysé")
            return []
        
        files = []
        
        try:
            # Obtention du répertoire
            directory = self.filesystem.open_dir(path)
            
            for file_entry in directory:
                # Filtrage des entrées système
                if file_entry.info.name.name in [b".", b".."]:
                    continue
                
                # Vérification si le fichier est alloué/supprimé
                is_allocated = file_entry.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_ALLOC
                is_deleted = file_entry.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC
                
                if not include_deleted and is_deleted:
                    continue
                
                try:
                    # Obtention des métadonnées du fichier
                    metadata = file_entry.info.meta
                    if metadata is None:
                        continue
                    
                    file_name = file_entry.info.name.name.decode('utf-8', errors='replace')
                    file_path = f"{path.rstrip('/')}/{file_name}" if path != "/" else f"/{file_name}"
                    
                    # Création de l'objet ForensicFile
                    forensic_file = ForensicFile(
                        inode=metadata.addr,
                        name=file_name,
                        path=file_path,
                        size=metadata.size,
                        allocated=is_allocated,
                        deleted=is_deleted,
                        file_type=self._get_file_type(metadata.type),
                        created_time=self._convert_timestamp(getattr(metadata, 'crtime', None)),
                        modified_time=self._convert_timestamp(getattr(metadata, 'mtime', None)),
                        accessed_time=self._convert_timestamp(getattr(metadata, 'atime', None)),
                        changed_time=self._convert_timestamp(getattr(metadata, 'ctime', None))
                    )
                    
                    # Calcul des hashs pour les fichiers réguliers
                    if metadata.type == pytsk3.TSK_FS_META_TYPE_REG and metadata.size > 0:
                        try:
                            file_data = file_entry.read_random(0, metadata.size)
                            if file_data:
                                forensic_file.md5_hash = hashlib.md5(file_data).hexdigest()
                                forensic_file.sha256_hash = hashlib.sha256(file_data).hexdigest()
                                forensic_file.mime_type = magic.from_buffer(file_data[:1024], mime=True)
                                
                                # Analyse YARA si disponible
                                if self.yara_rules:
                                    matches = self.yara_rules.match(data=file_data)
                                    if matches:
                                        forensic_file.signature_match = matches[0].rule
                        except Exception as e:
                            logger.debug(f"Erreur lecture fichier {file_path}: {e}")
                    
                    files.append(forensic_file)
                    
                    # Ajout des événements à la timeline
                    self._add_timeline_events(forensic_file)
                    
                    # Analyse récursive des répertoires
                    if (recursive and metadata.type == pytsk3.TSK_FS_META_TYPE_DIR 
                        and file_name not in [".", ".."]):
                        sub_files = self.list_files(file_path, recursive, include_deleted)
                        files.extend(sub_files)
                        
                except Exception as e:
                    logger.debug(f"Erreur analyse fichier: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Erreur listage fichiers dans {path}: {e}")
        
        # Sauvegarde en base de données
        self._save_files_to_db(files)
        
        return files
    
    def _get_file_type(self, tsk_type) -> str:
        """Convertit le type TSK en string lisible"""
        type_map = {
            pytsk3.TSK_FS_META_TYPE_REG: "File",
            pytsk3.TSK_FS_META_TYPE_DIR: "Directory", 
            pytsk3.TSK_FS_META_TYPE_LNK: "Link",
            pytsk3.TSK_FS_META_TYPE_CHR: "Character Device",
            pytsk3.TSK_FS_META_TYPE_BLK: "Block Device",
            pytsk3.TSK_FS_META_TYPE_FIFO: "FIFO",
            pytsk3.TSK_FS_META_TYPE_SOCK: "Socket"
        }
        return type_map.get(tsk_type, "Unknown")
    
    def _convert_timestamp(self, tsk_timestamp) -> Optional[datetime]:
        """Convertit un timestamp TSK en datetime"""
        if tsk_timestamp and tsk_timestamp > 0:
            try:
                return datetime.fromtimestamp(tsk_timestamp, tz=timezone.utc)
            except (ValueError, OSError):
                return None
        return None
    
    def _add_timeline_events(self, file: ForensicFile):
        """Ajoute les événements MACB à la timeline"""
        events = []
        
        if file.modified_time:
            events.append(TimelineEvent(
                timestamp=file.modified_time,
                event_type="M",
                source="File System",
                description=f"File modified: {file.path}",
                inode=file.inode,
                file_path=file.path,
                file_size=file.size
            ))
        
        if file.accessed_time:
            events.append(TimelineEvent(
                timestamp=file.accessed_time,
                event_type="A", 
                source="File System",
                description=f"File accessed: {file.path}",
                inode=file.inode,
                file_path=file.path,
                file_size=file.size
            ))
        
        if file.changed_time:
            events.append(TimelineEvent(
                timestamp=file.changed_time,
                event_type="C",
                source="File System",
                description=f"File metadata changed: {file.path}",
                inode=file.inode,
                file_path=file.path,
                file_size=file.size
            ))
        
        if file.created_time:
            events.append(TimelineEvent(
                timestamp=file.created_time,
                event_type="B",
                source="File System",
                description=f"File created: {file.path}",
                inode=file.inode,
                file_path=file.path,
                file_size=file.size
            ))
        
        self.timeline_events.extend(events)
    
    def file_carving(self, output_dir: str = None, file_types: List[str] = None) -> List[CarvedFile]:
        """
        Effectue le carving de fichiers sur l'image
        
        Args:
            output_dir: Répertoire de sortie pour les fichiers récupérés
            file_types: Types de fichiers à rechercher (None = tous)
            
        Returns:
            Liste des fichiers récupérés
        """
        if not self.image_handle:
            logger.error("Aucune image ouverte")
            return []
        
        if output_dir is None:
            output_dir = self.evidence_dir / f"carved_files_{self.case_id}"
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        carved_files = []
        chunk_size = 1024 * 1024  # 1MB chunks
        
        logger.info("Démarrage du file carving...")
        
        try:
            # Reset position
            self.image_handle.seek(0)
            offset = 0
            
            while True:
                # Lecture du chunk
                if hasattr(self.image_handle, 'read'):
                    chunk = self.image_handle.read(chunk_size)
                else:
                    chunk = self.image_handle.read_random(offset, chunk_size)
                
                if not chunk:
                    break
                
                # Recherche de signatures dans le chunk
                for pos in range(len(chunk) - 16):  # 16 bytes minimum pour header
                    signature_result = self.signature_db.detect_signature(chunk, pos)
                    
                    if signature_result:
                        file_type, confidence = signature_result
                        
                        # Filtrage par type si spécifié
                        if file_types and file_type not in file_types:
                            continue
                        
                        if confidence >= 0.6:  # Seuil de confiance
                            file_offset = offset + pos
                            carved_file = self._extract_carved_file(
                                file_offset, file_type, confidence, output_dir
                            )
                            
                            if carved_file:
                                carved_files.append(carved_file)
                                logger.info(f"Fichier récupéré: {file_type} à l'offset {file_offset:,}")
                
                offset += chunk_size
                
                # Affichage du progrès
                if offset % (100 * 1024 * 1024) == 0:  # Tous les 100MB
                    logger.info(f"Carving en cours: {offset:,} bytes analysés")
        
        except Exception as e:
            logger.error(f"Erreur pendant le carving: {e}")
        
        # Sauvegarde des résultats
        self.carved_files.extend(carved_files)
        self._save_carved_files_to_db(carved_files)
        
        logger.info(f"File carving terminé: {len(carved_files)} fichiers récupérés")
        return carved_files
    
    def _extract_carved_file(self, offset: int, file_type: str, confidence: float, 
                           output_dir: Path) -> Optional[CarvedFile]:
        """Extrait un fichier identifié par carving"""
        try:
            # Estimation de la taille basée sur le type
            max_size_map = {
                'JPEG': 50 * 1024 * 1024,  # 50MB
                'PNG': 20 * 1024 * 1024,   # 20MB
                'PDF': 100 * 1024 * 1024,  # 100MB
                'DOC': 50 * 1024 * 1024,   # 50MB
                'ZIP': 1024 * 1024 * 1024, # 1GB
                'MP4': 2 * 1024 * 1024 * 1024,  # 2GB
            }
            
            max_size = max_size_map.get(file_type, 10 * 1024 * 1024)  # Default 10MB
            
            # Lecture des données
            if hasattr(self.image_handle, 'read_random'):
                data = self.image_handle.read_random(offset, max_size)
            else:
                self.image_handle.seek(offset)
                data = self.image_handle.read(max_size)
            
            if not data:
                return None
            
            # Détection de la fin du fichier (basique)
            actual_size = self._detect_file_end(data, file_type)
            
            if actual_size > 0:
                file_data = data[:actual_size]
                
                # Génération du nom de fichier
                filename = f"carved_{offset:010d}_{file_type.lower()}"
                if file_type == 'JPEG':
                    filename += '.jpg'
                elif file_type == 'PNG':
                    filename += '.png'
                elif file_type == 'PDF':
                    filename += '.pdf'
                else:
                    filename += '.bin'
                
                file_path = output_dir / filename
                
                # Sauvegarde du fichier
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                
                # Calcul des hashs
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                
                carved_file = CarvedFile(
                    offset=offset,
                    size=actual_size,
                    file_type=file_type,
                    signature=file_type,
                    confidence=confidence,
                    recovered_path=str(file_path),
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash
                )
                
                return carved_file
                
        except Exception as e:
            logger.debug(f"Erreur extraction fichier carved à l'offset {offset}: {e}")
        
        return None
    
    def _detect_file_end(self, data: bytes, file_type: str) -> int:
        """Détecte la fin d'un fichier basé sur son type"""
        if file_type == 'JPEG':
            # Recherche du marqueur de fin JPEG
            end_marker = b'\xFF\xD9'
            pos = data.find(end_marker)
            return pos + 2 if pos != -1 else min(len(data), 10 * 1024 * 1024)
        
        elif file_type == 'PNG':
            # Recherche de IEND chunk
            end_marker = b'IEND\xaeB`\x82'
            pos = data.find(end_marker)
            return pos + 8 if pos != -1 else min(len(data), 10 * 1024 * 1024)
        
        elif file_type == 'PDF':
            # Recherche de %%EOF
            end_marker = b'%%EOF'
            pos = data.rfind(end_marker)  # Dernière occurrence
            return pos + 5 if pos != -1 else min(len(data), 50 * 1024 * 1024)
        
        else:
            # Estimation basée sur la taille moyenne du type
            size_estimates = {
                'GIF': 2 * 1024 * 1024,   # 2MB
                'BMP': 5 * 1024 * 1024,   # 5MB  
                'DOC': 10 * 1024 * 1024,  # 10MB
                'ZIP': 100 * 1024 * 1024, # 100MB
                'RAR': 100 * 1024 * 1024, # 100MB
            }
            
            return min(len(data), size_estimates.get(file_type, 1024 * 1024))
    
    def generate_timeline(self) -> List[TimelineEvent]:
        """
        Génère la timeline forensique complète
        
        Returns:
            Liste des événements triés par timestamp
        """
        # Tri des événements par timestamp
        sorted_events = sorted(
            self.timeline_events,
            key=lambda x: x.timestamp if x.timestamp else datetime.min.replace(tzinfo=timezone.utc)
        )
        
        # Sauvegarde en base
        self._save_timeline_to_db(sorted_events)
        
        logger.info(f"Timeline générée: {len(sorted_events)} événements")
        return sorted_events
    
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extrait les métadonnées détaillées d'un fichier
        
        Args:
            file_path: Chemin du fichier dans l'image
            
        Returns:
            Dictionnaire des métadonnées
        """
        if not self.filesystem:
            return {}
        
        metadata = {}
        
        try:
            # Ouverture du fichier
            file_obj = self.filesystem.open(file_path)
            file_info = file_obj.info
            file_meta = file_info.meta
            
            # Métadonnées de base
            metadata.update({
                'inode': file_meta.addr,
                'size': file_meta.size,
                'allocated': file_info.name.flags == pytsk3.TSK_FS_NAME_FLAG_ALLOC,
                'type': self._get_file_type(file_meta.type),
                'mode': oct(file_meta.mode) if hasattr(file_meta, 'mode') else None,
                'uid': getattr(file_meta, 'uid', None),
                'gid': getattr(file_meta, 'gid', None),
                'created': self._convert_timestamp(getattr(file_meta, 'crtime', None)),
                'modified': self._convert_timestamp(getattr(file_meta, 'mtime', None)),
                'accessed': self._convert_timestamp(getattr(file_meta, 'atime', None)),
                'changed': self._convert_timestamp(getattr(file_meta, 'ctime', None))
            })
            
            # Lecture du contenu pour analyse supplémentaire
            if file_meta.type == pytsk3.TSK_FS_META_TYPE_REG and file_meta.size > 0:
                try:
                    file_data = file_obj.read_random(0, min(file_meta.size, 1024 * 1024))  # Max 1MB
                    
                    if file_data:
                        # Type MIME
                        metadata['mime_type'] = magic.from_buffer(file_data, mime=True)
                        metadata['file_type_desc'] = magic.from_buffer(file_data)
                        
                        # Hashs
                        metadata['md5'] = hashlib.md5(file_data[:file_meta.size] if len(file_data) >= file_meta.size else file_data).hexdigest()
                        metadata['sha256'] = hashlib.sha256(file_data[:file_meta.size] if len(file_data) >= file_meta.size else file_data).hexdigest()
                        
                        # Métadonnées spécifiques par type
                        if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.gif')):
                            metadata.update(self._extract_image_metadata(file_data))
                        
                        # Analyse YARA
                        if self.yara_rules:
                            matches = self.yara_rules.match(data=file_data)
                            if matches:
                                metadata['yara_matches'] = [match.rule for match in matches]
                
                except Exception as e:
                    logger.debug(f"Erreur lecture métadonnées pour {file_path}: {e}")
            
        except Exception as e:
            logger.error(f"Erreur extraction métadonnées pour {file_path}: {e}")
        
        return metadata
    
    def _extract_image_metadata(self, image_data: bytes) -> Dict[str, Any]:
        """Extrait les métadonnées EXIF d'une image"""
        metadata = {}
        
        try:
            from io import BytesIO
            image = Image.open(BytesIO(image_data))
            
            # Informations de base
            metadata.update({
                'image_format': image.format,
                'image_mode': image.mode,
                'image_size': image.size,
                'has_transparency': 'transparency' in image.info
            })
            
            # Métadonnées EXIF
            if hasattr(image, '_getexif') and image._getexif():
                exif_data = image._getexif()
                exif_metadata = {}
                
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    
                    # Conversion des valeurs complexes
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    elif isinstance(value, tuple):
                        value = list(value)
                    
                    exif_metadata[str(tag)] = value
                
                metadata['exif'] = exif_metadata
                
        except Exception as e:
            logger.debug(f"Erreur extraction métadonnées image: {e}")
        
        return metadata
    
    def _save_case_info(self, case_id: str, image_path: str, image_format: str,
                       image_size: int, md5_hash: str, sha256_hash: str):
        """Sauvegarde les informations du cas en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cases 
            (case_id, image_path, image_format, image_size, image_md5, image_sha256, analysis_start)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (case_id, image_path, image_format, image_size, md5_hash, sha256_hash, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def _save_files_to_db(self, files: List[ForensicFile]):
        """Sauvegarde la liste des fichiers en base"""
        if not files:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for file in files:
            cursor.execute('''
                INSERT OR REPLACE INTO files 
                (case_id, inode, name, path, size, allocated, deleted, file_type, mime_type,
                 md5_hash, sha256_hash, created_time, modified_time, accessed_time, changed_time,
                 metadata, carved, signature_match)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, file.inode, file.name, file.path, file.size,
                file.allocated, file.deleted, file.file_type, file.mime_type,
                file.md5_hash, file.sha256_hash, file.created_time, file.modified_time,
                file.accessed_time, file.changed_time, json.dumps(file.metadata),
                file.carved, file.signature_match
            ))
        
        conn.commit()
        conn.close()
    
    def _save_timeline_to_db(self, events: List[TimelineEvent]):
        """Sauvegarde la timeline en base"""
        if not events:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for event in events:
            cursor.execute('''
                INSERT INTO timeline_events 
                (case_id, timestamp, event_type, source, description, inode, file_path, file_size, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, event.timestamp, event.event_type, event.source,
                event.description, event.inode, event.file_path, event.file_size,
                json.dumps(event.metadata)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_carved_files_to_db(self, carved_files: List[CarvedFile]):
        """Sauvegarde les fichiers carved en base"""
        if not carved_files:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for carved in carved_files:
            cursor.execute('''
                INSERT INTO carved_files 
                (case_id, offset, size, file_type, signature, confidence, recovered_path, hash_md5, hash_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.case_id, carved.offset, carved.size, carved.file_type,
                carved.signature, carved.confidence, carved.recovered_path,
                carved.hash_md5, carved.hash_sha256
            ))
        
        conn.commit()
        conn.close()
    
    def export_results(self, output_file: str, format_type: str = 'json') -> bool:
        """
        Export des résultats d'analyse
        
        Args:
            output_file: Fichier de sortie
            format_type: Format (json, csv, xml)
            
        Returns:
            True si succès
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            if format_type.lower() == 'json':
                # Export JSON
                data = {
                    'case_info': self._get_case_info_from_db(conn),
                    'files': self._get_files_from_db(conn),
                    'timeline': self._get_timeline_from_db(conn),
                    'carved_files': self._get_carved_files_from_db(conn)
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                # Export CSV des fichiers
                import csv
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM files WHERE case_id = ?', (self.case_id,))
                
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Headers
                    writer.writerow([desc[0] for desc in cursor.description])
                    # Data
                    writer.writerows(cursor.fetchall())
            
            conn.close()
            logger.info(f"Résultats exportés vers {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export: {e}")
            return False
    
    def _get_case_info_from_db(self, conn) -> Dict:
        """Récupère les informations du cas depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM cases WHERE case_id = ?', (self.case_id,))
        row = cursor.fetchone()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return {}
    
    def _get_files_from_db(self, conn) -> List[Dict]:
        """Récupère les fichiers depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_timeline_from_db(self, conn) -> List[Dict]:
        """Récupère la timeline depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_carved_files_from_db(self, conn) -> List[Dict]:
        """Récupère les fichiers carved depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM carved_files WHERE case_id = ?', (self.case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def close(self):
        """Ferme l'image et nettoie les ressources"""
        if self.image_handle:
            try:
                self.image_handle.close()
            except:
                pass
            self.image_handle = None
        
        self.filesystem = None
        logger.info("Analyseur fermé")


def main():
    """Fonction de démonstration"""
    print("🔍 Forensic Analysis Toolkit - Disk Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = DiskAnalyzer(evidence_dir="./evidence", temp_dir="./temp")
    
    # Simulation avec une image de test (remplacer par une vraie image)
    test_image = "./test_images/sample.dd"
    case_id = f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Cas d'analyse: {case_id}")
    
    # Si l'image de test existe
    if Path(test_image).exists():
        print(f"📁 Ouverture de l'image: {test_image}")
        
        if analyzer.open_image(test_image, case_id):
            # Analyse du système de fichiers
            fs_info = analyzer.analyze_filesystem()
            if fs_info:
                print(f"💾 Système de fichiers: {fs_info.fs_type.value}")
                print(f"📊 Blocs: {fs_info.block_count:,} x {fs_info.block_size} bytes")
                
                # Listage des fichiers
                print("📂 Analyse des fichiers...")
                files = analyzer.list_files("/", recursive=True, include_deleted=True)
                
                print(f"📁 {len(files)} fichiers analysés")
                deleted_count = sum(1 for f in files if f.deleted)
                print(f"🗑️  {deleted_count} fichiers supprimés détectés")
                
                # File carving
                print("🔧 File carving en cours...")
                carved_files = analyzer.file_carving()
                print(f"💾 {len(carved_files)} fichiers récupérés")
                
                # Timeline
                timeline = analyzer.generate_timeline()
                print(f"🕒 Timeline: {len(timeline)} événements")
                
                # Export des résultats
                output_file = f"./results_{case_id}.json"
                if analyzer.export_results(output_file, 'json'):
                    print(f"📄 Résultats exportés: {output_file}")
            
        analyzer.close()
    else:
        print("⚠️  Aucune image de test trouvée")
        print(f"   Créez un fichier {test_image} ou modifiez le chemin")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()