#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
Crypto Analyzer - Forensic Analysis Toolkit
============================================================================
Analyseur cryptographique et stéganographique forensique :
- Détection et analyse de contenu chiffré
- Reconnaissance d'algorithmes cryptographiques
- Analyse de certificats et clés cryptographiques
- Détection de stéganographie dans images/audio/vidéo
- Cracking de mots de passe et hashes
- Analyse d'entropie et détection de randomness
- Timeline des activités cryptographiques

Author: Cybersecurity Portfolio - Forensic Analysis Toolkit
Version: 2.1.0
Last Updated: January 2024
============================================================================
"""

import os
import sys
import hashlib
import hmac
import base64
import binascii
import sqlite3
import json
import logging
import struct
import math
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import re

# Bibliothèques cryptographiques
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Bibliothèques d'analyse d'image
try:
    from PIL import Image, ExifTags
    import numpy as np
    IMAGE_ANALYSIS_AVAILABLE = True
except ImportError:
    IMAGE_ANALYSIS_AVAILABLE = False

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CryptoAlgorithm(Enum):
    """Algorithmes cryptographiques détectés"""
    AES = "AES"
    DES = "DES"
    TRIPLE_DES = "3DES"
    RSA = "RSA"
    DSA = "DSA"
    ECDSA = "ECDSA"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    MD5 = "MD5"
    HMAC = "HMAC"
    BASE64 = "Base64"
    UNKNOWN = "Unknown"


class EncryptionType(Enum):
    """Types de chiffrement"""
    SYMMETRIC = "Symmetric"
    ASYMMETRIC = "Asymmetric"
    HASH = "Hash"
    SIGNATURE = "Digital Signature"
    ENCODING = "Encoding"
    STEGANOGRAPHY = "Steganography"


class SteganographyMethod(Enum):
    """Méthodes de stéganographie"""
    LSB = "Least Significant Bit"
    DCT = "Discrete Cosine Transform"
    FREQUENCY_DOMAIN = "Frequency Domain"
    PALETTE = "Palette Modification"
    METADATA = "Metadata Hiding"
    AUDIO_SPREAD = "Audio Spread Spectrum"
    UNKNOWN = "Unknown Method"


@dataclass
class CryptoArtifact:
    """Artefact cryptographique détecté"""
    artifact_id: str
    file_path: str
    offset: int
    size: int
    algorithm: CryptoAlgorithm
    encryption_type: EncryptionType
    confidence: float  # 0.0 - 1.0
    entropy: Optional[float] = None
    hash_value: Optional[str] = None
    key_info: Optional[Dict[str, Any]] = None
    certificate_info: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_encrypted: bool = False
    is_compressed: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SteganoArtifact:
    """Artefact stéganographique détecté"""
    artifact_id: str
    file_path: str
    carrier_type: str  # image, audio, video, text
    method: SteganographyMethod
    payload_size: Optional[int] = None
    payload_data: Optional[bytes] = None
    confidence: float = 0.0
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PasswordCrack:
    """Résultat de craquage de mot de passe"""
    hash_value: str
    hash_type: str
    plaintext: Optional[str] = None
    cracking_method: str = "Dictionary"
    attempts: int = 0
    time_taken: float = 0.0
    success: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CertificateAnalysis:
    """Analyse de certificat cryptographique"""
    certificate_path: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm: str
    extensions: List[str] = field(default_factory=list)
    is_valid: bool = True
    is_self_signed: bool = False
    trust_chain: List[str] = field(default_factory=list)


class EntropyAnalyzer:
    """
    Analyseur d'entropie pour détecter le contenu chiffré/compressé
    """
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcule l'entropie de Shannon des données"""
        if len(data) == 0:
            return 0.0
        
        # Compter la fréquence de chaque octet
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculer l'entropie
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequency:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_likely_encrypted(data: bytes, threshold: float = 7.0) -> bool:
        """Détermine si les données sont probablement chiffrées"""
        entropy = EntropyAnalyzer.calculate_entropy(data)
        return entropy > threshold
    
    @staticmethod
    def analyze_file_entropy(file_path: Path, block_size: int = 8192) -> Dict[str, Any]:
        """Analyse l'entropie d'un fichier par blocs"""
        results = {
            'file_entropy': 0.0,
            'block_entropies': [],
            'encrypted_blocks': 0,
            'total_blocks': 0,
            'max_entropy': 0.0,
            'min_entropy': 8.0,
            'avg_entropy': 0.0
        }
        
        try:
            with open(file_path, 'rb') as f:
                total_entropy = 0.0
                block_count = 0
                
                while True:
                    block = f.read(block_size)
                    if not block:
                        break
                    
                    block_entropy = EntropyAnalyzer.calculate_entropy(block)
                    results['block_entropies'].append(block_entropy)
                    
                    total_entropy += block_entropy
                    block_count += 1
                    
                    if block_entropy > 7.0:
                        results['encrypted_blocks'] += 1
                    
                    results['max_entropy'] = max(results['max_entropy'], block_entropy)
                    results['min_entropy'] = min(results['min_entropy'], block_entropy)
                
                results['total_blocks'] = block_count
                results['avg_entropy'] = total_entropy / block_count if block_count > 0 else 0.0
                
                # Entropie globale du fichier
                f.seek(0)
                file_data = f.read()
                results['file_entropy'] = EntropyAnalyzer.calculate_entropy(file_data)
        
        except Exception as e:
            logger.error(f"Erreur analyse entropie fichier {file_path}: {e}")
        
        return results


class CryptographicDetector:
    """
    Détecteur d'algorithmes et d'artefacts cryptographiques
    """
    
    def __init__(self):
        """Initialise le détecteur cryptographique"""
        self.crypto_patterns = self._init_crypto_patterns()
        self.hash_patterns = self._init_hash_patterns()
    
    def _init_crypto_patterns(self) -> Dict[str, Dict]:
        """Initialise les patterns de reconnaissance cryptographique"""
        return {
            'base64': {
                'pattern': rb'[A-Za-z0-9+/]{20,}={0,2}',
                'algorithm': CryptoAlgorithm.BASE64,
                'confidence': 0.7
            },
            'pem_header': {
                'pattern': rb'-----BEGIN [A-Z ]+-----',
                'algorithm': CryptoAlgorithm.RSA,
                'confidence': 0.9
            },
            'x509_certificate': {
                'pattern': rb'\x30\x82.{2}\x30\x82',  # ASN.1 sequence
                'algorithm': CryptoAlgorithm.RSA,
                'confidence': 0.8
            },
            'pkcs_structure': {
                'pattern': rb'\x30\x82.{2}\x02\x01\x00',
                'algorithm': CryptoAlgorithm.RSA,
                'confidence': 0.8
            }
        }
    
    def _init_hash_patterns(self) -> Dict[str, Dict]:
        """Initialise les patterns de reconnaissance de hashes"""
        return {
            'md5': {
                'pattern': rb'[a-fA-F0-9]{32}',
                'algorithm': CryptoAlgorithm.MD5,
                'length': 32
            },
            'sha1': {
                'pattern': rb'[a-fA-F0-9]{40}',
                'algorithm': CryptoAlgorithm.SHA1,
                'length': 40
            },
            'sha256': {
                'pattern': rb'[a-fA-F0-9]{64}',
                'algorithm': CryptoAlgorithm.SHA256,
                'length': 64
            },
            'sha512': {
                'pattern': rb'[a-fA-F0-9]{128}',
                'algorithm': CryptoAlgorithm.SHA512,
                'length': 128
            }
        }
    
    def detect_crypto_artifacts(self, file_path: Path) -> List[CryptoArtifact]:
        """Détecte les artefacts cryptographiques dans un fichier"""
        artifacts = []
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Analyse d'entropie globale
            entropy_results = EntropyAnalyzer.analyze_file_entropy(file_path)
            
            # Détection par patterns
            artifacts.extend(self._detect_by_patterns(file_path, file_data, entropy_results))
            
            # Analyse de certificats si disponible
            if CRYPTO_AVAILABLE:
                cert_artifacts = self._analyze_certificates(file_path, file_data)
                artifacts.extend(cert_artifacts)
            
            # Détection de contenu chiffré par entropie
            if entropy_results['avg_entropy'] > 7.5:
                crypto_artifact = CryptoArtifact(
                    artifact_id=f"crypto_entropy_{file_path.name}",
                    file_path=str(file_path),
                    offset=0,
                    size=len(file_data),
                    algorithm=CryptoAlgorithm.UNKNOWN,
                    encryption_type=EncryptionType.SYMMETRIC,
                    confidence=min(entropy_results['avg_entropy'] / 8.0, 1.0),
                    entropy=entropy_results['file_entropy'],
                    is_encrypted=True,
                    metadata=entropy_results
                )
                artifacts.append(crypto_artifact)
            
        except Exception as e:
            logger.error(f"Erreur détection crypto dans {file_path}: {e}")
        
        return artifacts
    
    def _detect_by_patterns(self, file_path: Path, file_data: bytes, 
                           entropy_results: Dict) -> List[CryptoArtifact]:
        """Détecte les artefacts par reconnaissance de patterns"""
        artifacts = []
        
        for pattern_name, pattern_info in self.crypto_patterns.items():
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, file_data)
            
            for match in matches:
                artifact = CryptoArtifact(
                    artifact_id=f"crypto_{pattern_name}_{match.start()}",
                    file_path=str(file_path),
                    offset=match.start(),
                    size=match.end() - match.start(),
                    algorithm=pattern_info['algorithm'],
                    encryption_type=self._determine_encryption_type(pattern_info['algorithm']),
                    confidence=pattern_info['confidence'],
                    entropy=EntropyAnalyzer.calculate_entropy(match.group()),
                    metadata={'pattern_type': pattern_name, 'matched_data': match.group()[:100]}
                )
                artifacts.append(artifact)
        
        # Détection de hashes
        for hash_type, hash_info in self.hash_patterns.items():
            pattern = hash_info['pattern']
            matches = re.finditer(pattern, file_data)
            
            for match in matches:
                # Vérifier que c'est bien un hash (pas du texte normal)
                if self._is_likely_hash(match.group()):
                    artifact = CryptoArtifact(
                        artifact_id=f"hash_{hash_type}_{match.start()}",
                        file_path=str(file_path),
                        offset=match.start(),
                        size=len(match.group()),
                        algorithm=hash_info['algorithm'],
                        encryption_type=EncryptionType.HASH,
                        confidence=0.8,
                        hash_value=match.group().decode('utf-8', errors='ignore'),
                        metadata={'hash_type': hash_type}
                    )
                    artifacts.append(artifact)
        
        return artifacts
    
    def _analyze_certificates(self, file_path: Path, file_data: bytes) -> List[CryptoArtifact]:
        """Analyse les certificats X.509"""
        artifacts = []
        
        try:
            # Tentative de parsing comme certificat X.509
            try:
                cert = x509.load_pem_x509_certificate(file_data)
                cert_info = self._extract_certificate_info(cert)
                
                artifact = CryptoArtifact(
                    artifact_id=f"cert_x509_{file_path.name}",
                    file_path=str(file_path),
                    offset=0,
                    size=len(file_data),
                    algorithm=CryptoAlgorithm.RSA,  # Supposé, sera mis à jour
                    encryption_type=EncryptionType.ASYMMETRIC,
                    confidence=1.0,
                    certificate_info=cert_info,
                    metadata={'certificate_type': 'X.509'}
                )
                artifacts.append(artifact)
                
            except:
                # Essayer DER format
                try:
                    cert = x509.load_der_x509_certificate(file_data)
                    cert_info = self._extract_certificate_info(cert)
                    
                    artifact = CryptoArtifact(
                        artifact_id=f"cert_x509_der_{file_path.name}",
                        file_path=str(file_path),
                        offset=0,
                        size=len(file_data),
                        algorithm=CryptoAlgorithm.RSA,
                        encryption_type=EncryptionType.ASYMMETRIC,
                        confidence=1.0,
                        certificate_info=cert_info,
                        metadata={'certificate_type': 'X.509 DER'}
                    )
                    artifacts.append(artifact)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Erreur analyse certificat {file_path}: {e}")
        
        return artifacts
    
    def _extract_certificate_info(self, cert) -> Dict[str, Any]:
        """Extrait les informations d'un certificat X.509"""
        try:
            # Algorithme de clé publique
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_algorithm = "RSA"
                key_size = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_algorithm = "ECDSA"
                key_size = public_key.curve.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_algorithm = "DSA"
                key_size = public_key.key_size
            else:
                key_algorithm = "Unknown"
                key_size = 0
            
            return {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_before': cert.not_valid_before,
                'not_after': cert.not_valid_after,
                'public_key_algorithm': key_algorithm,
                'public_key_size': key_size,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'extensions': [ext.oid._name for ext in cert.extensions],
                'is_self_signed': cert.issuer == cert.subject
            }
        except Exception as e:
            logger.error(f"Erreur extraction info certificat: {e}")
            return {}
    
    def _determine_encryption_type(self, algorithm: CryptoAlgorithm) -> EncryptionType:
        """Détermine le type de chiffrement basé sur l'algorithme"""
        hash_algorithms = [CryptoAlgorithm.MD5, CryptoAlgorithm.SHA1, 
                          CryptoAlgorithm.SHA256, CryptoAlgorithm.SHA512]
        asymmetric_algorithms = [CryptoAlgorithm.RSA, CryptoAlgorithm.DSA, CryptoAlgorithm.ECDSA]
        
        if algorithm in hash_algorithms:
            return EncryptionType.HASH
        elif algorithm in asymmetric_algorithms:
            return EncryptionType.ASYMMETRIC
        elif algorithm == CryptoAlgorithm.BASE64:
            return EncryptionType.ENCODING
        else:
            return EncryptionType.SYMMETRIC
    
    def _is_likely_hash(self, data: bytes) -> bool:
        """Détermine si une séquence hexadécimale est probablement un hash"""
        try:
            hex_string = data.decode('ascii')
            # Vérifier que c'est bien hexadécimal
            int(hex_string, 16)
            
            # Vérifier la distribution des caractères (doit être relativement uniforme)
            char_counts = {}
            for char in hex_string.lower():
                char_counts[char] = char_counts.get(char, 0) + 1
            
            # Un hash devrait avoir une distribution relativement uniforme
            expected_frequency = len(hex_string) / 16  # 16 caractères hex possibles
            max_deviation = expected_frequency * 0.5  # 50% de déviation max
            
            for count in char_counts.values():
                if abs(count - expected_frequency) > max_deviation:
                    return False
            
            return True
            
        except (ValueError, UnicodeDecodeError):
            return False


class SteganographyDetector:
    """
    Détecteur de stéganographie dans fichiers multimédia
    """
    
    def __init__(self):
        """Initialise le détecteur de stéganographie"""
        self.supported_formats = ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'wav', 'mp3']
    
    def detect_steganography(self, file_path: Path) -> List[SteganoArtifact]:
        """Détecte la stéganographie dans un fichier"""
        artifacts = []
        
        try:
            file_extension = file_path.suffix.lower().lstrip('.')
            
            if file_extension in ['png', 'jpg', 'jpeg', 'bmp', 'gif']:
                artifacts.extend(self._analyze_image_steganography(file_path))
            elif file_extension in ['wav', 'mp3']:
                artifacts.extend(self._analyze_audio_steganography(file_path))
            elif file_extension in ['txt', 'doc', 'docx']:
                artifacts.extend(self._analyze_text_steganography(file_path))
        
        except Exception as e:
            logger.error(f"Erreur détection stéganographie {file_path}: {e}")
        
        return artifacts
    
    def _analyze_image_steganography(self, file_path: Path) -> List[SteganoArtifact]:
        """Analyse la stéganographie dans les images"""
        artifacts = []
        
        if not IMAGE_ANALYSIS_AVAILABLE:
            return artifacts
        
        try:
            with Image.open(file_path) as img:
                # Analyse LSB (Least Significant Bit)
                lsb_result = self._detect_lsb_steganography(img, file_path)
                if lsb_result:
                    artifacts.append(lsb_result)
                
                # Analyse des métadonnées EXIF suspectes
                metadata_result = self._detect_metadata_hiding(img, file_path)
                if metadata_result:
                    artifacts.append(metadata_result)
                
                # Analyse statistique des couleurs
                color_stats = self._analyze_color_statistics(img, file_path)
                if color_stats:
                    artifacts.append(color_stats)
        
        except Exception as e:
            logger.error(f"Erreur analyse image stegano {file_path}: {e}")
        
        return artifacts
    
    def _detect_lsb_steganography(self, img: Image.Image, file_path: Path) -> Optional[SteganoArtifact]:
        """Détecte la stéganographie LSB dans une image"""
        try:
            if img.mode not in ['RGB', 'RGBA']:
                img = img.convert('RGB')
            
            # Convertir en array NumPy
            img_array = np.array(img)
            
            # Analyser les bits de poids faible
            lsb_data = img_array & 1  # Extraire les LSB
            
            # Calculer l'entropie des LSB
            flat_lsb = lsb_data.flatten()
            lsb_entropy = self._calculate_array_entropy(flat_lsb)
            
            # Une entropie élevée dans les LSB peut indiquer de la stéganographie
            if lsb_entropy > 0.9:  # Seuil empirique
                # Essayer d'extraire des données
                extracted_bits = []
                height, width = lsb_data.shape[:2]
                
                for y in range(height):
                    for x in range(width):
                        if len(lsb_data.shape) == 3:  # RGB
                            for channel in range(3):
                                extracted_bits.append(lsb_data[y, x, channel])
                        else:  # Grayscale
                            extracted_bits.append(lsb_data[y, x])
                
                # Convertir en bytes
                byte_data = []
                for i in range(0, len(extracted_bits) - 7, 8):
                    byte_val = 0
                    for j in range(8):
                        byte_val |= (extracted_bits[i + j] << j)
                    byte_data.append(byte_val)
                
                payload_data = bytes(byte_data[:1000])  # Premier KB pour analyse
                
                return SteganoArtifact(
                    artifact_id=f"stego_lsb_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="image",
                    method=SteganographyMethod.LSB,
                    payload_size=len(byte_data),
                    payload_data=payload_data,
                    confidence=min(lsb_entropy, 1.0),
                    analysis_results={
                        'lsb_entropy': lsb_entropy,
                        'extracted_bytes': len(byte_data)
                    }
                )
        
        except Exception as e:
            logger.debug(f"Erreur détection LSB: {e}")
        
        return None
    
    def _detect_metadata_hiding(self, img: Image.Image, file_path: Path) -> Optional[SteganoArtifact]:
        """Détecte la dissimulation dans les métadonnées EXIF"""
        try:
            exif_data = img._getexif()
            if not exif_data:
                return None
            
            suspicious_tags = []
            large_metadata = []
            
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Unknown_{tag_id}")
                
                # Recherche de données suspectes
                if isinstance(value, (str, bytes)):
                    # Métadonnées anormalement longues
                    if len(value) > 1000:
                        large_metadata.append((tag_name, len(value)))
                    
                    # Recherche de données binaires dans des champs texte
                    if isinstance(value, str):
                        try:
                            # Tester si c'est du base64
                            base64.b64decode(value)
                            if len(value) > 50:  # Au moins 50 caractères
                                suspicious_tags.append((tag_name, "Possible Base64"))
                        except:
                            pass
                        
                        # Recherche de patterns hexadécimaux
                        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) > 20:
                            suspicious_tags.append((tag_name, "Hexadecimal data"))
            
            if suspicious_tags or large_metadata:
                return SteganoArtifact(
                    artifact_id=f"stego_metadata_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="image",
                    method=SteganographyMethod.METADATA,
                    confidence=0.7,
                    analysis_results={
                        'suspicious_tags': suspicious_tags,
                        'large_metadata': large_metadata,
                        'total_exif_tags': len(exif_data)
                    }
                )
        
        except Exception as e:
            logger.debug(f"Erreur analyse métadonnées: {e}")
        
        return None
    
    def _analyze_color_statistics(self, img: Image.Image, file_path: Path) -> Optional[SteganoArtifact]:
        """Analyse statistique des couleurs pour détecter des anomalies"""
        try:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            
            # Analyser la distribution des couleurs
            color_stats = {}
            
            for channel in range(3):  # RGB
                channel_data = img_array[:, :, channel].flatten()
                
                # Calculer des statistiques
                mean_val = np.mean(channel_data)
                std_val = np.std(channel_data)
                
                # Analyser la distribution des valeurs paires/impaires
                even_count = np.sum(channel_data % 2 == 0)
                odd_count = np.sum(channel_data % 2 == 1)
                parity_ratio = even_count / (even_count + odd_count)
                
                color_stats[f'channel_{channel}'] = {
                    'mean': mean_val,
                    'std': std_val,
                    'parity_ratio': parity_ratio
                }
                
                # Une distribution 50/50 parfaite peut indiquer de la stéganographie
                if abs(parity_ratio - 0.5) < 0.01 and std_val > 50:
                    return SteganoArtifact(
                        artifact_id=f"stego_stats_{file_path.name}",
                        file_path=str(file_path),
                        carrier_type="image",
                        method=SteganographyMethod.LSB,
                        confidence=0.6,
                        analysis_results={
                            'color_statistics': color_stats,
                            'suspicious_channel': channel,
                            'anomaly_type': 'Perfect parity distribution'
                        }
                    )
        
        except Exception as e:
            logger.debug(f"Erreur analyse statistique couleurs: {e}")
        
        return None
    
    def _analyze_audio_steganography(self, file_path: Path) -> List[SteganoArtifact]:
        """Analyse la stéganographie dans les fichiers audio"""
        artifacts = []
        
        try:
            # Lecture basique du fichier audio (sans bibliothèques spécialisées)
            with open(file_path, 'rb') as f:
                audio_data = f.read()
            
            # Analyse de l'entropie
            entropy = EntropyAnalyzer.calculate_entropy(audio_data)
            
            # Recherche de patterns suspects dans les métadonnées
            if b'ID3' in audio_data[:10]:  # MP3 avec tags ID3
                id3_analysis = self._analyze_id3_tags(audio_data, file_path)
                if id3_analysis:
                    artifacts.append(id3_analysis)
            
            # Analyse d'entropie élevée (possible stéganographie)
            if entropy > 7.5:
                artifact = SteganoArtifact(
                    artifact_id=f"stego_audio_entropy_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="audio",
                    method=SteganographyMethod.FREQUENCY_DOMAIN,
                    confidence=min(entropy / 8.0, 1.0),
                    analysis_results={
                        'entropy': entropy,
                        'file_size': len(audio_data)
                    }
                )
                artifacts.append(artifact)
        
        except Exception as e:
            logger.error(f"Erreur analyse audio stégano: {e}")
        
        return artifacts
    
    def _analyze_id3_tags(self, audio_data: bytes, file_path: Path) -> Optional[SteganoArtifact]:
        """Analyse les tags ID3 pour détecter des données cachées"""
        try:
            # Recherche de tags ID3 suspects (très basique)
            suspicious_found = False
            
            # Recherche de données binaires dans les tags texte
            if len(audio_data) > 10:
                # Les 10 premiers octets contiennent l'en-tête ID3
                header = audio_data[:10]
                if header.startswith(b'ID3'):
                    # Taille des tags ID3
                    tag_size = int.from_bytes(header[6:10], 'big')
                    
                    if tag_size > len(audio_data) * 0.1:  # Tags > 10% du fichier
                        suspicious_found = True
            
            if suspicious_found:
                return SteganoArtifact(
                    artifact_id=f"stego_id3_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="audio",
                    method=SteganographyMethod.METADATA,
                    confidence=0.6,
                    analysis_results={
                        'anomaly_type': 'Large ID3 tags',
                        'tag_size': tag_size
                    }
                )
        
        except Exception as e:
            logger.debug(f"Erreur analyse ID3: {e}")
        
        return None
    
    def _analyze_text_steganography(self, file_path: Path) -> List[SteganoArtifact]:
        """Analyse la stéganographie dans les fichiers texte"""
        artifacts = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()
            
            # Recherche d'espaces invisibles (Unicode steganography)
            invisible_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']  # Zero-width chars
            invisible_found = any(char in text_content for char in invisible_chars)
            
            if invisible_found:
                artifact = SteganoArtifact(
                    artifact_id=f"stego_text_unicode_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="text",
                    method=SteganographyMethod.METADATA,
                    confidence=0.8,
                    analysis_results={
                        'steganography_type': 'Unicode zero-width characters',
                        'text_length': len(text_content)
                    }
                )
                artifacts.append(artifact)
            
            # Analyse des espaces/tabulations anormaux
            lines = text_content.split('\n')
            trailing_whitespace_count = sum(1 for line in lines if line.endswith(' ') or line.endswith('\t'))
            
            if trailing_whitespace_count > len(lines) * 0.3:  # >30% des lignes
                artifact = SteganoArtifact(
                    artifact_id=f"stego_text_whitespace_{file_path.name}",
                    file_path=str(file_path),
                    carrier_type="text",
                    method=SteganographyMethod.METADATA,
                    confidence=0.6,
                    analysis_results={
                        'steganography_type': 'Trailing whitespace encoding',
                        'suspicious_lines': trailing_whitespace_count,
                        'total_lines': len(lines)
                    }
                )
                artifacts.append(artifact)
        
        except Exception as e:
            logger.error(f"Erreur analyse texte stégano: {e}")
        
        return artifacts
    
    def _calculate_array_entropy(self, data_array: np.ndarray) -> float:
        """Calcule l'entropie d'un array NumPy"""
        unique, counts = np.unique(data_array, return_counts=True)
        probabilities = counts / len(data_array)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy / np.log2(len(unique))  # Entropie normalisée


class PasswordCracker:
    """
    Craqueur de mots de passe et hashes
    """
    
    def __init__(self, dictionary_path: Optional[Path] = None):
        """Initialise le craqueur de mots de passe"""
        self.dictionary_path = dictionary_path
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self) -> List[str]:
        """Charge une liste de mots de passe communs"""
        common_passwords = [
            'password', '123456', 'admin', 'root', 'user', 'guest',
            'password123', 'admin123', 'qwerty', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'shadow', 'football',
            '000000', '111111', '123123', '654321', 'abc123'
        ]
        
        # Charger dictionnaire personnalisé si disponible
        if self.dictionary_path and self.dictionary_path.exists():
            try:
                with open(self.dictionary_path, 'r', encoding='utf-8') as f:
                    custom_passwords = [line.strip() for line in f if line.strip()]
                    common_passwords.extend(custom_passwords)
            except Exception as e:
                logger.error(f"Erreur chargement dictionnaire: {e}")
        
        return common_passwords
    
    def crack_hash(self, hash_value: str, hash_type: str = "auto") -> PasswordCrack:
        """Craque un hash en utilisant un dictionnaire"""
        start_time = datetime.now()
        
        # Auto-détection du type de hash
        if hash_type == "auto":
            hash_type = self._detect_hash_type(hash_value)
        
        crack_result = PasswordCrack(
            hash_value=hash_value,
            hash_type=hash_type,
            cracking_method="Dictionary Attack"
        )
        
        # Tentative de craquage
        for attempt, password in enumerate(self.common_passwords):
            if self._hash_matches(password, hash_value, hash_type):
                crack_result.plaintext = password
                crack_result.success = True
                crack_result.attempts = attempt + 1
                break
            
            # Limiter le nombre de tentatives pour éviter les longs délais
            if attempt > 10000:
                break
        
        end_time = datetime.now()
        crack_result.time_taken = (end_time - start_time).total_seconds()
        
        return crack_result
    
    def _detect_hash_type(self, hash_value: str) -> str:
        """Détecte automatiquement le type de hash"""
        hash_clean = hash_value.strip().replace(' ', '')
        
        if len(hash_clean) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_clean):
            return "MD5"
        elif len(hash_clean) == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_clean):
            return "SHA1"
        elif len(hash_clean) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_clean):
            return "SHA256"
        elif len(hash_clean) == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_clean):
            return "SHA512"
        else:
            return "Unknown"
    
    def _hash_matches(self, password: str, target_hash: str, hash_type: str) -> bool:
        """Vérifie si un mot de passe correspond au hash cible"""
        try:
            target_hash_clean = target_hash.strip().lower()
            
            if hash_type == "MD5":
                computed_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == "SHA1":
                computed_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == "SHA256":
                computed_hash = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type == "SHA512":
                computed_hash = hashlib.sha512(password.encode()).hexdigest()
            else:
                return False
            
            return computed_hash.lower() == target_hash_clean
            
        except Exception:
            return False


class CryptoAnalyzer:
    """
    Analyseur cryptographique principal
    """
    
    def __init__(self, evidence_dir: str = "./evidence", temp_dir: str = "./temp"):
        """
        Initialise l'analyseur cryptographique
        
        Args:
            evidence_dir: Répertoire pour stocker les preuves
            temp_dir: Répertoire temporaire pour les analyses
        """
        self.evidence_dir = Path(evidence_dir)
        self.temp_dir = Path(temp_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Composants d'analyse
        self.crypto_detector = CryptographicDetector()
        self.stegano_detector = SteganographyDetector()
        self.password_cracker = PasswordCracker()
        
        # Base de données SQLite pour stocker les résultats
        self.db_path = self.evidence_dir / "crypto_analysis.db"
        self._init_database()
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des artefacts cryptographiques
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crypto_artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT,
                file_path TEXT,
                offset INTEGER,
                size INTEGER,
                algorithm TEXT,
                encryption_type TEXT,
                confidence REAL,
                entropy REAL,
                hash_value TEXT,
                is_encrypted BOOLEAN,
                is_compressed BOOLEAN,
                key_info TEXT,
                certificate_info TEXT,
                metadata TEXT,
                timestamp TEXT
            )
        ''')
        
        # Table des artefacts stéganographiques
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stegano_artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT,
                file_path TEXT,
                carrier_type TEXT,
                method TEXT,
                payload_size INTEGER,
                confidence REAL,
                analysis_results TEXT,
                metadata TEXT,
                timestamp TEXT
            )
        ''')
        
        # Table des résultats de craquage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_cracks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                hash_value TEXT,
                hash_type TEXT,
                plaintext TEXT,
                cracking_method TEXT,
                attempts INTEGER,
                time_taken REAL,
                success BOOLEAN,
                timestamp TEXT
            )
        ''')
        
        # Table des analyses de certificats
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                certificate_path TEXT,
                subject TEXT,
                issuer TEXT,
                serial_number TEXT,
                not_before TEXT,
                not_after TEXT,
                public_key_algorithm TEXT,
                public_key_size INTEGER,
                signature_algorithm TEXT,
                extensions TEXT,
                is_valid BOOLEAN,
                is_self_signed BOOLEAN,
                trust_chain TEXT,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_file(self, file_path: Union[str, Path], case_id: str) -> Dict[str, Any]:
        """
        Analyse cryptographique complète d'un fichier
        
        Args:
            file_path: Chemin vers le fichier à analyser
            case_id: Identifiant du cas
            
        Returns:
            Dictionnaire avec tous les résultats d'analyse
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"Fichier non trouvé: {file_path}")
            return {}
        
        logger.info(f"🔒 Analyse cryptographique: {file_path}")
        
        results = {
            'file_path': str(file_path),
            'case_id': case_id,
            'crypto_artifacts': [],
            'stegano_artifacts': [],
            'password_cracks': [],
            'entropy_analysis': {},
            'file_info': {
                'size': file_path.stat().st_size,
                'extension': file_path.suffix.lower(),
                'created': datetime.fromtimestamp(file_path.stat().st_ctime),
                'modified': datetime.fromtimestamp(file_path.stat().st_mtime)
            }
        }
        
        try:
            # 1. Détection d'artefacts cryptographiques
            logger.info("🔍 Détection artefacts cryptographiques...")
            crypto_artifacts = self.crypto_detector.detect_crypto_artifacts(file_path)
            results['crypto_artifacts'] = crypto_artifacts
            
            # 2. Analyse de stéganographie
            logger.info("🖼️ Analyse stéganographique...")
            stegano_artifacts = self.stegano_detector.detect_steganography(file_path)
            results['stegano_artifacts'] = stegano_artifacts
            
            # 3. Analyse d'entropie complète
            logger.info("📊 Analyse d'entropie...")
            entropy_analysis = EntropyAnalyzer.analyze_file_entropy(file_path)
            results['entropy_analysis'] = entropy_analysis
            
            # 4. Craquage de hashes détectés
            hash_artifacts = [a for a in crypto_artifacts if a.encryption_type == EncryptionType.HASH]
            if hash_artifacts:
                logger.info(f"🔓 Tentative de craquage de {len(hash_artifacts)} hashes...")
                for hash_artifact in hash_artifacts[:5]:  # Limiter à 5 hashes
                    if hash_artifact.hash_value:
                        crack_result = self.password_cracker.crack_hash(hash_artifact.hash_value)
                        results['password_cracks'].append(crack_result)
            
            # 5. Sauvegarde des résultats
            self._save_analysis_results(case_id, results)
            
            # 6. Génération des statistiques
            stats = self._generate_statistics(results)
            results['statistics'] = stats
            
        except Exception as e:
            logger.error(f"Erreur analyse cryptographique {file_path}: {e}")
            results['error'] = str(e)
        
        return results
    
    def analyze_directory(self, directory_path: Union[str, Path], case_id: str, 
                         recursive: bool = True) -> Dict[str, Any]:
        """
        Analyse cryptographique d'un répertoire complet
        
        Args:
            directory_path: Répertoire à analyser
            case_id: Identifiant du cas
            recursive: Analyse récursive des sous-répertoires
            
        Returns:
            Résultats d'analyse agrégés
        """
        directory_path = Path(directory_path)
        
        if not directory_path.exists() or not directory_path.is_dir():
            logger.error(f"Répertoire non trouvé: {directory_path}")
            return {}
        
        logger.info(f"📁 Analyse cryptographique répertoire: {directory_path}")
        
        aggregate_results = {
            'directory_path': str(directory_path),
            'case_id': case_id,
            'files_analyzed': 0,
            'total_crypto_artifacts': 0,
            'total_stegano_artifacts': 0,
            'total_password_cracks': 0,
            'file_results': {},
            'summary_statistics': {}
        }
        
        # Patterns de fichiers à analyser
        analysis_patterns = [
            '*.txt', '*.doc', '*.docx', '*.pdf', '*.zip', '*.rar', '*.7z',
            '*.png', '*.jpg', '*.jpeg', '*.gif', '*.bmp', '*.tiff',
            '*.mp3', '*.wav', '*.avi', '*.mp4', '*.mkv',
            '*.exe', '*.dll', '*.sys', '*.bin', '*.dat',
            '*.pem', '*.crt', '*.cer', '*.p12', '*.pfx', '*.key'
        ]
        
        files_to_analyze = []
        for pattern in analysis_patterns:
            if recursive:
                files_to_analyze.extend(directory_path.rglob(pattern))
            else:
                files_to_analyze.extend(directory_path.glob(pattern))
        
        # Supprimer les doublons et limiter le nombre de fichiers
        files_to_analyze = list(set(files_to_analyze))[:1000]  # Max 1000 fichiers
        
        logger.info(f"📊 {len(files_to_analyze)} fichiers à analyser")
        
        for file_path in files_to_analyze:
            try:
                # Ignorer les fichiers trop volumineux (>100MB)
                if file_path.stat().st_size > 100 * 1024 * 1024:
                    continue
                
                file_results = self.analyze_file(file_path, case_id)
                
                if file_results:
                    aggregate_results['file_results'][str(file_path)] = file_results
                    aggregate_results['files_analyzed'] += 1
                    aggregate_results['total_crypto_artifacts'] += len(file_results.get('crypto_artifacts', []))
                    aggregate_results['total_stegano_artifacts'] += len(file_results.get('stegano_artifacts', []))
                    aggregate_results['total_password_cracks'] += len(file_results.get('password_cracks', []))
            
            except Exception as e:
                logger.error(f"Erreur analyse fichier {file_path}: {e}")
        
        # Génération des statistiques agrégées
        aggregate_results['summary_statistics'] = self._generate_aggregate_statistics(aggregate_results)
        
        logger.info(f"✅ Analyse terminée: {aggregate_results['files_analyzed']} fichiers")
        logger.info(f"  🔒 Artefacts crypto: {aggregate_results['total_crypto_artifacts']}")
        logger.info(f"  🖼️ Artefacts stégano: {aggregate_results['total_stegano_artifacts']}")
        logger.info(f"  🔓 Hashes craqués: {sum(1 for fr in aggregate_results['file_results'].values() for pc in fr.get('password_cracks', []) if pc.success)}")
        
        return aggregate_results
    
    def _save_analysis_results(self, case_id: str, results: Dict[str, Any]):
        """Sauvegarde les résultats d'analyse en base de données"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Sauvegarde des artefacts cryptographiques
            for artifact in results.get('crypto_artifacts', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO crypto_artifacts 
                    (artifact_id, case_id, file_path, offset, size, algorithm, encryption_type,
                     confidence, entropy, hash_value, is_encrypted, is_compressed, key_info,
                     certificate_info, metadata, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    artifact.artifact_id, case_id, artifact.file_path, artifact.offset,
                    artifact.size, artifact.algorithm.value, artifact.encryption_type.value,
                    artifact.confidence, artifact.entropy, artifact.hash_value,
                    artifact.is_encrypted, artifact.is_compressed,
                    json.dumps(artifact.key_info) if artifact.key_info else None,
                    json.dumps(artifact.certificate_info) if artifact.certificate_info else None,
                    json.dumps(artifact.metadata), artifact.timestamp.isoformat()
                ))
            
            # Sauvegarde des artefacts stéganographiques
            for artifact in results.get('stegano_artifacts', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO stegano_artifacts 
                    (artifact_id, case_id, file_path, carrier_type, method, payload_size,
                     confidence, analysis_results, metadata, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    artifact.artifact_id, case_id, artifact.file_path, artifact.carrier_type,
                    artifact.method.value, artifact.payload_size, artifact.confidence,
                    json.dumps(artifact.analysis_results), json.dumps(artifact.metadata),
                    artifact.timestamp.isoformat()
                ))
            
            # Sauvegarde des résultats de craquage
            for crack in results.get('password_cracks', []):
                cursor.execute('''
                    INSERT INTO password_cracks 
                    (case_id, hash_value, hash_type, plaintext, cracking_method,
                     attempts, time_taken, success, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    case_id, crack.hash_value, crack.hash_type, crack.plaintext,
                    crack.cracking_method, crack.attempts, crack.time_taken,
                    crack.success, datetime.now().isoformat()
                ))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde résultats: {e}")
        finally:
            conn.close()
    
    def _generate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère les statistiques d'analyse"""
        stats = {
            'total_crypto_artifacts': len(results.get('crypto_artifacts', [])),
            'total_stegano_artifacts': len(results.get('stegano_artifacts', [])),
            'algorithms_detected': [],
            'encryption_types': [],
            'steganography_methods': [],
            'entropy_stats': {},
            'successful_cracks': 0
        }
        
        # Statistiques des artefacts crypto
        for artifact in results.get('crypto_artifacts', []):
            if artifact.algorithm.value not in stats['algorithms_detected']:
                stats['algorithms_detected'].append(artifact.algorithm.value)
            if artifact.encryption_type.value not in stats['encryption_types']:
                stats['encryption_types'].append(artifact.encryption_type.value)
        
        # Statistiques des artefacts stégano
        for artifact in results.get('stegano_artifacts', []):
            if artifact.method.value not in stats['steganography_methods']:
                stats['steganography_methods'].append(artifact.method.value)
        
        # Statistiques d'entropie
        entropy_analysis = results.get('entropy_analysis', {})
        if entropy_analysis:
            stats['entropy_stats'] = {
                'file_entropy': entropy_analysis.get('file_entropy', 0.0),
                'avg_block_entropy': entropy_analysis.get('avg_entropy', 0.0),
                'encrypted_blocks_ratio': (
                    entropy_analysis.get('encrypted_blocks', 0) / 
                    max(entropy_analysis.get('total_blocks', 1), 1)
                )
            }
        
        # Statistiques de craquage
        stats['successful_cracks'] = sum(
            1 for crack in results.get('password_cracks', []) if crack.success
        )
        
        return stats
    
    def _generate_aggregate_statistics(self, aggregate_results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère les statistiques agrégées pour une analyse de répertoire"""
        all_algorithms = set()
        all_encryption_types = set()
        all_stegano_methods = set()
        total_entropy = 0.0
        entropy_count = 0
        
        for file_results in aggregate_results['file_results'].values():
            file_stats = file_results.get('statistics', {})
            
            all_algorithms.update(file_stats.get('algorithms_detected', []))
            all_encryption_types.update(file_stats.get('encryption_types', []))
            all_stegano_methods.update(file_stats.get('steganography_methods', []))
            
            entropy_stats = file_stats.get('entropy_stats', {})
            if entropy_stats.get('file_entropy'):
                total_entropy += entropy_stats['file_entropy']
                entropy_count += 1
        
        return {
            'unique_algorithms': list(all_algorithms),
            'unique_encryption_types': list(all_encryption_types),
            'unique_steganography_methods': list(all_stegano_methods),
            'average_file_entropy': total_entropy / max(entropy_count, 1),
            'files_with_crypto': len([
                fr for fr in aggregate_results['file_results'].values() 
                if fr.get('crypto_artifacts')
            ]),
            'files_with_steganography': len([
                fr for fr in aggregate_results['file_results'].values() 
                if fr.get('stegano_artifacts')
            ])
        }
    
    def export_results(self, case_id: str, output_file: str, format_type: str = 'json') -> bool:
        """
        Export des résultats d'analyse cryptographique
        
        Args:
            case_id: Identifiant du cas
            output_file: Fichier de sortie
            format_type: Format (json, csv, html)
            
        Returns:
            True si succès
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            if format_type.lower() == 'json':
                # Export JSON complet
                data = {
                    'case_id': case_id,
                    'export_timestamp': datetime.now().isoformat(),
                    'crypto_artifacts': self._get_crypto_artifacts_from_db(conn, case_id),
                    'stegano_artifacts': self._get_stegano_artifacts_from_db(conn, case_id),
                    'password_cracks': self._get_password_cracks_from_db(conn, case_id),
                    'certificate_analysis': self._get_certificates_from_db(conn, case_id)
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                # Export CSV des artefacts crypto
                import csv
                artifacts = self._get_crypto_artifacts_from_db(conn, case_id)
                
                if artifacts:
                    with open(output_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=artifacts[0].keys())
                        writer.writeheader()
                        writer.writerows(artifacts)
            
            conn.close()
            logger.info(f"Résultats exportés vers {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export: {e}")
            return False
    
    def _get_crypto_artifacts_from_db(self, conn, case_id: str) -> List[Dict]:
        """Récupère les artefacts crypto depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM crypto_artifacts WHERE case_id = ?', (case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_stegano_artifacts_from_db(self, conn, case_id: str) -> List[Dict]:
        """Récupère les artefacts stégano depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM stegano_artifacts WHERE case_id = ?', (case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_password_cracks_from_db(self, conn, case_id: str) -> List[Dict]:
        """Récupère les résultats de craquage depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM password_cracks WHERE case_id = ?', (case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def _get_certificates_from_db(self, conn, case_id: str) -> List[Dict]:
        """Récupère les analyses de certificats depuis la DB"""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM certificate_analysis WHERE case_id = ?', (case_id,))
        rows = cursor.fetchall()
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def close(self):
        """Ferme l'analyseur et nettoie les ressources"""
        logger.info("Analyseur cryptographique fermé")


def main():
    """Fonction de démonstration"""
    print("🔒 Forensic Analysis Toolkit - Crypto Analyzer")
    print("=" * 50)
    
    # Exemple d'utilisation
    analyzer = CryptoAnalyzer(evidence_dir="./evidence", temp_dir="./temp")
    
    case_id = f"CRYPTO_CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📋 Cas d'analyse: {case_id}")
    
    # Test sur un fichier exemple (créer un fichier de test)
    test_file = Path("./test_crypto_file.txt")
    
    # Créer un fichier de test avec du contenu cryptographique
    test_content = """
    Fichier de test cryptographique
    Hash MD5: 5d41402abc4b2a76b9719d911017c592
    Hash SHA-1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    Hash SHA-256: 2cf24dba4f21d4288094c50de2c60d9a89a84f1c4d4b2a8b8b7b2c8b2c8b2c8b
    
    -----BEGIN CERTIFICATE-----
    MIICljCCAX4CCQC8X0H9+0O5jDANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC
    VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRQwEgYDVQQK
    DAtUZXN0IENvbXBhbnkxFDASBgNVBAsHC1Rlc3QgVW5pdDEeMBwGA1UEAwwVZXhh
    bXBsZS50ZXN0LWNvbXBhbnkuY29tMB4XDTE5MDEwMTEyMDAwMFoXDTIwMDEwMTEy
    MDAwMFowgY4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNTW91
    bnRhaW4gVmlldzEUMBIGA1UECgwLVGVzdCBDb21wYW55MRQwEgYDVQQLDAtUZXN0
    IFVuaXQxHjAcBgNVBAMMFWV4YW1wbGUudGVzdC1jb21wYW55LmNvbTBcMA0GCSqG
    SIb3DQEBAQUAA0sAMEgCQQC8Q2g/0O5jDANBgkqhkiG9w0BAQsFADCBjjELMAkG
    A1UEBhMCVVMxCzAJBgNVBAgMAkNBMB4XDTE5MDEwMTEyMDAwMFoXDTIwMDEwMTEy
    -----END CERTIFICATE-----
    
    Données potentiellement chiffrées (haute entropie):
    aG2jT9x8vK4nB7mF1qW5eR3pL9s6dF8hG2jT9x8vK4nB7mF1qW5eR3pL9s6dF8h
    """ + "x" * 1000  # Ajouter du contenu pour augmenter l'entropie
    
    try:
        # Créer le fichier de test
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        print(f"📄 Fichier de test créé: {test_file}")
        
        # Analyse du fichier
        print("🔍 Début de l'analyse cryptographique...")
        results = analyzer.analyze_file(test_file, case_id)
        
        # Affichage des résultats
        print("\n📊 Résultats d'analyse:")
        stats = results.get('statistics', {})
        
        print(f"  🔒 Artefacts cryptographiques: {stats.get('total_crypto_artifacts', 0)}")
        print(f"  🖼️ Artefacts stéganographiques: {stats.get('total_stegano_artifacts', 0)}")
        print(f"  🔓 Hashes craqués: {stats.get('successful_cracks', 0)}")
        
        # Détails des algorithmes détectés
        if stats.get('algorithms_detected'):
            print(f"  🔍 Algorithmes détectés: {', '.join(stats['algorithms_detected'])}")
        
        # Entropie du fichier
        entropy_stats = stats.get('entropy_stats', {})
        if entropy_stats:
            print(f"  📈 Entropie du fichier: {entropy_stats.get('file_entropy', 0):.2f}")
            print(f"  📊 Ratio blocs chiffrés: {entropy_stats.get('encrypted_blocks_ratio', 0):.2%}")
        
        # Export des résultats
        output_file = f"./crypto_analysis_{case_id}.json"
        if analyzer.export_results(case_id, output_file, 'json'):
            print(f"📄 Résultats exportés: {output_file}")
        
        # Nettoyage
        test_file.unlink()  # Supprimer le fichier de test
        analyzer.close()
        
    except Exception as e:
        print(f"❌ Erreur durant l'analyse: {e}")
        logger.error(f"Erreur analyse crypto: {e}")
    
    print("\n✅ Démonstration terminée")


if __name__ == "__main__":
    main()