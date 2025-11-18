#!/usr/bin/env python3
"""
Threat Intelligence Correlation Engine
Correlates IOCs across multiple sources and identifies patterns
"""

from typing import List, Dict, Set, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IOC, ThreatActor, Campaign, IOCType, ThreatLevel, Confidence


class CorrelationEngine:
    """Engine for correlating threat intelligence data"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.ioc_database: Dict[str, IOC] = {}
        self.correlation_cache: Dict[str, List[str]] = {}

    def add_ioc(self, ioc: IOC):
        """Add IOC to the correlation database"""
        self.ioc_database[ioc.ioc_id] = ioc

    def add_iocs(self, iocs: List[IOC]):
        """Add multiple IOCs to the database"""
        for ioc in iocs:
            self.add_ioc(ioc)

    def correlate_by_value(self, ioc_value: str) -> List[IOC]:
        """Find all IOCs with the same value"""
        return [
            ioc for ioc in self.ioc_database.values()
            if ioc.value == ioc_value
        ]

    def correlate_by_campaign(self, campaign_name: str) -> List[IOC]:
        """Find all IOCs associated with a campaign"""
        return [
            ioc for ioc in self.ioc_database.values()
            if campaign_name in ioc.campaigns
        ]

    def correlate_by_threat_actor(self, actor_name: str) -> List[IOC]:
        """Find all IOCs associated with a threat actor"""
        return [
            ioc for ioc in self.ioc_database.values()
            if actor_name in ioc.threat_actors
        ]

    def correlate_by_mitre_technique(self, technique_id: str) -> List[IOC]:
        """Find all IOCs associated with a MITRE ATT&CK technique"""
        return [
            ioc for ioc in self.ioc_database.values()
            if technique_id in ioc.mitre_techniques
        ]

    def find_related_iocs(self, ioc: IOC, max_results: int = 50) -> List[IOC]:
        """Find IOCs related to the given IOC"""
        related = []

        # Check cache first
        cache_key = ioc.ioc_id
        if cache_key in self.correlation_cache:
            related_ids = self.correlation_cache[cache_key]
            return [self.ioc_database[iid] for iid in related_ids if iid in self.ioc_database]

        # Find by shared campaigns
        for campaign in ioc.campaigns:
            related.extend(self.correlate_by_campaign(campaign))

        # Find by shared threat actors
        for actor in ioc.threat_actors:
            related.extend(self.correlate_by_threat_actor(actor))

        # Find by shared MITRE techniques
        for technique in ioc.mitre_techniques:
            related.extend(self.correlate_by_mitre_technique(technique))

        # Find by shared tags
        for tag in ioc.tags:
            tag_related = [
                i for i in self.ioc_database.values()
                if tag in i.tags and i.ioc_id != ioc.ioc_id
            ]
            related.extend(tag_related)

        # Remove duplicates and the original IOC
        unique_related = list({i.ioc_id: i for i in related if i.ioc_id != ioc.ioc_id}.values())

        # Sort by relevance (number of shared attributes)
        sorted_related = sorted(
            unique_related,
            key=lambda x: self._calculate_relationship_score(ioc, x),
            reverse=True
        )[:max_results]

        # Cache results
        self.correlation_cache[cache_key] = [i.ioc_id for i in sorted_related]

        return sorted_related

    def _calculate_relationship_score(self, ioc1: IOC, ioc2: IOC) -> int:
        """Calculate how related two IOCs are"""
        score = 0

        # Shared campaigns (high weight)
        shared_campaigns = set(ioc1.campaigns) & set(ioc2.campaigns)
        score += len(shared_campaigns) * 10

        # Shared threat actors (high weight)
        shared_actors = set(ioc1.threat_actors) & set(ioc2.threat_actors)
        score += len(shared_actors) * 8

        # Shared MITRE techniques (medium weight)
        shared_techniques = set(ioc1.mitre_techniques) & set(ioc2.mitre_techniques)
        score += len(shared_techniques) * 5

        # Shared tags (low weight)
        shared_tags = set(ioc1.tags) & set(ioc2.tags)
        score += len(shared_tags) * 2

        # Same type (small weight)
        if ioc1.ioc_type == ioc2.ioc_type:
            score += 1

        return score

    def identify_campaigns(self, min_iocs: int = 3) -> List[Dict]:
        """Identify potential campaigns based on IOC clustering"""
        campaigns = []

        # Group IOCs by shared attributes
        tag_groups = defaultdict(set)
        actor_groups = defaultdict(set)

        for ioc in self.ioc_database.values():
            for tag in ioc.tags:
                tag_groups[tag].add(ioc.ioc_id)

            for actor in ioc.threat_actors:
                actor_groups[actor].add(ioc.ioc_id)

        # Identify clusters
        for tag, ioc_ids in tag_groups.items():
            if len(ioc_ids) >= min_iocs:
                iocs = [self.ioc_database[iid] for iid in ioc_ids]
                campaign = {
                    'name': f"Campaign_{tag}",
                    'ioc_count': len(iocs),
                    'iocs': iocs,
                    'first_seen': min(ioc.first_seen for ioc in iocs),
                    'last_seen': max(ioc.last_seen for ioc in iocs),
                    'threat_level': self._aggregate_threat_level(iocs)
                }
                campaigns.append(campaign)

        return campaigns

    def _aggregate_threat_level(self, iocs: List[IOC]) -> ThreatLevel:
        """Aggregate threat level from multiple IOCs"""
        threat_scores = {
            ThreatLevel.CRITICAL: 5,
            ThreatLevel.HIGH: 4,
            ThreatLevel.MEDIUM: 3,
            ThreatLevel.LOW: 2,
            ThreatLevel.INFO: 1,
            ThreatLevel.UNKNOWN: 0
        }

        if not iocs:
            return ThreatLevel.UNKNOWN

        avg_score = sum(threat_scores[ioc.threat_level] for ioc in iocs) / len(iocs)

        if avg_score >= 4.5:
            return ThreatLevel.CRITICAL
        elif avg_score >= 3.5:
            return ThreatLevel.HIGH
        elif avg_score >= 2.5:
            return ThreatLevel.MEDIUM
        elif avg_score >= 1.5:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO

    def calculate_threat_score(self, ioc: IOC) -> float:
        """Calculate overall threat score for an IOC (0-100)"""
        score = 0.0

        # Base score from threat level
        threat_level_scores = {
            ThreatLevel.CRITICAL: 100,
            ThreatLevel.HIGH: 75,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.LOW: 25,
            ThreatLevel.INFO: 10,
            ThreatLevel.UNKNOWN: 5
        }
        score += threat_level_scores.get(ioc.threat_level, 5) * 0.4

        # Confidence score
        confidence_scores = {
            Confidence.CONFIRMED: 100,
            Confidence.HIGH: 80,
            Confidence.MEDIUM: 60,
            Confidence.LOW: 40,
            Confidence.UNCONFIRMED: 20
        }
        score += confidence_scores.get(ioc.confidence, 20) * 0.3

        # Number of sources (more sources = higher confidence)
        source_score = min(len(ioc.sources) * 10, 50)
        score += source_score * 0.2

        # Recency (newer IOCs may be more relevant)
        age_days = (datetime.now() - ioc.first_seen).days
        recency_score = max(0, 100 - (age_days * 2))
        score += recency_score * 0.1

        return min(100.0, score)

    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics"""
        total_iocs = len(self.ioc_database)

        ioc_types = defaultdict(int)
        threat_levels = defaultdict(int)
        sources = defaultdict(int)

        for ioc in self.ioc_database.values():
            ioc_types[ioc.ioc_type.value] += 1
            threat_levels[ioc.threat_level.value] += 1
            for source in ioc.sources:
                sources[source] += 1

        return {
            'total_iocs': total_iocs,
            'ioc_types': dict(ioc_types),
            'threat_levels': dict(threat_levels),
            'sources': dict(sources),
            'cache_size': len(self.correlation_cache)
        }

    def search(self, query: str, ioc_type: Optional[IOCType] = None,
              threat_level: Optional[ThreatLevel] = None,
              limit: int = 100) -> List[IOC]:
        """Search for IOCs matching criteria"""
        results = []

        for ioc in self.ioc_database.values():
            # Type filter
            if ioc_type and ioc.ioc_type != ioc_type:
                continue

            # Threat level filter
            if threat_level and ioc.threat_level != threat_level:
                continue

            # Text search in value, tags, and description
            if query.lower() in ioc.value.lower():
                results.append(ioc)
            elif any(query.lower() in tag.lower() for tag in ioc.tags):
                results.append(ioc)
            elif ioc.description and query.lower() in ioc.description.lower():
                results.append(ioc)

            if len(results) >= limit:
                break

        return results

    def clear_expired(self) -> int:
        """Remove expired IOCs from the database"""
        expired_count = 0

        expired_ids = [
            ioc_id for ioc_id, ioc in self.ioc_database.items()
            if not ioc.is_valid()
        ]

        for ioc_id in expired_ids:
            del self.ioc_database[ioc_id]
            expired_count += 1

        # Clear correlation cache
        self.correlation_cache.clear()

        return expired_count
