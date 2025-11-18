#!/usr/bin/env python3
"""
Threat Intelligence Platform - Command Line Interface
Simple CLI for testing and interacting with the platform
"""

import argparse
import json
import sys
import os
from datetime import datetime
from typing import Optional

from models import IOC, IOCType, ThreatLevel, Confidence
from processors.correlation_engine import CorrelationEngine
from collectors import OTXCollector, AbuseIPDBCollector


class ThreatIntelCLI:
    """Command-line interface for Threat Intelligence Platform"""

    def __init__(self):
        self.engine = CorrelationEngine()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="Threat Intelligence Platform CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Add IOC command
        add_parser = subparsers.add_parser('add', help='Add new IOC')
        add_parser.add_argument('type', choices=['ip', 'domain', 'url', 'hash', 'email'],
                                help='IOC type')
        add_parser.add_argument('value', help='IOC value')
        add_parser.add_argument('--threat-level', choices=['low', 'medium', 'high', 'critical'],
                                default='medium', help='Threat level')
        add_parser.add_argument('--confidence', choices=['low', 'medium', 'high'],
                                default='medium', help='Confidence level')
        add_parser.add_argument('--tags', nargs='+', help='Tags for the IOC')
        add_parser.add_argument('--description', help='IOC description')

        # Search command
        search_parser = subparsers.add_parser('search', help='Search IOCs')
        search_parser.add_argument('query', help='Search query')
        search_parser.add_argument('--limit', type=int, default=10, help='Maximum results')

        # List command
        list_parser = subparsers.add_parser('list', help='List all IOCs')
        list_parser.add_argument('--type', choices=['ip', 'domain', 'url', 'hash', 'email'],
                                 help='Filter by IOC type')
        list_parser.add_argument('--threat-level', choices=['low', 'medium', 'high', 'critical'],
                                 help='Filter by threat level')
        list_parser.add_argument('--limit', type=int, default=50, help='Maximum results')

        # Related command
        related_parser = subparsers.add_parser('related', help='Find related IOCs')
        related_parser.add_argument('ioc_id', help='IOC ID')
        related_parser.add_argument('--limit', type=int, default=10, help='Maximum results')

        # Score command
        score_parser = subparsers.add_parser('score', help='Calculate threat score')
        score_parser.add_argument('ioc_id', help='IOC ID')

        # Campaigns command
        campaigns_parser = subparsers.add_parser('campaigns', help='Identify threat campaigns')
        campaigns_parser.add_argument('--min-iocs', type=int, default=3,
                                      help='Minimum IOCs per campaign')

        # Stats command
        subparsers.add_parser('stats', help='Show platform statistics')

        # Collect command
        collect_parser = subparsers.add_parser('collect', help='Collect from threat feeds')
        collect_parser.add_argument('source', choices=['otx', 'abuseipdb'],
                                    help='Threat feed source')
        collect_parser.add_argument('--api-key', help='API key (or set env variable)')

        # Export command
        export_parser = subparsers.add_parser('export', help='Export IOCs')
        export_parser.add_argument('output', help='Output file path')
        export_parser.add_argument('--format', choices=['json', 'csv'], default='json',
                                   help='Export format')

        return parser

    def run(self, args=None):
        """Run CLI with arguments"""
        args = self.parser.parse_args(args)

        if not args.command:
            self.parser.print_help()
            return

        # Execute command
        command_method = getattr(self, f'cmd_{args.command}', None)
        if command_method:
            command_method(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)

    def cmd_add(self, args):
        """Add new IOC"""
        ioc = IOC(
            ioc_type=IOCType(args.type),
            value=args.value,
            threat_level=ThreatLevel(args.threat_level),
            confidence=Confidence(args.confidence),
            tags=args.tags or [],
            description=args.description
        )

        self.engine.add_ioc(ioc)

        print(f"✓ IOC added successfully")
        print(f"  ID: {ioc.ioc_id}")
        print(f"  Type: {ioc.ioc_type.value}")
        print(f"  Value: {ioc.value}")
        print(f"  Threat Level: {ioc.threat_level.value}")
        print(f"  Confidence: {ioc.confidence.value}")

    def cmd_search(self, args):
        """Search IOCs"""
        results = self.engine.search(args.query, limit=args.limit)

        print(f"\nSearch results for '{args.query}' ({len(results)} found):\n")

        if not results:
            print("No matching IOCs found.")
            return

        self._print_ioc_table(results)

    def cmd_list(self, args):
        """List all IOCs"""
        all_iocs = list(self.engine.ioc_database.values())

        # Apply filters
        if args.type:
            all_iocs = [ioc for ioc in all_iocs if ioc.ioc_type == IOCType(args.type)]

        if args.threat_level:
            all_iocs = [ioc for ioc in all_iocs if ioc.threat_level == ThreatLevel(args.threat_level)]

        # Limit results
        all_iocs = all_iocs[:args.limit]

        print(f"\nIOC List ({len(all_iocs)} shown):\n")

        if not all_iocs:
            print("No IOCs found.")
            return

        self._print_ioc_table(all_iocs)

    def cmd_related(self, args):
        """Find related IOCs"""
        ioc = self.engine.ioc_database.get(args.ioc_id)

        if not ioc:
            print(f"Error: IOC not found: {args.ioc_id}")
            sys.exit(1)

        related = self.engine.find_related_iocs(ioc, max_results=args.limit)

        print(f"\nIOCs related to {ioc.value} ({len(related)} found):\n")

        if not related:
            print("No related IOCs found.")
            return

        self._print_ioc_table(related)

    def cmd_score(self, args):
        """Calculate threat score"""
        ioc = self.engine.ioc_database.get(args.ioc_id)

        if not ioc:
            print(f"Error: IOC not found: {args.ioc_id}")
            sys.exit(1)

        score = self.engine.calculate_threat_score(ioc)

        print(f"\nThreat Score for {ioc.value}:")
        print(f"  Score: {score:.1f}/100")
        print(f"  Type: {ioc.ioc_type.value}")
        print(f"  Threat Level: {ioc.threat_level.value}")
        print(f"  Confidence: {ioc.confidence.value}")
        print(f"  Sources: {len(ioc.sources)}")
        print(f"  Tags: {', '.join(ioc.tags) if ioc.tags else 'None'}")

    def cmd_campaigns(self, args):
        """Identify threat campaigns"""
        campaigns = self.engine.identify_campaigns(min_iocs=args.min_iocs)

        print(f"\nIdentified Campaigns ({len(campaigns)} found):\n")

        if not campaigns:
            print("No campaigns identified.")
            return

        for i, campaign in enumerate(campaigns, 1):
            print(f"{i}. {campaign['name']}")
            print(f"   IOC Count: {campaign['ioc_count']}")
            print(f"   Threat Level: {campaign['threat_level'].value}")
            print(f"   First Seen: {campaign['first_seen'].strftime('%Y-%m-%d %H:%M')}")
            print(f"   Last Seen: {campaign['last_seen'].strftime('%Y-%m-%d %H:%M')}")
            print(f"   Sample IOCs: {', '.join([ioc.value for ioc in campaign['iocs'][:3]])}")
            print()

    def cmd_stats(self, args):
        """Show platform statistics"""
        stats = self.engine.get_statistics()

        print("\nPlatform Statistics:\n")
        print(f"Total IOCs: {stats['total_iocs']}")
        print()

        print("By Type:")
        for ioc_type, count in stats['by_type'].items():
            print(f"  {ioc_type:12} : {count}")
        print()

        print("By Threat Level:")
        for level, count in stats['by_threat_level'].items():
            print(f"  {level:12} : {count}")
        print()

        print("By Confidence:")
        for conf, count in stats['by_confidence'].items():
            print(f"  {conf:12} : {count}")

    def cmd_collect(self, args):
        """Collect from threat feeds"""
        api_key = args.api_key

        # Try environment variables
        if not api_key:
            if args.source == 'otx':
                api_key = os.getenv('OTX_API_KEY')
            elif args.source == 'abuseipdb':
                api_key = os.getenv('ABUSEIPDB_API_KEY')

        if not api_key:
            print(f"Error: API key required for {args.source}")
            print(f"Provide via --api-key or set environment variable")
            sys.exit(1)

        print(f"Collecting IOCs from {args.source}...")

        try:
            if args.source == 'otx':
                collector = OTXCollector(api_key=api_key)
            elif args.source == 'abuseipdb':
                collector = AbuseIPDBCollector(api_key=api_key)

            iocs = collector.collect()

            # Add to engine
            for ioc in iocs:
                self.engine.add_ioc(ioc)

            print(f"✓ Collected {len(iocs)} IOCs from {args.source}")

        except Exception as e:
            print(f"Error collecting from {args.source}: {e}")
            sys.exit(1)

    def cmd_export(self, args):
        """Export IOCs"""
        all_iocs = list(self.engine.ioc_database.values())

        if args.format == 'json':
            data = {
                'export_date': datetime.now().isoformat(),
                'total_iocs': len(all_iocs),
                'iocs': [ioc.to_dict() for ioc in all_iocs]
            }

            with open(args.output, 'w') as f:
                json.dump(data, f, indent=2)

        elif args.format == 'csv':
            import csv

            with open(args.output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IOC ID', 'Type', 'Value', 'Threat Level', 'Confidence', 'Tags'])

                for ioc in all_iocs:
                    writer.writerow([
                        ioc.ioc_id,
                        ioc.ioc_type.value,
                        ioc.value,
                        ioc.threat_level.value,
                        ioc.confidence.value,
                        ','.join(ioc.tags)
                    ])

        print(f"✓ Exported {len(all_iocs)} IOCs to {args.output}")

    def _print_ioc_table(self, iocs):
        """Print IOCs in table format"""
        print(f"{'Type':<12} {'Value':<40} {'Threat':<10} {'Conf.':<8} {'Tags'}")
        print("-" * 100)

        for ioc in iocs:
            tags_str = ', '.join(ioc.tags[:3]) if ioc.tags else '-'
            if len(tags_str) > 30:
                tags_str = tags_str[:27] + '...'

            print(f"{ioc.ioc_type.value:<12} {ioc.value:<40} "
                  f"{ioc.threat_level.value:<10} {ioc.confidence.value:<8} {tags_str}")


def main():
    """Main entry point"""
    cli = ThreatIntelCLI()
    cli.run()


if __name__ == '__main__':
    main()
