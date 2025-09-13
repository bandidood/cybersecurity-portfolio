(packet, 'ip') else 'unknown',
                    'dst': packet.ip.dst if hasattr(packet, 'ip') else 'unknown',
                    'size': packet_size,
                    'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'unknown'
                })
    
    def _check_external_communication(self, external_ip: str, packet):
        """Vérification des communications externes"""
        # Log des communications vers l'extérieur pour analyse
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
            port = packet.tcp.dstport
            # Ports suspects pour exfiltration
            suspicious_ports = ['4444', '8080', '8443', '9999']
            if port in suspicious_ports:
                self.suspicious_activities.append({
                    'type': 'suspicious_external_communication',
                    'timestamp': packet.sniff_time,
                    'external_ip': external_ip,
                    'port': port,
                    'protocol': 'TCP'
                })
    
    def _check_port_scan(self, src_ip: str, dst_port: str, timestamp):
        """Détection de scans de ports"""
        # Implémentation simplifiée - à améliorer avec fenêtre temporelle
        scan_key = f"port_scan_{src_ip}"
        if not hasattr(self, '_port_scan_tracker'):
            self._port_scan_tracker = defaultdict(set)
        
        self._port_scan_tracker[scan_key].add(dst_port)
        
        # Si plus de X ports différents depuis la même IP
        if len(self._port_scan_tracker[scan_key]) > self.config['suspicious_thresholds']['port_scan_threshold']:
            self.suspicious_activities.append({
                'type': 'port_scan',
                'timestamp': timestamp,
                'src_ip': src_ip,
                'ports_scanned': len(self._port_scan_tracker[scan_key]),
                'severity': 'high'
            })
    
    def _detect_web_attacks(self, transaction: Dict[str, Any]):
        """Détection d'attaques web"""
        uri = transaction.get('uri', '').lower()
        user_agent = transaction.get('user_agent', '').lower()
        
        # Patterns d'attaque SQL Injection
        sql_patterns = ['union', 'select', 'drop', 'insert', 'delete', 'update', '--', '/*']
        if any(pattern in uri for pattern in sql_patterns):
            self.suspicious_activities.append({
                'type': 'sql_injection_attempt',
                'timestamp': transaction['timestamp'],
                'src_ip': transaction['src_ip'],
                'target': transaction['dst_ip'],
                'uri': transaction['uri'],
                'severity': 'high'
            })
        
        # Patterns XSS
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
        if any(pattern in uri for pattern in xss_patterns):
            self.suspicious_activities.append({
                'type': 'xss_attempt',
                'timestamp': transaction['timestamp'],
                'src_ip': transaction['src_ip'],
                'target': transaction['dst_ip'],
                'uri': transaction['uri'],
                'severity': 'medium'
            })
        
        # Directory Traversal
        if '../' in uri or '..\\' in uri:
            self.suspicious_activities.append({
                'type': 'directory_traversal',
                'timestamp': transaction['timestamp'],
                'src_ip': transaction['src_ip'],
                'target': transaction['dst_ip'],
                'uri': transaction['uri'],
                'severity': 'high'
            })
        
        # User-Agent suspects
        suspicious_agents = ['python', 'wget', 'curl', 'nikto', 'sqlmap', 'nessus']
        if any(agent in user_agent for agent in suspicious_agents):
            self.suspicious_activities.append({
                'type': 'suspicious_user_agent',
                'timestamp': transaction['timestamp'],
                'src_ip': transaction['src_ip'],
                'user_agent': transaction['user_agent'],
                'severity': 'medium'
            })
    
    def _detect_dns_anomalies(self, query: Dict[str, Any], packet):
        """Détection d'anomalies DNS"""
        query_name = query['query_name']
        
        # Domaines malveillants connus
        if query_name in self.malicious_domains:
            self.threat_indicators.append({
                'type': 'malicious_domain',
                'timestamp': query['timestamp'],
                'src_ip': query['src_ip'],
                'domain': query_name,
                'severity': 'high'
            })
        
        # Requêtes DNS anormalement longues (possible tunneling)
        if len(query_name) > self.config['suspicious_thresholds']['dns_query_length']:
            self.suspicious_activities.append({
                'type': 'dns_tunneling_suspected',
                'timestamp': query['timestamp'],
                'src_ip': query['src_ip'],
                'domain': query_name,
                'length': len(query_name),
                'severity': 'medium'
            })
        
        # Détection de DGA (Domain Generation Algorithm)
        if self._is_dga_domain(query_name):
            self.suspicious_activities.append({
                'type': 'dga_domain_suspected',
                'timestamp': query['timestamp'],
                'src_ip': query['src_ip'],
                'domain': query_name,
                'severity': 'medium'
            })
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Détection heuristique de domaines DGA"""
        # Logique simplifiée - à améliorer avec ML
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        subdomain = parts[0]
        
        # Critères suspects :
        # - Longueur anormale
        if len(subdomain) > 20 or len(subdomain) < 6:
            return True
        
        # - Ratio consonnes/voyelles anormal
        vowels = 'aeiou'
        vowel_count = sum(1 for c in subdomain.lower() if c in vowels)
        consonant_count = sum(1 for c in subdomain.lower() if c.isalpha() and c not in vowels)
        
        if vowel_count == 0 or consonant_count / vowel_count > 5:
            return True
        
        # - Caractères numériques dans le domaine
        if any(c.isdigit() for c in subdomain):
            return True
        
        return False
    
    def _post_analysis(self):
        """Post-traitement après analyse de tous les paquets"""
        # Calcul des statistiques globales
        self.statistics = {
            'total_packets': self.packets_count,
            'protocols_count': len(self.protocols),
            'conversations_count': len(self.conversations),
            'suspicious_activities': len(self.suspicious_activities),
            'threat_indicators': len(self.threat_indicators),
            'http_transactions': len(self.http_transactions),
            'dns_queries': len(self.dns_queries),
            'tcp_sessions': len(self.tcp_sessions)
        }
        
        # Analyse des sessions TCP longues
        for stream_id, session in self.tcp_sessions.items():
            if 'start_time' in session and 'last_seen' in session:
                duration = (session['last_seen'] - session['start_time']).total_seconds()
                session['duration'] = duration
                
                if duration > self.config['suspicious_thresholds']['session_duration']:
                    self.suspicious_activities.append({
                        'type': 'long_tcp_session',
                        'stream_id': stream_id,
                        'duration': duration,
                        'bytes_transferred': session['bytes'],
                        'severity': 'medium'
                    })
        
        # Top des conversations par volume
        conversation_volumes = {}
        for conv, packets in self.conversations.items():
            total_bytes = sum(p['size'] for p in packets)
            conversation_volumes[conv] = total_bytes
        
        self.statistics['top_conversations'] = dict(
            Counter(conversation_volumes).most_common(10)
        )
    
    def _generate_report(self) -> Dict[str, Any]:
        """Génération du rapport d'analyse complet"""
        report = {
            'analysis_metadata': {
                'file': self.pcap_file,
                'analysis_time': datetime.now().isoformat(),
                'analyzer_version': '2.0',
                'config': self.config
            },
            'statistics': self.statistics,
            'protocol_distribution': dict(self.protocols.most_common()),
            'top_conversations': self.statistics.get('top_conversations', {}),
            'suspicious_activities': self.suspicious_activities,
            'threat_indicators': self.threat_indicators,
            'http_analysis': self._analyze_http_traffic(),
            'dns_analysis': self._analyze_dns_traffic(),
            'tcp_analysis': self._analyze_tcp_traffic(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _analyze_http_traffic(self) -> Dict[str, Any]:
        """Analyse spécialisée du trafic HTTP"""
        if not self.http_transactions:
            return {}
        
        methods = Counter()
        status_codes = Counter()
        user_agents = Counter()
        hosts = Counter()
        
        for transaction in self.http_transactions:
            if transaction.get('type') == 'request':
                methods[transaction.get('method', 'unknown')] += 1
                user_agents[transaction.get('user_agent', 'unknown')] += 1
                hosts[transaction.get('host', 'unknown')] += 1
            elif transaction.get('type') == 'response':
                status_codes[transaction.get('status_code', 'unknown')] += 1
        
        return {
            'total_transactions': len(self.http_transactions),
            'methods_distribution': dict(methods.most_common()),
            'status_codes_distribution': dict(status_codes.most_common()),
            'top_user_agents': dict(user_agents.most_common(10)),
            'top_hosts': dict(hosts.most_common(10))
        }
    
    def _analyze_dns_traffic(self) -> Dict[str, Any]:
        """Analyse spécialisée du trafic DNS"""
        if not self.dns_queries:
            return {}
        
        query_types = Counter()
        top_domains = Counter()
        response_codes = Counter()
        
        for query in self.dns_queries:
            query_types[query.get('query_type', 'unknown')] += 1
            top_domains[query.get('query_name', 'unknown')] += 1
            response_codes[query.get('response_code', 'unknown')] += 1
        
        return {
            'total_queries': len(self.dns_queries),
            'query_types_distribution': dict(query_types.most_common()),
            'top_domains': dict(top_domains.most_common(20)),
            'response_codes_distribution': dict(response_codes.most_common())
        }
    
    def _analyze_tcp_traffic(self) -> Dict[str, Any]:
        """Analyse spécialisée du trafic TCP"""
        if not self.tcp_sessions:
            return {}
        
        session_durations = []
        session_volumes = []
        
        for session in self.tcp_sessions.values():
            if 'duration' in session:
                session_durations.append(session['duration'])
            session_volumes.append(session['bytes'])
        
        return {
            'total_sessions': len(self.tcp_sessions),
            'avg_session_duration': sum(session_durations) / len(session_durations) if session_durations else 0,
            'avg_session_volume': sum(session_volumes) / len(session_volumes) if session_volumes else 0,
            'max_session_duration': max(session_durations) if session_durations else 0,
            'max_session_volume': max(session_volumes) if session_volumes else 0
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Génération de recommandations basées sur l'analyse"""
        recommendations = []
        
        # Recommandations basées sur les activités suspectes
        if self.suspicious_activities:
            activity_types = Counter(activity['type'] for activity in self.suspicious_activities)
            
            for activity_type, count in activity_types.items():
                if activity_type == 'sql_injection_attempt':
                    recommendations.append({
                        'priority': 'high',
                        'category': 'web_security',
                        'title': 'Tentatives d\'injection SQL détectées',
                        'description': f'{count} tentative(s) d\'injection SQL identifiée(s)',
                        'action': 'Vérifier les logs applicatifs, mettre à jour le WAF, patcher les applications'
                    })
                
                elif activity_type == 'port_scan':
                    recommendations.append({
                        'priority': 'medium',
                        'category': 'network_security',
                        'title': 'Activité de scan de ports',
                        'description': f'{count} scan(s) de ports détecté(s)',
                        'action': 'Analyser les IPs sources, renforcer la détection d\'intrusion'
                    })
        
        # Recommandations basées sur les indicateurs de menace
        if self.threat_indicators:
            recommendations.append({
                'priority': 'high',
                'category': 'threat_intelligence',
                'title': 'Indicateurs de menace détectés',
                'description': f'{len(self.threat_indicators)} indicateur(s) de menace identifié(s)',
                'action': 'Bloquer les IPs/domaines malveillants, analyser l\'impact'
            })
        
        # Recommandations générales
        if self.statistics.get('tcp_sessions', 0) > 10000:
            recommendations.append({
                'priority': 'low',
                'category': 'performance',
                'title': 'Nombre élevé de sessions TCP',
                'description': 'Volume important de connexions détecté',
                'action': 'Surveiller les performances réseau et serveurs'
            })
        
        return recommendations
    
    def export_report(self, report: Dict[str, Any], output_dir: str = "./reports"):
        """Export du rapport en différents formats"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"network_analysis_{timestamp}"
        
        # Export JSON
        if 'json' in self.config['export_formats']:
            json_file = os.path.join(output_dir, f"{base_filename}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str, ensure_ascii=False)
            logger.info(f"Rapport JSON exporté: {json_file}")
        
        # Export CSV (activités suspectes)
        if 'csv' in self.config['export_formats']:
            csv_file = os.path.join(output_dir, f"{base_filename}_suspicious.csv")
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                if self.suspicious_activities:
                    fieldnames = self.suspicious_activities[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.suspicious_activities)
            logger.info(f"Rapport CSV exporté: {csv_file}")
        
        # Export HTML (rapport formaté)
        if 'html' in self.config['export_formats']:
            html_file = os.path.join(output_dir, f"{base_filename}.html")
            self._export_html_report(report, html_file)
            logger.info(f"Rapport HTML exporté: {html_file}")
    
    def _export_html_report(self, report: Dict[str, Any], filename: str):
        """Export du rapport en format HTML"""
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Analyse Réseau</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .suspicious {{ background-color: #fff3cd; border-color: #ffeaa7; }}
        .threat {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .high {{ color: #dc3545; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Rapport d'Analyse de Trafic Réseau</h1>
        <p>Fichier analysé: {report['analysis_metadata']['file']}</p>
        <p>Date d'analyse: {report['analysis_metadata']['analysis_time']}</p>
    </div>
    
    <div class="section">
        <h2>📊 Statistiques Générales</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>{report['statistics']['total_packets']:,}</h3>
                <p>Paquets analysés</p>
            </div>
            <div class="stat-card">
                <h3>{report['statistics']['protocols_count']}</h3>
                <p>Protocoles détectés</p>
            </div>
            <div class="stat-card">
                <h3>{report['statistics']['conversations_count']}</h3>
                <p>Conversations réseau</p>
            </div>
            <div class="stat-card suspicious">
                <h3>{report['statistics']['suspicious_activities']}</h3>
                <p>Activités suspectes</p>
            </div>
            <div class="stat-card threat">
                <h3>{report['statistics']['threat_indicators']}</h3>
                <p>Indicateurs de menace</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🚨 Activités Suspectes</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Détails</th>
                    <th>Sévérité</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for activity in report['suspicious_activities'][:20]:  # Top 20
            severity_class = activity.get('severity', 'low')
            html_content += f"""
                <tr>
                    <td>{activity.get('type', 'N/A')}</td>
                    <td>{activity.get('timestamp', 'N/A')}</td>
                    <td>{activity.get('src_ip', activity.get('src', 'N/A'))}</td>
                    <td>{activity.get('uri', activity.get('details', 'N/A'))}</td>
                    <td class="{severity_class}">{severity_class.upper()}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>📈 Distribution des Protocoles</h2>
        <table>
            <thead>
                <tr><th>Protocole</th><th>Nombre de paquets</th><th>Pourcentage</th></tr>
            </thead>
            <tbody>
"""
        
        total_packets = sum(report['protocol_distribution'].values())
        for protocol, count in list(report['protocol_distribution'].items())[:10]:
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            html_content += f"""
                <tr>
                    <td>{protocol}</td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>💡 Recommandations</h2>
        <ul>
"""
        
        for rec in report['recommendations']:
            priority_class = rec.get('priority', 'low')
            html_content += f"""
            <li class="{priority_class}">
                <strong>[{rec.get('priority', 'LOW').upper()}]</strong> 
                {rec.get('title', 'N/A')}: {rec.get('description', 'N/A')}
                <br><em>Action recommandée: {rec.get('action', 'N/A')}</em>
            </li>
"""
        
        html_content += """
        </ul>
    </div>
    
    <div class="section">
        <h2>🔧 Métadonnées d'Analyse</h2>
        <p><strong>Version de l'analyseur:</strong> """ + report['analysis_metadata']['analyzer_version'] + """</p>
        <p><strong>Configuration:</strong> Seuils personnalisés appliqués</p>
        <p><strong>Couverture:</strong> """ + str(report['statistics']['total_packets']) + """ paquets analysés</p>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

def main():
    """Fonction principale avec interface en ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Analyseur de trafic réseau professionnel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python3 advanced_analyzer.py capture.pcap
  python3 advanced_analyzer.py --config config.json --output ./reports capture.pcap
  python3 advanced_analyzer.py --no-threat-intel --formats json,csv capture.pcap
        """
    )
    
    parser.add_argument('pcap_file', help='Fichier de capture à analyser (.pcap)')
    parser.add_argument('--config', '-c', help='Fichier de configuration JSON')
    parser.add_argument('--output', '-o', default='./reports', help='Répertoire de sortie')
    parser.add_argument('--formats', default='json,csv,html', 
                       help='Formats d\'export (json,csv,html)')
    parser.add_argument('--max-packets', type=int, default=1000000,
                       help='Nombre maximum de paquets à analyser')
    parser.add_argument('--no-threat-intel', action='store_true',
                       help='Désactiver la corrélation threat intelligence')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Vérification du fichier
    if not os.path.exists(args.pcap_file):
        logger.error(f"Fichier non trouvé: {args.pcap_file}")
        sys.exit(1)
    
    # Configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Mise à jour de la configuration avec les arguments
    config.update({
        'max_packets': args.max_packets,
        'threat_intel': not args.no_threat_intel,
        'export_formats': args.formats.split(',')
    })
    
    # Analyse
    analyzer = NetworkAnalyzer(args.pcap_file, config)
    
    if not PYSHARK_AVAILABLE:
        logger.error("pyshark requis. Installation: pip3 install pyshark")
        sys.exit(1)
    
    try:
        report = analyzer.analyze()
        
        if report:
            # Export des résultats
            analyzer.export_report(report, args.output)
            
            # Affichage du résumé
            print("\n" + "="*60)
            print("📊 RÉSUMÉ DE L'ANALYSE")
            print("="*60)
            print(f"Paquets analysés: {report['statistics']['total_packets']:,}")
            print(f"Protocoles détectés: {report['statistics']['protocols_count']}")
            print(f"Conversations: {report['statistics']['conversations_count']}")
            print(f"Activités suspectes: {report['statistics']['suspicious_activities']}")
            print(f"Indicateurs de menace: {report['statistics']['threat_indicators']}")
            
            if report['suspicious_activities']:
                print(f"\n🚨 ALERTES DE SÉCURITÉ:")
                for activity in report['suspicious_activities'][:5]:
                    severity = activity.get('severity', 'unknown').upper()
                    activity_type = activity.get('type', 'unknown')
                    print(f"  [{severity}] {activity_type}")
            
            print(f"\n📁 Rapports générés dans: {args.output}")
            
        else:
            logger.error("Échec de l'analyse")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
