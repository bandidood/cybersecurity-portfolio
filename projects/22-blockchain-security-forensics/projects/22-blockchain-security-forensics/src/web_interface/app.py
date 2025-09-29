#!/usr/bin/env python3
"""
Blockchain Security Dashboard
Web interface for blockchain security analysis and forensics
Author: Blockchain Security Team
Version: 1.0.0
"""

from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from flask_socketio import SocketIO, emit
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any
import plotly.graph_objs as go
import plotly.utils
import pandas as pd

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from src.blockchain.transaction_analyzer import BlockchainAnalyzer
from src.forensics.crypto_investigator import CryptocurrencyForensics
from src.smart_contracts.vulnerability_scanner import SmartContractScanner

app = Flask(__name__)
app.secret_key = 'blockchain_security_dashboard_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize analyzers
blockchain_analyzer = BlockchainAnalyzer()
crypto_forensics = CryptocurrencyForensics()
contract_scanner = SmartContractScanner()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    # Get overview statistics
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/transaction-analysis')
def transaction_analysis():
    """Transaction analysis page"""
    return render_template('transaction_analysis.html')

@app.route('/api/analyze-transaction', methods=['POST'])
def analyze_transaction():
    """API endpoint to analyze a single transaction"""
    data = request.get_json()
    tx_hash = data.get('tx_hash')
    blockchain = data.get('blockchain', 'ethereum')
    
    if not tx_hash:
        return jsonify({'error': 'Transaction hash is required'}), 400
    
    try:
        # This would normally analyze the real transaction
        # For demo purposes, we'll return mock data
        analysis_result = {
            'tx_hash': tx_hash,
            'blockchain': blockchain,
            'from_address': '0x742d35Cc6634C0532925a3b8D0baa8A8b4D3e3b',
            'to_address': '0x1234567890AbCdEf1234567890aBcDeF12345678',
            'amount': 1.5,
            'timestamp': datetime.now().isoformat(),
            'block_number': 18500000,
            'gas_fee': 0.002,
            'confirmations': 15,
            'risk_score': 0.3,
            'tags': ['medium-risk', 'exchange-involved'],
            'analysis': {
                'is_suspicious': False,
                'risk_factors': ['Large amount'],
                'recommendations': ['Monitor recipient address']
            }
        }
        
        return jsonify({
            'success': True,
            'data': analysis_result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/forensics')
def forensics():
    """Cryptocurrency forensics page"""
    return render_template('forensics.html')

@app.route('/api/create-case', methods=['POST'])
def create_case():
    """Create a new forensics investigation case"""
    data = request.get_json()
    
    case_type = data.get('case_type')
    victim_addresses = data.get('victim_addresses', [])
    estimated_loss = data.get('estimated_loss', 0.0)
    currency = data.get('currency', 'BTC')
    
    try:
        case_id = crypto_forensics.create_case(
            case_type=case_type,
            victim_addresses=victim_addresses,
            crime_date=datetime.now(),
            estimated_loss=estimated_loss,
            currency=currency
        )
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'message': f'Case {case_id} created successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigate-ransomware', methods=['POST'])
def investigate_ransomware():
    """Investigate ransomware payments"""
    data = request.get_json()
    victim_addresses = data.get('victim_addresses', [])
    case_id = data.get('case_id')
    
    try:
        # This would normally perform real analysis
        # For demo purposes, returning mock investigation results
        investigation_results = {
            'case_id': case_id or f"CASE-{datetime.now().strftime('%Y%m%d')}-0001",
            'payments_found': [
                {
                    'tx_hash': 'abc123def456',
                    'from_address': victim_addresses[0] if victim_addresses else 'unknown',
                    'to_address': '1RansomExampleAddress123456789',
                    'amount': 0.5,
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 0.9
                }
            ],
            'suspect_addresses': ['1RansomExampleAddress123456789'],
            'total_paid': 0.5,
            'ransomware_family': 'conti',
            'recovery_addresses': [
                {
                    'type': 'exchange_seizure',
                    'exchange': 'binance',
                    'address': '1BinanceHotWallet123456789',
                    'amount': 0.3,
                    'feasibility': 'high'
                }
            ]
        }
        
        return jsonify({
            'success': True,
            'data': investigation_results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/smart-contracts')
def smart_contracts():
    """Smart contract analysis page"""
    return render_template('smart_contracts.html')

@app.route('/api/scan-contract', methods=['POST'])
def scan_contract():
    """Scan smart contract for vulnerabilities"""
    data = request.get_json()
    source_code = data.get('source_code')
    contract_name = data.get('contract_name', 'Unknown')
    contract_address = data.get('contract_address', '')
    
    if not source_code:
        return jsonify({'error': 'Source code is required'}), 400
    
    try:
        # Perform actual contract analysis
        analysis = contract_scanner.scan_contract(source_code, contract_name, contract_address)
        report = contract_scanner.generate_report(analysis)
        
        return jsonify({
            'success': True,
            'data': report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/monitoring')
def monitoring():
    """Real-time monitoring page"""
    return render_template('monitoring.html')

@app.route('/api/monitoring-data')
def monitoring_data():
    """Get real-time monitoring data"""
    # Mock real-time data
    data = {
        'timestamp': datetime.now().isoformat(),
        'active_addresses': 15420,
        'transactions_per_minute': 847,
        'suspicious_activities': 12,
        'risk_alerts': [
            {
                'id': 'ALERT-001',
                'type': 'high_value_transfer',
                'address': '0x1234...5678',
                'amount': 100.5,
                'timestamp': datetime.now().isoformat(),
                'risk_level': 'HIGH'
            },
            {
                'id': 'ALERT-002',
                'type': 'mixer_usage',
                'address': '0x9876...4321',
                'amount': 5.2,
                'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
                'risk_level': 'MEDIUM'
            }
        ],
        'blockchain_stats': {
            'bitcoin': {
                'block_height': 815420,
                'transactions_today': 285000,
                'average_fee': 0.0003
            },
            'ethereum': {
                'block_height': 18500000,
                'transactions_today': 1200000,
                'average_gas_price': 25
            }
        }
    }
    
    return jsonify(data)

@app.route('/reports')
def reports():
    """Investigation reports page"""
    return render_template('reports.html')

@app.route('/api/generate-report/<case_id>')
def generate_report(case_id):
    """Generate investigation report for a case"""
    try:
        if case_id in crypto_forensics.cases:
            report = crypto_forensics.generate_forensic_report(case_id)
            return jsonify({
                'success': True,
                'data': report
            })
        else:
            return jsonify({'error': 'Case not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export-report/<case_id>')
def export_report(case_id):
    """Export investigation report"""
    try:
        if case_id in crypto_forensics.cases:
            filename = crypto_forensics.export_case_data(case_id)
            return jsonify({
                'success': True,
                'filename': filename,
                'download_url': f'/downloads/{filename}'
            })
        else:
            return jsonify({'error': 'Case not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to Blockchain Security Dashboard'})
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('subscribe_monitoring')
def handle_monitoring_subscription():
    """Handle monitoring data subscription"""
    # In a real implementation, this would start pushing real-time data
    # For now, we'll just acknowledge the subscription
    emit('monitoring_subscribed', {'status': 'subscribed'})

def get_dashboard_stats():
    """Get dashboard overview statistics"""
    return {
        'total_transactions_analyzed': 125420,
        'active_cases': 8,
        'contracts_scanned': 1247,
        'threats_detected': 156,
        'recovery_amount': 45.7,  # BTC
        'last_24h_alerts': 23,
        'risk_distribution': {
            'critical': 12,
            'high': 34,
            'medium': 89,
            'low': 21
        }
    }

def create_transaction_flow_chart(flow_data):
    """Create transaction flow visualization"""
    # Create nodes and edges for network graph
    nodes = []
    edges = []
    
    # This would process actual flow data
    # For demo, creating a simple example
    
    fig = go.Figure(data=[go.Scatter(
        x=[1, 2, 3, 4],
        y=[1, 2, 1, 2],
        mode='markers+lines+text',
        text=['Address A', 'Address B', 'Address C', 'Address D'],
        textposition="top center"
    )])
    
    fig.update_layout(
        title="Transaction Flow Analysis",
        xaxis_title="Flow Direction",
        yaxis_title="Transaction Level"
    )
    
    return plotly.utils.PlotlyJSONEncoder().encode(fig)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("🌐 Starting Blockchain Security Dashboard...")
    print("=" * 50)
    print("Dashboard URL: http://localhost:5000")
    print("Features available:")
    print("- Transaction Analysis")
    print("- Cryptocurrency Forensics")
    print("- Smart Contract Scanning")
    print("- Real-time Monitoring")
    print("- Investigation Reports")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)