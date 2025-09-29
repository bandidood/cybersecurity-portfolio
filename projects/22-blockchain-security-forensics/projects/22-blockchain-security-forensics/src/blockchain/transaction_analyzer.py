#!/usr/bin/env python3
"""
Blockchain Transaction Analyzer
Advanced multi-chain transaction analysis and tracing capabilities
Author: Blockchain Security Team
Version: 1.0.0
"""

import hashlib
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from web3 import Web3
import bitcoin
import networkx as nx

@dataclass
class TransactionInfo:
    """Structured transaction information"""
    tx_hash: str
    blockchain: str
    from_address: str
    to_address: str
    amount: float
    timestamp: datetime
    block_number: int
    gas_fee: Optional[float] = None
    confirmations: int = 0
    risk_score: float = 0.0
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class AddressProfile:
    """Comprehensive address profile with risk assessment"""
    address: str
    blockchain: str
    balance: float
    transaction_count: int
    first_seen: datetime
    last_seen: datetime
    risk_level: str
    classifications: List[str]
    connected_addresses: List[str]
    total_received: float
    total_sent: float

class BlockchainAnalyzer:
    """Multi-blockchain transaction analysis and investigation platform"""
    
    def __init__(self, config_file: str = None):
        """Initialize blockchain analyzer with configuration"""
        self.supported_chains = ['bitcoin', 'ethereum', 'bsc', 'polygon']
        self.api_keys = {}
        self.web3_providers = {}
        self.transaction_graph = nx.DiGraph()
        self.address_profiles = {}
        self.risk_indicators = self._load_risk_indicators()
        
        if config_file:
            self._load_config(config_file)
        
        self._initialize_providers()
    
    def _load_config(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.api_keys = config.get('api_keys', {})
        except FileNotFoundError:
            print(f"Warning: Config file {config_file} not found. Using default settings.")
    
    def _initialize_providers(self):
        """Initialize blockchain providers and connections"""
        # Ethereum provider
        if 'infura_key' in self.api_keys:
            self.web3_providers['ethereum'] = Web3(
                Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{self.api_keys['infura_key']}")
            )
        
        # BSC provider
        if 'bsc_key' in self.api_keys:
            self.web3_providers['bsc'] = Web3(
                Web3.HTTPProvider("https://bsc-dataseed.binance.org/")
            )
        
        print(f"Initialized providers for {len(self.web3_providers)} blockchains")
    
    def _load_risk_indicators(self) -> Dict[str, Any]:
        """Load risk indicators and threat intelligence"""
        return {
            'known_mixers': [
                '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',  # BitMixer
                '3BMEXqGpG4qxWD8KLwKhtzBhHYrJ2L7C6d',  # CoinJoin
            ],
            'known_exchanges': [
                '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',  # Genesis block
                '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',  # Example exchange
            ],
            'ransomware_addresses': [
                '1BTC...example',  # WannaCry example
                '1ETH...example',  # Ethereum ransomware example
            ],
            'sanctions_lists': {
                'OFAC': [],  # Would be loaded from official sources
                'UN': [],
                'EU': []
            },
            'high_risk_patterns': {
                'rapid_transfers': {'threshold': 100, 'timeframe': 3600},
                'round_numbers': {'precision': 0.001},
                'multiple_outputs': {'threshold': 10}
            }
        }
    
    def analyze_transaction(self, tx_hash: str, blockchain: str = 'ethereum') -> TransactionInfo:
        """Analyze a single transaction in detail"""
        if blockchain not in self.supported_chains:
            raise ValueError(f"Blockchain {blockchain} not supported")
        
        if blockchain == 'ethereum':
            return self._analyze_ethereum_transaction(tx_hash)
        elif blockchain == 'bitcoin':
            return self._analyze_bitcoin_transaction(tx_hash)
        else:
            # Use appropriate analyzer for other chains
            return self._analyze_generic_transaction(tx_hash, blockchain)
    
    def _analyze_ethereum_transaction(self, tx_hash: str) -> TransactionInfo:
        """Analyze Ethereum transaction using Web3"""
        if 'ethereum' not in self.web3_providers:
            raise ValueError("Ethereum provider not configured")
        
        w3 = self.web3_providers['ethereum']
        
        try:
            # Get transaction details
            tx = w3.eth.get_transaction(tx_hash)
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            
            # Get block information for timestamp
            block = w3.eth.get_block(tx['blockNumber'])
            
            # Calculate gas fee
            gas_price = tx.get('gasPrice', 0)
            gas_used = receipt.get('gasUsed', 0)
            gas_fee = w3.from_wei(gas_price * gas_used, 'ether')
            
            # Create transaction info
            tx_info = TransactionInfo(
                tx_hash=tx_hash,
                blockchain='ethereum',
                from_address=tx['from'],
                to_address=tx.get('to', ''),
                amount=float(w3.from_wei(tx['value'], 'ether')),
                timestamp=datetime.fromtimestamp(block['timestamp']),
                block_number=tx['blockNumber'],
                gas_fee=float(gas_fee),
                confirmations=w3.eth.block_number - tx['blockNumber']
            )
            
            # Calculate risk score
            tx_info.risk_score = self._calculate_risk_score(tx_info)
            tx_info.tags = self._generate_transaction_tags(tx_info)
            
            return tx_info
            
        except Exception as e:
            raise Exception(f"Error analyzing Ethereum transaction: {e}")
    
    def _analyze_bitcoin_transaction(self, tx_hash: str) -> TransactionInfo:
        """Analyze Bitcoin transaction using blockchain API"""
        # Use external API service like BlockCypher or similar
        api_url = f"https://api.blockcypher.com/v1/btc/main/txs/{tx_hash}"
        
        try:
            response = requests.get(api_url)
            response.raise_for_status()
            tx_data = response.json()
            
            # Parse Bitcoin transaction data
            inputs_value = sum([inp.get('output_value', 0) for inp in tx_data.get('inputs', [])])
            outputs_value = sum([out.get('value', 0) for out in tx_data.get('outputs', [])])
            
            # Get primary addresses (first input and output)
            from_address = ''
            to_address = ''
            
            if tx_data.get('inputs'):
                from_address = tx_data['inputs'][0].get('addresses', [''])[0]
            if tx_data.get('outputs'):
                to_address = tx_data['outputs'][0].get('addresses', [''])[0]
            
            tx_info = TransactionInfo(
                tx_hash=tx_hash,
                blockchain='bitcoin',
                from_address=from_address,
                to_address=to_address,
                amount=outputs_value / 100000000,  # Convert satoshis to BTC
                timestamp=datetime.fromisoformat(tx_data.get('confirmed', '').replace('Z', '+00:00')),
                block_number=tx_data.get('block_height', 0),
                confirmations=tx_data.get('confirmations', 0)
            )
            
            # Calculate risk score and tags
            tx_info.risk_score = self._calculate_risk_score(tx_info)
            tx_info.tags = self._generate_transaction_tags(tx_info)
            
            return tx_info
            
        except Exception as e:
            raise Exception(f"Error analyzing Bitcoin transaction: {e}")
    
    def _analyze_generic_transaction(self, tx_hash: str, blockchain: str) -> TransactionInfo:
        """Generic transaction analyzer for other blockchains"""
        # Placeholder for other blockchain analyzers
        return TransactionInfo(
            tx_hash=tx_hash,
            blockchain=blockchain,
            from_address='unknown',
            to_address='unknown',
            amount=0.0,
            timestamp=datetime.now(),
            block_number=0
        )
    
    def trace_transaction_flow(self, start_tx: str, blockchain: str = 'ethereum', 
                              max_hops: int = 5) -> Dict[str, Any]:
        """Trace cryptocurrency flow through multiple transactions"""
        flow_graph = nx.DiGraph()
        visited_addresses = set()
        current_level = [(start_tx, 0)]
        
        transactions_analyzed = []
        
        while current_level and max(level for _, level in current_level) < max_hops:
            next_level = []
            
            for tx_hash, level in current_level:
                try:
                    tx_info = self.analyze_transaction(tx_hash, blockchain)
                    transactions_analyzed.append(tx_info)
                    
                    # Add to graph
                    flow_graph.add_node(tx_info.from_address, 
                                       type='address', 
                                       level=level)
                    flow_graph.add_node(tx_info.to_address, 
                                       type='address', 
                                       level=level)
                    flow_graph.add_edge(tx_info.from_address, 
                                       tx_info.to_address, 
                                       tx_hash=tx_hash, 
                                       amount=tx_info.amount,
                                       timestamp=tx_info.timestamp)
                    
                    # Find next transactions from the 'to' address
                    if tx_info.to_address not in visited_addresses:
                        visited_addresses.add(tx_info.to_address)
                        next_txs = self._get_outgoing_transactions(
                            tx_info.to_address, blockchain, limit=5
                        )
                        
                        for next_tx in next_txs:
                            next_level.append((next_tx, level + 1))
                
                except Exception as e:
                    print(f"Error tracing transaction {tx_hash}: {e}")
                    continue
            
            current_level = next_level
        
        return {
            'flow_graph': flow_graph,
            'transactions': transactions_analyzed,
            'total_amount_traced': sum(tx.amount for tx in transactions_analyzed),
            'unique_addresses': len(visited_addresses),
            'analysis_summary': self._generate_flow_summary(flow_graph, transactions_analyzed)
        }
    
    def _get_outgoing_transactions(self, address: str, blockchain: str, 
                                  limit: int = 10) -> List[str]:
        """Get outgoing transactions from an address"""
        if blockchain == 'ethereum':
            return self._get_ethereum_outgoing_transactions(address, limit)
        elif blockchain == 'bitcoin':
            return self._get_bitcoin_outgoing_transactions(address, limit)
        else:
            return []
    
    def _get_ethereum_outgoing_transactions(self, address: str, limit: int) -> List[str]:
        """Get outgoing Ethereum transactions using Etherscan API"""
        if 'etherscan_key' not in self.api_keys:
            return []
        
        api_url = "https://api.etherscan.io/api"
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'sort': 'desc',
            'apikey': self.api_keys['etherscan_key']
        }
        
        try:
            response = requests.get(api_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data['status'] == '1':
                outgoing_txs = [
                    tx['hash'] for tx in data['result'][:limit]
                    if tx['from'].lower() == address.lower()
                ]
                return outgoing_txs
        except Exception as e:
            print(f"Error fetching Ethereum transactions: {e}")
        
        return []
    
    def _get_bitcoin_outgoing_transactions(self, address: str, limit: int) -> List[str]:
        """Get outgoing Bitcoin transactions"""
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/full"
        
        try:
            response = requests.get(api_url, params={'limit': limit})
            response.raise_for_status()
            data = response.json()
            
            outgoing_txs = []
            for tx in data.get('txs', [])[:limit]:
                # Check if this address is in the inputs (outgoing transaction)
                for inp in tx.get('inputs', []):
                    if address in inp.get('addresses', []):
                        outgoing_txs.append(tx['hash'])
                        break
            
            return outgoing_txs
        except Exception as e:
            print(f"Error fetching Bitcoin transactions: {e}")
        
        return []
    
    def analyze_address_profile(self, address: str, blockchain: str = 'ethereum') -> AddressProfile:
        """Create comprehensive address profile with risk assessment"""
        if blockchain == 'ethereum':
            return self._analyze_ethereum_address(address)
        elif blockchain == 'bitcoin':
            return self._analyze_bitcoin_address(address)
        else:
            raise ValueError(f"Address analysis not supported for {blockchain}")
    
    def _analyze_ethereum_address(self, address: str) -> AddressProfile:
        """Analyze Ethereum address profile"""
        if 'ethereum' not in self.web3_providers:
            raise ValueError("Ethereum provider not configured")
        
        w3 = self.web3_providers['ethereum']
        
        try:
            # Get current balance
            balance_wei = w3.eth.get_balance(address)
            balance = float(w3.from_wei(balance_wei, 'ether'))
            
            # Get transaction history using Etherscan API
            transaction_history = self._get_address_transaction_history(address, 'ethereum')
            
            # Calculate statistics
            total_received = sum(tx.amount for tx in transaction_history 
                               if tx.to_address.lower() == address.lower())
            total_sent = sum(tx.amount for tx in transaction_history 
                           if tx.from_address.lower() == address.lower())
            
            # Determine classifications
            classifications = self._classify_address(address, transaction_history)
            
            # Calculate risk level
            risk_level = self._assess_address_risk(address, transaction_history, classifications)
            
            profile = AddressProfile(
                address=address,
                blockchain='ethereum',
                balance=balance,
                transaction_count=len(transaction_history),
                first_seen=min(tx.timestamp for tx in transaction_history) if transaction_history else datetime.now(),
                last_seen=max(tx.timestamp for tx in transaction_history) if transaction_history else datetime.now(),
                risk_level=risk_level,
                classifications=classifications,
                connected_addresses=self._get_connected_addresses(address, transaction_history),
                total_received=total_received,
                total_sent=total_sent
            )
            
            return profile
            
        except Exception as e:
            raise Exception(f"Error analyzing Ethereum address: {e}")
    
    def _analyze_bitcoin_address(self, address: str) -> AddressProfile:
        """Analyze Bitcoin address profile"""
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        
        try:
            response = requests.get(api_url)
            response.raise_for_status()
            data = response.json()
            
            # Get transaction history
            transaction_history = self._get_address_transaction_history(address, 'bitcoin')
            
            # Calculate statistics
            balance = data.get('balance', 0) / 100000000  # Convert to BTC
            total_received = data.get('total_received', 0) / 100000000
            total_sent = data.get('total_sent', 0) / 100000000
            
            # Classifications and risk assessment
            classifications = self._classify_address(address, transaction_history)
            risk_level = self._assess_address_risk(address, transaction_history, classifications)
            
            profile = AddressProfile(
                address=address,
                blockchain='bitcoin',
                balance=balance,
                transaction_count=data.get('n_tx', 0),
                first_seen=datetime.now(),  # Would need API call to get actual first seen
                last_seen=datetime.now(),   # Would need API call to get actual last seen
                risk_level=risk_level,
                classifications=classifications,
                connected_addresses=self._get_connected_addresses(address, transaction_history),
                total_received=total_received,
                total_sent=total_sent
            )
            
            return profile
            
        except Exception as e:
            raise Exception(f"Error analyzing Bitcoin address: {e}")
    
    def _get_address_transaction_history(self, address: str, blockchain: str, 
                                       limit: int = 100) -> List[TransactionInfo]:
        """Get transaction history for an address"""
        # Implementation would fetch transaction history from appropriate APIs
        # This is a simplified placeholder
        return []
    
    def _classify_address(self, address: str, transactions: List[TransactionInfo]) -> List[str]:
        """Classify address based on behavior patterns"""
        classifications = []
        
        # Check against known address databases
        if address in self.risk_indicators['known_mixers']:
            classifications.append('mixer')
        if address in self.risk_indicators['known_exchanges']:
            classifications.append('exchange')
        if address in self.risk_indicators['ransomware_addresses']:
            classifications.append('ransomware')
        
        # Behavioral analysis
        if len(transactions) > 1000:
            classifications.append('high_activity')
        
        if self._has_mixing_pattern(transactions):
            classifications.append('potential_mixer')
        
        if self._has_exchange_pattern(transactions):
            classifications.append('potential_exchange')
        
        return classifications
    
    def _has_mixing_pattern(self, transactions: List[TransactionInfo]) -> bool:
        """Detect mixing service patterns"""
        # Look for patterns typical of mixing services
        # Multiple inputs, multiple outputs, round numbers, etc.
        return False  # Placeholder
    
    def _has_exchange_pattern(self, transactions: List[TransactionInfo]) -> bool:
        """Detect exchange patterns"""
        # Look for patterns typical of exchanges
        # Large number of small transactions, hot/cold wallet patterns, etc.
        return False  # Placeholder
    
    def _assess_address_risk(self, address: str, transactions: List[TransactionInfo], 
                           classifications: List[str]) -> str:
        """Assess overall risk level of an address"""
        risk_score = 0
        
        # High-risk classifications
        if 'ransomware' in classifications:
            risk_score += 100
        if 'mixer' in classifications:
            risk_score += 80
        if 'sanctions_list' in classifications:
            risk_score += 100
        
        # Medium-risk indicators
        if 'high_activity' in classifications:
            risk_score += 30
        if 'potential_mixer' in classifications:
            risk_score += 50
        
        # Transaction pattern analysis
        if self._has_suspicious_patterns(transactions):
            risk_score += 40
        
        if risk_score >= 80:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _has_suspicious_patterns(self, transactions: List[TransactionInfo]) -> bool:
        """Detect suspicious transaction patterns"""
        # Rapid succession of transactions
        # Round number amounts
        # Unusual timing patterns
        return False  # Placeholder
    
    def _get_connected_addresses(self, address: str, 
                               transactions: List[TransactionInfo]) -> List[str]:
        """Get addresses connected to this address"""
        connected = set()
        
        for tx in transactions:
            if tx.from_address.lower() == address.lower():
                connected.add(tx.to_address)
            elif tx.to_address.lower() == address.lower():
                connected.add(tx.from_address)
        
        return list(connected)[:20]  # Limit to top 20 connections
    
    def _calculate_risk_score(self, tx_info: TransactionInfo) -> float:
        """Calculate risk score for a transaction"""
        risk_score = 0.0
        
        # Check against known risky addresses
        if (tx_info.from_address in self.risk_indicators['known_mixers'] or 
            tx_info.to_address in self.risk_indicators['known_mixers']):
            risk_score += 0.8
        
        if (tx_info.from_address in self.risk_indicators['ransomware_addresses'] or 
            tx_info.to_address in self.risk_indicators['ransomware_addresses']):
            risk_score += 1.0
        
        # Check for suspicious amounts (round numbers)
        if abs(tx_info.amount - round(tx_info.amount)) < 0.001:
            risk_score += 0.2
        
        # Large amounts increase risk
        if tx_info.amount > 100:  # Adjust threshold based on cryptocurrency
            risk_score += 0.3
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _generate_transaction_tags(self, tx_info: TransactionInfo) -> List[str]:
        """Generate descriptive tags for a transaction"""
        tags = []
        
        if tx_info.risk_score > 0.7:
            tags.append('high-risk')
        elif tx_info.risk_score > 0.4:
            tags.append('medium-risk')
        
        if tx_info.amount > 100:
            tags.append('large-amount')
        
        if abs(tx_info.amount - round(tx_info.amount)) < 0.001:
            tags.append('round-number')
        
        # Check for known address types
        if (tx_info.from_address in self.risk_indicators['known_exchanges'] or 
            tx_info.to_address in self.risk_indicators['known_exchanges']):
            tags.append('exchange-involved')
        
        return tags
    
    def _generate_flow_summary(self, flow_graph: nx.DiGraph, 
                             transactions: List[TransactionInfo]) -> Dict[str, Any]:
        """Generate summary of transaction flow analysis"""
        return {
            'total_transactions': len(transactions),
            'total_addresses': len(flow_graph.nodes()),
            'total_amount': sum(tx.amount for tx in transactions),
            'average_amount': sum(tx.amount for tx in transactions) / len(transactions) if transactions else 0,
            'high_risk_transactions': len([tx for tx in transactions if tx.risk_score > 0.7]),
            'timespan': {
                'start': min(tx.timestamp for tx in transactions) if transactions else None,
                'end': max(tx.timestamp for tx in transactions) if transactions else None
            },
            'unique_blockchains': list(set(tx.blockchain for tx in transactions))
        }
    
    def generate_investigation_report(self, analysis_results: Dict[str, Any], 
                                    case_id: str) -> Dict[str, Any]:
        """Generate comprehensive investigation report"""
        report = {
            'case_id': case_id,
            'generated_at': datetime.now().isoformat(),
            'analysis_summary': analysis_results.get('analysis_summary', {}),
            'transactions_analyzed': len(analysis_results.get('transactions', [])),
            'total_amount_traced': analysis_results.get('total_amount_traced', 0),
            'risk_assessment': {
                'overall_risk': 'HIGH',  # Would be calculated based on findings
                'high_risk_transactions': 0,
                'suspicious_patterns': [],
                'known_malicious_addresses': []
            },
            'recommendations': [
                'Further investigation required for high-risk addresses',
                'Monitor connected addresses for suspicious activity',
                'Consider reporting to relevant authorities if criminal activity suspected'
            ],
            'technical_details': {
                'blockchains_analyzed': analysis_results.get('analysis_summary', {}).get('unique_blockchains', []),
                'analysis_depth': 'standard',
                'data_sources': ['blockchain_apis', 'threat_intelligence']
            }
        }
        
        return report

    def export_results(self, results: Dict[str, Any], format: str = 'json', 
                      filename: str = None) -> str:
        """Export analysis results in various formats"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"blockchain_analysis_{timestamp}.{format}"
        
        if format == 'json':
            with open(filename, 'w') as f:
                # Convert NetworkX graph to serializable format
                serializable_results = dict(results)
                if 'flow_graph' in serializable_results:
                    graph = serializable_results.pop('flow_graph')
                    serializable_results['flow_graph_nodes'] = list(graph.nodes(data=True))
                    serializable_results['flow_graph_edges'] = list(graph.edges(data=True))
                
                # Convert TransactionInfo objects to dictionaries
                if 'transactions' in serializable_results:
                    serializable_results['transactions'] = [
                        asdict(tx) for tx in serializable_results['transactions']
                    ]
                
                json.dump(serializable_results, f, indent=2, default=str)
        
        return filename

# Example usage and testing
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = BlockchainAnalyzer()
    
    # Example transaction analysis
    try:
        print("🔍 Blockchain Security & Forensics Analyzer")
        print("=" * 50)
        
        # Example Ethereum transaction
        eth_tx = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"
        print(f"Analyzing Ethereum transaction: {eth_tx}")
        
        # This would work with proper API keys configured
        # tx_info = analyzer.analyze_transaction(eth_tx, 'ethereum')
        # print(f"Transaction Amount: {tx_info.amount} ETH")
        # print(f"Risk Score: {tx_info.risk_score}")
        # print(f"Tags: {', '.join(tx_info.tags)}")
        
        print("\n✅ Blockchain analyzer initialized successfully!")
        print("Configure API keys in config file to enable full functionality.")
        
    except Exception as e:
        print(f"❌ Error: {e}")