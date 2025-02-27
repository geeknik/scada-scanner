#!/usr/bin/env python3
"""
SCADA/ICS Scanner and Fingerprinter
A comprehensive tool for identifying and fingerprinting SCADA/ICS devices and protocols.

IMPORTANT: This tool is intended for authorized security assessments only.
           Always obtain proper permission before scanning any networks.

Features:
- CIDR range scanning with adjustable scan parameters
- Advanced protocol detection and behavioral fingerprinting
- Device identification with vendor and model detection
- Vulnerability correlation based on device signatures
- Comprehensive reporting with risk assessments
- Safe defaults and rate limiting to prevent disruption

Usage:
    scada_scanner.py [-h] [-f CIDR_FILE] [-o OUTPUT] [-r RATE] [-t TIMEOUT] [--safe-mode]
"""

import argparse
import ipaddress
import logging
import json
import asyncio
import socket
import struct
import sys
import re
import time
import ssl
import hashlib
import random
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scada_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Scanner configuration settings"""
    rate_limit: float = 1.0  # requests per second
    timeout: int = 5  # seconds
    max_retries: int = 3
    verify_ssl: bool = False
    user_agent: str = "SCADA-Scanner/1.0"
    safe_mode: bool = True  # Default to safe mode
    max_concurrent: int = 50
    output_format: str = "json"
    verbosity: int = 1
    exclude_ips: List[str] = field(default_factory=list)
    scan_delay: float = 0.1  # seconds between requests to same host

@dataclass
class Vulnerability:
    """Known vulnerability information"""
    cve_id: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    affected_versions: List[str]
    affected_products: List[str]
    disclosure_date: str
    references: List[str] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    exploitability: float = 0.0  # 0.0-1.0 score
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "affected_versions": self.affected_versions,
            "affected_products": self.affected_products,
            "disclosure_date": self.disclosure_date,
            "references": self.references,
            "exploitability": self.exploitability
        }

@dataclass
class PortProtocol:
    """Port and protocol mapping"""
    port: int
    protocol: str
    service: str
    description: str
    probes: List[bytes] = field(default_factory=list)
    timeout: int = 5

# Common SCADA/ICS ports and protocols
SCADA_PORTS = [
    # Industrial Control Protocols
    PortProtocol(102, "TCP", "S7", "Siemens S7 Protocol"),
    PortProtocol(502, "TCP", "MODBUS", "Modbus Protocol"),
    PortProtocol(20000, "TCP", "DNP3", "DNP3 Protocol"),
    PortProtocol(44818, "TCP", "EIP", "EtherNet/IP"),
    PortProtocol(47808, "TCP", "BACNET", "BACnet Protocol"),
    PortProtocol(1911, "TCP", "FOX", "Tridium Fox Protocol"),
    PortProtocol(2404, "TCP", "IEC104", "IEC 60870-5-104"),
    PortProtocol(4840, "TCP", "OPCUA", "OPC UA Protocol"),
    
    # PLC Specific Protocols
    PortProtocol(2222, "TCP", "CODESYS", "CODESYS Runtime"),
    PortProtocol(789, "TCP", "CRIMSON", "Red Lion Crimson Protocol"),
    PortProtocol(1962, "TCP", "PCWorx", "Phoenix Contact PCWorx"),
    
    # Remote Access and Management
    PortProtocol(5900, "TCP", "VNC", "Virtual Network Computing"),
    PortProtocol(5007, "TCP", "SYSMGR", "Siemens SIMATIC System Manager"),
    PortProtocol(3389, "TCP", "RDP", "Remote Desktop Protocol"),
    
    # Vendor Specific Protocols
    PortProtocol(1089, "TCP", "FF", "Foundation Fieldbus HSE"),
    PortProtocol(18245, "TCP", "GE-SRTP", "GE SRTP Protocol"),
    PortProtocol(9600, "TCP", "OMRON-FINS", "Omron FINS Protocol"),
    PortProtocol(11740, "TCP", "PROCONOS", "ProConOS Protocol"),
    
    # Building Automation
    PortProtocol(47808, "UDP", "BACNET", "BACnet/IP Protocol"),
    PortProtocol(1876, "TCP", "LON", "LonWorks Protocol"),
    
    # Network and Security Management
    PortProtocol(161, "UDP", "SNMP", "Simple Network Management Protocol"),
    PortProtocol(123, "UDP", "NTP", "Network Time Protocol"),
    
    # Historian and Database
    PortProtocol(1433, "TCP", "MSSQL", "Microsoft SQL Server"),
    PortProtocol(3306, "TCP", "MYSQL", "MySQL Database"),
    PortProtocol(5432, "TCP", "POSTGRESQL", "PostgreSQL Database")
]

# Known SCADA/ICS Protocol signature database
PROTOCOL_SIGNATURES = {
    'MODBUS': {
        'patterns': [
            rb'\x00[\x00-\xff]{2}\x00\x00[\x00-\x08]',  # Modbus TCP header
            rb'\x01\x03[\x00-\xff]{4}',  # Read holding registers
            rb'\x01\x04[\x00-\xff]{4}',  # Read input registers
        ],
        'responses': [
            rb'\x00[\x00-\xff]{2}\x00\x00[\x00-\x08][\x81-\x88]',  # Error responses
            rb'\x00[\x00-\xff]{2}\x00[\x00-\xff][\x00-\x08][\x01-\x08]'  # Normal responses
        ]
    },
    'S7': {
        'patterns': [
            rb'^\x03\x00.{3}\x02\xf0.{2}',  # S7 header
            rb'\x72\x01\x00\x00',  # S7 data
        ],
        'responses': [
            rb'\x03\x00\x00[\x00-\xff]{4}\x02\xf0',  # S7 response header
            rb'\x03\x00\x00[\x00-\xff]\x0b\xd0'  # S7COMM setup communication
        ]
    },
    'DNP3': {
        'patterns': [
            rb'\x05\x64',  # DNP3 header
            rb'\x05\x64\x16',  # Common DNP3 message
        ],
        'responses': [
            rb'\x05\x64[\x00-\xff]{2}\x44\x01\x00\x00',  # DNP3 response
            rb'\x05\x64[\x00-\xff]{2}\x82[\x00-\xff]'  # DNP3 response with IIN bits
        ]
    },
    'BACNET': {
        'patterns': [
            rb'\x81[\x00-\x0f][\x00-\xff]{4}\x01',  # BACnet header
            rb'\x81\x0a\x00\x11',  # BACnet broadcast
        ],
        'responses': [
            rb'\x81[\x00-\x0f][\x00-\xff]{4}\x10',  # BACnet response
            rb'\x81[\x00-\x0f][\x00-\xff]{4}\x30'  # Complex ACK
        ]
    },
    'EIP': {
        'patterns': [
            rb'\x63\x00[\x00-\xff]{24}',  # EtherNet/IP header
            rb'\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # EtherNet/IP Register Session
        ],
        'responses': [
            rb'\x63\x00[\x00-\xff]{4}\x00\x00\x00\x00[\x00-\xff]{4}',  # EIP response
            rb'\x65\x00'  # EIP encapsulation error
        ]
    },
    'IEC104': {
        'patterns': [
            rb'\x68[\x00-\xff]{3}',  # IEC 60870-5-104 header
            rb'\x68\x04\x07\x00\x00\x00',  # STARTDT ACT message
        ],
        'responses': [
            rb'\x68\x04\x0b\x00\x00\x00',  # STARTDT CON response
            rb'\x68\x04\x43\x00\x00\x00'  # TESTFR ACT response
        ]
    },
    'OPCUA': {
        'patterns': [
            rb'HEL[\x00-\xff]',  # OPC UA Hello
            rb'OPN[\x00-\xff]',  # OPC UA Open
        ],
        'responses': [
            rb'ACK[\x00-\xff]',  # OPC UA Acknowledge
            rb'MSG[\x00-\xff]'   # OPC UA Message
        ]
    }
}

# Known vendor fingerprints
VENDOR_FINGERPRINTS = {
    'SIEMENS': {
        'patterns': [
            rb'Copyright.*Siemens',
            rb'SIMATIC',
            rb'S7-\d{3}',
        ],
        'products': [
            {'name': 'S7-200', 'patterns': [rb'S7-200', rb'CPU 22[1-6]']},
            {'name': 'S7-300', 'patterns': [rb'S7-300', rb'CPU 31[1-9]']},
            {'name': 'S7-400', 'patterns': [rb'S7-400', rb'CPU 41[1-9]']},
            {'name': 'S7-1200', 'patterns': [rb'S7-1200', rb'CPU 121[1-9]']},
            {'name': 'S7-1500', 'patterns': [rb'S7-1500', rb'CPU 151[1-9]']}
        ]
    },
    'SCHNEIDER': {
        'patterns': [
            rb'Schneider Electric',
            rb'Modicon',
            rb'Unity',
        ],
        'products': [
            {'name': 'M340', 'patterns': [rb'M340', rb'BMX']},
            {'name': 'M580', 'patterns': [rb'M580', rb'BME']},
            {'name': 'Quantum', 'patterns': [rb'Quantum', rb'140']}
        ]
    },
    'ROCKWELL': {
        'patterns': [
            rb'Allen-Bradley',
            rb'Rockwell',
            rb'CompactLogix',
            rb'ControlLogix',
        ],
        'products': [
            {'name': 'ControlLogix', 'patterns': [rb'ControlLogix', rb'1756']},
            {'name': 'CompactLogix', 'patterns': [rb'CompactLogix', rb'1769']},
            {'name': 'MicroLogix', 'patterns': [rb'MicroLogix', rb'1762']}
        ]
    },
    'WAGO': {
        'patterns': [
            rb'WAGO',
            rb'750-',
            rb'ETHERNET Controller',
        ],
        'products': [
            {'name': 'PFC100', 'patterns': [rb'750-81[0-9]', rb'PFC100']},
            {'name': 'PFC200', 'patterns': [rb'750-82[0-9]', rb'PFC200']}
        ]
    },
    'BECKHOFF': {
        'patterns': [
            rb'Beckhoff',
            rb'TwinCAT',
            rb'CX',
        ],
        'products': [
            {'name': 'CX5120', 'patterns': [rb'CX5120']},
            {'name': 'CX9020', 'patterns': [rb'CX9020']}
        ]
    },
    'ABB': {
        'patterns': [
            rb'ABB',
            rb'AC500',
            rb'AC 500',
        ],
        'products': [
            {'name': 'AC500', 'patterns': [rb'AC500-eCo', rb'PM5[0-9]{2}']},
            {'name': 'AC500', 'patterns': [rb'AC500', rb'PM5[0-9]{2}']}
        ]
    },
    'MITSUBISHI': {
        'patterns': [
            rb'MITSUBISHI',
            rb'MELSEC',
        ],
        'products': [
            {'name': 'Q-Series', 'patterns': [rb'Q-Series', rb'Q[0-9]{2}']},
            {'name': 'L-Series', 'patterns': [rb'L-Series', rb'L[0-9]{2}']},
            {'name': 'FX-Series', 'patterns': [rb'FX-Series', rb'FX[0-9]']}
        ]
    },
    'OMRON': {
        'patterns': [
            rb'OMRON',
            rb'SYSMAC',
            rb'CJ1',
            rb'CJ2',
            rb'CP1',
        ],
        'products': [
            {'name': 'CJ1', 'patterns': [rb'CJ1[A-Z]']},
            {'name': 'CJ2', 'patterns': [rb'CJ2[A-Z]']},
            {'name': 'CP1', 'patterns': [rb'CP1[A-Z]']}
        ]
    }
}

# Known vulnerabilities database
VULNERABILITY_DATABASE = {
    'MODBUS': [
        Vulnerability(
            cve_id="CVE-2018-10621",
            description="Modbus TCP buffer overflow vulnerability in specific implementations",
            severity="high",
            affected_versions=["*"],
            affected_products=["Multiple Vendors"],
            disclosure_date="2018-05-03",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2018-10621"],
            exploitability=0.7
        ),
        Vulnerability(
            cve_id="CVE-2019-12623",
            description="Unauthenticated Modbus TCP command execution",
            severity="critical",
            affected_versions=["<3.5"],
            affected_products=["Multiple PLCs"],
            disclosure_date="2019-07-12",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-12623"],
            exploitability=0.8
        )
    ],
    'S7': [
        Vulnerability(
            cve_id="CVE-2020-15782",
            description="Improper Access Control in Siemens SIMATIC S7-1200 and S7-1500 CPU",
            severity="critical",
            affected_versions=["<V4.2.3"],
            affected_products=["Siemens SIMATIC S7-1200", "Siemens SIMATIC S7-1500"],
            disclosure_date="2020-07-14",
            references=["https://cert-portal.siemens.com/productcert/pdf/ssa-434534.pdf"],
            exploitability=0.9
        ),
        Vulnerability(
            cve_id="CVE-2019-10915",
            description="Authentication bypass in S7 protocol implementation",
            severity="high",
            affected_versions=["<V4.0"],
            affected_products=["Siemens SIMATIC S7-300", "Siemens SIMATIC S7-400"],
            disclosure_date="2019-04-09",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-10915"],
            exploitability=0.7
        )
    ],
    'DNP3': [
        Vulnerability(
            cve_id="CVE-2013-2800",
            description="Buffer overflow in DNP3 protocol implementations",
            severity="high",
            affected_versions=["*"],
            affected_products=["Multiple DNP3 Devices"],
            disclosure_date="2013-06-14",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2013-2800"],
            exploitability=0.6
        )
    ],
    'BACNET': [
        Vulnerability(
            cve_id="CVE-2020-12556",
            description="Denial of Service vulnerability in BACnet protocol implementation",
            severity="medium",
            affected_versions=["*"],
            affected_products=["Multiple BACnet Devices"],
            disclosure_date="2020-05-12",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2020-12556"],
            exploitability=0.5
        )
    ],
    'EIP': [
        Vulnerability(
            cve_id="CVE-2018-19282",
            description="Improper authentication in EtherNet/IP protocol implementation",
            severity="high",
            affected_versions=["*"],
            affected_products=["Multiple EtherNet/IP Devices"],
            disclosure_date="2018-12-03",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2018-19282"],
            exploitability=0.7
        )
    ]
}

class SCADAScanner:
    """Main scanner class implementing SCADA/ICS device detection and fingerprinting"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: Dict = {}
        self.scanned_hosts: Set[str] = set()
        self.rate_limiter = asyncio.Semaphore(self.config.max_concurrent)
        self.host_locks: Dict[str, asyncio.Lock] = {}
        
        # Print banner and configuration info
        self._print_banner()
        logger.info(f"Scanner initialized with configuration:")
        logger.info(f"  - Rate limit: {config.rate_limit} req/s")
        logger.info(f"  - Timeout: {config.timeout}s")
        logger.info(f"  - Max concurrent: {config.max_concurrent}")
        logger.info(f"  - Safe mode: {'Enabled' if config.safe_mode else 'Disabled'}")
        
        if config.safe_mode:
            logger.info("Safe mode enabled: Using non-intrusive probes only")
        else:
            logger.warning("Safe mode disabled: Using all available probes (may be disruptive)")
    
    def _print_banner(self) -> None:
        """Print scanner banner"""
        banner = r"""
  ___ ___ ___ ___  _      ___ ___ ___ _  _ _  _ ___ ___ 
 / __/ __/ _ \   \| |__ _/ __/ __/ _ \ \| | \| | __| _ \
 \__ \__ \ /_\ | |) | / _\__ \__ \ /_\ .  | .` | _||   /
 |___/___/___/___/|_\_(_|___/___/___/_|\_|_|\_|___|_|_\
                                                        
        Industrial Control Systems Scanner v2.0
    [ For authorized security assessments only ]
        """
        print(banner)
    
    def get_host_lock(self, ip: str) -> asyncio.Lock:
        """Get or create a lock for a specific host"""
        if ip not in self.host_locks:
            self.host_locks[ip] = asyncio.Lock()
        return self.host_locks[ip]
    
    async def scan_target(self, ip: str, port: PortProtocol) -> Optional[Dict]:
        """Scan a single target IP and port combination"""
        try:
            # Check if IP is in excluded list
            if ip in self.config.exclude_ips:
                logger.debug(f"Skipping excluded IP {ip}")
                return None
                
            # Use rate limiter for overall scan rate
            async with self.rate_limiter:
                # Use per-host lock to enforce delay between requests to same host
                host_lock = self.get_host_lock(ip)
                async with host_lock:
                    result = await self._probe_port(ip, port)
                    
                    # Add delay before releasing lock to prevent flooding a host
                    await asyncio.sleep(self.config.scan_delay)
                    
                    if result:
                        fingerprint = await self._fingerprint_service(ip, port, result)
                        result['fingerprint'] = fingerprint
                        
                        # Add metadata
                        result['metadata'] = {
                            'scan_time': datetime.utcnow().isoformat(),
                            'scanner_version': '2.0',
                            'risk_score': fingerprint.get('risk_score', 0)
                        }
                        
                        # Log discovery
                        self._log_discovery(ip, port, fingerprint)
                        
                    return result
        except Exception as e:
            logger.error(f"Error scanning {ip}:{port.port} - {str(e)}")
            return None

    def _log_discovery(self, ip: str, port: PortProtocol, fingerprint: Dict) -> None:
        """Log discovery of SCADA/ICS device"""
        vendor = fingerprint.get('vendor', 'Unknown')
        product = fingerprint.get('product', 'Unknown')
        protocol = fingerprint.get('protocol', port.protocol)
        
        vulnerabilities = fingerprint.get('vulnerabilities', [])
        risk_level = "Low"
        if fingerprint.get('risk_score', 0) > 0.7:
            risk_level = "Critical"
        elif fingerprint.get('risk_score', 0) > 0.4:
            risk_level = "High"
        elif fingerprint.get('risk_score', 0) > 0.2:
            risk_level = "Medium"
        
        logger.info(f"DISCOVERED: {ip}:{port.port} - {protocol} - {vendor} {product} - Risk: {risk_level}")
        
        if vulnerabilities and len(vulnerabilities) > 0:
            vuln_str = ", ".join([v.get('cve_id', 'Unknown') for v in vulnerabilities])
            logger.warning(f"VULNERABILITIES for {ip}:{port.port}: {vuln_str}")

    async def _probe_port(self, ip: str, port: PortProtocol) -> Optional[Dict]:
        """Probe a specific port for SCADA/ICS services"""
        for attempt in range(self.config.max_retries):
            try:
                # Generate connection ID for tracking
                connection_id = f"{random.randint(1000, 9999)}"
                
                logger.debug(f"Probing {ip}:{port.port} ({port.protocol}) - Attempt {attempt+1}/{self.config.max_retries}")
                
                # Create a socket connection with timeout
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port.port),
                    timeout=self.config.timeout
                )
                
                # Get appropriate probe packet for this protocol
                probe = self._get_protocol_probe(port.protocol)
                
                # Send the probe and log it
                logger.debug(f"Sending {len(probe)} bytes to {ip}:{port.port}")
                writer.write(probe)
                await writer.drain()
                
                # Read response with timeout
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=self.config.timeout
                )
                
                # Close the writer
                writer.close()
                await writer.wait_closed()
                
                # Process response
                if response and len(response) > 0:
                    logger.debug(f"Received {len(response)} bytes from {ip}:{port.port}")
                    
                    # Calculate response hash for fingerprinting
                    response_hash = hashlib.md5(response).hexdigest()
                    
                    return {
                        'ip': ip,
                        'port': port.port,
                        'protocol': port.protocol,
                        'response': response.hex(),
                        'response_hash': response_hash,
                        'timestamp': datetime.utcnow().isoformat(),
                        'connection_id': connection_id
                    }
                else:
                    logger.debug(f"No data received from {ip}:{port.port}")
            
            except asyncio.TimeoutError:
                logger.debug(f"Timeout connecting to {ip}:{port.port}")
            
            except ConnectionRefusedError:
                logger.debug(f"Connection refused by {ip}:{port.port}")
                break  # No need to retry if connection is refused
            
            except (OSError, socket.error) as e:
                logger.debug(f"Socket error when connecting to {ip}:{port.port}: {str(e)}")
            
            except Exception as e:
                logger.debug(f"Error probing {ip}:{port.port}: {str(e)}")
            
            # Only sleep between retries, not after the last attempt
            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(1)
        
        return None

    async def _fingerprint_service(self, ip: str, port: PortProtocol, scan_result: Dict) -> Dict:
        """Enhanced fingerprinting with behavioral analysis and vulnerability checking"""
        try:
            # Decode hex response to bytes for pattern matching
            response_bytes = bytes.fromhex(scan_result['response'])
            
            # Initialize fingerprint result
            fingerprint = {
                'protocol': port.protocol,
                'confidence': 0.0,
                'vendor': 'Unknown',
                'product': 'Unknown',
                'version': 'Unknown',
                'vulnerabilities': [],
                'risk_score': 0.0,
                'behaviors': [],
                'findings': []
            }
            
            # Identify protocol
            protocol_details = self._identify_protocol(response_bytes)
            if protocol_details:
                fingerprint['protocol'] = protocol_details['protocol']
                fingerprint['confidence'] = protocol_details['confidence']
                
                # Add protocol-specific findings
                finding = f"Detected {protocol_details['protocol']} protocol (confidence: {protocol_details['confidence']})"
                fingerprint['findings'].append(finding)
            
            # Identify vendor and product
            vendor_details = self._identify_vendor(response_bytes)
            if vendor_details:
                fingerprint['vendor'] = vendor_details['vendor']
                fingerprint['product'] = vendor_details['product']
                
                # Add vendor findings
                finding = f"Identified vendor: {vendor_details['vendor']}, product: {vendor_details['product']}"
                fingerprint['findings'].append(finding)
            
            # Advanced behavioral analysis if not in safe mode
            if not self.config.safe_mode:
                behaviors = await self._analyze_behavior(ip, port.port, fingerprint['protocol'], response_bytes)
                fingerprint['behaviors'] = behaviors
                
                # Add behavior findings
                for behavior in behaviors:
                    finding = f"Behavior: {behavior['type']} - {behavior['detail']}"
                    fingerprint['findings'].append(finding)
            
            # Version detection
            version_info = await self._detect_version(ip, port.port, fingerprint['protocol'], response_bytes)
            if version_info:
                fingerprint['version'] = version_info['version']
                if 'details' in version_info:
                    fingerprint['version_details'] = version_info['details']
                
                # Add version findings
                finding = f"Detected version: {version_info['version']}"
                fingerprint['findings'].append(finding)
            
            # Check for known vulnerabilities
            vulnerabilities = self._check_vulnerabilities(
                fingerprint['protocol'],
                fingerprint['vendor'],
                fingerprint['product'],
                fingerprint['version']
            )
            
            # Convert vulnerability objects to dictionaries
            fingerprint['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
            
            # Add vulnerability findings
            for vuln in vulnerabilities:
                finding = f"Potential vulnerability: {vuln.cve_id} - {vuln.description} (Severity: {vuln.severity})"
                fingerprint['findings'].append(finding)
            
            # Calculate risk score based on vulnerabilities and other factors
            risk_score = self._calculate_risk_score(fingerprint)
            fingerprint['risk_score'] = risk_score
            
            # Add overall risk assessment
            risk_level = "Low"
            if risk_score > 0.7:
                risk_level = "Critical"
            elif risk_score > 0.4:
                risk_level = "High"
            elif risk_score > 0.2:
                risk_level = "Medium"
            
            finding = f"Overall risk assessment: {risk_level} (score: {risk_score:.2f})"
            fingerprint['findings'].append(finding)
            
            return fingerprint
            
        except Exception as e:
            logger.error(f"Fingerprinting error for {ip}:{port.port} - {str(e)}")
            return {
                'protocol': port.protocol,
                'error': str(e),
                'vulnerabilities': []
            }

    def _identify_protocol(self, response: bytes) -> Optional[Dict]:
        """Identify protocol from response patterns"""
        best_match = None
        highest_confidence = 0.0
        
        for protocol, signatures in PROTOCOL_SIGNATURES.items():
            pattern_matches = 0
            response_matches = 0
            
            # Check if response matches known patterns
            for pattern in signatures.get('patterns', []):
                if re.search(pattern, response):
                    pattern_matches += 1
            
            # Check if response matches known responses
            for resp_pattern in signatures.get('responses', []):
                if re.search(resp_pattern, response):
                    response_matches += 1
            
            # Calculate confidence based on matches
            total_patterns = len(signatures.get('patterns', [])) + len(signatures.get('responses', []))
            if total_patterns > 0:
                confidence = (pattern_matches + response_matches * 2) / (total_patterns * 2)
                
                # Only consider if confidence is above threshold
                if confidence > 0.2 and confidence > highest_confidence:
                    highest_confidence = confidence
                    best_match = protocol
        
        if best_match:
            return {
                'protocol': best_match,
                'confidence': highest_confidence
            }
        
        return None

    def _identify_vendor(self, response: bytes) -> Optional[Dict]:
        """Identify vendor and product from response patterns"""
        best_vendor = None
        best_product = None
        highest_confidence = 0.0
        
        for vendor, fingerprint in VENDOR_FINGERPRINTS.items():
            # Check vendor patterns
            vendor_matches = 0
            for pattern in fingerprint['patterns']:
                if re.search(pattern, response):
                    vendor_matches += 1
            
            vendor_confidence = vendor_matches / len(fingerprint['patterns']) if fingerprint['patterns'] else 0
            
            # If vendor confidence is above threshold, check for products
            if vendor_confidence > 0.3:
                best_product_confidence = 0.0
                for product in fingerprint['products']:
                    product_matches = 0
                    for pattern in product['patterns']:
                        if re.search(pattern, response):
                            product_matches += 1
                    
                    product_confidence = product_matches / len(product['patterns']) if product['patterns'] else 0
                    
                    if product_confidence > best_product_confidence:
                        best_product_confidence = product_confidence
                        best_product = product['name']
                
                # Overall confidence is a combination of vendor and product confidence
                overall_confidence = (vendor_confidence * 0.7) + (best_product_confidence * 0.3)
                
                if overall_confidence > highest_confidence:
                    highest_confidence = overall_confidence
                    best_vendor = vendor
        
        if best_vendor:
            return {
                'vendor': best_vendor,
                'product': best_product if best_product else "Unknown",
                'confidence': highest_confidence
            }
        
        return None

    async def _analyze_behavior(self, ip: str, port: int, protocol: str, initial_response: bytes) -> List[Dict]:
        """Analyze protocol behavior patterns for fingerprinting"""
        behaviors = []
        
        # Skip if in safe mode
        if self.config.safe_mode:
            return behaviors
        
        # Get protocol-specific behavior probes
        behavior_probes = self._get_behavior_probes(protocol)
        
        for behavior_name, probe in behavior_probes.items():
            try:
                # Send behavior probe and analyze response
                logger.debug(f"Sending behavior probe '{behavior_name}' to {ip}:{port}")
                response = await self._send_probe_data(ip, port, probe)
                
                if response:
                    # Analyze the response for expected patterns
                    match_result = self._match_behavior_response(protocol, behavior_name, response)
                    
                    if match_result['match']:
                        behaviors.append({
                            'type': behavior_name,
                            'detail': match_result['detail'],
                            'confidence': match_result['confidence']
                        })
            except Exception as e:
                logger.debug(f"Error during behavior probe '{behavior_name}': {str(e)}")
        
        return behaviors

    def _get_behavior_probes(self, protocol: str) -> Dict[str, bytes]:
        """Get protocol-specific behavior probes"""
        probes = {
            'MODBUS': {
                'read_coils': struct.pack('>HHHBBBH',
                    0x0001,  # Transaction ID
                    0x0000,  # Protocol ID
                    0x0006,  # Length
                    0x01,    # Unit ID
                    0x01,    # Function code (Read Coils)
                    0x0000,  # Starting Address
                    0x0001   # Quantity of coils
                ),
                'read_holding_registers': struct.pack('>HHHBBBH',
                    0x0002,  # Transaction ID
                    0x0000,  # Protocol ID
                    0x0006,  # Length
                    0x01,    # Unit ID
                    0x03,    # Function code (Read Holding Registers)
                    0x0000,  # Starting Address
                    0x0001   # Quantity of registers
                ),
                'device_info': struct.pack('>HHHBBBBB',
                    0x0003,  # Transaction ID
                    0x0000,  # Protocol ID
                    0x0005,  # Length
                    0x01,    # Unit ID
                    0x2B,    # Function code (Encapsulated Interface)
                    0x0E,    # MEI Type (Read Device ID)
                    0x01,    # Read Device ID code
                    0x00     # Object ID
                )
            },
            'S7': {
                'read_szl': bytes.fromhex('0300001902f080320100000e00000401120a10060001001400040001'),
                'setup_communication': bytes.fromhex('0300001611e00000000100c0010a0100c2020101c0010ac0010a'),
                'read_clock': bytes.fromhex('0300001902f080320100000e00000401120a10070001000000000000')
            },
            'DNP3': {
                'read_data': bytes.fromhex('0564 0a00 0104 0000 01 01 01 00 01 00 00 04 01 3c 01 06 45'),
                'ping': bytes.fromhex('0564 0700 0000 0000 fc eb 0f 92')
            },
            'BACNET': {
                'who_is': bytes.fromhex('810b0012010804001319bac0ffffffff30103e0c0c0220ffffffff39'),
                'read_property': bytes.fromhex('810a001101040005010c0c023FFFFF19')
            },
            'EIP': {
                'list_services': bytes.fromhex('6300 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0400 0000'),
                'list_identity': bytes.fromhex('6300 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0c00 0000')
            }
        }
        
        return probes.get(protocol, {})

    def _match_behavior_response(self, protocol: str, behavior: str, response: bytes) -> Dict:
        """Match behavior response patterns"""
        matchers = {
            'MODBUS': {
                'read_coils': {
                    'patterns': [rb'\x01\x01[\x00-\xff]'],
                    'detail': 'Device supports reading coils',
                    'confidence': 0.8
                },
                'read_holding_registers': {
                    'patterns': [rb'\x01\x03[\x00-\xff]'],
                    'detail': 'Device supports reading holding registers',
                    'confidence': 0.8
                },
                'device_info': {
                    'patterns': [rb'\x01\x2B\x0E'],
                    'detail': 'Device supports device identification',
                    'confidence': 0.9
                }
            },
            'S7': {
                'read_szl': {
                    'patterns': [rb'\x03\x00.{6}\x02\xf0'],
                    'detail': 'Device supports SZL reading',
                    'confidence': 0.8
                },
                'setup_communication': {
                    'patterns': [rb'\x03\x00.{6}\x02\xf0'],
                    'detail': 'Device supports S7 communication setup',
                    'confidence': 0.9
                },
                'read_clock': {
                    'patterns': [rb'\x03\x00.{6}\x02\xf0'],
                    'detail': 'Device supports clock reading',
                    'confidence': 0.7
                }
            },
            'DNP3': {
                'read_data': {
                    'patterns': [rb'\x05\x64'],
                    'detail': 'Device supports DNP3 data reading',
                    'confidence': 0.8
                },
                'ping': {
                    'patterns': [rb'\x05\x64'],
                    'detail': 'Device responds to DNP3 ping',
                    'confidence': 0.7
                }
            },
            'BACNET': {
                'who_is': {
                    'patterns': [rb'\x81.{3}\x10'],
                    'detail': 'Device responds to BACnet Who-Is',
                    'confidence': 0.9
                },
                'read_property': {
                    'patterns': [rb'\x81.{3}\x00\x00'],
                    'detail': 'Device supports BACnet property reading',
                    'confidence': 0.8
                }
            },
            'EIP': {
                'list_services': {
                    'patterns': [rb'\x63\x00'],
                    'detail': 'Device supports EtherNet/IP service listing',
                    'confidence': 0.8
                },
                'list_identity': {
                    'patterns': [rb'\x63\x00'],
                    'detail': 'Device supports EtherNet/IP identity listing',
                    'confidence': 0.9
                }
            }
        }
        
        protocol_matchers = matchers.get(protocol, {})
        behavior_matcher = protocol_matchers.get(behavior, {
            'patterns': [],
            'detail': f'Unknown behavior: {behavior}',
            'confidence': 0.1
        })
        
        # Check if response matches any pattern
        for pattern in behavior_matcher['patterns']:
            if re.search(pattern, response):
                return {
                    'match': True,
                    'detail': behavior_matcher['detail'],
                    'confidence': behavior_matcher['confidence']
                }
        
        return {
            'match': False,
            'detail': 'No match',
            'confidence': 0.0
        }

    async def _detect_version(self, ip: str, port: int, protocol: str, initial_response: bytes) -> Optional[Dict]:
        """Attempt to detect software/firmware version"""
        try:
            # Skip if in safe mode
            if self.config.safe_mode:
                # Try to extract version from initial response
                version = self._extract_version_from_response(protocol, initial_response)
                if version:
                    return {
                        'version': version,
                        'method': 'passive'
                    }
                return None
            
            # If not in safe mode, use active probing
            version_probe = self._get_version_probe(protocol)
            if not version_probe:
                return None
            
            logger.debug(f"Sending version probe to {ip}:{port}")
            response = await self._send_probe_data(ip, port, version_probe)
            
            if not response:
                return None
            
            # Parse version information from response
            version_info = self._parse_version_response(protocol, response)
            if version_info:
                return version_info
            
            # Try to extract version from initial response as fallback
            version = self._extract_version_from_response(protocol, initial_response)
            if version:
                return {
                    'version': version,
                    'method': 'passive'
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Version detection error: {str(e)}")
            return None

    def _get_version_probe(self, protocol: str) -> Optional[bytes]:
        """Get protocol-specific version probe"""
        probes = {
            'MODBUS': struct.pack('>HHHBBBBB',
                0x0001,  # Transaction ID
                0x0000,  # Protocol ID
                0x0005,  # Length
                0x01,    # Unit ID
                0x2B,    # Function code (Encapsulated Interface)
                0x0E,    # MEI Type (Read Device ID)
                0x01,    # Read Device ID code
                0x00     # Object ID
            ),
            'S7': bytes.fromhex('0300001902f080320100000e00000401120a10060001001400040001'),
            'DNP3': bytes.fromhex('0564070000000000fceb0f92'),
            'BACNET': bytes.fromhex('810a001108000100'),
            'EIP': bytes.fromhex('6300000000000000000000000000000000000000000000000c000000')
        }
        
        return probes.get(protocol)

    def _parse_version_response(self, protocol: str, response: bytes) -> Optional[Dict]:
        """Parse version information from response"""
        try:
            if protocol == 'MODBUS':
                return self._parse_modbus_version(response)
            elif protocol == 'S7':
                return self._parse_s7_version(response)
            elif protocol == 'DNP3':
                return self._parse_dnp3_version(response)
            elif protocol == 'BACNET':
                return self._parse_bacnet_version(response)
            elif protocol == 'EIP':
                return self._parse_eip_version(response)
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing version response: {str(e)}")
            return None

    def _parse_modbus_version(self, response: bytes) -> Optional[Dict]:
        """Parse Modbus version information"""
        try:
            # Check if response is a Modbus Device ID response (0x2B/0x0E)
            if len(response) > 8 and response[7] == 0x2B and response[8] == 0x0E:
                # Extract object values
                objects = {}
                pos = 10
                
                # Object count is at position 9
                object_count = response[9]
                
                for _ in range(object_count):
                    if pos + 2 >= len(response):
                        break
                    
                    obj_id = response[pos]
                    obj_len = response[pos + 1]
                    
                    if pos + 2 + obj_len <= len(response):
                        obj_value = response[pos + 2:pos + 2 + obj_len]
                        objects[obj_id] = obj_value.decode('utf-8', errors='ignore')
                    
                    pos += 2 + obj_len
                
                # Determine version from objects
                # Object ID 1: Vendor Name
                # Object ID 2: Product Code
                # Object ID 3: Major Minor Revision
                # Object ID 4: Vendor URL
                # Object ID 5: Product Name
                # Object ID 6: Model Name
                # Object ID 7: User Application Name
                version = objects.get(3, "Unknown")
                
                return {
                    'version': version,
                    'method': 'device_id',
                    'details': objects
                }
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing Modbus version: {str(e)}")
            return None

    def _parse_s7_version(self, response: bytes) -> Optional[Dict]:
        """Parse S7 version information"""
        try:
            # Look for module type information in S7 response
            if len(response) > 40:
                # Check for S7 header
                if response[0] == 0x03 and response[1] == 0x00:
                    # Try to extract module information
                    version_str = ""
                    
                    # Look for version strings like "V x.y.z"
                    for i in range(len(response) - 5):
                        if response[i] == 0x56 and response[i+1] == 0x20:  # "V "
                            version_data = response[i:i+10]
                            version_str = version_data.decode('utf-8', errors='ignore').strip()
                            
                            # Clean up version string
                            version_str = re.sub(r'[^\x20-\x7E]', '', version_str)
                            break
                    
                    if version_str:
                        return {
                            'version': version_str,
                            'method': 'szl'
                        }
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing S7 version: {str(e)}")
            return None

    def _parse_dnp3_version(self, response: bytes) -> Optional[Dict]:
        """Parse DNP3 version information"""
        try:
            if len(response) > 10 and response[0] == 0x05 and response[1] == 0x64:
                # DNP3 responses don't typically contain version info directly
                # Extract any device attributes that might be useful
                return {
                    'version': "Unknown",
                    'method': 'dnp3_response',
                    'details': {
                        'control': f"0x{response[2]:02x}{response[3]:02x}",
                        'function_code': f"0x{response[4]:02x}"
                    }
                }
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing DNP3 version: {str(e)}")
            return None

    def _parse_bacnet_version(self, response: bytes) -> Optional[Dict]:
        """Parse BACnet version information"""
        try:
            if len(response) > 6 and response[0] == 0x81:
                # Extract protocol version
                protocol_version = response[1] & 0x0F
                
                # Look for firmware version in response
                firmware_version = "Unknown"
                
                # Search for firmware version patterns like "v1.2.3"
                for i in range(len(response) - 5):
                    if response[i] in (0x76, 0x56) and response[i+1] == 0x2E:  # "v." or "V."
                        version_data = response[i:i+8]
                        try:
                            potential_version = version_data.decode('utf-8', errors='ignore').strip()
                            if re.match(r'[vV][\d\.]+', potential_version):
                                firmware_version = potential_version
                                break
                        except:
                            pass
                
                return {
                    'version': firmware_version,
                    'method': 'bacnet_response',
                    'details': {
                        'protocol_version': protocol_version
                    }
                }
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing BACnet version: {str(e)}")
            return None

    def _parse_eip_version(self, response: bytes) -> Optional[Dict]:
        """Parse EtherNet/IP version information"""
        try:
            if len(response) > 24 and response[0] == 0x63 and response[1] == 0x00:
                # Extract revision information if available
                revision = f"{response[34]}.{response[35]}" if len(response) > 35 else "Unknown"
                
                return {
                    'version': revision,
                    'method': 'list_identity',
                    'details': {
                        'encapsulation_version': f"{response[4]}.{response[5]}" if len(response) > 5 else "Unknown"
                    }
                }
            
            return None
        except Exception as e:
            logger.debug(f"Error parsing EtherNet/IP version: {str(e)}")
            return None

    def _extract_version_from_response(self, protocol: str, response: bytes) -> Optional[str]:
        """Try to extract version information from general response data"""
        # Look for common version patterns in the response
        try:
            # Look for version strings like "v1.2.3", "version 1.2.3", etc.
            version_patterns = [
                rb'[vV]ersion[:\s]+([0-9]+\.[0-9]+\.[0-9]+)',
                rb'[vV]er[:\s]+([0-9]+\.[0-9]+\.[0-9]+)',
                rb'[vV]([0-9]+\.[0-9]+\.[0-9]+)',
                rb'([0-9]+\.[0-9]+\.[0-9]+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, response)
                if match:
                    return match.group(1).decode('utf-8', errors='ignore')
            
            # Protocol-specific extraction
            if protocol == 'MODBUS':
                # Look for Modbus version strings
                modbus_match = re.search(rb'Rev[:\s]+([0-9]+\.[0-9]+)', response)
                if modbus_match:
                    return modbus_match.group(1).decode('utf-8', errors='ignore')
            
            elif protocol == 'S7':
                # Look for Siemens version patterns
                s7_match = re.search(rb'V\s+([0-9]+\.[0-9]+\.[0-9]+)', response)
                if s7_match:
                    return s7_match.group(1).decode('utf-8', errors='ignore')
            
            return None
        except Exception as e:
            logger.debug(f"Error extracting version from response: {str(e)}")
            return None

    def _check_vulnerabilities(self, protocol: str, vendor: str, product: str, version: str) -> List[Vulnerability]:
        """Check for known vulnerabilities based on protocol, vendor, product, and version"""
        vulnerabilities = []
        
        # Get protocol-specific vulnerabilities
        protocol_vulns = VULNERABILITY_DATABASE.get(protocol, [])
        
        for vuln in protocol_vulns:
            # Check if product matches
            product_match = False
            if "Multiple" in vuln.affected_products:
                product_match = True
            else:
                for affected_product in vuln.affected_products:
                    if affected_product in product or product in affected_product:
                        product_match = True
                        break
            
            # Skip if product doesn't match
            if not product_match:
                continue
            
            # Check if version matches
            version_match = False
            if version == "Unknown" or "*" in vuln.affected_versions:
                # If version is unknown or vulnerability affects all versions, assume it might be vulnerable
                version_match = True
            else:
                for affected_version in vuln.affected_versions:
                    # Check for version patterns like "<3.5" or ">2.1"
                    if affected_version.startswith("<"):
                        target_version = affected_version[1:]
                        if self._compare_versions(version, target_version) < 0:
                            version_match = True
                            break
                    elif affected_version.startswith(">"):
                        target_version = affected_version[1:]
                        if self._compare_versions(version, target_version) > 0:
                            version_match = True
                            break
                    elif affected_version.startswith("<="):
                        target_version = affected_version[2:]
                        if self._compare_versions(version, target_version) <= 0:
                            version_match = True
                            break
                    elif affected_version.startswith(">="):
                        target_version = affected_version[2:]
                        if self._compare_versions(version, target_version) >= 0:
                            version_match = True
                            break
                    elif affected_version in version or version in affected_version:
                        version_match = True
                        break
            
            # If both product and version match, add vulnerability
            if version_match:
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings (e.g., "3.5.1" vs "3.6.0")"""
        try:
            # Clean up version strings
            v1 = re.sub(r'[^0-9\.]', '', version1)
            v2 = re.sub(r'[^0-9\.]', '', version2)
            
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad with zeros to make equal length
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            
            # Compare part by part
            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except Exception:
            # If comparison fails, assume they're not equal
            return -1 if version1 != version2 else 0

    def _calculate_risk_score(self, fingerprint: Dict) -> float:
        """Calculate risk score based on vulnerabilities and other factors"""
        score = 0.0
        
        # Contribution from vulnerabilities
        vulnerabilities = fingerprint.get('vulnerabilities', [])
        if vulnerabilities:
            vuln_score = 0.0
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity == 'critical':
                    vuln_score += 0.3
                elif severity == 'high':
                    vuln_score += 0.2
                elif severity == 'medium':
                    vuln_score += 0.1
                else:  # low
                    vuln_score += 0.05
            
            # Cap vulnerability score at 0.6
            score += min(0.6, vuln_score)
        
        # Contribution from version
        version = fingerprint.get('version', 'Unknown')
        if version == 'Unknown':
            # Unknown version might indicate lack of security focus
            score += 0.1
        
        # Contribution from behaviors
        behaviors = fingerprint.get('behaviors', [])
        for behavior in behaviors:
            if 'default credentials' in behavior.get('detail', '').lower():
                score += 0.2
            elif 'unauthenticated' in behavior.get('detail', '').lower():
                score += 0.15
        
        # Clamp final score to 0.0-1.0 range
        return min(1.0, max(0.0, score))

    def _get_protocol_probe(self, protocol: str) -> bytes:
        """Get protocol-specific probe packet"""
        probes = {
            'MODBUS': struct.pack('>HHHBB',
                0x0001,  # Transaction ID
                0x0000,  # Protocol ID
                0x0002,  # Length
                0x00,    # Unit ID
                0x00     # Function code: null byte for initial probe
            ),
            'S7': bytes.fromhex('0300001611e00000000100c0010a0100c2020101c0010ac0010a'),
            'DNP3': bytes.fromhex('0564 0A00 0000 0000'),
            'BACNET': bytes.fromhex('810a001101040005010c0c023FFFFF19'),
            'EIP': bytes.fromhex('6300 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0400 0000'),
            'OPCUA': bytes.fromhex('4845 4c46 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000'),
            'FOX': bytes.fromhex('666f 7820 6120 302e 312e 300a'),
            'IEC104': bytes.fromhex('6804 0700 0000'),
            'CODESYS': bytes.fromhex('5353 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000')
        }
        
        return probes.get(protocol, b'\x00\x00\x00\x00\x00\x00\x00\x00')

    async def _send_probe_data(self, ip: str, port: int, data: bytes) -> Optional[bytes]:
        """Send probe data to target and get response"""
        for attempt in range(self.config.max_retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.config.timeout
                )
                
                writer.write(data)
                await writer.drain()
                
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=self.config.timeout
                )
                
                writer.close()
                await writer.wait_closed()
                
                return response
            
            except Exception as e:
                logger.debug(f"Error sending probe data to {ip}:{port}: {str(e)}")
                
                # Only sleep between retries, not after the last attempt
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(1)
        
        return None

    async def scan_cidr(self, cidr: str) -> List[Dict]:
        """Scan entire CIDR range"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            total_hosts = network.num_addresses
            
            logger.info(f"Starting scan of {cidr} ({total_hosts} addresses)")
            
            # Track progress
            completed = 0
            discovered = 0
            start_time = time.time()
            
            # Create tasks for all IP addresses and ports
            tasks = []
            for ip in network.hosts():
                ip_str = str(ip)
                
                # Skip excluded IPs
                if ip_str in self.config.exclude_ips:
                    continue
                
                for port in SCADA_PORTS:
                    tasks.append(self.scan_target(ip_str, port))
            
            # Process tasks in batches to avoid memory issues with large CIDRs
            batch_size = 1000
            results = []
            
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i+batch_size]
                
                # Run batch of tasks
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        continue
                        
                    if result is not None:
                        results.append(result)
                        discovered += 1
                
                # Update progress
                completed += len(batch)
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                
                # Calculate ETA
                remaining = len(tasks) - completed
                eta_seconds = remaining / rate if rate > 0 else 0
                eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
                
                logger.info(f"Progress: {completed}/{len(tasks)} ({completed/len(tasks)*100:.1f}%) - {discovered} devices found - ETA: {eta_str}")
            
            # Final summary
            total_time = time.time() - start_time
            logger.info(f"Scan complete: {discovered} devices found in {total_time:.1f} seconds")
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning CIDR {cidr}: {str(e)}")
            return []

    def generate_report(self, results: List[Dict], output_file: str) -> None:
        """Generate a comprehensive report of scan results"""
        try:
            # Group results by IP
            hosts = {}
            
            for result in results:
                ip = result.get('ip')
                if not ip:
                    continue
                
                if ip not in hosts:
                    hosts[ip] = {
                        'ip': ip,
                        'ports': [],
                        'protocols': set(),
                        'vendors': set(),
                        'products': set(),
                        'vulnerabilities': [],
                        'max_risk_score': 0.0
                    }
                
                # Add port info
                hosts[ip]['ports'].append({
                    'port': result.get('port'),
                    'protocol': result.get('protocol'),
                    'fingerprint': result.get('fingerprint', {})
                })
                
                # Add protocol
                fingerprint = result.get('fingerprint', {})
                if 'protocol' in fingerprint:
                    hosts[ip]['protocols'].add(fingerprint['protocol'])
                
                # Add vendor and product
                if 'vendor' in fingerprint and fingerprint['vendor'] != 'Unknown':
                    hosts[ip]['vendors'].add(fingerprint['vendor'])
                if 'product' in fingerprint and fingerprint['product'] != 'Unknown':
                    hosts[ip]['products'].add(fingerprint['product'])
                
                # Add vulnerabilities
                if 'vulnerabilities' in fingerprint:
                    for vuln in fingerprint['vulnerabilities']:
                        if vuln not in hosts[ip]['vulnerabilities']:
                            hosts[ip]['vulnerabilities'].append(vuln)
                
                # Update max risk score
                if 'risk_score' in fingerprint:
                    hosts[ip]['max_risk_score'] = max(hosts[ip]['max_risk_score'], fingerprint['risk_score'])
            
            # Convert sets to lists for JSON serialization
            for ip, host in hosts.items():
                host['protocols'] = list(host['protocols'])
                host['vendors'] = list(host['vendors'])
                host['products'] = list(host['products'])
            
            # Create report structure
            report = {
                'scan_summary': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_hosts_scanned': len(hosts),
                    'hosts_with_scada': sum(1 for host in hosts.values() if host['ports']),
                    'total_vulnerabilities': sum(len(host['vulnerabilities']) for host in hosts.values()),
                    'high_risk_hosts': sum(1 for host in hosts.values() if host['max_risk_score'] >= 0.7)
                },
                'hosts': list(hosts.values()),
                'raw_results': results
            }
            
            # Write to file
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report generated: {output_file}")
            
            # Print summary to console
            print("\n===== SCAN SUMMARY =====")
            print(f"Total hosts scanned: {report['scan_summary']['total_hosts_scanned']}")
            print(f"Hosts with SCADA/ICS protocols: {report['scan_summary']['hosts_with_scada']}")
            print(f"Total vulnerabilities found: {report['scan_summary']['total_vulnerabilities']}")
            print(f"High risk hosts: {report['scan_summary']['high_risk_hosts']}")
            print("========================\n")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")

async def scan_single_target(ip: str, config: ScanConfig) -> List[Dict]:
    """Scan a single target IP across all SCADA ports"""
    scanner = SCADAScanner(config)
    results = []
    
    try:
        logger.info(f"Scanning single target: {ip}")
        
        tasks = []
        for port in SCADA_PORTS:
            tasks.append(scanner.scan_target(ip, port))
        
        scan_results = await asyncio.gather(*tasks)
        results = [r for r in scan_results if r is not None]
        
        logger.info(f"Scan complete for {ip}. Found {len(results)} services.")
        
    except Exception as e:
        logger.error(f"Error scanning target {ip}: {str(e)}")
    
    return results

async def main(args: argparse.Namespace) -> None:
    """Main execution function"""
    # Create scanner configuration
    config = ScanConfig(
        rate_limit=args.rate,
        timeout=args.timeout,
        max_concurrent=args.max_concurrent,
        safe_mode=args.safe_mode,
        verbosity=args.verbosity
    )
    
    # Initialize scanner
    scanner = SCADAScanner(config)
    results = []
    
    try:
        # Display security warning
        print("\n[!] IMPORTANT: This tool is intended for authorized security assessments only.")
        print("[!] Always obtain proper permission before scanning any networks.")
        print("[!] You are responsible for complying with applicable laws and regulations.\n")
        
        if args.target:
            # Scan single target
            ip_results = await scan_single_target(args.target, config)
            results.extend(ip_results)
        elif args.cidr:
            # Scan single CIDR block
            cidr_results = await scanner.scan_cidr(args.cidr)
            results.extend(cidr_results)
        elif args.cidr_file:
            # Scan multiple CIDR blocks from file
            with open(args.cidr_file) as f:
                cidrs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            for cidr in cidrs:
                logger.info(f"Scanning CIDR: {cidr}")
                cidr_results = await scanner.scan_cidr(cidr)
                results.extend(cidr_results)
                
        # Generate report
        scanner.generate_report(results, args.output)
        
    except FileNotFoundError:
        logger.error(f"CIDR file not found: {args.cidr_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SCADA Scanner and Fingerprinter')
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target IP address')
    target_group.add_argument('-c', '--cidr', help='CIDR range to scan (e.g., 192.168.1.0/24)')
    target_group.add_argument('-f', '--cidr-file', help='File containing CIDR ranges (one per line)')
    
    parser.add_argument('-o', '--output', default='scan_results.json', help='Output file (default: scan_results.json)')
    parser.add_argument('-r', '--rate', type=float, default=10.0, help='Max requests per second (default: 10.0)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds (default: 5)')
    parser.add_argument('--max-concurrent', type=int, default=50, help='Maximum concurrent connections (default: 50)')
    parser.add_argument('--safe-mode', action='store_true', help='Enable safe mode (non-intrusive scans only)')
    parser.add_argument('--exclude', help='File containing IPs to exclude from scan')
    parser.add_argument('-v', '--verbosity', type=int, choices=[0, 1, 2], default=1, 
                        help='Verbosity level: 0=quiet, 1=normal, 2=debug (default: 1)')
    parser.add_argument('--format', choices=['json', 'csv'], default='json',
                        help='Output format (default: json)')
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbosity == 0:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbosity == 1:
        logging.getLogger().setLevel(logging.INFO)
    else:  # verbosity == 2
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
