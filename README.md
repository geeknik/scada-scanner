# SCADA Scanner and Fingerprinter

![image](https://github.com/user-attachments/assets/055c8128-135c-4521-ad3c-0e905308cf84)

## Overview
A high-performance, asynchronous SCADA/ICS scanner for identifying and fingerprinting industrial control systems across networks. Detects vulnerabilities, identifies vendors/products, and generates comprehensive risk reports.

**WARNING: For authorized security assessments only. Unauthorized scanning may violate laws and regulations.**

## Features

### Core Capabilities
- Fast, asynchronous scanning of CIDR ranges or individual targets
- Protocol detection for major industrial protocols (Modbus, S7, DNP3, BACnet, EtherNet/IP, etc.)
- Device fingerprinting with vendor, product, and version identification
- Vulnerability correlation with real-world CVEs and exploits
- Risk scoring and assessment

### Technical Highlights
- Multi-threaded architecture with configurable concurrency
- Rate limiting and per-host connection controls
- Behavioral fingerprinting through protocol-specific probes
- Detailed logging and comprehensive JSON reports

### Supported Protocols
- Modbus TCP
- Siemens S7
- DNP3
- BACnet
- EtherNet/IP
- IEC 60870-5-104
- OPC UA
- CODESYS
- And many others

## Installation

### Prerequisites
- Python 3.7+
- Linux/macOS/Windows

### Setup
```bash
# Clone the repository
git clone https://github.com/geeknik/scada-scanner.git
cd scada-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
# Single target scan
python scada_scanner.py -t 192.168.1.100 -o results.json

# CIDR range scan
python scada_scanner.py -c 192.168.1.0/24 -o results.json

# Multiple CIDR ranges from file
python scada_scanner.py -f networks.txt -o results.json
```

### Command Line Options
```
Required arguments (one of):
  -t, --target            Single target IP address
  -c, --cidr              CIDR range to scan (e.g., 192.168.1.0/24)
  -f, --cidr-file         File containing CIDR ranges (one per line)

Optional arguments:
  -o, --output            Output file (default: scan_results.json)
  -r, --rate              Max requests per second (default: 10.0)
  --timeout               Connection timeout in seconds (default: 5)
  --max-concurrent        Maximum concurrent connections (default: 50)
  --safe-mode             Enable safe mode (non-intrusive scans only)
  --exclude               File containing IPs to exclude from scan
  -v, --verbosity         Verbosity level: 0=quiet, 1=normal, 2=debug
  --format                Output format: json or csv (default: json)
```

## Safe Mode vs. Standard Mode

### Safe Mode
- Uses non-intrusive probes only
- Minimizes impact on target systems
- Recommended for production environments
- Enable with `--safe-mode` flag

### Standard Mode
- Uses more aggressive probing techniques
- May trigger IDS/IPS alerts
- Could potentially impact sensitive systems
- Use with caution in production environments

## Example Report
```json
{
  "scan_summary": {
    "timestamp": "2025-02-27T14:02:33.456789",
    "total_hosts_scanned": 256,
    "hosts_with_scada": 12,
    "total_vulnerabilities": 37,
    "high_risk_hosts": 5
  },
  "hosts": [
    {
      "ip": "192.168.1.100",
      "ports": [
        {
          "port": 502,
          "protocol": "MODBUS",
          "fingerprint": {
            "vendor": "Schneider",
            "product": "M340",
            "version": "2.6.0",
            "risk_score": 0.75
          }
        }
      ],
      "vulnerabilities": [
        {
          "cve_id": "CVE-2020-12345",
          "description": "Authentication bypass in Modbus TCP",
          "severity": "high"
        }
      ]
    }
  ]
}
```

## Ethical Considerations

### Legal Compliance
This tool is intended for authorized security assessments only. Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

### Best Practices
- Always obtain written permission before scanning
- Use safe mode when possible
- Scan during maintenance windows when possible
- Respect rate limits to avoid DoS conditions
- Consider the fragility of industrial systems

## Developer Documentation

### Adding New Protocols
The scanner is designed to be modular, making it easy to add support for new protocols:

1. Add the protocol details to `SCADA_PORTS` list
2. Add signature patterns to `PROTOCOL_SIGNATURES` dictionary
3. Create protocol-specific probe and analyzer functions
4. Add vulnerability information to `VULNERABILITY_DATABASE`

### Contributing
Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHORS DISCLAIM ALL LIABILITY FOR ANY DAMAGE OR LOSS RESULTING FROM THE USE OF THIS SOFTWARE.
