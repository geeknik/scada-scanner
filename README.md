# SCADA Scanner and Fingerprinter

<img src="https://github.com/user-attachments/assets/ada0122d-6d53-4006-8296-f91978617837" />

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
- Token-bucket rate limiting to respect global request caps
- Rate limiting and per-host connection controls
- Behavioral fingerprinting through protocol-specific probes
- Port-aware protocol heuristics with evidence trails for detections
- Detailed logging and comprehensive JSON/CSV reports

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

# Export CSV instead of JSON
python scada_scanner.py -t 192.168.1.100 --format csv -o results.csv

# Respect an exclude list
python scada_scanner.py -c 10.0.0.0/24 --exclude exclude.txt

# Highlight unexpected protocol/port combos (logged and in findings)
python scada_scanner.py -t 203.0.113.10 -o results.json

# Enable live vuln enrichment via ProjectDiscovery vulnx (requires vulnx + PDCP API key)
vulnx auth
python scada_scanner.py -t 192.168.1.100 --vulnx --vulnx-limit 3
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
            "risk_score": 0.75,
            "evidence": [
              "response:00010000000101",
              "port_hint:502"
            ],
            "findings": [
              "Detected MODBUS protocol (confidence: 0.55)",
              "Identified vendor: SCHNEIDER, product: M340",
              "Overall risk assessment: High (score: 0.75)"
            ],
            "unexpected_port": false
          }
        }
      ],
      "vulnerabilities": [
        {
          "cve_id": "CVE-2025-55221",
          "description": "Socomec DIRIS Digiware M-70 DoS via crafted Modbus TCP/RTU over TCP packets",
          "severity": "high",
          "source": "local_db"
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

## Vulnerability Intelligence

The scanner ships with a small built-in vulnerability database for core protocols (see `VULNERABILITY_DATABASE`). For fresher intel you can enable the optional [ProjectDiscovery vulnx](https://github.com/projectdiscovery/vulnx) integration:

1. Install `vulnx` and configure your PDCP API key (`vulnx auth`).
2. Run with `--vulnx` (optionally tune `--vulnx-limit` and `--vulnx-timeout`).
3. Vulns from vulnx are merged with local findings and marked with `source: "vulnx"`.

If `vulnx` is missing or unreachable, the scanner silently falls back to the local database.
Local database entries are periodically refreshed from vulnx searches for core protocols (captured in this repo snapshot) and are tagged with `source: "local_db"`.

## Testing

Run the unit test suite:
```bash
pytest
```

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
