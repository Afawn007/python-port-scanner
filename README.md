# Python Port & Subnet Scanner

A Python-based TCP port scanner with support for:
- TCP connect scan
- SYN (stealth) scan
- ARP-based subnet discovery (LAN)
- HTTP/HTTPS banner grabbing

## Features
- Scan a single host or an entire subnet
- Detect open and closed TCP ports
- Works on localhost, LAN, and remote hosts
- Uses ARP for reliable LAN host discovery
 ## Platform Support

- Linux: Full support
- macOS: Full support (requires root)
- Windows:
  - TCP connect scan supported
  - SYN scan and subnet discovery not supported

- ## Requirements

- Python 3.9+
- Scapy
- Linux or macOS (raw packet support required)
- Root privileges for:
  - SYN (stealth) scan
  - Subnet (ARP) scan
  ## Installation

```bash
pip install scapy
```
  
Disclaimer
This tool is intended for educational purposes and authorized security testing only.
Do not scan systems you do not own or have permission to test.
## Installation

Clone the repository:

```bash
git clone https://github.com/Afawn007/python-port-scanner.git
cd python-port-scanner
```



## Usage


Scan a single host:
```bash
python3 scanner.py 127.0.0.1
Scan a subnet (LAN):

sudo python3 scanner.py --subnet 192.168.1.0/24

Stealth scan:

sudo python3 scanner.py example.com --S
