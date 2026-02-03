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

## Requirements
- Python 3
- Scapy
- Root privileges for SYN scan and subnet scan

## Usage

Scan a single host:
```bash
python3 scanner.py 127.0.0.1
Scan a subnet (LAN):

sudo python3 scanner.py --subnet 192.168.1.0/24

Stealth scan:

sudo python3 scanner.py example.com --S
