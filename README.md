# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Student
Oreoluwa Ayinde

## Project Overview
This project is a packet sniffer built in Python using the Scapy library. It reads packets from a `.pcapng` capture file instead of live sniffing, which provides a safer and easier way to analyze network traffic.

The tool extracts useful packet information such as:

- Source IP address
- Destination IP address
- Protocol (TCP / UDP)
- Source and destination ports
- DNS queries
- Packet payload data

Sensitive information is redacted before output.

---

## Ethical Controls

This project only analyzes authorized lab traffic from a local packet capture file.

The program includes privacy protections:

- IP addresses are partially masked
- Email addresses are redacted
- Password values are redacted
- Tokens are redacted
- Cookies are redacted
- Authorization headers are redacted

---

## Files Included

- `sniffer.py` → Main Python script
- `sample.pcapng` → Packet capture file
- `tests/test-sniffer.py` → Basic tests
- `README.md` → Project documentation

---

## Requirements

Install Scapy:

```bash
pip install scapy