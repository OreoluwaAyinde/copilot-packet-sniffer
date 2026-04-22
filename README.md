# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Overview

This project is a Python-based packet sniffer that reads packets from a `.pcapng` capture file using Scapy. It safely analyzes network traffic in an authorized lab environment while redacting sensitive information.

## Features

* Reads packets from saved PCAP files
* Decodes IP, TCP, UDP, and DNS traffic
* Displays packet summaries in JSON format
* Masks IP addresses
* Redacts emails, passwords, tokens, cookies, and authorization headers
* Includes unit tests for redaction functions

## Files

* `sniffer.py` – main packet parser
* `sample.pcapng` – sample traffic capture
* `tests/test-sniffer.py` – unit tests
* `README.md` – project documentation

## Requirements

* Python 3.x
* Scapy

Install Scapy:

```bash
pip install scapy
```

## Run Project

```bash
python sniffer.py
```

## Example Output

```json
{
  "src_ip": "192.168.1.xxx",
  "dst_ip": "8.8.8.xxx",
  "protocol": "UDP"
}
```

## Ethical Use Policy

Use only on:

* Your own device
* Loopback traffic
* Instructor-provided lab systems
* Authorized packet capture files

Do not use on unauthorized networks or devices.

## AI Assistance Reflection

GitHub Copilot was used for boilerplate coding ideas, parsing structure, and test scaffolding. All output was reviewed and modified for safe and ethical use.
