import os
import tempfile

# Force Scapy to use a writable temp folder
temp_cache = os.path.join(tempfile.gettempdir(), "scapy_cache")
os.makedirs(temp_cache, exist_ok=True)

os.environ["HOME"] = temp_cache
os.environ["XDG_CACHE_HOME"] = temp_cache
os.environ["SCAPY_CACHE_FOLDER"] = temp_cache
os.environ["SCAPY_USE_CACHE"] = "0"

from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
import re
import json


# ---------- Redaction Functions ----------
def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"
    return ip


def redact_text(text):
    text = re.sub(r'[\w\.-]+@[\w\.-]+', '[REDACTED_EMAIL]', text)
    text = re.sub(r'password=\S+', 'password=[REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'token=\S+', 'token=[REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'Cookie:.*', 'Cookie: [REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'Authorization:.*', 'Authorization: [REDACTED]', text, flags=re.IGNORECASE)
    return text


# ---------- Packet Parsing ----------
def parse_packet(pkt):
    output = {}

    if IP in pkt:
        output["src_ip"] = mask_ip(pkt[IP].src)
        output["dst_ip"] = mask_ip(pkt[IP].dst)

    if TCP in pkt:
        output["protocol"] = "TCP"
        output["src_port"] = pkt[TCP].sport
        output["dst_port"] = pkt[TCP].dport

    elif UDP in pkt:
        output["protocol"] = "UDP"
        output["src_port"] = pkt[UDP].sport
        output["dst_port"] = pkt[UDP].dport

    if DNS in pkt and pkt[DNS].qd:
        output["dns_query"] = pkt[DNS].qd.qname.decode(errors="ignore")

    if Raw in pkt:
        payload = pkt[Raw].load.decode(errors="ignore")
        output["payload"] = redact_text(payload[:200])

    return output


# ---------- Main ----------
def main():
    print("Reading packets from sample.pcap ...")
    packets = rdpcap("sample.pcapng")

    count = 0
    for pkt in packets[:25]:
        parsed = parse_packet(pkt)
        print(json.dumps(parsed, indent=2))
        count += 1

    print(f"\nProcessed {count} packets.")


if __name__ == "__main__":
    main()