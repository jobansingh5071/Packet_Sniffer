# parser.py
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")

        info = {
            "protocol": protocol,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
        }

        if protocol == "TCP" and TCP in packet:
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
        elif protocol == "UDP" and UDP in packet:
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport

        return info
    return None
