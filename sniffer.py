# sniffer.py
from scapy.all import sniff
from parser import parse_packet

def packet_callback(packet):
    info = parse_packet(packet)
    if info:
        print(f"[{info['protocol']}] {info['src_ip']} -> {info['dst_ip']}", end="")
        if "src_port" in info:
            print(f" | Ports: {info['src_port']} -> {info['dst_port']}")
        else:
            print()

def main():
    print("Sniffing packets... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
	