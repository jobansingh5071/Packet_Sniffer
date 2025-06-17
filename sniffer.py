# sniffer.py
import argparse
from scapy.all import sniff
from parser import parse_packet

def packet_callback(packet, args):
    info = parse_packet(packet)

    if not info:
        return

    # Apply filters
    if args.ip and args.ip not in (info['src_ip'], info['dst_ip']):
        return
    if args.protocol and args.protocol.upper() != info['protocol']:
        return
    if args.port:
        port = str(info.get('src_port', '')) + str(info.get('dst_port', ''))
        if str(args.port) not in port:
            return

    # Print the filtered result
    print(f"[{info['protocol']}] {info['src_ip']} -> {info['dst_ip']}", end="")
    if "src_port" in info:
        print(f" | Ports: {info['src_port']} -> {info['dst_port']}")
    else:
        print()

def main():
    parser = argparse.ArgumentParser(description="Python Packet Sniffer with Filters")
    parser.add_argument("--ip", help="Filter by IP address")
    parser.add_argument("--protocol", help="Filter by protocol (TCP, UDP, ICMP)")
    parser.add_argument("--port", type=int, help="Filter by port number")
    args = parser.parse_args()

    print("Sniffing packets... Press Ctrl+C to stop.")
    sniff(prn=lambda pkt: packet_callback(pkt, args), store=False)

if __name__ == "__main__":
    main()
