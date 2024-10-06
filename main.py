import argparse
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

# Function to handle each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Add timestamp

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            log_packet(f"[{timestamp}] TCP Packet: Source IP {ip_src}:{sport}, Destination IP {ip_dst}:{dport}")

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            log_packet(f"[{timestamp}] UDP Packet: Source IP {ip_src}:{sport}, Destination IP {ip_dst}:{dport}")

        else:
            log_packet(f"[{timestamp}] Other Packet: Source IP {ip_src}, Destination IP {ip_dst}, Protocol: {proto}")

# Function to log packet details to a file or print to console
def log_packet(packet_info):
    if args.output:
        with open(args.output, "a") as log_file:
            log_file.write(packet_info + "\n")
    else:
        print(packet_info)

# Argument parser setup
parser = argparse.ArgumentParser(description="A simple packet sniffer.")
parser.add_argument("--protocol", choices=["tcp", "udp", "all"], default="all",
                    help="Filter packets by protocol (tcp, udp, or all). Default is all.")
parser.add_argument("--count", type=int, default=10, 
                    help="Number of packets to capture. Default is 10.")
parser.add_argument("--output", help="Log output to a file instead of printing to the console.")

args = parser.parse_args()

# Filter logic based on protocol argument
if args.protocol == "tcp":
    protocol_filter = lambda pkt: TCP in pkt
elif args.protocol == "udp":
    protocol_filter = lambda pkt: UDP in pkt
else:
    protocol_filter = None  # Capture all protocols if no filter is set

print(f"Starting packet capture... Capturing {args.count} packets.")
if args.protocol != "all":
    print(f"Filtering by protocol: {args.protocol.upper()}")

sniff(prn=packet_callback, count=args.count, lfilter=protocol_filter)
