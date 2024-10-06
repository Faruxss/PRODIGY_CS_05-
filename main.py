from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
    """
    Callback function to process captured packets.
    It checks if the packet contains an IP layer, then determines
    whether it is a TCP, UDP, or another type of packet.
    """
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        proto = packet[IP].proto  # Protocol number

        # Handling TCP packets
        if TCP in packet:
            sport = packet[TCP].sport  # Source port
            dport = packet[TCP].dport  # Destination port
            print(f"TCP Packet: Source IP {ip_src}:{sport}, Destination IP {ip_dst}:{dport}")

        # Handling UDP packets
        elif UDP in packet:
            sport = packet[UDP].sport  # Source port
            dport = packet[UDP].dport  # Destination port
            print(f"UDP Packet: Source IP {ip_src}:{sport}, Destination IP {ip_dst}:{dport}")

        # Handling other packet types
        else:
            print(f"Other Packet: Source IP {ip_src}, Destination IP {ip_dst}, Protocol: {proto}")


def start_packet_capture(packet_count=10):
    """
    Function to start packet capture. It captures the specified number of packets
    and processes them using the callback function.
    """
    print(f"Starting packet capture for {packet_count} packets...")
    sniff(prn=packet_callback, count=packet_count)


# Start capturing 10 packets
if __name__ == "__main__":
    start_packet_capture(packet_count=10)
