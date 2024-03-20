from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    global packet_count
    packet_count += 1

    if IP in packet:
        ip_packet = packet[IP]
        src_ip, dst_ip = ip_packet.src, ip_packet.dst

        if TCP in ip_packet:
            protocol = "TCP"
            src_port, dst_port = ip_packet[TCP].sport, ip_packet[TCP].dport
            payload = ip_packet[TCP].payload
        elif UDP in ip_packet:
            protocol = "UDP"
            src_port, dst_port = ip_packet[UDP].sport, ip_packet[UDP].dport
            payload = ip_packet[UDP].payload
        else:
            protocol, src_port, dst_port, payload = "Other", None, None, None

        print(f"Packet {packet_count}:")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        if src_port and dst_port:
            print(f"Ports: {src_port} -> {dst_port}")

        # first 16 bytes of payload in hexadecimal format
        if payload:
            payload_hex = payload.original.hex()[:32]  # Truncate to 16 bytes
            print(f"Payload (Hex): {payload_hex}...")

def main():
    global packet_count
    packet_count = 0

    # sniffing packets on the default network interface (you can specify an interface)
    sniff(filter="ip", prn=packet_handler, count=10)

    # total number of packets captured
    print(f"Total number of packets captured: {packet_count}")
    print()  # Add an empty line for separation

if __name__ == "__main__":
    main()
