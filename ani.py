from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "Other"
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        payload = packet[Raw].load if packet.haslayer(Raw) else b''
        print(f"\n[+] {proto} Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Payload: {payload[:100]}")  # First 100 bytes

sniff(filter="ip", prn=process_packet, count=10)