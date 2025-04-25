from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("\n[+] Packet Captured:")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"    From: {ip_layer.src} --> To: {ip_layer.dst} | Protocol: {ip_layer.proto}")
    
    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"    [TCP] Port: {tcp_layer.sport} --> {tcp_layer.dport}")
    
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"    [UDP] Port: {udp_layer.sport} --> {udp_layer.dport}")
    
    elif ICMP in packet:
        print("    [ICMP] Packet Type Detected")

print("Starting packet sniffing on Windows...")
sniff(prn=packet_callback, store=False)
