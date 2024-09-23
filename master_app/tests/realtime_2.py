from scapy.all import sniff, IP, TCP
import time

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport

        print(f"Packet from {ip_src}:{port_src} to {ip_dst}:{port_dst}")

# Run Scapy for 10 seconds
timeout_seconds = 10
start_time = time.time()

while time.time() - start_time < timeout_seconds:
    sniff(prn=packet_callback, store=0, filter="tcp", count=1)

# Optionally, you can add cleanup or additional processing after the sniffing loop
print("Scapy finished running.")