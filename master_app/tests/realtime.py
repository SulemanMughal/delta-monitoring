# # from scapy.all import sniff

# # def packet_callback(packet):
# #     if packet.haslayer('IP'):
# #         ip_src = packet['IP'].src
# #         ip_dst = packet['IP'].dst
# #         print(f"Packet from {ip_src} to {ip_dst}")

# # # Start sniffing on the network interface (e.g., 'eth0' on Linux)
# # sniff(prn=packet_callback, store=0)


# from scapy.all import sniff, IP

# target_ip = "192.168.0.143"  # Replace with the IP address you want to monitor

# def packet_callback(packet):
#     # if packet.haslayer(IP) and (packet[IP].dst == target_ip):
#     if packet.haslayer(IP) :
        
#         ip_src = packet[IP].src
#         ip_dst = packet[IP].dst
#         if str(packet[IP].dst) == str(target_ip):
#             print(f"Packet from {ip_src} to {ip_dst}")

# # Start sniffing on the network interface
# sniff(prn=packet_callback, store=0)


from scapy.all import sniff, IP, TCP

target_ip = "192.168.0.143"  # Replace with the IP address you want to monitor
target_port = "8000"         # Replace with the port number you want to monitor

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        

        # if ip_dst == target_ip and port_dst == target_port:
        #     print(f"Packet from {ip_src}:{port_src} to {ip_dst}:{port_dst}")

        # s

# Start sniffing on the network interface
    sniff(prn=packet_callback, store=0, filter="tcp")
