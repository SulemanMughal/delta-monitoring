from scapy.all import IP, TCP, sniff

def packet_callback(packet):
    if TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        seq_number = packet[TCP].seq
        ack_number = packet[TCP].ack
        payload = packet[TCP].payload.load.decode('utf-8', errors='ignore')

        # Check if it's the first packet in the stream
        if 'TCP_Stream' not in packet:
            packet['TCP_Stream'] = {'client': '', 'server': ''}

        # Determine if the packet is going from the client to the server or vice versa
        direction = 'client' if ip_src == '192.168.14.191' and tcp_sport == client_port else 'server'

        # Update the TCP stream for the appropriate direction
        packet['TCP_Stream'][direction] += payload

        print(f"{direction.capitalize()} to {ip_dst}:{tcp_dport} (Seq: {seq_number}, Ack: {ack_number}):")
        print(payload)
        print('-' * 50)

# Set the client's IP and port
client_ip = '192.168.14.191'
client_port = 80

# Sniff traffic on a specific interface (e.g., 'eth0')
interface = 'VMware Network Adapter VMnet8'
sniff(iface=interface, prn=packet_callback, store=0, filter=f'tcp port {client_port}')
