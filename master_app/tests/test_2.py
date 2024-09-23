from scapy.all import rdpcap, TCP

def filter_packets_by_port(file_path, port):
    try:
        # Read the PCAP file
        packets = rdpcap(file_path)

        # Filter packets based on the specified TCP port
        filtered_packets = [packet for packet in packets if TCP in packet and (packet[TCP].sport == port or packet[TCP].dport == port)]

        # Process the filtered packets
        for packet in filtered_packets:
            # Print information about the packet
            print(packet.summary())

    except Exception as e:
        print(f"Error reading/filering PCAP file: {e}")

# Replace 'your_file.pcap' with the actual path to your PCAP file
pcap_file_path = 'diabloCTF.pcap'
# Replace 80 with the specific TCP port you are interested in
desired_port = 80

filter_packets_by_port(pcap_file_path, desired_port)
