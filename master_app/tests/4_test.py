from scapy.all import *

# Replace 'your_file.pcap' with the path to your pcap file
file_path = 'diabloCTF.pcap'

# Read the pcap file
packets = rdpcap(file_path)

# Index of the packet you want to read (replace with the desired index)
packet_index = 32

# Check if the index is within the valid range
if 0 <= packet_index < len(packets):
    # Access the specific packet
    specific_packet = packets[packet_index]

    # Print the details of the specific packet
    print(specific_packet.show())
else:
    print(f"Invalid packet index: {packet_index}")
