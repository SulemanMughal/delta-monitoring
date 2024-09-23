from scapy.all import *

# Replace 'your_file.pcap' with the path to your pcap file
file_path = 'diabloCTF.pcap'

# Read the pcap file
packets = rdpcap(file_path)

# Index of the packet you want to read (replace with the desired index)
packet_index = 32

target_port = 30025


filtered_packets = [packet for packet in packets if packet.haslayer(TCP) and (packet[TCP].dport == target_port or packet[TCP].sport == target_port)]

for i in range(len(filtered_packets)):
    # print(i, filtered_packets[i].summary())
    print(i, filtered_packets[i].show())
    try:
        # print(i, filtered_packets[i].load)
        payload_str = str(filtered_packets[i].load, 'latin-1')
        print( payload_str)

    except:
        print("-"*70,   i, "-"*70, sep="\n")


for packet in filtered_packets:
    print(packet.summary())
    payload_str = str(packet.load, 'latin-1')
    print( payload_str)



# Check if the index is within the valid range
if 0 <= packet_index < len(packets):
    # Access the specific packet
    specific_packet = packets[packet_index]

    # Extract and print the payload (load) as a stringmz
    payload_str = str(specific_packet.load, 'latin-1')
    # print("Payload (load):", payload_str)
    print( payload_str)
    # print(specific_packet.summary())
else:
    print(f"Invalid packet index: {packet_index}")
