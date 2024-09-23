from scapy.all import rdpcap




# def read_raw_data_in_packet(file_path, packet_number):
#     try:
#         # Read the PCAP file
#         packets = rdpcap(file_path)

#         # Check if the specified packet number is within the valid range
#         if 0 <= packet_number < len(packets):
#             # Access the specific packet by its index
#             specific_packet = packets[packet_number]

#             # Access the raw data (payload) of the packet
#             raw_data = specific_packet.payload

#             # Print the raw data
#             print("Raw Data:")
#             print(raw_data)

#         else:
#             print(f"Invalid packet number: {packet_number}. It should be between 0 and {len(packets) - 1}.")

#     except Exception as e:
#         print(f"Error reading PCAP file: {e}")

def read_pcap_file(file_path):
    try:
        # Read the PCAP file
        packets = rdpcap(file_path)
        count = 0
        # Process each packet in the PCAP file
        for packet in packets:
            # Print information about the packet
            # print(packet.summary())
            # print(count, packet.payload)
            specific_packet = packets[count]
            raw_data = specific_packet.payload
            print(count, raw_data)
            count += 1

    except Exception as e:
        print(f"Error reading PCAP file: {e}")

# Replace 'your_file.pcap' with the actual path to your PCAP file
pcap_file_path = 'diabloCTF.pcap'
read_pcap_file(pcap_file_path)
