from scapy.all import rdpcap, IP, TCP

def read_payload_in_packet(file_path, packet_number):
    try:
        # Read the PCAP file
        packets = rdpcap(file_path)

        # Check if the specified packet number is within the valid range
        if 0 <= packet_number < len(packets):
            # Access the specific packet by its index
            specific_packet = packets[packet_number]

            # Check if the packet has IP and TCP layers
            if IP in specific_packet and TCP in specific_packet:
                # Access the payload of the TCP layer
                payload = specific_packet[TCP].payload

                # Print the payload (Layer 4 and above) in hexadecimal format
                print(f"Hexadecimal Payload for Packet {packet_number}:\n{payload}")

            else:
                print(f"Packet {packet_number} does not have IP and TCP layers.")

        else:
            print(f"Invalid packet number: {packet_number}. It should be between 0 and {len(packets) - 1}.")

    except Exception as e:
        print(f"Error reading PCAP file: {e}")

# Replace 'your_file.pcap' with the actual path to your PCAP file
pcap_file_path = 'diabloCTF.pcap'
# Replace 0 with the specific packet number you want to read
desired_packet_number = 32

read_payload_in_packet(pcap_file_path, desired_packet_number)
