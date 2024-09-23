# To open and inspect a specific packet number in a PCAP file 

from scapy.all import rdpcap

def open_specific_packet(file_path, packet_number):
    try:
        # Read the PCAP file
        packets = rdpcap(file_path)

        # Check if the specified packet number is within the valid range
        if 0 <= packet_number < len(packets):
            # Access the specific packet by its index
            specific_packet = packets[packet_number]

            # Print information about the specific packet
            print(specific_packet.summary())

        else:
            print(f"Invalid packet number: {packet_number}. It should be between 0 and {len(packets) - 1}.")

    except Exception as e:
        print(f"Error reading PCAP file: {e}")

# Replace 'your_file.pcap' with the actual path to your PCAP file
pcap_file_path = 'diabloCTF.pcap'
# Replace 0 with the specific packet number you want to open
desired_packet_number = 34

open_specific_packet(pcap_file_path, desired_packet_number)
