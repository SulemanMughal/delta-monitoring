import dpkt

def read_payload_in_packet(file_path, packet_number):
    try:
        # Open the PCAP file
        with open(file_path, 'rb') as pcap_file:
            # Create a PCAP reader
            pcap_reader = dpkt.pcap.Reader(pcap_file)

            # Read packets and find the specified packet
            for i, (timestamp, packet) in enumerate(pcap_reader):
                if i == packet_number:
                    # Parse the Ethernet frame
                    eth = dpkt.ethernet.Ethernet(packet)

                    # Check if the Ethernet frame contains an IP packet
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip_packet = eth.data

                        # Check if the IP packet contains a TCP segment
                        if isinstance(ip_packet.data, dpkt.tcp.TCP):
                            tcp_segment = ip_packet.data

                            # Access the payload of the TCP segment
                            payload = tcp_segment.data

                            # Print the payload in hexadecimal format
                            print(f"Hexadecimal Payload for Packet {packet_number}:\n{' '.join(format(byte, '02x') for byte in payload)}")

                            try:
                                decoded_payload = payload.decode('latin-1')
                                print(f"Human Readable Payload for Packet {packet_number}:\n{decoded_payload}")

                            except UnicodeDecodeError:
                                print(f"Payload for Packet {packet_number} is not in UTF-8 encoding.")

                                
                            return

    except Exception as e:
        print(f"Error reading PCAP file: {e}")

# Replace 'your_file.pcap' with the actual path to your PCAP file
pcap_file_path = 'diabloCTF.pcap'
# Replace 0 with the specific packet number you want to read
desired_packet_number = 32

read_payload_in_packet(pcap_file_path, desired_packet_number)

