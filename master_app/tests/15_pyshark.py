import pyshark

def extract_statistics_pcap_pyshark(pcap_file):
    capture = pyshark.FileCapture(pcap_file)

    # Basic statistics
    num_packets = len(capture)
    print(capture[0])
    # print(num_packets)
    duration = float(capture[-1].sniff_timestamp) - float(capture[0].sniff_timestamp)

    # Protocol distribution
    protocol_counts = {}
    for packet in capture:
        if hasattr(packet, 'protocol'):
            protocol = packet.protocol
            print(protocol)
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    return {
        'num_packets': num_packets,
        'duration': duration,
        'protocol_counts': protocol_counts,
    }

# Example usage
pcap_file_pyshark = "172_165_120_189.pcap"
statistics_pyshark = extract_statistics_pcap_pyshark(pcap_file_pyshark)
print("Statistics (PyShark):") 
print(f"Number of packets: {statistics_pyshark['num_packets']}")
print(f"Duration: {statistics_pyshark['duration']} seconds")
print("Protocol distribution:")
for protocol, count in statistics_pyshark['protocol_counts'].items():
    print(f"{protocol}: {count} packets")
