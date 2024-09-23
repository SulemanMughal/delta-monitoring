from scapy.all import sniff, wrpcap

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def capture_and_save_pcap(filename, filter=None, timeout=10):
    print("Starting")
    # Define a callback function to process each captured packet
    def packet_callback(packet):
        # You can process the packet or simply print information
        print(packet.summary())

    # Capture packets for a limited duration (timeout) and apply the callback function
    captured_packets = sniff(iface="ens33", prn=packet_callback, timeout=timeout)

    # Save the captured packets to a PCAP file
    wrpcap(filename, captured_packets)
    print("ending")



# capture_and_save_pcap("captured_packets.pcap", filter="tcp", timeout=30)
    

if __name__ == "__main__":
    # capture_and_save_pcap("captured_packets.pcap", filter="tcp", timeout=30)
    print(BASE_DIR.parent / 'pcap_files')
