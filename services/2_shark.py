import pyshark
# try:
#     capture = pyshark.LiveCapture(interface="VMware Network Adapter VMnet8", output_file="pyshark.pcap")
#     capture.sniff()
# except KeyboardInterrupt:
#     print(capture)

import time
import sys



def read_payload(packet):
    print(packet)
    

    # pyshark read packets for a limite dtime
    # pyshark.LiveCapture( interface= 'Ethernet 2', output_file="pyshark.pcap")



# def collect_packets(iface, time_out):
#     print("start Capturing")
#     timeout_seconds = int(time_out)
#     start_time = time.time()
#     captured_packets = []
#     while time.time() - start_time < timeout_seconds:
#         capture  = pyshark.LiveCapture( interface= str(iface))
#         # capture.sniff(timeout=time_out)
#         for raw_packet in capture.sniff_continuously():
#             print(filter_all_tcp_traffic_file(raw_packet))

#         #c = sniff( iface= 'Ethernet 2', timeout=1)
#         # print(c.summary())
#         # for packet in c:
            
#         #     # print(packet.lastlayer())
#         #     # print(hexdump(packet.lastlayer()))
#         #     read_payload(packet)
#             # captured_packets.append(packet)

#     # packets = get_packer_details(captured_packets)
#     # print(packets)
#     print("end Capturing")
    
def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface)
    for raw_packet in capture.sniff_continuously():
        print(filter_all_tcp_traffic_file(raw_packet))


def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'


def filter_all_tcp_traffic_file(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP) packets
    :param packet: raw packet
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
        results = get_packet_details(packet)
        try:
           print(packet.get_raw_packet())
        except :
            pass
        
        return results

# if __name__ == "__main__":
#     if len(sys.argv) > 1:
#         collect_packets(sys.argv[1], sys.argv[2])
#     else:
#         # print("Hello, world!")
#         print("Pass interface name as argument like \n\npython test_scapy.py eno2" )
    




capture_live_packets('VMware Network Adapter VMnet8')
