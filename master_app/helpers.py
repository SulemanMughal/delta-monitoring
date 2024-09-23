from scapy.all import *

from django.conf import settings

import socket


target_port = int(settings.TARGET_PORT)



def get_filtered_packets(packets, target_port=  int(settings.TARGET_PORT)):
    filtered_packets = [packet for packet in packets if packet.haslayer(TCP) and (packet[TCP].dport == target_port or packet[TCP].sport == target_port)]
    return filtered_packets

def read_pcap_file(filename , target_port = target_port):
    packets = rdpcap(filename)
    filtered_packets = get_filtered_packets(packets, target_port)
    return filtered_packets


def get_protocol_name(protocol):
    # print(protocol)
    try:
        return socket.getservbyport(6)
    except Exception as e:
        print(e)


# def proto_name_by_num(packet):
#     print(packet)
#     for name,num in vars(socket).items():
#         if name.startswith("IPPROTO") and packet.proto == num:
#             return name[8:]
#     return "Protocol not found"

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"



def read_payload(packet):
    try:
        # print(packet.load)
        # print(str(packet.load, 'latin-1'))
        return str(packet.load, 'latin-1', errors="replace").replace("\x00", ".")
    except Exception as e:
        print(e)
    return None

def read_payload_v2(packet):
    try:
        # print(str(packet.load, 'latin-1'))
        # convert_1 = str(packet.load, 'latin-1')
        convert_1 = str(packet.load, 'latin-1', errors="replace").replace("\x00", "\uFFFD")
        # byte_sequence = bytes.fromhex(convert_1[2:].replace('\\u', ''))
        # decoded_text = byte_sequence.decode('utf-16')
        # convert_2 = str(packet.load, 'latin-1')

        # return str(packet.load, 'latin-1')s
        # return decoded_text
        return convert_1
    except Exception as e:
        print(e)
    return ""


def get_packet_src_ip(packet):
    try:
        # print(ls(packet))
        # print(packet[IP].src)
        return packet[IP].src
    except Exception as e:
        print(e)
        return None
    


def get_packet_dst_ip(packet):
    try:
        # print(ls(packet))
        # print(packet[IP].src)
        return packet[IP].dst
    except Exception as e:
        print(e)
        return None


def decode_string(string):
    try:
        return string.decode('utf-8')
    except Exception as e:
        print(e)
        return None