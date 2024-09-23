import time
from scapy.all import *
import sys
from io import BytesIO
import traceback

# from django.conf import settings
# from .models import *


# from .utils import (
#     ETHERNET_IP_VERSION_TYPE
# )



ETHERNET_IP_VERSION_TYPE= {
    "2048" : "IPv4",
}




def decode_string(string):
    try:    
        s1 = string.decode('unicode-escape', "ignore")
        s2 = s1.encode('latin-1', "ignore")
        s3 = s2.decode('UTF8', "ignore")
        return s3
    except Exception as e:
        print("Error in decode_string")
        return None


def get_ethernet_type(packet):
    try:
        return ETHERNET_IP_VERSION_TYPE.get(str(packet.type  or  ''), "Unknown")
    except Exception as e:
        # print(e)
        return None



# Get Protocol Name by number
def proto_name_by_num(packet):
    try:
        for name,num in vars(socket).items():
            if name.startswith("IPPROTO") and packet.proto == num:
                return name[8:]
        return None
    except Exception as e:
        # print(e)
        return None
    
# Get Packet Source Port
    
def get_packet_src_port(packet):
    try:
        return packet.sport
    except Exception as e:
        # print(e)
        return None
    

def get_packet_dst_port(packet):
    try:
        return packet.dport
    except Exception as e:
        # print(e)
        return None
    
# def detect_nmap(payload):
#     try:
#         if "nmap" in payload.lower():
#             return "Y"
#         else:
#             return "N"
#     except Exception as e:
#         return "N"


def read_payload(packet):
    payload = None
    is_detected_nmap = "N"
    try:
        if TCP in packet:
            payload = decode_string(packet[TCP].payload)
            if payload and  "nmap" in payload.lower():
                is_detected_nmap = "Y"
        if Raw in packet:
            payload = decode_string(packet[Raw].load)
    except :
        traceback.print_exc()
    return (payload, is_detected_nmap)





def get_packet_dst_ip(packet):
    try:
        return packet[IP].dst
    except Exception as e:
        return None
    


def get_packet_src_ip(packet):
    try:
        return packet[IP].src
    except Exception as e:
        return None


def get_packer_details(result):
    packet_list = []
    try:
        if result is not None:
            for packet in result:
                x = read_payload(packet)
                if x[0] is not None:
                    if not x[0].isspace():
                        packet_list.append(
                            (
                                get_packet_dst_ip(packet),
                                get_packet_src_ip(packet),
                                # get_ethernet_type(packet),
                                proto_name_by_num(packet),
                                get_packet_src_port(packet),
                                get_packet_dst_port(packet),
                                x[0],
                                # x[1],
                                # packet # Raw Packet
                            )
                        )
    except Exception as e:
        traceback.print_exc()
    return packet_list


