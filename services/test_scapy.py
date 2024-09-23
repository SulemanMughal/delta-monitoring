
# import time
# from scapy.all import *

# import traceback

# ETHERNET_IP_VERSION_TYPE= {
#     "2048" : "IPv4",
# }



# def get_ethernet_type(packet):
#     try:
#         return ETHERNET_IP_VERSION_TYPE.get(str(packet.type  or  ''), "Unknown")
#     except Exception as e:
#         # print(e)
#         return None



# # Get Protocol Name by number
# def proto_name_by_num(packet):
#     try:
#         for name,num in vars(socket).items():
#             if name.startswith("IPPROTO") and packet.proto == num:
#                 return name[8:]
#         return None
#     except Exception as e:
#         # print(e)
#         return None
    
# # Get Packet Source Port
    
# def get_packet_src_port(packet):
#     try:
#         return packet.sport
#     except Exception as e:
#         # print(e)
#         return None
    

# def get_packet_dst_port(packet):
#     try:
#         return packet.dport
#     except Exception as e:
#         # print(e)
#         return None
    


# def read_payload(packet):
#     try:
#         print(packet.load)
#         return str(packet.load, 'latin-1', errors="replace").replace("\x00", ".")
#     except :
#         traceback.print_exc()
#         # print(e)
#     return None





# def get_packet_dst_ip(packet):
#     try:
#         return packet[IP].dst
#     except Exception as e:
#         return None
    


# def get_packet_src_ip(packet):
#     try:
#         return packet[IP].src
#     except Exception as e:
#         return None



# def get_packer_details(result):
#     packet_list = []
#     if result is not None:
#         for packet in result:
#             x = read_payload(packet)
#             if x is not None:
#                 if not x.isspace():
#                     packet_list.append(
#                         (
#                             get_packet_dst_ip(packet),
#                             get_packet_src_ip(packet),
#                             get_ethernet_type(packet),
#                             proto_name_by_num(packet),
#                             get_packet_src_port(packet),
#                             get_packet_dst_port(packet),
#                             x
#                         )
#                     )
#     return packet_list






# def collect_packets():
#     timeout_seconds = 1
#     start_time = time.time() 
#     captured_packets = []
#     while time.time() - start_time < timeout_seconds:
#         # c = sniff( iface= 'ens33', timeout=1)
#         c = sniff( iface= 'ens33', timeout=1)
#         print(c.summary())
#         for packet in c:
#             read_payload(packet)
#             # captured_packets.append(packet)

#     # packets = get_packer_details(captured_packets)
#     # print(packets)
        

# if __name__ == "__main__":
#     collect_packets()


import time
from scapy.all import *

import sys
from scapy.utils import hexdump


import traceback

ETHERNET_IP_VERSION_TYPE= {
    "2048" : "IPv4",
}
import urllib.parse



def get_ethernet_type(packet):
    try:
        return ETHERNET_IP_VERSION_TYPE.get(str(packet.type  or  ''), "Unknown")
    except Exception as e:
        traceback.print_exc()
        return None



# Get Protocol Name by number
def proto_name_by_num(packet):
    try:
        for name,num in vars(socket).items():
            if name.startswith("IPPROTO") and packet.proto == num:
                return name[8:]
        return None
    except Exception as e:
        traceback.print_exc()
        return None

# Get Packet Source Port

def get_packet_src_port(packet):
    try:
        return packet.sport
    except Exception as e:
        traceback.print_exc()
        return None


def get_packet_dst_port(packet):
    try:
        return packet.dport
    except Exception as e:
        traceback.print_exc()
        return None


# check a string is utf8 encoded or utf16 encoded
def is_utf8(s):
    try:
        s.decode('utf-8')
    except UnicodeDecodeError:
        return False
    else:
        return True

def read_payload(packet):
    try:
        # print(packet.hide_defaults())
        # print(Ether(raw(packet)))
        # print(export_object(packet))
        # print(raw(packet))
        # urllib.parse.unquote(raw(packet))
        # print(raw(packet))
        # print(nzpadding(packet))
        # byte_data = bytes.fromhex(raw(packet))

        # ascii_text = byte_data.decode('ascii')

        # print(BERcodec_Object.dec(raw(packet)))

        # xx,remain = BERcodec_Object.dec(raw(packet))

        # print(xx)

        # print(BERcodec_Object.dec(raw(packet)))
        # xx,remain = BERcodec_Object.dec(raw(packet))

        # print(remain)


        # print(ascii_text)

        # print("*"*70)

        
        # print(packet.show2())
        # print(packet.load)
        # print(bytes(packet.payload).decode('UTF-8','replace'))
        # print(bytes(packet.payload).decode('UTF8','replace'))
        # return str(packet.load, 'UTF-8', errors="replace").replace("\x00", ".")
        
        # if Raw in packet:
        #         payload = bytes(packet[Raw].load).decode('UTF8','ignore')
        #         print(payload)
                # print(is_utf8(payload))
                # if payload:
                #     print(payload)
                # print("--------"*70)
        #     # print(bytes(packet[TCP].payload).decode('UTF8','replace'))
        #     # print(bytes(packet[TCP].payload).decode("UTF-8", errors="replace").replace("\x00", "."))
        #     print(str(packet.load, 'latin-1', errors="replace").replace("\x00", "."))
            # x = bytes(packet[TCP].payload).decode('UTF8','replace')
            # print(x.)
        # print(payload)
        # s = str(packet).encode("utf-8").hex()
        # delim = int(s[:2])
        # index = int(s[2:6], 16)
        # rest = Ether(s[6:])
        # print(rest)
        if IP in packet and TCP in packet:
            
            # print(base64.b64decode(str(packet[TCP].payload)))
            # print(base64.b64decode(str(packet[TCP].payload)))
            print(raw(packet[TCP].payload))
            print(bytes((packet[TCP].payload)))
            # payload = bytes(packet[TCP].payload).decode('UTF8','ignore').lower()
            # if "nmap" in payload:
            #         # pass
            #     print(payload)
    except Exception as e:
        traceback.print_exc()
        # print(e)
        # pass
    return None





def get_packet_dst_ip(packet):
    try:
        return packet[IP].dst
    except Exception as e:
        traceback.print_exc()
        return None



def get_packet_src_ip(packet):
    try:
        return packet[IP].src
    except Exception as e:
        traceback.print_exc()
        return None



def get_packer_details(result):
    packet_list = []
    if result is not None:
        for packet in result:
            x = read_payload(packet)
            if x is not None:
                if not x.isspace():
                    packet_list.append(
                        (
                            get_packet_dst_ip(packet),
                            get_packet_src_ip(packet),
                            get_ethernet_type(packet),
                            proto_name_by_num(packet),
                            get_packet_src_port(packet),
                            get_packet_dst_port(packet),
                            x
                        )
                    )
    return packet_list



import base64 



def collect_packets(iface, time_out):
    print("start Capturing")
    timeout_seconds = int(time_out)
    start_time = time.time()
    captured_packets = []
    while time.time() - start_time < timeout_seconds:
        sniff( iface= str(iface), timeout=1, store=False, prn=read_payload)
        #c = sniff( iface= 'Ethernet 2', timeout=1)
        # print(c.summary())
        # for packet in c:
            
        #     # print(packet.lastlayer())
        #     # print(hexdump(packet.lastlayer()))
        #     read_payload(packet)
            # captured_packets.append(packet)

    # packets = get_packer_details(captured_packets)
    # print(packets)
    print("end Capturing")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        collect_packets(sys.argv[1], sys.argv[2])
    else:
        # print("Hello, world!")
        print("Pass interface name as argument like \n\npython test_scapy.py eno2" )
    