from scapy.all import *
from decouple import config
# from pathlib import Path


# # from scapy.all import *
# from os.path import isfile
# from datetime import datetime
# import warnings

# warnings.filterwarnings("ignore", category=DeprecationWarning) 

# __list = []


# Set the interface to capture on (replace 'eth0' with your actual interface)
# interface = 'eth0'

# Set the output file name
output_file = 'captured_traffic.pcap'



TMP="/tmp/access.log"


# def format(request, response) -> str:

#     def get_ent(it, field, alternate=''):
#         it = it.get(field, alternate)
#         if type(it) != str and it: it = it.decode()
#         return it

#     FMT = '{SRC_IP} - - [{DATE} +0500] "{METHOD} {ENDPOINT} {HTTP_VER}" {STATUS_CODE} {LEN} "{REFERER}" "{USER_AGENT}"'

#     rcv_time = request.time
#     rcv_time = datetime.fromtimestamp(rcv_time).strftime('%d/%b/%Y:%H:%M:%S')
#     src_ip = request['IP'].src
#     req_fields = request['HTTPRequest'].fields
#     resp_fields = response['HTTPResponse'].fields

#     referer = get_ent(req_fields, 'Referer', alternate="-")
#     status_code = get_ent(resp_fields, 'Status_Code')
#     user_agent = get_ent(req_fields, 'User_Agent')
#     method = request['HTTPRequest'].Method.decode()
#     path = request['HTTPRequest'].Path.decode()
#     http_ver = request['HTTPRequest'].Http_Version.decode()
#     _len = len(response['HTTPResponse'].payload)

#     return FMT.format(
#         SRC_IP=src_ip,
#         DATE=rcv_time,
#         METHOD=method,
#         ENDPOINT=path,
#         HTTP_VER=http_ver,
#         STATUS_CODE=status_code,
#         LEN=_len,
#         REFERER=referer,
#         USER_AGENT=user_agent
#     )

# def __parse__(pkt):
#     global __list
#     if pkt.haslayer(HTTPRequest):
#         __list.append(pkt)
#     elif pkt.haslayer(HTTPResponse):
#         for i in range(len(__list)):
#             p = __list[i]
#             if pkt.answers(p) == 1:
#                 fmt = format(request=p, response=pkt)
#                 print(fmt)
#                 with open("access.log", "a") as f:
#                     f.write(f"{fmt}\n")
#                 del __list[i]
#                 break



# BASE_DIR = Path(__file__).resolve().parent.parent
# PCAP_DIR = BASE_DIR.parent /  'media' / 'pcap_files'

# filename = PCAP_DIR.joinpath("captured_traffic" , ".pcap")

def packet_callback(pkt):
    print(pkt.summary())
    wrpcap(output_file, pkt, append=True)
    # Process each packet (you can add your logic here)
    # print(pkt.haslayer(HTTPRequest))
    # print(pkt.haslayer(HTTPResponse))
    # try:
    #     # e = Frame[Ether(_pkt=packet)]
        
    #     print(Ether(packet))
    # except Exception as e:
    #     print(e)
        
    # try:
    #     global __list
    #     if pkt.haslayer(HTTPRequest):
    #         __list.append(pkt)
    #     elif pkt.haslayer(HTTPResponse):
    #         for i in range(len(__list)):
    #             p = __list[i]
    #             if pkt.answers(p) == 1:
    #                 fmt = format(request=p, response=pkt)
    #                 print(fmt)
    #                 with open(TMP, "a") as f:
    #                     f.write(f"{fmt}\n")
    #                 del __list[i]
    #                 break
    # except Exception as e:
    #     print(e)
    
    # Write the packet to the pcap file
    

    

# Sniff live packets and save them to a file continuously
try:
    # load_layer('http')
    print("start captruging")
    # The packet_callback function will be called for each captured packet
    sniff(iface=config('NETWORK_INTERFACE_LABEL'), prn=packet_callback, store=0)

except KeyboardInterrupt:
    # Handle KeyboardInterrupt (Ctrl+C) to stop capturing gracefully
    print("Capturing stopped.")