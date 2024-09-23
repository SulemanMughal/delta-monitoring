from scapy.all import *
from decouple import config
from pathlib import Path


from scapy.all import *
from os.path import isfile
from datetime import datetime
import warnings

# warnings.filterwarnings("ignore", category=DeprecationWarning) 



load_layer("http")
pkts = sniff(offline="captured_traffic.pcap", session=TCPSession)

# for pkt in pkts:


# read a list using yield
def read_list(pkts):
    for pkt in pkts:
        yield pkt
    
for pkt in read_list(pkts):
    # print(pkt)
    try:
        # print(pkt['IP'].src, ":" , pkt['TCP'].sport, " -> ", pkt['IP'].dst, ":", pkt['TCP'].dport)
        # print tcp session info
        # print(pkt['TCP'].sport, " -> ", pkt['TCP'].dport)
        # print tcp stream number
        # print(pkt['TCP'].stream)

        # print http info
        # print(pkt['HTTPRequest'].Method.decode(), " ", pkt['HTTPRequest'].Path.decode(), " ", pkt['HTTPRequest'].Http_Version.decode())
    except Exception as e:
        print(e)