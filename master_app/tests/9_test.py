from scapy.all import *



a = rdpcap('192_168_0_143.pcap')


print(a)


s = a.sessions()


print(s)