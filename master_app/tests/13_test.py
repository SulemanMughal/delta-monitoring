from scapy.all import *

packets = PcapReader("172_165_120_189.pcap")

counts = {}
# QR = Query Response
# ANCOUNT = Answer Count
# https://datatracker.ietf.org/doc/html/rfc5395#section-2
for packet in packets:
    if packet.haslayer(DNS) :
        # DNS query returned no answerip.dst == 172.165.120.189
        # extract the destination IP (device that sent the query)
        ip = packet[IP].dst
        counts[ip] = counts.get(ip, 0) + 1

threshold = 100

print("+ Create list of suspicious IP addresses ...")
suspicious = []
for ip, occurrences in counts.items():
    if occurrences < threshold:
        continue
    suspicious.append(ip)

print(suspicious, counts)