import pyshark

pkts = pyshark.FileCapture("172_165_120_189.pcap")
streams = {}
for pkt in pkts:
    if 'tcp' not in pkt:
        continue
    if pkt.tcp.stream not in streams:
        streams[pkt.tcp.stream] = list()
    streams[pkt.tcp.stream].append(pkt)

for stream in streams:
    for pkt in streams[stream]:
        try:
            ack_rtt = pkt.tcp.analysis_ack_rtt
        except AttributeError as e:
            ack_rtt = '-'
        print(f"{pkt.frame_info.number} {stream} {pkt.ip.src} {pkt.ip.dst} {pkt.tcp.srcport} {pkt.tcp.dstport} - ack_rtt: {ack_rtt}")