# import pyshark

# cap = pyshark.FileCapture('172_165_120_189.pcap')

# sess_index = [] # to save stream indexes in an array

# for pkt in cap:
#     try:
#         sess_index.append(pkt.tcp.stream)
#     except:
#         pass

# print(sess_index)

# # if len(sess_index) == 0:
# #     max_index = 0
# #     print("No TCP Found")

# # else:
# #     max_index = int(max(sess_index)) + 1 # max function is used to get the highiest number

# # for session in range(0,max_index):
# #     for pkt in cap: 
# #         try:
# #             if int(pkt.tcp.stream) == session:
# #                 if pkt.http > 0:
# #                     print("Stream Index :",pkt.tcp.stream) # to print stream index at the start
# #                     print("HTTP LAYER :",str(pkt.http).replace("\\n","").replace("\\r", ""))
# #         except:
# #             pass



import pyshark

def count_streams(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    streams = set()

    for packet in capture:
        if "IP" in packet and "TCP" in packet:
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            source_port = packet.tcp.srcport
            dest_port = packet.tcp.dstport

            stream = f"{source_ip}:{source_port} - {dest_ip}:{dest_port}"
            streams.add(stream)

    return len(streams)

# Example usage
pcap_file = "172_165_120_189.pcap"
total_streams = count_streams(pcap_file)
print(f"Total number of streams: {total_streams}")