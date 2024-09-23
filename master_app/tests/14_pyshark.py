import pyshark
import socket

# Read the PCAP file
capture = pyshark.FileCapture('172_165_120_189.pcap',
                              display_filter='ssh',
                              include_raw=True, use_json=True)



prefix = "IPPROTO_"
protocol_table = {num:name[len(prefix):] for name,num in vars(socket).items() if name.startswith(prefix)}


# # Iterate over the packets
# for packet in capture:
#     # Print the packet summary
#     print(packet)
    
#     # Print the packet details
#     packet.show()


# filtered_capture = capture

# Extract the data from the packets
# data = [packet.data for packet in capture]

# # Print the data
# for d in data:
#     print(d)


# count  = 0
# for i in capture:
#     # print(i.ip.src, i.ip.dst, i.dns.qry_name)
#     # print(i.ssh)
#     # print(dir(i.ssh))
#     # print(i.ip.src, i.ip.dst, i.tcp.payload.raw_payload)
#     # count += 1
    
#     # print(count)
#     # protocol = i.layers
#     # protocol = i.highest_layer

#     # counter for different protcols
    

#     # print(protocol)
#     if 'IPV6 Layer' in str(i.layers):
#         protocol = [protocol_type for [protocol_number, protocol_type] in protocol_table.items()
#                     if protocol_number == int(i.ipv6.nxt)]
#         print(protocol)
#     elif 'IP Layer' in str(i.layers):
#         protocol = [protocol_type for [protocol_number, protocol_type] in protocol_table.items()
#                     if protocol_number == int(i.ip.proto)]
#         print(protocol)

#     # print(protocol)

#     # break
    

# # for packet in capture:
# #     print(packet.pretty_print())


with pyshark.FileCapture('192_168_14_161.pcap',display_filter='pgsql') as cap:
    for i, pkt in enumerate(cap):
        try:
            print([pkt.layers[i].layer_name for i, lay in enumerate(pkt.layers)])
        except AttributeError as ex:
            print(ex)