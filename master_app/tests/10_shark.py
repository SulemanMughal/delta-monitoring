# Network Conversations


import pyshark

def network_conversation(packet):
  try:
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    return (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}')
  except AttributeError as e:
    pass

capture = pyshark.FileCapture('172_165_120_189.pcap')
conversations = []
counter = 0
for packet in capture:
  results = network_conversation(packet)
  if results != None:
    counter = counter + 1
    print(counter , results)
    
    conversations.append(results)

# this sorts the conversations by protocol ssssssss
# TCP and UDP
    
# print(len(conversations))
# for item in sorted(conversations):
#   print (item)``