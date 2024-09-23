import pyshark

capture = pyshark.LiveCapture(interface='VMware Network Adapter VMnet8')
capture.sniff(timeout=10)
# capture.sniff(timeout=1)
# print('after sniff')
# print(capture)

def print_callback(pkt):
    print('Just arrived:', pkt)

# for packet in capture.sniff_continuously(packet_count=20):
#     print('Just arrived:', pkt)

# print(capture[0])
    

for packet in capture.sniff_continuously(packet_count=10):
    print('Just arrived:', packet)
