"""
Follow a TCP stream with pyshark.

"""
import pyshark

# Change FILENAME to your pcap file's name.
FILENAME = "172_165_120_189.pcap"
# Change STREAM_NUMBER to the stream number you want to follow.
STREAM_NUMBER = 0

# open the pcap file, filtered for a single TCP stream 
cap = pyshark.FileCapture(
    FILENAME,
    display_filter='tcp.stream eq %d' % STREAM_NUMBER)

# print(cap.__len__())

while True:
    try:
        p = cap.next()
    except StopIteration:  # Reached end of capture file.
        break
    try:
        # print data from the selected stream
        # print(p.data.data.binary_value)
        # print(p.show())
        # print(p.data.data)
        print(p.pretty_print())
        pass
    except AttributeError:  # Skip the ACKs.
        pass