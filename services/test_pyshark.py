import pyshark
try:
    capture = pyshark.LiveCapture(interface="VMware Network Adapter VMnet8", output_file="pyshark.pcap")
    capture.sniff()
except KeyboardInterrupt:
    print(capture)