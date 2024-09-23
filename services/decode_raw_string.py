# convert whole scapy packet to bytes


import time
from scapy.all import *

import sys
from scapy.utils import hexdump

import base64

def details(packet):
    print("received packet")

def collect_packets():
    print("start Capturing")
    timeout_seconds = 1
    start_time = time.time()
    captured_packets = []
    while time.time() - start_time < timeout_seconds:
        
        sniffed_packets = sniff( iface= "wlp6s0", timeout=1)
        for pkt in sniffed_packets:
            # print(pkt)

            # Print All Available for a single sniff packet
            # print(dir(pkt))

            # print(pkt._PickleType)
            # print(pkt._bytes_())
            # print(help(pkt._bytes_()))
            # print((pkt.build()))
            # print(pkt.show2())
            # base64.````````
            # print(hex(pkt))



            print("\n\n")




            
            # print(bytes(pkt))
            # print(hexdump(pkt))
            # hexdump(pkt)
            # print(raw(pkt) )
            # print(bytes(pkt))
            # # # print(pkt.summary())
            # # c = pkt.show2(prn=details)
            # print(c())
            # print(pkt.show2)
            # print(pkt.addr2())
            # pac = pkt.addr2

            # pac = pkt.show2


    print("end Capturing")


def decode_string():
    string = b'AAwpQjokAFBWwAAICABFAABA1ahAAIAGhxzAqA4BwKgOodkfFThKz7Nx0BogylAYEAThzQAAFwMDABMVDVX5CqfNpDkeIVfUJYs2HvFT'

    # decode base64 string

    # print(base64.b64decode(string[3:]))


    x = b'\x17\x03\x03\x00\x13\x15\rU\n\xcd\xa49\x1e!W%6\x1eS'
    print(x.decode("utf-8"))

    a = base64.b64decode(string)
    b = raw(a)
    c = Ether(b)/IP(b)/TCP(b)

    # c.show2()
    print(c[Raw].load.decode("utf-8", errors="ignore"))

    # print(c[TCP].load.decode("latin-1"))







    # # print(b'\x9c\xad\x97Wk=\xb8\xddq\xc2R\xfc\x08\x00E\x00\x00\x9bQ\x05@\x00m\x06\xa5\x19\x14*AX\xc0\xa8\x01\x14\x01\xbb\xcc\xdc\xe6\xc9\xfc\xcdz+\xd4\xc1\x80\x18?\xfc\x80\x18\x00\x00\x01\x01\x08\n\t\x0f@\x93\xa1\xdf\'W\x17\x03\x03\x00b{\x9b\x1a\x13\xdb"\xad\xef\xed\x12\xb6cW\xee\xc0{k\xc6\xb8q\x19\xa4\xa2\xb3\x03\xd6\xf2\x94\xcf\x06\x1aZC\xe8\xc1\x8aP1\xc2T\xabr\xfe\x1c,\xe5\x1c6e\x03\xdc(\'\xcf\xeb\xbb`\x87\x1f\x10\xce\x13LL\xcf\x1b\x87\x13\x9b\x0f=\xb0\xd6Z~Q1\xfa\x92\x8c\xf6]\xbfh\xf7\xb5GEX\x98"\xaf$\xe7\x013\x8fx'.decode("unicode-escape",errors="ignore"))

    # # s1 = string.encode("latin-1")
    # # s2 = s1.decode('unicode-escape', "replace").replace("\x00", ".")
    # # s3 = s2.encode('latin-1', "ignore")
    # # s4 = s3.decode('UTF8', "ignore")
    # # print(s1, s2,s3, s4, sep="\n")
    # string=b'nK2XV2s9uN1xwlL8CABFKABUAAAAADwBeHyO+rVOwKgBFAAAWdAAAWMr/tSwZQAAAADL9QkAAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc='
    # y = base64.b64decode(string)
    # print(y)

    # stringB = b'm\xd6\xb0e\x00\x00\x00\x00\xd6\xb2\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'


    # # print(str(stringB.decode("utf-8")))

    # # y = y.replace('\x01','\x00')
    # # print(y)
    # # print(bytes(y, "utf-8"))

    # # string.encode("latin-1").decode('unicode-escape', "ignore").encode('latin-1', "ignore").decode('UTF8', "ignore")

if __name__ == "__main__":
    # collect_packets()
    decode_string()