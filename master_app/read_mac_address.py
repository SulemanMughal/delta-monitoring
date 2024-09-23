
import traceback
import os


def get_mac_addresses(filename = None):
    A = {}
    if filename is None:
        # filename = PCAP_DIR.joinpath("output" + ".txt")
        print("Please provide filename")
        return None
    else:
        print("-"*70)
        print("Get mac addresses")
        print("-"*70)
        # print(filename)
        # open file
        with open(filename, "r", encoding="utf8", errors='ignore') as file:
            lines = file.readlines()
            for i in lines:
                print(i)
                # print(i.decode("utf-8"))
        