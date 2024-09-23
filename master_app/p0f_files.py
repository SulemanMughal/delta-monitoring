# import json
# import time
# from scapy.all import *
# from decouple import config
# import requests
# import psycopg2
# # import uuid
# # from datetime import datetime, timezone
import traceback
# # import os
# # import monitor_service
# import asyncio
# from pathlib import Path
# import base64
# from datetime import date


# BASE_DIR = Path(__file__).resolve().parent.parent
# PCAP_DIR = BASE_DIR.parent /  'media' / 'pcap_files




# filename = PCAP_DIR.joinpath("output" + ".txt")

# print(filename)

import os


def get_os(filename = None, ip_address=None):
    A = {}
    if filename is None:
        # filename = PCAP_DIR.joinpath("output" + ".txt")
        print("Please provide filename")
        return None
    else:
        # print(filename)
        with open(filename, "r") as file:
            lines = file.readlines()
            # print(lines)
            for i in lines:
                # print(i.split("|"))
                x = i.split("|")[4]
                client = i.split("|")[1].split("=")[-1].split("/")[0]
                if "os" in i.split("|")[4]:
                    y = x.split("=")[-1]
                    if y != "???":
                        # add a key to dict if not exist and append value to it
                        # if str(client) in A.keys():
                        #     A[str(client)] = set(A[str(client)] + [y])
                        if y is not None:
                            try:
                                if y not in A[str(client)]:
                                    A[str(client)].append(y)
                            except KeyError:
                                A[str(client)] = []
                                A[str(client)].append(y)
                            except AttributeError as e:
                                print(e)
                            except :
                                traceback.print_exc()


                        # try:
                            
                        # except KeyError:
                        #     A[str(client)] = []
                        #     A[str(client)].append(y)
                        # except : 
                        #     # A[str(client)] = []
                        #     # A[str(client)].append(y)
                        # # print(x)
                        #     print("{} :: {}".format(client, y))
                        # A.add((client, y))
                        # A[""]
                        # print(y)

        # os.remove(filename)
        # print("File Removed!")
        return {
            str(ip_address) : A[str(ip_address)]
        }
        # return A
# get_os()


#captured_traffic.pcap
# tshark -r captured_traffic.pcap -T fields -E separator=, -e eth.src -e eth.dst -e ip.src -e ip.dst  > output.txt

# p0f -r 3_161_104_31.pcap -o output.txt


# tshark -r 192_168_31_110.pcap -T fields -e tcp.stream | sort -urn | head -n 1

# tshark -r 142_250_181_69.pcap  -z "follow,tcp,ascii, 0"

#  raw data


# 4001-4100

# 10.12.*.100-200