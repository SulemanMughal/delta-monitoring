import json
import time
from scapy.all import *
from decouple import config
import requests
import psycopg2
import uuid
from datetime import datetime, timezone
import traceback
import os
import monitor_service
import asyncio
from pathlib import Path
import base64
from datetime import date


BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE_DIR.parent /  'media' / 'pcap_files
'



filename = PCAP_DIR.joinpath("output" + ".txt")

# print(filename)

def get_os():
    with open(filename, "r") as file:
        lines = file.readlines()
        # print(lines)
        for i in lines:
            print(i.split("|"))
            x = i.split("|")[4]
            client = i.split("|")[1].split("=")[-1].split("/")[0]
            if "os" in i.split("|")[4]:
                y = x.split("=")[-1]
                if y != "???":
                    # print(x)
                    print("{} :: {}".format(client, y))
                    # print(y)

get_os()


#captured_traffic.pcap
# tshark -r captured_traffic.pcap -T fields -E separator=, -e eth.src -e eth.dst -e ip.src -e ip.dst  > output.txt